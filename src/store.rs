//! Where the credential lives, and the care its file needs.
//!
//! **Not in a config file.** Every mechanism a robot's configuration has is wrong for a secret:
//! something prints what a robot has changed, something else shows the whole file in an editor,
//! and "what was configured on this robot" is a report somebody generates. A bearer token would
//! be in all three.
//!
//! This module is also where the **cross-process file format** is defined, which is the reason
//! [`read_access_token`] exists next to the writer rather than in whichever daemon reads it. The
//! process that performs the login is privileged; the process that *uses* the token — a relay, a
//! media daemon — usually is not, and has no business linking the rest of this crate. One key at
//! one level, pinned by a test here, is the whole contract between them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Identity, now_secs};

/// What is on disk.
///
/// The shape mirrors what the token endpoint returns, plus the two things it does not: an
/// absolute expiry (the response gives a duration, and a duration is meaningless after a reboot)
/// and the username, so a status call answers without a network round trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    /// The bearer token. **This key at this level is what other processes read.**
    pub access_token: String,
    /// Absent when Hugging Face issues none, which makes the token unrenewable rather than broken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds. Absent means "the server did not say", which is treated as not expiring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// As `/oauth/userinfo` reported it at login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl Stored {
    /// Seconds until the access token expires; negative once it has. [`i64::MAX`] when unknown.
    pub fn expires_in(&self) -> i64 {
        match self.expires_at {
            None => i64::MAX,
            Some(at) => at.saturating_sub(now_secs()),
        }
    }

    /// What a caller is told about this credential.
    pub fn identity(&self) -> Identity {
        Identity {
            username: self
                .username
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            token_expires_in: self.expires_in(),
            refreshable: self.refresh_token.is_some(),
        }
    }
}

/// The token file, and the three operations anything has on it.
///
/// **Configurable rather than abstract.** A path, an optional group and a mode cover the
/// differences between boards that actually exist: a different filesystem layout, a robot with no
/// group to share the token with, a stricter mode. What they do not cover is a credential that
/// does not live in a file at all — a TPM, a keyring — and that is a reason to add a trait when
/// somebody has one, not before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStore {
    path: PathBuf,
    group: Option<String>,
    mode: u32,
}

impl FileStore {
    /// A credential at `path`, readable only by the user that writes it.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            group: None,
            mode: 0o600,
        }
    }

    /// Let one more group read it, by **name**.
    ///
    /// By name because `systemd-sysusers` and its equivalents allocate dynamically: a number
    /// written down is right on one board and wrong on the next. This also relaxes the mode to
    /// `0640`, since group ownership without the group-read bit gives nobody anything — call
    /// [`Self::mode`] afterwards for the unusual case where that is what you meant.
    ///
    /// A group that does not exist on this system is a warning and a token that stays private to
    /// its owner, not an error: a login that failed because a developer's laptop has no such
    /// group would be a worse outcome than a token the other daemon cannot read yet.
    pub fn readable_by_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self.mode = 0o640;
        self
    }

    /// Override the mode the file ends up with.
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// Where the credential is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What is stored, or `None` when the robot belongs to nobody.
    ///
    /// A file that will not parse is `None` with a warning rather than an error: the recovery for
    /// a corrupt credential is signing in again, and a daemon that refuses to start — or a status
    /// call that fails — because of one would make that harder rather than safer.
    pub fn load(&self) -> Option<Stored> {
        let bytes = std::fs::read(&self.path).ok()?;
        match serde_json::from_slice::<Stored>(&bytes) {
            Ok(stored) => Some(stored),
            Err(e) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "the stored account credential does not parse; treating this robot as signed out"
                );
                None
            }
        }
    }

    /// Replace the credential, atomically, readable only by its owner and the named group.
    ///
    /// **The one window this cannot close.** Hugging Face rotates the refresh token on every
    /// refresh, so between "the server issued a new pair" and "the new pair is on disk" the old
    /// refresh token is already dead. A power cut in that window leaves a robot holding a
    /// credential Hugging Face will not renew, and no ordering here fixes it — the rotation
    /// happened on their side. It surfaces as a refresh failure in [`crate::Status::last_error`]
    /// and is fixed by signing in again, which is why [`crate::maintain`] starts trying a week
    /// early rather than on the last day.
    pub fn save(&self, stored: &Stored) -> Result<(), Error> {
        let bytes = serde_json::to_vec_pretty(stored).map_err(|e| Error::Io {
            path: self.path.clone(),
            source: std::io::Error::other(e),
        })?;

        // Written 0600 first and relaxed afterwards, so the file is never group- or
        // world-readable while it is owned by the writing user's default group.
        write_private(&self.path, &bytes)?;
        let Some(group) = self.group.as_deref() else {
            return set_mode(&self.path, self.mode);
        };
        // **Neither of the two ways this can fail may fail the save.** By the time a token is
        // being written somebody has approved a code on their phone, and losing the credential
        // over a group would make them do the whole flow again. A half-provisioned board has no
        // such group; an unprivileged writer cannot give a file to a group it is not in. Both
        // leave the token private to its owner and say so once, which is a robot whose other
        // daemon cannot read the token yet rather than a robot that is not signed in.
        //
        // The mode is only relaxed **after** the group actually changed. Relaxing it first — or
        // anyway — would hand group-read to the writer's own default group, which is wider than
        // what was asked for and is the mistake this ordering exists to prevent.
        let complaint = match ownership::group_id(group) {
            None => "no such group on this system",
            Some(gid) => match ownership::set_group(&self.path, gid) {
                Ok(()) => return set_mode(&self.path, self.mode),
                Err(_) => "this process may not give a file to that group",
            },
        };
        tracing::warn!(
            group,
            path = %self.path.display(),
            why = complaint,
            "the token stays private to its owner — a process that reads it through that group \
             will not be able to"
        );
        Ok(())
    }

    /// Forget the credential. Returns who it belonged to, if anyone.
    ///
    /// Clearing nothing is not an error: signing out twice is not a failure.
    pub fn clear(&self) -> Result<Option<String>, Error> {
        let was = self.load().and_then(|s| s.username);
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(was),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io {
                path: self.path.clone(),
                source: e,
            }),
        }
    }
}

/// The access token out of a credential file, or `None` when the robot belongs to nobody.
///
/// **The reading half, for a process that is not the one that writes.** Deliberately the smallest
/// possible reader: one field, so a record that grows another does not break the parse, and no
/// dependency on anything else in this crate's behaviour.
///
/// Read on every use rather than cached. A login that happens while the reader is running has to
/// take effect without a restart — it may arrive over Bluetooth, minutes or months after the
/// process started — and re-reading a small file costs nothing on any path that would care.
pub fn read_access_token(path: &Path) -> Option<String> {
    #[derive(Deserialize)]
    struct Credential {
        access_token: String,
    }

    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Credential>(&bytes) {
        Ok(credential) if !credential.access_token.is_empty() => Some(credential.access_token),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "the account credential does not parse; treating this robot as signed out"
            );
            None
        }
    }
}

// ── writing a file that is never briefly readable ────────────────────────────

/// Write via a temp file and rename, with the temp file created `0600` from the start.
///
/// The usual write-then-chmod is what this exists to avoid: a token written `0644` and chmodded
/// afterwards is world-readable for the moment in between, which is exactly the kind of window
/// that is invisible in testing and permanent in a log.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    let io = |source: std::io::Error, path: &Path| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| io(e, &tmp))?;
        file.write_all(bytes).map_err(|e| io(e, &tmp))?;
        file.sync_all().map_err(|e| io(e, &tmp))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| io(e, path))?;
    fsync_parent(path)
}

/// Flush the directory entry, so the rename survives a power cut and not only a crash.
fn fsync_parent(path: &Path) -> Result<(), Error> {
    // `parent()` yields `Some("")` for a bare filename, which cannot be opened; the containing
    // directory in that case is the working directory.
    let dir = match path.parent() {
        None => return Ok(()),
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
    };
    // Opening a directory read-only and fsyncing it is the portable way to flush its entries on
    // Linux and macOS.
    let handle = std::fs::File::open(dir).map_err(|e| Error::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    handle.sync_all().map_err(|e| Error::Io {
        path: dir.to_path_buf(),
        source: e,
    })
}

fn set_mode(path: &Path, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Group ownership, which is the only part of this crate that needs libc.
///
/// Split out so there is one SAFETY argument rather than one per caller. Names rather than
/// numbers throughout, because `systemd-sysusers` and its equivalents allocate dynamically: a gid
/// written down is right on one board and wrong on the next.
mod ownership {
    use std::path::Path;

    use crate::Error;

    /// The gid of a group by name, or `None` if there is no such group.
    pub fn group_id(name: &str) -> Option<u32> {
        let cname = std::ffi::CString::new(name).ok()?;
        // SAFETY: `getgrnam` takes a NUL-terminated string and returns a pointer into a static
        // buffer, or null. The one field we need is read immediately and nothing is retained, so
        // the next caller overwriting that buffer cannot be observed here.
        let entry = unsafe { libc::getgrnam(cname.as_ptr()) };
        if entry.is_null() {
            return None;
        }
        // SAFETY: non-null, and `getgrnam` guarantees a fully initialised `group` behind it.
        // The gid is copied out before anything else can call into the group database.
        Some(unsafe { (*entry).gr_gid })
    }

    /// Give the file to a group, leaving its owner alone.
    pub fn set_group(path: &Path, gid: u32) -> Result<(), Error> {
        use std::os::unix::ffi::OsStrExt as _;

        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Io {
            path: path.to_path_buf(),
            source: std::io::Error::other("path contains a NUL"),
        })?;
        // SAFETY: the pointer is valid for the call; `u32::MAX` is `(uid_t)-1`, which is how
        // `chown(2)` is told to leave the owner unchanged.
        let rc = unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) };
        if rc != 0 {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_in(dir: &tempfile::TempDir) -> FileStore {
        FileStore::at(dir.path().join("hf-token"))
    }

    fn token(access: &str) -> Stored {
        Stored {
            access_token: access.to_string(),
            refresh_token: Some("refresh-1".into()),
            expires_at: Some(now_secs() + 30 * 24 * 60 * 60),
            username: Some("PierreRouanet".into()),
        }
    }

    /// The store is a file, and the file survives being replaced.
    #[test]
    fn a_credential_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);

        assert!(store.load().is_none(), "nothing stored yet");
        store.save(&token("first")).unwrap();
        assert_eq!(store.load().unwrap().access_token, "first");

        store.save(&token("second")).unwrap();
        assert_eq!(store.load().unwrap().access_token, "second");
        assert_eq!(
            store.clear().unwrap(),
            Some("PierreRouanet".to_string()),
            "clear reports who it forgot, so a caller can say so"
        );
        assert!(store.load().is_none());
        assert_eq!(
            store.clear().unwrap(),
            None,
            "clearing nothing is not an error — signing out twice is not a failure"
        );
    }

    /// **A token must never be world-readable, at any point.**
    ///
    /// The mode is checked on the file that lands, and the temp file it was written through is
    /// checked by construction: `write_private` opens it `0600` rather than chmodding afterwards,
    /// which is the window this test cannot see and the reason the helper exists.
    #[test]
    fn the_token_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        for store in [
            store_in(&dir),
            store_in(&dir).readable_by_group("no-such-group-exists-here"),
        ] {
            store.save(&token("secret")).unwrap();

            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode & 0o007,
                0,
                "the token file is readable by other users: {mode:o}"
            );
            assert!(
                !dir.path().join("hf-token.tmp").exists(),
                "the temp file must not be left behind holding a copy of the token"
            );
        }
    }

    /// The group is a best effort, and a best effort must never cost the token.
    ///
    /// Three cases, and only the first one is the happy path. A group that does not exist and a
    /// group this process may not give a file to are both **warnings**: the credential lands,
    /// private to its owner, because by the time this runs somebody has approved a code and
    /// losing it over a permission bit would make them do the whole flow again.
    #[test]
    fn the_group_is_a_best_effort_and_never_costs_the_token() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let saved = |store: &FileStore| {
            store.save(&token("secret")).unwrap();
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            (mode, store.load().unwrap().access_token)
        };

        assert_eq!(
            saved(&store_in(&dir)),
            (0o600, "secret".into()),
            "private by default"
        );

        assert_eq!(
            saved(&store_in(&dir).readable_by_group("no-such-group-exists-here")),
            (0o600, "secret".to_string()),
            "a group that does not exist leaves the file private, and the token is still stored"
        );

        // A group this process is definitely not in, unless it is running as root — in which
        // case `chown` succeeds and the group-read bit is the right answer instead.
        let (mode, stored) = saved(&store_in(&dir).readable_by_group(OTHER_GROUP));
        assert_eq!(
            stored, "secret",
            "a refused chown must not lose the credential"
        );
        assert!(
            mode == 0o600 || (mode == 0o640 && is_root()),
            "a chown this process may not do leaves the file private: {mode:o}"
        );

        // And the group it *can* use gets the bit, which is the whole point of the option.
        let (mode, _) = saved(&store_in(&dir).readable_by_group(own_group()));
        assert_eq!(mode, 0o640, "the process's own group can be given read");
    }

    /// A group no ordinary user is a member of. `wheel` on macOS, `root` on Linux.
    const OTHER_GROUP: &str = if cfg!(target_os = "macos") {
        "wheel"
    } else {
        "root"
    };

    fn is_root() -> bool {
        // SAFETY: `getuid` takes nothing, returns the calling process's real uid, and cannot fail.
        unsafe { libc::getuid() == 0 }
    }

    /// The name of this process's own group, which `chown` will always accept.
    fn own_group() -> String {
        // SAFETY: `getgid` cannot fail. `getgrgid` returns a pointer into a static buffer or
        // null; the name is copied out immediately and nothing is retained, so a later caller
        // overwriting that buffer cannot be observed here.
        unsafe {
            let entry = libc::getgrgid(libc::getgid());
            assert!(
                !entry.is_null(),
                "this process's own gid has no group entry"
            );
            std::ffi::CStr::from_ptr((*entry).gr_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    /// **The one key another process reads, at the level it reads it.**
    ///
    /// The whole cross-process contract, and this is the writer, so this is where it is pinned.
    #[test]
    fn the_stored_shape_is_what_a_reader_reads() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store.save(&token("hf_abc")).unwrap();

        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
        assert_eq!(
            raw["access_token"], "hf_abc",
            "a reader reads exactly this key at exactly this level"
        );
        assert!(
            raw.get("refresh_token").is_some() && raw.get("expires_at").is_some(),
            "and the rest of the record is the writer's business: {raw}"
        );
        assert_eq!(
            read_access_token(store.path()).as_deref(),
            Some("hf_abc"),
            "and the reader in this crate is held to the same contract"
        );
    }

    /// The reader takes one field out of whatever the writer wrote, and survives the rest.
    #[test]
    fn the_reader_takes_one_field_and_tolerates_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hf-token");

        assert_eq!(read_access_token(&path), None, "no file is no account");

        std::fs::write(
            &path,
            r#"{"access_token":"hf_abc","refresh_token":"r","expires_at":1,
                "username":"x","added_later":true}"#,
        )
        .unwrap();
        assert_eq!(read_access_token(&path).as_deref(), Some("hf_abc"));

        std::fs::write(&path, r#"{"refresh_token":"only"}"#).unwrap();
        assert_eq!(
            read_access_token(&path),
            None,
            "a record with no token is no use"
        );

        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(read_access_token(&path), None, "corrupt is signed out");
    }

    /// A file somebody edited by hand reads as "signed out", not as a broken daemon.
    #[test]
    fn a_corrupt_credential_is_signed_out_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        std::fs::write(store.path(), b"{ this is not json").unwrap();
        assert!(store.load().is_none());
    }
}
