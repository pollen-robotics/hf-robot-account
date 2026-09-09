//! The part that owns the waiting.
//!
//! A device flow is four HTTP requests and a loop, and [`crate::oauth`] has those. What is here
//! is everything that follows from the loop outliving the call that started it: a login answers
//! with a code and a caller comes back later, so *something* has to hold the flow, refuse a
//! second one, and be able to disown one that has been replaced.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;

use crate::oauth::{self, DeviceCode, Poll, TokenResponse, http_client};
use crate::{Config, Error, FileStore, LoginCode, Status, Stored, now_secs};

/// A login in flight.
#[derive(Debug, Clone)]
struct Pending {
    login: LoginCode,
    /// When the code stops being good for anything, so `status` can count down.
    deadline: SystemTime,
}

/// The account, as the four operations on it see it.
#[derive(Debug)]
pub struct Account {
    store: FileStore,
    config: Config,
    /// `Mutex` rather than a channel because there is at most one login at a time and both
    /// `login` and `status` need to see it; the lock is held for a field read, and deliberately
    /// never across a network call — `status` is polled *while* a login is in flight, so
    /// anything that made it queue behind an HTTP round trip would make a wizard look stuck.
    pending: Mutex<Option<Pending>>,
    /// Which login is the current one.
    ///
    /// A flow lives in a spawned task that outlives the call that started it, and two things can
    /// happen to it while it waits: a forced login starts another, or `logout` says the robot
    /// belongs to nobody. In both cases the old task is still holding a device code Hugging Face
    /// will happily approve, and without this it would write that approval to the store — a robot
    /// signed back in a minute after being signed out, or signed in as the account somebody just
    /// replaced. Each flow carries the number it was started with and does nothing at all if it
    /// is no longer the current one.
    generation: AtomicU64,
    /// Held for the whole of starting a login, which the one above cannot be.
    ///
    /// Two callers arriving together both read `pending` as empty, both ask Hugging Face for a
    /// code, and both spawn a poller: the store then holds whichever approval landed last, which
    /// is neither predictable nor explicable to whoever was reading the other code. The window is
    /// the round trip to `/oauth/device`, so the guard has to cover it — and it is its own lock
    /// rather than `pending` because `status` must not wait on that round trip.
    starting: Mutex<()>,
    last_error: Mutex<Option<String>>,
}

impl Account {
    /// Infallible, so a process whose TLS stack will not build still starts and still answers
    /// [`Account::status`] — which is how anybody finds out. The HTTP client is built per
    /// operation instead: `status` and `logout` need none at all, and the one operation that
    /// polls in a loop wants a client that lives exactly as long as the loop.
    pub fn new(store: FileStore, config: Config) -> Self {
        Self {
            store,
            config,
            pending: Mutex::new(None),
            generation: AtomicU64::new(0),
            starting: Mutex::new(()),
            last_error: Mutex::new(None),
        }
    }

    /// Where the credential lives.
    pub fn store(&self) -> &FileStore {
        &self.store
    }

    /// What this account was configured with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Start a device-code login, and answer with the code to show somebody.
    ///
    /// The polling runs in a task this returns without waiting for, so the caller is free to hang
    /// up — which is the point. A client comes back to [`Account::status`] to find out what
    /// happened.
    ///
    /// `force` is what it takes to replace an account the robot already belongs to, **and** to
    /// abandon a code nobody is going to approve. The second matters more than it looks: without
    /// it, a login somebody started and walked away from holds the robot for the life of the
    /// code, and the only remedy is `logout` — which destroys a working credential to clear a
    /// pending one.
    pub async fn login(self: &Arc<Self>, force: bool) -> Result<LoginCode, Error> {
        if let Some(stored) = self.store.load()
            && !force
        {
            let who = stored.username.unwrap_or_else(|| "another account".into());
            return Err(Error::AlreadySignedIn(who));
        }

        // One login at a time, and the gate has to hold across the round trip below rather than
        // only across the check — see [`Self::starting`] for what two of them leave behind.
        // `try_lock`, so the second caller is told so now instead of queueing behind somebody
        // else's twenty-second timeout and then starting a login nobody is waiting for.
        let _starting = self.starting.try_lock().map_err(|_| Error::LoginInFlight)?;
        if !force {
            let pending = self.pending.lock().await;
            if let Some(pending) = pending.as_ref()
                && pending.deadline > SystemTime::now()
            {
                return Err(Error::LoginInFlight);
            }
        }

        let client = http_client(&self.config)?;
        let code = oauth::request_device_code(&client, &self.config).await?;
        let login = LoginCode {
            user_code: code.user_code.clone(),
            verification_uri: code.verification_uri.clone(),
            verification_uri_complete: code.verification_uri_complete.clone(),
            expires_in: code.expires_in,
            interval: code.interval,
        };
        // Claimed before the old flow can be told it has been replaced, so there is no instant
        // in which two tasks both believe they are current.
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.pending.lock().await = Some(Pending {
            login: login.clone(),
            deadline: SystemTime::now() + Duration::from_secs(code.expires_in),
        });
        *self.last_error.lock().await = None;

        tracing::info!(
            user_code = %code.user_code,
            uri = %code.verification_uri,
            expires_in = code.expires_in,
            "account login started; waiting for approval"
        );

        let this = Arc::clone(self);
        tokio::spawn(async move { this.wait_for_approval(client, code, generation).await });
        Ok(login)
    }

    /// Poll Hugging Face until the code is approved, refused, or out of time.
    async fn wait_for_approval(&self, client: reqwest::Client, code: DeviceCode, generation: u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(code.expires_in);
        let mut interval = Duration::from_secs(code.interval.max(1));

        let outcome = loop {
            tokio::time::sleep(interval).await;
            if tokio::time::Instant::now() >= deadline {
                break Err("the code expired before it was approved".to_string());
            }
            match oauth::poll_token(&client, &self.config, &code.device_code).await {
                Poll::Pending => continue,
                Poll::SlowDown => {
                    interval += Duration::from_secs(5);
                    continue;
                }
                // Logged rather than surfaced: a 502 from a proxy is not news about this login,
                // and RFC 8628 says to keep asking until the code expires.
                Poll::Inconclusive(why) => {
                    tracing::debug!(%why, "inconclusive poll; still waiting");
                    continue;
                }
                Poll::Refused(why) => break Err(why),
                Poll::Token(token) => break Ok(*token),
            }
        };

        // Superseded, and therefore silent: a forced login replaced this one, or `logout` said
        // the robot belongs to nobody. Either way an approval that arrives now is an answer to a
        // question that has been withdrawn, and writing it would sign the robot into the account
        // somebody just replaced or out of. Checked *before* the store is touched.
        if !self.is_current(generation) {
            tracing::info!(
                user_code = %code.user_code,
                "a login was superseded before it finished; dropping its result"
            );
            return;
        }

        let result = match outcome {
            Err(why) => Err(why),
            Ok(token) => self
                .persist(&client, token)
                .await
                .map_err(|e| e.to_string()),
        };

        // And again after it, because `persist` awaits: a `logout` landing during the write is
        // the same withdrawal, and the record it left behind has to go with it.
        if !self.is_current(generation) {
            let _ = self.store.clear();
            tracing::info!("a login completed after being superseded; its token was discarded");
            return;
        }

        *self.pending.lock().await = None;
        match result {
            Ok(username) => {
                let username = username.unwrap_or_else(|| "an account it cannot name yet".into());
                tracing::info!(%username, "this robot now belongs to a Hugging Face account");
                *self.last_error.lock().await = None;
            }
            Err(why) => {
                tracing::warn!(%why, "account login did not complete");
                *self.last_error.lock().await = Some(why);
            }
        }
    }

    /// Whether the flow started as `generation` is still the one this robot is waiting on.
    fn is_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::SeqCst) == generation
    }

    /// Store a fresh token, and return the username it belongs to if the name could be had.
    ///
    /// The username is asked for *before* the write and stored with it, so `status` never needs
    /// the network — and a robot that is offline still knows who it belongs to.
    ///
    /// **A failure to read the name must not lose the token.** By this point somebody has
    /// approved a code on their phone; throwing the credential away because `/oauth/userinfo`
    /// answered a 502 would make them do the whole flow again for a field that is a label. So
    /// the name is optional: the record lands either way, `status` says `unknown` until it is
    /// known, and [`maintain`] fills it in — see [`Self::name_if_unknown`].
    async fn persist(
        &self,
        client: &reqwest::Client,
        token: TokenResponse,
    ) -> Result<Option<String>, Error> {
        let username = match oauth::userinfo(client, &self.config, &token.access_token).await {
            Ok(username) => Some(username),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "signed in, but could not read the account name; storing the token anyway"
                );
                None
            }
        };
        self.store.save(&Stored {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at: token.expires_in.map(|s| now_secs() + s as i64),
            username: username.clone(),
        })?;
        Ok(username)
    }

    /// Who this robot belongs to, and whether a login is in flight.
    ///
    /// Answers from disk, with no network call, so it stays answerable on a robot whose wifi has
    /// gone — and so it can be polled during a login without queueing behind one.
    pub async fn status(&self) -> Status {
        let account = self.store.load().map(|stored| stored.identity());

        // The code's remaining life rather than its original one: a client polling this wants a
        // countdown, and `expires_in` is documented as what is *left* here.
        let login = self.pending.lock().await.as_ref().and_then(|pending| {
            let left = pending
                .deadline
                .duration_since(SystemTime::now())
                .ok()?
                .as_secs();
            Some(LoginCode {
                expires_in: left,
                ..pending.login.clone()
            })
        });

        Status {
            account,
            login,
            last_error: self.last_error.lock().await.clone(),
        }
    }

    /// Forget the account. A login in flight is abandoned with it. Returns who it was.
    ///
    /// **Forgets rather than revokes.** The file goes, so the robot stops being able to prove it
    /// belongs to anybody, which is what signing out is for. The token itself stays valid at
    /// Hugging Face until it expires — up to thirty days — for anything that read the file while
    /// it was there. Closing that would need a revocation endpoint and the certainty that no
    /// other process has a copy, and neither is available here.
    pub async fn logout(&self) -> Result<Option<String>, Error> {
        // Before the file goes, so a flow that approves during this call sees itself superseded
        // rather than writing a token into a robot that has just been signed out.
        self.generation.fetch_add(1, Ordering::SeqCst);
        let was = self.store.clear()?;
        *self.pending.lock().await = None;
        *self.last_error.lock().await = None;
        if let Some(username) = &was {
            tracing::info!(%username, "this robot no longer belongs to a Hugging Face account");
        }
        Ok(was)
    }

    /// Renew the token before it expires. One pass; [`maintain`] is the loop.
    ///
    /// Returns `true` when it wrote a new token. Does nothing when the robot is signed out, when
    /// there is no refresh token, or when there is plenty of time left — all three are the "do
    /// nothing" case, and each would otherwise be an HTTP request on every tick of the loop, on a
    /// board whose network may not be there.
    pub async fn refresh_if_due(&self) -> Result<bool, Error> {
        let Some(stored) = self.store.load() else {
            return Ok(false);
        };
        let Some(refresh_token) = stored.refresh_token.clone() else {
            return Ok(false);
        };
        if stored.expires_in() > self.config.refresh_when_under.as_secs() as i64 {
            return Ok(false);
        }

        let token =
            oauth::refresh(&http_client(&self.config)?, &self.config, &refresh_token).await?;
        // Keep the username rather than re-asking: a refresh cannot change who the token belongs
        // to, and this path runs unattended on a board whose network may be marginal.
        self.store.save(&Stored {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at: token.expires_in.map(|s| now_secs() + s as i64),
            username: stored.username,
        })?;
        Ok(true)
    }

    /// Ask who the token belongs to, when the stored record cannot say.
    ///
    /// Only ever the case after a login whose `/oauth/userinfo` call failed — [`Self::persist`]
    /// keeps the token in that case rather than losing it over a label. Left alone, `status`
    /// would answer `unknown` until somebody signed in again; this is what makes it answer
    /// properly on the next [`maintain`] pass instead. Returns `true` when it wrote a name.
    pub async fn name_if_unknown(&self) -> Result<bool, Error> {
        let Some(stored) = self.store.load() else {
            return Ok(false);
        };
        if stored.username.is_some() {
            return Ok(false);
        }
        let username = oauth::userinfo(
            &http_client(&self.config)?,
            &self.config,
            &stored.access_token,
        )
        .await?;
        self.store.save(&Stored {
            username: Some(username),
            ..stored
        })?;
        Ok(true)
    }
}

/// Keep the token fresh for as long as this process runs.
///
/// Spawn it once at startup, whatever the account state — a robot signed in later is picked up on
/// the next pass, which is what lets a login arrive over Bluetooth without a restart.
pub async fn maintain(account: Arc<Account>) {
    let interval = account.config.maintain_interval;
    loop {
        match account.refresh_if_due().await {
            Ok(true) => tracing::info!("renewed the account token"),
            Ok(false) => {}
            // Not fatal and not silent: a week of retries is left, and `status` carries the
            // reason for anyone asking why remote access stopped.
            Err(e) => {
                let why = e.to_string();
                tracing::warn!(%why, "could not renew the account token");
                *account.last_error.lock().await = Some(why);
            }
        }
        // A missing name is cosmetic, so its failure stays in the log rather than going to
        // `last_error`: that field answers "why did remote access stop", and this did not stop
        // it. Nothing happens here at all on the overwhelmingly common path — the name is only
        // absent after a login that could not reach `/oauth/userinfo`.
        match account.name_if_unknown().await {
            Ok(true) => tracing::info!("filled in the account name a login could not read"),
            Ok(false) => {}
            Err(e) => tracing::debug!(error = %e, "still cannot read the account name"),
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Stored;

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

    fn account_at(store: FileStore, base: &str) -> Arc<Account> {
        Arc::new(Account::new(store, Config::at(base)))
    }

    /// Hugging Face sends neither `interval` nor `verification_uri_complete`. Both are
    /// synthesised so nothing downstream has to know that.
    #[tokio::test]
    async fn a_device_code_response_is_normalised() {
        // Exactly what huggingface.co answered on 2026-09-02, field for field.
        let hf = fake_hf(
            r#"{"device_code":"41ad39ae","user_code":"A6MY-0314",
                "verification_uri":"https://hf.co/oauth/device","expires_in":300}"#,
        )
        .await;
        let config = Config::at(&hf.base);

        let code = oauth::request_device_code(&http_client(&config).unwrap(), &config)
            .await
            .unwrap();

        assert_eq!(code.user_code, "A6MY-0314");
        assert_eq!(code.expires_in, 300);
        assert_eq!(
            code.interval,
            crate::DEFAULT_POLL_INTERVAL,
            "RFC 8628's fallback, because HF sends no interval"
        );
        assert_eq!(
            code.verification_uri_complete, "https://hf.co/oauth/device",
            "the plain URI when the server sends none — HF's device page ignores a `?user_code=` \
             query, so inventing one would promise a prefill that does not happen"
        );
    }

    /// A robot that already belongs to somebody refuses without `force`, and says who.
    ///
    /// The check is before any network call, which is what makes this testable offline — and is
    /// also the behaviour that matters: a login that reached Hugging Face first would have burned
    /// a device code to arrive at the same refusal.
    #[tokio::test]
    async fn signing_in_over_an_existing_account_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store.save(&token("already-here")).unwrap();

        let account = account_at(store, "http://127.0.0.1:1");
        let error = account.login(false).await.expect_err("must refuse");
        assert!(
            matches!(&error, Error::AlreadySignedIn(who) if who == "PierreRouanet"),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("force"),
            "the message must name the way past it: {error}"
        );
    }

    /// `status` on a robot that belongs to nobody, which is every robot out of the box.
    #[tokio::test]
    async fn status_of_a_robot_that_belongs_to_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let account = Account::new(store_in(&dir), Config::default());
        let status = account.status().await;
        assert!(status.account.is_none());
        assert!(status.login.is_none());
        assert!(status.last_error.is_none());
    }

    /// `status` reports the account from disk, with no network call.
    #[tokio::test]
    async fn status_names_the_account_without_asking_anybody() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store.save(&token("stored")).unwrap();

        // Pointed at a port nothing is listening on: if this needed the network it would fail.
        let status = Account::new(store, Config::at("http://127.0.0.1:1"))
            .status()
            .await;
        let account = status.account.expect("signed in");
        assert_eq!(account.username, "PierreRouanet");
        assert!(account.refreshable, "a refresh token was stored");
        assert!(
            account.token_expires_in > 29 * 24 * 60 * 60,
            "about thirty days: {}",
            account.token_expires_in
        );
    }

    /// A token with a month left is not renewed, and a robot with no token is not renewed either.
    #[tokio::test]
    async fn a_fresh_token_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let account = Account::new(store.clone(), Config::at("http://127.0.0.1:1"));

        assert!(!account.refresh_if_due().await.unwrap(), "signed out");

        store.save(&token("fresh")).unwrap();
        assert!(!account.refresh_if_due().await.unwrap(), "plenty of time");

        // No refresh token: nothing to renew with, and it must not be an error — the robot is
        // signed in and working, it just cannot renew unattended.
        store
            .save(&Stored {
                refresh_token: None,
                expires_at: Some(now_secs() + 60),
                ..token("expiring")
            })
            .unwrap();
        assert!(!account.refresh_if_due().await.unwrap());
    }

    /// Two logins arriving together: one starts, the other is told the robot is busy.
    ///
    /// The guard has to cover the round trip to `/oauth/device`, not just the check before it —
    /// two codes handed out means two pollers, and the store then holds whichever approval landed
    /// last while somebody stares at the other code wondering why it did nothing.
    #[tokio::test]
    async fn two_logins_at_once_do_not_both_reach_hugging_face() {
        let dir = tempfile::tempdir().unwrap();
        let hf = fake_hf_slow_device().await;
        let account = account_at(store_in(&dir), &hf.base);

        let (first, second) = tokio::join!(account.login(false), account.login(false));

        let outcomes = [first, second];
        assert_eq!(
            outcomes.iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one login starts: {outcomes:?}"
        );
        let refusal = outcomes
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("the other is refused");
        assert!(
            matches!(refusal, Error::LoginInFlight),
            "and refused as busy, which is a state that passes: {refusal:?}"
        );
        assert!(
            refusal.to_string().contains("account status"),
            "and it says where the code that already exists can be read: {refusal}"
        );
        assert_eq!(
            hf.hits(),
            1,
            "one device code asked for, so there is only one code to read"
        );
    }

    /// `force` abandons a code nobody is going to approve.
    ///
    /// Without this the only ways past a live code are waiting five minutes and `logout`, and
    /// `logout` destroys a working credential to clear a *pending* one. The refusal has to name a
    /// way through it, and this is that way.
    #[tokio::test]
    async fn force_replaces_a_login_that_is_still_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let hf = fake_hf_slow_device().await;
        let account = account_at(store_in(&dir), &hf.base);

        let first = account.login(false).await.expect("the first login starts");
        assert_eq!(hf.hits(), 1);

        let refused = account
            .login(false)
            .await
            .expect_err("a live code refuses a second login");
        assert!(matches!(refused, Error::LoginInFlight), "{refused:?}");
        assert!(
            refused.to_string().contains("force"),
            "and says how to get past itself: {refused}"
        );

        account.login(true).await.expect("`force` gets past it");
        assert_eq!(hf.hits(), 2, "a new code was asked for");
        let waiting = account
            .status()
            .await
            .login
            .expect("one login is in flight");
        assert_eq!(
            waiting.user_code, first.user_code,
            "this fake answers with one code, so what is pinned here is that `status` describes \
             the current login and not a stale one"
        );
    }

    /// An approval that lands after `logout` is dropped, not written.
    ///
    /// The flow lives in a task that outlives the call that started it, so signing out while a
    /// code is live leaves somebody able to approve it a minute later. Writing that would sign
    /// the robot back in on its own, which is the one thing `logout` has to be able to promise it
    /// will not do.
    #[tokio::test]
    async fn a_login_approved_after_logout_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let hf = fake_hf_full(0).await;
        let account = account_at(store.clone(), &hf.base);

        account.login(false).await.expect("a login starts");
        account.logout().await.expect("and is signed out under it");

        // The fake approves on the first poll, one second in. Well past that, and nothing has
        // been written: the flow saw itself superseded before it touched the store.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert!(
            hf.hits() >= 1,
            "the abandoned flow did reach the token endpoint"
        );
        assert!(
            store.load().is_none(),
            "a robot signed out must stay signed out"
        );
        let status = account.status().await;
        assert!(status.account.is_none());
        assert!(status.login.is_none());
    }

    /// An approved token is not thrown away because `/oauth/userinfo` failed.
    ///
    /// By the time this runs somebody has typed a code into a phone. Losing the credential over
    /// the *label* would make them do all of it again, and on the board this is for — one whose
    /// network is the reason the call failed — quite possibly twice. So the name is optional, and
    /// the next `maintain` pass is what fills it in.
    #[tokio::test]
    async fn an_approved_token_survives_a_userinfo_failure() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let approved = || TokenResponse {
            access_token: "approved".into(),
            refresh_token: Some("refresh-1".into()),
            expires_in: Some(2_591_999),
        };

        let broken = fake_hf_userinfo("<html>502 Bad Gateway</html>", 502).await;
        let account = Account::new(store.clone(), Config::at(&broken.base));
        let named = account
            .persist(&http_client(account.config()).unwrap(), approved())
            .await
            .expect("a name that cannot be read is not a failed login");
        assert!(named.is_none());

        let stored = store.load().expect("the credential is on disk regardless");
        assert_eq!(stored.access_token, "approved");
        assert_eq!(stored.refresh_token.as_deref(), Some("refresh-1"));
        assert!(stored.username.is_none(), "the name is what is missing");
        assert_eq!(
            account.status().await.account.unwrap().username,
            "unknown",
            "a client is told the robot belongs to somebody it cannot name, not that it is \
             signed out"
        );

        // And the next pass names it, without touching the credential.
        let working = fake_hf_userinfo(r#"{"preferred_username":"PierreRouanet"}"#, 200).await;
        let account = Account::new(store.clone(), Config::at(&working.base));
        assert!(account.name_if_unknown().await.unwrap());
        let stored = store.load().unwrap();
        assert_eq!(stored.username.as_deref(), Some("PierreRouanet"));
        assert_eq!(
            stored.access_token, "approved",
            "the backfill writes the name and nothing else"
        );
        assert!(
            !account.name_if_unknown().await.unwrap(),
            "and asks nobody once it knows — this runs every six hours forever"
        );
    }

    /// A token near the end of its life is renewed, and **the rotated refresh token replaces the
    /// one that was spent**.
    ///
    /// The rotation is the part worth a test rather than a comment: Hugging Face spends the old
    /// refresh token on every refresh, so storing the one already on disk — the obvious mistake,
    /// since the rest of the record is carried over — leaves a robot that renews exactly once and
    /// then quietly stops being reachable.
    #[tokio::test]
    async fn a_due_token_is_renewed_and_the_rotation_lands_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        // Six days left: inside the default `refresh_when_under`, which is how a board with a
        // marginal network gets a week of retries instead of one last day.
        store
            .save(&Stored {
                expires_at: Some(now_secs() + 6 * 24 * 60 * 60),
                ..token("spent")
            })
            .unwrap();

        let hf = fake_hf_token(
            r#"{"access_token":"renewed","refresh_token":"refresh-2","expires_in":2591999}"#,
        )
        .await;
        let account = Account::new(store.clone(), Config::at(&hf.base));

        assert!(
            account.refresh_if_due().await.unwrap(),
            "a token with six days left is due"
        );

        let stored = store.load().unwrap();
        assert_eq!(stored.access_token, "renewed");
        assert_eq!(
            stored.refresh_token.as_deref(),
            Some("refresh-2"),
            "the answer's refresh token, not the one it was traded for"
        );
        assert_eq!(
            stored.username.as_deref(),
            Some("PierreRouanet"),
            "kept rather than re-asked: a refresh cannot change who a token belongs to, and this \
             path runs unattended"
        );
        assert!(
            stored.expires_in() > 29 * 24 * 60 * 60,
            "the new expiry is absolute and thirty days out: {}",
            stored.expires_in()
        );
        assert_eq!(
            hf.grants(),
            vec!["refresh_token".to_string()],
            "one refresh, sent as a refresh"
        );

        // And now it is not due again, which is what stops `maintain` renewing on every tick.
        assert!(!account.refresh_if_due().await.unwrap());
        assert_eq!(hf.grants().len(), 1, "no second round trip");
    }

    /// A refresh Hugging Face refuses leaves the credential alone and says so in `status`.
    ///
    /// This is the visible half of the window that cannot be closed: once the old refresh token
    /// is spent, no ordering here can recover it, so what the code owes is (a) not making it
    /// worse by writing a half-record and (b) telling somebody. `maintain` is what turns the
    /// error into an answer a client can read, so it is driven here rather than trusted.
    #[tokio::test]
    async fn a_refused_refresh_is_left_alone_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store
            .save(&Stored {
                expires_at: Some(now_secs() + 60 * 60),
                ..token("spent")
            })
            .unwrap();

        let hf = fake_hf_token(
            r#"{"error":"invalid_grant","error_description":"refresh token is expired"}"#,
        )
        .await;
        let account = Arc::new(Account::new(
            store.clone(),
            Config {
                // A loop that slept six hours between passes would not report inside this test.
                maintain_interval: Duration::from_millis(10),
                ..Config::at(&hf.base)
            },
        ));

        let error = account
            .refresh_if_due()
            .await
            .expect_err("a refused refresh is an error");
        assert!(
            error.to_string().contains("invalid_grant"),
            "the reason has to survive to the surface: {error}"
        );
        assert_eq!(
            store.load().unwrap().access_token,
            "spent",
            "the stored credential is untouched — an hour of access left is worth more than a \
             record half-replaced by a failed refresh"
        );

        let task = tokio::spawn(maintain(Arc::clone(&account)));
        let mut reported = None;
        for _ in 0..200 {
            if let Some(why) = account.status().await.last_error {
                reported = Some(why);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort();
        let reported = reported.expect("`maintain` must put the failure where a client can see it");
        assert!(
            reported.contains("invalid_grant"),
            "`status` is where somebody asks why remote access stopped: {reported}"
        );
    }

    // ── a stand-in for huggingface.co ────────────────────────────────────────

    /// A one-route stand-in for huggingface.co.
    struct FakeHf {
        base: String,
        /// Every `grant_type` the token endpoint was asked for, in order. Empty for a fake that
        /// does not serve `/oauth/token`.
        grants: Arc<std::sync::Mutex<Vec<String>>>,
        /// How many times the route under test was asked, for the tests where *once* is the
        /// property rather than the answer.
        hits: Arc<std::sync::atomic::AtomicUsize>,
        _task: tokio::task::JoinHandle<()>,
    }

    impl FakeHf {
        fn grants(&self) -> Vec<String> {
            self.grants.lock().unwrap().clone()
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    #[derive(Default)]
    struct Records {
        grants: Arc<std::sync::Mutex<Vec<String>>>,
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn serve(app: axum::Router, records: Records) -> FakeHf {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        FakeHf {
            base,
            grants: records.grants,
            hits: records.hits,
            _task: task,
        }
    }

    async fn fake_hf(device_response: &'static str) -> FakeHf {
        use axum::routing::post;

        let app = axum::Router::new().route(
            "/oauth/device",
            post(move || async move { ([("content-type", "application/json")], device_response) }),
        );
        serve(app, Records::default()).await
    }

    /// A stand-in for the token endpoint alone, which is all a refresh touches.
    ///
    /// It records the `grant_type` it was asked for, because a refresh sent as a device-code
    /// grant would be refused by Hugging Face and by nobody here.
    async fn fake_hf_token(answer: &'static str) -> FakeHf {
        use axum::routing::post;

        let records = Records::default();
        let seen = Arc::clone(&records.grants);
        let app = axum::Router::new().route(
            "/oauth/token",
            post(
                move |axum::extract::Form(form): axum::extract::Form<
                    std::collections::HashMap<String, String>,
                >| {
                    let seen = Arc::clone(&seen);
                    async move {
                        seen.lock()
                            .unwrap()
                            .push(form.get("grant_type").cloned().unwrap_or_default());
                        ([("content-type", "application/json")], answer)
                    }
                },
            ),
        );
        serve(app, records).await
    }

    /// A stand-in for `/oauth/userinfo` alone, answering with whatever status is asked for.
    async fn fake_hf_userinfo(answer: &'static str, status: u16) -> FakeHf {
        use axum::routing::get;

        let code = axum::http::StatusCode::from_u16(status).unwrap();
        let app = axum::Router::new().route(
            "/oauth/userinfo",
            get(move || async move { (code, [("content-type", "application/json")], answer) }),
        );
        serve(app, Records::default()).await
    }

    /// A device endpoint that takes its time, and counts how often it was asked.
    ///
    /// The delay is the point: the window two logins race for is exactly this round trip, so a
    /// fake that answered instantly would leave the test passing for the wrong reason.
    async fn fake_hf_slow_device() -> FakeHf {
        use axum::routing::post;

        let records = Records::default();
        let hits = Arc::clone(&records.hits);
        let app = axum::Router::new().route(
            "/oauth/device",
            post(move || {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    (
                        [("content-type", "application/json")],
                        r#"{"device_code":"device-abc","user_code":"A6MY-0314",
                            "verification_uri":"https://hf.co/oauth/device",
                            "expires_in":60,"interval":1}"#,
                    )
                }
            }),
        );
        serve(app, records).await
    }

    /// A whole fake Hugging Face: a device code, a token, and a name.
    ///
    /// `approve_after` is how many `authorization_pending` answers to give first; `0` approves on
    /// the first poll, which is what the tests about *abandoning* a login want — the approval has
    /// to land while the test is still watching.
    async fn fake_hf_full(approve_after: usize) -> FakeHf {
        use axum::routing::{get, post};

        let records = Records::default();
        let polls = Arc::clone(&records.hits);
        let app = axum::Router::new()
            .route(
                "/oauth/device",
                post(|| async {
                    (
                        [("content-type", "application/json")],
                        r#"{"device_code":"device-abc","user_code":"A6MY-0314",
                            "verification_uri":"https://hf.co/oauth/device",
                            "expires_in":60,"interval":1}"#,
                    )
                }),
            )
            .route(
                "/oauth/token",
                post(move || {
                    let polls = Arc::clone(&polls);
                    async move {
                        let n = polls.fetch_add(1, Ordering::SeqCst);
                        let body = if n < approve_after {
                            r#"{"error":"authorization_pending"}"#
                        } else {
                            r#"{"access_token":"approved","refresh_token":"refresh-1",
                                "expires_in":2591999}"#
                        };
                        ([("content-type", "application/json")], body)
                    }
                }),
            )
            .route(
                "/oauth/userinfo",
                get(|| async {
                    (
                        [("content-type", "application/json")],
                        r#"{"preferred_username":"PierreRouanet"}"#,
                    )
                }),
            );
        serve(app, records).await
    }
}
