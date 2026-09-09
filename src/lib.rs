//! Sign a browserless device in to a Hugging Face account, and keep it signed in.
//!
//! A robot that only ever talks to a client on its own LAN needs no account. An account is what
//! makes one reachable from *outside* the LAN: a rendezvous service resolves a bearer token to an
//! identity, shows a client only its own robots, and the pair of those is the authorisation a
//! session arrives with. This crate owns the credential and nothing else — it neither knows nor
//! cares what the token is later presented to.
//!
//! # The flow is RFC 8628, because the device has no browser
//!
//! The obvious alternative, authorization code + PKCE, points a redirect URI at an HTTP server on
//! the robot. That needs a redirect URI registered per hostname, and a browser that can resolve
//! and reach the robot — so logging in requires being on the robot's network with mDNS working,
//! and the robot is not even the party that authenticates. It merely hosts the landing pad.
//!
//! The device grant inverts it. The robot asks Hugging Face for a code, says *"open
//! hf.co/oauth/device and type `M8HJ-FMGN`"*, and polls. No redirect URI, no hostname, and no
//! requirement that the authorising device can reach the robot at all — a phone on cellular is
//! fine. It is also the only one of the two that yields a **refresh token**, which is what keeps
//! a robot signed in past its first month.
//!
//! The cost, stated plainly: somebody types eight characters.
//!
//! # Three consequences shape this API
//!
//! - **[`Account::login`] returns a code, not a token.** The waiting happens in a task this crate
//!   spawns, and the caller comes back to [`Account::status`]. A login that reported success by
//!   holding a connection open would work from a laptop and fail from the device it is for: a
//!   phone that opens a browser backgrounds itself, and iOS then tears a GATT link down.
//! - **The caller displays the code, and the code has to be typed.** Hugging Face sends no
//!   `verification_uri_complete`, and its device page ignores `?user_code=` — so no URL carries
//!   the code, which makes showing it the caller's whole job. Whether a caller also *opens* the
//!   page is a property of the surface, not a rule: a terminal keeps the code in the scrollback
//!   and can open a browser, a phone app must not, because the browser replaces the only screen
//!   and the code is gone before it was read.
//! - **A token expires in 30 days and its refresh token rotates.** So [`maintain`] renews well
//!   before expiry, and the store is written atomically — see [`FileStore::save`] for the one
//!   window that cannot be closed.
//!
//! # Using it
//!
//! ```no_run
//! use std::sync::Arc;
//! use hf_robot_account::{Account, Config, FileStore};
//!
//! # async fn example() -> Result<(), hf_robot_account::Error> {
//! let store = FileStore::at("/etc/robot/hf-token").readable_by_group("robot");
//! let account = Arc::new(Account::new(store, Config::from_env()));
//!
//! // Renew the token for as long as this process runs.
//! tokio::spawn(maintain_for(Arc::clone(&account)));
//!
//! // A client asks to sign in: answer with the code, and let it come back to `status`.
//! let code = account.login(false).await?;
//! println!("Open {} and type {}", code.verification_uri, code.user_code);
//! # Ok(())
//! # }
//! # use hf_robot_account::maintain as maintain_for;
//! ```
//!
//! # What is deliberately not here
//!
//! **Any notion of what the token is for.** No relay, no rendezvous, no IPC. A daemon wraps these
//! four methods in whatever protocol it serves and maps [`Error`] onto whatever error codes it
//! has; this crate has no opinion about either.
//!
//! **Windows.** The credential is a file with an owner, a group and a mode; this is a Unix
//! crate, and says so rather than carrying `cfg` branches nothing compiles.
//!
//! **A `TokenStore` trait.** [`FileStore`] takes a path, an optional group and a mode, which
//! covers every difference between boards that actually exists. A robot that wants a TPM or a
//! keyring is a reason to add the trait, and adding it then is a smaller change than carrying the
//! indirection until somebody does.

#![forbid(unsafe_op_in_unsafe_fn)]

mod account;
mod oauth;
mod store;

use std::time::Duration;

pub use account::{Account, maintain};
pub use oauth::{
    DeviceCode, Poll, TokenResponse, http_client, refresh, request_device_code, userinfo,
};
pub use store::{FileStore, Stored, read_access_token};

use serde::{Deserialize, Serialize};

/// Hugging Face's first-party device-code OAuth client.
///
/// `huggingface_hub`'s `DEVICE_CODE_OAUTH_CLIENT_ID`, which is what `hf auth login` uses. Public
/// — no secret, and none can be sent: Hugging Face refuses the device grant for a *confidential*
/// client unless it is given the secret, so an OAuth app that has one cannot be used here. Its
/// being first-party is also why this crate needs no app registered anywhere and works on a robot
/// that has never met its manufacturer.
///
/// **What it costs is scopes.** This client takes no `scope` parameter, so the token it issues
/// carries everything Hugging Face grants — `write-repos`, `manage-repos`, `jobs`, `read-billing`
/// — for a credential whose whole job is proving an identity. A *public* device-code client
/// registered to your own org with `openid profile read-repos` is one [`Config::client_id`] and
/// one click by an org admin, and it is the right thing to do before a robot ships.
pub const HUGGINGFACE_CLIENT_ID: &str = "26be6b09-91c5-47da-9861-d2d2bb7a7e36";

/// Hugging Face.
pub const HUGGINGFACE: &str = "https://huggingface.co";

/// The variable `huggingface_hub` itself reads to point at a mirror. [`Config::from_env`].
pub const ENDPOINT_VAR: &str = "HF_ENDPOINT";

/// RFC 8628's fallback when the server sends no `interval`. Hugging Face sends none.
pub(crate) const DEFAULT_POLL_INTERVAL: u64 = 5;

/// RFC 8628 requires `expires_in`; defaulted defensively so a poll loop stays bounded.
pub(crate) const DEFAULT_EXPIRES_IN: u64 = 900;

/// Everything about a login that a different robot might want to change.
///
/// Constructed with `..Config::default()` rather than a builder: every field is meaningful on its
/// own, and a struct literal is the one form that shows which of them a caller actually chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Where Hugging Face is. [`HUGGINGFACE`], or a mirror.
    pub endpoint: String,
    /// Which OAuth client to authenticate as. [`HUGGINGFACE_CLIENT_ID`], or your org's own.
    pub client_id: String,
    /// Sent on every request. Name your robot here — it is what a Hub-side log will show.
    pub user_agent: String,
    /// How long one HTTP round trip to Hugging Face gets.
    pub http_timeout: Duration,
    /// Renew a token with less than this left.
    ///
    /// Hugging Face issues 30 days. The default refreshes three-quarters of the way through the
    /// token's life and leaves a week of retries, which is what a board with a marginal network
    /// needs — a robot switched off for longer than the whole 30 days cannot be saved by any
    /// margin, and comes back needing a login.
    pub refresh_when_under: Duration,
    /// How often [`maintain`] wakes to look at the token's remaining life.
    ///
    /// Slow on purpose: the thing it guards against is a robot that has been on for a month, and
    /// the cost of asking too often is a request that answers "not yet".
    pub maintain_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: HUGGINGFACE.to_string(),
            client_id: HUGGINGFACE_CLIENT_ID.to_string(),
            user_agent: concat!("hf-robot-account/", env!("CARGO_PKG_VERSION")).to_string(),
            http_timeout: Duration::from_secs(20),
            refresh_when_under: Duration::from_secs(7 * 24 * 60 * 60),
            maintain_interval: Duration::from_secs(6 * 60 * 60),
        }
    }
}

impl Config {
    /// [`Config::default`], with [`ENDPOINT_VAR`] honoured if it is set to something non-empty.
    ///
    /// Separate from `default` because a library that reads the environment behind its caller's
    /// back is a surprise, and because a test wants an endpoint that no other test can change
    /// under it. Reading `HF_ENDPOINT` specifically means a board pointed at a mirror for one
    /// reason is pointed at it for all of them.
    pub fn from_env() -> Self {
        let endpoint = std::env::var(ENDPOINT_VAR)
            .ok()
            .filter(|s| !s.trim().is_empty());
        Self {
            endpoint: endpoint.unwrap_or_else(|| HUGGINGFACE.to_string()),
            ..Self::default()
        }
    }

    /// As [`Config::default`], against a named endpoint. For tests, mostly.
    pub fn at(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Self::default()
        }
    }
}

// ── what a caller sees ───────────────────────────────────────────────────────

/// A started login: what to show somebody, and how long they have to act on it.
///
/// Everything here is meant for a person's eyes except [`interval`](Self::interval), which is the
/// server's polling cadence and is reported only so a caller can explain a wait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginCode {
    /// The eight characters somebody types. **Show this.**
    pub user_code: String,
    /// Where they type it.
    pub verification_uri: String,
    /// The URI that carries the code, where a server sends one.
    ///
    /// Hugging Face does not, so this is [`verification_uri`](Self::verification_uri) unchanged —
    /// their device page ignores a `?user_code=` query, and a URL carrying a query the other end
    /// drops reads like a promise the page then breaks. The field stays because it is the
    /// protocol's, and a server that starts sending a real one is then used without a change.
    pub verification_uri_complete: String,
    /// How long the code is good for. In [`Status`] this is what is *left*, so a caller can count
    /// it down rather than repeat the original number.
    pub expires_in: u64,
    /// Seconds between polls, as the server asked for them.
    pub interval: u64,
}

/// Who a robot belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// The Hugging Face username, as `/oauth/userinfo` reports it. What to show a person.
    ///
    /// `"unknown"` when the robot holds a token whose owner could not be read at login — a
    /// network failure on the last and least important call of the flow. [`maintain`] fills it in.
    pub username: String,
    /// Seconds until the access token expires; negative once it has, so a caller can say "this
    /// robot needs signing in again" rather than "signed in" about a credential that is dead.
    /// [`i64::MAX`] when the server named no expiry.
    pub token_expires_in: i64,
    /// Whether a refresh token was stored. `false` means this credential dies at
    /// [`token_expires_in`](Self::token_expires_in) and nothing can renew it.
    pub refreshable: bool,
}

/// Everything [`Account::status`] knows, which is everything a client needs to render a wizard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Who the robot belongs to, or `None` for a robot out of the box.
    pub account: Option<Identity>,
    /// A login waiting for approval, with the time *left* on its code.
    ///
    /// Carried here so a client that lost track of a code — a phone that backgrounded itself, a
    /// terminal somebody closed — rejoins the login in flight rather than starting another.
    pub login: Option<LoginCode>,
    /// Why the last thing that failed, failed. `None` once something works.
    ///
    /// This is where somebody looks to find out why remote access stopped, so it carries refresh
    /// failures and abandoned logins — and deliberately not a missing username, which is
    /// cosmetic and did not stop anything.
    pub last_error: Option<String>,
}

// ── errors ───────────────────────────────────────────────────────────────────

/// What can go wrong.
///
/// Four variants, and two of them are refusals rather than faults: a caller serving this over a
/// protocol will want to map [`AlreadySignedIn`](Error::AlreadySignedIn) to something meaning
/// "your request was wrong and here is the parameter that fixes it", and
/// [`LoginInFlight`](Error::LoginInFlight) to something meaning "busy, try again".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Hugging Face could not be reached, or did not answer usefully.
    #[error("{0}")]
    Network(String),

    /// The credential could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file that could not be read or written.
        path: std::path::PathBuf,
        /// What the filesystem said.
        source: std::io::Error,
    },

    /// A second login while one is still waiting for approval.
    ///
    /// Retryable, and the message says where the code that already exists can be read — two
    /// logins collide during setup, when a console page and a phone are both pointed at the same
    /// robot, and what that person needs is that a code is already out.
    #[error(
        "a login is already waiting for approval — `account status` has the code, or force to \
         start a new one"
    )]
    LoginInFlight,

    /// A login on a robot that already belongs to somebody, without `force`.
    ///
    /// A robot changing hands is common enough that the message names the account and the flag
    /// rather than leaving somebody to hunt for them.
    #[error(
        "this robot already belongs to {0}. Sign that account out first, or force to replace it"
    )]
    AlreadySignedIn(String),
}

// ── small things ─────────────────────────────────────────────────────────────

/// Seconds since the Unix epoch, or `0` on a clock that predates it.
///
/// `0` rather than a panic: a board whose RTC has not been set yet reads as "everything expired",
/// which makes a robot ask for a login it may not need — annoying, and better than a daemon that
/// will not start because the clock is wrong.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
