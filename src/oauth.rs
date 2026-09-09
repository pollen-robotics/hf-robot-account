//! The Hugging Face half: four requests, and the normalisation their answers need.
//!
//! These are public because they are useful on their own — a tool that wants one login and no
//! daemon can drive them directly — but [`crate::Account`] is what most callers want, because
//! the interesting part of a device flow is not the requests. It is what owns the waiting.

use serde::Deserialize;

use crate::{Config, DEFAULT_EXPIRES_IN, DEFAULT_POLL_INTERVAL, Error};

/// An HTTP client configured the way every call below expects.
///
/// Built per operation rather than held: `status` and `logout` need none at all, and the one
/// operation that polls in a loop wants a client that lives exactly as long as the loop.
pub fn http_client(config: &Config) -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .user_agent(config.user_agent.clone())
        // Redirects are followed, but not indefinitely: a redirect loop is a misconfigured
        // mirror, not something to chase.
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| Error::Network(format!("could not build HTTP client: {e}")))
}

/// A started device authorization, with the fields Hugging Face omits filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCode {
    /// The robot's half of the pair. Never shown to anybody; this is what is polled with.
    pub device_code: String,
    /// The person's half. Eight characters, typed into a browser somewhere else.
    pub user_code: String,
    /// Where to type it.
    pub verification_uri: String,
    /// See [`crate::LoginCode::verification_uri_complete`].
    pub verification_uri_complete: String,
    /// Seconds the code is good for.
    pub expires_in: u64,
    /// Seconds between polls.
    pub interval: u64,
}

/// What `POST /oauth/device` answers, before normalisation.
#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
}

/// What `POST /oauth/token` answers on success.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    /// The bearer token.
    pub access_token: String,
    /// Absent when Hugging Face issues none, which makes the token unrenewable rather than broken.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Seconds from now. Absent means the server did not say.
    #[serde(default)]
    pub expires_in: Option<u64>,
}

impl PartialEq for TokenResponse {
    fn eq(&self, other: &Self) -> bool {
        self.access_token == other.access_token
            && self.refresh_token == other.refresh_token
            && self.expires_in == other.expires_in
    }
}
impl Eq for TokenResponse {}

/// What `POST /oauth/token` answers while nobody has approved yet.
#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// One poll of the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// Nobody has approved it yet.
    Pending,
    /// The server wants a longer interval. RFC 8628 §3.5: add five seconds.
    SlowDown,
    /// Approved.
    Token(Box<TokenResponse>),
    /// The user said no, or the code ran out. Either way, start again.
    Refused(String),
    /// Anything inconclusive — a 5xx, a proxy's error page, a network blip. **Not** a failure:
    /// RFC 8628 §3.5 says keep polling until the code expires, and the deadline bounds the wait.
    Inconclusive(String),
}

/// Ask Hugging Face to start a device authorization.
pub async fn request_device_code(
    client: &reqwest::Client,
    config: &Config,
) -> Result<DeviceCode, Error> {
    let url = format!("{}/oauth/device", config.endpoint);
    let response = client
        .post(&url)
        .timeout(config.http_timeout)
        .form(&[("client_id", config.client_id.as_str())])
        .send()
        .await
        .map_err(|e| Error::Network(format!("POST {url}: {e}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| Error::Network(format!("reading {url}: {e}")))?;
    if !status.is_success() {
        return Err(Error::Network(format!(
            "POST {url}: HTTP {status}: {}",
            body.chars().take(300).collect::<String>()
        )));
    }

    let raw: DeviceCodeResponse = serde_json::from_str(&body).map_err(|e| {
        Error::Network(format!(
            "POST {url}: could not parse the device code response: {e}"
        ))
    })?;

    // Hugging Face sends neither `interval` nor `verification_uri_complete`, so both are
    // defaulted here — the same normalisation `huggingface_hub` does, in the same place, so
    // nothing downstream has to know which fields a server bothered with.
    //
    // **The fallback is the plain URI, and the code still has to be typed.** Appending
    // `?user_code=` looks obvious and is wrong: Hugging Face's device page ignores the parameter,
    // it survives the login redirect and prefills nothing, and a URL carrying a query the other
    // end drops is worse than no query because it reads like a promise the page then breaks.
    let verification_uri_complete = raw
        .verification_uri_complete
        .unwrap_or_else(|| raw.verification_uri.clone());
    Ok(DeviceCode {
        device_code: raw.device_code,
        user_code: raw.user_code,
        verification_uri: raw.verification_uri,
        verification_uri_complete,
        expires_in: raw.expires_in.unwrap_or(DEFAULT_EXPIRES_IN),
        interval: raw.interval.unwrap_or(DEFAULT_POLL_INTERVAL),
    })
}

/// Poll the token endpoint once.
///
/// Infallible by design: every way this can go wrong is one of the [`Poll`] variants, because a
/// caller polling in a loop has to decide "keep going" or "stop" and a `Result` does not carry
/// that distinction. A 5xx is not an answer about this login; `access_denied` is.
pub async fn poll_token(client: &reqwest::Client, config: &Config, device_code: &str) -> Poll {
    let url = format!("{}/oauth/token", config.endpoint);
    let response = client
        .post(&url)
        .timeout(config.http_timeout)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", config.client_id.as_str()),
            ("device_code", device_code),
        ])
        .send()
        .await;

    let response = match response {
        Ok(response) => response,
        Err(e) => return Poll::Inconclusive(format!("POST {url}: {e}")),
    };
    // A 5xx is a Hugging Face problem, not an answer about this login.
    if response.status().is_server_error() {
        return Poll::Inconclusive(format!("POST {url}: HTTP {}", response.status()));
    }
    let body = match response.text().await {
        Ok(body) => body,
        Err(e) => return Poll::Inconclusive(format!("reading {url}: {e}")),
    };

    if let Ok(token) = serde_json::from_str::<TokenResponse>(&body) {
        return Poll::Token(Box::new(token));
    }
    match serde_json::from_str::<OAuthError>(&body) {
        Ok(err) => classify(&err),
        // JSON without an `error` member, or not JSON at all: a gateway's error page. Transient.
        Err(_) => Poll::Inconclusive(format!(
            "POST {url}: unexpected answer: {}",
            body.chars().take(200).collect::<String>()
        )),
    }
}

/// Which OAuth errors end a login and which are the login working normally.
fn classify(err: &OAuthError) -> Poll {
    let detail = err
        .error_description
        .clone()
        .unwrap_or_else(|| err.error.clone());
    match err.error.as_str() {
        "authorization_pending" => Poll::Pending,
        "slow_down" => Poll::SlowDown,
        "expired_token" => Poll::Refused(
            "the code expired before it was approved — start the login again".to_string(),
        ),
        "access_denied" => Poll::Refused("the login was refused on Hugging Face".to_string()),
        // An OAuth error we do not know is still an answer about this login rather than a blip:
        // `invalid_client` and `invalid_grant` will not fix themselves by being asked again.
        other => Poll::Refused(format!("Hugging Face said {other}: {detail}")),
    }
}

/// Exchange a refresh token for a new pair.
///
/// **Hugging Face rotates the refresh token**, so the answer's is the one to keep. Storing the one
/// already on disk is the obvious mistake — the rest of the record is carried over — and it
/// leaves a robot that renews exactly once and then quietly stops being reachable.
pub async fn refresh(
    client: &reqwest::Client,
    config: &Config,
    refresh_token: &str,
) -> Result<TokenResponse, Error> {
    let url = format!("{}/oauth/token", config.endpoint);
    let response = client
        .post(&url)
        .timeout(config.http_timeout)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", config.client_id.as_str()),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(|e| Error::Network(format!("POST {url}: {e}")))?;
    let body = response
        .text()
        .await
        .map_err(|e| Error::Network(format!("reading {url}: {e}")))?;
    serde_json::from_str::<TokenResponse>(&body).map_err(|_| {
        let detail = serde_json::from_str::<OAuthError>(&body)
            .map(|e| format!("{}: {}", e.error, e.error_description.unwrap_or_default()))
            .unwrap_or_else(|_| body.chars().take(200).collect());
        Error::Network(format!("could not refresh the account token: {detail}"))
    })
}

/// Who a token belongs to.
///
/// `/oauth/userinfo` rather than decoding the `id_token`: one round trip against an endpoint that
/// is part of the flow already, versus a JWT parser and a JWKS fetch for the same string.
///
/// `preferred_username` is the handle — `PierreRouanet` — and `name` is a display name that can be
/// anything, so the handle is preferred and `name` is the fallback.
pub async fn userinfo(
    client: &reqwest::Client,
    config: &Config,
    access_token: &str,
) -> Result<String, Error> {
    #[derive(Deserialize)]
    struct UserInfo {
        preferred_username: Option<String>,
        name: Option<String>,
    }

    let url = format!("{}/oauth/userinfo", config.endpoint);
    let response = client
        .get(&url)
        .timeout(config.http_timeout)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| Error::Network(format!("GET {url}: {e}")))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| Error::Network(format!("reading {url}: {e}")))?;
    if !status.is_success() {
        return Err(Error::Network(format!("GET {url}: HTTP {status}")));
    }
    let info: UserInfo = serde_json::from_str(&body)
        .map_err(|e| Error::Network(format!("GET {url}: could not parse the answer: {e}")))?;
    info.preferred_username
        .or(info.name)
        .ok_or_else(|| Error::Network(format!("GET {url}: no username in the answer")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which OAuth errors end a login, and which are it working normally.
    ///
    /// The two in the middle are the ones worth pinning: treating `slow_down` as a failure would
    /// abandon a login that was about to succeed, and treating `expired_token` as transient would
    /// poll a dead code until the deadline.
    #[test]
    fn oauth_errors_are_classified() {
        let of = |error: &str| {
            classify(&OAuthError {
                error: error.to_string(),
                error_description: None,
            })
        };
        assert_eq!(of("authorization_pending"), Poll::Pending);
        assert_eq!(of("slow_down"), Poll::SlowDown);
        assert!(matches!(of("expired_token"), Poll::Refused(_)));
        assert!(matches!(of("access_denied"), Poll::Refused(_)));
        // An error we have never seen is still an answer about this login: `invalid_client` will
        // not fix itself by being asked again, and polling it for five minutes hides the cause.
        assert!(matches!(of("invalid_client"), Poll::Refused(_)));
    }
}
