//! A whole login, driven the way a daemon drives one.
//!
//! The unit tests reach inside; this one is deliberately a **downstream** view — nothing but the
//! public API, against a fake Hugging Face — because that is the thing the crate boundary is for.
//! If a caller cannot sign a robot in with only what is exported here, the export list is wrong.

use std::sync::Arc;
use std::time::Duration;

use hf_robot_account::{Account, Config, FileStore, read_access_token};

mod fake_hf;

/// The shape a daemon serves: hand back a code, hang up, come back to `status`.
///
/// The hanging up is the part worth pinning. A phone that opens the Hugging Face page backgrounds
/// itself and iOS tears the transport down, so the login has to survive nobody being connected —
/// which is why `login` returns and the polling does not.
#[tokio::test]
async fn a_client_gets_a_code_hangs_up_and_comes_back_to_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hf-token");
    let hf = fake_hf::approving_after(2).await;

    let account = Arc::new(Account::new(FileStore::at(&path), Config::at(&hf.base)));

    // The client asks. It gets something to show a person, and nothing else.
    let code = account.login(false).await.expect("a login starts");
    assert_eq!(code.user_code, "A6MY-0314");
    assert_eq!(code.verification_uri, "https://hf.co/oauth/device");
    assert_eq!(
        code.verification_uri_complete, code.verification_uri,
        "no URL carries the code, so the caller must show it"
    );
    assert!(!path.exists(), "nothing is stored until somebody approves");

    // The client is gone. Something else asks, which is what a wizard does.
    let waiting = account.status().await;
    assert!(waiting.account.is_none(), "not signed in yet");
    let rejoined = waiting
        .login
        .expect("the code is in `status` so a client can rejoin it");
    assert_eq!(rejoined.user_code, code.user_code);
    assert!(
        rejoined.expires_in <= code.expires_in,
        "counted down, not repeated"
    );

    // Somebody approves it on their phone. The fake says yes on the third poll.
    let signed_in = wait_for(&account, |s| s.account.is_some())
        .await
        .expect("the daemon was doing the waiting");

    let who = signed_in.account.expect("signed in");
    assert_eq!(who.username, "PierreRouanet");
    assert!(who.refreshable, "a refresh token came with it");
    assert!(
        who.token_expires_in > 29 * 24 * 60 * 60,
        "about thirty days"
    );
    assert!(signed_in.login.is_none(), "and the code is spent");
    assert!(signed_in.last_error.is_none());

    // The other half of the contract: a second process reads the token out of the file.
    assert_eq!(
        read_access_token(&path).as_deref(),
        Some("approved"),
        "an unprivileged reader gets the token without linking any of this"
    );

    // And signing out forgets it.
    let was = account.logout().await.expect("logout");
    assert_eq!(
        was.as_deref(),
        Some("PierreRouanet"),
        "it says who it forgot"
    );
    assert_eq!(read_access_token(&path), None);
    assert!(account.status().await.account.is_none());
}

/// Poll `status` until it says something, or give up. What a client's wizard does.
async fn wait_for(
    account: &Account,
    done: impl Fn(&hf_robot_account::Status) -> bool,
) -> Option<hf_robot_account::Status> {
    for _ in 0..400 {
        let status = account.status().await;
        if done(&status) {
            return Some(status);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    None
}
