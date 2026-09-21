# hf-robot-account

[![crates.io](https://img.shields.io/crates/v/hf-robot-account.svg)](https://crates.io/crates/hf-robot-account)
[![docs.rs](https://docs.rs/hf-robot-account/badge.svg)](https://docs.rs/hf-robot-account)
[![CI](https://github.com/pollen-robotics/hf-robot-account/actions/workflows/ci.yml/badge.svg)](https://github.com/pollen-robotics/hf-robot-account/actions/workflows/ci.yml)

Sign a browserless device in to a Hugging Face account, and keep it signed in.

Unix only, and Rust 1.88 or newer — `rust-version` in the manifest is the promise, and CI holds
it to a build on exactly that toolchain.

```toml
[dependencies]
hf-robot-account = "0.1"
```

```rust,no_run
use std::sync::Arc;
use hf_robot_account::{Account, Config, FileStore, maintain};

#[tokio::main]
async fn main() -> Result<(), hf_robot_account::Error> {
    let store = FileStore::at("/etc/robot/hf-token").readable_by_group("robot");
    let account = Arc::new(Account::new(store, Config::from_env()));

    // Renew the token for as long as this process runs.
    tokio::spawn(maintain(Arc::clone(&account)));

    let code = account.login(false).await?;
    println!("Open {} and type {}", code.verification_uri, code.user_code);
    Ok(())
}
```

`login` answers with a code and returns. The polling runs in a task the crate owns, so the client
that asked is free to disconnect — it comes back to `account.status()` to find out what happened.

## Why the device grant

A robot has no browser. Authorization code + PKCE points a redirect URI at an HTTP server on the
robot, which needs a redirect URI registered per hostname and a browser that can resolve and reach
the robot — so signing in requires being on the robot's network with mDNS working, and the robot
is not even the party that authenticates.

RFC 8628 inverts that. The robot asks for a code, somebody types it into a browser anywhere, and
the robot polls. A phone on cellular is fine. It is also the only one of the two that yields a
refresh token, which is what keeps a robot signed in past its first month.

The cost is that somebody types eight characters.

## Two things a caller must get right

**Show the code.** Hugging Face sends no `verification_uri_complete`, and its device page ignores
`?user_code=` — so no URL carries the code and displaying it is the caller's whole job. Whether to
*also* open a browser is a property of the surface, not a rule: a terminal keeps the code in the
scrollback and can open one, a phone app must not, because the browser replaces the only screen
and the code is gone before it was read.

**Expect the client to vanish mid-flow.** Opening the Hugging Face page backgrounds a phone app,
and iOS then tears a Bluetooth link down. By that point the daemon is polling and the client comes
back to `status`, which carries the code so a client that lost track of one rejoins it rather than
starting another.

## The credential

`FileStore` writes JSON through a temp file opened `0600` and renamed, then gives it to a named
group if one was asked for. It is never briefly world-readable, and a group that does not exist —
or one this process may not chown to — is a warning and a private file, never a lost token.

A second, unprivileged process reads the token with `read_access_token(path)` and links nothing
else. One key at one level is the whole contract between the writer and the reader, and a test
here pins it.

```text
/etc/robot/hf-token   root:robot 0640
{"access_token": "...", "refresh_token": "...", "expires_at": 1788000000, "username": "..."}
```

Tokens last 30 days and **the refresh token rotates on every refresh**. `maintain` renews when
under a week is left, which leaves a week of retries on a board with a marginal network. One
window cannot be closed: a power cut between the server issuing a new pair and the pair reaching
the disk leaves a credential that cannot be renewed. It surfaces in `Status::last_error` and is
fixed by signing in again.

`logout` **forgets rather than revokes**. The file goes, so the robot stops being able to prove it
belongs to anybody; the token itself stays valid at Hugging Face until it expires, for anything
that read the file while it was there.

## Scopes

`Config::default()` authenticates as `HUGGINGFACE_CLIENT_ID` — the first-party public device-code
client `huggingface_hub` ships, which is what `hf auth login` uses. It needs no OAuth app
registered anywhere, and it works on a robot that has never met its manufacturer.

**It takes no `scope` parameter**, so the token it issues carries everything Hugging Face grants:
`write-repos`, `manage-repos`, `jobs`, `read-billing`. A robot holding that can push to its
owner's repositories, for a credential whose whole job is proving an identity.

Register a **public** device-code client to your own org with `openid profile read-repos` and set
`Config::client_id`. It is one constant here and one click by an org admin, and it is the right
thing to do before a robot ships. A *confidential* client will not work: Hugging Face refuses the
device grant for one unless it is given the secret, and a secret baked into every robot is not a
secret.

## Pointing it somewhere else

`Config::from_env()` honours `HF_ENDPOINT`, the same variable `huggingface_hub` reads, so a board
pointed at a mirror for one reason is pointed at it for all of them. `Config::at(url)` sets it
directly, which is what the tests do.

## License

Apache-2.0
