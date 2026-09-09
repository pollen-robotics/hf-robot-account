//! A stand-in for huggingface.co, serving the three routes a login touches.
//!
//! The bodies are what huggingface.co actually answered, field for field, with **one deliberate
//! deviation**: an explicit `"interval":1`, so a test that waits for a real approval takes three
//! seconds instead of fifteen. Hugging Face sends no interval and the RFC's five-second fallback
//! is what applies in the field; that the fallback is applied at all is pinned by a unit test,
//! where it costs no wall clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A running fake, torn down when it is dropped.
pub struct FakeHf {
    pub base: String,
    _task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeHf {
    fn drop(&mut self) {
        self._task.abort();
    }
}

/// A Hugging Face that answers `authorization_pending` `n` times and then approves.
pub async fn approving_after(n: usize) -> FakeHf {
    use axum::routing::{get, post};

    let polls = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route(
            "/oauth/device",
            post(|| async {
                (
                    [("content-type", "application/json")],
                    r#"{"device_code":"41ad39ae","user_code":"A6MY-0314",
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
                    let seen = polls.fetch_add(1, Ordering::SeqCst);
                    let body = if seen < n {
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
                    r#"{"name":"Rouanet","preferred_username":"PierreRouanet"}"#,
                )
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    FakeHf { base, _task: task }
}
