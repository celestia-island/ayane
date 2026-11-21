//! ayane — the control plane of the Celestia mail service.
//!
//! The crate is deliberately thin at this stage: it owns the HTTP surface and
//! the process lifecycle. Routing rules live in `ayane-mail`, the generated
//! daemon configuration lives in `ayane-engine`, and the shared data model
//! lives in `ayane-proto`.
//!
//! ayane never speaks SMTP or IMAP as a server. Postfix, Dovecot and rspamd are
//! separate processes; this service renders their configuration, drives their
//! admin surfaces and serves the webmail API.

pub mod config;

use axum::{routing::get, Json, Router};
use serde::Serialize;

/// Health payload returned by `GET /api/health`.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Stable service identifier.
    pub service: &'static str,
    /// Liveness marker; anything but `ok` means the process is not usable.
    pub status: &'static str,
    /// Crate version, so a rollout can be verified from the outside.
    pub version: &'static str,
    /// Which daemons this instance is wired to.
    pub engine: Engine,
}

/// The external daemons an instance drives.
#[derive(Debug, Clone, Serialize)]
pub struct Engine {
    /// Mail transfer agent.
    pub mta: &'static str,
    /// IMAP server.
    pub imap: &'static str,
    /// Content filter (spam, DKIM, antivirus hook).
    pub filter: &'static str,
}

/// Build the HTTP application.
///
/// Kept separate from the binary entry point so tests can drive it with `tower`
/// without binding a socket.
pub fn app() -> Router {
    Router::new().route("/api/health", get(health))
}

async fn health() -> Json<Health> {
    Json(Health {
        service: "ayane",
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        engine: Engine {
            mta: "postfix",
            imap: "dovecot",
            filter: "rspamd",
        },
    })
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_reports_the_engine_stack() {
        let response = super::app()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(value["service"], "ayane");
        assert_eq!(value["status"], "ok");
        assert_eq!(value["engine"]["mta"], "postfix");
        assert_eq!(value["engine"]["filter"], "rspamd");
    }
}
