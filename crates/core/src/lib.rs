//! ayane — the control plane of the Celestia mail service.
//!
//! The crate owns the HTTP surface and the process lifecycle. Routing rules
//! live in `ayane-mail`, the generated daemon configuration lives in
//! `ayane-engine`, the shared data model in `ayane-proto` and persistence in
//! `ayane-store`.
//!
//! ayane never speaks SMTP or IMAP as a server. Postfix, Dovecot and rspamd
//! are separate processes; this service renders their configuration, drives
//! their reloads and serves the management API.

pub mod api;
pub mod apply;
pub mod config;
pub mod driver;
pub mod rpc;
pub mod session;
pub mod state;
pub mod transport;

use serde::Serialize;
use state::AppState;

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

impl Default for Health {
    fn default() -> Self {
        Self {
            service: "ayane",
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            engine: Engine::default(),
        }
    }
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

impl Default for Engine {
    fn default() -> Self {
        Self {
            mta: "postfix",
            imap: "dovecot",
            filter: "rspamd",
        }
    }
}

/// Build the HTTP application.
///
/// Kept separate from the binary entry point so tests can drive it with
/// `tower` without binding a socket.
pub fn app(state: AppState) -> axum::Router {
    api::router(state)
}
