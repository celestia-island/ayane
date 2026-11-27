//! ayane — the control plane of the Celestia mail service.

//!
//! The crate owns the HTTP surface and the process lifecycle. Routing rules
//! live in `ayane-mail`, the generated daemon configuration lives in
//! `ayane-engine`, the shared data model in `ayane-proto` and persistence in
//! `ayane-store`.
//!
//! ayane speaks SMTP itself: the listener, the spool, the delivery consumer
//! and the outbound transport are [`ayane_smtpd`], and this crate runs them
//! ([`engine`]) when the mail section of the configuration enables them. What
//! is left of the old shape is the rendered Postfix/Dovecot map files — the
//! deployed read path still consumes those — and the management API.

pub use ayane_proto;
pub mod api;
pub mod apply;
pub mod auth;
pub mod config;
pub mod dns;
pub mod driver;
pub mod engine;
pub mod net;
pub mod rpc;
pub mod session;
pub mod state;
pub mod transport;
pub mod webui;

use serde::Serialize;
use state::AppState;

/// Health payload returned by `GET /api/health`.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Stable service identifier.
    pub service: &'static str,
    /// Liveness marker: `ok` when the process is serving its API and its mail
    /// service (if it runs one), `degraded` when the API is up but the mail
    /// service is not.
    ///
    /// The distinction is the one a supervisor and a panel need: a `degraded`
    /// process is answering — health checks should not restart it in a loop —
    /// while the reason below says what an operator has to fix.
    pub status: &'static str,
    /// Crate version, so a rollout can be verified from the outside.
    pub version: &'static str,
    /// Which daemons this instance is wired to.
    pub engine: Engine,
    /// The mail service's state, when this process was configured to run one.
    ///
    /// `None` for a process whose mail section is disabled (there is nothing to
    /// report), `Some` with `degraded: None` when it is serving, and `Some` with
    /// a reason when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailHealth>,
}

/// What `/api/health` says about the mail service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailHealth {
    /// Whether the listeners are serving.
    pub serving: bool,
    /// Why not, when [`MailHealth::serving`] is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<crate::engine::MailDegraded>,
    /// How many listeners are configured.
    pub listeners: usize,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            service: "ayane",
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            engine: Engine::default(),
            mail: None,
        }
    }
}

impl Health {
    /// The health payload for a process whose mail section is in `mail`.
    ///
    /// `mail` is `None` when the section is disabled; otherwise it is the one
    /// the process started, and `status` becomes `degraded` when it is not
    /// serving.
    #[must_use]
    pub fn with_mail(mail: Option<MailHealth>) -> Self {
        let serving = mail.as_ref().is_none_or(|mail| mail.serving);
        Self {
            status: if serving { "ok" } else { "degraded" },
            mail,
            ..Self::default()
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
