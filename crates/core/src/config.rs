//! Process configuration.
//!
//! Every knob is an environment variable so the container image stays
//! configuration-free: the deployment layer (compose / systemd) passes values,
//! the control plane stores everything else in its embedded store.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Default bind address for local development.
///
/// The port is a *candidate*: the deployment ledger assigns the real one when
/// the service is deployed, and `AYANE_LISTEN` overrides it there.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3023);

/// Default on-disk state location (store database, rendered config, maildirs
/// are all rooted here in a single-host dev deployment).
pub const DEFAULT_STATE_DIR: &str = "state";

/// Default compose file driving the engine containers.
pub const DEFAULT_COMPOSE_FILE: &str = "deploy/docker-compose.yml";

/// Default IMAP endpoint (prod publishes Dovecot's plaintext listener on the
/// host loopback only — the read path is a client of the engine).
pub const DEFAULT_IMAP: &str = "127.0.0.1:143";

/// Default submission endpoint (dev). The prod rig exposes a dedicated
/// loopback-only plaintext submission listener (10587) for the control
/// plane; the public 587/465 enforce TLS for human clients.
pub const DEFAULT_SUBMISSION: &str = "127.0.0.1:587";

/// Why the environment could not be turned into a [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `AYANE_LISTEN` is present but not a socket address.
    #[error("AYANE_LISTEN `{value}` is not a socket address")]
    Listen {
        /// The raw value.
        value: String,
        /// The parser error.
        #[source]
        source: std::net::AddrParseError,
    },
}

/// Environment-driven configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address the HTTP API binds to.
    pub listen: SocketAddr,
    /// `tracing` filter directive.
    pub log_filter: String,
    /// Root directory for the store and rendered engine configuration.
    pub state_dir: PathBuf,
    /// Bearer-style admin token protecting the management API
    /// (`X-Admin-Token`); management endpoints answer 503 while unset.
    pub admin_token: Option<String>,
    /// Compose file of the engine containers (for reloads).
    pub compose_file: PathBuf,
    /// IMAP endpoint the read path talks to.
    pub imap: String,
    /// Submission endpoint the send path talks to.
    pub submission: String,
    /// TLS certificate chain (PEM) the cert check reads: the leaf's
    /// validity drives the 域名与证书 page. Absent disables the check.
    pub cert_file: Option<PathBuf>,
}

impl Config {
    /// Read the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a variable is set but cannot be parsed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen = match std::env::var("AYANE_LISTEN") {
            Ok(raw) => raw
                .parse()
                .map_err(|source| ConfigError::Listen { value: raw, source })?,
            Err(_) => DEFAULT_LISTEN,
        };
        let log_filter =
            std::env::var("AYANE_LOG").unwrap_or_else(|_| "ayane=info,tower_http=warn".to_owned());
        let state_dir = PathBuf::from(
            std::env::var("AYANE_STATE_DIR").unwrap_or_else(|_| DEFAULT_STATE_DIR.to_owned()),
        );
        let admin_token = std::env::var("AYANE_ADMIN_TOKEN").ok();
        let compose_file = PathBuf::from(
            std::env::var("AYANE_COMPOSE_FILE").unwrap_or_else(|_| DEFAULT_COMPOSE_FILE.to_owned()),
        );
        let imap = std::env::var("AYANE_IMAP").unwrap_or_else(|_| DEFAULT_IMAP.to_owned());
        let submission =
            std::env::var("AYANE_SUBMISSION").unwrap_or_else(|_| DEFAULT_SUBMISSION.to_owned());
        let cert_file = std::env::var("AYANE_CERT_FILE").ok().map(PathBuf::from);
        Ok(Self {
            listen,
            log_filter,
            state_dir,
            admin_token,
            compose_file,
            imap,
            submission,
            cert_file,
        })
    }

    /// Path of the embedded store database.
    #[must_use]
    pub fn store_path(&self) -> PathBuf {
        self.state_dir.join("store").join("ayane.redb")
    }
}
