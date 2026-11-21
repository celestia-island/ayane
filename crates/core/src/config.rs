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
        Ok(Self {
            listen,
            log_filter,
            state_dir,
            admin_token,
            compose_file,
        })
    }

    /// Path of the embedded store database.
    #[must_use]
    pub fn store_path(&self) -> PathBuf {
        self.state_dir.join("store").join("ayane.redb")
    }
}
