//! Process configuration.
//!
//! Every knob is an environment variable so the container image stays
//! configuration-free: the deployment layer (compose / systemd) passes values,
//! the control plane stores everything else in PostgreSQL.

use std::net::SocketAddr;

/// Default bind address for local development.
///
/// The port is a *candidate*: the deployment ledger assigns the real one when
/// the service is deployed, and `AYANE_LISTEN` overrides it there.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3023);

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
    /// Control-plane database URL; absent in a bare skeleton run.
    pub database_url: Option<String>,
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
        let database_url = std::env::var("AYANE_DATABASE_URL").ok();
        Ok(Self {
            listen,
            log_filter,
            database_url,
        })
    }
}
