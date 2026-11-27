//! Process configuration.
//!
//! Every knob is an environment variable so the container image stays
//! configuration-free: the deployment layer (compose / systemd) passes values,
//! the control plane stores everything else in its embedded store.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ayane_smtpd::ListenerRole;

/// Default bind address for local development.
///
/// The port is a *candidate*: the deployment ledger assigns the real one when
/// the service is deployed, and `AYANE_LISTEN` overrides it there.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3023);

/// Default on-disk state location (store database, rendered config, maildirs
/// are all rooted here in a single-host dev deployment).
pub const DEFAULT_STATE_DIR: &str = "state";

/// Default compose file of the **retired** Postfix/Dovecot rig.
///
/// Nothing in this process reads it any more (the mail service is
/// [`ayane_smtpd`](crate::engine)), but `AYANE_COMPOSE_FILE` still names it so
/// an existing deployment's environment file keeps parsing, and so the dev rig
/// (`just engine-up`) has one knob rather than two.
pub const DEFAULT_COMPOSE_FILE: &str = "deploy/docker-compose.yml";

/// The spool, as a sibling of the mail root — never inside it.
///
/// The two are separate roots because a maildir's `tmp/`, `new/`, `cur/` and
/// `corrupt/` are the spool's own directory names: a spool *inside* the mail
/// root is the failure block ⑤ taught, and
/// [`Deliverer::check_roots`](ayane_smtpd::Deliverer::check_roots) refuses it.
pub const DEFAULT_SPOOL_DIR: &str = "spool";

/// Where delivered mail lands, as a sibling of the spool.
pub const DEFAULT_MAIL_ROOT: &str = "mail";

/// Default IMAP endpoint (prod publishes Dovecot's plaintext listener on the
/// host loopback only — the read path is a client of the engine).
pub const DEFAULT_IMAP: &str = "127.0.0.1:143";

/// Default submission endpoint (dev). The prod rig exposes a dedicated
/// loopback-only plaintext submission listener (10587) for the control
/// plane; the public 587/465 enforce TLS for human clients.
pub const DEFAULT_SUBMISSION: &str = "127.0.0.1:587";

/// One SMTP listener the mail service binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailListener {
    /// `inbound` (port 25 posture), `submission` (587 with STARTTLS) or
    /// `submissions-tls` (465, implicit TLS).
    pub role: ListenerRole,
    /// The address to bind.
    pub listen: SocketAddr,
    /// The role's name, kept as written for error text.
    pub role_name: String,
    /// The certificate chain (PEM) this listener presents.
    pub tls_cert: Option<PathBuf>,
    /// The private key for [`MailListener::tls_cert`].
    pub tls_key: Option<PathBuf>,
}

/// The mail service's configuration: the part of the process that speaks SMTP.
///
/// Off unless [`MailConfig::enabled`] was asked for
/// (`AYANE_MAIL_ENABLED=1`). The default value is inert: no listener, no spool,
/// no roots — a process started without it behaves exactly as the control plane
/// did before the mail engine existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailConfig {
    /// Whether the mail service runs in this process at all.
    pub enabled: bool,
    /// The name in the greeting, `Received:` and the DMARC `authserv-id`.
    pub hostname: String,
    /// The listeners to bind, in order.
    pub listeners: Vec<MailListener>,
    /// Where messages await delivery (default `state/spool`).
    pub spool_root: PathBuf,
    /// Where delivered mail lands (default `state/mail`).
    pub mail_root: PathBuf,
    /// The state snapshot the delivery consumer and the outbound signers read
    /// (default `state/desired-state.json`, written by every apply).
    ///
    /// It must be the file the apply writes — under `AYANE_STATE_DIR`, named
    /// [`crate::apply::SNAPSHOT_PATH`]. A value anywhere else is refused at
    /// start (degraded, cause `state_path`): a consumer reading a file nothing
    /// writes routes by a table that never changes, and every apply would
    /// silently reach the listener and not the delivery.
    pub state_path: PathBuf,
    /// The `SIZE` ceiling for a message.
    pub max_message_size: u64,
    /// The header-section bound.
    pub max_header_bytes: u64,
    /// Concurrent connections per client address.
    pub per_ip_limit: usize,
    /// The retry horizon (RFC 5321 §4.5.4.1 says five days).
    pub retry_max_age_seconds: u64,
    /// The attempt cap (`0` = the policy's own cap).
    pub retry_max_attempts: u32,
    /// The per-mailbox quota, `0` for none.
    pub quota_bytes: u64,
    /// How long the delivery loop sleeps between passes when nothing is due.
    pub delivery_interval_seconds: u64,
    /// Whether remote recipients leave the machine over SMTP.
    pub outbound: bool,
    /// The port the outbound transport connects to (25, the MX default).
    pub smtp_port: u16,
    /// The environment variable template each domain's DKIM key is read from
    /// (`{domain}`, dots spelled `_`).
    pub dkim_key_env: Option<String>,
    /// Whether a mail service that cannot start stops the *process*.
    ///
    /// Off by default: the control plane keeps serving and
    /// `/api/health` carries the reason ([`crate::engine::MailDegraded`]). A
    /// deployment that wants its supervisor to see a failed start as a failed
    /// process sets `AYANE_MAIL_REQUIRE_START=1`.
    pub require_start: bool,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hostname: "localhost".to_owned(),
            listeners: Vec::new(),
            // `state/spool` and `state/mail`: siblings, never nested, which is
            // what `check_roots` insists on. The paths are resolved against
            // `AYANE_STATE_DIR` by `from_env`, so this default is the
            // *relative* form.
            spool_root: PathBuf::from(DEFAULT_STATE_DIR).join(DEFAULT_SPOOL_DIR),
            mail_root: PathBuf::from(DEFAULT_STATE_DIR).join(DEFAULT_MAIL_ROOT),
            state_path: PathBuf::from(DEFAULT_STATE_DIR).join("desired-state.json"),
            max_message_size: 25 * 1024 * 1024,
            max_header_bytes: ayane_smtpd::server::DEFAULT_MAX_HEADER_BYTES,
            per_ip_limit: 8,
            retry_max_age_seconds: 5 * 24 * 3600,
            retry_max_attempts: 0,
            quota_bytes: 0,
            delivery_interval_seconds: 30,
            outbound: false,
            smtp_port: ayane_smtpd::outbound::SMTP_PORT,
            dkim_key_env: None,
            require_start: false,
        }
    }
}

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
    /// `AYANE_MAIL_LISTEN` names a listener that is not `role@addr`.
    #[error("AYANE_MAIL_LISTEN `{value}` is not `role@addr` (roles: inbound, submission, submissions-tls)")]
    MailListen {
        /// The raw value.
        value: String,
    },
    /// A `AYANE_MAIL_*` numeric knob is not a number.
    #[error("AYANE_MAIL_{name} `{value}` is not a number")]
    MailNumber {
        /// The knob's name, without the prefix.
        name: &'static str,
        /// The raw value.
        value: String,
    },
    /// `AYANE_MAIL_ENABLED` is not a boolean.
    #[error("AYANE_MAIL_ENABLED `{value}` is not `1`/`0`/`true`/`false`")]
    MailEnabled {
        /// The raw value.
        value: String,
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
    /// The mail service (listeners, spool, delivery, outbound); disabled by
    /// default.
    pub mail: MailConfig,
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
        let mail = mail_from_env(&state_dir)?;
        Ok(Self {
            listen,
            log_filter,
            state_dir,
            admin_token,
            compose_file,
            imap,
            submission,
            cert_file,
            mail,
        })
    }

    /// Path of the embedded store database.
    #[must_use]
    pub fn store_path(&self) -> PathBuf {
        self.state_dir.join("store").join("ayane.redb")
    }
}

/// The mail section, read from the `AYANE_MAIL_*` variables.
///
/// Every path defaults to a sibling under `state_dir`, so a deployment that
/// turns the mail service on and says nothing else gets a coherent
/// single-host layout — spool and mail root apart, snapshot where the apply
/// loop writes it.
fn mail_from_env(state_dir: &Path) -> Result<MailConfig, ConfigError> {
    let mut mail = MailConfig::default();
    if let Ok(raw) = std::env::var("AYANE_MAIL_ENABLED") {
        mail.enabled = match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" | "" => false,
            _ => return Err(ConfigError::MailEnabled { value: raw }),
        };
    }
    mail.hostname = std::env::var("AYANE_MAIL_HOSTNAME").unwrap_or(mail.hostname);
    mail.spool_root = path_or(
        std::env::var("AYANE_MAIL_SPOOL_ROOT").ok(),
        state_dir,
        DEFAULT_SPOOL_DIR,
    );
    mail.mail_root = path_or(
        std::env::var("AYANE_MAIL_ROOT").ok(),
        state_dir,
        DEFAULT_MAIL_ROOT,
    );
    mail.state_path = path_or(
        std::env::var("AYANE_MAIL_STATE").ok(),
        state_dir,
        "desired-state.json",
    );
    if let Ok(raw) = std::env::var("AYANE_MAIL_LISTENERS") {
        for entry in raw.split(',').filter(|entry| !entry.trim().is_empty()) {
            mail.listeners.push(parse_listener(entry)?);
        }
    }
    mail.max_message_size = number("MAX_MESSAGE_SIZE", mail.max_message_size)?;
    mail.max_header_bytes = number("MAX_HEADER_BYTES", mail.max_header_bytes)?;
    mail.per_ip_limit = number::<usize>("PER_IP_LIMIT", mail.per_ip_limit)?;
    mail.retry_max_age_seconds = number("RETRY_MAX_AGE_SECONDS", mail.retry_max_age_seconds)?;
    mail.retry_max_attempts = number("RETRY_MAX_ATTEMPTS", mail.retry_max_attempts)?;
    mail.quota_bytes = number("QUOTA_BYTES", mail.quota_bytes)?;
    mail.delivery_interval_seconds =
        number("DELIVERY_INTERVAL_SECONDS", mail.delivery_interval_seconds)?;
    mail.smtp_port = number("SMTP_PORT", mail.smtp_port)?;
    if let Ok(raw) = std::env::var("AYANE_MAIL_OUTBOUND") {
        mail.outbound = matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    mail.dkim_key_env = std::env::var("AYANE_MAIL_DKIM_KEY_ENV").ok();
    if let Ok(raw) = std::env::var("AYANE_MAIL_REQUIRE_START") {
        mail.require_start = matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    Ok(mail)
}

/// A path from the environment, or `state_dir/leaf`.
fn path_or(value: Option<String>, state_dir: &Path, leaf: &str) -> PathBuf {
    match value {
        Some(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => state_dir.join(leaf),
    }
}

/// A numeric knob, or its default when unset.
fn number<T: std::str::FromStr>(name: &'static str, default: T) -> Result<T, ConfigError> {
    match std::env::var(format!("AYANE_MAIL_{name}")) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse()
            .map_err(|_| ConfigError::MailNumber { name, value: raw }),
        _ => Ok(default),
    }
}

/// `role@addr` (with optional `,cert=…,key=…` for a TLS role).
fn parse_listener(entry: &str) -> Result<MailListener, ConfigError> {
    let entry = entry.trim();
    let mut parts = entry.split('@');
    let role_name = parts.next().unwrap_or_default().trim().to_owned();
    let rest = parts.next().unwrap_or_default().trim().to_owned();
    if rest.is_empty() {
        return Err(ConfigError::MailListen {
            value: entry.to_owned(),
        });
    }
    let role = match role_name.as_str() {
        "inbound" => ListenerRole::Inbound,
        "submission" => ListenerRole::Submission,
        "submissions-tls" | "submissions" => ListenerRole::SubmissionsTls,
        _ => {
            return Err(ConfigError::MailListen {
                value: entry.to_owned(),
            })
        }
    };
    // `addr[,cert=PATH][,key=PATH]`
    let mut fields = rest.split(',');
    let address = fields.next().unwrap_or_default().trim();
    let listen = address.parse().map_err(|_| ConfigError::MailListen {
        value: entry.to_owned(),
    })?;
    let mut tls_cert = None;
    let mut tls_key = None;
    for field in fields {
        let field = field.trim();
        if let Some(value) = field.strip_prefix("cert=") {
            tls_cert = Some(PathBuf::from(value));
        } else if let Some(value) = field.strip_prefix("key=") {
            tls_key = Some(PathBuf::from(value));
        } else if !field.is_empty() {
            return Err(ConfigError::MailListen {
                value: entry.to_owned(),
            });
        }
    }
    Ok(MailListener {
        role,
        listen,
        role_name,
        tls_cert,
        tls_key,
    })
}
