//! The mail service this process runs: turning the stored state into a
//! listener configuration, and the tasks that make it live.
//!
//! Until this module existed the control plane drove three containers it did
//! not own — Postfix, Dovecot and rspamd — by rendering their configuration
//! files and shelling out to `docker compose exec … reload`. The mail service
//! is now [`ayane_smtpd`]: an SMTP listener, a delivery consumer over the same
//! spool, and an outbound transport, all in this process when
//! [`crate::config::MailConfig`] is enabled.
//!
//! # What "enabled" means
//!
//! Off by default. A process started without the mail section behaves exactly
//! as it did before this module existed: no listener is bound, no spool is
//! opened, no delivery pass runs, and the driver is a
//! [`crate::driver::RecordingDriver`] that records reloads instead of
//! performing them. Turning it on is a deployment decision
//! (`AYANE_MAIL_ENABLED=1` plus the paths and listeners), which is what keeps a
//! control plane whose operator has not moved their mail yet from binding a
//! port on their behalf.
//!
//! # The two roots, and why the spool is not inside the mail root
//!
//! [`Deliverer::new`] takes a spool and a mail root and [`Deliverer::check_roots`]
//! refuses a pair that would write a maildir into the spool's own `tmp/`,
//! `new/`, `cur/` or `corrupt/` — a failure that looks like success because
//! every write appears to work. The defaults are therefore siblings
//! (`state/spool` and `state/mail`), and the check runs before the first
//! delivery pass rather than after the first message.
//!
//! # The credential check
//!
//! A submission listener authenticates against the store: the account's stored
//! hash through [`ayane_store::password::verify_password`], or a shared
//! mailbox's machine credential. The operator binary's
//! `--submission-authenticates` flag (which accepts every login) is not what
//! this process passes — a listener inside the control plane has the store, so
//! it uses it.
//!
//! # The seam that did not survive: rendered files → daemons
//!
//! The apply loop still renders Postfix-shaped maps — they are what the
//! deployed read path (Dovecot over IMAP, and the webmail that talks to it)
//! still consumes, and this block does not move them. What *did* move is who
//! acts on them: no daemon re-reads `config/postfix/virtual_domains` and no
//! `doveadm reload` runs. The listener's routing snapshot is the state itself,
//! installed by `NativeDriver::reload` ([`crate::driver::EngineDriver::reload`])
//! as a new `ServerConfig`. The rendered files are a compatibility surface;
//! the `ArcSwap` is the live one.

use std::sync::Arc;

use ayane_smtpd::authn::PasswordVerifier;
use ayane_smtpd::policy::AddressPolicy;
use ayane_smtpd::queue::Spool;
use ayane_smtpd::server::ServerConfig;
use ayane_smtpd::{Deliverer, ListenerRole, Metrics, RetryPolicy, Verifier};

use crate::config::{Config, MailConfig};
use crate::driver::{unix_now, MailControl};

/// Why the mail service could not be built or started.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// The spool could not be opened.
    #[error("spool {path}: {reason}")]
    Spool {
        /// What went wrong.
        reason: String,
        /// The root that could not be opened.
        path: std::path::PathBuf,
    },
    /// The mail root and the spool root collide.
    #[error("delivery roots: {0}")]
    Roots(String),
    /// A listener's TLS material could not be loaded, or a TLS role named none.
    #[error("tls: {0}")]
    Tls(String),
    /// The outbound transport or its DKIM keys could not be built.
    #[error("outbound: {0}")]
    Outbound(String),
    /// A required setting is missing from the configuration.
    #[error("mail.{0} is required when the mail engine is enabled")]
    Missing(&'static str),
    /// A listener could not bind its address.
    #[error("bind {addr}: {reason}")]
    Bind {
        /// What went wrong.
        reason: String,
        /// The address that could not be bound.
        addr: std::net::SocketAddr,
    },
    /// The stored state cannot be turned into a routing snapshot.
    #[error("state: {0}")]
    State(String),
}

/// The running mail service: the handles the driver needs, and the tasks that
/// make it live.
#[derive(Debug)]
pub struct RunningEngine {
    control: MailControl,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningEngine {
    /// The shared control handles (clone into a [`crate::driver::NativeDriver`]).
    #[must_use]
    pub fn control(&self) -> &MailControl {
        &self.control
    }

    /// Stops the tasks this process started (the listeners and the delivery
    /// loop). Used by tests and by a controlled shutdown; a process `exit`
    /// stops them anyway.
    pub fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

/// Starts the mail service for `config`, and the tasks that run it.
///
/// `store` is the live snapshot the listeners route by and the credential check
/// reads; the caller keeps its own handle (the API needs one too).
///
/// The three tasks are the three jobs the mail service has:
///
/// | task | what it is | cancelled by |
/// |---|---|---|
/// | listener × N | `ayane_smtpd::serve` over the bound socket | process exit |
/// | delivery | the spawn loop below: one pass, then a sleep bounded by the earliest due attempt | process exit |
///
/// The outbound transport is not a task: it is installed on the deliverer
/// ([`deliverer`]), so a message for a remote domain leaves the machine
/// inside the delivery pass that decided it was due.
///
/// # Errors
///
/// Returns [`MailError`] when a listener cannot be bound, the spool or roots
/// are unusable, the state cannot be turned into a configuration, or a
/// certificate cannot be loaded — all of them conditions a deployment has to
/// fix before it can serve mail, and none of them worth starting a
/// half-working instance over.
pub async fn start(
    config: &Config,
    store: Arc<dyn ayane_store::StateStore>,
) -> Result<RunningEngine, MailError> {
    let mail = &config.mail;
    if mail.listeners.is_empty() {
        return Err(MailError::Missing("listeners"));
    }
    if mail.hostname.trim().is_empty() || mail.hostname == "localhost" {
        // `localhost` in a greeting is a mail server that tells every peer it
        // has no name; it is the default so a *unit test* can build one, and a
        // deployment that forgot to set it is refused here rather than served.
        return Err(MailError::Missing("hostname"));
    }
    let spool_root = mail.spool_root.clone();
    let spool = Spool::open(&spool_root).map_err(|err| MailError::Spool {
        reason: err.to_string(),
        path: spool_root,
    })?;
    // A crash leaves `tmp/` leftovers and, at worst, a half entry: recovery
    // runs before the first connection is accepted.
    let recovery = spool.recover().map_err(|err| MailError::Spool {
        reason: err.to_string(),
        path: mail.spool_root.clone(),
    })?;
    tracing::info!(
        tmp_removed = recovery.tmp_removed,
        intact = recovery.intact,
        corrupt = recovery.corrupt,
        "spool recovered"
    );

    // The shared part — the spool, the counters, the credential check — is
    // built once; each listener gets its own copy with its own role, TLS
    // acceptor and verifier.
    let metrics = Arc::new(Metrics::new());
    let passwords: Arc<dyn PasswordVerifier> = Arc::new(StoreVerifier {
        store: store.clone(),
    });
    let desired = store
        .load()
        .map_err(|err| MailError::State(err.to_string()))?
        .desired;
    // The listeners start on the configuration the store holds now; a later
    // apply replaces it through `MailControl`. `ServerConfig` is deliberately
    // not `Clone` (it holds a spool, a policy and a verifier), so the shared
    // half is rebuilt per listener from the same inputs rather than copied.
    // The slot is the configuration a *reload* replaces, and it is seeded with
    // the first listener's full section (role, counters and all) rather than
    // with the shared half: a driver that swapped in the shared half would
    // hand the listener a configuration with no role and no counters, which is
    // exactly the class of wiring mistake this module can make and its end-to-end
    // test catches.
    let first = mail
        .listeners
        .first()
        .ok_or(MailError::Missing("listeners"))?;
    let seed = listener_config(
        mail,
        config_for(mail, &spool, desired.clone(), passwords.clone())?,
        first,
        metrics.clone(),
    )?;
    let control = MailControl::new(seed, metrics.clone(), mail.listeners.len());
    let mut tasks = Vec::new();
    for listener in &mail.listeners {
        let base = config_for(mail, &spool, desired.clone(), passwords.clone())?;
        let config = listener_config(mail, base, listener, metrics.clone())?;
        let socket = tokio::net::TcpListener::bind(listener.listen)
            .await
            .map_err(|err| MailError::Bind {
                reason: err.to_string(),
                addr: listener.listen,
            })?;
        tracing::info!(
            %listener.listen,
            role = %listener.role_name,
            tls = config.tls.is_some(),
            "mail listener bound"
        );
        tasks.push(tokio::spawn(async move {
            // A listener whose `serve` returns has failed permanently (the
            // socket is gone); the log line is the operator's only signal, and
            // the process keeps the other listeners and the API alive.
            if let Err(err) = ayane_smtpd::serve(socket, Arc::new(config)).await {
                tracing::error!(%err, "mail listener stopped");
            }
        }));
    }

    // The delivery consumer: recover, then one pass per tick, sleeping no
    // longer than the earliest attempt that is due.
    let (deliverer, _spool) = deliverer(mail, metrics.clone())?;
    // The delivery side's counters (a maildir write, a bounce, a deferral) are
    // read off the reports each pass returns — see `MetricsDelivery::count_outcomes`.
    // The *outbound* half is counted by the decorator [`deliverer`] installs on
    // the transport itself, when the outbound path is enabled.
    let state_path = mail.state_path.clone();
    let interval = std::time::Duration::from_secs(mail.delivery_interval_seconds.max(1));
    tracing::info!(
        spool = %mail.spool_root.display(),
        mail_root = %mail.mail_root.display(),
        interval_seconds = interval.as_secs(),
        "delivery consumer started"
    );
    tasks.push(tokio::spawn(async move {
        run_delivery(deliverer, state_path, interval, metrics).await;
    }));

    Ok(RunningEngine { control, tasks })
}

/// The delivery loop: drain the queue, sleep, repeat.
///
/// Split out from [`start`] so it can be read on its own — and so a test can
/// run it against a deliverer it built. The shape is the same one
/// `ayane-smtpd --deliver` runs, with the one difference that matters here: a
/// snapshot that cannot be read, parsed or validated is a *skipped pass*, never
/// a stopped consumer. The receiver may already have answered `250` for mail
/// this instance holds (a promise the spool keeps), and a consumer that exited
/// on a half-written snapshot would leave it sitting in `cur/` with nobody to
/// deliver it.
/// The delivery loop: drain the queue, sleep, repeat — with the traffic
/// counters wired into each pass.
pub async fn run_delivery(
    deliverer: Deliverer,
    state_path: std::path::PathBuf,
    interval: std::time::Duration,
    metrics: Arc<Metrics>,
) {
    let mut last_warning: Option<String> = None;
    loop {
        let state = match load_state(&state_path) {
            Ok(state) => {
                if last_warning.take().is_some() {
                    tracing::info!("the state snapshot is usable again; delivery resumed");
                }
                state
            }
            Err(reason) => {
                if last_warning.as_deref() != Some(reason.as_str()) {
                    tracing::error!(
                        %reason,
                        "the state snapshot cannot be used: holding delivery until it is fixed"
                    );
                }
                last_warning = Some(reason);
                tokio::time::sleep(interval).await;
                continue;
            }
        };
        let reports = match deliverer.run(&state) {
            Ok(reports) => reports,
            Err(err) => {
                // An unreadable spool is the same treatment as an unreadable
                // snapshot: hold, log once, retry on the next tick.
                let reason = err.to_string();
                if last_warning.as_deref() != Some(reason.as_str()) {
                    tracing::error!(%reason, "delivery pass failed");
                }
                last_warning = Some(reason);
                tokio::time::sleep(interval).await;
                continue;
            }
        };
        // The delivery side's counters, read off the reports the pass produced:
        // a maildir write, a bounce, a deferral. The outbound half is counted
        // by the transport decorator `deliverer` installs, at the moment the
        // receiver answers.
        ayane_smtpd::MetricsDelivery::count_outcomes(&metrics, &reports);
        let due = next_due(&reports);
        let waiting: usize = reports.iter().map(|pass| pass.waiting().count()).sum();
        tracing::debug!(passes = reports.len(), waiting, "delivery pass finished");
        // The sleep is bounded by the earliest due attempt (never longer than
        // the interval, never shorter than a second), so a message due in
        // fifteen minutes is not retried every thirty seconds and not
        // discovered an hour late.
        let cap = interval.as_secs().max(1);
        let sleep = due
            .map_or(cap, |due| due.saturating_sub(unix_now()))
            .clamp(1, cap);
        tokio::time::sleep(std::time::Duration::from_secs(sleep)).await;
    }
}

/// Reads, parses and validates the state snapshot the consumer routes by.
///
/// # Errors
///
/// Returns the reason as a string: a missing file is an apply that has not run
/// yet, a parse error is a half-written file, and a rejected state is one the
/// operator has to change.
pub fn load_state(path: &std::path::Path) -> Result<ayane_proto::DesiredState, String> {
    let bytes = std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let state: ayane_proto::DesiredState =
        serde_json::from_slice(&bytes).map_err(|err| format!("{}: {err}", path.display()))?;
    state
        .validate()
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(state)
}

/// The earliest instant the last pass said something would be due.
fn next_due(passes: &[ayane_smtpd::DeliveryReport]) -> Option<u64> {
    passes
        .iter()
        .flat_map(|pass| pass.waiting())
        .filter_map(|report| match &report.outcome {
            ayane_smtpd::RecipientOutcome::Deferred {
                next_attempt_epoch, ..
            } => Some(*next_attempt_epoch),
            _ => None,
        })
        .min()
}

/// The credential check a submission listener uses: the store's password
/// hashes, verified with the same function the API uses.
///
/// This is the half the operator binary lacked (`--submission-authenticates`
/// accepted every login). A shared mailbox authenticates with the
/// server-minted machine credential the store keeps for it, which is what makes
/// the webmail's shared-mailbox session work over the same listener.
struct StoreVerifier {
    store: Arc<dyn ayane_store::StateStore>,
}

impl PasswordVerifier for StoreVerifier {
    fn verify<'a>(
        &'a self,
        identity: &'a str,
        password: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let stored = match self.store.load() {
                Ok(stored) => stored,
                Err(err) => {
                    tracing::warn!(%err, "cannot read the store for a login attempt");
                    return false;
                }
            };
            let address = match ayane_proto::Address::parse(identity) {
                Ok(address) => address,
                Err(_) => return false,
            };
            if let Some(hash) = stored.password_hash(&address) {
                return ayane_store::password::verify_password(password, hash).is_ok();
            }
            if stored
                .desired
                .shared
                .iter()
                .any(|shared| shared.address.as_str().eq_ignore_ascii_case(identity))
            {
                if let Ok(machine) = self.store.shared_imap_password(identity) {
                    return machine == password;
                }
            }
            false
        })
    }
}

/// The shared half of every listener's configuration: everything that does not
/// depend on the role.
fn config_for(
    mail: &MailConfig,
    spool: &Spool,
    state: ayane_proto::DesiredState,
    passwords: Arc<dyn PasswordVerifier>,
) -> Result<ServerConfig, MailError> {
    // The one property of a routing snapshot that makes it unusable is the one
    // `validate` states: a snapshot the listeners cannot route with is a
    // configuration error, and starting on it would mean answering `550` to
    // every recipient until someone fixed the store.
    state
        .validate()
        .map_err(|err| MailError::State(err.to_string()))?;
    let policy = AddressPolicy::from_state(&state);
    Ok(ServerConfig {
        hostname: mail.hostname.clone(),
        // Overwritten per listener; the shared value is the inbound posture.
        role: ListenerRole::Inbound,
        max_message_size: mail.max_message_size,
        limits: ayane_smtpd::session::Limits {
            max_message_size: mail.max_message_size,
            ..ayane_smtpd::session::Limits::default()
        },
        per_ip_limit: mail.per_ip_limit,
        command_timeout: ayane_smtpd::server::COMMAND_TIMEOUT,
        transaction_timeout: ayane_smtpd::server::TRANSACTION_TIMEOUT,
        spool: spool.clone(),
        policy,
        state,
        passwords,
        verifier: None,
        tls: None,
        max_received_headers: 25,
        max_header_bytes: mail.max_header_bytes,
        // The one bound on password guessing that survives a reconnect.
        auth_guard: Some(Arc::new(ayane_smtpd::server::AuthGuard::default())),
        metrics: None,
    })
}

/// One listener's configuration: the shared half plus its role and TLS.
///
/// # Errors
///
/// Returns [`MailError::Tls`] when a listener names a certificate that cannot be
/// loaded, or a role that requires TLS and names none.
fn listener_config(
    mail: &MailConfig,
    base: ServerConfig,
    listener: &crate::config::MailListener,
    metrics: Arc<Metrics>,
) -> Result<ServerConfig, MailError> {
    let mut config = base;
    config.role = listener.role;
    config.metrics = Some(metrics);
    config.tls = match (&listener.tls_cert, &listener.tls_key) {
        (Some(cert), Some(key)) => Some(load_tls(cert, key)?),
        (None, None) => None,
        _ => {
            return Err(MailError::Tls(format!(
                "{} ({}): the certificate and the key go together",
                listener.listen, listener.role_name
            )))
        }
    };
    if listener.role.needs_tls() && config.tls.is_none() {
        return Err(MailError::Tls(format!(
            "{} ({}): this role requires a certificate",
            listener.listen, listener.role_name
        )));
    }
    // An inbound listener verifies with the system resolver; a submission
    // listener does not (the client is already the authenticated identity, and
    // the outbound path signs).
    if listener.role == ListenerRole::Inbound {
        config.verifier = Some(
            Verifier::with_system_resolver(&mail.hostname)
                .map_err(|err| MailError::Tls(err.to_string()))?,
        );
    }
    Ok(config)
}

/// Loads the TLS acceptor from a PEM chain and key.
///
/// # Errors
///
/// Returns [`MailError::Tls`] when either file cannot be read or parsed, or the
/// pair is not a usable certificate/private-key combination.
pub fn load_tls(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<tokio_rustls::TlsAcceptor, MailError> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert)
            .map_err(|err| MailError::Tls(format!("{}: {err}", cert.display())))?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|err| MailError::Tls(format!("{}: {err}", cert.display())))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key)
            .map_err(|err| MailError::Tls(format!("{}: {err}", key.display())))?,
    ))
    .map_err(|err| MailError::Tls(format!("{}: {err}", key.display())))?
    .ok_or_else(|| MailError::Tls(format!("{}: no private key", key.display())))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| MailError::Tls(err.to_string()))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Builds the delivery consumer for the configured roots.
///
/// # Errors
///
/// Returns [`MailError::Spool`] when the spool cannot be opened, and
/// [`MailError::Roots`] when the mail root and the spool root collide (see
/// [`Deliverer::check_roots`]).
pub fn deliverer(
    mail: &MailConfig,
    metrics: Arc<Metrics>,
) -> Result<(Deliverer, Spool), MailError> {
    let spool_root = mail.spool_root.clone();
    let spool = Spool::open(&spool_root).map_err(|err| MailError::Spool {
        reason: err.to_string(),
        path: spool_root,
    })?;
    let retry = RetryPolicy {
        max_age: std::time::Duration::from_secs(mail.retry_max_age_seconds),
        max_attempts: mail.retry_max_attempts,
        ..RetryPolicy::default()
    };
    let mut deliverer =
        Deliverer::new(spool.clone(), mail.mail_root.clone(), mail.hostname.clone())
            .with_retry(retry)
            .with_quota((mail.quota_bytes > 0).then_some(mail.quota_bytes));
    if mail.outbound {
        // The outbound transport: an MX resolver, the opportunistic-TLS client
        // and the DKIM signers the state's selectors name. The keys are read
        // from the process environment here and nowhere else, so the state
        // snapshot on disk never carries one.
        let resolver: Arc<dyn ayane_smtpd::Resolver> = Arc::new(
            ayane_smtpd::outbound::SystemResolver::system()
                .map_err(|err| MailError::Outbound(err.to_string()))?,
        );
        let mut outbound = ayane_smtpd::outbound::Outbound::new(resolver, mail.hostname.clone())
            .with_port(mail.smtp_port);
        // The keys are loaded from the environment once, here: a selector is a
        // key, so a selector change is a restart of the consumer rather than a
        // hot swap (a reload that changes one logs that fact).
        if let Some(template) = &mail.dkim_key_env {
            for (_, signer) in signers(mail, template)? {
                outbound = outbound.with_signer(signer);
            }
        }
        let transport = ayane_smtpd::outbound::SyncedTransport::new(outbound)
            .map_err(|err| MailError::Outbound(err.to_string()))?;
        let transport: Arc<dyn ayane_smtpd::RemoteTransport> = Arc::new(
            ayane_smtpd::metrics::MetricsDelivery::new(metrics.clone(), Arc::new(transport)),
        );
        deliverer = deliverer.with_remote(transport);
    }
    deliverer
        .check_roots()
        .map_err(|err| MailError::Roots(err.to_string()))?;
    Ok((deliverer, spool))
}

/// The DKIM signers the state's domains name, read from the environment.
fn signers(
    mail: &MailConfig,
    template: &str,
) -> Result<std::collections::BTreeMap<String, ayane_smtpd::outbound::Signer>, MailError> {
    // The state is read from the same snapshot the delivery loop reads, so a
    // domain that exists in the store is a domain that can sign.
    let bytes = std::fs::read(&mail.state_path)
        .map_err(|err| MailError::Outbound(format!("{}: {err}", mail.state_path.display())))?;
    let state: ayane_proto::DesiredState = serde_json::from_slice(&bytes)
        .map_err(|err| MailError::Outbound(format!("{}: {err}", mail.state_path.display())))?;
    ayane_smtpd::outbound::signers_from_env(&state, template)
        .map_err(|err| MailError::Outbound(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mail_root_that_is_a_spool_tree_is_refused_before_the_first_pass() {
        // The pair block ⑤ taught, at a root that needs no privileges to build:
        // a mail root holding the spool's own directory names is a failure that
        // looks like success (every write appears to work), and `check_roots`
        // is what makes it fatal at start rather than at the first delivery.
        let root = std::env::temp_dir().join(format!("ayane-roots-{}", uuid::Uuid::new_v4()));
        let mail_root = root.join("mail");
        // The `tmp/`, `new/`, `cur/` and `corrupt/` names are the spool's, and
        // a maildir's — one of them at the mail root means the two layouts were
        // pointed at each other.
        std::fs::create_dir_all(mail_root.join("new")).expect("maildir");
        let mail = MailConfig {
            spool_root: root.join("spool"),
            mail_root: mail_root.clone(),
            ..MailConfig::default()
        };
        let err = deliverer(&mail, Arc::new(Metrics::new())).expect_err("the pair is refused");
        assert!(
            matches!(err, MailError::Roots(_)),
            "the mail root is a spool tree, which `check_roots` refuses: {err:?}"
        );

        // The same roots with the reserved name gone start fine: the refusal
        // is about the layout, not about the paths being unusual.
        std::fs::remove_dir(mail_root.join("new")).expect("clean");
        let (_, _spool) =
            deliverer(&mail, Arc::new(Metrics::new())).expect("sibling roots are fine");

        // The spool root *is* the mail root: the one-level-up version of the
        // same mistake.
        let same = MailConfig {
            spool_root: root.join("mail"),
            mail_root: root.join("mail"),
            ..MailConfig::default()
        };
        let err = deliverer(&same, Arc::new(Metrics::new())).expect_err("one path, two roles");
        assert!(matches!(err, MailError::Roots(_)), "{err:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_default_mail_section_is_inert() {
        // The default configuration binds nothing, so a control plane that was
        // never told about mail is the control plane it always was.
        let mail = MailConfig::default();
        assert!(!mail.enabled, "off by default");
        assert!(mail.listeners.is_empty(), "no listener to bind");
        assert!(!mail.outbound, "no message leaves the machine");
        assert!(
            mail.spool_root.ends_with("spool") && mail.mail_root.ends_with("mail"),
            "the two roots are siblings: {:?} {:?}",
            mail.spool_root,
            mail.mail_root
        );
    }
}
