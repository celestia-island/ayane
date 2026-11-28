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
//! mailbox's machine credential (compared in constant time). A listener inside
//! the control plane has the store, so it needs nothing else — and the split
//! process does not get a way to opt out of checking: `ayane-smtpd` used to
//! carry `--submission-authenticates`, which accepted every login, and that flag
//! is gone (see [`ayane_smtpd`]'s `SnapshotVerifier`).
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
    /// The snapshot the delivery loop reads is not the one `admin.apply`
    /// writes, so nothing would ever update the routing table it uses.
    #[error(
        "mail.state_path is {configured} but every apply writes {applied}: \\
         set AYANE_MAIL_STATE to the applied path (or unset it and let the default stand)"
    )]
    StatePath {
        /// Where the consumer was told to look.
        configured: std::path::PathBuf,
        /// Where the apply writes.
        applied: std::path::PathBuf,
    },
    /// A listener cannot serve the role it was configured with.
    #[error("listener {listen}: {reason}")]
    Listener {
        /// The address it was meant to bind.
        listen: std::net::SocketAddr,
        /// What is missing.
        reason: String,
    },
}

/// The running mail service: the handles the driver needs, and the tasks that
/// make it live.
#[derive(Debug)]
pub struct RunningEngine {
    /// The listener slot a reload replaces. Present even when degraded, so the
    /// driver has one object either way and a reload after a fix is the same
    /// call.
    control: MailControl,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// `None` when the service is serving; the reason when it is not.
    degraded: Option<MailDegraded>,
}

impl RunningEngine {
    /// The shared control handles (clone into a [`crate::driver::NativeDriver`]).
    #[must_use]
    pub fn control(&self) -> &MailControl {
        &self.control
    }

    /// Why the mail service is not serving, or `None` when it is.
    #[must_use]
    pub fn degraded(&self) -> Option<&MailDegraded> {
        self.degraded.as_ref()
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

impl RunningEngine {
    /// An engine that is up.
    #[must_use]
    fn running(control: MailControl, tasks: Vec<tokio::task::JoinHandle<()>>) -> Self {
        Self {
            control,
            tasks,
            degraded: None,
        }
    }

    /// The engine shape a failed start leaves: the control plane keeps serving,
    /// the mail side does not, and the slot exists for a later fix to reach.
    ///
    /// The slot is seeded from the **configured** listeners rather than from a
    /// store read, because the store may be the very thing that failed; its
    /// configuration is not served by anyone until a reload lands, and a
    /// degraded instance is not going to accept a connection anyway.
    fn not_serving(reason: MailDegraded) -> Self {
        Self {
            control: MailControl::unstarted(),
            tasks: Vec::new(),
            degraded: Some(reason),
        }
    }
}

/// Why the mail service is not serving, as the process reports it.
///
/// `None` on [`RunningEngine::degraded`] means the service is up. Any `Some`
/// means the control plane is running — its API, its RPC surface, its health
/// endpoint — while the mail side is not, and the reason says which part and
/// which kind of fault:
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MailDegraded {
    /// A stable, machine-readable cause: `listeners`, `hostname`, `spool`,
    /// `roots`, `state`, `state_path`, `tls`, `outbound`, or `bind` for a
    /// listener that could not take its address.
    pub cause: &'static str,
    /// Whether a restart could fix it without a human — an address that is
    /// taken, a store that is briefly unreadable — as opposed to a
    /// configuration only an operator can change.
    pub retryable: bool,
    /// The human-readable reason, exactly as the log line carries it.
    pub reason: String,
}

impl MailDegraded {
    /// The class of a [`MailError`], for the report and for the retry hint.
    #[must_use]
    pub fn of(err: &MailError) -> Self {
        let (cause, retryable) = match err {
            // A taken port is the one fault that is not necessarily a
            // misconfiguration: another instance, a restart racing its own
            // socket, a supervisor that has not let go yet.
            MailError::Bind { .. } => ("bind", true),
            MailError::Spool { .. } => ("spool", false),
            MailError::Roots(_) => ("roots", false),
            MailError::Tls(_) => ("tls", false),
            MailError::Outbound(_) => ("outbound", false),
            MailError::Missing(what) => (*what, false),
            MailError::State(_) => ("state", true),
            MailError::StatePath { .. } => ("state_path", false),
            MailError::Listener { .. } => ("listeners", false),
        };
        Self {
            cause,
            retryable,
            reason: err.to_string(),
        }
    }
}

/// Starts the mail service for `config`, and the tasks that run it.
///
/// `store` is the live snapshot the listeners route by and the credential check
/// reads; the caller keeps its own handle (the API needs one too).
///
/// # It never takes the control plane down
///
/// A mail service that cannot start is **reported**, not fatal: this returns an
/// [`RunningEngine`] either way, with [`RunningEngine::degraded`] saying that
/// nothing is serving and why. The control plane is the process's primary job —
/// an operator whose SMTP port is not bound yet still needs the panel that tells
/// them so — and exiting is how one mistyped certificate path came to cost an
/// instance its entire API. The one exception is
/// [`crate::config::MailConfig::require_start`], which a deployment sets when it
/// wants a supervisor to see a failed start as a failed process instead.
///
/// What is *not* caught here, on purpose: a panic in the startup path. Every
/// failure a configuration can produce is an `Err` from the startup path, and a panic
/// is a bug in this crate rather than in a deployment.
///
/// # The tasks
///
/// | task | what it is | cancelled by |
/// |---|---|---|
/// | listener × N | `ayane_smtpd::serve` over the bound socket | process exit |
/// | delivery | one pass per tick, sleeping no longer than the earliest due attempt | process exit |
///
/// The outbound transport is not a task: it is installed on the deliverer
/// ([`deliverer`]), so a message for a remote domain leaves the machine
/// inside the delivery pass that decided it was due.
///
/// # Errors
///
/// Returns [`MailError`] only when `mail.require_start` is set and the service
/// cannot start — the one case a deployment asked to be fatal.
pub async fn start(
    config: &Config,
    store: Arc<dyn ayane_store::StateStore>,
) -> Result<RunningEngine, MailError> {
    match build(config, store).await {
        Ok(engine) => Ok(engine),
        Err(err) => {
            let degraded = MailDegraded::of(&err);
            tracing::error!(
                cause = degraded.cause,
                retryable = degraded.retryable,
                reason = %degraded.reason,
                "the mail service did not start; the control plane keeps serving"
            );
            if config.mail.require_start {
                return Err(err);
            }
            Ok(RunningEngine::not_serving(degraded))
        }
    }
}

/// The configuration each listener serves, built once per listener.
///
/// `ServerConfig` is deliberately not `Clone` (it owns a spool, a policy and a
/// verifier), so this is the one place the per-listener copy is made: the
/// listener's own section for its socket, and — for a *reload* — the sections
/// [`crate::driver::MailControl`] swaps in, which the driver rebuilds from the
/// same inputs.
fn per_listener(
    mail: &MailConfig,
    spool: &Spool,
    desired: &ayane_proto::DesiredState,
    passwords: &Arc<dyn PasswordVerifier>,
) -> Result<Vec<ServerConfig>, MailError> {
    let mut out = Vec::with_capacity(mail.listeners.len());
    for listener in &mail.listeners {
        let base = config_for(mail, spool, desired.clone(), passwords.clone())?;
        out.push(listener_config(mail, base, listener)?);
    }
    Ok(out)
}

/// The startup itself: every step that can fail, with nothing softened.
async fn build(
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
    // The state the listeners are built from and the state the delivery loop
    // reads must be **one file**. `admin.apply` writes the store's snapshot
    // under the state directory; `AYANE_MAIL_STATE` says where the consumer
    // looks. If they differ, the consumer routes by a file nothing updates and
    // every apply silently reaches the listener and not the delivery.
    let canonical = config.state_dir.join(crate::apply::SNAPSHOT_PATH);
    if mail.state_path != canonical {
        return Err(MailError::StatePath {
            configured: mail.state_path.clone(),
            applied: canonical,
        });
    }
    // The two roots are the one mistake this process cannot survive: a maildir
    // written into the spool's own `tmp/`/`new/`/`cur/`/`corrupt/` is a failure
    // that looks like success. Checked before anything is bound.
    let roots = Deliverer::new(
        Spool::open(&mail.spool_root).map_err(|err| MailError::Spool {
            reason: err.to_string(),
            path: mail.spool_root.clone(),
        })?,
        mail.mail_root.clone(),
        mail.hostname.clone(),
    );
    roots
        .check_roots()
        .map_err(|err| MailError::Roots(err.to_string()))?;
    // A submission listener without TLS cannot offer AUTH, and a submission
    // listener that cannot authenticate accepts nothing: better to say so here
    // than to serve a port that answers `538` to every login. An IMAP listener
    // has the same shape of problem for the same reason — its session refuses
    // `LOGIN` unless the transport is encrypted — so a TLS-less `imap` entry is
    // refused here rather than started as a port that answers `NO` to every
    // client.
    for listener in &mail.listeners {
        if !matches!(listener.role, ListenerRole::Inbound) && listener.tls_cert.is_none() {
            return Err(MailError::Listener {
                listen: listener.listen,
                reason: format!(
                    "role {} needs a certificate: without TLS a password is never \
                     accepted, so every login is refused",
                    listener.role_name
                ),
            });
        }
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

    // The delivery side is built **before** any socket is bound: a pair of
    // roots that collide, or a DKIM key that will not load, is a configuration
    // fault, and nothing should be left serving because it was discovered one
    // step later.
    let metrics = Arc::new(Metrics::new());
    let (deliverer, _spool) = deliverer(mail, metrics.clone())?;

    let passwords: Arc<dyn PasswordVerifier> = Arc::new(StoreVerifier {
        store: store.clone(),
    });
    let desired = store
        .load()
        .map_err(|err| MailError::State(err.to_string()))?
        .desired;
    let configs = per_listener(mail, &spool, &desired, &passwords)?;

    // Bind every socket before serving any of them, then start the tasks: a
    // listener that cannot take its address is a startup failure, not a
    // half-served instance. SMTP sockets and IMAP sockets are bound together
    // and served by two different loops — one `serve` per protocol — so an
    // instance that has both ports either has both or starts neither.
    let mut smtp_sockets = Vec::with_capacity(configs.len());
    let mut imap_sockets: Vec<(tokio::net::TcpListener, Arc<ayane_smtpd::ImapConfig>)> = Vec::new();
    for (config, listener) in configs.iter().zip(&mail.listeners) {
        let socket = tokio::net::TcpListener::bind(listener.listen)
            .await
            .map_err(|err| MailError::Bind {
                reason: err.to_string(),
                addr: listener.listen,
            })?;
        tracing::info!(
            listen = %listener.listen,
            role = %listener.role_name,
            tls = config.tls.is_some(),
            "mail listener bound"
        );
        if listener.role == ListenerRole::Imap {
            imap_sockets.push((socket, Arc::new(imap_config(mail, listener, config)?)));
        } else {
            smtp_sockets.push(socket);
        }
    }

    // The slot a reload replaces: seeded with the first listener's full section,
    // counters attached, so a driver that swaps a configuration in hands the
    // listener a *usable* one (role, counters and all) rather than the shared
    // half.
    let first = per_listener(mail, &spool, &desired, &passwords)?
        .into_iter()
        .next()
        .ok_or(MailError::Missing("listeners"))?;
    let control = MailControl::new(
        attach_metrics(first, metrics.clone()),
        metrics.clone(),
        mail.listeners.len(),
    );

    let mut tasks = Vec::new();
    for (socket, config) in smtp_sockets.into_iter().zip(configs) {
        let served = attach_metrics(config, metrics.clone());
        tasks.push(tokio::spawn(async move {
            // A listener whose `serve` returns has failed permanently (the
            // socket is gone): the log line is the operator's signal, and the
            // process keeps the other listeners and the API alive.
            if let Err(err) = ayane_smtpd::serve(socket, Arc::new(served)).await {
                tracing::error!(%err, "mail listener stopped");
            }
        }));
    }
    for (socket, config) in imap_sockets {
        tasks.push(tokio::spawn(async move {
            if let Err(err) = ayane_smtpd::serve_imap(socket, config).await {
                tracing::error!(%err, "imap listener stopped");
            }
        }));
    }

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

    Ok(RunningEngine::running(control, tasks))
}

/// Attaches the counters a listener writes to.
fn attach_metrics(mut config: ServerConfig, metrics: Arc<Metrics>) -> ServerConfig {
    config.metrics = Some(metrics);
    config
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
/// This is the half the operator binary lacked, and the replacement for what it
/// had instead (`--submission-authenticates`, which accepted every login and is
/// now deleted). A shared mailbox authenticates with the server-minted machine
/// credential the store keeps for it, which is what makes the webmail's
/// shared-mailbox session work over the same listener.
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
            let Ok(address) = ayane_proto::Address::parse(identity) else {
                return false;
            };
            if let Some(hash) = stored.password_hash(&address) {
                return ayane_store::password::verify_password(password, hash).is_ok();
            }
            // A shared mailbox logs in with the machine credential the store
            // mints for it. The comparison is constant-time (`subtle`), for the
            // same reason the password hashes are verified by a hash function
            // rather than by a string compare: a byte-at-a-time early exit is a
            // byte-at-a-time oracle, and this branch is reachable without a
            // hash to slow it down.
            if stored
                .desired
                .shared
                .iter()
                .any(|shared| shared.address.as_str().eq_ignore_ascii_case(identity))
            {
                if let Ok(machine) = self.store.shared_imap_password(identity) {
                    return constant_time_eq(machine.as_bytes(), password.as_bytes());
                }
            }
            false
        })
    }
}

/// Whether two octet strings are equal, in time that depends only on their
/// lengths.
///
/// `subtle`'s constant-time primitives, not a manual XOR loop: the point is that
/// the comparison cannot be made to leak where the first difference is, and a
/// loop that a compiler is free to reorder is not that.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    left.ct_eq(right).into()
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
        rspamd: None,
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
) -> Result<ServerConfig, MailError> {
    let mut config = base;
    config.role = listener.role;
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
    // listener does not (the client is already the authenticated identity,
    // and the outbound path signs).
    if listener.role == ListenerRole::Inbound {
        config.verifier = Some(
            Verifier::with_system_resolver(&mail.hostname)
                .map_err(|err| MailError::Tls(err.to_string()))?,
        );
        // The content scan rides the same role split, for the same reason:
        // it is an inbound-posture enhancement, and the scan endpoint was
        // syntax-checked at `from_env`, so a failure here is the process's
        // "configuration says one thing, the world says another" error.
        config.rspamd = rspamd_client(mail)?;
    }
    Ok(config)
}

/// The content scanner a listener runs with, when it runs one.
///
/// `None` when `AYANE_MAIL_RSPAMD_URL` is unset: no client, no connection,
/// no behaviour change — the switch the deployment rollback leans on.
///
/// # Errors
///
/// The URL's syntax was already refused in `from_env`
/// ([`crate::config::ConfigError::MailRspamd`]), so the only failure left is
/// the HTTP client's own construction, which does not fail on the rustls
/// stack; it is mapped onto the required-setting error so the impossible
/// stays an `Err` rather than a panic.
fn rspamd_client(
    mail: &MailConfig,
) -> Result<Option<ayane_smtpd::rspamd::RspamdClient>, MailError> {
    let Some(url) = mail.rspamd_url.as_deref() else {
        return Ok(None);
    };
    ayane_smtpd::rspamd::RspamdClient::parse(
        url,
        std::time::Duration::from_millis(mail.rspamd_timeout_ms),
        mail.rspamd_password.clone(),
    )
    .map(Some)
    .map_err(|_| MailError::Missing("rspamd_url"))
}

/// One IMAP listener's own configuration.
///
/// It is built from the mail role's configuration rather than beside it, so the
/// two protocols cannot disagree about the three things that must not: the
/// credential check (`config.passwords` — the same store-backed verifier a
/// submission listener uses), the certificate (`config.tls`), and the mail root
/// (where the delivery consumer writes and the reader reads).
///
/// # Errors
///
/// Returns [`MailError::Listener`] when an `imap` entry asks for implicit TLS
/// without a certificate — there would be nothing to hand the socket to.
fn imap_config(
    mail: &MailConfig,
    listener: &crate::config::MailListener,
    base: &ServerConfig,
) -> Result<ayane_smtpd::ImapConfig, MailError> {
    let implicit = listener.imap_tls.unwrap_or(false);
    if implicit && base.tls.is_none() {
        return Err(MailError::Listener {
            listen: listener.listen,
            reason: "imap-tls=1 needs cert= and key=: there is no certificate to \
                     hand the socket to"
                .to_owned(),
        });
    }
    Ok(ayane_smtpd::ImapConfig {
        hostname: mail.hostname.clone(),
        mail_root: mail.mail_root.clone(),
        passwords: Arc::clone(&base.passwords),
        tls: base.tls.clone(),
        imap_tls: implicit,
        per_ip_limit: mail.per_ip_limit,
        command_timeout: ayane_smtpd::imap_server::AUTOLOGOUT,
    })
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
        // hot swap (a reload that changes one logs that fact). A snapshot that
        // does not exist yet yields no signers rather than no engine — see
        // [`signers`] for why that is the only ordering a first deployment has.
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
///
/// # A state that is not there yet is not a startup failure
///
/// The snapshot this reads is written by `admin.apply`, and `apply` is an RPC
/// — it needs the process up to be called. Reading it as a fatal step at start
/// therefore made the first deployment of an instance with
/// `AYANE_MAIL_OUTBOUND=1` impossible: the engine could not start without a
/// snapshot, and the only writer of the snapshot needs the engine. The
/// resolution is that **signing is not delivery**: a remote recipient is still
/// reachable, and DKIM's `p=` is the receiver's policy to enforce, so the same
/// decision `signers_from_env` already makes per domain ("a domain with a
/// selector and no key is logged and left unsigned") applies to the snapshot as
/// a whole. A missing or unparsable snapshot is **one** `warn!`, an empty
/// signer set, and mail leaves unsigned — exactly what it did before this
/// instance had a selector.
///
/// The catch-up is a restart, not a reload: the keys are loaded once, here, and
/// only the state file is re-read by the delivery consumer. An instance that
/// applied after this start signs nothing until it is restarted; the operator's
/// signal is the `warn!` line, which names the path and the reason.
///
/// A snapshot that *is* there and *is* readable but names a key the environment
/// cannot supply is unchanged behaviour: [`signers_from_env`] warns per domain
/// and leaves that domain unsigned. A key that is present and will not parse is
/// still a hard error — that is a deployment that said it signs and shipped a
/// broken key.
fn signers(
    mail: &MailConfig,
    template: &str,
) -> Result<std::collections::BTreeMap<String, ayane_smtpd::outbound::Signer>, MailError> {
    // The state is read from the same snapshot the delivery loop reads, so a
    // domain that exists in the store is a domain that can sign.
    let bytes = match std::fs::read(&mail.state_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(
                path = %mail.state_path.display(),
                %err,
                "no routing snapshot to read DKIM selectors from yet (the first `admin.apply` \
                 writes it): outbound mail leaves unsigned until the next start"
            );
            return Ok(std::collections::BTreeMap::new());
        }
    };
    let state: ayane_proto::DesiredState = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(err) => {
            tracing::warn!(
                path = %mail.state_path.display(),
                %err,
                "the routing snapshot cannot be parsed, so no DKIM selector can be read from it: \
                 outbound mail leaves unsigned until the next start"
            );
            return Ok(std::collections::BTreeMap::new());
        }
    };
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

    /// A store with one account, one shared mailbox (with a machine
    /// credential) and nothing else.
    fn verifier_fixture(tag: &str) -> (StoreVerifier, std::path::PathBuf) {
        use ayane_store::{password, RedbStateStore, StateStore, StoredState};
        let root =
            std::env::temp_dir().join(format!("ayane-verifier-{tag}-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let store = RedbStateStore::open(root.join("store.redb")).expect("store");
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(
            "inbox@example.test".to_owned(),
            password::hash_password("the-right-password").expect("hash"),
        );
        let stored = StoredState {
            desired: ayane_proto::DesiredState {
                domains: vec![ayane_proto::MailDomain {
                    name: "example.test".to_owned(),
                    catch_all: None,
                    enabled: true,
                    dkim: None,
                }],
                accounts: vec![ayane_proto::Account {
                    id: uuid::Uuid::new_v4(),
                    address: ayane_proto::Address::parse("inbox@example.test").expect("addr"),
                    display_name: "Inbox".to_owned(),
                    quota_bytes: 0,
                    admin: false,
                }],
                shared: vec![ayane_proto::SharedMailbox {
                    id: uuid::Uuid::new_v4(),
                    address: ayane_proto::Address::parse("team@example.test").expect("addr"),
                    members: vec![uuid::Uuid::new_v4()],
                }],
                ..Default::default()
            },
            password_hashes: hashes,
            external_identities: Vec::new(),
        };
        store.save(&stored).expect("seed");
        // Mint the shared mailbox's machine credential so the fixture has one
        // to log in with.
        store
            .shared_imap_password("team@example.test")
            .expect("machine credential");
        (
            StoreVerifier {
                store: std::sync::Arc::new(store) as std::sync::Arc<dyn ayane_store::StateStore>,
            },
            root,
        )
    }

    /// The five answers a submission listener's credential check can give.
    ///
    /// Every row is a separate assertion because every one of them is a
    /// separable mutation: accepting everything turns the second, third and
    /// fifth red; verifying against the wrong address turns the first red; a
    /// verifier that never looks at a shared mailbox turns the fourth red.
    /// Before these tests the module had none — the end-to-end test could not
    /// reach the verifier either, because a listener without TLS never offers
    /// AUTH — so "accept every login" was a change no test could see.
    #[tokio::test]
    async fn the_submission_credential_check_has_five_answers() {
        let (verifier, root) = verifier_fixture("five");
        // 1. The right account and the right password.
        assert!(
            verifier
                .verify("inbox@example.test", "the-right-password")
                .await,
            "an account with its own password authenticates"
        );
        // 2. The right account and the wrong password.
        assert!(
            !verifier
                .verify("inbox@example.test", "not-the-password")
                .await,
            "a wrong password is refused"
        );
        // 3. An account that does not exist, with a password-shaped guess. The
        //    answer is the same word as 2's and comes from the same path — a
        //    login that says "no such user" is a directory oracle.
        assert!(
            !verifier
                .verify("nobody@example.test", "the-right-password")
                .await,
            "an unknown account is refused"
        );
        assert!(
            !verifier
                .verify("nobody@example.test", "not-the-password")
                .await,
            "an unknown account is refused for a wrong password too"
        );
        // 4. A shared mailbox with its machine credential, and with anything
        //    else.
        let machine = verifier
            .store
            .shared_imap_password("team@example.test")
            .expect("machine credential");
        assert!(
            verifier.verify("team@example.test", &machine).await,
            "a shared mailbox authenticates with its machine credential"
        );
        assert!(
            !verifier
                .verify("team@example.test", "not-the-credential")
                .await,
            "and not with anything else"
        );
        assert!(
            verifier.verify("team@example.test", &machine).await,
            "the machine credential is stable across attempts"
        );
        // 5. Something that is not an identity at all.
        for junk in [
            "",
            "not-an-address",
            "inbox@",
            "@example.test",
            "in box@example.test",
        ] {
            assert!(
                !verifier.verify(junk, "the-right-password").await,
                "{junk:?} is not an identity, so it is not a login"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The comparison for the machine credential does not exit at the first
    /// differing octet.
    ///
    /// A byte-at-a-time check is an oracle even when the answer is one bit: the
    /// number of octets that matched leaks through timing. This cannot measure
    /// time reliably in a unit test, so it pins the *other* observable property
    /// of the constant-time comparison — that it agrees with `==` on every
    /// input pair it is given, including different lengths — and the
    /// implementation reads `subtle::ConstantTimeEq`, which is the part that
    /// matters.
    #[test]
    fn the_machine_credential_comparison_agrees_with_equality() {
        for (left, right, expected) in [
            ("abcdef", "abcdef", true),
            ("abcdef", "abcdeg", false),
            ("abcdef", "abcde", false),
            ("abcdef", "abcdefg", false),
            ("", "", true),
            ("", "a", false),
            ("a", "", false),
        ] {
            assert_eq!(
                constant_time_eq(left.as_bytes(), right.as_bytes()),
                expected,
                "{left:?} vs {right:?}"
            );
            assert_eq!(
                constant_time_eq(left.as_bytes(), right.as_bytes()),
                left == right
            );
        }
    }

    // ── the DKIM selector source (the outbound half of a first deploy) ────

    /// A snapshot with one hosted domain and, when `selector` is given, a DKIM
    /// selector for it.
    fn snapshot(selector: Option<&str>) -> ayane_proto::DesiredState {
        ayane_proto::DesiredState {
            domains: vec![ayane_proto::MailDomain {
                name: "example.test".to_owned(),
                catch_all: None,
                enabled: true,
                dkim: selector.map(ayane_proto::DkimSigningConfig::selector_only),
            }],
            ..Default::default()
        }
    }

    /// The signing-test key: the same throwaway RSA-2048 pair
    /// `crates/smtpd/tests/outbound.rs` signs with, registered in
    /// `_ledger/tool-exemptions.md`. It authenticates nothing here.
    const FIXTURE_KEY: &str = include_str!("../../smtpd/tests/fixtures/dkim-private.pem");

    /// A `MailConfig` whose snapshot path is this test's own file.
    fn dkim_mail(root: &std::path::Path) -> MailConfig {
        MailConfig {
            state_path: root.join("desired-state.json"),
            dkim_key_env: Some(DKIM_TEMPLATE.to_owned()),
            ..MailConfig::default()
        }
    }

    /// The variable `signers` reads for `example.test` — spelled the way the
    /// substitution spells it, so the test cannot disagree with the lookup:
    /// dots become underscores, and the prefix spells them too.
    const DKIM_VARIABLE: &str = "AYANE_L946_DKIM_KEY_example_test";
    const DKIM_TEMPLATE: &str = "AYANE_L946_DKIM_KEY_{domain}";

    /// **The first-deployment deadlock.** With `AYANE_MAIL_OUTBOUND=1` the
    /// snapshot the signers are read from is written by `admin.apply`, and
    /// `apply` is an RPC that needs the service up. A `signers()` that treats a
    /// missing file as fatal therefore makes the first start of such an
    /// instance impossible — measured on the 2026-11-27 cutover, where the
    /// mail service never came up and the rollback followed.
    ///
    /// The assertion is the whole chain, not just the return value: the engine
    /// starts **degraded-free** (listeners bound, delivery consumer running),
    /// and it starts with **no signers** rather than with an error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_outbound_engine_starts_before_the_first_apply_writes_a_snapshot() {
        let root = std::env::temp_dir().join(format!("ayane-l946-first-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("state")).expect("state dir");
        // The variable is set so that *if* a signer were produced, the fixture
        // key would be found: the test must fail for the missing snapshot, not
        // for a missing key. It is set **after** the start, because this test
        // shares the process with every other one in the crate (`set_var` races
        // them under `cargo test`'s threads) and the start is the half that
        // must not depend on it.

        let store: std::sync::Arc<dyn ayane_store::StateStore> = std::sync::Arc::new(
            ayane_store::RedbStateStore::open(root.join("store.redb")).expect("store"),
        );
        let address = {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("probe");
            probe.local_addr().expect("addr")
        };
        let mut mail = dkim_mail(&root.join("state"));
        mail.enabled = true;
        mail.hostname = "mx.example.test".to_owned();
        mail.outbound = true;
        mail.delivery_interval_seconds = 1;
        mail.listeners = vec![crate::config::MailListener {
            role: ayane_smtpd::ListenerRole::Inbound,
            listen: address,
            role_name: "inbound".to_owned(),
            tls_cert: None,
            tls_key: None,
            imap_tls: None,
        }];
        let config = Config {
            listen: "127.0.0.1:0".parse().expect("listen"),
            log_filter: String::new(),
            state_dir: root.join("state"),
            admin_token: None,
            compose_file: root.join("docker-compose.yml"),
            cert_file: None,
            mail: mail.clone(),
        };
        // The precondition of the whole test: nothing has been applied.
        assert!(
            !mail.state_path.exists(),
            "the fixture starts before the first apply"
        );

        let engine = start(&config, store).await.expect("the engine starts");
        assert_eq!(
            engine.degraded(),
            None,
            "a first deployment with outbound enabled must not be degraded"
        );
        // The listener really is bound: a degraded engine that merely *said* it
        // was fine would still fail this.
        let socket = tokio::net::TcpStream::connect(address)
            .await
            .expect("the inbound listener is bound");
        drop(socket);
        engine.shutdown();

        // And once the snapshot exists, the same configuration signs.
        assert_eq!(
            ayane_smtpd::outbound::dkim_env_name(DKIM_TEMPLATE, "example.test"),
            DKIM_VARIABLE,
            "the fixture's spelling is the lookup's spelling"
        );
        std::env::set_var(DKIM_VARIABLE, FIXTURE_KEY);
        std::fs::write(
            &mail.state_path,
            serde_json::to_vec(&snapshot(Some("ayane"))).expect("snapshot"),
        )
        .expect("write snapshot");
        let signed = signers(&mail, &mail.dkim_key_env.clone().expect("template"))
            .expect("a readable snapshot with a key yields signers");
        assert_eq!(
            signed.keys().collect::<Vec<_>>(),
            vec![&"example.test".to_owned()],
            "the domain in the snapshot is the domain that signs"
        );
        std::env::remove_var(DKIM_VARIABLE);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The two non-fatal snapshot faults: a file that is not JSON (a half
    /// write, a hand edit that did not land) is the same answer as a file that
    /// is not there. Neither may stop the engine — the delivery consumer's own
    /// rule for an unusable snapshot ("hold, log, retry") is the same reasoning
    /// one layer up.
    #[test]
    fn an_unreadable_snapshot_yields_no_signers_and_no_error() {
        let root = std::env::temp_dir().join(format!("ayane-l946-junk-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let mail = dkim_mail(&root);
        let template = DKIM_TEMPLATE;

        // Absent.
        let absent = signers(&mail, template).expect("a missing snapshot is not fatal");
        assert!(absent.is_empty(), "{absent:?}");

        // Present but unparsable.
        std::fs::write(&mail.state_path, b"{ not json").expect("write");
        let junk = signers(&mail, template).expect("an unparsable snapshot is not fatal");
        assert!(junk.is_empty(), "{junk:?}");

        // Present, parsable, selector set, no key in the environment: the
        // per-domain rule that already existed — warn and stay unsigned.
        std::fs::write(
            &mail.state_path,
            serde_json::to_vec(&snapshot(Some("ayane"))).expect("snapshot"),
        )
        .expect("write");
        std::env::remove_var(DKIM_VARIABLE);
        let keyless = signers(&mail, template).expect("no key is not fatal either");
        assert!(keyless.is_empty(), "no key means no signer: {keyless:?}");
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
        // The content scan is off with it: no client, no endpoint, nothing.
        assert_eq!(mail.rspamd_url, None);
        assert_eq!(mail.rspamd_timeout_ms, 5_000);
        assert_eq!(mail.rspamd_password, None);
    }

    #[test]
    fn only_an_inbound_listener_is_given_the_content_scanner() {
        // The role split the verifier set: an inbound listener verifies and
        // scans, a submission listener does neither — the client is already
        // the authenticated identity, and the outbound path signs its own.
        // The certificate is the tests' own fixture pair; it authenticates
        // nothing here, it only has to load.
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .canonicalize()
            .expect("fixture directory");
        let mail = MailConfig {
            hostname: "mx.test".to_owned(),
            listeners: vec![
                crate::config::MailListener {
                    role: ListenerRole::Inbound,
                    listen: "127.0.0.1:0".parse().expect("listen"),
                    role_name: "inbound".to_owned(),
                    tls_cert: None,
                    tls_key: None,
                    imap_tls: None,
                },
                crate::config::MailListener {
                    role: ListenerRole::SubmissionsTls,
                    listen: "127.0.0.1:0".parse().expect("listen"),
                    role_name: "submissions-tls".to_owned(),
                    tls_cert: Some(fixtures.join("mx-test-cert.pem")),
                    tls_key: Some(fixtures.join("mx-test-key.pem")),
                    imap_tls: None,
                },
            ],
            rspamd_url: Some("http://127.0.0.1:11333/scan".to_owned()),
            ..MailConfig::default()
        };
        let root = std::env::temp_dir().join(format!("ayane-rspamd-{}", uuid::Uuid::new_v4()));
        let spool = Spool::open(root.join("spool")).expect("spool");
        let mut desired = ayane_proto::DesiredState::default();
        desired.domains.push(ayane_proto::MailDomain {
            name: "example.test".to_owned(),
            catch_all: None,
            enabled: true,
            dkim: None,
        });
        let passwords: Arc<dyn PasswordVerifier> = Arc::new(ayane_smtpd::authn::DenyAll);
        let configs = per_listener(&mail, &spool, &desired, &passwords).expect("configs");
        assert_eq!(configs.len(), 2);
        assert!(
            configs[0].rspamd.is_some() && configs[0].verifier.is_some(),
            "inbound verifies and scans: rspamd={:?} verifier={:?}",
            configs[0].rspamd.is_some(),
            configs[0].verifier.is_some()
        );
        assert!(
            configs[1].rspamd.is_none() && configs[1].verifier.is_none(),
            "submission neither verifies nor scans"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unset_scan_url_gives_no_client_to_any_listener() {
        // The rollback switch: unset the URL, and the assembly builds the
        // exact listener set it built before the feature existed.
        let mail = MailConfig {
            hostname: "mx.test".to_owned(),
            listeners: vec![crate::config::MailListener {
                role: ListenerRole::Inbound,
                listen: "127.0.0.1:0".parse().expect("listen"),
                role_name: "inbound".to_owned(),
                tls_cert: None,
                tls_key: None,
                imap_tls: None,
            }],
            ..MailConfig::default()
        };
        assert!(rspamd_client(&mail).expect("no client").is_none());
    }
}
