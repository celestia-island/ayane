//! The operator's entry point: one listener per role, configured from a
//! state snapshot and a TLS certificate — or, with `--deliver`, the delivery
//! consumer over the same spool.
//!
//! Receiving and delivering are two modes of one process because they are two
//! jobs over one spool: the listener binds, recovers the queue once and
//! serves; the consumer recovers, drains what is due and sleeps until the
//! next attempt is due. Neither is a daemon with its own copy of the queue.
//!
//! ```text
//! ayane-smtpd --role inbound --listen 127.0.0.1:3025 --spool state/spool \
//!             --state state/desired-state.json --hostname mx.example.com
//! ayane-smtpd --deliver --spool /var/mail/vhosts --state state/desired-state.json \
//!             --hostname mx.example.com [--retry-max-age-seconds N] [--quota BYTES]
//! ```

#![warn(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ayane_smtpd::authn::PasswordVerifier;
use ayane_smtpd::policy::AddressPolicy;
use ayane_smtpd::queue::Spool;
use ayane_smtpd::server::{serve, ServerConfig};
use ayane_smtpd::session::Limits;
use ayane_smtpd::verify::Verifier;
use ayane_smtpd::ListenerRole;
use tokio_rustls::TlsAcceptor;

/// What the command line asks for.
#[derive(Debug)]
enum Options {
    /// Bind a listener and serve until stopped.
    Serve(ServeOptions),
    /// Drain the queue until stopped.
    Deliver(DeliverOptions),
}

/// The listener mode's options.
#[derive(Debug)]
struct ServeOptions {
    role: ListenerRole,
    listen: SocketAddr,
    spool: PathBuf,
    state: PathBuf,
    hostname: String,
    tls: Option<(PathBuf, PathBuf)>,
    max_message_size: u64,
    max_header_bytes: u64,
    per_ip_limit: usize,
    submission_authenticates: bool,
}

/// The consumer mode's options.
#[derive(Debug)]
struct DeliverOptions {
    spool: PathBuf,
    state: PathBuf,
    hostname: String,
    retry_max_age: Duration,
    retry_max_attempts: u32,
    quota: Option<u64>,
    interval: Duration,
}

fn usage() -> &'static str {
    "usage: ayane-smtpd --role inbound|submission|submissions-tls \
        --listen ADDR --spool DIR --state FILE --hostname NAME \
        [--tls-cert FILE --tls-key FILE] [--max-size BYTES] \
        [--max-header-bytes BYTES] [--per-ip LIMIT] \
        [--submission-authenticates]\n\
     \x20 or: ayane-smtpd --deliver --spool DIR --state FILE --hostname NAME \
        [--retry-max-age-seconds N] [--retry-max-attempts N] \
        [--quota BYTES] [--interval-seconds N]"
}

fn parse_options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut deliver = false;
    let mut retry_max_age = ayane_smtpd::retry::RetryPolicy::DEFAULT_MAX_AGE;
    let mut retry_max_attempts = 0u32;
    let mut quota = None;
    let mut interval = Duration::from_secs(30);
    let mut role = None;
    let mut listen = None;
    let mut spool = None;
    let mut state = None;
    let mut hostname = None;
    let mut cert = None;
    let mut key = None;
    let mut max_message_size = 25 * 1024 * 1024;
    let mut max_header_bytes = ayane_smtpd::server::DEFAULT_MAX_HEADER_BYTES;
    let mut per_ip_limit = 8;
    let mut submission_authenticates = false;
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--role" => {
                role = Some(match value()?.as_str() {
                    "inbound" => ListenerRole::Inbound,
                    "submission" => ListenerRole::Submission,
                    "submissions-tls" => ListenerRole::SubmissionsTls,
                    other => return Err(format!("unknown role {other}")),
                });
            }
            "--listen" => {
                listen = Some(
                    value()?
                        .parse()
                        .map_err(|err| format!("bad --listen: {err}"))?,
                );
            }
            "--spool" => spool = Some(PathBuf::from(value()?)),
            "--state" => state = Some(PathBuf::from(value()?)),
            "--hostname" => hostname = Some(value()?),
            "--tls-cert" => cert = Some(PathBuf::from(value()?)),
            "--tls-key" => key = Some(PathBuf::from(value()?)),
            "--max-size" => {
                max_message_size = value()?
                    .parse()
                    .map_err(|err| format!("bad --max-size: {err}"))?;
            }
            "--max-header-bytes" => {
                max_header_bytes = value()?
                    .parse()
                    .map_err(|err| format!("bad --max-header-bytes: {err}"))?;
            }
            "--per-ip" => {
                per_ip_limit = value()?
                    .parse()
                    .map_err(|err| format!("bad --per-ip: {err}"))?;
            }
            "--submission-authenticates" => submission_authenticates = true,
            "--deliver" => deliver = true,
            "--retry-max-age-seconds" => {
                // The RFC 5321 §4.5.4.1 horizon, expressed in seconds: an
                // operator who needs a longer one says so, and the default is
                // not silently shortened by a unit mix-up.
                retry_max_age = Duration::from_secs(
                    value()?
                        .parse()
                        .map_err(|err| format!("bad --retry-max-age-seconds: {err}"))?,
                );
            }
            "--retry-max-attempts" => {
                retry_max_attempts = value()?
                    .parse()
                    .map_err(|err| format!("bad --retry-max-attempts: {err}"))?;
            }
            "--quota" => {
                quota = Some(
                    value()?
                        .parse()
                        .map_err(|err| format!("bad --quota: {err}"))?,
                );
            }
            "--interval-seconds" => {
                interval = Duration::from_secs(
                    value()?
                        .parse()
                        .map_err(|err| format!("bad --interval-seconds: {err}"))?,
                );
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let spool = spool.ok_or("--spool is required")?;
    let state = state.ok_or("--state is required")?;
    let hostname = hostname.ok_or("--hostname is required")?;
    if deliver {
        if role.is_some() || listen.is_some() {
            return Err("--deliver does not take --role or --listen".to_owned());
        }
        return Ok(Options::Deliver(DeliverOptions {
            spool,
            state,
            hostname,
            retry_max_age,
            retry_max_attempts,
            quota,
            interval,
        }));
    }
    let tls = match (cert, key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return Err("--tls-cert and --tls-key go together".to_owned()),
    };
    Ok(Options::Serve(ServeOptions {
        role: role.ok_or("--role is required")?,
        listen: listen.ok_or("--listen is required")?,
        spool,
        state,
        hostname,
        tls,
        max_message_size,
        max_header_bytes,
        per_ip_limit,
        submission_authenticates,
    }))
}

/// The credential check for a submission listener.
///
/// W1 does not link the identity store: an operator who turns this on gets a
/// verifier that accepts every login, which is only ever right behind a
/// network boundary that already authenticated the client (the internal
/// submission port the engine rig runs). W2 replaces this with the store's
/// `verify_password`.
struct OperatorVerifier {
    accept_all: bool,
}

impl PasswordVerifier for OperatorVerifier {
    fn verify<'a>(
        &'a self,
        _identity: &'a str,
        _password: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        let accept = self.accept_all;
        Box::pin(async move { accept })
    }
}

fn load_tls(cert: &PathBuf, key: &PathBuf) -> Result<TlsAcceptor, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert).map_err(|err| format!("{}: {err}", cert.display()))?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|err| format!("{}: {err}", cert.display()))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).map_err(|err| format!("{}: {err}", key.display()))?,
    ))
    .map_err(|err| format!("{}: {err}", key.display()))?
    .ok_or_else(|| format!("{}: no private key", key.display()))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("TLS configuration: {err}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = match parse_options() {
        Ok(options) => options,
        Err(err) => {
            eprintln!("{err}\n{}", usage());
            std::process::exit(2);
        }
    };
    match options {
        Options::Serve(options) => serve_listener(options).await,
        Options::Deliver(options) => deliver_forever(options).await,
    }
}

/// The receiving half: bind, recover, serve until the process is stopped.
async fn serve_listener(options: ServeOptions) -> Result<(), Box<dyn std::error::Error>> {
    let state: ayane_proto::DesiredState = serde_json::from_slice(&std::fs::read(&options.state)?)?;
    state.validate()?;
    let spool = Spool::open(&options.spool)?;
    // A crash leaves `tmp/` leftovers and, at worst, a half entry: recovery
    // runs before the first connection is accepted.
    let report = spool.recover()?;
    tracing::info!(
        tmp_removed = report.tmp_removed,
        intact = report.intact,
        corrupt = report.corrupt,
        "spool recovered"
    );
    let policy = AddressPolicy::from_state(&state);
    let verifier = if matches!(options.role, ListenerRole::Inbound) {
        Some(Verifier::with_system_resolver(&options.hostname)?)
    } else {
        // A submission listener does not verify: the client is already the
        // authenticated identity, and the outbound path signs in W5.
        None
    };
    let config = Arc::new(ServerConfig {
        hostname: options.hostname.clone(),
        role: options.role,
        max_message_size: options.max_message_size,
        limits: Limits {
            max_message_size: options.max_message_size,
            ..Limits::default()
        },
        per_ip_limit: options.per_ip_limit,
        command_timeout: ayane_smtpd::server::COMMAND_TIMEOUT,
        transaction_timeout: ayane_smtpd::server::TRANSACTION_TIMEOUT,
        spool,
        policy,
        state,
        passwords: Arc::new(OperatorVerifier {
            accept_all: options.submission_authenticates,
        }),
        verifier,
        tls: match &options.tls {
            Some((cert, key)) => Some(load_tls(cert, key)?),
            None => None,
        },
        max_received_headers: 25,
        // The header section bound: without it a peer's `DATA` decides how much
        // memory the streaming verifier's header buffer holds.
        max_header_bytes: options.max_header_bytes,
        // The only bound on password guessing that survives a reconnect.
        auth_guard: Some(Arc::new(ayane_smtpd::server::AuthGuard::default())),
    });
    if options.role.needs_tls() && config.tls.is_none() {
        return Err("this role requires --tls-cert and --tls-key".into());
    }
    let listener = tokio::net::TcpListener::bind(options.listen).await?;
    tracing::info!(%options.listen, role = ?options.role, "listening");
    serve(listener, config).await?;
    Ok(())
}

/// The delivery half: drain the queue, sleep until something is due, repeat.
///
/// Each iteration re-reads the state snapshot, so an operator who changes an
/// alias does not have to restart the consumer for the change to reach
/// delivery — the same reason the listener reads its snapshot per connection.
/// The sleep is bounded by the earliest due attempt the last pass reported
/// (never longer than `--interval-seconds`, never shorter than one second), so
/// a message that is due in fifteen minutes is not retried every thirty
/// seconds and not discovered an hour late.
async fn deliver_forever(options: DeliverOptions) -> Result<(), Box<dyn std::error::Error>> {
    let retry = ayane_smtpd::retry::RetryPolicy {
        max_age: options.retry_max_age,
        max_attempts: options.retry_max_attempts,
        ..ayane_smtpd::retry::RetryPolicy::default()
    };
    let deliverer = ayane_smtpd::deliver::Deliverer::new(
        Spool::open(&options.spool)?,
        options.hostname.clone(),
    )
    .with_retry(retry)
    .with_quota(options.quota);
    tracing::info!(
        spool = %options.spool.display(),
        max_age_seconds = options.retry_max_age.as_secs(),
        max_attempts = options.retry_max_attempts,
        "delivery consumer started"
    );
    loop {
        let state: ayane_proto::DesiredState =
            serde_json::from_slice(&std::fs::read(&options.state)?)?;
        state.validate()?;
        let passes = deliverer.run(&state)?;
        let due = next_due(&passes);
        let reports = passes.len();
        let waiting: usize = passes
            .iter()
            .map(|pass| pass.waiting().count())
            .sum::<usize>();
        tracing::info!(reports, waiting, "delivery pass finished");
        let cap = options.interval.as_secs().max(1);
        let sleep = due
            .map_or(cap, |due| due.saturating_sub(now_epoch()))
            .clamp(1, cap);
        tokio::time::sleep(Duration::from_secs(sleep)).await;
    }
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

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
