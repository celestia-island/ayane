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
//! ayane-smtpd --deliver --spool state/spool --mail-root /var/mail/vhosts \
//!             --state state/desired-state.json --hostname mx.example.com \
//!             [--retry-max-age-seconds N] [--quota BYTES]
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
    /// Where the mailboxes live (`/var/mail/vhosts`). Never the spool.
    mail_root: PathBuf,
    state: PathBuf,
    hostname: String,
    retry_max_age: Duration,
    retry_max_attempts: u32,
    quota: Option<u64>,
    interval: Duration,
    /// Deliver to remote domains over SMTP (the outbound transport). Off by
    /// default: a consumer without it leaves remote recipients in the queue,
    /// which is what a local-only deployment wants and what every pass before
    /// this flag existed did.
    outbound: bool,
    /// The port the outbound transport connects to. `25` — the MX default — is
    /// what a deployment uses; a rig behind a NAT that forwards another port
    /// says so.
    smtp_port: u16,
    /// The environment variable each hosted domain's DKIM private key is read
    /// from, with `{domain}` standing in for the domain name (PKCS #8 PEM).
    ///
    /// One variable per domain rather than one directory of keys because the
    /// delivery of a secret is the operator's environment (systemd
    /// `LoadCredential`, a 0600 env file) and this process only reads the name:
    /// nothing here opens a path of its own, and no key is ever written to the
    /// state snapshot.
    ///
    /// **The substituted name carries no dot.** A POSIX environment variable
    /// name may not contain one, and every hosted domain has one, so the
    /// domain is spelled with `_` where its dots are:
    /// `--dkim-key-env 'AYANE_DKIM_KEY_{domain}'` reads `example.com`'s key
    /// from `AYANE_DKIM_KEY_example_com`. See
    /// [`ayane_smtpd::outbound::dkim_env_name`].
    dkim_key_env: Option<String>,
}

fn usage() -> &'static str {
    "usage: ayane-smtpd --role inbound|submission|submissions-tls \
        --listen ADDR --spool DIR --state FILE --hostname NAME \
        [--tls-cert FILE --tls-key FILE] [--max-size BYTES] \
        [--max-header-bytes BYTES] [--per-ip LIMIT] \
        [--submission-authenticates]\n\
     \x20 or: ayane-smtpd --deliver --spool DIR --mail-root DIR --state FILE \
        --hostname NAME [--retry-max-age-seconds N] [--retry-max-attempts N] \
        [--quota BYTES] [--interval-seconds N] [--outbound] \
        [--smtp-port N] [--dkim-key-env VAR]\n\
     \x20 (VAR may contain {domain}; a domain's dots become _ in the name: \
        example.com -> example_com)"
}

fn parse_options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut deliver = false;
    let mut retry_max_age = ayane_smtpd::retry::RetryPolicy::DEFAULT_MAX_AGE;
    let mut retry_max_attempts = 0u32;
    let mut quota = None;
    let mut interval = Duration::from_secs(30);
    let mut outbound = false;
    let mut smtp_port = ayane_smtpd::outbound::SMTP_PORT;
    let mut dkim_key_env = None;
    let mut role = None;
    let mut listen = None;
    let mut spool = None;
    let mut mail_root = None;
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
            "--mail-root" => mail_root = Some(PathBuf::from(value()?)),
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
            "--outbound" => outbound = true,
            "--smtp-port" => {
                smtp_port = value()?
                    .parse()
                    .map_err(|err| format!("bad --smtp-port: {err}"))?;
            }
            "--dkim-key-env" => dkim_key_env = Some(value()?),
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
            mail_root: mail_root
                .ok_or("--mail-root is required with --deliver (it is never the spool)")?,
            state,
            hostname,
            retry_max_age,
            retry_max_attempts,
            quota,
            interval,
            outbound,
            smtp_port,
            dkim_key_env,
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

/// Installs the log subscriber, before anything can want to log.
///
/// Until this runs, every `tracing` event in this crate and the ones it calls
/// is dropped: `warn!` and `error!` are macros that check for a subscriber
/// first, and with none installed they are no-ops. That is the difference
/// between an operator seeing "a DKIM selector is configured but its key is not
/// in the environment" and that message existing only in the source.
///
/// The filter is `RUST_LOG` when set, and `warn` when not -- the level at which
/// this binary has something to say (a missing key, a failed handshake, a
/// snapshot that cannot be used) without drowning a systemd journal in a line
/// per connection. `AYANE_LOG` is the family's name for the same knob; it is
/// honoured when `RUST_LOG` is not set, so an operator who already writes one
/// for the control plane does not have to learn a second spelling.
///
/// A filter that does not parse falls back to `warn` and says so on stderr: a
/// typo must not cost the operator the very messages this installs.
fn init_tracing() {
    let (directives, source) = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => (value, "RUST_LOG"),
        _ => match std::env::var("AYANE_LOG") {
            Ok(value) if !value.trim().is_empty() => (value, "AYANE_LOG"),
            _ => ("warn".to_owned(), "default"),
        },
    };
    let filter = tracing_subscriber::EnvFilter::try_new(&directives).unwrap_or_else(|err| {
        eprintln!("ignoring a malformed {source}={directives:?}: {err}; logging at `warn`");
        tracing_subscriber::EnvFilter::new("warn")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    tracing::debug!(source, directives = %directives, "log subscriber installed");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
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
        // A listener started from this binary has no one to hand the numbers
        // to: the control plane that reports traffic starts its own listeners
        // in-process (`--serve` here is the split-process shape, for an
        // installation that wants the listener under its own unit).
        metrics: None,
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
    let spool = Spool::open(&options.spool)?;
    let mut deliverer = ayane_smtpd::deliver::Deliverer::new(
        spool,
        options.mail_root.clone(),
        options.hostname.clone(),
    )
    .with_retry(retry)
    .with_quota(options.quota);
    if options.outbound {
        // The outbound transport: an MX resolver, the opportunistic-TLS client
        // and the DKIM signers the state's selectors name. The keys are read
        // from the process environment here and nowhere else, so the state
        // snapshot on disk never carries one.
        let resolver: std::sync::Arc<dyn ayane_smtpd::outbound::Resolver> = std::sync::Arc::new(
            ayane_smtpd::outbound::SystemResolver::system().map_err(|err| err.to_string())?,
        );
        let mut transport =
            ayane_smtpd::outbound::Outbound::new(resolver, options.hostname.clone())
                .with_port(options.smtp_port);
        // The signers need the state, which this function has not loaded yet:
        // it is read once here for the keys and once more every pass for the
        // routing (an operator who adds a domain does not restart the
        // consumer, and a selector change is a restart).
        if let Some(template) = &options.dkim_key_env {
            match load_state(&options.state) {
                Ok(state) => {
                    let signers = ayane_smtpd::outbound::signers_from_env(&state, template)
                        .map_err(|err| err.to_string())?;
                    for (_, signer) in signers {
                        transport = transport.with_signer(signer);
                    }
                }
                Err(reason) => {
                    tracing::warn!(%reason, "no state yet: outbound mail will be unsigned");
                }
            }
        }
        deliverer = deliverer.with_remote(std::sync::Arc::new(
            ayane_smtpd::outbound::SyncedTransport::new(transport)?,
        ));
        tracing::info!(port = options.smtp_port, "outbound transport enabled");
    }
    // The two roots are the one mistake this process cannot survive: writing
    // mail into the spool's own directory names is a failure that looks like
    // success. It is checked before the first pass, and a bad pair is fatal —
    // this is not a configuration value that can be ignored.
    deliverer.check_roots()?;
    tracing::info!(
        spool = %options.spool.display(),
        mail_root = %options.mail_root.display(),
        max_age_seconds = options.retry_max_age.as_secs(),
        max_attempts = options.retry_max_attempts,
        "delivery consumer started"
    );
    let mut last_warning: Option<String> = None;
    loop {
        // A snapshot that cannot be loaded, parsed or validated is a *skipped
        // pass*, never a stopped consumer. The receiver may already have
        // accepted mail for this instance (a `250` is a promise the spool
        // keeps), and a consumer that exits on a bad annotation file would
        // leave that mail sitting in `cur/` with nobody to deliver it. So the
        // loop logs the reason once, keeps the process alive, and tries again
        // on the next tick — the same treatment an unreadable spool gets.
        let state = match load_state(&options.state) {
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
                tokio::time::sleep(options.interval).await;
                continue;
            }
        };
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

/// Reads, parses and validates the state snapshot, or says why it cannot be
/// used.
///
/// The three failures are one answer to the consumer — "do not deliver this
/// pass" — because each of them makes the routing snapshot unusable in a
/// different way and none of them is the consumer's to fix: a missing file is
/// an apply that has not run yet, a parse error is a half-written file, and a
/// rejected state is one the operator has to change.
fn load_state(path: &std::path::Path) -> Result<ayane_proto::DesiredState, String> {
    let bytes = std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let state: ayane_proto::DesiredState =
        serde_json::from_slice(&bytes).map_err(|err| format!("{}: {err}", path.display()))?;
    state
        .validate()
        .map_err(|err| format!("{}: {err}", path.display()))?;
    // Ambiguous objects are warnings, not failures: `route` has a fixed order
    // for them and the operator should see which objects they are.
    for warning in state.warnings() {
        tracing::warn!(state = %path.display(), %warning, "state snapshot warning");
    }
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

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_state(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ayane-smtpd-bin-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("desired-state.json");
        std::fs::write(&path, contents).expect("write");
        path
    }

    #[test]
    fn a_usable_snapshot_loads() {
        let path = temp_state(
            "good",
            r#"{"domains":[],"accounts":[],"aliases":[],"shared":[],
                "policy":{"default_action":"reject","allowlist":[],"denylist":[]}}"#,
        );
        let state = load_state(&path).expect("a healthy snapshot");
        assert!(state.warnings().is_empty());
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn an_unusable_snapshot_is_reported_not_fatal() {
        // `S1-d`: the three ways a snapshot can be unusable are the three
        // reasons the consumer holds delivery instead of exiting. The receiver
        // may already hold mail for this instance (a 250 is a promise), so a
        // consumer that stopped here would strand it.
        let missing = temp_state("missing", "");
        let parent = missing.parent().expect("dir").to_path_buf();
        std::fs::remove_file(&missing).expect("remove");
        assert!(
            load_state(&missing).is_err(),
            "a missing file is not a state"
        );

        let broken = temp_state("broken", "{\"domains\": [");
        assert!(
            load_state(&broken).is_err(),
            "a half-written file is not a state"
        );

        // A state `validate` refuses: an account in a domain nobody hosts.
        let unhosted = temp_state(
            "unhosted",
            r#"{"domains":[],"accounts":[{"id":"00000000-0000-0000-0000-000000000000",
                "address":"a@nowhere.example","display_name":"A","quota_bytes":0}],
                "aliases":[],"shared":[],
                "policy":{"default_action":"reject","allowlist":[],"denylist":[]}}"#,
        );
        let reason = load_state(&unhosted).expect_err("an unhosted account is refused");
        assert!(reason.contains("nowhere.example"), "{reason}");
        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_dir_all(unhosted.parent().expect("dir"));
        let _ = std::fs::remove_dir_all(broken.parent().expect("dir"));
    }

    #[test]
    fn an_ambiguous_but_usable_snapshot_loads_with_its_warnings() {
        // 裁决 1: an address that is both a shared mailbox and an alias source
        // is no longer fatal — it loads, and `route`'s fixed order decides.
        let path = temp_state(
            "ambiguous",
            r#"{"domains":[{"name":"example.com","catch_all":null,"enabled":true}],
                "accounts":[],"shared":[{"address":"team@example.com","members":[],
                "id":"00000000-0000-0000-0000-000000000000"}],
                "aliases":[{"source":"team@example.com","targets":["x@other.example"]}],
                "policy":{"default_action":"reject","allowlist":[],"denylist":[]}}"#,
        );
        // An empty-member shared mailbox is still refused; give it a member.
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::write(
            &path,
            text.replace(
                "\"members\":[]",
                "\"members\":[\"00000000-0000-0000-0000-000000000001\"]",
            ),
        )
        .expect("write");
        let state = load_state(&path).expect("an ambiguous address is a warning");
        assert_eq!(state.warnings().len(), 1, "{:?}", state.warnings());
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}
