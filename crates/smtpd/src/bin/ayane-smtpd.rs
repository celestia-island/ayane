//! The operator's entry point: one listener per role, configured from a
//! state snapshot and a TLS certificate.
//!
//! W1 ships the receiving half only. The binary binds a listener, runs the
//! spool's recovery once, and serves until it is stopped; delivery from the
//! queue is W2's.
//!
//! ```text
//! ayane-smtpd --role inbound --listen 127.0.0.1:3025 --spool state/spool \
//!             --state state/desired-state.json --hostname mx.example.com
//! ```

#![warn(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
struct Options {
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

fn usage() -> &'static str {
    "usage: ayane-smtpd --role inbound|submission|submissions-tls \
        --listen ADDR --spool DIR --state FILE --hostname NAME \
        [--tls-cert FILE --tls-key FILE] [--max-size BYTES] \
        [--max-header-bytes BYTES] [--per-ip LIMIT] \
        [--submission-authenticates]"
}

fn parse_options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
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
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let tls = match (cert, key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => return Err("--tls-cert and --tls-key go together".to_owned()),
    };
    Ok(Options {
        role: role.ok_or("--role is required")?,
        listen: listen.ok_or("--listen is required")?,
        spool: spool.ok_or("--spool is required")?,
        state: state.ok_or("--state is required")?,
        hostname: hostname.ok_or("--hostname is required")?,
        tls,
        max_message_size,
        max_header_bytes,
        per_ip_limit,
        submission_authenticates,
    })
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
