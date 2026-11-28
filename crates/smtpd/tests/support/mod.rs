//! Test support: a fixture state, a running listener, and a raw SMTP client.
//!
//! Everything the security matrix needs is here so each test reads as one
//! assertion about observable behaviour: what the client wrote, what the
//! client read, what ended up in the spool.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ayane_proto::{
    Account, Address, Alias, DefaultAction, DesiredState, MailDomain, Policy, SenderRule,
};
use ayane_smtpd::authn::{DenyAll, PasswordVerifier};
use ayane_smtpd::policy::AddressPolicy;
use ayane_smtpd::queue::Spool;
use ayane_smtpd::server::{serve, AuthGuard, ServerConfig};
use ayane_smtpd::session::Limits;
use ayane_smtpd::ListenerRole;
use tokio::net::TcpListener;
use uuid::Uuid;

/// A verifier that accepts one fixed credential pair.
pub struct FixedPassword {
    identity: String,
    password: String,
}

impl FixedPassword {
    /// Accepts exactly `identity` / `password`.
    pub fn new(identity: &str, password: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            password: password.to_owned(),
        }
    }
}

impl PasswordVerifier for FixedPassword {
    fn verify<'a>(
        &'a self,
        identity: &'a str,
        password: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        let ok = identity.eq_ignore_ascii_case(&self.identity) && password == self.password;
        Box::pin(async move { ok })
    }
}

fn addr(raw: &str) -> Address {
    Address::parse(raw).expect("fixture address")
}

/// The fixture state: `example.com` with two accounts, an alias, a shared
/// mailbox and the catch-all switch as configured.
pub fn fixture_state(catch_all: bool) -> DesiredState {
    DesiredState {
        domains: vec![MailDomain {
            name: "example.com".to_owned(),
            catch_all: catch_all.then(|| addr("inbox@example.com")),
            enabled: true,
            dkim: None,
        }],
        accounts: vec![
            Account {
                id: Uuid::new_v4(),
                address: addr("inbox@example.com"),
                display_name: "Inbox".to_owned(),
                quota_bytes: 0,
                admin: true,
            },
            Account {
                id: Uuid::new_v4(),
                address: addr("ops@example.com"),
                display_name: "Ops".to_owned(),
                quota_bytes: 0,
                admin: false,
            },
        ],
        aliases: vec![Alias {
            source: addr("sales@example.com"),
            targets: vec![addr("ops@example.com")],
        }],
        shared: vec![ayane_proto::SharedMailbox {
            id: Uuid::new_v4(),
            address: addr("team@example.com"),
            members: vec![Uuid::new_v4()],
        }],
        policy: Policy {
            default_action: DefaultAction::Reject,
            allowlist: Vec::new(),
            denylist: vec![SenderRule::Domain("spam.example".to_owned())],
            variants: Default::default(),
        },
        audit: Default::default(),
        mcp: Default::default(),
    }
}

/// A temporary directory that cleans itself up.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a directory under the system temp dir.
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ayane-smtpd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    /// The path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// How to build the fixture listener.
#[derive(Clone)]
pub struct HarnessOptions {
    /// The listener role (this is the authorisation branch).
    pub role: ListenerRole,
    /// The fixture state's catch-all switch.
    pub catch_all: bool,
    /// Run SPF/DKIM/DMARC verification.
    pub verify: bool,
    /// Offer TLS (only reaches the client as STARTTLS on the submission role).
    pub tls: bool,
    /// The credential the submission listener accepts.
    pub password: Option<(String, String)>,
    /// Overrides for the session limits.
    pub limits: Limits,
    /// The SIZE ceiling.
    pub max_message_size: u64,
    /// The RFC 5321 command timer (default 5 min).
    pub command_timeout: Duration,
    /// The RFC 5321 mail transaction timer (default 10 min).
    pub transaction_timeout: Duration,
    /// The per-peer AUTH failure budget, as `(failures, window)`; `None` turns
    /// the per-peer bound off (only appropriate for a test that is not about
    /// it — a deployment always runs with one).
    pub auth_guard: Option<(usize, Duration)>,
    /// The largest header section the listener accepts.
    pub max_header_bytes: u64,
    /// Whether the listener counts traffic. Off by default: a counter here is
    /// a shared, order-dependent number in every test that starts a listener,
    /// and only a test that asks for one should see it.
    pub metrics: bool,
    /// The content scanner this listener runs with (`None` = unconfigured,
    /// which is the default and the zero-behaviour-change case).
    pub rspamd: Option<ayane_smtpd::rspamd::RspamdClient>,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            role: ListenerRole::Inbound,
            catch_all: false,
            verify: false,
            tls: false,
            password: None,
            limits: Limits::default(),
            max_message_size: 25 * 1024 * 1024,
            command_timeout: Duration::from_secs(300),
            transaction_timeout: Duration::from_secs(600),
            auth_guard: None,
            max_header_bytes: ayane_smtpd::server::DEFAULT_MAX_HEADER_BYTES,
            metrics: false,
            rspamd: None,
        }
    }
}

impl HarnessOptions {
    /// The default inbound listener without verification.
    pub fn inbound() -> Self {
        Self::default()
    }

    /// The submission listener on 587 with STARTTLS.
    pub fn submission() -> Self {
        Self {
            role: ListenerRole::Submission,
            tls: true,
            password: Some(("ops@example.com".to_owned(), "s3cret".to_owned())),
            ..Self::default()
        }
    }
}

/// A running listener plus its spool.
pub struct Harness {
    /// The bound address.
    pub addr: SocketAddr,
    /// The spool root.
    pub spool: Spool,
    /// The fixture state, for assertions.
    pub state: DesiredState,
    /// The temp dir holding the spool.
    pub dir: TempDir,
    /// The per-peer AUTH budget this listener runs with, when it has one.
    pub auth_guard: Option<Arc<AuthGuard>>,
    /// The traffic counters this listener writes to, when it was asked for
    /// them ([`HarnessOptions::metrics`]).
    pub metrics: Option<Arc<ayane_smtpd::metrics::Metrics>>,
    shutdown: Arc<AtomicBool>,
}

impl Harness {
    /// The mail tree the fixture's deliveries land in: a sibling of the
    /// spool, never the spool itself.
    pub fn mail_root(&self) -> std::path::PathBuf {
        self.dir.path().join("mail")
    }

    /// Starts a listener on a loopback port.
    pub async fn start(tag: &str, options: HarnessOptions) -> Self {
        Self::start_with(tag, options, None).await
    }

    /// [`Harness::start`] with a caller-supplied state instead of the fixture's.
    ///
    /// The routing snapshot, the address policy and the `Received:` name all
    /// come from it, so a test that needs a different hosted set (the outbound
    /// tests do: one listener must see a domain outside its delivery snapshot)
    /// gets one without a second harness.
    pub async fn start_with(
        tag: &str,
        options: HarnessOptions,
        state: Option<DesiredState>,
    ) -> Self {
        let dir = TempDir::new(tag);
        let spool = Spool::open(dir.path().join("spool")).expect("spool");
        let state = state.unwrap_or_else(|| fixture_state(options.catch_all));
        let policy = AddressPolicy::from_state(&state);
        let tls = options
            .tls
            .then(|| tokio_rustls::TlsAcceptor::from(Arc::new(test_tls_config())));
        let verifier = options
            .verify
            .then(|| ayane_smtpd::verify::Verifier::with_system_resolver("mx.test"))
            .transpose()
            .expect("verifier");
        let passwords: Arc<dyn PasswordVerifier> = match &options.password {
            Some((identity, password)) => Arc::new(FixedPassword::new(identity, password)),
            None => Arc::new(DenyAll),
        };
        let auth_guard = options
            .auth_guard
            .map(|(budget, window)| Arc::new(AuthGuard::new(budget, window)));
        let metrics = options
            .metrics
            .then(|| Arc::new(ayane_smtpd::metrics::Metrics::new()));
        let config = Arc::new(ServerConfig {
            hostname: "mx.test".to_owned(),
            role: options.role,
            max_message_size: options.max_message_size,
            limits: options.limits,
            per_ip_limit: 8,
            command_timeout: options.command_timeout,
            transaction_timeout: options.transaction_timeout,
            spool: spool.clone(),
            policy,
            state: state.clone(),
            passwords,
            verifier,
            rspamd: options.rspamd.clone(),
            tls,
            max_received_headers: 25,
            max_header_bytes: options.max_header_bytes,
            auth_guard: auth_guard.clone(),
            // The harness counts nothing unless a test asks: a counter here
            // would be a shared, order-dependent number in every test that
            // happens to start a listener. `Harness::metrics` reads them.
            metrics: metrics.clone(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve(listener, config).await;
        });
        Self {
            addr,
            spool,
            state,
            dir,
            auth_guard,
            metrics,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A raw client connected to this listener.
    pub fn client(&self) -> Client {
        Client::connect(self.addr)
    }

    /// The committed messages.
    pub fn queued(&self) -> Vec<ayane_smtpd::queue::QueuedMessage> {
        self.spool
            .list(ayane_smtpd::queue::QueueState::New)
            .expect("list")
    }

    /// The only committed message's bytes.
    pub fn only_message(&self) -> Vec<u8> {
        let queued = self.queued();
        assert_eq!(queued.len(), 1, "expected exactly one queued message");
        self.spool
            .read_message(ayane_smtpd::queue::QueueState::New, &queued[0].id)
            .expect("read")
    }

    /// Marks the harness as done (the listener task is detached by design).
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// A raw SMTP client: every byte on the wire is under test control.
///
/// `pending` holds client-side upload bytes that must reach the server before
/// the next reply can arrive: TCP will not deliver a reply the application
/// layer has not finished sending, and the server deliberately reads a BDAT
/// chunk's octets after acknowledging the command.
pub struct Client {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    pending: Option<Vec<u8>>,
}

impl Client {
    /// Connects and reads the greeting.
    pub fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_nodelay(true).expect("nodelay");
        let reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut client = Self {
            stream,
            reader,
            pending: None,
        };
        let greeting = client.read_reply();
        assert_eq!(greeting.code, 220, "greeting: {greeting:?}");
        client
    }

    /// Queues raw octets that follow the next command on the wire (the BDAT
    /// chunk body): they are written together with that command, exactly as a
    /// pipelining client would.
    pub fn pending(&mut self, bytes: &[u8]) {
        self.pending = Some(bytes.to_vec());
    }

    /// Drops octets queued by [`Client::pending`] without sending them: for a
    /// command the server is expected to answer before it reads them.
    pub fn clear_pending(&mut self) {
        self.pending = None;
    }

    /// Sends `NOOP` and reads its reply, so the client knows the server is at
    /// a command boundary.
    ///
    /// A chunking client and the server take turns: the server will not read
    /// the next command until the current chunk's octets are in. After the
    /// reply to a `BDAT` whose octets were already written, the server may
    /// still be finishing the read of those octets when the next command is
    /// written, and what the client sees first is not guaranteed to be the
    /// reply to that command. A `NOOP` — which the client's own write of the
    /// chunk's octets precedes — puts the connection back in step.
    pub fn settle(&mut self) {
        self.expect("NOOP", 250);
    }

    /// Writes raw octets, no interpretation.
    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("write");
        self.stream.flush().expect("flush");
    }

    /// Writes raw octets without reading the reply: for the cases where the
    /// transfer is refused and the server may close the socket while the
    /// client is still uploading (the next read then sees EOF).
    pub fn send_raw_best_effort(&mut self, bytes: &[u8]) {
        let _ = self.stream.write_all(bytes);
        let _ = self.stream.flush();
    }

    /// Writes raw octets in one piece at a time, best effort, without reading
    /// a reply.
    ///
    /// Asynchronous Rust TCP stacks cap a single segment at `TCP_MAXSEG` (the
    /// async loopback connects with a ~8 KiB MSS), and a `write_all` larger
    /// than the buffers would block — which, for a client whose point is
    /// "these octets must not all fit", is a deadlock rather than a test. A
    /// real chunking client writes a chunk in whatever pieces its stack gives
    /// it, so this is also the honest shape.
    pub fn send_raw_pieces(&mut self, bytes: &[u8]) {
        for piece in bytes.chunks(64 * 1024) {
            if self.stream.write_all(piece).is_err() {
                return;
            }
        }
        let _ = self.stream.flush();
    }

    /// Sets how long a plain [`Client::read_reply`] waits for the server.
    ///
    /// The default is the socket's twenty seconds, which is what a test that
    /// asserts *that* a reply arrives wants. A test that asserts **when** it
    /// arrives needs the wait itself to be short, so a regression fails as a
    /// read timeout instead of passing after a longer wait that the assertion
    /// never looked at.
    pub fn set_read_timeout(&mut self, within: Duration) {
        self.stream.set_read_timeout(Some(within)).expect("timeout");
        self.reader
            .get_ref()
            .set_read_timeout(Some(within))
            .expect("timeout");
    }

    /// Measures how long [`Client::read_reply`] takes, with no bound but the
    /// socket's own. Used where the bound under test is "well under a second"
    /// and the assertion is on the measurement, not on a timeout.
    pub fn read_reply_timed(&mut self) -> (Duration, Reply) {
        let started = std::time::Instant::now();
        let reply = self.read_reply();
        (started.elapsed(), reply)
    }

    /// Shuts the write side down, so a server waiting for a terminator sees
    /// EOF instead of waiting for its timer.
    pub fn finish_sending(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Write);
    }

    /// Whether the server is done with the connection, now that the client
    /// has stopped sending.
    ///
    /// Every octet the server already wrote is drained first, so a reply
    /// arriving late cannot be mistaken for a live connection; what is left
    /// after the drain is the question. `true` when the connection is closed
    /// or reset within `within`, `false` when it is still open and silent.
    pub fn closed_without_sending(&mut self, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        let mut byte = [0u8; 1];
        loop {
            // A peek never consumes: EOF, a reset and "nothing yet" stay three
            // different answers, and a reply in the buffer is taken as "still
            // talking" only until it is drained.
            self.stream.set_nonblocking(true).expect("client socket");
            let outcome = self.stream.peek(&mut byte);
            self.stream.set_nonblocking(false).expect("client socket");
            match outcome {
                Ok(0) => return true,
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return true,
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Reads whatever the server wrote without ever blocking on the socket,
    /// returning the bytes and whether the server closed.
    ///
    /// With no octets owed to the server, `read` puts what is there into the
    /// kernel's buffer: this is "everything the server sent before it went
    /// quiet", which a blocking read cannot see (it waits for octets, and
    /// then sees them in one piece).
    pub fn drain_available(&mut self, within: Duration) -> (String, bool) {
        let deadline = std::time::Instant::now() + within;
        self.stream.set_nonblocking(true).expect("client socket");
        let mut out = Vec::new();
        let mut closed = false;
        let mut buffer = [0u8; 4096];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(read) => out.extend_from_slice(&buffer[..read]),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    closed = true;
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stream.set_nonblocking(false).expect("client socket");
        (String::from_utf8_lossy(&out).into_owned(), closed)
    }

    /// Shuts the write side down and reads until the server closes too,
    /// returning everything the server sent after the replies already read.
    ///
    /// A client whose octets are still on the wire keeps the kernel from
    /// reporting the server's close — it sends a reset instead of a FIN — so a
    /// test that wants to see "the server closed the socket" has to stop
    /// sending first. This is that, in one call.
    pub fn finish_reading(&mut self) -> String {
        self.finish_sending();
        self.read_to_end()
    }

    /// Writes one CRLF-terminated command.
    pub fn send(&mut self, line: &str) {
        self.send_raw(format!("{line}\r\n").as_bytes());
    }

    /// Reads one complete (possibly multi-line) reply.
    pub fn read_reply(&mut self) -> Reply {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).expect("read reply");
            assert!(read > 0, "connection closed while reading a reply");
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let code: u16 = line
                .get(..3)
                .and_then(|digits| digits.parse().ok())
                .unwrap_or_else(|| panic!("no reply code in {line:?}"));
            let text = line.get(4..).unwrap_or_default().to_owned();
            match line.as_bytes().get(3) {
                Some(b'-') => lines.push(text),
                _ => {
                    lines.push(text.clone());
                    return Reply { code, text, lines };
                }
            }
        }
    }

    /// Sends a command and reads the reply. Queued [`Client::pending`] octets
    /// follow the command on the wire, as a chunking client writes them.
    pub fn command(&mut self, line: &str) -> Reply {
        let pending = self.pending.take().unwrap_or_default();
        let mut wire = format!("{line}\r\n").into_bytes();
        wire.extend_from_slice(&pending);
        self.send_raw(&wire);
        self.read_reply()
    }

    pub fn command_tls(&mut self, line: &str) -> Reply {
        self.send(line);
        self.read_reply()
    }

    /// Sends a command and asserts the expected code, returning the reply.
    #[track_caller]
    pub fn expect(&mut self, line: &str, code: u16) -> Reply {
        let reply = self.command(line);
        assert_eq!(
            reply.code, code,
            "`{line}` answered {reply:?}, expected {code}"
        );
        reply
    }

    /// Runs EHLO and asserts 250.
    pub fn ehlo(&mut self, name: &str) -> Reply {
        let reply = self.expect(&format!("EHLO {name}"), 250);
        reply
    }

    /// Reads one raw line (for DATA replies that are not commands).
    pub fn read_line(&mut self) -> String {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read line");
        line
    }

    /// Whether the server has closed its side: `true` at EOF, `false` while
    /// the socket stays open, and at worst `within` of waiting.
    ///
    /// [`Client::try_read_reply`] answers `false` for a connection that is
    /// open and silent, which is exactly what a test about "the server closed,
    /// it did not wait" must be able to tell apart from "EOF arrived".
    pub fn is_closed_within(&mut self, within: Duration) -> bool {
        self.stream.set_read_timeout(Some(within)).expect("timeout");
        let mut byte = [0u8; 1];
        matches!(self.stream.read(&mut byte), Ok(0))
    }

    /// Reads one reply, waiting at most `within` for it; `None` when nothing
    /// arrived in time (the connection is open and silent) or the server
    /// already closed it.
    ///
    /// With a read timeout set, the plain [`Client::try_read_reply`] cannot be
    /// used: a timed wait surfaces as an I/O error, not as EOF.
    pub fn try_read_reply_within(&mut self, within: Duration) -> Option<Reply> {
        self.stream.set_read_timeout(Some(within)).expect("timeout");
        let mut lines = Vec::new();
        let reply = loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) | Err(_) => break None,
                Ok(_) => {}
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let Some(code) = line.get(..3).and_then(|digits| digits.parse::<u16>().ok()) else {
                break None;
            };
            let text = line.get(4..).unwrap_or_default().to_owned();
            if line.as_bytes().get(3) == Some(&b'-') {
                lines.push(text);
                continue;
            }
            lines.push(text.clone());
            break Some(Reply { code, text, lines });
        };
        self.stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        reply
    }

    /// Reads one reply; `None` when the server already closed the connection.
    pub fn try_read_reply(&mut self) -> Option<Reply> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line).expect("read reply") == 0 {
                return None;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let code: u16 = line.get(..3).and_then(|digits| digits.parse().ok())?;
            let text = line.get(4..).unwrap_or_default().to_owned();
            match line.as_bytes().get(3) {
                Some(b'-') => lines.push(text),
                _ => {
                    lines.push(text.clone());
                    return Some(Reply { code, text, lines });
                }
            }
        }
    }

    /// Reads until EOF and returns everything.
    pub fn read_to_end(&mut self) -> String {
        let mut buffer = String::new();
        let _ = self.reader.read_to_string(&mut buffer);
        buffer
    }
}

/// A parsed reply.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The code.
    pub code: u16,
    /// The last line's text.
    pub text: String,
    /// All lines (the capability list for EHLO).
    pub lines: Vec<String>,
}

impl Reply {
    /// Whether any capability line equals `capability`.
    pub fn advertises(&self, capability: &str) -> bool {
        self.lines.iter().any(|line| line == capability)
    }

    /// Whether any capability line starts with `prefix`.
    pub fn advertises_prefix(&self, prefix: &str) -> bool {
        self.lines.iter().any(|line| line.starts_with(prefix))
    }
}

/// A rustls server configuration with a self-signed certificate for
/// `mx.test`, generated once per test process.
pub fn test_tls_config() -> rustls::ServerConfig {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cert, key) = static_certificate();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())),
        )
        .expect("server config");
    config
}

/// The client side: trust exactly the test certificate.
pub fn test_client_config() -> Arc<rustls::ClientConfig> {
    use rustls::pki_types::{CertificateDer, ServerName};
    let (cert, _) = static_certificate();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert.clone())).expect("root");
    let _ = ServerName::try_from("mx.test").expect("server name");
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// One DER certificate and key, derived from a fixed self-signed PEM pair.
fn static_certificate() -> &'static (Vec<u8>, Vec<u8>) {
    use std::sync::OnceLock;
    static CERT: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CERT.get_or_init(|| {
        // A self-signed pair generated for the tests only; it authenticates
        // nothing and protects nothing, which is exactly its role here.
        let pem_cert = include_str!("../fixtures/test-cert.pem");
        let pem_key = include_str!("../fixtures/test-key.pem");
        (decode_pem(pem_cert), decode_pem(pem_key))
    })
}

fn decode_pem(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64_decode(&body)
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("pem base64")
}

/// Feeds a whole SMTP transaction for a local recipient and returns the final
/// reply.
pub fn deliver(client: &mut Client, sender: &str, recipient: &str, message: &str) -> Reply {
    client.ehlo("client.test");
    client.expect(&format!("MAIL FROM:<{sender}>"), 250);
    client.expect(&format!("RCPT TO:<{recipient}>"), 250);
    client.expect("DATA", 354);
    let mut body = String::new();
    for line in message.split_inclusive('\n') {
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        if line.starts_with('.') {
            body.push('.');
        }
        body.push_str(line);
        body.push_str("\r\n");
    }
    body.push_str(".\r\n");
    client.send_raw(body.as_bytes());
    client.read_reply()
}

/// A client that upgrades to TLS by hand, for the STARTTLS/AUTH tests.
pub struct TlsClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    tls: Option<rustls::StreamOwned<rustls::ClientConnection, Replayed>>,
}

impl TlsClient {
    /// Connects and reads the greeting, still in plain text.
    pub fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        stream.set_nodelay(true).expect("nodelay");
        let reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut client = Self {
            stream,
            reader,
            tls: None,
        };
        let greeting = client.read_reply();
        assert_eq!(greeting.code, 220, "greeting: {greeting:?}");
        client
    }

    /// Writes raw octets.
    pub fn send_raw(&mut self, bytes: &[u8]) {
        match self.tls.as_mut() {
            Some(conn) => {
                conn.write_all(bytes).expect("tls write");
                conn.flush().expect("tls flush");
            }
            None => {
                self.stream.write_all(bytes).expect("write");
                self.stream.flush().expect("flush");
            }
        }
    }

    /// Sends one CRLF-terminated command.
    pub fn send(&mut self, line: &str) {
        self.send_raw(format!("{line}\r\n").as_bytes());
    }

    /// Reads one reply.
    pub fn read_reply(&mut self) -> Reply {
        let mut lines = Vec::new();
        loop {
            let line = match self.tls.as_mut() {
                Some(conn) => read_line_owned(conn),
                None => {
                    let mut line = String::new();
                    let read = self.reader.read_line(&mut line).expect("read");
                    assert!(read > 0, "connection closed while reading a reply");
                    line
                }
            };
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let code: u16 = line
                .get(..3)
                .and_then(|digits| digits.parse().ok())
                .unwrap_or_else(|| panic!("no reply code in {line:?}"));
            let text = line.get(4..).unwrap_or_default().to_owned();
            match line.as_bytes().get(3) {
                Some(b'-') => lines.push(text),
                _ => {
                    lines.push(text.clone());
                    return Reply { code, text, lines };
                }
            }
        }
    }

    /// Sends a command and reads the reply.
    pub fn command(&mut self, line: &str) -> Reply {
        self.send(line);
        self.read_reply()
    }

    /// Sends a command and asserts the expected code.
    #[track_caller]
    pub fn expect(&mut self, line: &str, code: u16) -> Reply {
        let reply = self.command(line);
        assert_eq!(
            reply.code, code,
            "`{line}` answered {reply:?}, expected {code}"
        );
        reply
    }

    /// Runs EHLO and asserts 250.
    pub fn ehlo(&mut self, name: &str) -> Reply {
        self.expect(&format!("EHLO {name}"), 250)
    }

    /// Reads one plain-text reply (before the handshake), waiting at most
    /// `within` for it.
    ///
    /// `None` means nothing arrived in time: the server is holding the
    /// connection open and silent. It is the "the server closed the socket"
    /// question of [`Client::try_read_reply_within`] asked of a client that is
    /// about to upgrade, and it is what a test needs to tell "answered then
    /// closed" from "answered and kept waiting".
    pub fn try_read_reply_within(&mut self, within: Duration) -> Option<Reply> {
        assert!(
            self.tls.is_none(),
            "try_read_reply_within is for the plain-text phase"
        );
        self.stream.set_read_timeout(Some(within)).expect("timeout");
        let mut lines = Vec::new();
        let reply = loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) | Err(_) => break None,
                Ok(_) => {}
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let Some(code) = line.get(..3).and_then(|digits| digits.parse::<u16>().ok()) else {
                break None;
            };
            let text = line.get(4..).unwrap_or_default().to_owned();
            if line.as_bytes().get(3) == Some(&b'-') {
                lines.push(text);
                continue;
            }
            lines.push(text.clone());
            break Some(Reply { code, text, lines });
        };
        let _ = self.stream.set_read_timeout(Some(Duration::from_secs(20)));
        reply
    }

    /// A client for an implicit-TLS listener (465, RFC 8314 §3.3): no `220`
    /// is read in the clear, because the greeting and every command travel
    /// inside the encrypted stream.
    pub fn connect_tls(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        stream.set_nodelay(true).expect("nodelay");
        let reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut client = Self {
            stream,
            reader,
            tls: None,
        };
        client.handshake();
        let greeting = client.read_reply();
        assert_eq!(greeting.code, 220, "greeting: {greeting:?}");
        client
    }

    /// Completes the TLS handshake after the server's 220.
    pub fn handshake(&mut self) {
        let conn = rustls::ClientConnection::new(
            test_client_config(),
            rustls::pki_types::ServerName::try_from("mx.test").expect("name"),
        )
        .expect("client connection");
        // Whatever the plaintext reader pulled off the socket *past* the reply
        // it was asked for is handed to the TLS stream. A `BufReader` reads in
        // blocks, so a reply followed immediately by the server's next bytes
        // leaves those bytes in the client's buffer, not on the socket; if they
        // are TLS records (anything the server sent after the upgrade), the
        // handshake would never see them and would time out. They are this
        // client's own input, so they are replayed in front of the socket for
        // the TLS stream to read first.
        let leftover = {
            let buffered = self.reader.buffer();
            buffered.to_vec()
        };
        let mut stream = rustls::StreamOwned::new(
            conn,
            Replayed {
                prelude: leftover.into(),
                inner: self.stream.try_clone().expect("clone"),
            },
        );
        // `flush` pushes this side's hello and pulls the server's, so the
        // handshake is complete when it returns and no later read can be
        // mistaken for the plaintext phase.
        // The client's hello is written straight to the socket, without
        // waiting for anything to read: `StreamOwned::flush` writes *and*
        // then reads, and an implicit-TLS client that reads first is waiting
        // on a server that is waiting on this client.
        let mut hello = Vec::new();
        while stream.conn.wants_write() {
            stream.conn.write_tls(&mut hello).expect("hello");
        }
        stream.sock.write_all(&hello).expect("send hello");
        stream.sock.flush().expect("flush hello");
        self.tls = Some(stream);
    }
}

impl TlsClient {
    /// Reads whatever is left on the plain-text connection and returns it once
    /// the server closed (EOF); `None` if `limit` passes first.
    ///
    /// It reads the raw socket rather than going through the TLS session: the
    /// case under test is a handshake that never completed.
    pub fn read_to_eof_within(&mut self, limit: Duration) -> Option<String> {
        self.stream.set_read_timeout(Some(limit)).expect("timeout");
        let mut out = String::new();
        let mut buffer = [0u8; 1024];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => return Some(out),
                Ok(read) => out.push_str(&String::from_utf8_lossy(&buffer[..read])),
                Err(_) => return None,
            }
        }
    }
}

/// A socket for the TLS client that answers reads from a prelude first.
///
/// `rustls::StreamOwned` takes the transport by value and reads from it, so the
/// one place a client can put back the octets its plaintext reader already
/// consumed is a wrapper that serves them before touching the socket. Writes
/// and everything else go straight through.
struct Replayed {
    prelude: std::collections::VecDeque<u8>,
    inner: TcpStream,
}

impl Read for Replayed {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.prelude.is_empty() {
            return self.inner.read(buffer);
        }
        let take = buffer.len().min(self.prelude.len());
        for slot in buffer.iter_mut().take(take) {
            *slot = self.prelude.pop_front().expect("checked above");
        }
        Ok(take)
    }
}

impl Write for Replayed {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn read_line_owned(conn: &mut rustls::StreamOwned<rustls::ClientConnection, Replayed>) -> String {
    let mut byte = [0u8; 1];
    let mut line = String::new();
    loop {
        conn.read_exact(&mut byte).expect("read tls");
        line.push(byte[0] as char);
        if line.ends_with("\r\n") {
            return line;
        }
    }
}
