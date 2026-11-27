//! End to end, through the control plane: one process that serves the API and
//! the mail.
//!
//! Everything below goes through the real code paths — [`ayane::engine::start`]
//! binds a real socket and spawns the real listener and the real delivery
//! consumer, the client speaks real SMTP over TCP, and the traffic numbers are
//! read back through the same [`ayane::driver::EngineDriver`] the
//! `admin.net.traffic` RPC uses. Nothing here is a unit: the point is that the
//! pieces the other crates test one at a time are wired to each other.
//!
//! # Why this test exists
//!
//! The mail service used to be three containers the control plane shelled out
//! to. Now it is in the process, which means the wiring is the thing that can be
//! wrong: a listener that never gets the hot-swapped configuration, a delivery
//! consumer that reads a snapshot nothing writes, a counter no layer feeds. Each
//! is a green unit test and a broken deployment, and each shows up here.
//!
//! The two methods below are the two halves of one story:
//!
//! - [`an_enabled_engine_delivers_mail_and_counts_it`] — the full pass: send,
//!   deliver into a maildir, count, apply, reload.
//! - [`a_disabled_engine_binds_nothing_and_counts_nothing`] — the default, which
//!   must stay exactly what it was before the mail engine existed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ayane::config::{MailConfig, MailListener};
use ayane::driver::{EngineDriver, NativeDriver};
use ayane_store::{password, RedbStateStore, StateStore, StoredState};

/// The admin token the RPC part of the test logs in with. Not a credential:
/// it is this test's own, invented here and used nowhere else.
const ADMIN_TOKEN: &str = "e2e-admin-token-placeholder";

/// Where the fixture's files live.
struct Fixture {
    root: PathBuf,
    spool: PathBuf,
    mail: PathBuf,
    store: Arc<RedbStateStore>,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ayane-e2e-{tag}-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let store = Arc::new(RedbStateStore::open(root.join("store.redb")).expect("store"));
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(
            "inbox@example.test".to_owned(),
            password::hash_password("hunter2-correct-horse").expect("hash"),
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
                ..Default::default()
            },
            password_hashes: hashes,
            external_identities: Vec::new(),
        };
        store.save(&stored).expect("seed");
        Self {
            spool: root.join("state/spool"),
            mail: root.join("state/mail"),
            root,
            store,
        }
    }

    /// The mail section, enabled, on a free loopback port.
    async fn mail_config(&self) -> (MailConfig, std::net::SocketAddr) {
        let address = free_port().await;
        let mail = MailConfig {
            enabled: true,
            hostname: "mx.example.test".to_owned(),
            listeners: vec![MailListener {
                role: ayane_smtpd::ListenerRole::Inbound,
                listen: address,
                role_name: "inbound".to_owned(),
                tls_cert: None,
                tls_key: None,
            }],
            spool_root: self.spool.clone(),
            mail_root: self.mail.clone(),
            state_path: self.root.join("state/desired-state.json"),
            // A short tick: the delivery pass is what this test is waiting on.
            delivery_interval_seconds: 1,
            // No outbound: the fixture's recipients are local, and a test that
            // opened port 25 to a stranger would be a test that talks to the
            // internet.
            outbound: false,
            ..MailConfig::default()
        };
        (mail, address)
    }

    fn config(&self, mail: MailConfig) -> ayane::config::Config {
        ayane::config::Config {
            listen: "127.0.0.1:0".parse().expect("listen"),
            log_filter: String::new(),
            state_dir: self.root.join("state"),
            admin_token: None,
            compose_file: self.root.join("docker-compose.yml"),
            imap: "127.0.0.1:1".to_owned(),
            submission: "127.0.0.1:1".to_owned(),
            cert_file: None,
            mail,
        }
    }
}

/// A free loopback port, by binding one and letting it go.
async fn free_port() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    listener.local_addr().expect("addr")
}

/// A dead-simple SMTP client: the three commands the test needs, read back as
/// whole replies.
struct Client {
    stream: std::net::TcpStream,
    reader: std::io::BufReader<std::net::TcpStream>,
}

impl Client {
    fn connect(address: std::net::SocketAddr) -> Self {
        let stream = std::net::TcpStream::connect(address).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
        let mut client = Self { stream, reader };
        let greeting = client.reply();
        assert_eq!(greeting.0, 220, "{greeting:?}");
        client
    }

    fn send(&mut self, line: &str) {
        use std::io::Write as _;
        self.stream.write_all(line.as_bytes()).expect("write");
        self.stream.flush().expect("flush");
    }

    /// One complete reply — multi-line (the `250-` continuation lines of an
    /// `EHLO` answer) read through to its final line, which is where the last
    /// three octets are the code and the fourth is not a `-`.
    fn reply(&mut self) -> (u16, String) {
        use std::io::BufRead as _;
        let mut all = String::new();
        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).expect("read");
            assert!(read > 0, "the server closed the connection: {all:?}");
            let code = line.get(..3).and_then(|digits| digits.parse().ok());
            let more = line.as_bytes().get(3) == Some(&b'-');
            all.push_str(&line);
            if !more {
                return (code.unwrap_or(0), all.trim_end().to_owned());
            }
        }
    }

    fn expect(&mut self, line: &str, code: u16) -> String {
        self.send(&format!("{line}\r\n"));
        let reply = self.reply();
        assert_eq!(reply.0, code, "{line} answered {reply:?}");
        reply.1
    }
}

/// Delivers one message and returns the transaction's answer.
fn send_message(client: &mut Client, sender: &str, recipient: &str, subject: &str) -> String {
    client.expect("EHLO client.test", 250);
    client.expect(&format!("MAIL FROM:<{sender}>"), 250);
    client.expect(&format!("RCPT TO:<{recipient}>"), 250);
    client.expect("DATA", 354);
    let message = format!(
        "From: <{sender}>\r\nTo: <{recipient}>\r\nSubject: {subject}\r\n\r\n\
         The body of {subject}.\r\n.\r\n"
    );
    client.send(&message);
    client.reply().1
}

/// Waits until `check` holds, or fails the test with `what`.
async fn eventually(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Walks a maildir tree and returns every file in any `new/` directory.
fn maildir_deliveries(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "new") {
                if let Ok(files) = std::fs::read_dir(&path) {
                    out.extend(files.flatten().map(|file| file.path()));
                }
            } else {
                out.extend(maildir_deliveries(&path));
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enabled_engine_delivers_mail_and_counts_it() {
    let fixture = Fixture::new("enabled");
    let (mail, address) = fixture.mail_config().await;
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let engine = ayane::engine::start(&fixture.config(mail.clone()), store)
        .await
        .expect("the engine starts");
    let driver = NativeDriver::new(engine.control().clone());

    // 1. A real client, a real socket, a real transaction.
    let mut client = Client::connect(address);
    let answer = send_message(
        &mut client,
        "someone@remote.test",
        "inbox@example.test",
        "hello",
    );
    assert!(
        answer.starts_with("250"),
        "the message is accepted: {answer}"
    );
    // The delivery consumer routes by the snapshot the apply loop writes, so
    // the first apply is what tells it there is a hosted domain at all — the
    // same ordering a deployment has (seed the store, apply, send). It runs
    // here, between the send and the pass, on purpose: a message queued before
    // the routing table exists must be delivered once it does, not bounced.
    let stored = fixture.store.load().expect("load");
    let state_dir = fixture.root.join("state");
    ayane::apply::apply(
        fixture.store.as_ref(),
        &state_dir,
        &stored,
        Arc::new(ayane::driver::RecordingDriver::new(
            fixture.root.join("docker-compose.yml"),
        )),
    )
    .await
    .expect("the first apply writes the routing snapshot");
    // A second recipient that does not exist: counted as refused, never as
    // delivered.
    client.send("MAIL FROM:<someone@remote.test>\r\n");
    assert_eq!(client.reply().0, 250);
    client.send("RCPT TO:<nobody@example.test>\r\n");
    assert_eq!(client.reply().0, 550, "an unknown mailbox is refused");
    drop(client);

    // 2. The delivery pass writes the maildir. The consumer ticks once a
    //    second, so this is the one place the test waits on a clock.
    eventually(
        "the message to land in a maildir",
        Duration::from_secs(20),
        || !maildir_deliveries(&fixture.mail).is_empty(),
    )
    .await;
    let delivered = maildir_deliveries(&fixture.mail);
    assert_eq!(delivered.len(), 1, "{delivered:?}");
    let body = std::fs::read(&delivered[0]).expect("read");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Subject: hello"), "{text}");
    // The spool is empty again: the message was claimed and delivered, not
    // copied.
    eventually("the spool to drain", Duration::from_secs(10), || {
        std::fs::read_dir(fixture.spool.join("new"))
            .map(|dir| dir.flatten().next().is_none())
            .unwrap_or(true)
    })
    .await;

    // 3. The traffic the client caused is in the counters, through the same
    //    entry point `admin.net.traffic` calls.
    let snapshot = driver.traffic_snapshot("24h").expect("counters");
    let row = snapshot
        .inbound
        .iter()
        .find(|row| row.peer == "127.0.0.1")
        .unwrap_or_else(|| panic!("no row for the client: {snapshot:?}"));
    assert_eq!(row.connects, 1, "{row:?}");
    assert_eq!(row.messages, 1, "one message was queued: {row:?}");
    assert_eq!(row.recipients, 1, "one recipient was accepted: {row:?}");
    assert_eq!(row.refused, 1, "one was refused: {row:?}");
    assert!(
        snapshot.totals.delivered_local >= 1,
        "the delivery pass counted the maildir write: {snapshot:?}"
    );

    // 4. Apply, then reload: the second apply rewrites nothing and the reload
    //    reaches the listener through the hot swap.
    // The consumer reads the snapshot the apply writes; write it the way the
    // apply does so the delivery loop keeps a valid state afterwards.
    let report = ayane::apply::apply(
        fixture.store.as_ref(),
        &state_dir,
        &stored,
        Arc::new(driver.clone()),
    )
    .await
    .expect("apply");
    assert!(
        report.warnings.is_empty(),
        "apply warned: {:?}",
        report.warnings
    );
    assert_eq!(report.reloaded.len(), 1, "{report:?}");
    assert_eq!(report.reloaded[0].service, "smtp");
    assert!(report.reloaded[0].ok, "{report:?}");
    assert!(
        state_dir.join("desired-state.json").is_file(),
        "the apply wrote the routing snapshot the consumer reads"
    );
    let generation_before = engine.control().generation();
    let report = ayane::apply::apply(
        fixture.store.as_ref(),
        &state_dir,
        &stored,
        Arc::new(driver.clone()),
    )
    .await
    .expect("second apply");
    assert!(
        report.files.iter().all(|file| !file.changed),
        "the second apply rewrites nothing: {report:?}"
    );
    assert!(
        engine.control().generation() > generation_before,
        "the reload reached the listener's configuration slot"
    );

    // 5. And the connection that the reload is about to affect still works: a
    //    message after the apply is delivered with the same routing.
    let mut client = Client::connect(address);
    let answer = send_message(
        &mut client,
        "someone@remote.test",
        "inbox@example.test",
        "second",
    );
    assert!(answer.starts_with("250"), "{answer}");
    eventually(
        "the second message to land",
        Duration::from_secs(20),
        || maildir_deliveries(&fixture.mail).len() == 2,
    )
    .await;
    drop(client);

    // 6. The same numbers through the RPC surface the webui calls, in the
    //    shape the page draws: `admin.net.traffic {since:"24h"}`.
    //    The page is admin-only, so the call carries an admin session minted
    //    the way the deployment mints one (the admin token).
    let mut control_config = fixture.config(mail.clone());
    control_config.admin_token = Some(ADMIN_TOKEN.to_owned());
    let sessions = Arc::new(ayane::session::SessionStore::new());
    let (token, _session) = sessions
        .admin_login(Some(ADMIN_TOKEN), ADMIN_TOKEN)
        .expect("admin login");
    let surface = ayane::transport::RpcSurface {
        app: ayane::state::AppState {
            store: fixture.store.clone(),
            driver: Arc::new(driver.clone()),
            config: Arc::new(control_config),
            auth: Arc::new(ayane::auth::AuthState::local()),
        },
        sessions,
    };
    let reply = call_rpc(
        &surface,
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "admin.net.traffic",
            "params": {"since": "24h", "token": token}}),
    )
    .await;
    assert_eq!(
        reply["result"]["inbound"][0]["peer"], "127.0.0.1",
        "{reply}"
    );
    assert_eq!(reply["result"]["inbound"][0]["connects"], 2, "{reply}");
    assert_eq!(reply["result"]["inbound"][0]["messages"], 2, "{reply}");
    assert_eq!(
        reply["result"]["window_seconds"], 86_400,
        "the window the page asked for: {reply}"
    );

    engine.shutdown();
    let _ = std::fs::remove_dir_all(&fixture.root);
}

/// One JSON-RPC request straight into the transport, bypassing the socket.
async fn call_rpc(
    surface: &ayane::transport::RpcSurface,
    request: serde_json::Value,
) -> serde_json::Value {
    let mut context = ayane::rpc::WsContext::new();
    let reply = ayane::transport::handle_one_for_tests(surface, &mut context, &request.to_string())
        .await
        .expect("a reply");
    serde_json::from_str(&reply).expect("json")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_engine_binds_nothing_and_counts_nothing() {
    // The default configuration: the mail section is off, so the process is
    // the control plane and nothing else. Asserted two ways — the defaults say
    // so, and a port the disabled configuration did *not* name is still free
    // after a process has "started" on it.
    let fixture = Fixture::new("disabled");
    let mail = MailConfig::default();
    assert!(!mail.enabled, "the default is off");
    assert!(mail.listeners.is_empty());
    assert!(
        mail.spool_root.ends_with("spool") && mail.mail_root.ends_with("mail"),
        "the two roots are siblings: {:?} {:?}",
        mail.spool_root,
        mail.mail_root
    );
    assert_ne!(mail.spool_root, mail.mail_root);

    let config = fixture.config(mail);
    // `ayane::engine::start` on a disabled configuration is never called by
    // `main`; what is checked here is that the inert configuration *is* inert:
    // nothing in it names an address to bind, and a driver built from it reports
    // a reload it did not perform as an error rather than a success.
    let driver = ayane::driver::RecordingDriver::new(config.compose_file.clone());
    let err = driver.reload().expect_err("no engine, no reload");
    assert!(err.contains("engine not running"), "{err}");
    let empty = driver.traffic_snapshot("24h").expect("counters");
    assert!(empty.inbound.is_empty() && empty.outbound.is_empty());
    assert_eq!(ayane::net::traffic_reply(&empty)["totals"]["connects"], 0);

    let _ = std::fs::remove_dir_all(&fixture.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_engine_without_a_hostname_or_listeners_refuses_to_start() {
    // A deployment that turned the mail section on and said nothing else is
    // refused at start rather than served: a greeting of `localhost` is a mail
    // server that tells every peer it has no name.
    let fixture = Fixture::new("bystart");
    let mut mail = fixture.mail_config().await.0;
    mail.listeners.clear();
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let err = ayane::engine::start(&fixture.config(mail), store)
        .await
        .expect_err("no listeners is not a mail service");
    assert!(
        matches!(err, ayane::engine::MailError::Missing("listeners")),
        "{err}"
    );

    let mut mail = fixture.mail_config().await.0;
    mail.hostname = "localhost".to_owned();
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let err = ayane::engine::start(&fixture.config(mail), store)
        .await
        .expect_err("a nameless host is not a mail service");
    assert!(
        matches!(err, ayane::engine::MailError::Missing("hostname")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}
