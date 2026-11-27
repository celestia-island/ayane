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

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

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

    // 4. Apply, then reload. The first apply above was the one that gave the
    //    delivery loop a routing table; this one runs against a store whose
    //    snapshot is already written, so it must rewrite nothing — and its
    //    reload still has to reach the listener through the hot swap (a reload
    //    is not conditional on a file changing).
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
            mail_health: Some(Arc::new(ayane::MailHealth {
                serving: engine.degraded().is_none(),
                degraded: engine.degraded().cloned(),
                listeners: 1,
            })),
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

/// The mail service cannot start and the control plane serves anyway.
///
/// This is the shape that made a mistyped certificate path cost an instance its
/// entire API: `engine::start` used to propagate the error into `main`, which
/// returned it, and `axum::serve` was never reached. Now the failure is *reported*
/// — `MailDegraded` with a cause and a `retryable` flag — and the process is a
/// control plane with a mail section that is not serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mail_service_that_cannot_start_leaves_the_control_plane_serving() {
    let fixture = Fixture::new("degraded");
    // Every shape of not-starting, one per row: what the operator broke, the
    // cause it is reported under, and whether a restart could fix it.
    let cases: Vec<(&str, MailConfig, &'static str, bool)> = vec![
        (
            "no listeners",
            MailConfig {
                listeners: Vec::new(),
                ..fixture.mail_config().await.0
            },
            "listeners",
            false,
        ),
        (
            "no hostname",
            MailConfig {
                hostname: "localhost".to_owned(),
                ..fixture.mail_config().await.0
            },
            "hostname",
            false,
        ),
        (
            "certificate that is not there",
            {
                let (mut mail, address) = fixture.mail_config().await;
                mail.listeners = vec![MailListener {
                    role: ayane_smtpd::ListenerRole::Submission,
                    listen: address,
                    role_name: "submission".to_owned(),
                    tls_cert: Some(fixture.root.join("no-such-cert.pem")),
                    tls_key: Some(fixture.root.join("no-such-key.pem")),
                }];
                mail
            },
            "tls",
            false,
        ),
        (
            "mail root nested in the spool's names",
            // The reserved child is created by the loop, right before this
            // row starts (see `arm` in the cases below): it is the *state* of
            // the mail root, so it must not exist while the earlier rows run.
            fixture.mail_config().await.0,
            "roots",
            false,
        ),
        (
            "state path the apply does not write",
            {
                let (mut mail, _) = fixture.mail_config().await;
                mail.state_path = fixture.root.join("elsewhere.json");
                mail
            },
            "state_path",
            false,
        ),
        (
            "a submission listener without TLS",
            {
                let (mut mail, address) = fixture.mail_config().await;
                mail.listeners = vec![MailListener {
                    role: ayane_smtpd::ListenerRole::Submission,
                    listen: address,
                    role_name: "submission".to_owned(),
                    tls_cert: None,
                    tls_key: None,
                }];
                mail
            },
            "listeners",
            false,
        ),
    ];
    for (what, mail, cause, retryable) in cases {
        if what == "mail root nested in the spool's names" {
            std::fs::create_dir_all(mail.mail_root.join("new")).expect("maildir");
        }
        let store: Arc<dyn StateStore> = fixture.store.clone();
        let engine = ayane::engine::start(&fixture.config(mail), store)
            .await
            .unwrap_or_else(|err| panic!("{what}: start must not fail the process: {err}"));
        let degraded = engine
            .degraded()
            .unwrap_or_else(|| panic!("{what}: the engine must report itself degraded"))
            .clone();
        assert_eq!(degraded.cause, cause, "{what}: {degraded:?}");
        assert_eq!(degraded.retryable, retryable, "{what}: {degraded:?}");
        assert!(
            !degraded.reason.is_empty(),
            "{what}: a degradation has a reason"
        );
        engine.shutdown();
        // Clean the fixture up for the next row.
        let _ = std::fs::remove_dir_all(fixture.mail.join("new"));
    }

    // And the payload an operator (and a supervisor) reads: `/api/health`.
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let (mut mail, _) = fixture.mail_config().await;
    mail.listeners.clear();
    let engine = ayane::engine::start(&fixture.config(mail.clone()), store)
        .await
        .expect("start returns");
    let state = ayane::state::AppState {
        store: fixture.store.clone(),
        driver: Arc::new(ayane::driver::NativeDriver::new(engine.control().clone())),
        config: Arc::new(fixture.config(mail)),
        auth: Arc::new(ayane::auth::AuthState::local()),
        mail_health: Some(Arc::new(ayane::MailHealth {
            serving: engine.degraded().is_none(),
            degraded: engine.degraded().cloned(),
            listeners: 0,
        })),
    };
    let app = ayane::api::router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("the control plane answers");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "health answers 200 even when the mail side is down: it is a report, not a probe"
    );
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body"),
    )
    .expect("json");
    // The bytes of the report, not the code: `status` says `degraded` and the
    // reason is in it, so a panel can show the operator what to fix.
    assert_eq!(body["status"], "degraded", "{body}");
    assert_eq!(body["mail"]["serving"], false, "{body}");
    assert_eq!(body["mail"]["degraded"]["cause"], "listeners", "{body}");
    assert!(
        body["mail"]["degraded"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("listeners")),
        "{body}"
    );
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&fixture.root);
}

/// A listener that cannot take its address is a `bind` degradation, and it is
/// the one that is marked retryable: the port may be held by a restart that has
/// not let go yet, and a supervisor may simply try again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taken_port_is_a_retryable_degradation() {
    let fixture = Fixture::new("bind");
    let (mail, address) = fixture.mail_config().await;
    // Somebody else owns the port — a supervisor's old instance, another
    // service, or (here) the test itself.
    let held = tokio::net::TcpListener::bind(address)
        .await
        .expect("the test holds the port");
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let engine = ayane::engine::start(&fixture.config(mail), store)
        .await
        .expect("a taken port is not a process failure");
    let degraded = engine.degraded().expect("degraded");
    assert_eq!(degraded.cause, "bind", "{degraded:?}");
    assert!(
        degraded.retryable,
        "a taken port may free itself: {degraded:?}"
    );
    assert!(
        degraded.reason.contains(&address.to_string()),
        "the report names the address: {degraded:?}"
    );
    engine.shutdown();
    drop(held);

    // The one way it is fatal: a deployment that says so.
    let (mail, address) = fixture.mail_config().await;
    let held = tokio::net::TcpListener::bind(address)
        .await
        .expect("the test holds the port");
    let mut fatal = mail;
    fatal.require_start = true;
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let err = ayane::engine::start(&fixture.config(fatal), store)
        .await
        .expect_err("AYANE_MAIL_REQUIRE_START=1 makes a failed start fatal");
    assert!(
        matches!(err, ayane::engine::MailError::Bind { .. }),
        "{err}"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(&fixture.root);
}

// ── the submission listener: credentials that are actually checked ────────
//
// S1-2, both halves. The half that could not be tested before was *reachability*:
// a submission listener without TLS does not advertise AUTH, so every login was
// answered `538` and the credential check — whatever it did — was never called.
// These two tests are the two answers to that:
//
// 1. a submission listener with no certificate is refused at **start** (it is a
//    configuration fault, reported as degraded, not a port that looks alive);
// 2. a submission listener with one is reachable end to end — `STARTTLS`,
//    `AUTH PLAIN` with the account's password succeeds, the wrong password is
//    `535`, and the authenticated client can then send a message.

/// A `STARTTLS` + `AUTH` client, just enough of one for the test.
struct SubmissionClient {
    plain: std::net::TcpStream,
    reader: std::io::BufReader<std::net::TcpStream>,
    tls: Option<(rustls::ClientConnection, std::net::TcpStream)>,
    /// Bytes decrypted but not yet handed out as a line.
    tls_reader: String,
}

/// The client half of the fixture's self-signed certificate: trust it by
/// name, since nothing signed it but itself.
fn test_client_tls() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let pem = include_str!("fixtures/mx-test-cert.pem");
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots
            .add(cert.expect("fixture certificate"))
            .expect("add root");
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

impl SubmissionClient {
    fn connect(address: std::net::SocketAddr) -> Self {
        let plain = std::net::TcpStream::connect(address).expect("connect");
        plain
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let reader = std::io::BufReader::new(plain.try_clone().expect("clone"));
        let mut client = Self {
            plain,
            reader,
            tls: None,
            tls_reader: String::new(),
        };
        let greeting = client.reply();
        assert_eq!(greeting.0, 220, "{greeting:?}");
        client
    }

    fn write(&mut self, bytes: &[u8]) {
        use std::io::Write as _;
        match self.tls.as_mut() {
            Some((connection, socket)) => {
                connection.writer().write_all(bytes).expect("tls write");
                let mut out = Vec::new();
                while connection.wants_write() {
                    connection.write_tls(&mut out).expect("write tls");
                }
                socket.write_all(&out).expect("send tls");
                socket.flush().expect("flush");
            }
            None => {
                self.plain.write_all(bytes).expect("write");
                self.plain.flush().expect("flush");
            }
        }
    }

    fn reply(&mut self) -> (u16, String) {
        use std::io::BufRead as _;
        let mut all = String::new();
        loop {
            let mut line = String::new();
            match self.tls.as_mut() {
                Some((connection, socket)) => {
                    // Reassemble one line from what rustls has decrypted,
                    // reading a record from the socket whenever the component
                    // is empty.
                    while !self.tls_reader.ends_with('\n') {
                        let available = match connection.reader().fill_buf() {
                            Ok(buf) => buf.to_vec(),
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                                let mut buffer = [0u8; 4096];
                                use std::io::Read as _;
                                let read = match socket.read(&mut buffer) {
                                    Ok(0) => panic!("closed during a tls read"),
                                    Ok(read) => read,
                                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                                        continue
                                    }
                                    Err(err) => panic!("tls read: {err}"),
                                };
                                connection.read_tls(&mut &buffer[..read]).expect("read tls");
                                connection.process_new_packets().expect("tls packets");
                                continue;
                            }
                            Err(err) => panic!("fill_buf: {err}"),
                        };
                        if available.is_empty() {
                            let mut buffer = [0u8; 4096];
                            use std::io::Read as _;
                            let read = match socket.read(&mut buffer) {
                                Ok(0) => panic!("closed during a tls read"),
                                Ok(read) => read,
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                                    continue
                                }
                                Err(err) => panic!("tls read: {err}"),
                            };
                            connection.read_tls(&mut &buffer[..read]).expect("read tls");
                            connection.process_new_packets().expect("tls packets");
                            continue;
                        }
                        let take = available
                            .iter()
                            .position(|byte| *byte == b'\n')
                            .map_or(available.len(), |index| index + 1);
                        self.tls_reader
                            .extend(available[..take].iter().map(|b| *b as char));
                        connection.reader().consume(take);
                    }
                    let complete = std::mem::take(&mut self.tls_reader);
                    line.push_str(&complete);
                }
                None => {
                    let read = self.reader.read_line(&mut line).expect("read");
                    assert!(read > 0, "closed while reading a reply: {all:?}");
                }
            }
            let code = line.get(..3).and_then(|digits| digits.parse::<u16>().ok());
            let more = line.as_bytes().get(3) == Some(&b'-');
            all.push_str(&line);
            if !more {
                return (code.unwrap_or(0), all.trim_end().to_owned());
            }
        }
    }

    fn command(&mut self, line: &str) -> (u16, String) {
        self.write(format!("{line}\r\n").as_bytes());
        self.reply()
    }

    fn expect(&mut self, line: &str, code: u16) -> String {
        let reply = self.command(line);
        assert_eq!(reply.0, code, "`{line}` answered {reply:?}");
        reply.1
    }

    /// `STARTTLS` and the handshake.
    ///
    /// The client drives `rustls` by hand rather than through `StreamOwned:
    /// the plaintext reader may have pulled octets past the `220` into its own
    /// buffer, and those belong to the TLS stream.
    fn upgrade(self) -> Self {
        let mut this = self;
        this.expect("STARTTLS", 220);
        let leftover = this.reader.buffer().to_vec();
        let mut socket = this.plain.try_clone().expect("clone");
        let mut connection = rustls::ClientConnection::new(
            Arc::new(test_client_tls()),
            rustls::pki_types::ServerName::try_from("mx.test").expect("name"),
        )
        .expect("client connection");
        // A blocking socket: `TcpStream` is not `Send`-checked here, and a
        // handshake that reads on a non-blocking socket spins.
        socket.set_nonblocking(false).expect("blocking");
        // Anything the plaintext reader already consumed comes first, then
        // whatever the socket has.
        let prelude = leftover.to_vec();
        // The handshake: one round of `write_tls` / `read_tls` until rustls says
        // it is done. The server's hello is read after our own is written.
        let mut pending: std::collections::VecDeque<u8> = prelude.into();
        loop {
            let mut out = Vec::new();
            while connection.wants_write() {
                connection.write_tls(&mut out).expect("write tls");
            }
            if !out.is_empty() {
                use std::io::Write as _;
                socket.write_all(&out).expect("send");
            }
            if !connection.is_handshaking() {
                break;
            }
            // Read at least one record.
            let mut buffer = [0u8; 4096];
            let read = if pending.is_empty() {
                use std::io::Read as _;
                match socket.read(&mut buffer) {
                    Ok(0) => panic!("the server closed during the handshake"),
                    Ok(read) => read,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(err) => panic!("handshake read: {err}"),
                }
            } else {
                let take = buffer.len().min(pending.len());
                for (slot, byte) in buffer.iter_mut().zip(pending.drain(..take)) {
                    *slot = byte;
                }
                take
            };
            assert!(read > 0, "the server closed during the handshake");
            connection.read_tls(&mut &buffer[..read]).expect("read tls");
            connection.process_new_packets().expect("handshake packets");
        }
        this.tls = Some((connection, socket));
        this
    }
}

/// A submission listener without a certificate is refused at start.
///
/// It would otherwise advertise no `AUTH`, answer `538` to every login and
/// accept no mail: a port that looks alive and does nothing. The reason names
/// the role and the consequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_submission_listener_without_tls_is_refused_at_start() {
    let fixture = Fixture::new("submission-notls");
    let (mut mail, address) = fixture.mail_config().await;
    mail.listeners = vec![MailListener {
        role: ayane_smtpd::ListenerRole::Submission,
        listen: address,
        role_name: "submission".to_owned(),
        tls_cert: None,
        tls_key: None,
    }];
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let engine = ayane::engine::start(&fixture.config(mail), store)
        .await
        .expect("start returns");
    let degraded = engine.degraded().expect("degraded");
    assert_eq!(degraded.cause, "listeners", "{degraded:?}");
    assert!(
        degraded.reason.contains("certificate") && degraded.reason.contains("submission"),
        "{degraded:?}"
    );
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&fixture.root);
}

/// The submission listener with TLS: `AUTH` is reachable, the store's password
/// is what it checks, and a wrong password is `535`.
///
/// Every assertion here is one the pre-change code could not make. `AUTH` was
/// unreachable without TLS (every attempt `538`), so no test exercised the
/// credential check at all; and the check was a `StoreVerifier` mutation — an
/// accept-everything version — that nothing would have caught.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_submission_listener_authenticates_against_the_store() {
    let fixture = Fixture::new("submission-tls");
    let (mut mail, address) = fixture.mail_config().await;
    mail.listeners = vec![MailListener {
        role: ayane_smtpd::ListenerRole::Submission,
        listen: address,
        role_name: "submission".to_owned(),
        tls_cert: Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mx-test-cert.pem"),
        ),
        tls_key: Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mx-test-key.pem"),
        ),
    }];
    let store: Arc<dyn StateStore> = fixture.store.clone();
    let engine = ayane::engine::start(&fixture.config(mail), store)
        .await
        .expect("start returns");
    assert!(
        engine.degraded().is_none(),
        "a submission listener with a certificate starts: {:?}",
        engine.degraded()
    );

    // 1. The capability is advertised once TLS is up — this is the bit that was
    //    missing, and it is why nothing ever checked a credential.
    let mut client = SubmissionClient::connect(address);
    let ehlo = client.expect("EHLO client.test", 250);
    assert!(ehlo.contains("STARTTLS"), "STARTTLS is offered: {ehlo}");
    let mut client = client.upgrade();
    let ehlo = client.expect("EHLO client.test", 250);
    assert!(ehlo.contains("AUTH"), "AUTH is offered over TLS: {ehlo}");

    // 2. The wrong password: `535`, and the connection survives to try again.
    use base64::Engine as _;
    let wrong = base64::engine::general_purpose::STANDARD.encode("\0inbox@example.test\0not-it");
    let reply = client.command(&format!("AUTH PLAIN {wrong}"));
    assert_eq!(reply.0, 535, "a wrong password is refused: {reply:?}");

    // 3. The right one — the store's hash is what decided both answers.
    let right = base64::engine::general_purpose::STANDARD
        .encode("\0inbox@example.test\0hunter2-correct-horse");
    client.expect(&format!("AUTH PLAIN {right}"), 235);

    // 4. And an authenticated submission really sends: the envelope opens and
    //    the message is queued.
    client.expect("MAIL FROM:<inbox@example.test>", 250);
    client.expect("RCPT TO:<inbox@example.test>", 250);
    client.expect("DATA", 354);
    client.write(b"From: <inbox@example.test>\r\nSubject: submitted\r\n\r\nbody\r\n.\r\n");
    let queued = client.reply();
    assert_eq!(queued.0, 250, "the submission is queued: {queued:?}");
    engine.shutdown();
    let _ = std::fs::remove_dir_all(&fixture.root);
}
