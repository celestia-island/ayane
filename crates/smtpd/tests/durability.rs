//! Durability under `kill -9` (T-B7) and half-written files (T-B8).
//!
//! The rule: after a crash at any point of the commit, a message the server
//! answered `250` for is complete and deliverable, and a message it did not
//! answer is not in the queue — "either fully deliverable or never
//! acknowledged".
//!
//! The crash is a real `SIGKILL` of a **child process**. The child re-runs
//! this test binary (`--exact child_<point> --ignored`), opens the shared
//! spool with one injection hook installed, runs the listener and serves one
//! message; the hook blocks the commit at the chosen point and writes the
//! queue id to a file. The parent sees the id, sends `kill -9` to the child,
//! then reopens the spool and checks what a restart sees. Nothing in the test
//! process stops the child except that signal.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ayane_smtpd::authn::DenyAll;
use ayane_smtpd::policy::AddressPolicy;
use ayane_smtpd::queue::{QueueState, Spool, SyncHook};
use ayane_smtpd::server::{serve, ServerConfig};
use ayane_smtpd::session::Limits;
use ayane_smtpd::ListenerRole;
use support::{fixture_state, Harness, HarnessOptions, TempDir};

/// Where the child was when it died.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailPoint {
    /// After `fsync(file)`, before any rename: the message is on disk under
    /// `tmp/` and the client is still waiting.
    AfterFileSync,
    /// After both renames, before `fsync(dir)`: the files are in `new/` but
    /// the directory entry is not durable yet.
    BeforeDirSync,
    /// The message is written and acknowledged; the next one is mid-commit.
    /// (Not used as a crash point; here so the child can serve one normally.)
    None,
    /// A message is acknowledged normally, and the child keeps serving: the
    /// parent reads the file the child's spool hook wrote, which lists every
    /// fsync the commit performed, in order.
    FsyncLog,
}

impl FailPoint {
    fn name(self) -> &'static str {
        match self {
            Self::AfterFileSync => "after_file_sync",
            Self::BeforeDirSync => "before_dir_sync",
            Self::None => "none",
            Self::FsyncLog => "fsync_log",
        }
    }
}

// ── the child ─────────────────────────────────────────────────────────────

/// The child: serves one message over the shared spool with a hook installed.
///
/// Run by the parent as `--exact child_after_file_sync --ignored` with
/// `AYANE_DURABILITY_ROOT`, `AYANE_DURABILITY_POINT` and
/// `AYANE_DURABILITY_IDFILE` in the environment; never on its own.
#[test]
#[ignore = "spawned by the durability tests, not meant to run alone"]
fn child_after_file_sync() {
    child(FailPoint::AfterFileSync);
}

#[test]
#[ignore = "spawned by the durability tests, not meant to run alone"]
fn child_before_dir_sync() {
    child(FailPoint::BeforeDirSync);
}

#[test]
#[ignore = "spawned by the durability tests, not meant to run alone"]
fn child_none() {
    child(FailPoint::None);
}

#[test]
#[ignore = "spawned by the durability tests, not meant to run alone"]
fn child_fsync_log() {
    child(FailPoint::FsyncLog);
}

fn child(point: FailPoint) {
    let root = PathBuf::from(std::env::var("AYANE_DURABILITY_ROOT").expect("root"));
    let id_file = PathBuf::from(std::env::var("AYANE_DURABILITY_IDFILE").expect("id file"));
    let spool = Spool::open(&root).expect("spool");
    let hook: SyncHook = {
        let id_file = id_file.clone();
        Arc::new(move |id: &str| {
            std::fs::write(&id_file, id).expect("write id");
            // Park here until the parent kills the process.
            std::thread::sleep(Duration::from_secs(600));
        })
    };
    if point == FailPoint::FsyncLog {
        // The live path, observed: every fsync the commit issues is appended
        // to the id file as it happens. The parent uses this against the
        // conversation a real client has with a real listener — the claim
        // under test is "by the time 250 is on the wire, both syncs ran".
        let log = id_file.clone();
        // The record is scope-qualified now: `FsyncEvent` carries the
        // operation that issued the sync, the kind, and (for a directory) which
        // one. The test's claim is about the *commit* path specifically, so the
        // log keeps the operation too — a sync made by `claim`/`remove` must
        // not be able to stand in for the commit's.
        spool.set_fsync_observer(Arc::new(move |event| {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .expect("fsync log");
            let line = format!(
                "{:?} {:?} {}\n",
                event.op,
                event.kind,
                event.dir.as_deref().unwrap_or("-")
            );
            file.write_all(line.as_bytes()).expect("fsync log write");
        }));
    } else if point != FailPoint::None {
        match point {
            FailPoint::AfterFileSync => spool.set_after_file_sync_hook(hook),
            FailPoint::BeforeDirSync => spool.set_before_dir_sync_hook(hook),
            FailPoint::None | FailPoint::FsyncLog => {}
        }
    }
    let state = fixture_state(false);
    let config = Arc::new(ServerConfig {
        hostname: "mx.test".to_owned(),
        role: ListenerRole::Inbound,
        max_message_size: 25 * 1024 * 1024,
        limits: Limits::default(),
        per_ip_limit: 8,
        command_timeout: Duration::from_secs(600),
        transaction_timeout: Duration::from_secs(600),
        spool,
        policy: AddressPolicy::from_state(&state),
        state,
        passwords: Arc::new(DenyAll),
        verifier: None,
        tls: None,
        max_received_headers: 25,
        max_header_bytes: ayane_smtpd::server::DEFAULT_MAX_HEADER_BYTES,
        auth_guard: Some(Arc::new(ayane_smtpd::server::AuthGuard::default())),
        metrics: None,
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        // The address goes to the parent through a file the hook does not
        // touch, so the parent can connect before the commit starts.
        std::fs::write(
            PathBuf::from(std::env::var("AYANE_DURABILITY_ADDRFILE").expect("addr file")),
            addr.to_string(),
        )
        .expect("write addr");
        let _ = serve(listener, config).await;
    });
}

// ── the parent ────────────────────────────────────────────────────────────

/// Starts the child for `point` and waits for its listening address.
fn start_child(dir: &Path, point: FailPoint) -> (Child, std::net::SocketAddr, PathBuf) {
    let addr_file = dir.join("addr");
    let id_file = dir.join("id");
    let child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            &format!("child_{}", point.name()),
            "--ignored",
            "--test-threads=1",
        ])
        .env("AYANE_DURABILITY_ROOT", dir.join("spool"))
        .env("AYANE_DURABILITY_POINT", point.name())
        .env("AYANE_DURABILITY_IDFILE", &id_file)
        .env("AYANE_DURABILITY_ADDRFILE", &addr_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");
    let addr = wait_for_addr(&addr_file, Duration::from_secs(20));
    (child, addr, id_file)
}

/// Waits until the child has written the address it bound.
fn wait_for_addr(addr_file: &Path, timeout: Duration) -> std::net::SocketAddr {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(addr_file) {
            if let Ok(addr) = text.trim().parse() {
                return addr;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the child listener never bound an address"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_id(id_file: &Path, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(id_file) {
            if !text.trim().is_empty() {
                return Some(text.trim().to_owned());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Uploads one message; returns the reply code when the server answered.
fn send_one(addr: std::net::SocketAddr) -> Option<u16> {
    let mut client = support::Client::connect(addr);
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\nSubject: durable\r\n\r\n");
    for _ in 0..2000 {
        body.push_str(
            "0123456789012345678901234567890123456789012345678901234567890123456789012345\r\n",
        );
    }
    body.push_str(".\r\n");
    client.send_raw(body.as_bytes());
    client.try_read_reply().map(|reply| reply.code)
}

fn kill(child: &mut Child) {
    child.kill().expect("kill -9");
    let _ = child.wait();
}

/// Whether `id` is in `new/`, complete and matching its checked-in digest.
fn deliverable(spool: &Spool, id: &str) -> bool {
    let Ok(queued) = spool.list(QueueState::New) else {
        return false;
    };
    let Some(message) = queued.iter().find(|message| message.id == id) else {
        return false;
    };
    let Ok(bytes) = spool.read_message(QueueState::New, id) else {
        return false;
    };
    use sha2::Digest as _;
    let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
    bytes.len() as u64 == message.envelope.size && digest == message.envelope.sha256
}

// ── T-B7: crash at each unacknowledged step of the commit ────────────────

#[test]
fn tb7_a_crash_after_the_file_sync_never_acknowledges() {
    {
        let point = FailPoint::AfterFileSync;
        let dir = TempDir::new("tb7-file");
        let (mut child, addr, id_file) = start_child(dir.path(), point);
        let client = std::thread::spawn(move || send_one(addr));
        let id = wait_for_id(&id_file, Duration::from_secs(20))
            .unwrap_or_else(|| panic!("{}: the commit hook never ran", point.name()));
        // The child is parked between fsync(file) and the renames.
        kill(&mut child);
        let reply = client.join().expect("client thread");
        assert!(
            reply.is_none(),
            "{}: a message must not be acknowledged before its renames, got {reply:?}",
            point.name()
        );

        let spool = Spool::open(dir.path().join("spool")).expect("spool");
        let report = spool.recover().expect("recover");
        assert_eq!(report.corrupt, 0, "no half entry may be kept");
        assert!(
            !deliverable(&spool, &id),
            "{}: the killed commit left a deliverable message",
            point.name()
        );
        assert!(
            spool.list(QueueState::New).expect("list").is_empty(),
            "{}: the queue must be empty after the crash",
            point.name()
        );
    }
}

#[test]
fn tb7_a_crash_after_the_renames_is_either_complete_or_absent() {
    let dir = TempDir::new("tb7-dir");
    let (mut child, addr, id_file) = start_child(dir.path(), FailPoint::BeforeDirSync);
    let client = std::thread::spawn(move || send_one(addr));
    let id = wait_for_id(&id_file, Duration::from_secs(20)).expect("the commit hook never ran");
    // The child is parked between the renames and fsync(dir): the files are in
    // `new/` but nothing was acknowledged.
    kill(&mut child);
    let reply = client.join().expect("client thread");
    assert!(reply.is_none(), "nothing was acknowledged, got {reply:?}");

    let spool = Spool::open(dir.path().join("spool")).expect("spool");
    let report = spool.recover().expect("recover");
    assert_eq!(report.corrupt, 0, "no half entry may be kept");
    if deliverable(&spool, &id) {
        // The rename reached the disk before the crash: the message is
        // complete, so a delivery agent may take it even though the client was
        // never told — a duplicate delivery, never a lost one.
        assert_eq!(report.intact, 1);
    } else {
        assert!(spool.list(QueueState::New).expect("list").is_empty());
    }
}

#[test]
fn tb7_the_acknowledgement_follows_both_syncs() {
    // The gap mutation testing found: T-B7 above is an *or* — with the
    // directory sync deleted it still passes, because a crash test can only
    // observe the outcome a lost page cache would produce, not whether the
    // call is there. This test observes the calls themselves, on the same
    // path a client takes: a real listener, a real commit, and the record the
    // spool wrote as it worked.
    let dir = TempDir::new("tb7-order");
    let (mut child, addr, log_file) = start_child(dir.path(), FailPoint::FsyncLog);
    // The child appends to the id file, so it must start empty.
    let _ = std::fs::remove_file(&log_file);
    let reply = send_one(addr);
    assert_eq!(reply, Some(250), "the message is acknowledged");
    let log = loop {
        let text = std::fs::read_to_string(&log_file).unwrap_or_default();
        if text.lines().count() >= 2 {
            break text;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    kill(&mut child);
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        vec!["Commit File -", "Commit Dir new"],
        "the 250 went out only after the commit's fsync(file) and then its \
         fsync(dir) of new/, in that order"
    );
}

#[test]
fn tb7_an_acknowledged_message_survives_the_crash() {
    // Control case: the same path without a crash point acknowledges and the
    // message is intact — which is what makes the two tests above meaningful.
    let dir = TempDir::new("tb7-ok");
    let (mut child, addr, _id_file) = start_child(dir.path(), FailPoint::None);
    let reply = send_one(addr);
    assert_eq!(reply, Some(250), "the control message is acknowledged");
    kill(&mut child);
    let spool = Spool::open(dir.path().join("spool")).expect("spool");
    let queued = spool.list(QueueState::New).expect("list");
    assert_eq!(queued.len(), 1);
    assert!(deliverable(&spool, &queued[0].id));
    let report = spool.recover().expect("recover");
    assert_eq!(report.intact, 1);
    assert_eq!(report.corrupt, 0);
}

// ── T-B8: a half-written file is never delivered ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb8_a_truncated_message_is_quarantined_and_not_delivered() {
    let harness = Harness::start("tb8-truncate", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    support::deliver(
        &mut client,
        "a@example.net",
        "inbox@example.com",
        "From: <a@example.net>\r\nSubject: half\r\n\r\nbody that will be cut\r\n",
    );
    let queued = harness.queued();
    assert_eq!(queued.len(), 1);
    let id = queued[0].id.clone();
    // Simulate a disk that lost the tail of the file: cut it and corrupt it.
    let path = harness
        .dir
        .path()
        .join("spool")
        .join("new")
        .join(format!("{id}.eml"));
    let bytes = std::fs::read(&path).expect("read");
    std::fs::write(&path, &bytes[..bytes.len() - 10]).expect("truncate");
    let report = harness.spool.recover().expect("recover");
    assert_eq!(report.corrupt, 1);
    assert_eq!(report.intact, 0);
    assert!(
        harness.queued().is_empty(),
        "a truncated message is not delivered"
    );
    assert!(
        harness
            .dir
            .path()
            .join("spool")
            .join("corrupt")
            .join(format!("{id}.eml"))
            .exists(),
        "the broken file is kept out of the delivery path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tb8_a_corrupted_message_with_the_right_length_is_quarantined() {
    let harness = Harness::start("tb8-corrupt", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    support::deliver(
        &mut client,
        "a@example.net",
        "inbox@example.com",
        "From: <a@example.net>\r\nSubject: tampered\r\n\r\nbody\r\n",
    );
    let id = harness.queued()[0].id.clone();
    let path = harness
        .dir
        .path()
        .join("spool")
        .join("new")
        .join(format!("{id}.eml"));
    let mut bytes = std::fs::read(&path).expect("read");
    // Same length, one flipped octet: only the checksum can catch this.
    let position = bytes.len() / 2;
    bytes[position] ^= 0x20;
    std::fs::write(&path, &bytes).expect("tamper");
    let report = harness.spool.recover().expect("recover");
    assert_eq!(report.corrupt, 1);
    assert!(harness.queued().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn tb8_a_metadata_file_without_its_message_is_dropped() {
    let harness = Harness::start("tb8-orphan", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    support::deliver(
        &mut client,
        "a@example.net",
        "inbox@example.com",
        "From: <a@example.net>\r\nSubject: orphan\r\n\r\nbody\r\n",
    );
    let id = harness.queued()[0].id.clone();
    let eml = harness
        .dir
        .path()
        .join("spool")
        .join("new")
        .join(format!("{id}.eml"));
    std::fs::remove_file(&eml).expect("unlink");
    let report = harness.spool.recover().expect("recover");
    assert_eq!(report.orphan_metadata, 1);
    assert!(harness.queued().is_empty());
}

use std::sync::Arc;
