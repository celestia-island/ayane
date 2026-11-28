//! The CONDSTORE/QRESYNC/UIDPLUS session: a real socket, the extension
//! grammar, and the wire facts a client syncs from.
//!
//! [`crate::imap_session`]'s unit tests drive the state machine as a table;
//! this file drives the listener, because the extension parameters live in
//! the client's raw bytes (the sidecar parser in `imap_session::ext_wire`
//! lifts them before the codec sees the line), and the one fact each test
//! asserts is a line the client read back. The kill matrix in the design
//! report maps onto these tests one to one.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ayane_proto::Address;
use ayane_smtpd::authn::PasswordVerifier;
use ayane_smtpd::imap_server::{serve, ImapConfig};
use ayane_smtpd::maildir_reader::{MaildirReader, INBOX};
use rustls::pki_types::ServerName;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod support;

const IDENTITY: &str = "alice@example.test";
const PASSWORD: &str = "correct horse";

/// A verifier that accepts exactly one identity/password pair.
struct OnePassword {
    asked: AtomicUsize,
}

impl PasswordVerifier for OnePassword {
    fn verify<'s>(
        &'s self,
        identity: &'s str,
        password: &'s str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 's>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let ok = identity.eq_ignore_ascii_case(IDENTITY) && password == PASSWORD;
        Box::pin(async move { ok })
    }
}

/// One mail root, removed when the test ends.
struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ayane-imap-condstore-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("root");
        Self(path)
    }

    /// A message in the account's INBOX, written the way a delivery lands.
    /// The name carries `seq`, so name order (UID order) follows it.
    fn deliver(&self, seq: u64, subject: &str) {
        let address = Address::parse(IDENTITY).expect("address");
        let dir = MaildirReader::new(&self.0)
            .folder_dir(&address, INBOX, true)
            .expect("maildir");
        let name = format!("17{seq:012}.M1.P1.ayane-test");
        let bytes = format!(
            "From: bob@example.test\r\nTo: {IDENTITY}\r\nSubject: {subject}\r\n\
             Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <{name}>\r\n\r\n\
             body of {subject}\r\n"
        );
        std::fs::write(dir.join("new").join(&name), bytes).expect("message");
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running implicit-TLS listener on a loopback port, on its own thread and
/// runtime (a listener cancelled with the test's runtime would close under a
/// reading client).
struct Listener {
    addr: std::net::SocketAddr,
}

impl Listener {
    async fn start(dir: &Path) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        let passwords = Arc::new(OnePassword {
            asked: AtomicUsize::new(0),
        });
        let config = Arc::new(ImapConfig {
            hostname: "mx.test".to_owned(),
            mail_root: dir.to_path_buf(),
            passwords,
            tls: Some(TlsAcceptor::from(Arc::new(support::test_tls_config()))),
            imap_tls: true,
            per_ip_limit: 8,
            command_timeout: Duration::from_secs(20),
        });
        let plain = socket.into_std().expect("std socket");
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let socket = TcpListener::try_from(plain).expect("tokio socket");
                let _ = serve(socket, config).await;
            });
        });
        Self { addr }
    }

    fn connect(&self) -> Client {
        let stream = TcpStream::connect(self.addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        let name = ServerName::try_from("mx.test").expect("name").to_owned();
        let mut conn =
            rustls::ClientConnection::new(support::test_client_config(), name).expect("client");
        let mut stream = stream;
        while conn.is_handshaking() {
            conn.complete_io(&mut stream).expect("handshake");
        }
        let mut client = Client {
            conn: Box::new(conn),
            stream,
            buffer: Vec::new(),
        };
        let greeting = client.line();
        assert!(greeting.contains("CONDSTORE"), "greeting: {greeting}");
        assert!(greeting.contains("QRESYNC"), "greeting: {greeting}");
        assert!(greeting.contains("UIDPLUS"), "greeting: {greeting}");
        assert!(greeting.contains("ENABLE"), "greeting: {greeting}");
        client
    }
}

/// A line-oriented TLS client: the smallest reader that can assert on the
/// wire the way a real CONDSTORE client would.
struct Client {
    conn: Box<rustls::ClientConnection>,
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Client {
    fn send(&mut self, line: &str) {
        let mut tls = rustls::Stream::new(self.conn.as_mut(), &mut self.stream);
        tls.write_all(format!("{line}\r\n").as_bytes())
            .and_then(|()| Write::flush(&mut tls))
            .expect("write");
    }

    /// One reply line, CRLF removed.
    fn line(&mut self) -> String {
        loop {
            if let Some(at) = self.buffer.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buffer.drain(..at + 2).collect();
                return String::from_utf8_lossy(&line[..at]).into_owned();
            }
            let mut chunk = [0u8; 4096];
            let mut tls = rustls::Stream::new(self.conn.as_mut(), &mut self.stream);
            let read = tls.read(&mut chunk).expect("read");
            assert!(read > 0, "the server closed the connection mid-reply");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Every line until (and including) the tagged reply for `tag`.
    fn until_tag(&mut self, tag: &str) -> Vec<String> {
        let prefix = format!("{tag} ");
        let mut lines = Vec::new();
        loop {
            let line = self.line();
            let done = line.starts_with(&prefix);
            lines.push(line);
            if done {
                return lines;
            }
        }
    }

    /// Sends `line` and answers with everything up to its tagged reply.
    fn say(&mut self, line: &str) -> Vec<String> {
        let tag = line.split(' ').next().expect("tag").to_owned();
        self.send(line);
        self.until_tag(&tag)
    }

    fn login(&mut self) {
        let reply = self.say(&format!("a LOGIN {IDENTITY} \"{PASSWORD}\""));
        assert!(reply.last().expect("reply").contains("a OK"), "login");
    }
}

/// Whether a reply line is an untagged FETCH (the tagged completion also
/// says "FETCH completed", so the star is the discriminator).
fn is_untagged_fetch(line: &str) -> bool {
    line.starts_with("* ") && line.contains("FETCH (")
}

/// The number in a `… [HIGHESTMODSEQ n] …` line.
fn highest_of(lines: &[String]) -> u64 {
    for line in lines {
        if let Some(rest) = line.split("[HIGHESTMODSEQ ").nth(1) {
            if let Some(number) = rest.split(']').next() {
                if let Ok(value) = number.parse::<u64>() {
                    return value;
                }
            }
        }
    }
    panic!("no HIGHESTMODSEQ in {lines:?}");
}

/// The number in a `* n FETCH … MODSEQ (m)` line.
fn modseq_of(line: &str) -> u64 {
    let at = line.find("MODSEQ (").expect("MODSEQ in line") + "MODSEQ (".len();
    let end = line[at..].find(')').expect("close") + at;
    line[at..end].parse().expect("number")
}

// ── advertising and enabling ──────────────────────────────────────────────

#[tokio::test]
async fn select_with_condstore_reports_the_watermark() {
    let root = Root::new("select-hms");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    let lines = client.say("s SELECT INBOX (CONDSTORE)");
    let line = lines
        .iter()
        .find(|l| l.contains("HIGHESTMODSEQ"))
        .expect("code");
    assert!(
        line.starts_with("* OK [HIGHESTMODSEQ "),
        "the untagged form, before the tagged OK: {line}"
    );
    let highest = highest_of(&lines);
    assert!(
        highest >= 2,
        "the scan assigned the message a mod-sequence: {highest}"
    );
    // An enabling reselect reports the watermark again — and a switch of
    // mailbox announces the old one closed first (RFC 7162 §3.2.11).
    let lines = client.say("s2 SELECT INBOX (CONDSTORE)");
    assert_eq!(
        lines[0], "* OK [CLOSED] Previous mailbox is now closed",
        "CLOSED is the first line of the switch: {:?}",
        lines[0]
    );
    assert!(
        highest_of(&lines) >= highest,
        "the watermark never rolls back"
    );
}

#[tokio::test]
async fn closed_is_unconditional_once_advertised() {
    let root = Root::new("closed");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    let lines = client.say("s SELECT INBOX");
    assert!(
        !lines.iter().any(|l| l.contains("HIGHESTMODSEQ")),
        "not yet enabled: {lines:?}"
    );
    let lines = client.say("s2 EXAMINE INBOX");
    assert_eq!(
        lines[0], "* OK [CLOSED] Previous mailbox is now closed",
        "advertising CONDSTORE makes CLOSED a duty even for a plain SELECT: {:?}",
        lines
    );
}

#[tokio::test]
async fn enable_qresync_is_acknowledged_and_gates_the_parameters() {
    let root = Root::new("enable");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    // Before ENABLE: the QRESYNC parameter and the VANISHED modifier are BAD
    // (RFC 7162 §3.2.2), and a BAD never selects the mailbox.
    let lines = client.say("s SELECT INBOX (QRESYNC (1 1))");
    assert!(lines.last().expect("reply").contains("BAD"), "{lines:?}");
    client.send("f UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)");
    let lines = client.until_tag("f");
    assert!(lines.last().expect("reply").contains("BAD"), "{lines:?}");
    // Unknown parameters are ignored (RFC 5161 §3.1); QRESYNC is answered.
    let lines = client.say("e ENABLE XYZZY QRESYNC");
    let enabled = lines
        .iter()
        .find(|l| l.starts_with("* ENABLED"))
        .expect("ENABLED");
    assert_eq!(*enabled, "* ENABLED QRESYNC", "{enabled}");
    assert!(lines.last().expect("reply").contains("e OK"), "{lines:?}");
    // Enabled: the SELECT parameter passes — and the gate the wrong way
    // (plain FETCH with VANISHED) stays BAD.
    let lines = client.say("s2 SELECT INBOX (QRESYNC (1 1))");
    assert!(lines.last().expect("reply").contains("s2 OK"), "{lines:?}");
    let lines = client.say("f2 FETCH 1 (FLAGS) (CHANGEDSINCE 1 VANISHED)");
    assert!(
        lines.last().expect("reply").contains("BAD"),
        "plain FETCH: {lines:?}"
    );
}

// ── the STORE contract ────────────────────────────────────────────────────

#[tokio::test]
async fn store_unchangedsince_passes_on_equality_and_fails_above() {
    let root = Root::new("unchanged");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    let lines = client.say("s SELECT INBOX (CONDSTORE)");
    let highest = highest_of(&lines);
    // Equality passes (RFC 7162 §3.1.3); the answer carries the fresh value.
    let lines = client.say(&format!(
        "st STORE 1 (UNCHANGEDSINCE {highest}) +FLAGS (\\Seen)"
    ));
    let fetch = lines.iter().find(|l| l.contains("FETCH")).expect("fetch");
    assert!(fetch.contains("\\Seen"), "{fetch}");
    let stored = modseq_of(fetch);
    assert!(stored > highest, "the STORE bumped: {stored} > {highest}");
    assert!(
        lines.last().expect("tagged").contains("st OK")
            && !lines.last().unwrap().contains("MODIFIED"),
        "{:?}",
        lines.last()
    );
    // One above: the message is newer than the client believes → it lands in
    // the MODIFIED set, and no flag moved.
    let lines = client.say(&format!(
        "st2 STORE 1 (UNCHANGEDSINCE {highest}) +FLAGS (\\Flagged)"
    ));
    let tagged = lines.last().expect("tagged");
    assert!(tagged.contains("[MODIFIED 1]"), "the failure set: {tagged}");
    assert!(!lines.iter().any(|l| l.contains("\\Flagged")), "{lines:?}");
}

#[tokio::test]
async fn store_silent_still_answers_the_condstore_fetch() {
    let root = Root::new("silent");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    let lines = client.say("s SELECT INBOX (CONDSTORE)");
    let highest = highest_of(&lines);
    // RFC 7162 §3.1.3: an executed conditional STORE answers an untagged
    // FETCH with UID, FLAGS and MODSEQ even for .SILENT.
    let lines = client.say(&format!(
        "st STORE 1 (UNCHANGEDSINCE {highest}) +FLAGS.SILENT (\\Seen)"
    ));
    let fetch = lines.iter().find(|l| l.contains("FETCH")).expect("fetch");
    assert!(fetch.contains("UID 1"), "{fetch}");
    assert!(fetch.contains("\\Seen"), "{fetch}");
    assert!(fetch.contains("MODSEQ ("), "{fetch}");
    assert!(lines.last().expect("tagged").contains("st OK"), "{lines:?}");
}

#[tokio::test]
async fn store_unchangedsince_zero_fails_every_system_flag() {
    let root = Root::new("zero");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("s SELECT INBOX (CONDSTORE)");
    // System flags are treated as present since forever (RFC 7162 §3.1.3):
    // UNCHANGEDSINCE 0 must fail them all.
    let lines = client.say("st STORE 1:* (UNCHANGEDSINCE 0) +FLAGS (\\Seen)");
    assert!(
        lines.last().expect("tagged").contains("[MODIFIED 1]"),
        "{:?}",
        lines.last()
    );
}

#[tokio::test]
async fn a_store_that_changes_nothing_bumps_nothing() {
    let root = Root::new("noop-store");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("s SELECT INBOX (CONDSTORE)");
    let lines = client.say("st STORE 1 +FLAGS (\\Seen)");
    let stored = modseq_of(lines.iter().find(|l| l.contains("FETCH")).expect("fetch"));
    // The same STORE again: the flags already hold, so the mod-sequence
    // holds too (RFC 7162 §3.1's SHOULD, exercised as a fact).
    let lines = client.say("st2 STORE 1 +FLAGS (\\Seen)");
    let again = modseq_of(lines.iter().find(|l| l.contains("FETCH")).expect("fetch"));
    assert_eq!(stored, again, "a no-op STORE must not advance the value");
    // …and the CHANGEDSINCE filter agrees: nothing new since the first bump.
    let lines = client.say(&format!("f UID FETCH 1:* (FLAGS) (CHANGEDSINCE {stored})"));
    assert!(
        !lines.iter().any(|l| is_untagged_fetch(l)),
        "empty at the exact value: {lines:?}"
    );
}

#[tokio::test]
async fn changedsince_is_strictly_above_the_value() {
    let root = Root::new("changedsince");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("s SELECT INBOX (CONDSTORE)");
    let lines = client.say("st STORE 1 +FLAGS (\\Seen)");
    let stored = modseq_of(lines.iter().find(|l| l.contains("FETCH")).expect("fetch"));
    // Exactly at the value: not reported (RFC 7162 §3.1.4.1's strict >).
    let lines = client.say(&format!("f UID FETCH 1:* (FLAGS) (CHANGEDSINCE {stored})"));
    assert!(!lines.iter().any(|l| is_untagged_fetch(l)), "{lines:?}");
    // One below: reported, and the answer carries the MODSEQ item even
    // though the client did not ask for it.
    let lines = client.say(&format!(
        "f2 UID FETCH 1:* (FLAGS) (CHANGEDSINCE {})",
        stored - 1
    ));
    let fetch = lines.iter().find(|l| l.contains("FETCH")).expect("fetch");
    assert!(fetch.contains("MODSEQ ("), "{fetch}");
    assert!(
        fetch.contains("UID 1"),
        "QRESYNC-less UID FETCH still names the UID"
    );
}

#[tokio::test]
async fn a_flag_change_is_visible_above_the_cached_watermark() {
    let root = Root::new("watermark");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut watcher = listener.connect();
    watcher.login();
    let lines = watcher.say("s SELECT INBOX (CONDSTORE)");
    let cached = highest_of(&lines);
    // Another session flips a flag; the change must land ABOVE the value the
    // watcher cached, or the watcher's CHANGEDSINCE filter would never hear
    // about it (the bump is what makes the change visible).
    let mut actor = listener.connect();
    actor.login();
    actor.say("s2 SELECT INBOX (CONDSTORE)");
    let lines = actor.say("st STORE 1 +FLAGS (\\Flagged)");
    let stored = modseq_of(lines.iter().find(|l| is_untagged_fetch(l)).expect("fetch"));
    assert!(
        stored > cached,
        "the change outran the cache: {stored} > {cached}"
    );
    let lines = watcher.say(&format!("f UID FETCH 1:* (FLAGS) (CHANGEDSINCE {cached})"));
    assert!(
        lines.iter().any(|l| is_untagged_fetch(l)),
        "the change is above the cached watermark: {lines:?}"
    );
    // And the watcher's own view agrees with the reporter's value.
    let fetch = lines.iter().find(|l| is_untagged_fetch(l)).expect("fetch");
    assert_eq!(modseq_of(fetch), stored, "{fetch}");
}

#[tokio::test]
async fn a_modseq_item_and_search_key_answer_on_the_wire() {
    let root = Root::new("modseq-items");
    root.deliver(1, "one");
    root.deliver(2, "two");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("s SELECT INBOX (CONDSTORE)");
    // RFC 7162 §3.1.4.2: `FETCH … (MODSEQ)` answers `MODSEQ (m)` items —
    // the item is lifted off the raw bytes (the codec cannot frame it) and
    // rendered back inside the item list.
    let lines = client.say("f FETCH 1:2 (MODSEQ)");
    let fetches = lines.iter().filter(|l| is_untagged_fetch(l)).count();
    assert_eq!(fetches, 2, "both messages answer: {lines:?}");
    for line in lines.iter().filter(|l| is_untagged_fetch(l)) {
        assert!(line.contains("MODSEQ ("), "{line}");
    }
    // …and the item is a CONDSTORE enabling command: a plain session that
    // asks for it hears MODSEQ on later untagged FETCHes too.
    let lines = client.say("f2 FETCH 1 (FLAGS)");
    let fetch = lines.iter().find(|l| is_untagged_fetch(l)).expect("fetch");
    assert!(fetch.contains("MODSEQ ("), "enabling persists: {fetch}");
    // RFC 7162 §3.1.5/§3.1.6: the MODSEQ search key filters, and a non-empty
    // result carries the `(MODSEQ n)` tail.
    let lines = client.say("sm SEARCH MODSEQ 1");
    let search = lines
        .iter()
        .find(|l| l.starts_with("* SEARCH"))
        .expect("search");
    assert!(search.contains("(MODSEQ "), "the tail: {search}");
    assert!(
        search.contains("1 2"),
        "both messages are above 1: {search}"
    );
}

#[tokio::test]
async fn uid_expunge_removes_only_the_intersection() {
    let root = Root::new("uid-expunge");
    root.deliver(1, "one");
    root.deliver(2, "two");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("s SELECT INBOX");
    client.say("st STORE 1:2 +FLAGS (\\Deleted)");
    // RFC 4315 §2.1: only UID 2 is in the set, so only UID 2 goes.
    let lines = client.say("ux UID EXPUNGE 2");
    assert!(lines.last().expect("tagged").contains("ux OK"), "{lines:?}");
    let lines = client.say("f UID FETCH 1:* (UID)");
    assert!(
        lines.iter().any(|l| l.contains("UID 1")),
        "uid 1 stays: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("UID 2")),
        "uid 2 is gone: {lines:?}"
    );
}

#[tokio::test]
async fn expunge_reports_vanished_for_a_qresync_session() {
    let root = Root::new("expunge-vanished");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("e ENABLE QRESYNC");
    client.say("s SELECT INBOX");
    client.say("st STORE 1 +FLAGS (\\Deleted)");
    let lines = client.say("x EXPUNGE");
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("* VANISHED "))
            .count(),
        1,
        "one VANISHED line, not one EXPUNGE per message: {lines:?}"
    );
    assert!(!lines.iter().any(|l| l.ends_with(" EXPUNGE")), "{lines:?}");
    let vanished = lines
        .iter()
        .find(|l| l.starts_with("* VANISHED "))
        .expect("vanished");
    assert_eq!(
        *vanished, "* VANISHED 1",
        "the live form carries no (EARLIER): {vanished}"
    );
    // RFC 7162 §3.2.7: the tagged OK carries the watermark.
    assert!(
        lines.last().expect("tagged").contains("[HIGHESTMODSEQ"),
        "{:?}",
        lines.last()
    );
}

#[tokio::test]
async fn close_answers_a_bare_ok_and_no_details() {
    let root = Root::new("close");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("e ENABLE QRESYNC");
    let lines = client.say("s SELECT INBOX");
    let validity = lines
        .iter()
        .find_map(|l| {
            l.split("[UIDVALIDITY ")
                .nth(1)
                .and_then(|rest| rest.split(']').next())
        })
        .and_then(|v| v.parse::<u32>().ok())
        .expect("UIDVALIDITY");
    client.say("st STORE 1 +FLAGS (\\Deleted)");
    // RFC 3501 §6.4.2 and RFC 7162 §3.2.8 (errata 1808): no detail lines,
    // no code on the tagged OK — even with QRESYNC enabled.
    let lines = client.say("c CLOSE");
    assert_eq!(lines, vec!["c OK CLOSE completed".to_owned()], "{lines:?}");
    // The deletion still happened and still recorded.
    let mut client2 = listener.connect();
    client2.login();
    client2.say("e2 ENABLE QRESYNC");
    let lines = client2.say(&format!("s2 SELECT INBOX (QRESYNC ({validity} 1))"));
    assert!(
        lines.iter().any(|l| l.contains("VANISHED (EARLIER)")),
        "the CLOSE deletion was recorded for the next sync: {lines:?}"
    );
}

#[tokio::test]
async fn noop_reports_flag_changes_and_removals() {
    let root = Root::new("noop");
    root.deliver(1, "one");
    root.deliver(2, "two");
    let listener = Listener::start(&root.0).await;
    let mut watcher = listener.connect();
    watcher.login();
    watcher.say("e ENABLE QRESYNC CONDSTORE");
    watcher.say("s SELECT INBOX");
    // Another session flips a flag and expunges.
    let mut actor = listener.connect();
    actor.login();
    actor.say("s2 SELECT INBOX");
    actor.say("st STORE 1 +FLAGS (\\Flagged)");
    actor.say("st2 STORE 2 +FLAGS (\\Deleted)");
    actor.say("x EXPUNGE");
    let lines = watcher.say("n NOOP");
    // The flag change: one FETCH line with UID and MODSEQ (RFC 7162 §3.2.4).
    let fetch = lines.iter().find(|l| l.contains("FETCH")).expect("fetch");
    assert!(
        fetch.contains("UID 1") && fetch.contains("MODSEQ (") && fetch.contains("\\Flagged"),
        "{fetch}"
    );
    // The removal: VANISHED for a QRESYNC session (RFC 7162 §3.2.10.2).
    let vanished = lines
        .iter()
        .find(|l| l.starts_with("* VANISHED "))
        .expect("vanished");
    assert_eq!(*vanished, "* VANISHED 2", "{vanished}");
    // And the plain session hears the renumbering EXPUNGE instead.
    let mut plain = listener.connect();
    plain.login();
    plain.say("s3 SELECT INBOX");
    actor.say("st3 STORE 1 +FLAGS (\\Deleted)");
    actor.say("x2 EXPUNGE");
    let lines = plain.say("n2 NOOP");
    assert!(
        lines.iter().any(|l| l == "* 1 EXPUNGE"),
        "the plain session hears EXPUNGE lines: {lines:?}"
    );
}

#[tokio::test]
async fn qresync_select_replays_vanished_before_fetch() {
    let root = Root::new("qresync-select");
    root.deliver(1, "one");
    root.deliver(2, "two");
    root.deliver(3, "three");
    let listener = Listener::start(&root.0).await;
    // Session one: selects with CONDSTORE, flips a flag, expunges uid 2,
    // and leaves its watermark behind.
    let mut first = listener.connect();
    first.login();
    let lines = first.say("s SELECT INBOX (CONDSTORE)");
    let validity = lines
        .iter()
        .find_map(|l| {
            l.split("[UIDVALIDITY ")
                .nth(1)
                .and_then(|rest| rest.split(']').next())
        })
        .and_then(|v| v.parse::<u32>().ok())
        .expect("UIDVALIDITY");
    let st_lines = first.say("st STORE 2 +FLAGS (\\Deleted)");
    assert!(
        st_lines.last().expect("tagged").contains("st OK"),
        "{st_lines:?}"
    );
    let x_lines = first.say("x EXPUNGE");
    assert!(
        x_lines.last().expect("tagged").contains("x OK"),
        "{x_lines:?}"
    );
    let lines = first.say("st2 STORE 1 +FLAGS (\\Seen)");
    // The cached watermark sits between the expunge and this change, the
    // way a client that heard about the \Seen change but resyncs from an
    // older snapshot would hold it.
    let watermark = modseq_of(lines.iter().find(|l| is_untagged_fetch(l)).expect("fetch")) - 2;
    first.send("l LOGOUT");
    let _ = first.until_tag("l");
    // Session two: a client that cached UIDs 1..10 and resyncs from the old
    // watermark hears the expunged UID first, then the flag change.
    let mut second = listener.connect();
    second.login();
    second.say("e ENABLE QRESYNC");
    let lines = second.say(&format!(
        "s SELECT INBOX (QRESYNC ({validity} {watermark} 1:10))"
    ));
    let vanished_at = lines.iter().position(|l| l.contains("VANISHED (EARLIER)"));
    let fetch_at = lines.iter().position(|l| l.contains("FETCH"));
    assert!(
        vanished_at.expect("VANISHED (EARLIER) present") < fetch_at.expect("fetch"),
        "VANISHED (EARLIER) precedes the FETCH lines: {lines:?}"
    );
    let vanished = lines
        .iter()
        .find(|l| l.contains("VANISHED (EARLIER)"))
        .expect("line");
    assert_eq!(
        *vanished, "* VANISHED (EARLIER) 2",
        "exact queue answer: {vanished}"
    );
    let fetch = lines.iter().find(|l| l.contains("FETCH")).expect("fetch");
    assert!(
        fetch.contains("UID 1") && fetch.contains("\\Seen"),
        "{fetch}"
    );
    assert!(
        modseq_of(fetch) > watermark,
        "the change took a value above the client's watermark"
    );
    // The client that only holds uid 1 hears nothing about uid 2 — the
    // known-uids set intersects the report (RFC 7162 §3.2.5).
    let mut third = listener.connect();
    third.login();
    third.say("e2 ENABLE QRESYNC");
    let lines = third.say(&format!("s2 SELECT INBOX (QRESYNC ({validity} 1 1:1))"));
    assert!(
        !lines.iter().any(|l| l.contains("VANISHED")),
        "uid 2 is outside the client's known set: {lines:?}"
    );
    // A UIDVALIDITY mismatch ignores the parameters whole (RFC 7162 §3.2.5.1).
    let lines = third.say(&format!(
        "s3 SELECT INBOX (QRESYNC ({} {watermark} 1:10))",
        validity.wrapping_add(1)
    ));
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("VANISHED") || l.contains("FETCH")),
        "mismatched UIDVALIDITY: no replay at all: {lines:?}"
    );
    assert!(lines.last().expect("tagged").contains("s3 OK"), "{lines:?}");
}

#[tokio::test]
async fn status_highestmodseq_enables_and_answers() {
    let root = Root::new("status");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    // A selected mailbox is what makes the enabling notice owed (RFC 7162
    // §3.1.2.1): a plain SELECT, then STATUS with the item.
    client.say("s SELECT INBOX");
    let lines = client.say("st STATUS INBOX (MESSAGES HIGHESTMODSEQ)");
    assert!(
        lines
            .iter()
            .take_while(|l| !l.starts_with("* STATUS"))
            .any(|l| l.starts_with("* OK [HIGHESTMODSEQ")),
        "the one-time enabling notice rides before the STATUS line: {lines:?}"
    );
    let status = lines
        .iter()
        .find(|l| l.starts_with("* STATUS"))
        .expect("status");
    // The value rides inside the item list the codec rendered (1.0 has no
    // HIGHESTMODSEQ status item to put there itself).
    let value: u64 = status
        .split("HIGHESTMODSEQ ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|v| v.parse().ok())
        .expect("the status value");
    assert!(status.contains("MESSAGES 1"), "{status}");
    assert!(
        value >= 2,
        "the scan assigned the message a value: {status}"
    );
}

#[tokio::test]
async fn append_and_copy_answer_the_uidplus_codes() {
    let root = Root::new("uidplus");
    root.deliver(1, "one");
    let listener = Listener::start(&root.0).await;
    let mut client = listener.connect();
    client.login();
    client.say("s SELECT INBOX");
    // APPENDUID (RFC 4315 §3).
    let message = "From: bob@example.test\r\nSubject: appended\r\n\r\nbody\r\n";
    client.send(&format!("ap APPEND INBOX {{{}}}", message.len()));
    // A synchronizing literal is answered with a continuation first.
    let continuation = client.line();
    assert!(continuation.starts_with('+'), "{continuation}");
    client.send(message);
    let lines = client.until_tag("ap");
    let tagged = lines.last().expect("tagged");
    let uid: u32 = tagged
        .split("[APPENDUID ")
        .nth(1)
        .and_then(|rest| rest.split(' ').nth(1))
        .and_then(|v| v.trim_end_matches(']').parse().ok())
        .expect("APPENDUID uid");
    assert!(uid >= 2, "{tagged}");
    // COPYUID on COPY, aligned (RFC 4315 §3).
    let lines = client.say("cp COPY 1 Archive");
    assert!(
        lines.last().expect("tagged").contains("[COPYUID "),
        "COPY carries the code on the tagged OK: {:?}",
        lines.last()
    );
    // The MOVE shape: the mapping rides an untagged `* OK [COPYUID …]`
    // before the removal lines (RFC 6851 §4.3).
    let lines = client.say("mv MOVE 1 Archive");
    let copyuid_at = lines
        .iter()
        .position(|l| l.contains("COPYUID"))
        .expect("COPYUID present");
    let expunge_at = lines.iter().position(|l| l.contains("EXPUNGE"));
    assert!(
        expunge_at.is_none_or(|at| copyuid_at < at),
        "COPYUID precedes the EXPUNGE lines: {lines:?}"
    );
    let mapping = &lines[copyuid_at];
    assert!(
        mapping.starts_with("* OK [COPYUID "),
        "the untagged form: {mapping}"
    );
}
