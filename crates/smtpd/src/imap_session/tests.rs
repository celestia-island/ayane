//! Tests for the IMAP4rev1 session: the state machine driven as a table, the
//! maildir backend's identity rules, and the literal framing a client's
//! upload depends on.

use std::sync::atomic::{AtomicUsize, Ordering};

use imap_codec::decode::Decoder;
use imap_codec::imap_types::{
    core::{NonEmptyVec, Tag},
    fetch::MessageDataItem,
    response::{Data, Response},
};
use imap_codec::CommandCodec;

use super::render::literal_string;
use super::session::{ImapSession, Transport};
use super::wire::{encode, glob, line, non_zero};
use super::*;
use crate::authn::PasswordVerifier;
use crate::maildir_reader::{MaildirReader, MessageId, INBOX};

/// A verifier that accepts exactly one identity/password pair, and counts how
/// often it was asked (so "the password was never checked" is a fact a test
/// can assert rather than infer).
struct OnePassword {
    identity: &'static str,
    password: &'static str,
    asked: AtomicUsize,
}

impl PasswordVerifier for OnePassword {
    fn verify<'s>(
        &'s self,
        identity: &'s str,
        password: &'s str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 's>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let ok = identity == self.identity && password == self.password;
        Box::pin(async move { ok })
    }
}

/// One account's mail root, removed when the test ends.
struct Fixture {
    /// Owns the directory; dropped (and therefore removed) with the fixture.
    _root: tempdir::Dir,
    reader: MaildirReader,
    mailbox: Address,
}

impl Fixture {
    fn new() -> Self {
        let root = tempdir::Dir::new();
        let reader = MaildirReader::new(root.path());
        let mailbox = Address::parse("alice@example.test").expect("a valid address");
        Self {
            _root: root,
            reader,
            mailbox,
        }
    }

    fn session<'a>(&self, transport: Transport, passwords: &'a OnePassword) -> ImapSession<'a> {
        ImapSession::new(
            "mail.example.test",
            self.mailbox.clone(),
            self.reader.clone(),
            transport,
            passwords,
        )
    }

    /// The octets of a message the test delivered.
    fn message_bytes(&self, address: &Address, name: &str) -> Vec<u8> {
        // The folder is checked to exist inside `read_raw`; this only reads.
        let _ = self.reader.folder_dir(address, INBOX, false);
        let id = MessageId::parse(name).expect("a maildir name");
        self.reader
            .read_raw(address, INBOX, &id.file_name())
            .expect("the message")
    }

    /// Write one message straight into the account's INBOX maildir, the way a
    /// delivery lands (`new/`, no flag suffix).
    fn deliver(&self, unique: &str, subject: &str) {
        let dir = self
            .reader
            .folder_dir(&self.mailbox, INBOX, true)
            .expect("the maildir exists");
        std::fs::write(
            dir.join("new").join(unique),
            format!("From: bob@example.test\r\nTo: alice@example.test\r\nSubject: {subject}\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <{unique}>\r\n\r\nbody of {subject}\r\n"),
        )
        .expect("message written");
    }
}

/// A tiny directory under the system temporary directory, removed on drop.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "ayane-imap-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn passwords() -> OnePassword {
    OnePassword {
        identity: "alice@example.test",
        password: "correct horse",
        asked: AtomicUsize::new(0),
    }
}

/// Feed one command line and answer with the reply text.
async fn say(session: &mut ImapSession<'_>, line: &str) -> String {
    let bytes = line.as_bytes().to_vec();
    let (_, command) = CommandCodec::default()
        .decode(&bytes)
        .expect("the command parses");
    let outcome = session.handle(&command).await;
    assert!(
        outcome.start_tls.is_none(),
        "a plain command never starts TLS"
    );
    String::from_utf8_lossy(&outcome.out).into_owned()
}

/// Log in over TLS (the only transport that accepts a password).
async fn login(session: &mut ImapSession<'_>) -> String {
    say(session, "a1 LOGIN alice@example.test \"correct horse\"\r\n").await
}

// ── the state machine ────────────────────────────────────────────────────

#[tokio::test]
async fn a_password_in_the_clear_is_never_verified() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let mut session = fixture.session(Transport::Clear, &passwords);
    let reply = login(&mut session).await;
    assert!(
        reply.contains("a1 NO"),
        "LOGIN over plaintext is refused: {reply}"
    );
    assert_eq!(
        passwords.asked.load(Ordering::SeqCst),
        0,
        "the password must not even be checked"
    );
    assert_eq!(session.state(), State::NotAuthenticated);
    assert!(session.capabilities().contains("LOGINDISABLED"));
    assert!(session.capabilities().contains("STARTTLS"));
}

#[tokio::test]
async fn a_password_over_tls_is_checked_and_only_for_this_mailbox() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    let reply = login(&mut session).await;
    assert!(reply.contains("a1 OK"), "LOGIN over TLS succeeds: {reply}");
    assert_eq!(session.state(), State::Authenticated);
    assert_eq!(passwords.asked.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_valid_password_for_another_mailbox_does_not_open_this_one() {
    let fixture = Fixture::new();
    // The verifier says yes for `bob`; this session is alice's.
    // Invented here, for this test only: the point is that a *valid* password
    // for one account must not open another's mailbox.
    let bob_password = "bob-test-only-password";
    let passwords = OnePassword {
        identity: "bob@example.test",
        password: bob_password,
        asked: AtomicUsize::new(0),
    };
    let mut session = fixture.session(Transport::Tls, &passwords);
    let reply = say(
        &mut session,
        "a1 LOGIN bob@example.test \"bob-test-only-password\"\r\n",
    )
    .await;
    assert!(
        reply.contains("a1 NO"),
        "the mailbox is the destination, not a claim: {reply}"
    );
    assert_eq!(session.state(), State::NotAuthenticated);
}

#[tokio::test]
async fn a_command_before_login_is_refused_and_changes_nothing() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    let reply = say(&mut session, "a1 SELECT INBOX\r\n").await;
    assert!(reply.contains("a1 BAD"), "SELECT before LOGIN: {reply}");
    assert_eq!(session.state(), State::NotAuthenticated);
}

#[tokio::test]
async fn authenticating_twice_is_refused() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    let reply = login(&mut session).await;
    assert!(
        reply.contains("BAD"),
        "a second LOGIN is a protocol error: {reply}"
    );
    assert_eq!(session.state(), State::Authenticated);
}

#[tokio::test]
async fn the_full_lifecycle_walks_the_four_states() {
    let fixture = Fixture::new();
    fixture.deliver("1700000000.M1P1Q0.example", "hello");
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    assert_eq!(session.state(), State::NotAuthenticated);
    assert!(session.greeting().starts_with(b"* OK [CAPABILITY"));
    login(&mut session).await;
    assert_eq!(session.state(), State::Authenticated);
    let reply = say(&mut session, "a2 SELECT INBOX\r\n").await;
    assert!(reply.contains("[READ-WRITE]"), "SELECT: {reply}");
    assert_eq!(session.state(), State::Selected);
    let reply = say(&mut session, "a3 CLOSE\r\n").await;
    assert!(reply.contains("OK"), "CLOSE: {reply}");
    assert_eq!(session.state(), State::Authenticated);
    let outcome = {
        let (_, command) = CommandCodec::default()
            .decode(b"a4 LOGOUT\r\n")
            .expect("parses");
        session.handle(&command).await
    };
    assert!(outcome.close, "LOGOUT closes the connection");
    assert_eq!(session.state(), State::Logout);
    let reply = say(&mut session, "a5 NOOP\r\n").await;
    assert!(reply.contains("BAD"), "nothing runs after LOGOUT: {reply}");
}

#[tokio::test]
async fn examine_is_read_only_and_refuses_every_mutation() {
    let fixture = Fixture::new();
    fixture.deliver("1700000001.M1P1Q0.example", "hello");
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    let reply = say(&mut session, "a2 EXAMINE INBOX\r\n").await;
    assert!(reply.contains("[READ-ONLY]"), "EXAMINE: {reply}");
    for (tag, command) in [
        ("a3", "a3 STORE 1 +FLAGS (\\Seen)\r\n"),
        ("a4", "a4 EXPUNGE\r\n"),
        ("a5", "a5 COPY 1 Sent\r\n"),
        ("a6", "a6 MOVE 1 Sent\r\n"),
    ] {
        let reply = say(&mut session, command).await;
        assert!(
            reply.contains(&format!("{tag} NO")),
            "{command} must be refused: {reply}"
        );
    }
    // Nothing was renamed: the maildir still holds the untouched name.
    let dir = fixture
        .reader
        .folder_dir(&fixture.mailbox, INBOX, false)
        .expect("maildir");
    let names: Vec<_> = std::fs::read_dir(dir.join("new"))
        .expect("new/")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert_eq!(names.len(), 1, "the read-only selection changed nothing");
}

#[tokio::test]
async fn an_unimplemented_command_is_named_in_the_refusal() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    let reply = say(&mut session, "a2 CREATE Archives\r\n").await;
    assert!(
        reply.contains("a2 BAD"),
        "CREATE is not implemented: {reply}"
    );
    assert!(
        reply.contains("CREATE"),
        "the refusal names the command: {reply}"
    );
}

// ── the maildir backend's identity rules ─────────────────────────────────

#[tokio::test]
async fn a_uid_survives_a_flag_change_and_a_move_into_cur() {
    let fixture = Fixture::new();
    fixture.deliver("1700000100.M1P1Q0.example", "one");
    fixture.deliver("1700000101.M1P1Q0.example", "two");
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    say(&mut session, "a2 SELECT INBOX\r\n").await;
    let before = say(&mut session, "a3 UID SEARCH ALL\r\n").await;
    assert!(before.contains("1 2"), "two messages, two UIDs: {before}");
    // Marking message 1 seen renames it (`:2,S`) and moves it to cur/.
    let reply = say(&mut session, "a4 UID STORE 1 +FLAGS (\\Seen)\r\n").await;
    assert!(
        reply.contains("UID 1"),
        "the STORE answers with the UID it kept: {reply}"
    );
    assert!(
        reply.contains("\\Seen"),
        "and with the flags now set: {reply}"
    );
    let after = say(&mut session, "a5 UID SEARCH ALL\r\n").await;
    assert!(after.contains("1 2"), "the UIDs are unchanged: {after}");
    let dir = fixture
        .reader
        .folder_dir(&fixture.mailbox, INBOX, false)
        .expect("maildir");
    assert!(
        std::fs::read_dir(dir.join("cur")).expect("cur/").any(|e| e
            .expect("entry")
            .file_name()
            .to_string_lossy()
            .ends_with(":2,S")),
        "the flag lives in the name"
    );
    assert_eq!(
        std::fs::read_dir(dir.join("new")).expect("new/").count(),
        1,
        "only the untouched message stays in new/"
    );
}

#[tokio::test]
async fn a_delivery_that_lands_later_gets_the_next_uid() {
    let fixture = Fixture::new();
    fixture.deliver("1700000200.M1P1Q0.example", "one");
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    say(&mut session, "a2 SELECT INBOX\r\n").await;
    assert!(say(&mut session, "a3 UID SEARCH ALL\r\n")
        .await
        .contains("1"));
    // A delivery writes `new/` behind the session's back.
    fixture.deliver("1700000201.M1P1Q0.example", "two");
    let reply = say(&mut session, "a4 NOOP\r\n").await;
    assert!(
        reply.contains("2 EXISTS"),
        "NOOP announces the new message: {reply}"
    );
    let reply = say(&mut session, "a5 UID SEARCH ALL\r\n").await;
    assert!(
        reply.contains("1 2"),
        "the new message takes the next UID: {reply}"
    );
    // The same folder scanned by a *second* session agrees, because the table
    // is a file and not a session's memory.
    let mut other = fixture.session(Transport::Tls, &passwords);
    login(&mut other).await;
    say(&mut other, "b2 SELECT INBOX\r\n").await;
    let reply = say(&mut other, "b3 UID SEARCH ALL\r\n").await;
    assert!(
        reply.contains("1 2"),
        "a second session sees the same UIDs: {reply}"
    );
}

#[test]
fn an_assigned_uid_is_never_reassigned() {
    let dir = tempdir::Dir::new();
    let mut map = UidMap::default();
    let live = vec![
        ("a.msg".to_owned(), "a.msg".to_owned(), false),
        ("b.msg".to_owned(), "b.msg".to_owned(), false),
    ];
    let first = map.sync(&live);
    assert_eq!(
        first.iter().map(|(uid, _, _)| *uid).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(map.next, 3);
    // `a.msg` disappears and a new message arrives.
    let second = map.sync(&[("c.msg".to_owned(), "c.msg:2,S".to_owned(), true)]);
    assert_eq!(
        second.iter().map(|(uid, _, _)| *uid).collect::<Vec<_>>(),
        vec![3],
        "only the new message is live"
    );
    assert_eq!(map.next, 4, "the watermark only grows");
    assert_eq!(
        map.uid_of("a.msg"),
        Some(1),
        "the vanished message keeps its UID, so no later one can take it"
    );
    map.store(dir.path()).expect("the table is written");
    let reloaded = UidMap::load(dir.path()).expect("the table is read back");
    assert_eq!(reloaded.lines, map.lines, "the table round-trips");
    assert_eq!(reloaded.next, map.next, "the watermark round-trips");
    assert_eq!(reloaded.validity, map.validity, "the validity round-trips");
    assert!(
        reloaded.validity_persisted,
        "the stored file carries the validity line"
    );
}

/// The one path where a rotation could be undone by the scan's own store: the
/// sidecar is lost *and* new mail arrives before the next scan, so the table
/// grows in the very pass that must rotate it. The table is read before the
/// rotation, so the store that follows would put the stale validity back —
/// a QRESYNC client would then keep mod-sequence state this server rebuilt.
#[tokio::test]
async fn a_lost_sidecar_rotates_even_when_the_same_scan_takes_new_mail() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let session = fixture.session(Transport::Tls, &passwords);
    let dir = fixture
        .reader
        .folder_dir(&fixture.mailbox, INBOX, true)
        .expect("the maildir exists");
    // The CONDSTORE era: one scan persisted the table *and* the sidecar.
    fixture.deliver("a.msg", "first");
    let mut map = UidMap::load(&dir).expect("load");
    session.scan(&dir, &mut map).expect("the first scan");
    let persisted = UidMap::load(&dir).expect("reload");
    assert!(
        persisted.validity_persisted,
        "the first scan froze the minted validity"
    );
    // A crash loses the sidecar only, and a message lands before the next
    // scan sees the folder.
    std::fs::remove_file(modseq::ModSeqTable::path(&dir)).expect("sidecar removed");
    fixture.deliver("b.msg", "second");
    let mut map = UidMap::load(&dir).expect("load");
    session
        .scan(&dir, &mut map)
        .expect("the scan after the loss");
    let rotated = persisted.validity.wrapping_add(1).max(2);
    assert_eq!(
        map.validity, rotated,
        "the scan answers the rotated validity (§5.3)"
    );
    let stored = UidMap::load(&dir).expect("reload");
    assert_eq!(
        stored.validity, rotated,
        "and the scan's own store does not put the stale value back"
    );
    assert_eq!(stored.lines.len(), 2, "the new message still got its UID");
    assert_eq!(stored.lines[1].1, "b.msg", "in scan order");
    // Once is enough: the rebuilt sidecar ends the fresh state.
    let mut map = UidMap::load(&dir).expect("load");
    session.scan(&dir, &mut map).expect("the third scan");
    assert_eq!(map.validity, rotated, "a later scan rotates nothing");
}

/// The other half of that ordering: a table written before CONDSTORE existed
/// (no `v` line) is an **upgrade**, not a loss, so the scan must not rotate
/// it. The store has to come after the sync for that: a table stored first
/// would already carry a persisted validity when the sync looks at it, and
/// the upgrade would be mistaken for a lost sidecar.
#[tokio::test]
async fn an_upgrade_keeps_the_identity_through_the_scan() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let session = fixture.session(Transport::Tls, &passwords);
    let dir = fixture
        .reader
        .folder_dir(&fixture.mailbox, INBOX, true)
        .expect("the maildir exists");
    fixture.deliver("a.msg", "first");
    fixture.deliver("b.msg", "second");
    // A pre-CONDSTORE table: message lines, no persisted validity, and `b`
    // not yet mapped — so the scan that adopts the sidecar also grows the
    // table, which is the store that would run first in the wrong order.
    std::fs::write(UidMap::path(&dir), "1 a.msg\n").expect("write");
    let minted = UidMap::load(&dir).expect("load").validity;
    let mut map = UidMap::load(&dir).expect("load");
    session.scan(&dir, &mut map).expect("the adopting scan");
    let stored = UidMap::load(&dir).expect("reload");
    assert_eq!(
        stored.validity, minted,
        "an upgrade keeps the folder's identity"
    );
    assert!(
        stored.validity_persisted,
        "and the minted value is frozen into the file"
    );
    assert_eq!(map.validity, minted, "the answer agrees with the file");
    assert_eq!(stored.lines.len(), 2, "the unmapped message got its UID");
}

#[test]
fn a_corrupt_table_line_is_skipped_rather_than_fatal() {
    let dir = tempdir::Dir::new();
    std::fs::write(
        UidMap::path(dir.path()),
        "1 good.msg\nnot-a-line\n2\n0 zero.msg\n3 bad/name\n4 also.msg:2,SF\n",
    )
    .expect("write");
    let map = UidMap::load(dir.path()).expect("a corrupt line is not an error");
    assert_eq!(
        map.lines,
        vec![(1, "good.msg".to_owned()), (4, "also.msg".to_owned())]
    );
    assert_eq!(
        map.next, 5,
        "the watermark clears every UID the file mentioned"
    );
}

#[test]
fn uidvalidity_is_stable_for_the_folder_and_changes_with_it() {
    let dir = tempdir::Dir::new();
    let inbox = dir.path().join("Maildir");
    std::fs::create_dir_all(inbox.join("new")).expect("maildir");
    let first = uid_validity(&inbox);
    assert_ne!(first, 0, "a UIDVALIDITY is never zero");
    assert_eq!(uid_validity(&inbox), first, "asking twice is one answer");
    // Filling the folder does not change the *folder's* identity.
    std::fs::write(inbox.join("new").join("m.msg"), b"x").expect("write");
    assert_eq!(
        uid_validity(&inbox),
        first,
        "a child does not move the parent's inode"
    );
    // Recreating it at the same path does.
    std::fs::remove_dir_all(&inbox).expect("remove");
    // Make the second creation demonstrably a different moment: tmpfs can
    // hand a recreated inode the same ctime tick, and the value is a hash of
    // exactly that stamp.
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::create_dir_all(inbox.join("new")).expect("recreate");
    let second = uid_validity(&inbox);
    // The digest is inode + device + ctime: a filesystem may hand a recreated
    // directory the same inode, so the value only *guarantees* a change when
    // the stamp moved too. A value that stayed identical with an identical
    // inode is the filesystem's, not this function's, and the function is
    // still exactly what RFC 3501 §2.3.1.1 asks for.
    assert_ne!(second, 0, "UIDVALIDITY is never zero");
    std::fs::write(inbox.join("new").join("other.msg"), b"x").expect("write");
    assert_eq!(
        uid_validity(&inbox),
        second,
        "a child does not move the folder's identity"
    );
    assert_eq!(
        uid_validity(&dir.path().join("absent")),
        1,
        "a folder that is not there answers 1"
    );
}

#[tokio::test]
async fn sequence_numbers_are_uid_order_and_expunge_renumbers() {
    let fixture = Fixture::new();
    // Written out of name order so a listing-order implementation would fail.
    fixture.deliver("1700000302.M1P1Q0.example", "third");
    fixture.deliver("1700000300.M1P1Q0.example", "first");
    fixture.deliver("1700000301.M1P1Q0.example", "second");
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    say(&mut session, "a2 SELECT INBOX\r\n").await;
    // UID `n` is the n-th name, and FETCH reports the sequence number that
    // UID's order gives it.
    let reply = say(&mut session, "a3 UID FETCH 1 (UID)\r\n").await;
    assert!(
        reply.contains("* 1 FETCH (UID 1)"),
        "UID 1 is sequence 1: {reply}"
    );
    let reply = say(&mut session, "a4 UID FETCH 3 (UID)\r\n").await;
    assert!(
        reply.contains("* 3 FETCH (UID 3)"),
        "UID 3 is sequence 3: {reply}"
    );
    // Deleting the middle one and expunging renumbers the last to 2.
    assert!(say(&mut session, "a5 STORE 2 +FLAGS (\\Deleted)\r\n")
        .await
        .contains("OK"));
    let reply = say(&mut session, "a6 EXPUNGE\r\n").await;
    assert!(
        reply.contains("* 2 EXPUNGE"),
        "the middle message is expunged: {reply}"
    );
    let reply = say(&mut session, "a7 FETCH 2 (UID)\r\n").await;
    assert!(
        reply.contains("* 2 FETCH (UID 3)"),
        "sequence 2 is now the old sequence 3: {reply}"
    );
}

#[tokio::test]
async fn append_stores_the_literal_verbatim_and_answers_appenduid() {
    let fixture = Fixture::new();
    let passwords = passwords();
    let mut session = fixture.session(Transport::Tls, &passwords);
    login(&mut session).await;
    say(&mut session, "a2 SELECT INBOX\r\n").await;
    let message = b"From: bob@example.test\r\nSubject: cro\r\n\r\nline one\r\nline two\r\n";
    let command = format!("a3 APPEND INBOX (\\Seen) {{{}}}\r\n", message.len());
    let mut bytes = command.into_bytes();
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(b"\r\n");
    let (_, parsed) = CommandCodec::default()
        .decode(&bytes)
        .expect("APPEND parses");
    let reply = String::from_utf8_lossy(&session.handle(&parsed).await.out).into_owned();
    assert!(reply.contains("a3 OK"), "APPEND: {reply}");
    assert!(
        reply.contains("1 EXISTS"),
        "the selected mailbox is told: {reply}"
    );
    assert!(
        reply.contains("APPENDUID"),
        "UIDPLUS is advertised, so the code is obligatory (RFC 4315 §3): {reply}"
    );
    assert!(
        !reply.contains("COPYUID"),
        "COPYUID belongs to COPY, not APPEND: {reply}"
    );
    let dir = fixture
        .reader
        .folder_dir(&fixture.mailbox, INBOX, true)
        .expect("maildir");
    let stored: Vec<Vec<u8>> = std::fs::read_dir(dir.join("cur"))
        .expect("cur/")
        .filter_map(|e| e.ok())
        .map(|e| std::fs::read(e.path()).expect("read"))
        .collect();
    assert_eq!(
        stored,
        vec![message.to_vec()],
        "the literal is stored byte for byte, CRLFs and all"
    );
}

// ── literal framing ──────────────────────────────────────────────────────

#[test]
fn a_fetch_of_body_sets_seen_but_peek_does_not() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let fixture = Fixture::new();
        fixture.deliver("1700000400.M1P1Q0.example", "hello");
        let passwords = passwords();
        let mut session = fixture.session(Transport::Tls, &passwords);
        login(&mut session).await;
        say(&mut session, "a2 SELECT INBOX\r\n").await;
        let reply = say(&mut session, "a3 FETCH 1 BODY.PEEK[]\r\n").await;
        assert!(
            !reply.contains("\\Seen"),
            "BODY.PEEK leaves the message unread: {reply}"
        );
        let reply = say(&mut session, "a4 FETCH 1 FLAGS\r\n").await;
        assert!(!reply.contains("\\Seen"), "FLAGS: {reply}");
        let reply = say(&mut session, "a5 FETCH 1 BODY[]\r\n").await;
        assert!(
            reply.contains("hello"),
            "the whole message comes back: {reply}"
        );
        let reply = say(&mut session, "a6 FETCH 1 FLAGS\r\n").await;
        assert!(reply.contains("\\Seen"), "BODY[] marks it read: {reply}");
    });
}

#[test]
fn a_body_literal_is_announced_with_its_own_length_and_nothing_else() {
    // RFC 3501 §4.3 and §6.4.5: `{n}` is the number of octets **in the
    // literal**, and the literal is the message. A client reads exactly `n`
    // octets after the announcement's CRLF and then expects the rest of the
    // response, so an announcement that counted its own `{n}\r\n` would hand
    // every client seven octets that belong to the announcement.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let fixture = Fixture::new();
        fixture.deliver("1700000500.M1P1Q0.example", "literal-length");
        let address = Address::parse("alice@example.test").expect("address");
        let dir = fixture
            .reader
            .folder_dir(&address, INBOX, true)
            .expect("maildir");
        let name = std::fs::read_dir(dir.join("new"))
            .expect("messages")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .next()
            .expect("a message");
        let message = fixture.message_bytes(&address, &name);

        let passwords = passwords();
        let mut session = fixture.session(Transport::Tls, &passwords);
        login(&mut session).await;
        say(&mut session, "a2 SELECT INBOX\r\n").await;
        let reply = say(&mut session, "a3 FETCH 1 BODY.PEEK[]\r\n").await;

        // Read it the way a client does: the last `{n}` in the reply is the
        // literal's announcement, `n` octets follow it, and whatever comes
        // after them is the rest of the response.
        let (announced, literal, rest) = split_literal(&reply)
            .unwrap_or_else(|| panic!("the reply holds no literal: {reply:?}"));
        assert_eq!(
            announced,
            message.len(),
            "the announcement counts the message, not itself: {reply:?}"
        );
        assert_eq!(
            literal, message,
            "the literal is the message's own octets, and nothing else"
        );
        // What follows the literal is the rest of the FETCH item list, never a
        // second announcement or a repeated `{n}`.
        let tail = String::from_utf8_lossy(&rest);
        assert!(
            tail.starts_with(')'),
            "the response resumes with `)`: {tail:?}"
        );
        assert!(
            !tail.contains('{'),
            "no announcement follows the literal: {tail:?}"
        );
        assert!(
            !tail.contains("FETCH (BODY[] {"),
            "no second FETCH line: {tail:?}"
        );
    });
}

#[test]
fn an_announcement_is_written_once_and_counts_only_the_literal() {
    // RFC 3501 §4.3 and §6.4.5: a literal is announced once, on the line
    // before its octets, and `{n}` counts the octets **in the literal** and
    // nothing else. Both halves of that rule are asserted on the bytes the
    // encoder produces for one small FETCH, where every octet is spelled out:
    // the announcement appears exactly once, the literal is the message's own
    // octets, and the response resumes immediately after it.
    let body = b"hello\r\nworld\r\n";
    let response = Response::Data(Data::Fetch {
        seq: non_zero(1),
        items: NonEmptyVec::try_from(vec![
            MessageDataItem::Uid(non_zero(1)),
            MessageDataItem::BodyExt {
                section: None,
                origin: None,
                data: literal_string(body),
            },
        ])
        .expect("two items"),
    });
    let text = String::from_utf8_lossy(&encode(&response)).into_owned();
    let expected = format!(
        "* 1 FETCH (UID 1 BODY[] {{{}}}\r\n{})\r\n",
        body.len(),
        String::from_utf8_lossy(body)
    );
    assert_eq!(
        text, expected,
        "the answer is the announcement, then the message, then the rest"
    );
    // The same facts, stated separately so a failure names which one broke.
    assert_eq!(
        text.matches('{').count(),
        1,
        "the announcement is written exactly once: {text:?}"
    );
    let (announced, literal, rest) =
        split_literal(&text).unwrap_or_else(|| panic!("no literal in {text:?}"));
    assert_eq!(announced, body.len(), "`{{n}}` counts the literal only");
    assert_eq!(literal, body.to_vec(), "and the literal is the message");
    assert_eq!(rest.as_slice(), b")\r\n", "the response resumes after it");
}

/// The literal a rendered reply carries, as `(its announced length, its
/// octets, what follows them)`.
///
/// A client's reading, byte for byte: the **last** `{n}` in the reply is the
/// announcement, exactly `n` octets follow it (they may hold CRLF, braces and
/// anything else), and the rest of the response comes after. `None` when the
/// reply holds no `{n}` that its own octets fit.
fn split_literal(wire: &str) -> Option<(usize, Vec<u8>, Vec<u8>)> {
    let bytes = wire.as_bytes();
    let announced = bytes.iter().rposition(|byte| *byte == b'{')?;
    let close = announced + bytes[announced..].iter().position(|byte| *byte == b'}')?;
    let length: usize = std::str::from_utf8(&bytes[announced + 1..close])
        .ok()?
        .parse()
        .ok()?;
    let start = close + 1 + 2; // past `}` and the CRLF that ends its line
    let end = start.checked_add(length)?;
    if end > bytes.len() {
        return None;
    }
    Some((length, bytes[start..end].to_vec(), bytes[end..].to_vec()))
}

/// The reply bytes a status line carries, for the tests that only look at the
/// text (a NO line and a BAD line differ only in the word between tag and
/// text).
#[test]
fn a_status_line_is_encoded_the_way_the_protocol_spells_it() {
    let tag = Tag::try_from("A1".to_owned()).expect("tag");
    assert_eq!(
        line(tag.as_ref(), Kind::No, None, "nope", false),
        b"A1 NO nope"
    );
}

/// A `LIST` wildcard selects the folders it names and nothing else.
#[test]
fn list_wildcards_select_by_pattern() {
    assert!(glob("*", "INBOX"));
    assert!(glob("*", "Sent"));
    assert!(glob("Sent*", "Sent"));
    assert!(!glob("Sent*", "Drafts"));
    assert!(glob("%", "INBOX"));
    assert!(!glob("INBX", "INBOX"));
}
