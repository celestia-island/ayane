//! The IMAP listener: a real socket, a real TLS handshake, a real maildir.
//!
//! [`crate::imap_session`]'s tests drive the state machine as a table. This
//! file drives the driver — the layer that frames a client's octets, orders a
//! `STARTTLS` around them, and bounds what a stranger can make it hold — and
//! every assertion here is about bytes a client wrote and bytes it read back.
//!
//! The client is written by hand rather than taken from a crate so each test
//! reads as one fact about the wire: `a1 LOGIN …` in, `a1 OK …` out.

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

/// Accepts exactly one identity/password pair, and counts how often it was
/// asked — so "the password was never checked" is a fact, not an inference.
struct OnePassword {
    identity: &'static str,
    password: &'static str,
    asked: AtomicUsize,
}

impl OnePassword {
    fn new() -> Self {
        Self {
            identity: "alice@example.test",
            password: "correct horse",
            asked: AtomicUsize::new(0),
        }
    }
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

/// One mail root, removed when the test ends.
struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ayane-imap-listener-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// The same, with the message spelled out by the test.
    fn deliver_raw(&self, unique: &str, bytes: &[u8]) {
        let address = Address::parse("alice@example.test").expect("address");
        let dir = MaildirReader::new(self.path())
            .folder_dir(&address, INBOX, true)
            .expect("maildir");
        std::fs::write(
            dir.join("new").join(format!(
                "{}-{unique}.M{}.ayane-test",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_nanos()),
                std::process::id()
            )),
            bytes,
        )
        .expect("message");
    }

    /// A message in the account's INBOX, written the way a delivery lands.
    fn deliver(&self, subject: &str) {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let address = Address::parse("alice@example.test").expect("address");
        let dir = MaildirReader::new(self.path())
            .folder_dir(&address, INBOX, true)
            .expect("maildir");
        let name = format!(
            "{}.M{}.P{}.ayane-test",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos()),
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let bytes = format!(
            "From: bob@example.test\r\nTo: alice@example.test\r\nSubject: {subject}\r\n\
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

/// A running listener on a loopback port.
struct Listener {
    addr: std::net::SocketAddr,
    passwords: Arc<OnePassword>,
}

impl Listener {
    /// A listener with the test certificate (`implicit` = the IMAPS shape), or
    /// one with no certificate at all.
    async fn start(dir: &Path, implicit: bool) -> Self {
        Self::spawn(dir, Some(implicit), Duration::from_secs(20)).await
    }

    /// The startup both shapes share: bind, build the configuration, and serve
    /// it on a thread of its own.
    ///
    /// The listener runs on a **separate thread with its own runtime** rather
    /// than on the test's. That is not ceremony: a test's runtime is dropped
    /// when the test returns, and a `JoinHandle` dropped with it **cancels** the
    /// listener — a client that is still reading then sees the connection close
    /// mid-command instead of the reply it was waiting for. A listener in
    /// production lives as long as the process; here it lives as long as the
    /// test does.
    async fn spawn(dir: &Path, implicit: Option<bool>, timeout: Duration) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        let passwords = Arc::new(OnePassword::new());
        let config = Arc::new(ImapConfig {
            hostname: "mx.test".to_owned(),
            mail_root: dir.to_path_buf(),
            passwords: Arc::clone(&passwords) as Arc<dyn PasswordVerifier>,
            tls: implicit.map(|_| TlsAcceptor::from(Arc::new(support::test_tls_config()))),
            imap_tls: implicit.unwrap_or(false),
            per_ip_limit: 8,
            command_timeout: timeout,
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
        Self { addr, passwords }
    }

    /// A listener with no certificate: it can greet and it can never log in.
    async fn without_tls(dir: &Path) -> Self {
        Self::spawn(dir, None, Duration::from_secs(20)).await
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(self.addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("timeout");
        stream
    }
}

/// A client over whatever the test is talking on: plain TCP, or TLS over it.
enum Wire {
    Plain(TcpStream),
    /// An established rustls session and the socket under it.
    Tls(Box<rustls::ClientConnection>, TcpStream),
}

impl Wire {
    fn write_all(&mut self, bytes: &[u8]) {
        match self {
            Self::Plain(stream) => stream.write_all(bytes),
            Self::Tls(conn, stream) => {
                let mut tls = rustls::Stream::new(conn.as_mut(), stream);
                tls.write_all(bytes).and_then(|()| Write::flush(&mut tls))
            }
        }
        .expect("write");
    }

    fn read_some(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(conn, stream) => rustls::Stream::new(conn.as_mut(), stream).read(buf),
        }
    }

    /// Wraps the socket in TLS, after a `STARTTLS` was answered.
    fn upgrade(self) -> Self {
        let stream = match self {
            Self::Plain(stream) => stream,
            Self::Tls(..) => panic!("already inside TLS"),
        };
        Self::tls(stream)
    }

    fn tls(mut stream: TcpStream) -> Self {
        let name = ServerName::try_from("mx.test").expect("name").to_owned();
        let mut conn =
            rustls::ClientConnection::new(support::test_client_config(), name).expect("client");
        while conn.is_handshaking() {
            conn.complete_io(&mut stream).expect("handshake");
        }
        Self::Tls(Box::new(conn), stream)
    }
}

/// A line-oriented IMAP client.
struct Client {
    wire: Wire,
    buffer: Vec<u8>,
    /// The peer closed its side; no further reply can arrive.
    closed_at_eof: bool,
}

impl Client {
    fn plain(stream: TcpStream) -> Self {
        Self {
            wire: Wire::Plain(stream),
            buffer: Vec::new(),
            closed_at_eof: false,
        }
    }

    fn tls(stream: TcpStream) -> Self {
        Self {
            wire: Wire::tls(stream),
            buffer: Vec::new(),
            closed_at_eof: false,
        }
    }

    fn upgrade(mut self) -> Self {
        self.wire = self.wire.upgrade();
        self
    }

    /// One reply line, CRLF removed.
    fn line(&mut self) -> String {
        loop {
            if let Some(at) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                let line: Vec<u8> = self.buffer.drain(..at + 2).collect();
                return String::from_utf8_lossy(&line[..at]).into_owned();
            }
            if self.closed_at_eof {
                panic!("the server closed the connection while a reply was expected");
            }
            let mut chunk = [0u8; 4096];
            match self.wire.read_some(&mut chunk) {
                Ok(0) => {
                    // No more octets will arrive. If the buffer already holds
                    // complete lines they are still answers; a *later* read
                    // finds an empty buffer and knows there is nothing left.
                    self.closed_at_eof = true;
                    continue;
                }
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
                Err(err) => panic!("read failed: {err:?}"),
            }
        }
    }

    /// Every line until the tagged reply for `tag`.
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

    fn write(&mut self, bytes: &[u8]) {
        self.wire.write_all(bytes);
    }

    /// One command, and the tagged reply.
    fn say(&mut self, command: &str, tag: &str) -> Vec<String> {
        self.write(format!("{command}\r\n").as_bytes());
        self.until_tag(tag)
    }

    fn login(&mut self) {
        let reply = self.say("a1 LOGIN alice@example.test \"correct horse\"", "a1");
        assert!(reply[0].starts_with("a1 OK"), "{reply:?}");
    }
}

// ── the session over a socket ────────────────────────────────────────────

#[tokio::test]
async fn a_plain_client_is_refused_a_password_and_offered_starttls() {
    // The one property that must hold on an unencrypted port: the password is
    // never looked at. The greeting says so (`LOGINDISABLED`), the `LOGIN`
    // says so, and the verifier's counter proves nothing was asked to check it.
    let root = Root::new("plain");
    let listener = Listener::start(root.path(), false).await;
    let mut client = Client::plain(listener.connect());
    let greeting = client.line();
    assert!(greeting.starts_with("* OK"), "{greeting}");
    assert!(greeting.contains("STARTTLS"), "{greeting}");
    assert!(greeting.contains("LOGINDISABLED"), "{greeting}");

    let reply = client.say("a1 LOGIN alice@example.test \"correct horse\"", "a1");
    assert!(reply[0].starts_with("a1 NO"), "{reply:?}");
    assert!(reply[0].contains("PRIVACYREQUIRED"), "{reply:?}");
    assert_eq!(
        listener.passwords.asked.load(Ordering::SeqCst),
        0,
        "the password must not reach the verifier without TLS"
    );

    // A command that needs a mailbox is refused for the state it is in, not
    // for its spelling.
    let reply = client.say("a2 SELECT INBOX", "a2");
    assert!(reply[0].starts_with("a2 BAD"), "{reply:?}");
    assert!(reply[0].contains("before authentication"), "{reply:?}");

    let reply = client.say("a3 NOOP", "a3");
    assert_eq!(reply, vec!["a3 OK NOOP completed".to_owned()]);

    let reply = client.say("a4 LOGOUT", "a4");
    assert!(
        reply.iter().any(|line| line.starts_with("* BYE")),
        "{reply:?}"
    );
    assert!(
        reply.last().expect("tagged").starts_with("a4 OK"),
        "{reply:?}"
    );
}

#[tokio::test]
async fn starttls_upgrades_the_same_socket_and_then_logs_in() {
    let root = Root::new("starttls");
    root.deliver("hello");
    let listener = Listener::start(root.path(), false).await;
    let mut client = Client::plain(listener.connect());
    assert!(client.line().starts_with("* OK"));

    let reply = client.say("a1 STARTTLS", "a1");
    assert_eq!(reply, vec!["a1 OK Begin TLS negotiation now".to_owned()]);

    // Everything from here is inside TLS, on the same socket, and the server
    // had to stop reading at the `STARTTLS` line for that to be true.
    let mut client = client.upgrade();
    client.login();
    let reply = client.say("a2 SELECT INBOX", "a2");
    assert!(
        reply.iter().any(|line| line.starts_with("* 1 EXISTS")),
        "{reply:?}"
    );
    assert!(
        reply.last().expect("tagged").starts_with("a2 OK"),
        "{reply:?}"
    );
    assert_eq!(listener.passwords.asked.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_imaps_shape_greets_inside_tls_and_serves_the_whole_command_set() {
    // LOGIN → SELECT → FETCH → STORE → SEARCH → LOGOUT over a real handshake
    // and a real maildir — the same chain the Python `imaplib` end-to-end run
    // walks, asserted here so `cargo test` covers it without an interpreter.
    let root = Root::new("imaps");
    root.deliver("first");
    root.deliver("second");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    let greeting = client.line();
    assert!(greeting.starts_with("* OK"), "{greeting}");
    assert!(greeting.contains("AUTH=PLAIN"), "{greeting}");
    assert!(
        !greeting.contains("LOGINDISABLED") && !greeting.contains("STARTTLS"),
        "{greeting}"
    );

    client.login();
    let reply = client.say("a2 SELECT INBOX", "a2");
    assert!(
        reply.iter().any(|line| line.starts_with("* 2 EXISTS")),
        "{reply:?}"
    );

    let reply = client.say("a3 FETCH 1 (UID RFC822.SIZE BODY.PEEK[HEADER])", "a3");
    assert!(
        reply.iter().any(|line| line.starts_with("* 1 FETCH")),
        "{reply:?}"
    );
    assert!(
        reply.iter().any(|line| line.contains("Subject: first")),
        "{reply:?}"
    );

    let reply = client.say("a4 STORE 1 +FLAGS (\\Flagged)", "a4");
    assert!(
        reply.iter().any(|line| line.contains("\\Flagged")),
        "{reply:?}"
    );
    assert!(
        reply.last().expect("tagged").starts_with("a4 OK"),
        "{reply:?}"
    );

    let reply = client.say("a5 SEARCH FLAGGED", "a5");
    assert_eq!(reply[0], "* SEARCH 1", "{reply:?}");
    assert!(
        reply.last().expect("tagged").starts_with("a5 OK"),
        "{reply:?}"
    );

    let reply = client.say("a6 LOGOUT", "a6");
    assert!(
        reply.iter().any(|line| line.starts_with("* BYE")),
        "{reply:?}"
    );
    assert!(
        reply.last().expect("tagged").starts_with("a6 OK"),
        "{reply:?}"
    );
}

#[tokio::test]
async fn a_sync_literal_is_announced_with_a_continuation_before_its_octets() {
    // The literal arrives on one line and is answered with `+`; its octets
    // then contain a line that looks like a command. A reader that framed by
    // line would store the wrong bytes and then run `x9 NOOP` as a command.
    let root = Root::new("append");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    client.login();

    let payload = b"Subject: appended\r\n\r\nx9 NOOP\r\n";
    client.write(format!("a2 APPEND INBOX {{{}}}\r\n", payload.len()).as_bytes());
    let continuation = client.line();
    assert_eq!(
        continuation,
        format!("+ Ready for {} octets", payload.len())
    );
    client.write(payload);
    client.write(b"\r\n");
    let reply = client.until_tag("a2");
    assert!(
        reply.last().expect("tagged").starts_with("a2 OK"),
        "{reply:?}"
    );

    // The stored octets are exactly the literal, and the `x9 NOOP` inside them
    // was data rather than a command.
    let reply = client.say("a3 SELECT INBOX", "a3");
    assert!(
        reply.iter().any(|line| line.starts_with("* 1 EXISTS")),
        "{reply:?}"
    );
    assert!(
        reply.iter().any(|line| line.contains("UIDVALIDITY")),
        "{reply:?}"
    );
    let reply = client.say("a4 FETCH 1 BODY.PEEK[]", "a4");
    let text = reply.join("\r\n");
    assert!(text.contains("Subject: appended"), "{text}");
    assert!(text.contains("x9 NOOP"), "{text}");
    assert!(
        !text.contains("x9 OK"),
        "the literal's line was executed as a command: {text}"
    );
}

#[tokio::test]
async fn a_non_sync_literal_needs_no_continuation() {
    let root = Root::new("literal-plus");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    let greeting = client.line();
    assert!(greeting.contains("LITERAL+"), "{greeting}");
    client.login();

    let payload = b"Subject: plus\r\n\r\nbody\r\n";
    // `{n+}`: no `+` line comes back, and the octets follow immediately.
    client.write(format!("a2 APPEND INBOX {{{}+}}\r\n", payload.len()).as_bytes());
    client.write(payload);
    client.write(b"\r\n");
    let reply = client.until_tag("a2");
    assert_eq!(reply.len(), 1, "no continuation was expected: {reply:?}");
    assert!(reply[0].starts_with("a2 OK"), "{reply:?}");
}

#[tokio::test]
async fn a_second_login_is_refused_and_logout_ends_the_connection() {
    let root = Root::new("second-login");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    client.login();

    let reply = client.say("a2 LOGIN alice@example.test \"correct horse\"", "a2");
    assert!(reply[0].starts_with("a2 BAD"), "{reply:?}");
    assert!(
        reply[0].contains("not permitted after authentication"),
        "{reply:?}"
    );
    assert_eq!(
        listener.passwords.asked.load(Ordering::SeqCst),
        1,
        "the second LOGIN must not reach the verifier"
    );

    let reply = client.say("a3 LOGOUT", "a3");
    assert!(
        reply.iter().any(|line| line.starts_with("* BYE")),
        "{reply:?}"
    );
    // The server closes the socket. Under TLS that arrives as EOF-without-
    // `close_notify`, because the session is torn down rather than shut down
    // politely; either way nothing follows the tagged reply.
    let mut chunk = [0u8; 16];
    match client.wire.read_some(&mut chunk) {
        Ok(0) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
        other => panic!("expected the connection to end, got {other:?}"),
    }
}

#[tokio::test]
async fn a_credentials_never_open_another_account_mailbox() {
    // The session is built over the mailbox the credential opened, so a
    // password that is valid for one account cannot select another's.
    let root = Root::new("wrong-account");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    let reply = client.say("a1 LOGIN bob@example.test \"correct horse\"", "a1");
    assert!(reply[0].starts_with("a1 NO"), "{reply:?}");
    assert!(reply[0].contains("AUTHENTICATIONFAILED"), "{reply:?}");
    let reply = client.say("a2 SELECT INBOX", "a2");
    assert!(reply[0].starts_with("a2 BAD"), "{reply:?}");
}

#[tokio::test]
async fn a_listener_without_a_certificate_never_accepts_a_login() {
    let root = Root::new("no-tls");
    let listener = Listener::without_tls(root.path()).await;
    let mut client = Client::plain(listener.connect());
    let greeting = client.line();
    assert!(greeting.contains("LOGINDISABLED"), "{greeting}");
    assert!(!greeting.contains("STARTTLS"), "{greeting}");
    let reply = client.say("a1 LOGIN alice@example.test \"correct horse\"", "a1");
    assert!(reply[0].starts_with("a1 NO"), "{reply:?}");
    let reply = client.say("a2 STARTTLS", "a2");
    assert!(reply[0].starts_with("a2 BAD"), "{reply:?}");
    assert_eq!(listener.passwords.asked.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_fetch_literal_is_exactly_as_long_as_it_announces() {
    // RFC 3501 §4.3: a client reads `{n}` octets after the announcement's CRLF
    // and then the rest of the response. This test *is* that client — it reads
    // one octet at a time from the socket, counts `n` of them, and requires the
    // next octet to be the one that closes the item list.
    let root = Root::new("literal-length");
    let message = format!(
        "From: bob@example.test\r\nTo: alice@example.test\r\nSubject: {}\r\n\
         Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <literal@example.test>\r\n\r\n\
         {{not-a-literal}}\r\nbody\r\n",
        "x".repeat(80)
    );
    root.deliver_raw("literal-length", message.as_bytes());
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    client.login();
    let reply = client.say("a2 SELECT INBOX", "a2");
    assert!(
        reply.iter().any(|line| line.starts_with("* 1 EXISTS")),
        "{reply:?}"
    );

    // Over TLS, `imaplib`-style line buffering would eat the literal, so the
    // reply is read off the socket one octet at a time.
    client.wire.write_all(b"a3 FETCH 1 BODY.PEEK[]\r\n");
    let head = read_line_octetwise(&mut client.wire);
    let text = String::from_utf8_lossy(&head).into_owned();
    let open = text.rfind('{').expect("an announcement");
    let close = text.rfind('}').expect("the end of it");
    let announced: usize = text[open + 1..close].parse().expect("a count");
    assert_eq!(
        announced,
        message.len(),
        "`{{n}}` counts the message, not the announcement: {text}"
    );
    let literal = read_octets(&mut client.wire, announced);
    assert_eq!(
        literal,
        message.as_bytes(),
        "the octets that follow are the message, first octet to last"
    );
    // The very next octet is the one that closes the FETCH item list.
    let mut next = [0u8; 1];
    client.wire.read_some(&mut next).expect("the trailer");
    assert_eq!(next[0], b')', "the response resumes with `)`");
    let rest = read_line_octetwise(&mut client.wire);
    assert!(
        rest.starts_with(b"\r\n"),
        "and the item list's line ends there: {:?}",
        String::from_utf8_lossy(&rest)
    );
    let tagged = read_line_octetwise(&mut client.wire);
    assert!(
        tagged.starts_with(b"a3 OK"),
        "then the tagged reply: {:?}",
        String::from_utf8_lossy(&tagged)
    );
}

/// One CRLF-terminated line, octet by octet, CRLF included.
fn read_line_octetwise(wire: &mut Wire) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let mut octet = [0u8; 1];
        let read = wire.read_some(&mut octet).expect("a line arrives");
        assert!(read > 0, "the connection closed mid-line");
        line.push(octet[0]);
        if line.ends_with(b"\r\n") {
            return line;
        }
    }
}

/// Exactly `count` octets, octet by octet.
fn read_octets(wire: &mut Wire, count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut octet = [0u8; 1];
        let read = wire.read_some(&mut octet).expect("a literal octet arrives");
        assert!(read > 0, "the connection closed inside a literal");
        out.push(octet[0]);
    }
    out
}

#[tokio::test]
async fn a_command_that_is_not_imap_is_answered_with_its_own_tag_and_outlives_the_line() {
    // RFC 3501 §7.1: the tag is the client's, and the client matches replies
    // by it. A malformed command gets `BAD` and the connection stays usable.
    let root = Root::new("bad-command");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    client.login();
    let reply = client.say("x9 FROBNICATE everything", "x9");
    assert!(reply[0].starts_with("x9 BAD"), "{reply:?}");
    let reply = client.say("a2 NOOP", "a2");
    assert_eq!(reply, vec!["a2 OK NOOP completed".to_owned()]);
}

#[tokio::test]
async fn a_client_that_leaves_mid_literal_does_not_take_the_listener_down() {
    let root = Root::new("half-literal");
    let listener = Listener::start(root.path(), true).await;
    {
        let mut client = Client::tls(listener.connect());
        assert!(client.line().starts_with("* OK"));
        // Announces twenty octets, sends three, and goes away.
        client.write(b"a1 APPEND INBOX {20}\r\nabc");
    }
    // The listener is still serving.
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    client.login();
}

#[tokio::test]
async fn a_line_past_the_bound_is_refused_without_reading_the_rest() {
    let root = Root::new("long-line");
    let listener = Listener::start(root.path(), true).await;
    let mut client = Client::tls(listener.connect());
    assert!(client.line().starts_with("* OK"));
    client.login();
    let mut long = Vec::from("a1 NOOP ".as_bytes());
    long.extend(std::iter::repeat_n(
        b'x',
        ayane_smtpd::imap_session::MAX_LINE_BYTES + 64,
    ));
    long.extend_from_slice(b"\r\n");
    client.write(&long);
    // The reply is the tag plus `BAD` whatever the server thought of the rest
    // of the line — the assertion is about the tag, not the length.
    let reply = client.line();
    let reply = reply.chars().take(40).collect::<String>();
    assert!(
        reply.starts_with("a1 BAD") || reply.starts_with("* BAD"),
        "{reply}"
    );
}

#[tokio::test]
async fn an_idle_connection_is_closed_with_bye() {
    // The autologout timer is the only bound on a client that opens a socket
    // and says nothing, so it is exercised with a short one rather than
    // trusted to fire in thirty minutes.
    let root = Root::new("idle");
    let listener = Listener::spawn(root.path(), Some(true), Duration::from_millis(200)).await;
    let stream = TcpStream::connect(listener.addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    let mut client = Client::tls(stream);
    assert!(client.line().starts_with("* OK"));
    let line = client.line();
    assert!(line.starts_with("* BYE"), "{line}");
    assert!(line.contains("Autologout"), "{line}");
}
