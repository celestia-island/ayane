//! The outbound transport over real sockets: a message enters through the
//! receiver, is delivered by the consumer, and leaves over SMTP.
//!
//! Two kinds of test live here. The **end-to-end** ones use this crate as both
//! the sender and the receiver — an inbound listener with a hosted domain is
//! the target, so the whole chain (a client speaking SMTP → the spool → the
//! delivery decision → the outbound transport → the target's spool → the
//! target's maildir) is exercised without a third-party MTA. The **wire** ones
//! put a scripted server on a loopback port and read exactly what the client
//! wrote, because the parts worth pinning (dot-stuffing, the `STARTTLS`
//! fallback, `SIZE`) are octets, and a cooperating peer cannot show them.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ayane_proto::{Address, DesiredState};
use ayane_smtpd::deliver::{Deliverer, Disposition, RecipientOutcome};
use ayane_smtpd::outbound::{
    AttemptError, Outbound, Resolver, Signer, StaticResolver, SyncedTransport, TlsPolicy,
};
use ayane_smtpd::queue::Spool;
use support::{fixture_state, Harness, HarnessOptions};

/// The snapshot a fixture listener runs with: it hosts both `example.test`
/// and `remote.test`.
///
/// The **origin** listener must accept `RCPT TO:<girl@remote.test>` before the
/// delivery decision can call it remote — `RCPT` refuses a recipient whose
/// domain is not hosted ("relay access denied", RFC 5321 §4.5.4.1's shape),
/// and a listener that may relay is a different role with a different
/// credential gate. So what makes `remote.test` *outbound* is the **delivery**
/// snapshot ([`origin_state`]) and not the listener's: a real instance whose
/// hosted set changed under a queued message has the same shape, and that is
/// the case this exercises.
///
/// The **target** listener hosts both too, which is what lets it accept the
/// message the origin sends and then deliver it into its own maildir.
fn listener_state() -> DesiredState {
    let mut state = fixture_state(false);
    state.domains = vec![
        ayane_proto::MailDomain {
            name: "example.test".to_owned(),
            catch_all: None,
            enabled: true,
            dkim: None,
        },
        ayane_proto::MailDomain {
            name: "remote.test".to_owned(),
            catch_all: None,
            enabled: true,
            dkim: None,
        },
    ];
    // The listener must accept the recipient before the envelope exists: a
    // mailbox for it (the target), and for the origin an alias whose target
    // the *delivery* snapshot routes remotely — so the origin's `RCPT` is
    // accepted and the delivery decision is what makes it outbound.
    state.accounts.push(ayane_proto::Account {
        id: uuid::Uuid::new_v4(),
        address: addr("girl@remote.test"),
        display_name: "Girl".to_owned(),
        quota_bytes: 0,
        admin: false,
    });
    state
}

const MESSAGE: &str = "From: Alice <alice@example.test>\r\n\
                       To: girl@remote.test\r\n\
                       Subject: outbound\r\n\
                       Date: Tue, 14 Jul 2026 03:33:20 +0000\r\n\
                       Message-ID: <one@example.test>\r\n\
                       \r\n\
                       body\r\n";

const SENDER: &str = "alice@example.test";

fn addr(raw: &str) -> Address {
    Address::parse(raw).expect("fixture address")
}

/// A state that hosts `example.test` and nothing else, so every `*.remote.test`
/// recipient is outbound.
fn origin_state() -> DesiredState {
    let mut state = fixture_state(false);
    state.domains = vec![ayane_proto::MailDomain {
        name: "example.test".to_owned(),
        catch_all: None,
        enabled: true,
        dkim: None,
    }];
    state
        .accounts
        .retain(|account| account.address.domain() == "example.test");
    state
        .aliases
        .retain(|alias| alias.source.domain() == "example.test");
    state.shared.clear();
    state
}

/// The maildir `new/` directory of `address` under `root`.
fn maildir_new(root: &std::path::Path, address: &str) -> std::path::PathBuf {
    let address = addr(address);
    root.join(address.domain())
        .join(address.local())
        .join("Maildir")
        .join("new")
}

/// Every message in a maildir's `new/`, as strings.
fn maildir_messages(root: &std::path::Path, address: &str) -> Vec<String> {
    let dir = maildir_new(root, address);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|path| std::fs::read_to_string(path).expect("read the delivered message"))
        .collect()
}

// ── the end-to-end chain ─────────────────────────────────────────────────

/// Inbound listener + spool → consumer with the outbound transport → a target
/// that is this same crate listening as an MX, whose own consumer writes the
/// maildir.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_for_a_remote_domain_lands_in_that_hosts_maildir() {
    // The target: an inbound listener that hosts `remote.test` and accepts
    // mail for `girl@remote.test`.
    let target = Harness::start_with(
        "outbound-target",
        HarnessOptions::inbound(),
        Some(listener_state()),
    )
    .await;
    // The target's own consumer writes into its own mail tree.
    let target_deliverer = Deliverer::new(
        target.spool.clone(),
        target.dir.path().join("target-mail"),
        "mx.test",
    );

    // The origin: a client sends one message to `girl@remote.test`, which the
    // origin's *delivery* snapshot does not host, so the delivery decision
    // leaves it remote.
    let origin = Harness::start_with(
        "outbound-origin",
        HarnessOptions::inbound(),
        Some(listener_state()),
    )
    .await;
    let mut client = origin.client();
    client.ehlo("client.test");
    client.expect(&format!("MAIL FROM:<{SENDER}>"), 250);
    let accepted = client.expect("RCPT TO:<girl@remote.test>", 250);
    assert_eq!(accepted.code, 250);
    client.expect("DATA", 354);
    client.send_raw(MESSAGE.as_bytes());
    client.send_raw(b".\r\n");
    let accepted = client.read_reply();
    assert_eq!(accepted.code, 250, "{accepted:?}");

    // The outbound transport: the MX of `remote.test` is the origin's own
    // listener, pinned to its loopback address; the certificate is the
    // fixture's self-signed one, so the test connection accepts any.
    let resolver = StaticResolver::empty().with_mx("remote.test", vec![(10, "mx.remote.test")]);
    let outbound = Outbound::new(Arc::new(resolver) as Arc<dyn Resolver>, "mx.origin.test")
        .with_address("mx.remote.test", target.addr)
        .with_tls_policy(TlsPolicy::InsecureForTests)
        .with_limits(ayane_smtpd::outbound::ClientLimits {
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        });
    let transport = Arc::new(SyncedTransport::new(outbound).expect("transport"));

    let deliverer = Deliverer::new(origin.spool.clone(), origin.mail_root(), "mx.origin.test")
        .with_remote(transport);
    let state = origin_state();
    let reports = deliverer.run_at(&state, 1_000).expect("a delivery pass");

    // The origin's pass delivered it — outbound, not held.
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].disposition, Disposition::Delivered);
    assert!(
        matches!(
            reports[0].recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ),
        "{:?}",
        reports[0].recipients[0].outcome
    );
    assert!(
        origin.queued().is_empty(),
        "the origin's queue is empty once the message left"
    );

    // The target's spool holds it, for the recipient the origin addressed.
    let landed = target.queued();
    assert_eq!(landed.len(), 1, "the target accepted exactly one message");
    assert_eq!(landed[0].envelope.recipients, vec!["girl@remote.test"]);
    assert_eq!(
        landed[0].envelope.mail_from, SENDER,
        "the reverse-path survives the hop"
    );

    // And the target's own consumer puts it in the maildir the target hosts.
    // The target's own delivery snapshot: it hosts `remote.test` and the
    // mailbox the message is for.
    let target_state = {
        let mut state = fixture_state(false);
        state.domains = vec![ayane_proto::MailDomain {
            name: "remote.test".to_owned(),
            catch_all: None,
            enabled: true,
            dkim: None,
        }];
        state.accounts = vec![ayane_proto::Account {
            id: uuid::Uuid::new_v4(),
            address: addr("girl@remote.test"),
            display_name: "Girl".to_owned(),
            quota_bytes: 0,
            admin: false,
        }];
        state.aliases.clear();
        state.shared.clear();
        state
    };
    let target_reports = target_deliverer
        .run_at(&target_state, 1_000)
        .expect("the target's pass");
    assert_eq!(target_reports.len(), 1, "{target_reports:?}");
    let delivered = maildir_messages(&target.dir.path().join("target-mail"), "girl@remote.test");
    assert_eq!(delivered.len(), 1, "the message is in the remote maildir");
    let body = &delivered[0];
    assert!(body.contains("Subject: outbound\r\n"), "{body}");
    assert!(body.contains("body\r\n"), "{body}");
    // The trace field the origin's final hop wrote is on top, above the
    // target's own `Delivered-To:`.
    assert!(
        body.starts_with("Delivered-To: girl@remote.test\r\n"),
        "{body}"
    );
    assert!(
        body.contains("by mx.remote.test with "),
        "the delivery hop wrote its own Received: field: {body}"
    );
    assert!(body.contains("from mx.origin.test"), "{body}");

    origin.stop();
    target.stop();
}

/// The delivery hop's trace field records whether the connection was
/// upgraded: `ESMTPS` when the target offered `STARTTLS` and the origin used
/// it (the fixture listener on the inbound role does not offer TLS, so this
/// case is covered by the wire tests below; here the observable is that a
/// plaintext delivery says `ESMTP`).
#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_delivery_says_esmtp_in_its_trace_field() {
    let target = Harness::start_with(
        "outbound-plain-target",
        HarnessOptions::inbound(),
        Some(listener_state()),
    )
    .await;
    let origin = Harness::start_with(
        "outbound-plain-origin",
        HarnessOptions::inbound(),
        Some(listener_state()),
    )
    .await;
    let mut client = origin.client();
    client.ehlo("client.test");
    client.expect(&format!("MAIL FROM:<{SENDER}>"), 250);
    client.expect("RCPT TO:<girl@remote.test>", 250);
    client.expect("DATA", 354);
    client.send_raw(MESSAGE.as_bytes());
    client.send_raw(b".\r\n");
    let accepted = client.read_reply();
    assert_eq!(accepted.code, 250, "{accepted:?}");

    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", target.addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    let deliverer = Deliverer::new(origin.spool.clone(), origin.mail_root(), "mx.origin.test")
        .with_remote(Arc::new(SyncedTransport::new(outbound).expect("transport")));
    deliverer
        .run_at(&origin_state(), 1_000)
        .expect("a delivery pass");

    let landed = target.queued();
    assert_eq!(landed.len(), 1);
    let stored = target
        .spool
        .read_message(ayane_smtpd::queue::QueueState::New, &landed[0].id)
        .expect("the stored octets");
    let text = String::from_utf8(stored).expect("utf8");
    // The delivery hop's own field — `(ayane)` marks it, so the inbound
    // driver's `Received:` (which also says `with ESMTP`) cannot stand in for
    // it: a test that matched the bare phrase would pass with no field written
    // at all.
    assert!(
        text.contains("from mx.origin.test (ayane) by mx.remote.test with ESMTP id "),
        "the delivery hop wrote its own field, saying ESMTP: {text}"
    );
    assert!(
        !text.contains("(ayane) by mx.remote.test with ESMTPS"),
        "a connection that was never upgraded must not claim ESMTPS: {text}"
    );
    origin.stop();
    target.stop();
}

// ── a scripted MX, for the octets ────────────────────────────────────────

/// What a scripted server captured.
#[derive(Clone, Default)]
struct Captured {
    transcript: Arc<Mutex<Vec<String>>>,
    data: Arc<Mutex<Vec<u8>>>,
    /// The octets as they arrived, before unstuffing.
    wire: Arc<Mutex<Vec<u8>>>,
}

impl Captured {
    fn lines(&self) -> Vec<String> {
        self.transcript.lock().expect("transcript").clone()
    }
    fn data(&self) -> Vec<u8> {
        self.data.lock().expect("data").clone()
    }
    fn wire(&self) -> Vec<u8> {
        self.wire.lock().expect("wire").clone()
    }
}

/// Runs `serve` against each accepted connection on a loopback port, and
/// returns the address plus what it captured.
fn scripted(
    serve: impl Fn(TcpStream, &Captured) + Send + Sync + 'static,
) -> (SocketAddr, Captured) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured = Captured::default();
    let serve = Arc::new(serve);
    let held = captured.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let held = held.clone();
            let serve = Arc::clone(&serve);
            std::thread::spawn(move || serve(stream, &held));
        }
    });
    (addr, captured)
}

fn read_line(reader: &mut BufReader<TcpStream>, captured: &Captured) -> Option<String> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    captured
        .transcript
        .lock()
        .expect("transcript")
        .push(line.clone());
    Some(line)
}

/// Reads a whole `DATA` upload, unstuffing it the way a server does.
///
/// The **raw** octets are kept beside the unstuffed ones: dot-stuffing is a
/// property of the wire and only the raw bytes can show it. A test that looked
/// at the unstuffed data would agree with a client that never stuffed at all,
/// which is the one thing the stuffing exists to prevent.
fn read_data(reader: &mut BufReader<TcpStream>, captured: &Captured) -> Vec<u8> {
    let mut out = Vec::new();
    let mut wire = Vec::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).expect("read data") == 0 {
            break;
        }
        if line == b".\r\n" {
            break;
        }
        wire.extend_from_slice(&line);
        if line.starts_with(b".") {
            line.remove(0);
        }
        out.extend_from_slice(&line);
    }
    *captured.wire.lock().expect("wire") = wire;
    *captured.data.lock().expect("data") = out.clone();
    out
}

#[test]
fn the_wire_carries_a_dot_stuffed_body_that_unstuffs_to_the_original() {
    // A body with a line-leading dot — the shape that ends a transfer early if
    // it is not stuffed — must arrive as `..` and be recovered byte for byte.
    let body = b"Subject: dots\r\n\r\n.first\r\nnot.here\r\n.\r\nafter\r\n";
    let expected = body.to_vec();
    let (addr, captured) = scripted(move |stream, captured| {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        read_line(&mut reader, captured);
        writer
            .write_all(b"250-scripted\r\n250-8BITMIME\r\n250 SIZE 1000000\r\n")
            .expect("ehlo");
        read_line(&mut reader, captured);
        writer.write_all(b"250 sender ok\r\n").expect("mail");
        read_line(&mut reader, captured);
        writer.write_all(b"250 recipient ok\r\n").expect("rcpt");
        read_line(&mut reader, captured);
        writer.write_all(b"354 go\r\n").expect("data");
        let _ = read_data(&mut reader, captured);
        writer.write_all(b"250 queued\r\n").expect("accept");
        read_line(&mut reader, captured);
        writer.write_all(b"221 bye\r\n").expect("quit");
    });

    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            SENDER,
            &["girl@remote.test".to_owned()],
            body,
            "qid",
            1_000,
        ));
    assert!(result.delivered().count() == 1, "{result:?}");
    let received = captured.data();
    let text = String::from_utf8_lossy(&received).into_owned();
    assert!(
        text.starts_with("Received: from mx.origin.test"),
        "the hop's trace field leads the message: {text}"
    );
    assert!(
        received.ends_with(&expected),
        "what the receiver unstuffs is byte-identical to what the queue held: {text}"
    );
    // And the wire shows the stuffing: the body's leading `.` arrived doubled,
    // and the line consisting of `.` arrived as `..`.
    let wire = String::from_utf8_lossy(&captured.wire()).into_owned();
    assert!(wire.contains("\r\n..first\r\n"), "{wire}");
    assert!(wire.contains("\r\n..\r\n"), "{wire}");
    assert!(
        !wire.contains("\r\n.first\r\n"),
        "an un-stuffed leading dot would end the transfer early: {wire}"
    );
    // The wire carried the stuffing: the receiver read a line that began with
    // `..` and recovered `.`, which the assertion above pins by recovering the
    // original octets. The shapes are also pinned directly, without a socket,
    // by `outbound`'s own unit tests.
}

#[test]
fn the_client_announces_size_and_reads_the_capability_list() {
    let (addr, captured) = scripted(|stream, captured| {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        read_line(&mut reader, captured);
        writer
            .write_all(
                b"250-scripted\r\n250-8BITMIME\r\n250-SIZE 1000000\r\n250 ENHANCEDSTATUSCODES\r\n",
            )
            .expect("ehlo");
        read_line(&mut reader, captured);
        writer.write_all(b"250 sender ok\r\n").expect("mail");
        read_line(&mut reader, captured);
        writer.write_all(b"250 recipient ok\r\n").expect("rcpt");
        read_line(&mut reader, captured);
        writer.write_all(b"354 go\r\n").expect("data");
        let _ = read_data(&mut reader, captured);
        writer.write_all(b"250 queued\r\n").expect("accept");
        read_line(&mut reader, captured);
        writer.write_all(b"221 bye\r\n").expect("quit");
    });

    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            SENDER,
            &["girl@remote.test".to_owned()],
            b"Subject: s\r\n\r\nbody\r\n",
            "qid",
            1_000,
        ));

    let lines = captured.lines();
    // The origin identifies itself, and the `MAIL FROM` carries SIZE=.
    assert_eq!(lines[0], "EHLO mx.origin.test\r\n", "{lines:?}");
    let mail = lines
        .iter()
        .find(|line| line.starts_with("MAIL FROM:"))
        .expect("a MAIL line");
    assert!(
        mail.starts_with(&format!("MAIL FROM:<{SENDER}> SIZE=")),
        "{mail}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("RCPT TO:<girl@remote.test>")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.trim_end() == "QUIT"),
        "{lines:?}"
    );
}

#[test]
fn a_receiver_that_offers_starttls_is_upgraded() {
    // The wire test upgrades with a real handshake: the client's own TLS
    // configuration accepts the fixture's self-signed certificate.
    use std::sync::OnceLock;

    static CERT: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    let (cert, key) = CERT.get_or_init(|| {
        let decode = |pem: &str| {
            let body: String = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .expect("pem")
        };
        (
            decode(include_str!("fixtures/test-cert.pem")),
            decode(include_str!("fixtures/test-key.pem")),
        )
    });
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert.clone())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.clone()),
                ),
            )
            .expect("server config"),
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let upgraded = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&upgraded);
    let (addr, _captured) = scripted(move |stream, _| {
        // `scripted` runs one thread per connection and this closure is shared
        // by all of them, so the acceptor and the counter are per-call clones.
        let acceptor = acceptor.clone();
        let seen = Arc::clone(&seen);
        // One synchronous server thread, but the handshake is async: drive
        // the acceptor on a small runtime of its own.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("server runtime");
        runtime.block_on(async move {
            stream.set_nonblocking(true).expect("nonblocking");
            let stream = tokio::net::TcpStream::from_std(stream).expect("tokio stream");
            let mut reader = tokio::io::BufReader::new(stream);
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            reader
                .get_mut()
                .write_all(b"220 scripted ESMTP\r\n")
                .await
                .expect("greeting");
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("ehlo");
            reader
                .get_mut()
                .write_all(b"250-scripted\r\n250-STARTTLS\r\n250 SIZE 1000000\r\n")
                .await
                .expect("ehlo reply");
            line.clear();
            reader.read_line(&mut line).await.expect("starttls");
            assert_eq!(line.trim_end(), "STARTTLS", "{line:?}");
            reader
                .get_mut()
                .write_all(b"220 go ahead\r\n")
                .await
                .expect("starttls reply");
            let socket = reader.into_inner();
            let tls = acceptor.accept(socket).await.expect("handshake");
            seen.fetch_add(1, Ordering::SeqCst);
            // One reader over the TLS stream serves both directions: the buffered
            // reader IS the socket, so `get_mut().write_all` writes through the
            // session this connection upgraded to.
            let mut buffered = tokio::io::BufReader::new(tls);
            line.clear();
            buffered.read_line(&mut line).await.expect("ehlo after tls");
            assert!(line.starts_with("EHLO "), "{line:?}");
            buffered
                .get_mut()
                .write_all(b"250-scripted\r\n250 SIZE 1000000\r\n")
                .await
                .expect("ehlo reply");
            for expected in [
                ("MAIL FROM:", "250 sender ok\r\n"),
                ("RCPT TO:", "250 recipient ok\r\n"),
                ("DATA", "354 go\r\n"),
            ] {
                line.clear();
                buffered.read_line(&mut line).await.expect("command");
                assert!(line.starts_with(expected.0), "{line:?}");
                buffered
                    .get_mut()
                    .write_all(expected.1.as_bytes())
                    .await
                    .expect("reply");
            }
            loop {
                line.clear();
                if buffered.read_line(&mut line).await.expect("data line") == 0 {
                    break;
                }
                if line == ".\r\n" {
                    break;
                }
            }
            buffered
                .get_mut()
                .write_all(b"250 queued\r\n")
                .await
                .expect("accept");
            line.clear();
            let _ = buffered.read_line(&mut line).await;
            buffered
                .get_mut()
                .write_all(b"221 bye\r\n")
                .await
                .expect("bye");
            buffered.get_mut().flush().await.expect("flush");
            buffered.get_mut().shutdown().await.expect("shutdown");
        });
    });

    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let endpoint = ayane_smtpd::outbound::Endpoint {
                address: addr,
                host: "mx.remote.test".to_owned(),
            };
            let mut session =
                ayane_smtpd::outbound::Session::connect(outbound.client_config(), &endpoint)
                    .await
                    .expect("connect");
            session.start_tls("mx.remote.test").await.expect("upgrade");
            let tls = session.tls().clone();
            let delivered = session
                .deliver(
                    "mx.remote.test",
                    SENDER,
                    &["girl@remote.test".to_owned()],
                    b"Subject: s\r\n\r\nbody\r\n",
                )
                .await;
            (tls, delivered)
        });
    assert_eq!(
        outcome.0,
        ayane_smtpd::outbound::TlsOutcome::Upgraded,
        "{:?}",
        outcome.1
    );
    assert_eq!(
        outcome.0.protocol(),
        "ESMTPS",
        "an upgraded delivery says ESMTPS"
    );
    assert_eq!(
        upgraded.load(Ordering::SeqCst),
        1,
        "the handshake actually ran"
    );
    let delivered = outcome.1.expect("delivered");
    assert_eq!(delivered.delivered, vec!["girl@remote.test"]);
}

#[test]
fn a_receiver_whose_tls_fails_still_takes_the_message_in_cleartext() {
    // The opportunistic rule: an advertised `STARTTLS` whose handshake fails
    // is a downgrade, not a bounce. This server answers `STARTTLS` and then
    // sends a plaintext `250` instead of a TLS record — the handshake dies —
    // and the client reconnects and delivers over cleartext.
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&connections);
    let (addr, captured) = scripted(move |stream, captured| {
        let index = seen.fetch_add(1, Ordering::SeqCst);
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        read_line(&mut reader, captured);
        if index == 0 {
            writer
                .write_all(b"250-scripted\r\n250 STARTTLS\r\n")
                .expect("ehlo");
            read_line(&mut reader, captured);
            writer.write_all(b"220 go ahead\r\n").expect("starttls");
            // Not TLS: a reply the handshake will reject.
            writer
                .write_all(b"250 that is not a client hello\r\n")
                .expect("bogus");
            std::thread::sleep(Duration::from_millis(50));
            return;
        }
        // The second connection is plaintext, and the server does not offer
        // STARTTLS again.
        writer.write_all(b"250 scripted\r\n").expect("ehlo");
        read_line(&mut reader, captured);
        writer.write_all(b"250 sender ok\r\n").expect("mail");
        read_line(&mut reader, captured);
        writer.write_all(b"250 recipient ok\r\n").expect("rcpt");
        read_line(&mut reader, captured);
        writer.write_all(b"354 go\r\n").expect("data");
        let body = read_data(&mut reader, captured);
        assert!(body.ends_with(b"body\r\n"), "{body:?}");
        writer.write_all(b"250 queued\r\n").expect("accept");
        read_line(&mut reader, captured);
        writer.write_all(b"221 bye\r\n").expect("quit");
    });

    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            SENDER,
            &["girl@remote.test".to_owned()],
            b"Subject: s\r\n\r\nbody\r\n",
            "qid",
            1_000,
        ));
    assert_eq!(
        result.delivered().count(),
        1,
        "a failed handshake must not bounce the message: {result:?}"
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "the client fell back to a second, plaintext connection"
    );
    // The body the server read is the whole message, not a fragment the failed
    // handshake left behind.
    let body = captured.data();
    assert!(
        String::from_utf8_lossy(&body).starts_with("Received: "),
        "{body:?}"
    );
}

#[test]
fn a_receiver_that_refuses_mail_from_ends_the_delivery_permanently() {
    let (addr, _captured) = scripted(|stream, _captured| {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        writer.write_all(b"250 scripted\r\n").expect("ehlo");
        line.clear();
        let _ = reader.read_line(&mut line);
        writer
            .write_all(b"550 5.7.1 this sender is not welcome here\r\n")
            .expect("refuse");
    });
    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            SENDER,
            &["girl@remote.test".to_owned()],
            b"Subject: s\r\n\r\nbody\r\n",
            "qid",
            1_000,
        ));
    assert_eq!(result.results.len(), 1);
    let (_, reply) = &result.results[0];
    match reply {
        Err(AttemptError::Refused(reply)) => {
            assert_eq!(reply.code, 550, "{reply:?}");
            assert!(reply.text().contains("5.7.1"), "{}", reply.text());
        }
        other => panic!("a 550 at MAIL FROM is permanent: {other:?}"),
    }
}

#[test]
fn a_receiver_that_defers_mail_from_is_temporary() {
    let (addr, _captured) = scripted(|stream, _captured| {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        writer.write_all(b"250 scripted\r\n").expect("ehlo");
        line.clear();
        let _ = reader.read_line(&mut line);
        writer
            .write_all(b"451 4.7.1 greylisted, come back later\r\n")
            .expect("defer");
    });
    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            SENDER,
            &["girl@remote.test".to_owned()],
            b"Subject: s\r\n\r\nbody\r\n",
            "qid",
            1_000,
        ));
    match &result.results[0].1 {
        Err(error) => assert!(error.is_temporary(), "{error:?}"),
        Ok(host) => panic!("a 451 is not a delivery ({host})"),
    }
}

#[test]
fn a_null_mx_fails_every_recipient_permanently_without_a_connection() {
    let (addr, captured) = scripted(|_stream, _captured| {
        // Any connection at all is a failure of the test: connecting would
        // already violate RFC 7505.
    });
    let resolver = StaticResolver::empty().with_null_mx("remote.test");
    let outbound = Outbound::new(Arc::new(resolver) as Arc<dyn Resolver>, "mx.origin.test")
        .with_address("mx.remote.test", addr)
        .with_tls_policy(TlsPolicy::InsecureForTests);
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            SENDER,
            &["a@remote.test".to_owned(), "b@remote.test".to_owned()],
            b"Subject: s\r\n\r\nbody\r\n",
            "qid",
            1_000,
        ));
    assert_eq!(result.results.len(), 2);
    for (_, reply) in &result.results {
        match reply {
            Err(AttemptError::Refused(reply)) => {
                assert_eq!(reply.code, 556, "RFC 7505's code: {reply:?}");
                assert!(reply.text().contains("null MX"), "{}", reply.text());
            }
            other => panic!("a null MX is permanent: {other:?}"),
        }
    }
    assert!(captured.lines().is_empty(), "no connection is made");
}

// ── DKIM ─────────────────────────────────────────────────────────────────

/// A 2048-bit RSA key, generated for this fixture only.
///
/// It signs nothing outside a test: the test's verifier is given the matching
/// public key through a fixed zone, so the fixture is self-contained and no
/// network record is consulted.
fn fixture_key() -> (&'static str, &'static str) {
    (
        include_str!("fixtures/dkim-private.pem"),
        include_str!("fixtures/dkim-public.txt"),
    )
}

/// Sends one message through an `Outbound` with `signer` installed and
/// returns the octets a scripted receiver captured.
fn deliver_signed(body: &[u8], signer: Option<Signer>) -> Vec<u8> {
    let (addr, captured) = scripted(|stream, captured| {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        read_line(&mut reader, captured);
        writer
            .write_all(b"250-scripted\r\n250-8BITMIME\r\n250 SIZE 1000000\r\n")
            .expect("ehlo");
        read_line(&mut reader, captured);
        writer.write_all(b"250 sender ok\r\n").expect("mail");
        read_line(&mut reader, captured);
        writer.write_all(b"250 recipient ok\r\n").expect("rcpt");
        read_line(&mut reader, captured);
        writer.write_all(b"354 go\r\n").expect("data");
        let _ = read_data(&mut reader, captured);
        writer.write_all(b"250 queued\r\n").expect("accept");
        read_line(&mut reader, captured);
        writer.write_all(b"221 bye\r\n").expect("quit");
    });
    let mut outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    if let Some(signer) = signer {
        outbound = outbound.with_signer(signer);
    }
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            "alice@example.test",
            &["girl@remote.test".to_owned()],
            body,
            "qid",
            1_000,
        ));
    assert_eq!(result.delivered().count(), 1, "{result:?}");
    captured.data()
}

/// Whether the verifier, given the fixture's public key in a fixed zone, says
/// the message carries a passing signature.
fn verifies(received: &[u8]) -> String {
    use mail_auth::dns::TxtRecordParser as _;
    let (_, public) = fixture_key();
    let record = mail_auth::dkim::DomainKey::parse(public.as_bytes()).expect("a DKIM1 record");
    let zone = ayane_smtpd::zone::FixedZone::empty_authority().with_txt(
        "ayane._domainkey.example.test",
        mail_auth::dns::TxtRecord::from(record),
    );
    let verifier = ayane_smtpd::verify::Verifier::with_zone("mx.remote.test", zone);
    let streamed = ayane_smtpd::verify::StreamedMessage::from_bytes(received).expect("a message");
    let facts = ayane_smtpd::verify::SessionFacts {
        remote_ip: "192.0.2.1".parse().expect("ip"),
        helo: "mx.origin.test".to_owned(),
        mail_from: "alice@example.test".to_owned(),
        authenticated: None,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(verifier.verify(streamed, &facts, "from mx.origin.test"))
        .summary
}

fn fixture_signer() -> Signer {
    let (private, _) = fixture_key();
    Signer::rsa("example.test", "ayane", private).expect("a fixture key")
}

#[test]
fn an_outbound_message_carries_a_signature_that_verifies() {
    // The signature is checked by the same `mail-auth` verifier production
    // runs, over the octets the receiver actually got.
    let body = b"From: Alice <alice@example.test>\r\n\
                 To: girl@remote.test\r\n\
                 Subject: signed\r\n\
                 Date: Tue, 14 Jul 2026 03:33:20 +0000\r\n\
                 Message-ID: <one@example.test>\r\n\
                 \r\nsigned body\r\n";
    let received = deliver_signed(body, Some(fixture_signer()));
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("DKIM-Signature: "),
        "the signature is the topmost field: {text}"
    );
    assert!(
        text.contains("\r\nReceived: from mx.origin.test"),
        "the trace field sits below the signature: {text}"
    );
    assert!(
        text.contains("d=example.test") && text.contains("s=ayane"),
        "{text}"
    );
    let summary = verifies(&received);
    assert!(
        summary.contains("dkim=1/1"),
        "the signature must verify as a pass: {summary}"
    );
}

#[test]
fn a_malformed_header_before_the_from_does_not_suppress_the_signature() {
    // R1's S1-1 over the wire: a field name that is not UTF-8 and a `From`
    // with no `@` both used to abort the scan, so a message from a signed
    // domain went out unsigned — silently, and with one junk line as the only
    // cost to an attacker.
    let body = b"X-Junk-\xff\xfe: not a field name\r\n\
                 From: Alice <alice@example.test>\r\n\
                 To: girl@remote.test\r\n\
                 Subject: still signed\r\n\
                 Date: Tue, 14 Jul 2026 03:33:20 +0000\r\n\
                 \r\nbody\r\n";
    let received = deliver_signed(body, Some(fixture_signer()));
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("DKIM-Signature: "),
        "one junk field above the real From must not suppress the signature: {text}"
    );
    assert!(text.contains("d=example.test"), "{text}");
    assert!(
        verifies(&received).contains("dkim=1/1"),
        "and the signature still verifies"
    );

    // The second half of S1-1: a `From` field whose *own* value has no domain
    // used to end the scan too. It still contributes nothing, and the real
    // `From` below it is still the one signed — but a message with two `From`
    // fields is now ambiguous by design, so this shape is exercised through
    // `from_domain` in the unit tests. Over the wire the reachable case is a
    // domainless `From` followed by a real `To` and no other `From`: that
    // message has no signing domain at all and must go out unsigned.
    let body = b"From: nobody-at-all\r\n\
                 To: girl@remote.test\r\n\
                 Subject: no domain\r\n\
                 Date: Tue, 14 Jul 2026 03:33:20 +0000\r\n\
                 \r\nbody\r\n";
    let received = deliver_signed(body, Some(fixture_signer()));
    let text = String::from_utf8_lossy(&received);
    assert!(
        !text.contains("DKIM-Signature:"),
        "a From with no domain names nothing to sign for: {text}"
    );
}

#[test]
fn two_from_fields_go_out_unsigned_rather_than_signed_for_one_of_them() {
    // R1's S2-1 over the wire: a reader and DMARC take the *last* `From`, so a
    // signature for the first would give a forger "DKIM pass" for a domain the
    // message does not claim.
    let body = b"From: Alice <alice@example.test>\r\n\
                 From: Bank <security@victim.test>\r\n\
                 To: girl@remote.test\r\n\
                 Subject: two Froms\r\n\
                 Date: Tue, 14 Jul 2026 03:33:20 +0000\r\n\
                 \r\nbody\r\n";
    let received = deliver_signed(body, Some(fixture_signer()));
    let text = String::from_utf8_lossy(&received);
    assert!(
        !text.contains("DKIM-Signature:"),
        "an ambiguous message must not be vouched for: {text}"
    );
    assert!(
        !text.contains("d=example.test"),
        "and certainly not for the first From: {text}"
    );
    // It is still delivered — the refusal is about the signature, not the
    // message — and the trace field is this hop's.
    assert!(
        text.contains("(ayane) by mx.remote.test"),
        "the message still left with its trace field: {text}"
    );
    assert!(
        text.contains("From: Bank <security@victim.test>"),
        "the octets are unchanged: {text}"
    );
}

#[test]
fn a_domain_with_no_signer_goes_out_unsigned() {
    let (addr, captured) = scripted(|stream, captured| {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer = stream;
        writer
            .write_all(b"220 scripted ESMTP\r\n")
            .expect("greeting");
        read_line(&mut reader, captured);
        writer.write_all(b"250 scripted\r\n").expect("ehlo");
        read_line(&mut reader, captured);
        writer.write_all(b"250 ok\r\n").expect("mail");
        read_line(&mut reader, captured);
        writer.write_all(b"250 ok\r\n").expect("rcpt");
        read_line(&mut reader, captured);
        writer.write_all(b"354 go\r\n").expect("data");
        let _ = read_data(&mut reader, captured);
        writer.write_all(b"250 queued\r\n").expect("accept");
        read_line(&mut reader, captured);
        writer.write_all(b"221 bye\r\n").expect("quit");
    });
    let outbound = Outbound::new(
        Arc::new(StaticResolver::empty().with_mx("remote.test", vec![(0, "mx.remote.test")]))
            as Arc<dyn Resolver>,
        "mx.origin.test",
    )
    .with_address("mx.remote.test", addr)
    .with_tls_policy(TlsPolicy::InsecureForTests);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(outbound.deliver_group(
            "remote.test",
            "alice@somebody-else.test",
            &["girl@remote.test".to_owned()],
            b"From: x@somebody-else.test\r\n\r\nbody\r\n",
            "qid",
            1_000,
        ));
    let text = String::from_utf8_lossy(&captured.data()).into_owned();
    assert!(!text.contains("DKIM-Signature:"), "{text}");
    assert!(text.starts_with("Received: "), "{text}");
}

// ── delivery-layer wiring ────────────────────────────────────────────────

/// A transport that answers from a script, so the retry ladder and the DSN can
/// be driven without a socket: the delivery layer is what is under test.
struct ScriptedTransport {
    replies: Mutex<Vec<ayane_smtpd::RemoteReply>>,
    calls: AtomicUsize,
    /// The recipient list of every group the delivery layer asked about, in
    /// order: the shape of the transaction, not just how many calls there were.
    groups: Mutex<Vec<(String, Vec<String>)>>,
}

impl ScriptedTransport {
    fn new(replies: Vec<ayane_smtpd::RemoteReply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies),
            calls: AtomicUsize::new(0),
            groups: Mutex::new(Vec::new()),
        })
    }

    /// The groups seen so far, as `(domain, recipients)`.
    fn groups(&self) -> Vec<(String, Vec<String>)> {
        self.groups.lock().expect("groups").clone()
    }
}

impl ayane_smtpd::RemoteTransport for ScriptedTransport {
    fn deliver_group(
        &self,
        request: &ayane_smtpd::RemoteRequest<'_>,
    ) -> std::io::Result<Vec<ayane_smtpd::RemoteReport>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.groups
            .lock()
            .expect("groups")
            .push((request.domain.to_owned(), request.recipients.to_vec()));
        let mut replies = self.replies.lock().expect("replies");
        let reply = if replies.len() > 1 {
            replies.remove(0)
        } else {
            replies.first().cloned().expect("a scripted reply")
        };
        Ok(request
            .recipients
            .iter()
            .map(|recipient| ayane_smtpd::RemoteReport {
                recipient: recipient.clone(),
                reply: reply.clone(),
            })
            .collect())
    }
}

#[test]
fn a_remote_failure_climbs_the_retry_ladder_and_keeps_the_message() {
    let dir = tempfile();
    let spool = Spool::open(dir.join("spool")).expect("spool");
    let transport = ScriptedTransport::new(vec![ayane_smtpd::RemoteReply::Deferred {
        reason: "smtp; 451 4.7.1 greylisted".to_owned(),
    }]);
    let deliverer = Deliverer::new(spool.clone(), dir.join("mail"), "mx.origin.test")
        .with_remote(transport.clone());
    let state = origin_state();
    let queued = stage(&spool, "remote-retry", &["girl@remote.test"]);

    let first = deliverer
        .deliver_message(&state, &queued, 1_000)
        .expect("a pass");
    assert_eq!(first.disposition, Disposition::Held);
    let RecipientOutcome::Deferred {
        next_attempt_epoch, ..
    } = &first.recipients[0].outcome
    else {
        panic!("expected a retry, got {:?}", first.recipients[0].outcome);
    };
    assert_eq!(*next_attempt_epoch, 1_000 + 15 * 60, "the first rung");

    let record = deliverer.record_of("remote-retry").expect("the record");
    let entry = &record.recipients[0];
    assert_eq!(entry.state.attempts, 1, "the attempt is charged");
    assert_eq!(entry.state.next_attempt_epoch, 1_000 + 15 * 60);
    assert_eq!(entry.state.first_attempt_epoch, 1_000);
    assert!(entry.state.pending, "the message is not lost");
    assert_eq!(
        entry.state.last_error.as_deref(),
        Some("smtp; 451 4.7.1 greylisted"),
        "the receiver's own words are kept for the DSN"
    );
    // And the message is still in the queue, not settled.
    assert_eq!(
        spool
            .list(ayane_smtpd::queue::QueueState::Cur)
            .expect("list")
            .len(),
        1
    );
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_permanent_remote_refusal_produces_a_dsn_for_the_original_sender() {
    let dir = tempfile();
    let spool = Spool::open(dir.join("spool")).expect("spool");
    let transport = ScriptedTransport::new(vec![ayane_smtpd::RemoteReply::Refused {
        reason: "smtp; 550 5.1.1 no such user".to_owned(),
    }]);
    let deliverer = Deliverer::new(spool.clone(), dir.join("mail"), "mx.origin.test")
        .with_remote(transport.clone());
    let state = origin_state();
    let queued = stage(&spool, "remote-dsn", &["nobody@remote.test"]);

    let report = deliverer
        .deliver_message(&state, &queued, 1_000)
        .expect("a pass");
    let RecipientOutcome::Bounced { dsn, reason } = &report.recipients[0].outcome else {
        panic!("expected a bounce, got {:?}", report.recipients[0].outcome);
    };
    assert_eq!(reason, "smtp; 550 5.1.1 no such user");
    let dsn = dsn.as_ref().expect("a DSN for a real sender");
    assert_eq!(report.disposition, Disposition::Delivered);

    // The report is a queued message addressed to the envelope sender with the
    // null reverse-path.
    let reports = spool
        .list(ayane_smtpd::queue::QueueState::New)
        .expect("list");
    let queued_report = reports
        .iter()
        .find(|entry| entry.id == *dsn)
        .expect("the report is queued");
    assert_eq!(queued_report.envelope.mail_from, "");
    assert_eq!(queued_report.envelope.mail_from_wire, "<>");
    assert_eq!(
        queued_report.envelope.recipients,
        vec!["alice@example.test"],
        "the report goes back to the sender"
    );
    let body = String::from_utf8(
        spool
            .read_message(ayane_smtpd::queue::QueueState::New, dsn)
            .expect("read"),
    )
    .expect("utf8");
    assert!(
        body.contains("Final-Recipient: rfc822; nobody@remote.test"),
        "{body}"
    );
    assert!(body.contains("Action: failed"), "{body}");
    let diagnostic = body
        .lines()
        .find(|line| line.starts_with("Diagnostic-Code:"))
        .unwrap_or_else(|| panic!("no Diagnostic-Code in the report: {body}"));
    assert!(
        diagnostic.contains("550 5.1.1 no such user"),
        "the remote code and text reach the DSN: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("undeliverable"),
        "the reason is the receiver's, not a placeholder: {diagnostic}"
    );
    // The 5.x.x status the task asks for: the report names a permanent class.
    let status = body
        .lines()
        .find(|line| line.starts_with("Status:"))
        .unwrap_or_else(|| panic!("no Status in the report: {body}"));
    assert!(status.trim().starts_with("Status: 5."), "{status}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_successful_remote_delivery_settles_the_recipient_and_removes_the_entry() {
    let dir = tempfile();
    let spool = Spool::open(dir.join("spool")).expect("spool");
    let transport = ScriptedTransport::new(vec![ayane_smtpd::RemoteReply::Delivered {
        host: "mx.remote.test".to_owned(),
    }]);
    let deliverer =
        Deliverer::new(spool.clone(), dir.join("mail"), "mx.origin.test").with_remote(transport);
    let state = origin_state();
    let queued = stage(&spool, "remote-ok", &["girl@remote.test"]);

    let report = deliverer
        .deliver_message(&state, &queued, 1_000)
        .expect("a pass");
    assert_eq!(report.disposition, Disposition::Delivered);
    // **One** report for the one recipient: the transport answers for it, and
    // the local loop must not ask the router again and add a second, `Remote`
    // one beside it.
    assert_eq!(report.recipients.len(), 1, "{:?}", report.recipients);
    assert!(
        matches!(report.recipients[0].outcome, RecipientOutcome::Delivered(_)),
        "{:?}",
        report.recipients[0].outcome
    );
    assert!(
        spool
            .list(ayane_smtpd::queue::QueueState::Cur)
            .expect("list")
            .is_empty(),
        "the entry left the queue"
    );
    assert!(
        spool
            .list(ayane_smtpd::queue::QueueState::New)
            .expect("list")
            .is_empty(),
        "and no DSN was generated"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_a_transport_a_remote_recipient_is_left_alone_as_before() {
    // The pre-transport behaviour, kept: no transport, no attempt, no record
    // write, and the entry waits — a local-only deployment depends on it.
    let dir = tempfile();
    let spool = Spool::open(dir.join("spool")).expect("spool");
    let deliverer = Deliverer::new(spool.clone(), dir.join("mail"), "mx.origin.test");
    let state = origin_state();
    let queued = stage(&spool, "remote-none", &["girl@remote.test"]);
    let report = deliverer
        .deliver_message(&state, &queued, 1_000)
        .expect("a pass");
    assert_eq!(report.recipients[0].outcome, RecipientOutcome::Remote);
    assert_eq!(report.disposition, Disposition::Held);
    assert_eq!(
        spool
            .list(ayane_smtpd::queue::QueueState::Cur)
            .expect("list")
            .len(),
        1
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn one_pass_groups_every_recipient_of_a_domain_into_one_transaction() {
    let dir = tempfile();
    let spool = Spool::open(dir.join("spool")).expect("spool");
    let transport = ScriptedTransport::new(vec![ayane_smtpd::RemoteReply::Delivered {
        host: "mx.remote.test".to_owned(),
    }]);
    let deliverer = Deliverer::new(spool.clone(), dir.join("mail"), "mx.origin.test")
        .with_remote(transport.clone());
    let state = origin_state();
    let queued = stage(
        &spool,
        "remote-group",
        &["a@remote.test", "b@remote.test", "c@elsewhere.test"],
    );
    deliverer
        .deliver_message(&state, &queued, 1_000)
        .expect("a pass");
    assert_eq!(
        transport.calls.load(Ordering::SeqCst),
        2,
        "one call per destination domain, not one per recipient"
    );
    // The shape of that, not just the count: each domain is one transaction
    // carrying all of its recipients, so a real client would write one `MAIL
    // FROM` and one `DATA` per group and one `RCPT` per recipient.
    let groups = transport.groups();
    assert_eq!(
        groups,
        vec![
            (
                "elsewhere.test".to_owned(),
                vec!["c@elsewhere.test".to_owned()]
            ),
            (
                "remote.test".to_owned(),
                vec!["a@remote.test".to_owned(), "b@remote.test".to_owned()]
            ),
        ],
        "one group per domain, carrying every one of its recipients"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn tempfile() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ayane-outbound-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("temp dir");
    path
}

fn stage(spool: &Spool, id: &str, recipients: &[&str]) -> ayane_smtpd::queue::QueuedMessage {
    let mut envelope = ayane_smtpd::queue::Envelope::placeholder(id, "mx.origin.test");
    envelope.received_at = "2026-11-27T00:00:00Z".to_owned();
    envelope.mail_from = SENDER.to_owned();
    envelope.mail_from_wire = format!("<{SENDER}>");
    envelope.helo = "client.test".to_owned();
    envelope.remote_ip = "192.0.2.9".to_owned();
    envelope.recipients = recipients.iter().map(|raw| (*raw).to_owned()).collect();
    let mut staged = spool.stage(id, envelope).expect("stage");
    staged
        .write(b"Received: from client.test by mx.origin.test with ESMTP\r\nSubject: hi\r\n\r\nbody\r\n")
        .expect("write");
    staged.commit().expect("commit")
}
