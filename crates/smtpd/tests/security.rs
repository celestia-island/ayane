//! The security matrix over real sockets (MAP §四).
//!
//! Each test states the rule it exercises in its name so a failure reads as
//! "the open-relay test broke", not "protocol.rs line 214".

mod support;

use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::time::Duration;

use ayane_smtpd::ListenerRole;
use support::{deliver, Client, Harness, HarnessOptions};

const MESSAGE: &str =
    "From: <sender@example.net>\r\nTo: <inbox@example.com>\r\nSubject: matrix\r\n\r\nbody\r\n";

// ── T-B1: open relay ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb1_unauthenticated_remote_recipient_is_refused_at_rcpt() {
    let harness = Harness::start("tb1", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<x@example.net>", 250);
    let reply = client.command("RCPT TO:<y@gmail.com>");
    assert_eq!(reply.code, 550, "{reply:?}");
    assert!(
        reply.text.contains("5.7.1") && reply.text.contains("Relay access denied"),
        "{reply:?}"
    );
    // Refused at RCPT means DATA is unreachable: no backscatter can exist.
    assert_eq!(client.command("DATA").code, 503);
    // The local domain is accepted in the same transaction.
    client.expect("RCPT TO:<inbox@example.com>", 250);
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb1_relay_target_shapes_never_fall_through() {
    let harness = Harness::start("tb1-shapes", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<x@example.net>", 250);
    // A domain literal is refused by the path syntax itself: this server
    // never accepts one, so it can never be relayed to either.
    for recipient in ["user@[192.0.2.1]", "user@[IPv6:2001:db8::1]"] {
        let reply = client.command(&format!("RCPT TO:<{recipient}>"));
        assert_eq!(reply.code, 501, "{recipient} answered {reply:?}");
    }
    // A remote or merely sub-domain recipient is a relay attempt: 550 5.7.1.
    for recipient in [
        "user@gmail.com",
        "user@example.net",
        "user@sub.example.com",
        "user@192.0.2.1", // a dotted quad is a domain, and not a hosted one
    ] {
        let reply = client.command(&format!("RCPT TO:<{recipient}>"));
        assert_eq!(reply.code, 550, "{recipient} answered {reply:?}");
        assert!(reply.text.contains("5.7.1"), "{reply:?}");
    }
    // Over-long local part and malformed domains are syntax, not relay.
    for recipient in [
        format!("{}@example.com", "a".repeat(70)),
        "user@exa mple.com".to_owned(),
        "user@-example.com".to_owned(),
        "user@example..com".to_owned(),
    ] {
        let reply = client.command(&format!("RCPT TO:<{recipient}>"));
        assert!(
            (400..600).contains(&reply.code) && reply.code != 250,
            "{recipient} answered {reply:?}"
        );
    }
    assert!(harness.queued().is_empty());
    harness.stop();
}

// ── T-B3 / T-B4: catch-all is a destination, not existence ──────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb3_unknown_recipient_is_refused_at_rcpt_without_catch_all() {
    let harness = Harness::start("tb3", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<x@example.net>", 250);
    let reply = client.command("RCPT TO:<nobody@example.com>");
    assert_eq!(reply.code, 550, "{reply:?}");
    assert_eq!(client.command("DATA").code, 503);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb4_catch_all_does_not_accept_a_random_address() {
    for catch_all in [false, true] {
        let options = HarnessOptions {
            catch_all,
            ..HarnessOptions::inbound()
        };
        let harness = Harness::start("tb4", options).await;
        let mut client = harness.client();
        client.ehlo("client.test");
        client.expect("MAIL FROM:<x@example.net>", 250);
        let reply = client.command("RCPT TO:<random-3f9a2c@example.com>");
        assert_eq!(
            reply.code, 550,
            "catch_all={catch_all}: a catch-all mailbox is not an existence proof: {reply:?}"
        );
        // And the named mailboxes are accepted either way.
        client.expect("RCPT TO:<inbox@example.com>", 250);
        assert!(harness.queued().is_empty());
        drop(client);
        harness.stop();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tb4_alias_and_shared_mailboxes_exist() {
    let harness = Harness::start("tb4-tables", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<x@example.net>", 250);
    client.expect("RCPT TO:<sales@example.com>", 250);
    client.expect("RCPT TO:<team@example.com>", 250);
    let reply = deliver_rest(&mut client);
    assert_eq!(reply.code, 250, "{reply:?}");
    let queued = harness.queued();
    assert_eq!(
        queued[0].envelope.recipients,
        vec!["sales@example.com", "team@example.com"]
    );
    harness.stop();
}

fn deliver_rest(client: &mut Client) -> support::Reply {
    client.expect("DATA", 354);
    let mut body = String::new();
    for line in MESSAGE.split_inclusive("\r\n") {
        body.push_str(line.trim_end_matches("\r\n"));
        body.push_str("\r\n");
    }
    body = body.trim_end_matches("\r\n").to_owned();
    body.push_str("\r\n.\r\n");
    client.send_raw(body.as_bytes());
    client.read_reply()
}

// ── T-B6: STARTTLS injection ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb6_starttls_pipeline_injection_cannot_enter_a_transaction() {
    let harness = Harness::start("tb6", HarnessOptions::submission()).await;
    let mut stream = std::net::TcpStream::connect(harness.addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    // Greeting.
    let greeting = read_line(&mut stream);
    assert!(greeting.starts_with("220"), "{greeting:?}");
    // EHLO, then — in ONE write — STARTTLS and a whole transaction.
    stream
        .write_all(b"EHLO client.test\r\nSTARTTLS\r\nMAIL FROM:<a@example.net>\r\nRCPT TO:<inbox@example.com>\r\nDATA\r\n")
        .expect("write");
    let ehlo = read_reply_from(&mut stream);
    assert!(ehlo.0, "EHLO: {ehlo:?}");
    let ready = read_line(&mut stream);
    assert!(ready.starts_with("220"), "STARTTLS reply: {ready:?}");

    // From here the connection is TLS: everything after 220 was discarded, so
    // the injected MAIL/RCPT/DATA must be gone (not executed, not buffered).
    let tls = rustls::ClientConnection::new(
        support::test_client_config(),
        rustls::pki_types::ServerName::try_from("mx.test").expect("name"),
    )
    .expect("client connection");
    let mut conn = rustls::StreamOwned::new(tls, stream);
    conn.flush().expect("flush");
    // The handshake completes because the server dropped the plaintext bytes.
    conn.write_all(b"EHLO client.test\r\n").expect("ehlo");
    conn.flush().expect("flush");
    let (ok, first) = read_reply_tls(&mut conn);
    assert!(ok, "TLS session must be usable: {first:?}");
    // The session forgot everything: DATA cannot start a transaction.
    conn.write_all(b"DATA\r\n").expect("data");
    conn.flush().expect("flush");
    let line = read_line_tls(&mut conn);
    assert!(
        line.starts_with("503"),
        "DATA after an injected STARTTLS: {line:?}"
    );
    conn.write_all(b"QUIT\r\n").expect("quit");
    conn.flush().expect("flush");
    harness.stop();
}

fn read_line(stream: &mut std::net::TcpStream) -> String {
    let mut byte = [0u8; 1];
    let mut line = String::new();
    loop {
        let read = stream.read(&mut byte).expect("read");
        assert!(read > 0, "connection closed");
        line.push(byte[0] as char);
        if line.ends_with("\r\n") {
            return line.trim_end().to_owned();
        }
    }
}

fn read_reply_from(stream: &mut std::net::TcpStream) -> (bool, String) {
    loop {
        let line = read_line(stream);
        if !line.starts_with("250-") {
            return (line.starts_with("250"), line);
        }
    }
}

fn read_reply_tls(
    conn: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
) -> (bool, String) {
    loop {
        let line = read_line_tls(conn);
        if !line.starts_with("250-") {
            return (line.starts_with("250"), line);
        }
    }
}

fn read_line_tls(
    conn: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
) -> String {
    let mut byte = [0u8; 1];
    let mut line = String::new();
    loop {
        conn.read_exact(&mut byte).expect("read tls");
        line.push(byte[0] as char);
        if line.ends_with("\r\n") {
            return line.trim_end().to_owned();
        }
    }
}

// ── STARTTLS / AUTH on the submission listener ──────────────────────────

async fn tls_client(harness: &Harness) -> support::TlsClient {
    support::TlsClient::connect(harness.addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_auth_plain_then_relays_with_its_own_sender() {
    let harness = Harness::start("auth-plain", HarnessOptions::submission()).await;
    let mut client = tls_client(&harness).await;
    let ehlo = client.ehlo("client.test");
    assert!(ehlo.advertises("STARTTLS"), "{ehlo:?}");
    client.expect("STARTTLS", 220);
    client.handshake();
    let ehlo = client.ehlo("client.test");
    assert!(ehlo.advertises_prefix("AUTH PLAIN LOGIN"), "{ehlo:?}");
    let credential = base64_plain("ops@example.com", "s3cret");
    client.expect(&format!("AUTH PLAIN {credential}"), 235);
    client.expect("MAIL FROM:<ops@example.com>", 250);
    client.expect("RCPT TO:<someone@gmail.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"Subject: submitted\r\n\r\nbody\r\n.\r\n");
    let reply = client.read_reply();
    assert_eq!(reply.code, 250, "{reply:?}");
    let queued = harness.queued();
    assert_eq!(queued[0].envelope.recipients, vec!["someone@gmail.com"]);
    assert_eq!(
        queued[0].envelope.authenticated.as_deref(),
        Some("ops@example.com")
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_auth_login_works_and_wrong_password_is_535() {
    let harness = Harness::start("auth-login", HarnessOptions::submission()).await;
    let mut client = tls_client(&harness).await;
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    let challenge = client.expect("AUTH LOGIN", 334);
    assert_eq!(challenge.text, "VXNlcm5hbWU6");
    let challenge = client.expect(&base64("ops@example.com"), 334);
    assert_eq!(challenge.text, "UGFzc3dvcmQ6");
    client.expect(&base64("s3cret"), 235);

    let mut client = tls_client(&harness).await;
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "wrong")),
        535,
    );

    let mut client = tls_client(&harness).await;
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!(
            "AUTH PLAIN {}",
            base64_plain("nobody@example.com", "s3cret")
        ),
        535,
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_never_accepts_credentials_on_a_clear_channel() {
    let harness = Harness::start("auth-clear", HarnessOptions::submission()).await;
    let mut client = harness.client();
    let ehlo = client.ehlo("client.test");
    assert!(
        !ehlo.advertises_prefix("AUTH"),
        "AUTH must not be advertised before TLS: {ehlo:?}"
    );
    let reply = client.command(&format!(
        "AUTH PLAIN {}",
        base64_plain("ops@example.com", "s3cret")
    ));
    assert_eq!(reply.code, 538, "clear-text AUTH: {reply:?}");
    // The rejected attempt leaves no identity behind, so the submission is
    // refused — at `RCPT`, with the code that says "authenticate first".
    client.expect("MAIL FROM:<ops@example.com>", 250);
    assert_eq!(client.command("RCPT TO:<someone@gmail.com>").code, 530);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn submission_refuses_a_sender_bound_to_another_identity() {
    let harness = Harness::start("auth-binding", HarnessOptions::submission()).await;
    let mut client = tls_client(&harness).await;
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "s3cret")),
        235,
    );
    // Authenticated as ops, submitting as somebody else's mailbox.
    client.expect("MAIL FROM:<inbox@example.com>", 250);
    assert_eq!(client.command("RCPT TO:<someone@gmail.com>").code, 553);
    // And as an external address.
    client.expect("RSET", 250);
    client.expect("MAIL FROM:<forged@example.net>", 250);
    assert_eq!(client.command("RCPT TO:<someone@gmail.com>").code, 553);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_attempts_are_bounded() {
    let mut options = HarnessOptions::submission();
    options.limits.max_auth_attempts = 2;
    let harness = Harness::start("auth-limit", options).await;
    let mut client = tls_client(&harness).await;
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "bad1")),
        535,
    );
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "bad2")),
        535,
    );
    let reply = client.command(&format!(
        "AUTH PLAIN {}",
        base64_plain("ops@example.com", "s3cret")
    ));
    assert_eq!(reply.code, 421, "the third attempt must close: {reply:?}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn port_25_has_no_auth_at_all() {
    let harness = Harness::start("noauth-25", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = client.ehlo("client.test");
    assert!(!reply.advertises_prefix("AUTH"), "{reply:?}");
    assert_eq!(
        client
            .command(&format!(
                "AUTH PLAIN {}",
                base64_plain("ops@example.com", "s3cret")
            ))
            .code,
        502
    );
    harness.stop();
}

// ── T-B10: null sender ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb10_null_sender_is_accepted_and_creates_no_outbound_work() {
    let harness = Harness::start("tb10", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<>", 250);
    // An unknown recipient is still a 550 — and nothing is generated for it.
    let reply = client.command("RCPT TO:<nobody@example.com>");
    assert_eq!(reply.code, 550, "{reply:?}");
    client.expect("RCPT TO:<inbox@example.com>", 250);
    let reply = deliver_rest(&mut client);
    assert_eq!(reply.code, 250, "{reply:?}");
    let queued = harness.queued();
    assert_eq!(queued[0].envelope.mail_from, "");
    assert_eq!(queued[0].envelope.mail_from_wire, "<>");
    // W1 has no delivery and no DSN: the null sender's failure left no trace
    // beyond the 550 it already got (no queue entry, no second connection).
    assert_eq!(queued.len(), 1);
    harness.stop();
}

// ── T-B13 / T-B14: resource bounds ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb13_size_over_the_limit_is_refused_before_data() {
    let mut options = HarnessOptions::inbound();
    options.max_message_size = 64 * 1024;
    let harness = Harness::start("tb13", options).await;
    let mut client = harness.client();
    let ehlo = client.ehlo("client.test");
    assert!(ehlo.advertises("SIZE 65536"), "{ehlo:?}");
    let reply = client.command("MAIL FROM:<a@example.net> SIZE=65537");
    assert_eq!(reply.code, 552, "{reply:?}");
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb14_a_dripping_data_transfer_times_out() {
    // The RFC transaction timer is ten minutes; this test shortens it so the
    // behaviour (421 then close) is observable in a unit-test run.
    let mut options = HarnessOptions::inbound();
    options.transaction_timeout = Duration::from_millis(600);
    let harness = Harness::start("tb14", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    // One byte per second: never a terminator, never a full line.
    for _ in 0..3 {
        client.send_raw(b"x");
        std::thread::sleep(Duration::from_millis(200));
    }
    let reply = client.read_reply();
    assert_eq!(reply.code, 421, "slow drip: {reply:?}");
    assert!(
        harness.queued().is_empty(),
        "a timed-out body is not spooled"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb14_a_silent_command_wait_times_out() {
    let mut options = HarnessOptions::inbound();
    options.command_timeout = Duration::from_millis(400);
    let harness = Harness::start("tb14-idle", options).await;
    let mut client = harness.client();
    // Say nothing: the command timer must answer 421 and close.
    let reply = client.read_reply();
    assert_eq!(reply.code, 421, "{reply:?}");
    let rest = client.read_to_end();
    assert!(rest.is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb14_body_over_the_message_limit_fails_the_transaction() {
    let mut options = HarnessOptions::inbound();
    options.max_message_size = 4096;
    options.limits.max_message_size = 4096;
    // A client that keeps sending past a refusal must not keep the server
    // waiting: the transfer timer bounds it (here shortened for the test).
    options.transaction_timeout = Duration::from_millis(1500);
    let harness = Harness::start("tb14-cap", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    let line = format!("{}\r\n", "a".repeat(1000));
    let mut body = String::from("Subject: big\r\n\r\n");
    for _ in 0..8 {
        body.push_str(&line);
    }
    body.push_str(".\r\n");
    client.send_raw_best_effort(body.as_bytes());
    let reply = client
        .try_read_reply()
        .expect("the server answers the refused transfer");
    assert!(
        matches!(reply.code, 554 | 421),
        "an over-cap transfer is failed (554) or cut off by the timer (421), got {reply:?}"
    );
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb14_over_long_data_line_fails_without_desync() {
    // The refused transfer is drained up to its terminator; a client that
    // stops sending after the refusal is cut off by the drain's own short
    // bound, which is what keeps this test from waiting on the transaction
    // timer.
    let options = HarnessOptions {
        transaction_timeout: Duration::from_millis(1500),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("tb14-line", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    // A 70 KiB line is past the body line bound; the server must drain to the
    // terminator and answer rather than treat the noise as commands.
    let long = format!("{}\r\n", "b".repeat(70 * 1024));
    // The rest of the "envelope" is inside the failed transfer: it is drained
    // with the body, never executed.
    client.send_raw_best_effort(long.as_bytes());
    client.send_raw_best_effort(b"MAIL FROM:<evil@example.net>\r\n.\r\n");
    let reply = client
        .try_read_reply()
        .expect("the refused transfer is answered");
    // `552 5.2.3` — RFC 5321 §4.3.2's "line too long" — and not the
    // transaction's `554`: a line over a resource bound is a request the client
    // can fix by re-wrapping it, which is what the code tells it. `BDAT` answers
    // the same octets the same way (`header_bound::the_line_bound_is_one_answer`).
    assert_eq!(
        (reply.code, reply.text.as_str()),
        (552, "5.2.3 Message line too long"),
        "an over-long body line fails the transfer: {reply:?}"
    );
    assert!(harness.queued().is_empty());
    // The same `MAIL FROM` that was in the tail is answered `503`, not run:
    // the connection will not open an envelope while it is still discarding the
    // refused upload, because it cannot tell that command from the forged one
    // right next to it.
    //
    // What must hold either way is the sentence this test is named for: nothing
    // in the tail was executed. The connection must never answer a step of the
    // forged transaction — never a `250`, and never a `354` that would let the
    // second message in.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let probe = client.try_read_reply_within(Duration::from_millis(200));
        assert!(
            probe.is_none() || probe.as_ref().is_some_and(|r| r.code == 503),
            "nothing in the tail is accepted: {probe:?}"
        );
        if probe.is_none() {
            break;
        }
    }
    assert!(harness.queued().is_empty(), "still nothing queued");
    harness.stop();
}

// ── T-B15: SMTP smuggling ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb15_bare_lf_smuggling_produces_no_second_envelope() {
    // The client stops mid-transfer on purpose, which a server bounds by its
    // transaction timer; shortened here so the test stays quick.
    let options = HarnessOptions {
        transaction_timeout: Duration::from_millis(1500),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("tb15", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    // The classic CVE-2023-51764 shape: a body, then a bare-LF `.`, then a
    // forged envelope. A server that reads LF as a line break sees two
    // messages and relays the second — and because a bare-LF line is not the
    // real terminator, the server then waits for one. The forged lines were
    // never commands, so they cannot be smuggled into a second envelope.
    client.send_raw(
        b"Subject: smuggle\r\n\r\nfirst\r\n\n.\nMAIL FROM:<evil@example.net>\r\nRCPT TO:<someone@gmail.com>\r\nDATA\r\nsecond\r\n.\r\n",
    );
    // A bare LF is data, not the end of the transfer: the server fails the
    // transaction. The reply is `554 5.6.0 Transaction failed` either way —
    // measured — but *when* it arrives depends on the drain a failed transfer
    // runs first: with a `.<CRLF>` somewhere ahead in this wire the drain ends
    // there and the answer is immediate (about a millisecond), and with nothing
    // the client ever means as a terminator the answer waits for the drain to
    // give up at the transaction timer (here 1.5 s). Both are the same refusal;
    // the code is neither `421` (the connection is not closed) nor a second
    // answer to an answered command.
    if let Some(reply) = client.try_read_reply() {
        assert_eq!(
            (reply.code, reply.text.as_str()),
            (554, "5.6.0 Transaction failed"),
            "a bare LF must fail the transfer: {reply:?}"
        );
    }
    // Exactly zero messages, and certainly no relayed envelope.
    assert!(
        harness.queued().is_empty(),
        "smuggled envelope: {:?}",
        harness
            .queued()
            .iter()
            .map(|m| m.envelope.clone())
            .collect::<Vec<_>>()
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb15_dot_stuffing_is_undone_exactly() {
    let harness = Harness::start("tb15-dots", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"Subject: dots\r\n\r\n..leading dot\r\n...two\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);
    let stored = String::from_utf8_lossy(&harness.only_message()).to_string();
    assert!(
        stored.contains("\r\n.leading dot\r\n..two\r\n"),
        "dot-stuffing must be undone one dot per line: {stored}"
    );
    harness.stop();
}

// ── T-B19: mail loops ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tb19_received_headers_over_the_loop_bound_are_refused() {
    let harness = Harness::start("tb19", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    let mut body = String::from("From: <a@example.net>\r\nSubject: loop\r\n");
    for index in 0..30 {
        body.push_str(&format!("Received: from loop{index} by mx.test\r\n"));
    }
    body.push_str("\r\nbody\r\n.\r\n");
    client.send_raw(body.as_bytes());
    let reply = client.read_reply();
    assert_eq!(reply.code, 554, "a loop is refused, not queued: {reply:?}");
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn tb19_a_reasonable_return_path_is_accepted() {
    let harness = Harness::start("tb19-ok", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    deliver(&mut client, "a@example.net", "inbox@example.com", MESSAGE);
    assert_eq!(harness.queued().len(), 1);
    harness.stop();
}

// ── BDAT bounds ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn bdat_chunks_cannot_exceed_the_message_limit() {
    let mut options = HarnessOptions {
        transaction_timeout: Duration::from_millis(1500),
        ..HarnessOptions::inbound()
    };
    options.max_message_size = 2048;
    options.limits.max_message_size = 2048;
    let harness = Harness::start("bdat-cap", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.pending(&vec![b'a'; 1024]);
    let ack = client.command("BDAT 1024");
    assert_eq!(ack.code, 250, "the first chunk: {ack:?}");
    // The second chunk's octets never get sent: the refusal comes first, and
    // a client that keeps silent after it is closed by the transaction timer
    // (421) rather than answered twice.
    let reply = client.command("BDAT 1024 LAST");
    assert!(
        matches!(reply.code, 552 | 421),
        "the second chunk would pass 2048: {reply:?}"
    );
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_starttls_handshake_closes_the_socket() {
    // The handshake consumes the stream, and the server used to be left
    // holding an empty one: `shutdown` then reached nothing and the client
    // waited for a FIN that never came. The connection must be closed, and
    // quickly — the command timer is five minutes.
    let options = HarnessOptions {
        command_timeout: Duration::from_secs(300),
        ..HarnessOptions::submission()
    };
    let harness = Harness::start("tls-fail", options).await;
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    // Anything that is not a ClientHello: the server's rustls sees a
    // handshake record it cannot parse and drops the connection.
    client.send_raw(b"this is not a TLS handshake\r\n");
    let started = std::time::Instant::now();
    let remainder = client.read_to_eof_within(Duration::from_secs(10));
    let elapsed = started.elapsed();
    assert!(
        remainder.is_some(),
        "the server must close the socket after a failed handshake"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the close is a FIN, not a timeout: took {elapsed:?}"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_role_without_tls_cannot_start_one() {
    let harness = Harness::start("no-tls", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    assert_eq!(client.command("STARTTLS").code, 454);
    assert_eq!(HarnessOptions::inbound().role, ListenerRole::Inbound);
    harness.stop();
}

fn base64(text: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

/// An `AUTH PLAIN` initial response: `NUL authcid NUL passwd` (RFC 4616).
fn base64_plain(identity: &str, password: &str) -> String {
    base64(&format!("\0{identity}\0{password}"))
}

// ── the per-peer AUTH budget (the bound a reconnect cannot reset) ────────

/// Runs `attempts` failed logins on `attempts` fresh connections — the shape a
/// password-guessing client uses, which the per-connection counter never sees.
/// Each connection is *new* on purpose: that is the case the per-connection
/// bound misses.
fn fail_across_connections(harness: &Harness, attempts: usize) -> Vec<u16> {
    let budget = attempts as u16;
    let mut codes = Vec::new();
    for index in 0..attempts {
        let mut client = support::TlsClient::connect(harness.addr);
        client.ehlo("client.test");
        client.expect("STARTTLS", 220);
        client.handshake();
        client.ehlo("client.test");
        let credential = base64_plain("ops@example.com", &format!("guess-{index}"));
        codes.push(client.command(&format!("AUTH PLAIN {credential}")).code);
        if codes.last().is_some_and(|code| *code != 535) {
            // The budget is spent: every later connection would be refused
            // too, which is the point.
            let _ = budget;
            break;
        }
    }
    codes
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_failures_are_counted_per_peer_across_connections() {
    let mut options = HarnessOptions::submission();
    // One attempt per connection: the per-connection counter can never fire.
    options.limits.max_auth_attempts = 5;
    options.auth_guard = Some((3, Duration::from_secs(60)));
    let harness = Harness::start("auth-per-ip", options).await;
    let codes = fail_across_connections(&harness, 3);
    assert_eq!(
        codes,
        vec![535, 535, 535],
        "three failures on three connections spend the budget, whatever the connection"
    );
    // The budget is spent: the *next* connection cannot even use the right
    // password.
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    let reply = client.command(&format!(
        "AUTH PLAIN {}",
        base64_plain("ops@example.com", "s3cret")
    ));
    assert_eq!(
        reply.code, 421,
        "a peer whose budget is spent is refused whatever it presents: {reply:?}"
    );
    assert_eq!(
        harness
            .auth_guard
            .as_ref()
            .expect("guard")
            .failures("127.0.0.1".parse().expect("ip")),
        3,
        "the budget stays spent for the window"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_peer_budget_does_not_leak_into_a_later_login() {
    // The same three failures on three connections, then a *successful* login
    // from the same address: a peer that proves itself is not left carrying
    // its earlier failures.
    let mut options = HarnessOptions::submission();
    options.auth_guard = Some((4, Duration::from_secs(60)));
    let harness = Harness::start("auth-recover", options).await;
    let codes = fail_across_connections(&harness, 2);
    assert_eq!(codes, vec![535, 535]);
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "s3cret")),
        235,
    );
    assert_eq!(
        harness
            .auth_guard
            .as_ref()
            .expect("guard")
            .failures("127.0.0.1".parse().expect("ip")),
        0,
        "a successful login clears the failures charged to the address"
    );
    harness.stop();
}

// ── S3: the identity in `Received:` cannot carry a header ────────────────

#[tokio::test(flavor = "multi_thread")]
async fn an_identity_with_a_crlf_is_refused_and_never_reaches_received() {
    let harness = Harness::start("auth-inject", HarnessOptions::submission()).await;
    let injected = "ops@example.com\r\nX-Injected: yes";
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    let reply = client.command(&format!("AUTH PLAIN {}", base64_plain(injected, "s3cret")));
    assert_eq!(
        reply.code, 501,
        "an identity that is not a mailbox is a syntax error: {reply:?}"
    );
    // The session did not authenticate, so the submission is refused — and no
    // message carries the injected field.
    client.expect("MAIL FROM:<ops@example.com>", 250);
    assert_eq!(client.command("RCPT TO:<someone@gmail.com>").code, 530);
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bdat_chain_is_bounded_by_what_the_transport_holds() {
    // Two ceilings stand between a client and the spool, and they are the same
    // ceiling twice: the session's running total of the **declarations** against
    // the message size, and the transport's bound on the octets it actually
    // holds, `max_bdat_total` = the message size raised to one chunk. The
    // session refuses a chunk that would break it with `552` before its octets
    // are read; the transport's copy of the same comparison is an invariant
    // (asserted, not enforced — see the module note in `server.rs`), because
    // `chunk_bytes` is the sum of exactly the chunks the transport appended, so
    // the two inequalities are one.
    //
    // This test pins the reachable side: the ceiling holds, the step past it is
    // a single terminal reply, and nothing past it reaches the queue. The chain
    // is built of full chunks so no step is refused for its size alone.
    let limit = 2 * ayane_smtpd::server::MAX_BDAT_BUFFER;
    let options = HarnessOptions {
        max_message_size: limit as u64,
        limits: ayane_smtpd::Limits {
            max_message_size: limit as u64,
            ..ayane_smtpd::Limits::default()
        },
        transaction_timeout: Duration::from_secs(20),
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("bdat-ceiling", options).await;
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    // The whole ceiling, in chunks the single-chunk bound admits.
    let chunk = vec![b'x'; ayane_smtpd::server::MAX_BDAT_BUFFER];
    for _ in 0..2 {
        client.pending(&chunk);
        let reply = client.command(&format!("BDAT {}", chunk.len()));
        assert_eq!(
            reply.code, 250,
            "a chunk inside the ceiling is acknowledged: {reply:?}"
        );
    }
    // One more full chunk: the chain would hold twice the message size. Its
    // octets are never sent, so the answer must not depend on them.
    client.settle();
    let started = std::time::Instant::now();
    client.send(&format!("BDAT {}", chunk.len()));
    let terminal = client
        .try_read_reply()
        .expect("the chunk past the ceiling is answered, not parked");
    let elapsed = started.elapsed();
    assert_eq!(
        terminal.code, 552,
        "a chunk past the ceiling is answered once: {terminal:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the refusal is stated, not waited out at a timer: {elapsed:?}"
    );
    // Nothing follows it, and nothing was kept: the close is right behind the
    // one reply, and the queue is empty.
    let tail = client.finish_reading();
    assert!(tail.is_empty(), "one answer, then the close: {tail:?}");
    assert!(
        harness.queued().is_empty(),
        "a chain past the ceiling never reaches the queue"
    );
    harness.stop();
}

// ── a full AUTH table keeps what it counted ──────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_password_guesser_cannot_flush_someone_elses_budget_by_filling_the_table() {
    // The per-peer budget is only worth its name if a reported address keeps
    // it. A recorded address is charged only when it fails itself, so an
    // eviction policy (oldest-touched first) let an attacker with enough fresh
    // addresses push a quiet victim's entry out of the table — the victim's
    // count went to zero and its guesses could start again. At capacity the
    // guard now refuses the *new* address instead, so nothing already counted
    // is ever forgotten early.
    let options = HarnessOptions {
        auth_guard: Some((10, Duration::from_secs(300))),
        ..HarnessOptions::submission()
    };
    let harness = Harness::start("auth-full", options).await;
    let guard = Arc::clone(harness.auth_guard.as_ref().expect("guard"));
    // Small table, so the test fills it from loopback the way an attacker
    // would from a botnet: a few recorded addresses and then a flood.
    guard.set_capacity(4);
    let victim: std::net::IpAddr = "192.0.2.200".parse().expect("ip");
    let now = std::time::Instant::now();
    guard.record_failure(victim, now);
    assert_eq!(guard.failures(victim), 1, "the victim spent one guess");
    // Fill the table and then keep going: the extra addresses cannot get in.
    for index in 0..64u32 {
        guard.record_failure(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index)),
            now,
        );
    }
    assert_eq!(
        guard.failures(victim),
        1,
        "filling the table must not hand the victim its spent budget back"
    );
    assert_eq!(guard.tracked(), 4, "the table stopped at its capacity");
    assert_eq!(
        guard.failures(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
            0x0a00_0000 + 63
        ))),
        0,
        "an address that arrived at a full table is not recorded"
    );
    harness.stop();
}

// ── SMTPUTF8 identities can log in (the extension is not a tease) ────────

#[tokio::test(flavor = "multi_thread")]
async fn an_smtputf8_identity_can_authenticate() {
    // The greeting advertises SMTPUTF8 and the path parser accepts
    // `用户@例子.测试` in `MAIL FROM` — so the identity check must accept the
    // same shape, or the server offers an extension its own login path
    // contradicts.
    let options = HarnessOptions {
        password: Some(("用户@例子.测试".to_owned(), "s3cret".to_owned())),
        ..HarnessOptions::submission()
    };
    let harness = Harness::start("auth-utf8", options).await;
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    assert!(
        client.command("STARTTLS").code == 220,
        "the submission listener offers STARTTLS"
    );
    client.handshake();
    let ehlo = client.ehlo("client.test");
    assert!(
        ehlo.advertises("SMTPUTF8"),
        "the extension this test is about: {ehlo:?}"
    );
    let reply = client.command(&format!(
        "AUTH PLAIN {}",
        base64_plain("用户@例子.测试", "s3cret")
    ));
    assert_eq!(
        reply.code, 235,
        "a non-ASCII mailbox is a mailbox: {reply:?}"
    );
    // And the session acts as it: the identity is bound to the reverse-path
    // it may use.
    client.expect("MAIL FROM:<用户@example.net> SMTPUTF8", 250);
    // The sender binding binds to the identity exactly as it stands: a From it
    // does not own is refused, whatever alphabet the identity is written in.
    let stranger = client.command("RCPT TO:<someone@gmail.com>");
    assert_eq!(
        stranger.code, 553,
        "a submission may not claim a From it does not own: {stranger:?}"
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_ascii_identity_with_a_crlf_is_still_refused() {
    // Widening the alphabet is not widening the control check: the identity is
    // written into `Received:`, so a CR/LF in it is refused whatever else it
    // contains, and before the credential is looked at.
    let options = HarnessOptions {
        password: Some(("用户@例子.测试".to_owned(), "s3cret".to_owned())),
        ..HarnessOptions::submission()
    };
    let harness = Harness::start("auth-utf8-crlf", options).await;
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    let reply = client.command(&format!(
        "AUTH PLAIN {}",
        base64_plain("用户@例子.测试\r\nBcc: victim@example.net", "s3cret")
    ));
    assert_eq!(reply.code, 501, "the identity is not a mailbox: {reply:?}");
    harness.stop();
}

// ── a full AUTH table is not an open door ────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_full_table_bounds_the_addresses_it_could_not_record() {
    // The per-peer budget is worth its name only if a *full* table still
    // bounds the addresses it has no room for. Recording them would let an
    // attacker flush a victim's count by filling the table (a recorded address
    // is charged only when it fails); leaving them out entirely is a fail-open
    // of the opposite kind — the table fills, and every address after it
    // guesses for free, forever. So the traffic the table cannot hold is
    // counted once for all of it, and past that budget every address that is
    // not in the table is refused — while every address that *is* keeps the
    // count and the verdict it had.
    let options = HarnessOptions {
        auth_guard: Some((2, Duration::from_secs(300))),
        ..HarnessOptions::submission()
    };
    let harness = Harness::start("auth-flood", options).await;
    let guard = Arc::clone(harness.auth_guard.as_ref().expect("guard"));
    // A table this size can only be filled by the test itself: loopback is one
    // address, and filling 4 096 slots from the wire would be a slow way to
    // say the same thing.
    guard.set_capacity(4);
    let now = std::time::Instant::now();
    let recorded: Vec<std::net::IpAddr> = (0..4u32)
        .map(|index| std::net::IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index)))
        .collect();
    for ip in &recorded {
        guard.record_failure(*ip, now);
    }
    assert_eq!(guard.tracked(), 4, "the table is full");
    // Every one of the recorded addresses still answers from its own count:
    // they are one failure into a budget of two, so all of them are admitted.
    for ip in &recorded {
        assert_eq!(
            guard.admit(*ip, now),
            ayane_smtpd::server::AuthGate::Allowed,
            "a recorded entry is not refused because the table filled"
        );
    }
    // The unrecorded traffic spends the shared budget and one failure more.
    let spend = guard.flood_budget();
    for index in 0..=spend as u32 {
        guard.record_failure(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(0x0c00_0000 + index)),
            now,
        );
    }
    // Now the addresses the table cannot hold are refused — including the one
    // this connection is running on.
    let reply = {
        let mut client = support::TlsClient::connect(harness.addr);
        client.ehlo("client.test");
        client.expect("STARTTLS", 220);
        client.handshake();
        client.ehlo("client.test");
        client.command(&format!(
            "AUTH PLAIN {}",
            base64_plain("ops@example.com", "s3cret")
        ))
    };
    assert_eq!(
        reply.code, 421,
        "an address the table cannot record is refused once the shared budget is spent —              even with the right password: {reply:?}"
    );
    // And nothing that was already counted was touched to do it.
    for ip in &recorded {
        assert_eq!(guard.failures(*ip), 1, "no recorded count was changed");
    }
    harness.stop();
}

// ── AUTH and MAIL FROM agree about what a mailbox is ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn auth_and_mail_from_agree_about_what_a_mailbox_is() {
    // The identity a client logs in as and the path it puts in `MAIL FROM` are
    // judged by the same parser, so a text one accepts the other accepts. They
    // used to be judged by two copies of the rules: `a@-example.com`,
    // `a@example..com` and `a@example.com.` are not mailboxes, and the path
    // parser said so with a `501` while the identity check — which only knew
    // "one `@`, no quoting" — answered `235`. One server, two answers about
    // whether the same text is an address.
    let harness = Harness::start("auth-shape", HarnessOptions::submission()).await;
    for identity in ["a@-example.com", "a@example..com", "a@example.com."] {
        // The path: a syntax error, and therefore no transaction to log into.
        let mut path_client = harness.client();
        path_client.ehlo("client.test");
        let path = path_client.command(&format!("MAIL FROM:<{identity}>"));
        assert_eq!(
            path.code, 501,
            "`{identity}` is not a mailbox, so MAIL FROM must refuse it: {path:?}"
        );
        // The identity: the same answer, and never a credential verdict.
        let mut client = support::TlsClient::connect(harness.addr);
        client.ehlo("client.test");
        client.expect("STARTTLS", 220);
        client.handshake();
        client.ehlo("client.test");
        let reply = client.command(&format!("AUTH PLAIN {}", base64_plain(identity, "s3cret")));
        assert_eq!(
            reply.code, 501,
            "`{identity}` must be refused here exactly as MAIL FROM refuses it: {reply:?}"
        );
    }
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bare_postmaster_identity_is_the_host_s_own() {
    // RFC 5321 §4.1.3's `postmaster` has no domain and means "this server's".
    // The path is qualified with the host the session greets for, and a login
    // identity is qualified the same way — one rule, one place — so the
    // operator who creates the postmaster account can log in with the name the
    // RFC makes every server accept, and the session it gets submits as the
    // mailbox the envelope would record.
    let options = HarnessOptions {
        password: Some(("postmaster@mx.test".to_owned(), "s3cret".to_owned())),
        ..HarnessOptions::submission()
    };
    let harness = Harness::start("auth-postmaster", options).await;
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("postmaster", "s3cret")),
        235,
    );
    // And the identity it carries is the qualified one, exactly as the path
    // would be.
    client.expect("MAIL FROM:<postmaster>", 250);
    client.expect("RCPT TO:<someone@gmail.com>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"Subject: from the postmaster\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);
    let queued = harness.queued();
    assert_eq!(
        queued[0].envelope.mail_from, "postmaster@mx.test",
        "the bare postmaster is the host's own, on both sides of the envelope"
    );
    assert_eq!(
        queued[0].envelope.authenticated.as_deref(),
        Some("postmaster@mx.test"),
        "the identity is recorded as the mailbox the path names"
    );
    harness.stop();
}

// ── the traffic counters ────────────────────────────────────────────────
//
// The control plane's traffic page used to be built from Postfix log lines
// (`connect from unknown[…]: …`, `to=<…>, relay=…, status=sent`). The engine
// that produces those lines is no longer in the path, so the numbers have to
// come from the layer that knows the event happened. These tests pin what the
// listener counts, from the outside: what a client does, and what the counter
// says afterwards.

#[tokio::test(flavor = "multi_thread")]
async fn traffic_counts_what_the_listener_answered() {
    use ayane_smtpd::metrics::Counter;

    let options = HarnessOptions {
        metrics: true,
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("metrics", options).await;
    let metrics = harness
        .metrics
        .clone()
        .expect("the harness asked for counting");

    // One connection, three recipients: two accepted, one refused.
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("RCPT TO:<ops@example.com>", 250);
    let refused = client.command("RCPT TO:<nobody@example.net>");
    assert_eq!(refused.code, 550, "{refused:?}");
    // The message goes in: one message, and the recipients it was accepted
    // for were counted as they were accepted.
    client.expect("DATA", 354);
    client.send_raw(b"Subject: counted\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);

    // A second connection that only greets, so `connects` is 2 and nothing
    // else moves.
    let mut second = harness.client();
    second.ehlo("client.test");

    let snapshot = metrics.snapshot(ayane_smtpd::server::received_now_epoch(), 3600);
    let row = snapshot
        .inbound
        .iter()
        .find(|row| row.peer == "127.0.0.1")
        .unwrap_or_else(|| panic!("no row for the loopback peer: {snapshot:?}"));
    assert_eq!(row.connects, 2, "two connections were accepted: {row:?}");
    assert_eq!(row.messages, 1, "one message was queued: {row:?}");
    assert_eq!(row.recipients, 2, "two recipients were accepted: {row:?}");
    assert_eq!(row.refused, 1, "one was refused: {row:?}");
    // The reported totals are the same numbers, summed.
    assert_eq!(snapshot.totals.connects, 2);
    assert_eq!(snapshot.totals.messages_in, 1);
    assert_eq!(snapshot.totals.recipients_in, 2);
    assert_eq!(snapshot.totals.recipients_refused, 1);
    // A listener that was never asked to count stays silent.
    assert_eq!(
        ayane_smtpd::metrics::Metrics::new().total(Counter::Connects),
        0
    );
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn traffic_does_not_count_a_refused_transaction_as_a_message() {
    use ayane_smtpd::metrics::Counter;

    let options = HarnessOptions {
        metrics: true,
        ..HarnessOptions::inbound()
    };
    let harness = Harness::start("metrics-refused", options).await;
    let metrics = harness.metrics.clone().expect("counters");
    let mut client = harness.client();
    client.ehlo("client.test");
    client.expect("MAIL FROM:<a@example.net>", 250);
    client.expect("RCPT TO:<inbox@example.com>", 250);
    client.expect("DATA", 354);
    // A bare `LF` fails the transaction; nothing is queued, so no message is
    // counted — but the recipient *was* accepted, and that half is true.
    client.send_raw(b"Subject: bad\r\n\r\nbody\n.\r\n");
    let reply = client
        .try_read_reply_within(Duration::from_secs(5))
        .expect("the refused transfer is answered");
    assert_eq!(reply.code, 554, "{reply:?}");
    let now = ayane_smtpd::server::received_now_epoch();
    assert_eq!(metrics.total(Counter::MessagesIn), 0);
    assert_eq!(metrics.total(Counter::RecipientsIn), 1);
    let snapshot = metrics.snapshot(now, 3600);
    assert!(snapshot.totals.messages_in == 0, "{snapshot:?}");
    harness.stop();
}
