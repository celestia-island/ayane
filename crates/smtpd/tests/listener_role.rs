//! The listener-role wiring, asserted through the driver's own code path.
//!
//! The session layer's own suite has a `verdict_for` helper that mirrors the
//! driver's recipient decision. It is a *replica*: it answers the same question
//! by hand, so it proves what the router would say and nothing about what the
//! listener does with the answer. The function that actually decides is
//! `Connection::recipient_verdict` in `server.rs`, and it is chosen by
//! `ServerConfig::role` — one `match`, on one field, standing between a
//! configuration mistake and an open relay.
//!
//! That is the failure this module exists to catch: swap the two arms and every
//! replica in the tree still passes while a port-25 listener starts relaying for
//! anybody and a submission listener refuses the operator's own users. So every
//! assertion below drives a **real listener, configured with one role**, over a
//! **real socket**, and reads the codes a client gets back. Nothing here
//! re-implements the decision; if the driver's `match` were inverted, these
//! tests would be the ones that go red.
//!
//! The three properties, one per pair of roles:
//!
//! | Listener | Client | RCPT to a remote domain | Why |
//! |---|---|---|---|
//! | inbound (25) | unauthenticated (it has no AUTH at all) | `550 5.7.1` | a relay is not this listener's job |
//! | submission (587) | unauthenticated | `530 5.7.0` | submission is for authenticated clients, and RFC 4954 §4 says so |
//! | submission (587) | authenticated as its own sender | `250` | this is what submission is for |
//!
//! and the fourth, which is the wiring read the other way round: an address that
//! only the *inbound* arm knows how to answer (a hosted mailbox) must be
//! answered by the inbound listener's own router, not by a role-blind shortcut.

mod support;

use std::time::Duration;

use ayane_smtpd::ListenerRole;
use support::{Client, Harness, HarnessOptions};

/// A remote domain: hosted nowhere in the fixture state, so an `RCPT` for it is
/// a relay attempt on any listener.
const REMOTE: &str = "someone@gmail.com";

fn base64_plain(identity: &str, password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("\0{identity}\0{password}"))
}

/// Opens an unauthenticated plain-text client on `harness`.
fn unauthenticated(harness: &Harness) -> Client {
    let mut client = Client::connect(harness.addr);
    client.ehlo("client.test");
    client
}

/// The inbound arm: a port-25 listener refuses to relay, with the relay code.
#[tokio::test(flavor = "multi_thread")]
async fn an_inbound_listener_refuses_an_unauthenticated_remote_recipient() {
    let harness = Harness::start("wiring-inbound", HarnessOptions::inbound()).await;
    let mut client = unauthenticated(&harness);
    client.expect("MAIL FROM:<x@example.net>", 250);
    let reply = client.command(&format!("RCPT TO:<{REMOTE}>"));
    assert_eq!(
        reply.code, 550,
        "a port-25 listener must not relay: {reply:?}"
    );
    assert!(
        reply.text.contains("5.7.1") && reply.text.contains("Relay access denied"),
        "the refusal must be the relay verdict, not a missing mailbox: {reply:?}"
    );
    // Refused at RCPT means the message can never reach DATA — no backscatter.
    assert_eq!(client.command("DATA").code, 503);
    assert!(harness.queued().is_empty(), "nothing was queued");
    harness.stop();
}

/// The same refusal on the submission arm, for a client that has not logged in.
#[tokio::test(flavor = "multi_thread")]
async fn a_submission_listener_refuses_an_unauthenticated_recipient() {
    let harness = Harness::start("wiring-sub-anon", HarnessOptions::submission()).await;
    let mut client = unauthenticated(&harness);
    client.expect("MAIL FROM:<ops@example.com>", 250);
    let reply = client.command(&format!("RCPT TO:<{REMOTE}>"));
    assert_eq!(
        reply.code, 530,
        "submission without a login must not relay, and says to authenticate: {reply:?}"
    );
    assert!(reply.text.contains("5.7.0"), "{reply:?}");
    assert!(harness.queued().is_empty(), "nothing was queued");
    harness.stop();
}

/// The submission arm, authenticated: the remote recipient is the whole point
/// of the listener, and the message goes to the queue.
#[tokio::test(flavor = "multi_thread")]
async fn a_submission_listener_lets_an_authenticated_client_relay() {
    let harness = Harness::start("wiring-sub-auth", HarnessOptions::submission()).await;
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "s3cret")),
        235,
    );
    client.expect("MAIL FROM:<ops@example.com>", 250);
    let reply = client.command(&format!("RCPT TO:<{REMOTE}>"));
    assert_eq!(
        reply.code, 250,
        "an authenticated client may submit to a remote domain: {reply:?}"
    );
    client.expect("DATA", 354);
    client.send_raw(b"Subject: submitted\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);
    let queued = harness.queued();
    assert_eq!(queued.len(), 1, "exactly one message");
    assert_eq!(queued[0].envelope.recipients, vec![REMOTE]);
    assert_eq!(
        queued[0].envelope.authenticated.as_deref(),
        Some("ops@example.com"),
        "the envelope records who submitted it"
    );
    harness.stop();
}

/// The wiring, read from the other side: the inbound arm answers with its own
/// router — a hosted mailbox exists, an unknown address of the same hosted
/// domain does not — while a submission listener, unauthorised, says neither
/// (it can only ever say "relay denied", whatever the address).
///
/// This is what tells the two arms apart when the *addresses* are identical: a
/// role-blind implementation that answered from the router on both listeners,
/// or one that answered "relay denied" on both, would pass at most one of the
/// assertions here.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_inbound_arm_answers_from_the_router() {
    let inbound = Harness::start("wiring-router-in", HarnessOptions::inbound()).await;
    let submission = Harness::start("wiring-router-sub", HarnessOptions::submission()).await;

    let mut client = unauthenticated(&inbound);
    client.expect("MAIL FROM:<x@example.net>", 250);
    let reply = client.command("RCPT TO:<inbox@example.com>");
    assert_eq!(reply.code, 250, "a hosted mailbox exists here: {reply:?}");
    let reply = client.command("RCPT TO:<nobody@example.com>");
    assert_eq!(
        reply.code, 550,
        "an unknown address of a hosted domain does not exist: {reply:?}"
    );
    assert!(
        reply.text.contains("5.1.1") && !reply.text.contains("Relay denied"),
        "that is a mailbox answer, not a relay answer: {reply:?}"
    );

    let mut client = unauthenticated(&submission);
    client.expect("MAIL FROM:<ops@example.com>", 250);
    // The same hosted mailbox: not an answer this listener's arm can give, so
    // it is the "authenticate first" refusal — identical to what a remote
    // domain gets.
    let reply = client.command("RCPT TO:<inbox@example.com>");
    assert_eq!(
        reply.code, 530,
        "an unauthenticated submission relays nowhere: {reply:?}"
    );
    assert!(reply.text.contains("5.7.0"), "{reply:?}");

    inbound.stop();
    submission.stop();
}

/// `SubmissionsTls` (465) takes the submission arm too: implicit TLS, and the
/// same anonymous refusal a clear-text submission gives.
#[tokio::test(flavor = "multi_thread")]
async fn the_implicit_tls_listener_takes_the_submission_arm() {
    // The TLS acceptor, the credentials and the rest are the submission
    // fixture's; only the role changes, and that one field is the whole point.
    let mut options = HarnessOptions::submission();
    options.role = ListenerRole::SubmissionsTls;
    let harness = Harness::start("wiring-465", options).await;
    // 465 is implicit TLS: the handshake comes first and the greeting arrives
    // inside it, so this client never reads a `220` in the clear.
    let mut client = support::TlsClient::connect_tls(harness.addr);
    let ehlo = client.ehlo("client.test");
    assert!(
        ehlo.advertises_prefix("AUTH"),
        "implicit TLS starts authenticated-capable: {ehlo:?}"
    );
    client.expect("MAIL FROM:<ops@example.com>", 250);
    let reply = client.command(&format!("RCPT TO:<{REMOTE}>"));
    assert_eq!(
        reply.code, 530,
        "an unauthenticated 465 listener relays nowhere and says to authenticate: {reply:?}"
    );
    assert!(reply.text.contains("5.7.0"), "{reply:?}");
    harness.stop();
}

/// The two arms answer the same question differently, which is the property a
/// role-blind implementation cannot have.
///
/// This one is comparative on purpose. ``an_inbound_listener_refuses_an_
/// unauthenticated_remote_recipient`` and ``a_submission_listener_lets_an_
/// authenticated_client_relay`` already pin each answer; what they cannot say
/// on their own is that the answers come from *different arms*. Here the same
/// address, the same fixture state and the same client state get `530 5.7.0`
/// from one listener and `250` from the other — and from the inbound listener
/// `550 5.7.1`, which is the relay verdict, so an implementation that read
/// one arm for both (or collapsed the `match` into a shared answer) fails the
/// pair even if it happened to pick a plausible single code.
#[tokio::test(flavor = "multi_thread")]
async fn the_two_arms_answer_the_same_address_differently() {
    let inbound = Harness::start("wiring-compare-in", HarnessOptions::inbound()).await;
    let submission = Harness::start("wiring-compare-sub", HarnessOptions::submission()).await;

    let mut client = unauthenticated(&inbound);
    client.expect("MAIL FROM:<x@example.net>", 250);
    let on_inbound = client.command(&format!("RCPT TO:<{REMOTE}>")).code;

    let mut client = unauthenticated(&submission);
    client.expect("MAIL FROM:<ops@example.com>", 250);
    let on_submission_anon = client.command(&format!("RCPT TO:<{REMOTE}>")).code;

    let mut client = support::TlsClient::connect(submission.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    client.expect(
        &format!("AUTH PLAIN {}", base64_plain("ops@example.com", "s3cret")),
        235,
    );
    client.expect("MAIL FROM:<ops@example.com>", 250);
    let on_submission_auth = client.command(&format!("RCPT TO:<{REMOTE}>")).code;

    assert_eq!(on_inbound, 550, "port 25 refuses to relay");
    assert_eq!(
        on_submission_anon, 530,
        "submission without a login says which refusal it is: authenticate first"
    );
    assert_eq!(
        on_submission_auth, 250,
        "an authenticated submission is the same address, accepted"
    );

    inbound.stop();
    submission.stop();
}

/// `SubmissionsTls` is not only the submission arm's authorisation — it is
/// also the arm that must be encrypted **before** it speaks. Nothing may leave
/// the server in the clear on that listener, the greeting included: a client
/// that connects and reads without handshaking gets a silence it has to time
/// out on, never a `220`.
///
/// This test exists because the release this branch carries did leak exactly
/// that: the role was dispatched to the submission arm while the greeting was
/// still written on the unwrapped socket, which put plaintext on a TLS port.
#[tokio::test(flavor = "multi_thread")]
async fn the_implicit_tls_listener_greets_only_inside_tls() {
    use std::io::Read as _;

    let mut options = HarnessOptions::submission();
    options.role = ListenerRole::SubmissionsTls;
    let harness = Harness::start("wiring-465-clear", options).await;
    let mut raw = std::net::TcpStream::connect(harness.addr).expect("connect");
    raw.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let mut buffer = [0u8; 64];
    // A TLS client speaks first; a plain-text read here is exactly what a
    // downgrade attempt looks like, and the answer must be nothing at all.
    match raw.read(&mut buffer) {
        Ok(0) => {}
        Ok(read) => panic!(
            "implicit TLS sent {} octets in the clear: {:?}",
            read,
            String::from_utf8_lossy(&buffer[..read])
        ),
        Err(err) => assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "the socket is open and silent, not failed: {err:?}"
        ),
    }
    // And the session itself works over TLS: the greeting arrives encrypted.
    let mut client = support::TlsClient::connect_tls(harness.addr);
    let ehlo = client.ehlo("client.test");
    assert!(
        !ehlo.advertises("STARTTLS"),
        "an already-encrypted session does not offer to upgrade: {ehlo:?}"
    );
    assert!(ehlo.advertises_prefix("AUTH"), "{ehlo:?}");
    harness.stop();
}

/// The budget the per-IP AUTH guard ships with, read through the configuration
/// the driver is handed: fifty failures per address in five minutes. The guard
/// itself is unit-tested in `server.rs`; this pins the *default* a deployment
/// gets when it constructs `AuthGuard::default()` — the value the operator
/// binary installs — so a change to it is a decision and not a drift.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_peer_budget_is_the_documented_one() {
    use ayane_smtpd::server::{AUTH_FAIL_BUDGET, AUTH_FAIL_WINDOW, AUTH_GUARD_CAPACITY};
    assert_eq!(AUTH_FAIL_BUDGET, 50);
    assert_eq!(AUTH_FAIL_WINDOW, Duration::from_secs(300));
    assert_eq!(AUTH_GUARD_CAPACITY, 4096);
    let guard = ayane_smtpd::server::AuthGuard::default();
    assert_eq!(
        guard.flood_budget(),
        AUTH_FAIL_BUDGET * ayane_smtpd::server::AUTH_FLOOD_BUDGET_FACTOR,
        "a full table's shared budget follows the per-address one"
    );
}
