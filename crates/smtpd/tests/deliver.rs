//! The receiving half and the delivery half over one spool.
//!
//! Everything here goes through the real driver: a client speaks SMTP to a
//! bound listener, the listener commits to its spool, and the delivery
//! consumer — the same `Deliverer` the binary runs — drains what was
//! committed. The point is the seam between the two, which no unit test
//! crosses: the spool's envelope is whatever the session wrote, and the
//! consumer has to route every recipient the session accepted from exactly
//! those fields.

mod support;

use ayane_proto::Address;
use ayane_smtpd::deliver::{Deliverer, Disposition, RecipientOutcome};
use support::{deliver, Harness, HarnessOptions};

const MESSAGE: &str = "From: Alice <alice@partner.example>\r\n\
                       To: ops@example.com\r\n\
                       Subject: hello\r\n\
                       \r\n\
                       body\r\n";

fn addr(raw: &str) -> Address {
    Address::parse(raw).expect("fixture address")
}

/// The consumer over the harness' spool, writing into its own mail tree.
///
/// The two roots are separate because a deployment's are: the spool owns
/// `tmp/`, `new/`, `cur/` and `corrupt/`, and every maildir owns three of
/// those names of its own.
fn deliverer(harness: &Harness) -> Deliverer {
    Deliverer::new(harness.spool.clone(), harness.mail_root(), "mx.test")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_message_reaches_the_maildir_of_its_recipient() {
    let harness = Harness::start("deliver-local", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = deliver(
        &mut client,
        "alice@partner.example",
        "ops@example.com",
        MESSAGE,
    );
    assert_eq!(reply.code, 250, "{reply:?}");
    assert_eq!(harness.queued().len(), 1);

    let deliverer = deliverer(&harness);
    let reports = deliverer
        .run_at(&harness.state, 1_000)
        .expect("the consumer drains the queue");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].disposition, Disposition::Delivered);
    assert!(matches!(
        reports[0].recipients[0].outcome,
        RecipientOutcome::Delivered(_)
    ));

    // The delivery landed one floor below the engine's home, which is what
    // Dovecot's `mail_location = maildir:~/Maildir` opens.
    let new = deliverer.maildir_path(&addr("ops@example.com")).join("new");
    let names: Vec<String> = std::fs::read_dir(&new)
        .expect("maildir/new")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    let body = std::fs::read_to_string(new.join(&names[0])).expect("read");
    assert!(
        body.starts_with("Delivered-To: ops@example.com\r\n"),
        "{body}"
    );
    assert!(body.contains("Subject: hello\r\n"), "{body}");
    // The trace field the driver wrote is in front of the client's headers.
    // The driver's `Received:` is the first field of the stored octets, so
    // what a client opens is that block, then this layer's `Delivered-To:`,
    // then the sender's headers.
    let subject = body.find("Subject: hello").expect("Subject");
    let received = body.find("Received: from").expect("the trace field");
    assert!(
        body.find("Delivered-To:") == Some(0) && received < subject,
        "the trace field belongs on top, behind only this layer's own field: {body}"
    );
    // And nothing is left in the queue.
    assert!(harness.queued().is_empty());
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_alias_recipient_is_forwarded_with_the_original_envelope_sender() {
    let harness = Harness::start("deliver-alias", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = deliver(
        &mut client,
        "alice@partner.example",
        "sales@example.com",
        MESSAGE,
    );
    assert_eq!(reply.code, 250, "{reply:?}");

    let deliverer = deliverer(&harness);
    let reports = deliverer
        .run_at(&harness.state, 1_000)
        .expect("the consumer drains the queue");
    assert_eq!(reports[0].disposition, Disposition::Forwarded);
    let children = harness.queued();
    assert_eq!(children.len(), 1, "one child for the one alias target");
    assert_eq!(
        children[0].envelope.mail_from, "alice@partner.example",
        "a forward keeps the sender's responsibility for a bounce"
    );
    assert_eq!(children[0].envelope.recipients, vec!["ops@example.com"]);
    assert_eq!(
        children[0].envelope.forwarded_from.as_deref(),
        Some("sales@example.com")
    );
    assert_eq!(children[0].envelope.forward_hops, 1);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shared_mailbox_recipient_is_delivered_like_any_other() {
    // `team@example.com` is a shared mailbox: the listener accepts it at
    // `RCPT` (it is a real mailbox), and the consumer has to write it into a
    // maildir instead of bouncing it.
    let harness = Harness::start("deliver-shared", HarnessOptions::inbound()).await;
    let mut client = harness.client();
    let reply = deliver(
        &mut client,
        "alice@partner.example",
        "team@example.com",
        MESSAGE,
    );
    assert_eq!(reply.code, 250, "{reply:?}");

    let deliverer = deliverer(&harness);
    let reports = deliverer
        .run_at(&harness.state, 1_000)
        .expect("the consumer drains the queue");
    assert_eq!(reports[0].disposition, Disposition::Delivered);
    assert!(matches!(
        reports[0].recipients[0].outcome,
        RecipientOutcome::Delivered(_)
    ));
    let new = deliverer
        .maildir_path(&addr("team@example.com"))
        .join("new");
    assert_eq!(std::fs::read_dir(&new).expect("maildir").count(), 1);
    harness.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_submitted_message_for_a_remote_recipient_is_left_for_the_outbound_transport() {
    // A submission listener accepts a remote recipient; the consumer must not
    // pretend to deliver it and must not bounce it either. The entry stays
    // queued with its recipient untouched.
    let options = HarnessOptions::submission();
    let harness = Harness::start("deliver-remote", options.clone()).await;
    let mut client = support::TlsClient::connect(harness.addr);
    client.ehlo("client.test");
    client.expect("STARTTLS", 220);
    client.handshake();
    client.ehlo("client.test");
    let (identity, password) = options.password.expect("fixture credential");
    client.expect(&format!("AUTH PLAIN {}", base64(&identity, &password)), 235);
    client.expect(&format!("MAIL FROM:<{identity}>"), 250);
    client.expect("RCPT TO:<girl@remote.example>", 250);
    client.expect("DATA", 354);
    client.send_raw(b"Subject: hi\r\n\r\nbody\r\n.\r\n");
    assert_eq!(client.read_reply().code, 250);

    let deliverer = deliverer(&harness);
    let reports = deliverer
        .run_at(&harness.state, 1_000)
        .expect("the consumer drains the queue");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].disposition, Disposition::Held);
    assert_eq!(reports[0].recipients[0].outcome, RecipientOutcome::Remote);
    // The entry is still the delivery consumer's, in `cur/` with its
    // recipient untouched — not in `new/`, where the consumer would claim it
    // again on the next pass.
    assert_eq!(
        harness
            .spool
            .list(ayane_smtpd::queue::QueueState::Cur)
            .expect("list")
            .len(),
        1,
        "the entry stays in the queue for the outbound side"
    );
    harness.stop();
}

fn base64(identity: &str, password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("\0{identity}\0{password}"))
}
