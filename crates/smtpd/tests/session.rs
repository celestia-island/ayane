//! The session state machine driven directly — no socket, no harness.
//!
//! W1's protocol suite drove most of these properties over a real TCP
//! connection through the listener. That is the right way to prove the wire
//! behaviour, but it ties every assertion to a server; the properties
//! themselves belong to [`Session`]: which code a malformed line gets, which
//! code a misordered one gets, what a transaction looks like after each step.
//! They are asserted here against the machine alone, so they hold whether or
//! not a listener is built around them.
//!
//! Everything the machine cannot know — whether a mailbox exists, whether a
//! password is right, whether the disk took the message — is supplied here the
//! way a driver supplies it: through [`Session::outcome`] and
//! [`Session::end_of_message`]. `RCPT` is the one command that answers twice
//! (a provisional `250` immediately, then the verdict), so a test that accepts
//! a recipient must complete the pair, exactly as a driver does.

use ayane_proto::{Account, Address, Alias, DefaultAction, DesiredState, MailDomain, Policy};
use ayane_smtpd::command::{self, AuthMechanism, Command};
use ayane_smtpd::policy::{inbound_recipient, AddressPolicy, RecipientVerdict};
use ayane_smtpd::session::{Action, Extensions, HelloMode, Limits, Outcome, Phase, Reply};
use ayane_smtpd::{Mailbox, Session};
use uuid::Uuid;

// ── fixtures ─────────────────────────────────────────────────────────────

fn addr(raw: &str) -> Address {
    Address::parse(raw).expect("fixture address")
}

fn state() -> DesiredState {
    DesiredState {
        domains: vec![MailDomain {
            name: "example.com".to_owned(),
            catch_all: None,
            enabled: true,
        }],
        accounts: vec![Account {
            id: Uuid::new_v4(),
            address: addr("inbox@example.com"),
            display_name: "Inbox".to_owned(),
            quota_bytes: 0,
            admin: false,
        }],
        aliases: vec![Alias {
            source: addr("sales@example.com"),
            targets: vec![addr("inbox@example.com")],
        }],
        shared: Vec::new(),
        policy: Policy {
            default_action: DefaultAction::Reject,
            allowlist: Vec::new(),
            denylist: Vec::new(),
            variants: Default::default(),
        },
        audit: Default::default(),
        mcp: Default::default(),
    }
}

fn extensions(hostname: &str, starttls: bool, auth: bool) -> Extensions {
    Extensions {
        max_message_size: 25 * 1024 * 1024,
        starttls,
        auth: if auth {
            vec![AuthMechanism::Plain, AuthMechanism::Login]
        } else {
            Vec::new()
        },
        smtputf8: true,
        eight_bit_mime: true,
        hostname: hostname.to_owned(),
    }
}

/// An inbound listener: no TLS, no AUTH, RFC 5321 only.
fn inbound() -> Session {
    Session::new(
        extensions("mx.test", false, false),
        Limits::default(),
        AddressPolicy::from_state(&state()),
    )
}

/// A submission listener already past AUTH as `identity`.
fn submission(identity: &str) -> Session {
    let mut session = Session::new(
        extensions("mx.test", false, true),
        Limits::default(),
        AddressPolicy::from_state(&state()),
    );
    session.set_tls_active();
    session.command(&Command::Ehlo("client.test".to_owned()));
    session.outcome(Outcome::Authenticated(identity.to_owned()));
    session
}

fn greeted_inbound() -> Session {
    let mut session = inbound();
    line(&mut session, "EHLO client.test");
    session
}

/// Feeds one raw line through the parser and the machine, exactly as a driver
/// does: parse, then `command`.
fn line(session: &mut Session, raw: &str) -> Reply {
    match command::parse(raw, session.extensions().smtputf8) {
        Ok(parsed) => session.command(&parsed),
        Err(err) => err.reply(),
    }
}

/// The pair of replies one `RCPT` produces: the immediate provisional answer
/// and then the verdict the driver reports through [`Session::outcome`].
///
/// The verdict here is the **real** policy layer's, so the test asserts the
/// composition of the two — which is what a client actually sees — rather than
/// inventing an outcome the router would never produce.
fn rcpt(session: &mut Session, raw: &str) -> (Reply, Option<Reply>) {
    let provisional = line(session, raw);
    if provisional.code != 250 {
        return (provisional, None);
    }
    let held = session
        .pending_recipient()
        .expect("an accepted RCPT is held until it is resolved")
        .clone();
    let outcome = verdict_for(session, &held);
    (provisional, Some(session.outcome(outcome)))
}

/// Runs the policy layer over the recipient the session is holding.
fn verdict_for(session: &Session, held: &Mailbox) -> Outcome {
    // The bare `postmaster` has no domain to route by; `qualify` is the one
    // rule that gives it the host's own name, and the driver applies it before
    // the router sees the address.
    // A bare `postmaster` is this server's, by RFC 5321 §4.1.3, and has no
    // domain for the router to match: the driver accepts it outright rather
    // than asking the router about a domain that is not there.
    if held.postmaster_domain().is_some() {
        return Outcome::RecipientAccepted;
    }
    let qualified = session.qualify(held);
    let Ok(recipient) = Address::parse(&qualified.as_text()) else {
        return Outcome::RecipientInvalid;
    };
    // An authenticated client may submit to a remote recipient; an
    // unauthenticated one may not relay at all.
    let sender = session
        .authenticated()
        .or(Some("sender@remote.example"))
        .expect("a sender always exists");
    let Ok(sender) = Address::parse(sender) else {
        return Outcome::RecipientInvalid;
    };
    if session.authenticated().is_none()
        && !state()
            .domains
            .iter()
            .any(|domain| domain.enabled && domain.name.eq_ignore_ascii_case(recipient.domain()))
    {
        return Outcome::RelayDenied;
    }
    if session.authenticated().is_some() {
        // Submission: the recipient may be remote.
        return Outcome::RecipientAccepted;
    }
    match inbound_recipient(&state(), &sender, &recipient).verdict {
        RecipientVerdict::Exists => Outcome::RecipientAccepted,
        RecipientVerdict::Unknown => Outcome::RecipientUnknown,
        RecipientVerdict::RelayDenied => Outcome::RelayDenied,
    }
}

/// Accepts a local recipient and completes the pair.
fn accept_local(session: &mut Session) {
    let (provisional, verdict) = rcpt(session, "RCPT TO:<inbox@example.com>");
    assert_eq!(provisional.code, 250, "{provisional:?}");
    let verdict = verdict.expect("an accepted RCPT is resolved");
    assert_eq!(verdict.code, 250, "{verdict:?}");
}

/// Opens a transaction with one accepted local recipient.
fn transaction(session: &mut Session) {
    line(session, "MAIL FROM:<sender@remote.example>");
    accept_local(session);
}

// ── the greeting ─────────────────────────────────────────────────────────

#[test]
fn ehlo_advertises_the_four_extensions_and_helo_offers_none() {
    let mut session = inbound();
    let reply = line(&mut session, "EHLO client.test");
    assert_eq!(reply.code, 250);
    let advertised = reply.lines.join("\n");
    for keyword in ["PIPELINING", "SIZE", "CHUNKING", "SMTPUTF8"] {
        assert!(advertised.contains(keyword), "EHLO lacks {keyword}");
    }
    assert_eq!(session.hello(), Some((HelloMode::Ehlo, "client.test")));

    let mut session = inbound();
    let reply = line(&mut session, "HELO client.test");
    assert_eq!(reply.code, 250);
    assert!(
        reply.lines.is_empty(),
        "HELO must not advertise extensions: {reply:?}"
    );
}

#[test]
fn a_bare_domainless_greeting_is_a_syntax_error() {
    let mut session = inbound();
    assert_eq!(line(&mut session, "EHLO").code, 501);
    assert_eq!(line(&mut session, "HELO ").code, 501);
    assert_eq!(session.hello(), None);
}

// ── structural: shape errors versus state errors ─────────────────────────

#[test]
fn unknown_and_empty_commands_are_500() {
    // "There is no such verb" and "there is no verb at all" are both shape
    // answers, and the client's fix is the same: do not send that line.
    let mut session = greeted_inbound();
    assert_eq!(line(&mut session, "FOO bar").code, 500);
    assert_eq!(line(&mut session, "").code, 500);
    // The session is not wedged by either.
    assert_eq!(line(&mut session, "NOOP").code, 250);
}

#[test]
fn a_malformed_line_is_501_wherever_it_appears() {
    let mut session = greeted_inbound();
    assert_eq!(line(&mut session, "MAIL <a@b.example>").code, 501);
    assert_eq!(line(&mut session, "RCPT TO:<a@b").code, 501);
    assert_eq!(
        line(&mut session, "MAIL FROM:<a@b.example> SIZE=abc").code,
        501
    );
    assert_eq!(line(&mut session, "BDAT x").code, 501);
    assert_eq!(session.phase(), Phase::Greeted);
}

#[test]
fn rcpt_without_mail_is_a_sequence_error_even_with_wrong_syntax() {
    // This is the one deliberate exception: a client that sends `RCPT` before
    // `MAIL` has a sequencing bug, and telling it about the path's syntax
    // would send it looking at a line it can parse fine.
    let mut session = greeted_inbound();
    assert_eq!(line(&mut session, "RCPT TO:a@example.com").code, 503);
    assert_eq!(line(&mut session, "DATA").code, 503);
}

#[test]
fn commands_out_of_order_are_503_and_the_sequence_is_not_wedged() {
    let mut session = greeted_inbound();
    assert_eq!(line(&mut session, "DATA").code, 503);
    assert_eq!(line(&mut session, "BDAT 10").code, 503);
    transaction(&mut session);
    assert_eq!(line(&mut session, "DATA").code, 354);
    session.end_of_message(true);
    // The transaction is over: a fresh one starts at MAIL again.
    assert_eq!(line(&mut session, "RCPT TO:<inbox@example.com>").code, 503);
}

#[test]
fn a_known_command_with_an_unimplemented_parameter_is_504() {
    // 504 is "the argument asks for something this server does not have", not
    // "the line is malformed" — the mechanism name is well formed.
    let mut session = greeted_inbound();
    assert_eq!(line(&mut session, "AUTH CRAM-MD5").code, 504);
}

// ── the inbound transaction ──────────────────────────────────────────────

#[test]
fn a_full_transaction_walks_greeted_to_delivered() {
    let mut session = greeted_inbound();
    assert_eq!(
        line(&mut session, "MAIL FROM:<sender@remote.example>").code,
        250
    );
    assert_eq!(session.phase(), Phase::Mail);

    transaction(&mut session);
    assert_eq!(session.phase(), Phase::Rcpt);

    let reply = line(&mut session, "DATA");
    assert_eq!(reply.code, 354);
    assert_eq!(reply.action, Action::ReadData);
    assert_eq!(session.phase(), Phase::Data);

    // The body arrives through the transport; the verdict on the queue is the
    // caller's, and only `true` earns the 250.
    let reply = session.end_of_message(true);
    assert_eq!(reply.code, 250);
    assert_eq!(session.messages_delivered(), 1);
    assert_eq!(session.phase(), Phase::Greeted);
}

#[test]
fn a_failed_queue_commit_is_554_and_not_a_delivery() {
    // The transaction is abandoned rather than left open: the client must
    // re-send the whole message, and `messages_delivered` must not move — a
    // message that never reached the disk is not one this server delivered.
    let mut session = greeted_inbound();
    transaction(&mut session);
    line(&mut session, "DATA");
    let reply = session.end_of_message(false);
    assert_eq!(reply.code, 554, "a spool failure must not answer 250");
    assert_eq!(reply.enhanced, Some("5.6.0"));
    assert_eq!(session.messages_delivered(), 0);
    assert_eq!(
        session.phase(),
        Phase::Greeted,
        "the transaction is abandoned"
    );
}

#[test]
fn rset_clears_the_transaction_but_not_the_greeting() {
    let mut session = greeted_inbound();
    transaction(&mut session);
    assert_eq!(line(&mut session, "RSET").code, 250);
    assert_eq!(session.hello(), Some((HelloMode::Ehlo, "client.test")));
    assert_eq!(session.phase(), Phase::Greeted);
    // The transaction is gone, so the same path is once more a sequence error.
    assert_eq!(line(&mut session, "RCPT TO:<inbox@example.com>").code, 503);
}

#[test]
fn the_recipient_limit_is_enforced_by_the_machine() {
    let limits = Limits {
        max_recipients: 2,
        ..Limits::default()
    };
    let mut session = Session::new(
        extensions("mx.test", false, false),
        limits,
        AddressPolicy::from_state(&state()),
    );
    line(&mut session, "EHLO client.test");
    line(&mut session, "MAIL FROM:<sender@remote.example>");
    for _ in 0..2 {
        accept_local(&mut session);
    }
    let reply = line(&mut session, "RCPT TO:<inbox@example.com>");
    assert_eq!(reply.code, 452, "{reply:?}");
}

#[test]
fn the_message_limit_ends_the_connection() {
    let limits = Limits {
        max_messages: 1,
        ..Limits::default()
    };
    let mut session = Session::new(
        extensions("mx.test", false, false),
        limits,
        AddressPolicy::from_state(&state()),
    );
    line(&mut session, "EHLO client.test");
    transaction(&mut session);
    line(&mut session, "DATA");
    // The budgeted message is delivered and acknowledged.
    assert_eq!(session.end_of_message(true).code, 250);
    assert_eq!(session.messages_delivered(), 1);

    // The next one is over budget, and the refusal is the one that ends the
    // connection — a fourth message would only repeat it.
    transaction(&mut session);
    line(&mut session, "DATA");
    let reply = session.end_of_message(true);
    assert_eq!(reply.code, 421, "{reply:?}");
    assert_eq!(reply.action, Action::Close);
    assert_eq!(
        session.messages_delivered(),
        1,
        "the refused message is not counted as delivered"
    );
}

#[test]
fn quit_closes_the_connection() {
    let mut session = greeted_inbound();
    let reply = line(&mut session, "QUIT");
    assert_eq!(reply.code, 221);
    assert_eq!(reply.action, Action::Close);
}

// ── SIZE and SMTPUTF8 ────────────────────────────────────────────────────

#[test]
fn a_declared_size_over_the_ceiling_is_refused_at_mail() {
    let limits = Limits {
        max_message_size: 1024,
        ..Limits::default()
    };
    let mut session = Session::new(
        Extensions {
            max_message_size: 1024,
            ..extensions("mx.test", false, false)
        },
        limits,
        AddressPolicy::from_state(&state()),
    );
    line(&mut session, "EHLO client.test");
    let reply = line(&mut session, "MAIL FROM:<sender@remote.example> SIZE=2048");
    assert_eq!(reply.code, 552, "{reply:?}");
    assert_eq!(session.phase(), Phase::Greeted);
    // Exactly the ceiling is admissible.
    assert_eq!(
        line(&mut session, "MAIL FROM:<sender@remote.example> SIZE=1024").code,
        250
    );
}

#[test]
fn a_utf8_path_needs_the_smtputf8_parameter_on_a_server_that_offers_it() {
    // The server offers SMTPUTF8, but the *path* does not get the extended
    // alphabet until the transaction asks for it: a bare `MAIL FROM` with
    // non-ASCII octets is a syntax error, and the same path sent with
    // `SMTPUTF8` is a transaction.
    let mut session = greeted_inbound();
    assert_eq!(line(&mut session, "MAIL FROM:<用户@例子.测试>").code, 501);
    assert_eq!(
        line(&mut session, "MAIL FROM:<用户@例子.测试> SMTPUTF8").code,
        250
    );
    // And the extended transaction accepts an extended forward-path.
    accept_local(&mut session);
}

// ── the postmaster exemption (RFC 5321 §4.1.3) ───────────────────────────

#[test]
fn postmaster_is_accepted_without_a_domain_in_any_case() {
    // The RFC makes bare `<postmaster>` a MUST for every server, in any case,
    // and the envelope records it qualified with the server's own name so a
    // delivery agent can route it.
    for spelling in ["postmaster", "Postmaster", "POSTMASTER"] {
        let mut session = greeted_inbound();
        line(&mut session, "MAIL FROM:<sender@remote.example>");
        let raw = format!("RCPT TO:<{spelling}>");
        let (provisional, verdict) = rcpt(&mut session, &raw);
        assert_eq!(
            provisional.code, 250,
            "<{spelling}> must be accepted: RFC 5321 §4.1.3 makes it a MUST"
        );
        let verdict = verdict.expect("an accepted RCPT is resolved");
        assert_eq!(verdict.code, 250, "<{spelling}>: {verdict:?}");
    }
}

#[test]
fn the_bare_postmaster_is_qualified_with_the_hosts_own_name() {
    let mut session = greeted_inbound();
    line(&mut session, "MAIL FROM:<sender@remote.example>");
    line(&mut session, "RCPT TO:<Postmaster>");
    let held = session.pending_recipient().expect("recipient held").clone();
    // The parser folds the case: RFC 5321 §4.1.3 makes `<Postmaster>` the same
    // mailbox as `<postmaster>`, so there is one spelling from here on and no
    // consumer has to remember to compare case-insensitively.
    assert_eq!(held.as_text(), "postmaster");
    // The envelope records the qualified form: that is what a delivery agent
    // can route, and it is the same mailbox for every spelling (RFC 5321
    // compares the postmaster name case-insensitively).
    let recorded = session.qualify(&held).as_text();
    assert_eq!(recorded, "postmaster@mx.test");
    for spelling in ["postmaster", "POSTMASTER", "PostMaster"] {
        let other = Mailbox::parse(spelling, true).expect("bare postmaster parses");
        assert_eq!(
            session.qualify(&other).as_text(),
            recorded,
            "every spelling is the same postmaster mailbox"
        );
    }
}

#[test]
fn only_postmaster_is_exempt_from_having_a_domain() {
    let mut session = greeted_inbound();
    line(&mut session, "MAIL FROM:<sender@remote.example>");
    for spelling in ["other", "postmasterx", "postmaster.example", "x-postmaster"] {
        let reply = line(&mut session, &format!("RCPT TO:<{spelling}>"));
        assert_eq!(reply.code, 501, "<{spelling}> has no domain: {reply:?}");
    }
}

// ── BDAT (RFC 3030) ──────────────────────────────────────────────────────

#[test]
fn a_bdat_chain_builds_one_message_and_last_ends_it() {
    let mut session = greeted_inbound();
    transaction(&mut session);

    let first = line(&mut session, "BDAT 10");
    assert_eq!(first.code, 250);
    assert_eq!(first.action, Action::ReadChunk(10));
    assert!(!session.pending_chunk_is_last());
    session.chunk_received(10);

    let last = line(&mut session, "BDAT 5 LAST");
    assert_eq!(last.code, 250);
    assert_eq!(last.action, Action::ReadChunk(5));
    assert!(session.pending_chunk_is_last());
    session.chunk_received(5);

    let reply = session.end_of_message(true);
    assert_eq!(reply.code, 250);
    assert_eq!(session.messages_delivered(), 1);
}

#[test]
fn data_and_bdat_are_mutually_exclusive() {
    let mut session = greeted_inbound();
    transaction(&mut session);
    line(&mut session, "BDAT 10");
    session.chunk_received(10);
    // The chain is open: DATA cannot start a body the transaction already has.
    assert_eq!(line(&mut session, "DATA").code, 503);
}

#[test]
fn a_chunk_over_the_buffer_is_refused_before_its_octets_are_read() {
    // The transport is what knows a chunk is too large to hold, and the
    // refusal ends the connection rather than answering a command whose
    // octets are still in flight.
    let mut session = greeted_inbound();
    transaction(&mut session);
    line(&mut session, "BDAT 10");
    let reply = session.chunk_abandon();
    assert_eq!(reply.code, 421);
    assert_eq!(reply.action, Action::Close);
}

// ── AUTH (the verdicts come from the caller) ─────────────────────────────

/// A submission-shaped listener that has NOT gone through STARTTLS must
/// refuse to take a password in the clear — this is MAP rule 9, and it is
/// the branch a configuration mistake (auth advertised, TLS forgotten)
/// would silently walk past.
#[test]
fn auth_in_the_clear_is_refused_even_where_auth_is_offered() {
    let mut session = Session::new(
        extensions("mx.test", false, true),
        Limits::default(),
        AddressPolicy::from_state(&state()),
    );
    session.command(&Command::Ehlo("client.test".to_owned()));
    let reply = line(&mut session, "AUTH PLAIN AHRlc3QA");
    assert_eq!(reply.code, 538, "{reply:?}");
    assert_eq!(session.authenticated(), None);
}

/// The bare `postmaster` spelling is qualified case-insensitively: the
/// exemption RFC 5321 gives the name does not depend on how the client
/// spelled it. (The parse-level acceptance is `Mailbox::parse`'s; this
/// pins the qualification the session applies to what it accepted.)
#[test]
fn the_bare_postmaster_is_qualified_the_same_however_it_is_spelled() {
    let session = greeted_inbound();
    // Built as literals rather than through `Mailbox::parse`: the parser
    // normalizes the bare name to lowercase on the way in, so only a
    // hand-built path reaches `qualify` with a mixed spelling intact —
    // and the case-insensitive rule lives in `qualify`, not the parser.
    for spelling in ["Postmaster", "POSTMASTER", "postmaster"] {
        let path = Mailbox::Address {
            local: spelling.to_owned(),
            domain: String::new(),
            utf8: false,
            routed: false,
        };
        assert_eq!(
            session.qualify(&path).as_text(),
            "postmaster@mx.test",
            "{spelling} qualified wrong"
        );
    }
    // A spelled-out postmaster with a domain is qualified as itself, and
    // so is every other address.
    let with_domain = Mailbox::parse("postmaster@example.com", false).unwrap();
    assert_eq!(
        session.qualify(&with_domain).as_text(),
        "postmaster@example.com"
    );
}

#[test]
fn auth_is_not_offered_on_the_inbound_listener() {
    let mut session = greeted_inbound();
    let reply = line(&mut session, "AUTH PLAIN AHRlc3QA");
    assert_eq!(reply.code, 502, "{reply:?}");
    assert_eq!(session.authenticated(), None);
}

#[test]
fn the_sender_a_submission_may_claim_is_decided_by_the_policy_layer() {
    // The machine answers `MAIL FROM` on shape alone; *whose* address a
    // client may claim is a policy question the driver asks, and it asks it
    // at RCPT — the same place an existence check happens, so the refusal
    // lands before DATA rather than as a bounce afterwards.
    let policy = AddressPolicy::from_state(&state());
    let claims = [
        ("inbox@example.com", "inbox@example.com", true), // its own
        ("ops@example.com", "inbox@example.com", false),  // somebody else's
        ("inbox@example.com", "sales@example.com", true), // an alias onto it
        ("ops@example.com", "sales@example.com", false),  // an alias onto another
        ("inbox@example.com", "friend@remote.example", false),
    ];
    for (identity, sender, allowed) in claims {
        assert_eq!(
            policy.may_submit_as(identity, sender),
            allowed,
            "{identity} claiming {sender}"
        );
        // Whatever the policy says, the machine itself answers 250 on shape:
        // the binding is not the parser's job and must not pretend to be.
        let mut session = submission(identity);
        let code = line(&mut session, &format!("MAIL FROM:<{sender}>")).code;
        assert_eq!(
            code, 250,
            "{identity} sending as {sender}: the shape is fine"
        );
    }

    // A claimed sender that fails the binding is answered at RCPT with the
    // code for a bad forward-path, and the verdict replaces the provisional
    // 250 — the client never reaches DATA.
    let mut session = submission("ops@example.com");
    line(&mut session, "MAIL FROM:<inbox@example.com>");
    assert_eq!(
        line(&mut session, "RCPT TO:<friend@remote.example>").code,
        250
    );
    let verdict = session.outcome(Outcome::RecipientInvalid);
    assert_eq!(verdict.code, 553);
    assert_eq!(verdict.enhanced, Some("5.1.3"));
}

#[test]
fn a_submission_may_reach_a_remote_recipient_and_an_inbound_transaction_may_not() {
    let mut session = submission("inbox@example.com");
    line(&mut session, "MAIL FROM:<inbox@example.com>");
    let (provisional, verdict) = rcpt(&mut session, "RCPT TO:<friend@remote.example>");
    assert_eq!(provisional.code, 250, "{provisional:?}");
    let verdict = verdict.expect("an accepted RCPT is resolved");
    assert_eq!(verdict.code, 250, "{verdict:?}");

    // The same recipient on a relay listener is a relay attempt, refused at
    // RCPT — never accepted and bounced later.
    let mut session = greeted_inbound();
    line(&mut session, "MAIL FROM:<sender@remote.example>");
    let (provisional, verdict) = rcpt(&mut session, "RCPT TO:<friend@remote.example>");
    assert_eq!(provisional.code, 250);
    let verdict = verdict.expect("an accepted RCPT is resolved");
    assert_eq!(verdict.code, 550, "{verdict:?}");
    assert_eq!(
        verdict.enhanced,
        Some("5.7.1"),
        "relay denial, not no-such-user"
    );
}

#[test]
fn too_many_auth_attempts_closes_the_connection() {
    let mut session = submission("inbox@example.com");
    let reply = session.outcome(Outcome::AuthenticationLockout);
    assert_eq!(reply.code, 421);
    assert_eq!(reply.action, Action::Close);
}

// ── the policy layer, composed the way a driver composes it ──────────────

#[test]
fn an_existing_recipient_is_accepted_and_an_unknown_one_is_refused() {
    let mut session = greeted_inbound();
    line(&mut session, "MAIL FROM:<sender@remote.example>");
    let (provisional, verdict) = rcpt(&mut session, "RCPT TO:<inbox@example.com>");
    assert_eq!(provisional.code, 250);
    let verdict = verdict.expect("an accepted RCPT is resolved");
    assert_eq!(verdict.code, 250);
    assert!(
        session.pending_recipient().is_none(),
        "the pair is complete"
    );
    assert_eq!(session.phase(), Phase::Rcpt);

    // The router has no such mailbox, so the verdict replaces the provisional
    // 250 with the code for "no such user" — and the envelope stays unchanged.
    let (provisional, verdict) = rcpt(&mut session, "RCPT TO:<nobody@example.com>");
    assert_eq!(provisional.code, 250);
    let verdict = verdict.expect("an accepted RCPT is resolved");
    assert_eq!(verdict.code, 550);
    assert_eq!(verdict.enhanced, Some("5.1.1"));
    assert_eq!(session.phase(), Phase::Rcpt);
}

#[test]
fn an_alias_resolves_to_an_existing_recipient() {
    let mut session = greeted_inbound();
    line(&mut session, "MAIL FROM:<sender@remote.example>");
    let (_, verdict) = rcpt(&mut session, "RCPT TO:<sales@example.com>");
    let verdict = verdict.expect("an accepted RCPT is resolved");
    assert_eq!(verdict.code, 250, "the router forwards it: {verdict:?}");
}
