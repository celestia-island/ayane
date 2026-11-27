//! The inbound SMTP side of the ayane mail service, and the delivery consumer
//! that empties the queue it fills.
//!
//! This crate lands in layers. It holds six of them, and four share one
//! property worth stating up front: **they open no socket, read no clock, and
//! keep no state outside themselves.** [`queue`] and [`deliver`] are the ones
//! that touch the disk; [`retry`] is pure arithmetic over what a delivery
//! recorded; [`server`] is the one that owns sockets, timers and TLS — and it
//! owns *nothing else*: every decision it makes is a question it asks one of
//! the layers below.
//!
//! # The session layer — pure logic
//!
//! [`mailbox`] parses a `<path>`, [`command`] parses a command line, [`policy`]
//! answers the two authorisation questions (`MAIL FROM`, `RCPT TO`), and
//! [`session`] is the RFC 5321 state machine that ties them together. A
//! [`Session`] is fed one [`command::Command`] at a time plus the verdicts only
//! the outside world can produce (does this recipient exist? did the queue take
//! it?), and answers with a [`Reply`]. No I/O, no clock: the whole protocol is
//! testable as a table.
//!
//! ## What the session answers, and why the codes are what they are
//!
//! The reply code distinguishes **what is wrong**, because the three cases have
//! three different fixes on the client side, and flattening them teaches the
//! client the wrong lesson:
//!
//! | Wrong thing | Code | What the client must change |
//! | --- | --- | --- |
//! | The command text is not a command (bad syntax, bad path) | `500` / `501` | the line it wrote |
//! | The command is real but this server does not implement it | `500` / `502` | nothing — stop sending it |
//! | The command is real but the **order** is wrong (`RCPT` before `MAIL`, `AUTH` before `EHLO`) | `503` | when it sends it |
//! | The command is real and this server says it is unsupported in this state (`VRFY`) | `500` / `501` | nothing |
//! | The command cannot be carried out now (`NOOP` with no room, an extension this connection did not negotiate) | `504` | the parameter it asked for |
//!
//! The two that get confused most often are the ones this crate keeps apart on
//! purpose: **a shape error is `500`/`501` and a state error is `503`.** A
//! client that gets `503` knows its parser is fine and its sequencing is not; a
//! client that gets `501` knows the opposite. Returning `503` for a malformed
//! command makes well-meaning clients retry the same bytes forever, and
//! returning `501` for a command that arrived too early makes them rewrite a
//! line that was never wrong.
//!
//! `504` is reserved for "the *parameter* is not implemented here" —
//! `MAIL FROM:<> AUTH=<>` on a listener that does not do `AUTH`, or a `BDAT`
//! sized above what this connection will buffer. The command is fine; the
//! argument asked for a capability this server does not have.
//!
//! ## What the session deliberately does *not* do
//!
//! It never decides whether a mailbox exists, whether a password is right, or
//! whether the disk took the message. Those are three different authorities and
//! the driver asks them: [`policy::inbound_recipient`] /
//! [`policy::submission_recipient`] for existence, the [`authn::PasswordVerifier`]
//! trait for credentials, and the caller for the queue outcome. Keeping the
//! answers on the outside is what makes the session a state machine instead of
//! a server.
//!
//! # The spool — the only place that decides what "accepted" means
//!
//! [`queue`] is the file queue a message enters after the server has accepted
//! it.
//!
//! ## What the spool promises
//!
//! A message the server acknowledged is on disk, and the acknowledgement
//! is the last thing that happens: the data file, then the entry that
//! describes it, then the directory holding both. A crash between any two
//! of those steps leaves either a message the queue can still deliver or
//! no trace of a message that was never acknowledged — never a promise
//! the disk did not keep (RFC 5321 §6.1 puts the responsibility on the
//! server from the moment it answers).
//!
//! Recovery is the other half of that promise: a file that does not match
//! its own size and digest is moved aside rather than delivered, and a
//! half-written temporary file is discarded.
//!
//! # The verification layer — pure computation over the octets
//!
//! [`verify`] answers "what does the message claim, and does the claim hold?"
//! and [`zone`] is the DNS side of that question: a fixed zone a caller hands
//! in, which is authoritative for **every name it is asked about** — it is not
//! scoped to the names it lists — so the whole layer runs without a resolver,
//! a network or a listener. A lookup that misses is answered *negatively* (no
//! records) and never falls through to the network, which is why a run with no
//! network measures the verifier instead of an outage.
//!
//! ## The verification order, and why it is that order
//!
//! ```text
//! SPF (envelope)  ──►  DKIM (message)  ──►  ARC (evidence)  ──►  DMARC  ──►  local policy
//!                                                                          (the driver)
//! ```
//!
//! The order is not a preference, but it is also not asserted anywhere:
//! DMARC's result is a function of SPF's and DKIM's, so it cannot come
//! earlier; SPF needs no header bytes, so it need not come later; ARC is
//! evidence *about earlier hops* and never overrides a DKIM verdict. The legs
//! are independent enough that reordering them would not change any verdict —
//! which is why [`Verifier::verify`] runs them in this order and this section
//! states the reason, rather than a test claiming to protect it.
//!
//! ## `Received:` is only ever prepended, at the top
//!
//! [`Verification::prepend`] is the block the spool writes in front of the
//! bytes that were verified, `Received:` first. Nothing else about the message
//! moves: RFC 5321 §4.4 makes each hop responsible for its own trace field in
//! front of everything that arrived, and a DKIM signature may itself sign
//! `Received:` (RFC 6376 Appendix A.2 does), so an insertion anywhere else — or
//! a rewrite of an existing field — would invalidate a signature that was
//! valid on the wire.
//!
//! ## Fail-closed is a verdict here, a refusal in the driver
//!
//! This layer decides; it does not refuse. [`PolicyVerdict::Reject`] is what a
//! DMARC failure under `p=reject` / `p=quarantine` yields, and turning that
//! into the 5xx at the end of `DATA` is the driver's act — the same split as
//! the session layer, which never decides whether a mailbox exists either. A
//! DNS outage yields accept-with-`temperror` rather than a rejection, because a
//! temporary failure must not lose mail; what it must never do is read as
//! `pass`, and it does not.
//!
//! # The delivery consumer — where a message goes after the 250
//!
//! [`deliver`] is the other half of the queue, and it owns the two decisions
//! the spool cannot make:
//!
//! 1. **Where each recipient goes.** It asks [`ayane_mail::route`] — the same
//!    pure router `RCPT` consults, so a message is delivered where the
//!    transaction said it would be — and then writes a maildir, writes the
//!    quarantine, or re-enqueues a forward. It never re-decides policy.
//! 2. **Whether a failure is retried.** [`retry`] is the ladder: first hour
//!    twice, then every few hours, five days at the outside (RFC 5321
//!    §4.5.4.1), with the horizon and the attempt cap configurable. When the
//!    horizon ends the recipient is bounced with an RFC 3464 report — unless
//!    the reverse-path is null, which is the one recipient a mail system may
//!    never bounce (RFC 5321 §6.1).
//!
//! The crash story is the spool's plus one file: the claim moves a message out
//! of `new/`, the maildir write is ordered so that a crash duplicates rather
//! than loses (see [`deliver`]), and recovery puts a message a dead consumer
//! left behind back into the queue.
//!
//! # The listener split is structural, not configured
//!
//! [`policy`] answers two *different listeners*, not one listener with a flag:
//! a relay listener (port 25) accepts mail only for hosted domains, and a
//! submission listener (465/587) accepts remote recipients but only from an
//! authenticated client whose `MAIL FROM` is bound to its own mailbox. Those
//! are two security postures, and a boolean between them is a boolean an
//! operator can set wrong. They are two functions, chosen by the driver from
//! the socket it is on.
//!
//! # The driver — the one layer that owns the outside world
//!
//! [`server`] is a tokio I/O driver over the layers below it, and its job is
//! to keep every bound those layers *cannot* see: the RFC 5321 §4.5.3.2
//! timers, the command and body line limits, the per-IP connection cap, the
//! BDAT chunk buffer, the **header section bound** the streaming verifier
//! needs from it, and the per-address AUTH failure budget a reconnect cannot
//! reset. It also chooses the listener's posture — the
//! [`ListenerRole`] it was configured with decides which
//! recipient function runs at `RCPT`, and that choice is asserted by a test
//! that drives the real driver code over a real socket rather than a copy of
//! its logic.
//!
//! The split is what makes the security properties testable: the state machine
//! is a table, the router is a function, the spool is a file layout, and the
//! driver is the only part that has to be exercised by talking to it.

#![warn(missing_docs)]

pub mod authn;
pub mod command;
pub mod deliver;
pub mod imap_server;
pub mod imap_session;
pub mod mailbox;
pub mod maildir_reader;
pub mod metrics;
pub mod outbound;
pub mod policy;
pub mod queue;
pub mod retry;
pub mod server;
pub mod session;
pub mod verify;
pub mod zone;

pub use authn::{valid_identity, DenyAll, PasswordVerifier, SaslError};
pub use command::{Command, ParseError};
pub use deliver::{
    AuditEvent, Defaults, Deliverer, DeliveryRecord, DeliveryReport, Disposition, MaildirHook,
    MaildirStep, MaildirSync, RecipientOutcome, RecipientReport, RecordedRecipient, RemoteReply,
    RemoteReport, RemoteRequest, RemoteTransport, DEFAULTS,
};
pub use imap_server::{serve as serve_imap, ImapConfig};
pub use mailbox::{Mailbox, MailboxError, POSTMASTER};
pub use maildir_reader::{
    digest as message_digest, FlagChange, Flags, FolderListing, ListingRow, MaildirReader,
    MessageId, OpenedMessage, ReaderError, Renamed, DRAFTS, INBOX as INBOX_FOLDER,
    SENT as SENT_FOLDER, STARRED_FOLDERS, TRASH as TRASH_FOLDER,
};
pub use metrics::{
    Counter, DomainTraffic, Metrics, MetricsDelivery, PeerTraffic, TrafficSnapshot, TrafficTotals,
};
pub use outbound::{
    Outbound, Resolver, Signer, StaticResolver, SyncedTransport, TlsPolicy, ZoneResolver,
};
pub use policy::{inbound_recipient, submission_recipient, AddressPolicy, ListenerRole};
pub use policy::{RecipientVerdict, SessionRefusal, Verdict};
pub use queue::{
    Envelope, FsyncEvent, FsyncKind, FsyncObserver, FsyncOp, QueueState, QueuedMessage, Spool,
    StagedMessage, SyncHook,
};
pub use retry::{RecipientState, RetryClass, RetryDecision, RetryPolicy};
pub use server::{serve, AuthGate, AuthGuard, ServerConfig, ServerError};
pub use session::{Action, Extensions, Limits, Outcome, Phase, Reply, Session};
pub use verify::{
    decide, BodyDigest, BodyHasher, PolicyVerdict, SessionFacts, StreamedMessage, Verification,
    Verifier, VerifyError,
};
pub use zone::{FixedCache, FixedZone};
