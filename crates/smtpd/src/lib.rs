//! The inbound SMTP side of the ayane mail service.
//!
//! This crate lands in layers. Right now it holds two of them, and they share
//! one property worth stating up front: **neither opens a socket, reads a
//! clock, or keeps state outside itself.**
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
//! # The listener split is structural, not configured
//!
//! [`policy`] answers two *different listeners*, not one listener with a flag:
//! a relay listener (port 25) accepts mail only for hosted domains, and a
//! submission listener (465/587) accepts remote recipients but only from an
//! authenticated client whose `MAIL FROM` is bound to its own mailbox. Those
//! are two security postures, and a boolean between them is a boolean an
//! operator can set wrong. They are two functions, chosen by the driver from
//! the socket it is on.

#![warn(missing_docs)]

pub mod authn;
pub mod command;
pub mod mailbox;
pub mod policy;
pub mod queue;
pub mod session;

pub use authn::{valid_identity, DenyAll, PasswordVerifier, SaslError};
pub use command::{Command, ParseError};
pub use mailbox::{Mailbox, MailboxError, POSTMASTER};
pub use policy::{inbound_recipient, submission_recipient, AddressPolicy, ListenerRole};
pub use policy::{RecipientVerdict, SessionRefusal, Verdict};
pub use queue::{
    Envelope, FsyncEvent, FsyncKind, FsyncObserver, FsyncOp, QueueState, QueuedMessage, Spool,
    StagedMessage, SyncHook,
};
pub use session::{Action, Extensions, Limits, Outcome, Phase, Reply, Session};
