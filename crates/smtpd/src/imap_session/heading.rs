//! What a session says about itself and how it answers a command: the
//! greeting and capability list, `LOGIN`/`AUTHENTICATE`, the answer to one
//! `STARTTLS`, and the dispatcher that hands every other command to
//! [`super::commands`].

use ayane_proto::Address;
use imap_codec::imap_types::response::{Code, Status};

use crate::authn::PasswordVerifier;
use crate::maildir_reader::MaildirReader;

use super::session::{ImapSession, State, Transport};
use super::wire::{capabilities, line, trim_crlf};
use super::Kind;

impl<'a> ImapSession<'a> {
    /// A session for `mailbox`, reached over `transport`.
    #[must_use]
    pub fn new(
        hostname: impl Into<String>,
        mailbox: Address,
        reader: MaildirReader,
        transport: Transport,
        passwords: &'a dyn PasswordVerifier,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            mailbox,
            reader,
            transport,
            state: State::NotAuthenticated,
            selected: None,
            passwords,
            starttls: true,
            condstore_enabled: false,
            qresync_enabled: false,
        }
    }

    /// Records whether the listener has a certificate to offer `STARTTLS` with.
    #[must_use]
    pub fn with_starttls(mut self, starttls: bool) -> Self {
        self.starttls = starttls;
        self
    }

    /// The state the session is in.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The greeting the caller writes first (RFC 3501 §7.1).
    #[must_use]
    pub fn greeting(&self) -> Vec<u8> {
        let mut out = self.notice(
            Code::Capability(capabilities(self.transport, self.starttls)),
            &self.hostname,
        );
        trim_crlf(&mut out);
        out.extend_from_slice(b" IMAP4rev1 ready\r\n");
        out
    }

    /// What this connection advertises, as text.
    #[must_use]
    pub fn capabilities(&self) -> &'static str {
        match (self.transport, self.starttls) {
            (Transport::Clear, true) => {
                "IMAP4rev1 STARTTLS LOGINDISABLED MOVE LITERAL+ ENABLE UIDPLUS CONDSTORE QRESYNC"
            }
            (Transport::Clear, false) => {
                "IMAP4rev1 LOGINDISABLED MOVE LITERAL+ ENABLE UIDPLUS CONDSTORE QRESYNC"
            }
            (Transport::Tls, _) => {
                "IMAP4rev1 AUTH=PLAIN MOVE LITERAL+ ENABLE UIDPLUS CONDSTORE QRESYNC"
            }
        }
    }

    // ── the connection half ──────────────────────────────────────────────
    //
    // What is below is the *same* protocol state, entered from the socket's
    // side rather than from a command's. A connection asks the state machine
    // for the parts of RFC 3501 §3 that happen before a mailbox exists — the
    // unauthenticated `CAPABILITY`/`NOOP`/`LOGOUT`/`STARTTLS`, and the
    // refusals for everything else — and then hands over to
    // [`ImapSession::handle`] once [`ImapSession::mark_authenticated`] has
    // said who the client is. All of it renders through the same `line`
    // helper, so a reply written here is spelled exactly as the same reply
    // written from `handle`.

    /// Records that the connection's credential check succeeded.
    ///
    /// Called by the listener *after* it has verified the password: the
    /// session exists for one mailbox and is built over the account the
    /// credential opened, so this takes the check's result as a fact rather
    /// than repeating it. It leaves the session in [`State::Authenticated`].
    pub fn mark_authenticated(&mut self) {
        self.state = State::Authenticated;
    }

    /// The tagged `OK` that answers a successful `LOGIN` / `AUTHENTICATE`.
    #[must_use]
    pub fn logged_in(&self, tag: &str) -> Vec<u8> {
        line(
            tag,
            Kind::Ok,
            Some(Code::Capability(capabilities(
                self.transport,
                self.starttls,
            ))),
            "Logged in",
            true,
        )
    }

    /// The untagged `OK [CAPABILITY …]` line a `CAPABILITY` command answers
    /// with, and the greeting carries.
    #[must_use]
    pub fn notice_line(&self) -> Vec<u8> {
        self.notice(
            Code::Capability(capabilities(self.transport, self.starttls)),
            &self.hostname,
        )
    }

    /// The untagged `BYE` that ends a `LOGOUT`.
    #[must_use]
    pub fn bye_line(&self) -> Vec<u8> {
        self.contained(&Status::bye(None, "Logging out").expect("bye"))
    }

    /// The untagged `OK [<code>] …` line a command answers with, for the
    /// commands a connection answers before a session exists.
    #[must_use]
    pub fn notice_with(&self, code: Code<'_>, text: &str) -> Vec<u8> {
        self.notice(code, text)
    }

    /// The tagged `OK` that completes a command, for the commands a
    /// connection answers itself.
    #[must_use]
    pub fn done(&self, tag: &str, name: &str) -> Vec<u8> {
        self.ok(tag, &format!("{name} completed"))
    }

    /// A tagged `NO` line, for the answers a connection writes itself before
    /// it has a session to ask.
    #[must_use]
    pub fn refuse_no(&self, tag: &str, text: &str) -> Vec<u8> {
        line(tag, Kind::No, None, text, true)
    }

    /// A tagged `BAD` line, for the same reason as [`ImapSession::refuse_no`].
    #[must_use]
    pub fn refuse_bad(&self, tag: &str, text: &str) -> Vec<u8> {
        line(tag, Kind::Bad, None, text, true)
    }

    /// The line that answers `STARTTLS` — no CRLF, because the handshake
    /// follows it (RFC 3501 §6.2.1).
    #[must_use]
    pub fn starttls_line(tag: &str) -> Vec<u8> {
        line(tag, Kind::Ok, None, "Begin TLS negotiation now", false)
    }
}
