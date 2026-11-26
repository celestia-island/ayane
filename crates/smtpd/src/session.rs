//! The RFC 5321 session state machine — pure logic, no I/O, no clock.
//!
//! One [`Session`] per connection. The driver feeds it commands (already
//! parsed by [`crate::command`]) and the verdicts of the pieces that need the
//! outside world (recipient existence, queue outcome) and gets back a
//! [`Reply`] plus an [`Action`] saying what the transport must do next.
//! Nothing here performs I/O, which is what makes the legal/illegal command
//! matrix a plain table test.
//!
//! State progression (RFC 5321 §4.1.4):
//!
//! ```text
//! Connected ──HELO/EHLO──► Greeted ──MAIL──► Mail ──RCPT──► Rcpt ──DATA──► Data
//!                                ▲                          └──BDAT──► Bdat
//!                                └──────── RSET / end of message ───────┘
//! ```
//!
//! `STARTTLS` and a successful `AUTH` return to `Connected`/`Greeted` after
//! discarding every envelope fact (§4.1.4: the server forgets what it learned
//! before the security layer changed).

use std::fmt;

use crate::command::AuthMechanism;
use crate::mailbox::Mailbox;
use crate::policy::AddressPolicy;

/// The phase of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Connected, greeting sent, no HELO/EHLO yet.
    Connected,
    /// After HELO/EHLO.
    Greeted,
    /// After a successful `MAIL FROM`.
    Mail,
    /// At least one `RCPT TO` accepted.
    Rcpt,
    /// `DATA` was accepted; the transport is reading the dot-terminated body.
    Data,
    /// A `BDAT` chunk chain is open; the client keeps sending chunks.
    Bdat,
}

/// How the session was greeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloMode {
    /// `HELO` — no ESMTP extensions in effect.
    Helo,
    /// `EHLO` — extensions in effect.
    Ehlo,
}

/// The transaction in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    /// No `MAIL FROM` in progress.
    Idle,
    /// A reverse-path and its parameters are known.
    Open(Envelope),
}

/// The envelope of the transaction in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The reverse-path (RFC 5321 §4.1.1.2).
    pub sender: Mailbox,
    /// The `SIZE=` estimate, when the client sent one.
    pub declared_size: Option<u64>,
    /// `SMTPUTF8` was requested and is advertised.
    pub smtputf8: bool,
    /// Recipients accepted so far, in arrival order.
    pub recipients: Vec<Mailbox>,
}

/// A message ready for the driver to hand to the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView<'a> {
    /// The reverse-path.
    pub sender: &'a Mailbox,
    /// Every recipient accepted in this transaction.
    pub recipients: &'a [Mailbox],
    /// `SMTPUTF8` was in effect.
    pub smtputf8: bool,
    /// The declared size, when the client sent one.
    pub declared_size: Option<u64>,
}

/// What the transport has to do after a [`Reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send the reply and read the next command line.
    Continue,
    /// Send the reply, then consume exactly this many raw octets (a BDAT
    /// chunk) before reading another command.
    ReadChunk(u64),
    /// Send the reply, then read the rest of the connection as message body
    /// until `<CRLF>.<CRLF>`.
    ReadData,
    /// Send the reply, then run the TLS handshake. **Every octet buffered
    /// before this reply must be thrown away** (VU#555316).
    StartTls,
    /// Send the reply, then read one SASL response line.
    ReadAuth(AuthContinuation),
    /// Send the reply and close the connection.
    Close,
}

/// The SASL step the transport must drive after a `334` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthContinuation {
    /// Waiting for the base64 initial response of `AUTH PLAIN`.
    Plain,
    /// Waiting for the base64 user name of `AUTH LOGIN`.
    LoginUser,
    /// Waiting for the base64 password of `AUTH LOGIN`.
    LoginPassword,
}

/// One SMTP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The three-digit code.
    pub code: u16,
    /// The enhanced status code (RFC 3463), when the reply carries one.
    pub enhanced: Option<&'static str>,
    /// The text after the code.
    pub text: String,
    /// Extra lines before the last (the EHLO capability list).
    pub lines: Vec<String>,
    /// What the transport does next.
    pub action: Action,
}

impl Reply {
    fn new(code: u16, enhanced: Option<&'static str>, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced,
            text: text.into(),
            lines: Vec::new(),
            action: Action::Continue,
        }
    }

    fn with_action(mut self, action: Action) -> Self {
        self.action = action;
        self
    }

    /// Builds the EHLO answer from the capability lines (each already carrying
    /// its `250-` prefix except the last, which is rewritten to `250 `).
    fn from_capabilities(lines: Vec<String>) -> Self {
        // The wire form is `250-<cap>` for every line but the last, which is
        // `250 <cap>`; `to_wire` adds that prefix, so the list drops the
        // continuation marker here and the last line's marker is what makes
        // the reply terminate.
        Self {
            code: 250,
            enhanced: None,
            text: lines.last().cloned().unwrap_or_default(),
            // Every line but the last; the last one is the terminating line
            // and travels in `text`.
            lines: lines
                .iter()
                .take(lines.len().saturating_sub(1))
                .cloned()
                .collect(),
            action: Action::Continue,
        }
    }

    /// Renders the reply as wire bytes, CRLF-terminated, with multi-line
    /// continuation exactly as RFC 5321 §4.2.1 requires.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.lines.len() * 32);
        let code = format!("{:03}", self.code);
        for line in &self.lines {
            out.extend_from_slice(code.as_bytes());
            out.push(b'-');
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(code.as_bytes());
        out.push(b' ');
        if let Some(enhanced) = self.enhanced {
            out.extend_from_slice(enhanced.as_bytes());
            out.push(b' ');
        }
        out.extend_from_slice(self.text.as_bytes());
        out.extend_from_slice(b"\r\n");
        out
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {}", self.code, self.text)
    }
}

/// The extensions the session advertises on EHLO, decided by configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extensions {
    /// The `SIZE` limit in octets; always advertised (RFC 1870 §4).
    pub max_message_size: u64,
    /// Offer `STARTTLS` — only on a listener that can upgrade.
    pub starttls: bool,
    /// SASL mechanisms to advertise; empty on a listener that takes no
    /// submissions.
    pub auth: Vec<AuthMechanism>,
    /// Advertise `SMTPUTF8` (RFC 6531).
    pub smtputf8: bool,
    /// Advertise `8BITMIME` (RFC 6152) — the spool stores octets unchanged.
    pub eight_bit_mime: bool,
    /// This listener's own name: the greeting hostname, and the domain a bare
    /// `postmaster` (RFC 5321 §4.1.3) is qualified with, so the envelope names
    /// the mailbox a delivery agent can route.
    pub hostname: String,
}

impl Default for Extensions {
    fn default() -> Self {
        Self {
            max_message_size: 25 * 1024 * 1024,
            starttls: false,
            auth: Vec::new(),
            smtputf8: true,
            eight_bit_mime: true,
            hostname: String::new(),
        }
    }
}

/// Parameters that bound one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Refuse the `n`-th `RCPT` beyond this.
    pub max_recipients: usize,
    /// Refuse the `n`-th message of one connection beyond this.
    pub max_messages: usize,
    /// Refuse a `BDAT` that would push the message past this.
    pub max_message_size: u64,
    /// AUTH attempts per connection.
    pub max_auth_attempts: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_recipients: 100,
            max_messages: 50,
            max_message_size: 25 * 1024 * 1024,
            max_auth_attempts: 5,
        }
    }
}

/// Verdicts the session asks the transport for, already decided elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `RCPT` verdict: the mailbox exists (account, shared mailbox or alias).
    RecipientAccepted,
    /// `RCPT` verdict: no such mailbox here.
    RecipientUnknown,
    /// `RCPT` verdict: the policy layer refuses the address shape.
    RecipientInvalid,
    /// `RCPT` verdict: the transaction may not relay there unauthenticated.
    RelayDenied,
    /// `STARTTLS` is not available.
    TlsUnavailable,
    /// `AUTH` succeeded; the transport supplies the authenticated identity.
    Authenticated(String),
    /// `AUTH` failed.
    AuthenticationFailed,
    /// The AUTH identity is not a mailbox at all (a control octet, no `@`, an
    /// empty field): a syntax answer, `501`, and no verdict on any credential.
    AuthenticationIdentityInvalid,
    /// Too many AUTH attempts: the driver must close after replying.
    AuthenticationLockout,
    /// Too many AUTH **failures from this peer address**, across connections:
    /// the attempt is not even checked, the reply is `421`, and the connection
    /// closes.
    ///
    /// The budget lives in the **driver**, not here. A per-connection counter
    /// is a counter a reconnect resets, so the limit that matters is keyed by
    /// peer address and outlives any one session; this variant is how that
    /// driver tells the session it has already refused. Nothing in this state
    /// machine may keep the ledger — it holds no peer address and no clock.
    PeerAuthenticationLockout {
        /// How long the peer has to wait before another attempt.
        retry_after: std::time::Duration,
    },
}

/// The session. Construct with [`Session::new`], then feed it commands.
#[derive(Debug, Clone)]
pub struct Session {
    phase: Phase,
    hello: Option<(HelloMode, String)>,
    transaction: Transaction,
    extensions: Extensions,
    limits: Limits,
    policy: AddressPolicy,
    authenticated: Option<String>,
    tls_active: bool,
    messages_delivered: usize,
    chunk_bytes: u64,
    auth_attempts: usize,
    /// Set when the transport failed mid-transfer; the next command must fail
    /// the transaction and reset it (there is no other way to abort a BDAT
    /// chain halfway, RFC 3030 §4.2).
    abort_pending: bool,
    /// A `RCPT` whose existence is being decided: the forward-path as the
    /// client wrote it, and what it is to be recorded as once accepted.
    pending_recipient: Option<(Mailbox, Mailbox)>,
    /// The `BDAT` chunk whose octets the transport is reading, when a read is
    /// in flight: its declared size and whether it ended the message.
    pending_chunk: Option<(u64, bool)>,
}

impl Session {
    /// A fresh session, offered the given extensions on EHLO.
    #[must_use]
    pub fn new(extensions: Extensions, limits: Limits, policy: AddressPolicy) -> Self {
        Self {
            phase: Phase::Connected,
            hello: None,
            transaction: Transaction::Idle,
            extensions,
            limits,
            policy,
            authenticated: None,
            tls_active: false,
            messages_delivered: 0,
            chunk_bytes: 0,
            auth_attempts: 0,
            abort_pending: false,
            pending_recipient: None,
            pending_chunk: None,
        }
    }

    /// Marks the connection as already running over TLS (implicit TLS on 465).
    pub fn set_tls_active(&mut self) {
        self.tls_active = true;
        self.extensions.starttls = false;
    }

    /// The phase, for the driver and tests.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The greeting mode and name, once greeted.
    #[must_use]
    pub fn hello(&self) -> Option<(HelloMode, &str)> {
        self.hello
            .as_ref()
            .map(|(mode, name)| (*mode, name.as_str()))
    }

    /// The transaction in progress.
    #[must_use]
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// The transaction as a view over its parts, when one is open.
    #[must_use]
    pub fn envelope(&self) -> Option<TransactionView<'_>> {
        match &self.transaction {
            Transaction::Idle => None,
            Transaction::Open(envelope) => Some(TransactionView {
                sender: &envelope.sender,
                recipients: &envelope.recipients,
                smtputf8: envelope.smtputf8,
                declared_size: envelope.declared_size,
            }),
        }
    }

    /// Whether the next `RCPT` would exceed [`Limits::max_recipients`]; the
    /// driver answers 452 itself, so it needs to know before asking the
    /// router.
    #[must_use]
    pub fn at_recipient_limit(&self) -> bool {
        match &self.transaction {
            // The pending slot (if any) is not yet part of the envelope, so
            // the count of accepted recipients plus one more is exactly the
            // size the transaction would reach.
            Transaction::Open(envelope) => {
                envelope.recipients.len() + 1 > self.limits.max_recipients
            }
            Transaction::Idle => false,
        }
    }

    /// The recipient whose existence is being decided, if a `RCPT` is open —
    /// the forward-path as the client wrote it.
    #[must_use]
    pub fn pending_recipient(&self) -> Option<&Mailbox> {
        self.pending_recipient.as_ref().map(|(written, _)| written)
    }

    /// The authenticated identity, when one exists.
    #[must_use]
    pub fn authenticated(&self) -> Option<&str> {
        self.authenticated.as_deref()
    }

    /// Whether the session is running over TLS.
    #[must_use]
    pub fn tls_active(&self) -> bool {
        self.tls_active
    }

    /// How many messages this connection has completed.
    #[must_use]
    pub fn messages_delivered(&self) -> usize {
        self.messages_delivered
    }

    /// The extensions in effect.
    #[must_use]
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// The octets received by BDAT so far in the open transaction.
    #[must_use]
    pub fn chunk_bytes(&self) -> u64 {
        self.chunk_bytes
    }

    /// Whether AUTH is still open to this connection (attempts left).
    #[must_use]
    pub fn auth_attempts_left(&self) -> usize {
        self.limits
            .max_auth_attempts
            .saturating_sub(self.auth_attempts)
    }

    /// Whether the session is greeted: `EHLO`/`HELO` succeeded and no
    /// security layer change or reset put it back in front of the greeting.
    #[must_use]
    pub fn greeted(&self) -> bool {
        self.phase != Phase::Connected
    }

    /// The greeting the transport must send on connect.
    #[must_use]
    pub fn greeting(hostname: &str, with_tls: bool) -> Reply {
        let mut text = format!("{hostname} ESMTP ayane");
        if !with_tls {
            text.push_str(" (no TLS) ");
        }
        Reply::new(220, None, text)
    }

    /// Applies a parsed command.
    pub fn command(&mut self, command: &crate::command::Command) -> Reply {
        use crate::command::Command;
        match command {
            Command::Hello(name) => self.helo(name),
            Command::Ehlo(name) => self.ehlo(name),
            Command::Mail {
                path,
                size,
                smtputf8,
                unsupported,
            } => self.mail(path, *size, *smtputf8, unsupported.as_deref()),
            Command::Rcpt { path, unsupported } => self.rcpt(path, unsupported.as_deref()),
            Command::Data => self.data(),
            Command::Bdat { size, last } => self.bdat(*size, *last),
            Command::Rset => self.reset(),
            Command::Noop => Reply::new(250, Some("2.0.0"), "OK"),
            Command::Quit => Reply::new(221, Some("2.0.0"), "Bye").with_action(Action::Close),
            Command::Vrfy(_) => Reply::new(
                252,
                Some("2.5.2"),
                "Cannot VRFY user, but will accept message and attempt delivery",
            ),
            Command::StartTls => self.starttls(),
            Command::Auth { mechanism, initial } => self.auth(*mechanism, initial.as_deref()),
        }
    }

    /// Reports the outcome of a decision the transport made.
    pub fn outcome(&mut self, outcome: Outcome) -> Reply {
        match outcome {
            Outcome::RecipientAccepted => self.recipient_accepted(),
            Outcome::RecipientUnknown => {
                self.pending_recipient = None;
                Reply::new(
                    550,
                    Some("5.1.1"),
                    "Recipient address rejected: no such mailbox",
                )
            }
            Outcome::RecipientInvalid => {
                self.pending_recipient = None;
                Reply::new(553, Some("5.1.3"), "Recipient address rejected: bad syntax")
            }
            Outcome::RelayDenied => {
                self.pending_recipient = None;
                Reply::new(550, Some("5.7.1"), "Relay access denied")
            }
            Outcome::TlsUnavailable => {
                self.abandon_transaction();
                self.phase = self.phase_after_reset();
                Reply::new(454, Some("4.7.0"), "TLS not available")
            }
            Outcome::Authenticated(identity) => self.authenticated_reply(identity),
            Outcome::AuthenticationFailed => {
                self.auth_attempts += 1;
                Reply::new(535, Some("5.7.8"), "Authentication failed")
            }
            Outcome::AuthenticationIdentityInvalid => {
                Reply::new(501, Some("5.5.2"), "Bad authentication identity syntax")
            }
            Outcome::AuthenticationLockout => {
                self.auth_attempts = self.limits.max_auth_attempts;
                Reply::new(
                    421,
                    Some("4.7.0"),
                    "Too many authentication attempts, closing",
                )
                .with_action(Action::Close)
            }
            Outcome::PeerAuthenticationLockout { retry_after } => Reply::new(
                421,
                Some("4.7.0"),
                format!(
                    "Too many failed authentication attempts from your host, try again in {} seconds",
                    retry_after.as_secs().max(1)
                ),
            )
            .with_action(Action::Close),
        }
    }

    // ── verbs ────────────────────────────────────────────────────────────

    fn helo(&mut self, name: &str) -> Reply {
        if self.phase == Phase::Bdat || self.phase == Phase::Data {
            return self.sequence_error();
        }
        self.hello = Some((HelloMode::Helo, name.to_owned()));
        self.abandon_transaction();
        self.phase = Phase::Greeted;
        Reply::new(250, Some("2.0.0"), "OK")
    }

    fn ehlo(&mut self, name: &str) -> Reply {
        if self.phase == Phase::Bdat || self.phase == Phase::Data {
            return self.sequence_error();
        }
        self.hello = Some((HelloMode::Ehlo, name.to_owned()));
        self.abandon_transaction();
        self.phase = Phase::Greeted;
        let mut lines = vec![
            "PIPELINING".to_owned(),
            format!("SIZE {}", self.extensions.max_message_size),
            "CHUNKING".to_owned(),
        ];
        if self.extensions.eight_bit_mime {
            lines.push("8BITMIME".to_owned());
        }
        if self.extensions.smtputf8 {
            lines.push("SMTPUTF8".to_owned());
        }
        if self.extensions.starttls && !self.tls_active {
            lines.push("STARTTLS".to_owned());
        }
        if !self.extensions.auth.is_empty() && self.tls_active {
            let list = self
                .extensions
                .auth
                .iter()
                .map(|mechanism| mechanism.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("AUTH {list}"));
        }
        lines.push("ENHANCEDSTATUSCODES".to_owned());
        Reply::from_capabilities(lines)
    }

    fn mail(
        &mut self,
        path: &Mailbox,
        size: Option<u64>,
        smtputf8: bool,
        unsupported: Option<&str>,
    ) -> Reply {
        match self.phase {
            Phase::Data | Phase::Bdat => return self.sequence_error(),
            Phase::Connected => {
                return Reply::new(503, Some("5.5.1"), "Send HELO/EHLO first");
            }
            Phase::Mail | Phase::Rcpt => {
                return Reply::new(503, Some("5.5.1"), "Nested MAIL command");
            }
            Phase::Greeted => {}
        }
        if let Some(param) = unsupported {
            return Reply::new(555, Some("5.5.4"), format!("Unsupported parameter {param}"));
        }
        if matches!(path, Mailbox::Address { utf8: true, .. }) {
            let helo_only = self.hello_mode() == HelloMode::Helo;
            if !smtputf8 || !self.extensions.smtputf8 || helo_only {
                return Reply::new(
                    553,
                    Some("5.6.7"),
                    "Non-ASCII reverse-path without SMTPUTF8",
                );
            }
        }
        if path != &Mailbox::Null {
            if let Err(reason) = self.policy.check_sender(&path.as_text()) {
                return Reply::new(553, Some("5.1.7"), reason);
            }
        }
        if let Some(declared) = size {
            if declared > self.extensions.max_message_size
                || declared > self.limits.max_message_size
            {
                // RFC 1870 §6.2: refuse at MAIL, never after the body arrived.
                return Reply::new(
                    552,
                    Some("5.3.4"),
                    "Message size exceeds fixed maximum message size",
                );
            }
        }
        self.transaction = Transaction::Open(Envelope {
            // RFC 5321 §4.1.3 reads the same in both directions: a bare
            // `postmaster` is this server's, so it is qualified for the
            // envelope exactly as a bare `RCPT TO:<Postmaster>` is.
            sender: self.recorded_recipient(path),
            declared_size: size,
            smtputf8,
            recipients: Vec::new(),
        });
        self.phase = Phase::Mail;
        self.pending_recipient = None;
        Reply::new(250, Some("2.1.0"), "Sender OK")
    }

    fn rcpt(&mut self, path: &Mailbox, unsupported: Option<&str>) -> Reply {
        if self.phase == Phase::Data || self.phase == Phase::Bdat {
            return self.sequence_error();
        }
        let smtputf8 = match &self.transaction {
            Transaction::Open(envelope) => envelope.smtputf8,
            Transaction::Idle => {
                return match self.phase {
                    Phase::Connected => Reply::new(503, Some("5.5.1"), "Send HELO/EHLO first"),
                    _ => Reply::new(503, Some("5.5.1"), "Need MAIL before RCPT"),
                };
            }
        };
        if let Some(param) = unsupported {
            return Reply::new(555, Some("5.5.4"), format!("Unsupported parameter {param}"));
        }
        let recipient_count = match &self.transaction {
            Transaction::Open(envelope) => envelope.recipients.len(),
            Transaction::Idle => 0,
        };
        if recipient_count >= self.limits.max_recipients {
            return Reply::new(452, Some("4.5.3"), "Too many recipients");
        }
        if path == &Mailbox::Null {
            // RFC 5321 §4.1.1.3: the forward-path is never empty.
            return Reply::new(501, Some("5.1.3"), "Bad recipient address syntax");
        }
        if matches!(path, Mailbox::Address { utf8: true, .. }) && !smtputf8 {
            return Reply::new(
                553,
                Some("5.6.7"),
                "Non-ASCII forward-path without SMTPUTF8",
            );
        }
        self.pending_recipient = Some((path.clone(), self.recorded_recipient(path)));
        // The transport decides existence; the provisional 250 is replaced by
        // the verdict the driver reports through [`Session::outcome`].
        Reply::new(250, Some("2.1.5"), "Recipient OK")
    }

    /// The path as the envelope records it.
    ///
    /// RFC 5321 §4.1.3 makes every SMTP server accept `postmaster` without a
    /// domain, as a forward-path and as a reverse-path alike. A domain is
    /// needed to record and route it, so the bare name is qualified with the
    /// domain the session is *named* for — the hostname in the greeting — and
    /// that mailbox is the postmaster account of the host. Every other
    /// domainless path is a syntax error and never reaches this function.
    fn recorded_recipient(&self, path: &Mailbox) -> Mailbox {
        self.qualify(path)
    }

    /// A parsed mailbox with a bare `postmaster` given the domain this session
    /// is named for, and every other mailbox left as it is.
    ///
    /// This is the one rule for "the postmaster of this server" (RFC 5321
    /// §4.1.3), and both places that need it go through it: the envelope
    /// (`MAIL FROM:<postmaster>`, `RCPT TO:<Postmaster>`) and the identity a
    /// client logs in as. Two copies of the rule would be two answers to the
    /// same question — the drift this crate just removed from the identity
    /// check.
    #[must_use]
    pub fn qualify(&self, path: &Mailbox) -> Mailbox {
        match path {
            Mailbox::Address { local, domain, .. }
                if domain.is_empty() && local.eq_ignore_ascii_case(crate::mailbox::POSTMASTER) =>
            {
                Mailbox::Address {
                    local: crate::mailbox::POSTMASTER.to_owned(),
                    domain: self.extensions.hostname.clone(),
                    utf8: false,
                    routed: false,
                }
            }
            other => other.clone(),
        }
    }

    fn recipient_accepted(&mut self) -> Reply {
        if let (Some((_, recorded)), Transaction::Open(envelope)) =
            (self.pending_recipient.take(), &mut self.transaction)
        {
            envelope.recipients.push(recorded);
            self.phase = Phase::Rcpt;
        }
        Reply::new(250, Some("2.1.5"), "Recipient OK")
    }

    fn data(&mut self) -> Reply {
        match self.phase {
            Phase::Rcpt => {}
            Phase::Data | Phase::Bdat => return self.sequence_error(),
            Phase::Connected => {
                return Reply::new(503, Some("5.5.1"), "Send HELO/EHLO first");
            }
            Phase::Greeted | Phase::Mail => {
                return Reply::new(503, Some("5.5.1"), "Need RCPT before DATA");
            }
        }
        if self.abort_pending {
            self.abandon_transaction();
            self.phase = self.phase_after_reset();
            return Reply::new(554, Some("5.6.0"), "Transaction failed");
        }
        self.phase = Phase::Data;
        Reply::new(354, None, "Start mail input; end with <CRLF>.<CRLF>")
            .with_action(Action::ReadData)
    }

    fn bdat(&mut self, size: u64, last: bool) -> Reply {
        if !matches!(self.transaction, Transaction::Open(_)) {
            return match self.phase {
                Phase::Data | Phase::Bdat => self.sequence_error(),
                Phase::Connected => Reply::new(503, Some("5.5.1"), "Send HELO/EHLO first"),
                _ => Reply::new(503, Some("5.5.1"), "Need MAIL before BDAT"),
            };
        }
        if self.phase == Phase::Data {
            // DATA and BDAT are mutually exclusive within a transaction.
            return self.sequence_error();
        }
        if self.phase != Phase::Rcpt && self.phase != Phase::Bdat {
            return Reply::new(503, Some("5.5.1"), "Need RCPT before BDAT");
        }
        if self.abort_pending {
            self.abandon_transaction();
            self.phase = self.phase_after_reset();
            return Reply::new(554, Some("5.6.0"), "Transaction failed");
        }
        let limit = self
            .extensions
            .max_message_size
            .min(self.limits.max_message_size);
        // Each chunk is admitted only if the whole chain stays inside the
        // ceiling; the octets arrive after the reply, so the check is on the
        // declared sizes and is exact.
        let received = self.chunk_bytes.saturating_add(size);
        if received > limit {
            self.abandon_transaction();
            self.phase = self.phase_after_reset();
            return Reply::new(
                552,
                Some("5.3.4"),
                "Message size exceeds fixed maximum message size",
            );
        }
        self.phase = Phase::Bdat;
        self.pending_chunk = Some((size, last));
        // The driver consumes `size` raw octets after this reply, then calls
        // [`Session::chunk_received`]. `LAST` is recorded by the driver, which
        // knows the chunk has been read, and cleared by
        // [`Session::chunk_reading`].
        Reply::new(250, Some("2.0.0"), "OK").with_action(Action::ReadChunk(size))
    }

    /// Whether the chunk the session is waiting for ends the message.
    ///
    /// The driver answers the octets of a non-`LAST` chunk with its own 250
    /// before the session has seen the next command, so it is the session —
    /// not the parsed command — that knows whether the message is complete.
    #[must_use]
    pub fn pending_chunk_is_last(&self) -> bool {
        self.pending_chunk.is_some_and(|(_, last)| last)
    }

    /// The transport started reading the octets of a chunk the session has
    /// already answered. Until it finishes, the chunk is upload in progress
    /// and a reply about its *content* would be a second answer to the same
    /// command; only `421` may cut the connection there.
    pub fn chunk_reading(&mut self) {
        self.pending_chunk = None;
    }

    /// The reply that abandons an open chunk chain whose octets the transport
    /// is not going to read, and closes the connection.
    ///
    /// RFC 3030 §4.2 wants a chunk refused **before** its octets are sent, and
    /// this is the one refusal the session cannot make for itself: a chunk
    /// larger than the transport's buffer is inside the message size, so
    /// `Session::bdat` admits it and the *transport* is what knows it must not
    /// hold those octets. Their octets were never accepted as belonging to the
    /// message, so a `552` after them would answer a command that already had
    /// its `250`; what is left on the wire is not a command stream either, so
    /// the connection ends (RFC 5321 §4.7).
    pub fn chunk_abandon(&mut self) -> Reply {
        self.pending_chunk = None;
        self.abandon_transaction();
        self.phase = Phase::Greeted;
        Reply::new(421, Some("4.3.0"), "BDAT chunk refused, closing connection")
            .with_action(Action::Close)
    }

    /// Records the octets of a BDAT chunk the transport has consumed. Must be
    /// called once per [`Action::ReadChunk`], after the chunk was read.
    pub fn chunk_received(&mut self, size: u64) {
        self.chunk_bytes = self.chunk_bytes.saturating_add(size);
    }

    /// Marks the content of the open transaction as failed. The next command
    /// that belongs to the transaction answers `554` and resets it; this is
    /// the only legal way to abort a BDAT chain (RFC 3030 §4.2).
    pub fn fail_data(&mut self) {
        self.abort_pending = true;
    }

    /// Keeps the connection out of a transaction after a refused `DATA`
    /// transfer until the sender asks for one.
    ///
    /// [`Session::end_of_message`] already resets the envelope when the
    /// transfer fails; what this exists for is the ordering. A sender whose
    /// upload was refused may still be writing — the octets it had queued
    /// behind the terminator, which the driver drains and discards — and the
    /// first of those that *is* a command (`MAIL FROM:…`) must be answered, not
    /// run. Running it would mean a refused transfer produced a new envelope,
    /// which is the transaction-level half of the smuggling this guards
    /// against. Sequencing is the session's business, so the answer is its
    /// `503` and nothing here decides policy.
    pub fn end_after_refusal(&mut self) {
        self.abandon_transaction();
        self.phase = self.phase_after_reset();
    }

    fn starttls(&mut self) -> Reply {
        if self.phase == Phase::Data || self.phase == Phase::Bdat {
            return self.sequence_error();
        }
        if self.tls_active {
            return Reply::new(503, Some("5.5.1"), "TLS already active");
        }
        if !self.extensions.starttls {
            return Reply::new(454, Some("4.7.0"), "TLS not available");
        }
        // Success: everything learned before the handshake is discarded.
        self.hello = None;
        self.authenticated = None;
        self.abandon_transaction();
        self.phase = Phase::Connected;
        self.tls_active = true;
        Reply::new(220, None, "Ready to start TLS").with_action(Action::StartTls)
    }

    fn auth(&mut self, mechanism: AuthMechanism, initial: Option<&str>) -> Reply {
        if self.phase == Phase::Data || self.phase == Phase::Bdat {
            return self.sequence_error();
        }
        if self.extensions.auth.is_empty() {
            return Reply::new(502, Some("5.5.1"), "Authentication not enabled");
        }
        if !self.tls_active {
            // MAP §四 rule 9: no credential is ever accepted on a clear
            // channel. AUTH is not advertised before TLS either, but a client
            // may send it anyway; 538 is the RFC 4954 answer.
            return Reply::new(
                538,
                Some("5.7.0"),
                "Encryption required for requested authentication mechanism",
            );
        }
        if self.authenticated.is_some() {
            return Reply::new(503, Some("5.5.1"), "Already authenticated");
        }
        if self.transaction != Transaction::Idle {
            // RFC 4954 §4: AUTH is invalid with a mail transaction open.
            return Reply::new(
                503,
                Some("5.5.1"),
                "AUTH not permitted during a mail transaction",
            );
        }
        if self.auth_attempts >= self.limits.max_auth_attempts {
            return Reply::new(
                421,
                Some("4.7.0"),
                "Too many authentication attempts, closing",
            )
            .with_action(Action::Close);
        }
        if !self.extensions.auth.contains(&mechanism) {
            return Reply::new(504, Some("5.5.4"), "Unrecognized authentication mechanism");
        }
        // Sans initial response, `AUTH LOGIN` asks for the user name.
        let (text, action) = match (mechanism, initial) {
            (AuthMechanism::Plain, _) => (String::new(), AuthContinuation::Plain),
            (AuthMechanism::Login, None) => {
                ("VXNlcm5hbWU6".to_owned(), AuthContinuation::LoginUser)
            }
            (AuthMechanism::Login, Some(_)) => {
                ("UGFzc3dvcmQ6".to_owned(), AuthContinuation::LoginPassword)
            }
        };
        Reply {
            code: 334,
            enhanced: None,
            text,
            lines: Vec::new(),
            action: Action::ReadAuth(action),
        }
    }

    fn authenticated_reply(&mut self, identity: String) -> Reply {
        self.authenticated = Some(identity);
        // RFC 4954 §4: a successful AUTH discards the transaction.
        self.abandon_transaction();
        self.phase = self.phase_after_reset();
        Reply::new(235, Some("2.7.0"), "Authentication successful")
    }

    fn reset(&mut self) -> Reply {
        if self.phase == Phase::Data {
            // Inside DATA every octet is message content.
            return self.sequence_error();
        }
        // Inside a BDAT chain RSET is the client's way out of the chain
        // (RFC 3030 §4.2): the unfinished message is discarded.
        self.abandon_transaction();
        self.phase = self.phase_after_reset();
        Reply::new(250, Some("2.0.0"), "OK")
    }

    /// The reply that closes a completed `DATA`/`BDAT` transfer.
    ///
    /// The driver calls this only after the queue has durably accepted the
    /// message (for a successful outcome) or after it gave up.
    pub fn end_of_message(&mut self, queue_ok: bool) -> Reply {
        if !queue_ok || self.abort_pending {
            self.abandon_transaction();
            self.phase = self.phase_after_reset();
            return Reply::new(554, Some("5.6.0"), "Transaction failed");
        }
        if self.messages_delivered >= self.limits.max_messages {
            self.abandon_transaction();
            self.phase = Phase::Greeted;
            self.hello = None;
            return Reply::new(
                421,
                Some("4.7.0"),
                "Too many messages on one connection, closing",
            )
            .with_action(Action::Close);
        }
        self.messages_delivered += 1;
        self.abandon_transaction();
        self.phase = self.phase_after_reset();
        Reply::new(250, Some("2.0.0"), "OK: queued")
    }

    fn sequence_error(&self) -> Reply {
        Reply::new(503, Some("5.5.1"), "Bad sequence of commands")
    }

    fn hello_mode(&self) -> HelloMode {
        self.hello
            .as_ref()
            .map_or(HelloMode::Helo, |(mode, _)| *mode)
    }

    fn phase_after_reset(&self) -> Phase {
        if self.hello.is_some() {
            Phase::Greeted
        } else {
            Phase::Connected
        }
    }

    fn abandon_transaction(&mut self) {
        self.transaction = Transaction::Idle;
        self.chunk_bytes = 0;
        self.abort_pending = false;
        self.pending_recipient = None;
        self.pending_chunk = None;
    }
}
