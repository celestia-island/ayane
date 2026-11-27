//! The IMAP4rev1 listener: the socket end of [`crate::imap_session`].
//!
//! [`crate::imap_session`] is the state machine and it opens no socket — it is
//! handed commands and answers with bytes. This module owns the socket, and it
//! is deliberately the *smallest* layer on the IMAP side of this crate: it
//! frames a client's command (literals included), asks the session, and writes
//! what the session said. Every decision about protocol state, identifiers and
//! authorisation stays one layer down, for the same reason
//! [`crate::server`] is not where SMTP's sequencing lives: what the session
//! refuses can be driven as a table, and what this module does can only be
//! exercised by talking to it.
//!
//! # One shape, three listeners
//!
//! [`serve`] has the shape [`crate::server::serve`] has — a bound
//! [`TcpListener`] and an `Arc<ImapConfig>` — because the same caller starts
//! both (the control plane's engine, or the `ayane-smtpd` binary), and a
//! second driver shape would be a second place for the same mistakes. What a
//! listener *is* is one bit, [`ImapConfig::imap_tls`]:
//!
//! | listener | TLS | password |
//! | --- | --- | --- |
//! | IMAPS (`993`) | implicit: the handshake is the first octet | accepted |
//! | IMAP (`143`) | offered as `STARTTLS`, required before `LOGIN` | only after it |
//! | a port with no certificate | none | refused (`LOGINDISABLED`) |
//!
//! The third row is not a mode; it is the second row with no certificate, and
//! it exists because a listener that answers `LOGIN` on an unencrypted socket
//! is the one thing that must never be reachable by accident. A `None`
//! [`ImapConfig::tls`] says *never authenticate here*: the session is told
//! ([`Transport::Clear`]) and refuses, rather than advertising a capability it
//! would not honour.
//!
//! # `LOGIN` is where the session is born
//!
//! An [`ImapSession`] is scoped to one mailbox, and which mailbox is what the
//! client proves — so a connection has no session until a credential check has
//! answered `OK`, and the session it then creates is built over the account
//! that check opened. Before that, the connection answers the small
//! unauthenticated half of RFC 3501 §3 itself (`CAPABILITY`, `NOOP`,
//! `LOGOUT`, `STARTTLS`) through the same rendering the session uses, so the
//! wire spelling of a reply does not depend on which layer wrote it.
//!
//! # `STARTTLS` is a state transition this module performs
//!
//! The session answers `STARTTLS` with [`Outcome::start_tls`] — a line with no
//! CRLF, because a handshake is what follows it. This module writes that line,
//! flushes, and *then* hands the socket to the acceptor. Three consequences
//! are load-bearing:
//!
//! - the greeting is never written before the handshake on an implicit-TLS
//!   port (RFC 8314 §3.3, the rule the 465 listener already follows);
//! - the reader takes one octet at a time, so it cannot read past the
//!   `STARTTLS` line and swallow a command the client sent behind it into a
//!   buffer the TLS layer would then read as plaintext;
//! - the upgrade **refuses** a connection whose buffer still holds octets: a
//!   command a client injects in front of its own handshake is the classic
//!   plaintext-injection hole (RFC 3501 §6.2.1), and this is where it closes.
//!
//! # What this module bounds
//!
//! A listener is reachable by anyone who can open a TCP connection, so the
//! reader is bounded before the session is: a command line past
//! [`MAX_LINE_BYTES`], a command with its literals past
//! [`MAX_COMMAND_BYTES`], a literal announced larger than what is left of that
//! bound, and a connection idle past [`ImapConfig::command_timeout`] are each
//! answered with a tagged `BAD` (or a `* BYE`) and a closed socket. None of
//! them is the session's to impose — they are facts about a socket, and the
//! session's input arrives already framed.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use imap_codec::decode::{CommandDecodeError, Decoder};
use imap_codec::imap_types::core::LiteralMode;
use imap_codec::CommandCodec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::authn::PasswordVerifier;
use crate::imap_session::{ImapSession, Outcome, Transport, MAX_COMMAND_BYTES, MAX_LINE_BYTES};
use crate::maildir_reader::MaildirReader;
use crate::server::{PerIpLimiter, ServerError};

/// How much of a command's **first line** is read in one call, at most.
///
/// The first read of a command may take a whole line (a line is everything up
/// to its CRLF, so it can never contain octets the client sent behind the
/// command); this only bounds how long a line may be, and
/// [`MAX_LINE_BYTES`] is the bound that refuses one. Every read after the
/// first line takes a single octet (`Connection::next_octet`).
pub const IMAP_READ_SLICE: usize = 4096;

/// The RFC 3501 §5.4 autologout timer: thirty minutes of no command.
pub const AUTOLOGOUT: Duration = Duration::from_secs(30 * 60);

/// A bidirectional stream, so one connection runs over plain TCP and TLS with
/// the same code.
trait AsyncIoStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncIoStream for T {}

/// Everything an IMAP listener needs to run.
///
/// There is no per-listener role here, unlike SMTP's
/// [`crate::policy::ListenerRole`]: an IMAP listener serves exactly one mailbox
/// per connection, and *which* mailbox is what the client proves at `LOGIN`,
/// not what the socket is bound for. What the socket decides is whether a
/// password may cross it — [`ImapConfig::tls`].
pub struct ImapConfig {
    /// The name in the greeting and the log.
    pub hostname: String,
    /// Where mailboxes live — the same root the delivery consumer writes into.
    pub mail_root: std::path::PathBuf,
    /// The credential check `LOGIN` and `AUTHENTICATE PLAIN` run.
    pub passwords: Arc<dyn PasswordVerifier>,
    /// The TLS acceptor. `None` is a listener that offers no encryption and
    /// therefore refuses every login; see the module documentation.
    pub tls: Option<TlsAcceptor>,
    /// Whether TLS comes *before* the greeting (IMAPS, 993) rather than after
    /// it (`STARTTLS`, 143). Ignored when [`ImapConfig::tls`] is `None`.
    pub imap_tls: bool,
    /// Concurrent connections from one client IP.
    pub per_ip_limit: usize,
    /// The RFC 3501 §5.4 autologout timer.
    pub command_timeout: Duration,
}

impl std::fmt::Debug for ImapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapConfig")
            .field("hostname", &self.hostname)
            .field("mail_root", &self.mail_root)
            .field("tls", &self.tls.is_some())
            .field("imap_tls", &self.imap_tls)
            .field("per_ip_limit", &self.per_ip_limit)
            .field("command_timeout", &self.command_timeout)
            .finish_non_exhaustive()
    }
}

impl ImapConfig {
    /// The transport a connection starts with, before any upgrade.
    #[must_use]
    pub fn transport(&self) -> Transport {
        if self.imap_tls && self.tls.is_some() {
            Transport::Tls
        } else {
            Transport::Clear
        }
    }
}

/// Serves IMAP connections until the task is cancelled.
///
/// The same contract as [`crate::server::serve`]: each connection runs in its
/// own task, a peer over the per-IP cap is greeted-and-closed rather than
/// dropped (a client that sees a `BYE` knows the server is there and
/// overloaded; a reset looks like a network fault), and a connection that
/// fails only closes itself.
///
/// # Errors
///
/// Returns [`ServerError::Io`] when accepting on the socket fails permanently.
pub async fn serve(listener: TcpListener, config: Arc<ImapConfig>) -> Result<(), ServerError> {
    let limiter = Arc::new(PerIpLimiter::new(config.per_ip_limit));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(permit) = limiter.acquire(peer.ip()) else {
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = stream
                    .write_all(b"* BYE Too many concurrent connections from your host\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
            continue;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _permit = permit;
            let mut connection = Connection::new(stream, config);
            let outcome = connection.run().await;
            if let Err(err) = outcome {
                tracing::debug!(%peer, "imap connection closed: {err}");
            }
        });
    }
}

/// The stream a connection owns.
type Stream = Pin<Box<dyn AsyncIoStream>>;

/// What reading another octet found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filled {
    /// An octet arrived (it is in the buffer that was read into).
    Data,
    /// The peer closed its side.
    Eof,
    /// The autologout timer fired: nothing arrived in time.
    TimedOut,
}

/// Where the command being assembled has got to in its lines.
///
/// It is what decides how much the next read may take: a command's first line
/// is one line by definition, and past its CRLF anything waiting on the socket
/// belongs to a later command — or to a `STARTTLS`'s handshake, which must not
/// be read as if it had already crossed TLS. A field rather than a local,
/// because it has to survive the `await` between octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineState {
    /// Nothing of the command has been read: the next read may take a line.
    Unopened,
    /// A line of the command has ended: one octet per read from here on.
    Closed,
}

/// What [`Connection::read_command`] produced.
#[derive(Debug)]
enum Pasted {
    /// A command's bytes, literals included.
    Complete {
        /// The command as the codec wants it, and exactly it.
        bytes: Vec<u8>,
    },
    /// The peer went away.
    Eof,
    /// These octets cannot be a command this server will frame.
    Refused(String),
    /// The autologout timer fired.
    TimedOut,
}

/// One IMAP connection.
struct Connection {
    stream: Stream,
    config: Arc<ImapConfig>,
    /// The session, once a client has said who it is. See the module
    /// documentation: a session exists only after the credential check.
    session: Option<ImapSession<'static>>,
    /// The command being assembled.
    command: Vec<u8>,
    /// Octets read from the socket that belong to a *later* command: at most
    /// one command's last line, because the reader takes one octet at a time
    /// past the first. A `STARTTLS` may only run when this is empty.
    buffer: Vec<u8>,
    /// Where the command has got to in its lines — which is what decides
    /// whether the next read may take a whole line or must take one octet.
    line_state: LineState,
    /// Whether the socket is inside TLS (implicit from the first octet, or
    /// after `STARTTLS`).
    tls: bool,
}

impl Connection {
    fn new(stream: TcpStream, config: Arc<ImapConfig>) -> Self {
        Self {
            stream: Box::pin(stream),
            config,
            session: None,
            command: Vec::new(),
            buffer: Vec::new(),
            line_state: LineState::Unopened,
            tls: false,
        }
    }

    fn transport(&self) -> Transport {
        if self.tls {
            Transport::Tls
        } else {
            Transport::Clear
        }
    }

    async fn run(&mut self) -> Result<(), ServerError> {
        if self.config.imap_tls {
            self.handshake().await?;
        }
        // The capability list is the session's to state, so the greeting is
        // asked of a throwaway one; the transcript below then reuses that same
        // throwaway session for the unauthenticated commands.
        let greeting = self.anonymous().greeting();
        self.stream.write_all(&greeting).await?;
        self.stream.flush().await?;
        loop {
            let pasted = match self.read_command().await {
                Ok(pasted) => pasted,
                Err(err) => {
                    return Err(err);
                }
            };
            match pasted {
                Pasted::Complete { bytes, .. } => {
                    let closed = self.answer(&bytes).await?;
                    if closed {
                        return Ok(());
                    }
                }
                Pasted::Eof => return Ok(()),
                Pasted::TimedOut => {
                    let _ = self
                        .stream
                        .write_all(b"* BYE Autologout; idle for too long\r\n")
                        .await;
                    self.close().await;
                    return Ok(());
                }
                Pasted::Refused(tag) => {
                    let line = format!("{tag} BAD the command could not be framed\r\n");
                    let _ = self.stream.write_all(line.as_bytes()).await;
                    self.close().await;
                    return Ok(());
                }
            }
        }
    }

    async fn close(&mut self) {
        let _ = self.stream.flush().await;
        let _ = self.stream.shutdown().await;
    }

    /// A session over no mailbox: the greeting and the unauthenticated half of
    /// §3 are questions that do not depend on one.
    fn anonymous(&self) -> ImapSession<'static> {
        static PASSWORDS: crate::authn::DenyAll = crate::authn::DenyAll;
        ImapSession::new(
            self.config.hostname.clone(),
            crate::imap_session::unassigned(),
            MaildirReader::new(&self.config.mail_root),
            self.transport(),
            &PASSWORDS,
        )
        .with_starttls(self.config.tls.is_some())
    }

    /// Asks the session about one command, writes its answer, and says whether
    /// the connection ends here.
    ///
    /// Every command that reaches this point has been framed and decoded —
    /// `Connection::read_command` answers a line the codec refuses itself,
    /// because that is the only place the tag and the stream are both in
    /// hand — so the decode here cannot fail. If it ever did, closing the
    /// connection is the honest answer: a session handed a command nobody
    /// parsed would be answered from state that does not describe it.
    async fn answer(&mut self, bytes: &[u8]) -> Result<bool, ServerError> {
        let Ok((_, command)) = CommandCodec::default().decode(bytes) else {
            return Err(ServerError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "a framed command did not decode",
            )));
        };
        // A `STARTTLS` is the one answer this layer acts on rather than writes
        // through: the line goes out, and then the socket becomes TLS.
        let outcome = match &mut self.session {
            Some(session) => session.handle(&command).await,
            None => self.before_login(&command).await,
        };
        self.stream.write_all(&outcome.out).await?;
        self.stream.flush().await?;
        if let Some(line) = &outcome.start_tls {
            self.stream.write_all(line).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream.flush().await?;
            self.start_tls().await?;
        }
        Ok(outcome.close)
    }

    /// The commands a connection with no session answers: RFC 3501 §3's
    /// not-authenticated half.
    ///
    /// Every reply is rendered by the session ([`ImapSession::refuse_no`],
    /// [`ImapSession::done`], …) so the spelling is the state machine's, and
    /// `LOGIN` is refused on any transport that cannot keep a password off the
    /// wire — the same rule [`ImapSession::handle`] applies, enforced from the
    /// same fact ([`Transport`]).
    async fn before_login(
        &mut self,
        command: &imap_codec::imap_types::command::Command<'_>,
    ) -> Outcome {
        use imap_codec::imap_types::command::CommandBody as B;
        let session = self.anonymous();
        let tag = command.tag.as_ref().to_owned();
        let encrypted = self.tls;
        let privacy = || {
            outcome_of(session.refuse_no(
                &tag,
                "[PRIVACYREQUIRED] TLS is required before authenticating",
            ))
        };
        match &command.body {
            B::Capability => {
                let mut out = session.notice_line();
                out.extend(session.done(&tag, "CAPABILITY"));
                outcome_of(out)
            }
            B::Noop | B::Check => outcome_of(session.done(&tag, "NOOP")),
            // RFC 3501 §6.3.10: `LOGOUT` needs no mailbox, and a client that
            // gives up after a failed login still gets its `BYE` and its `OK`.
            B::Logout => {
                let mut out = session.bye_line();
                out.extend(session.done(&tag, "LOGOUT"));
                Outcome {
                    out,
                    close: true,
                    ..Outcome::default()
                }
            }
            // Offered only by a listener that has a certificate (see
            // `ImapSession::with_starttls`).
            B::StartTLS if !encrypted && self.config.tls.is_some() => {
                Outcome::start_tls(ImapSession::starttls_line(&tag))
            }
            B::StartTLS => {
                outcome_of(session.refuse_bad(&tag, "STARTTLS is not available on this connection"))
            }
            B::Login { username, password } => {
                if !encrypted {
                    return privacy();
                }
                let user = astring_of(username);
                let pass = astring_of(password.declassify());
                self.authenticate(&tag, &user, &pass).await
            }
            B::Authenticate {
                initial_response, ..
            } => {
                if !encrypted {
                    return privacy();
                }
                // PLAIN carries its whole message in the initial response; a
                // client that sends it in a continuation is answered `NO`
                // rather than driven through a second state this connection
                // does not have.
                let Some(initial) = initial_response else {
                    return outcome_of(session.refuse_no(&tag, "SASL initial response required"));
                };
                match crate::authn::decode_plain(&String::from_utf8_lossy(initial.declassify())) {
                    Ok((user, pass)) => self.authenticate(&tag, &user, &pass).await,
                    Err(_) => outcome_of(
                        session.refuse_no(&tag, "[AUTHENTICATIONFAILED] malformed PLAIN response"),
                    ),
                }
            }
            other => outcome_of(session.refuse_bad(
                &tag,
                &format!(
                    "{} is not allowed before authentication",
                    verb_of(&self.command).unwrap_or(crate::imap_session::command_name(other))
                ),
            )),
        }
    }

    /// Checks the credential and, when it holds, opens the session over the
    /// mailbox it opened.
    async fn authenticate(&mut self, tag: &str, user: &str, pass: &str) -> Outcome {
        let probe = self.anonymous();
        if !self.config.passwords.verify(user.trim(), pass).await {
            return outcome_of(probe.refuse_no(tag, "[AUTHENTICATIONFAILED] invalid credentials"));
        }
        let Ok(address) = ayane_proto::Address::parse(user.trim()) else {
            // A verifier may accept an identity that is not an address; the
            // mailbox still has to be one. Nothing is served for it.
            return outcome_of(probe.refuse_no(tag, "[AUTHENTICATIONFAILED] invalid credentials"));
        };
        // This session's credential check has *already* been answered — by the
        // listener, above. It exists so a second `LOGIN` on this connection is
        // refused by the session's own rule ("command is not permitted after
        // authentication") without a second syscall to the store.
        static NO_SECOND_LOGIN: crate::authn::DenyAll = crate::authn::DenyAll;
        let mut session = ImapSession::new(
            self.config.hostname.clone(),
            address,
            MaildirReader::new(&self.config.mail_root),
            self.transport(),
            &NO_SECOND_LOGIN,
        )
        .with_starttls(self.config.tls.is_some());
        session.mark_authenticated();
        let out = session.logged_in(tag);
        self.session = Some(session);
        outcome_of(out)
    }

    /// Upgrades a connection that answered `STARTTLS`.
    async fn start_tls(&mut self) -> Result<(), ServerError> {
        if !self.buffer.is_empty() {
            // Octets a client sent before the upgrade are plaintext it is
            // asking us to treat as if they had crossed the TLS channel.
            // Refusing is the only answer that cannot be an injection.
            return Err(ServerError::Tls(
                "octets arrived before the TLS handshake".to_owned(),
            ));
        }
        let Some(acceptor) = self.config.tls.clone() else {
            return Err(ServerError::Tls("no TLS configuration".to_owned()));
        };
        let owned = std::mem::replace(&mut self.stream, Box::pin(tokio::io::empty()));
        let stream = acceptor
            .accept(owned)
            .await
            .map_err(|err| ServerError::Tls(err.to_string()))?;
        self.stream = Box::pin(stream);
        self.tls = true;
        self.session = None;
        Ok(())
    }

    /// Performs the TLS handshake this listener puts before the greeting.
    async fn handshake(&mut self) -> Result<(), ServerError> {
        let Some(acceptor) = self.config.tls.clone() else {
            return Err(ServerError::Tls("no TLS configuration".to_owned()));
        };
        let owned = std::mem::replace(&mut self.stream, Box::pin(tokio::io::empty()));
        let stream = acceptor
            .accept(owned)
            .await
            .map_err(|err| ServerError::Tls(err.to_string()))?;
        self.stream = Box::pin(stream);
        self.tls = true;
        Ok(())
    }

    // ── byte plumbing ────────────────────────────────────────────────────

    /// Reads the next octet of the command being assembled, or says why there
    /// is none.
    ///
    /// The first read of a command takes **one line**, everything up to and
    /// including its CRLF: by definition that cannot be octets the client sent
    /// *behind* the command — a literal's octets can only follow an
    /// announcement, and an announcement ends its line. Every read after that
    /// first line takes a **single octet**, because past it any octets waiting
    /// belong to a later command (or to a `STARTTLS`'s handshake) and the
    /// reader has not been asked for them yet.
    async fn next_octet(&mut self) -> io::Result<(Filled, u8)> {
        if self.buffer.is_empty() {
            let want = if self.line_state == LineState::Unopened {
                IMAP_READ_SLICE
            } else {
                1
            };
            let mut chunk = vec![0u8; want];
            match tokio::time::timeout(
                self.config.command_timeout,
                AsyncReadExt::read(&mut self.stream, &mut chunk),
            )
            .await
            {
                Err(_) => return Ok((Filled::TimedOut, 0)),
                Ok(Err(err)) => return Err(err),
                Ok(Ok(0)) => return Ok((Filled::Eof, 0)),
                Ok(Ok(read)) => {
                    let line_len = match chunk[..read].windows(2).position(|w| w == b"\r\n") {
                        Some(at) => {
                            self.line_state = LineState::Closed;
                            at + 2
                        }
                        None => {
                            if self.line_state == LineState::Unopened && read == want {
                                self.line_state = LineState::Closed;
                            }
                            read
                        }
                    };
                    self.buffer.extend_from_slice(&chunk[..read]);
                    let _ = line_len;
                }
            }
        }
        let octet = self.buffer[0];
        self.buffer.remove(0);
        Ok((Filled::Data, octet))
    }

    /// Reads one command, literals included.
    ///
    /// The loop is [`crate::imap_session::read_command`]'s, driven by a socket
    /// instead of a blocking reader: the command is fed octet by octet until
    /// the codec accepts it, and a literal's announcement is looked for the
    /// moment a CRLF completes the line — the client stops there and waits for
    /// `+`, so a read that ran past it would have taken octets the client has
    /// not been asked for. The announced octets are then taken exactly, as
    /// data. One octet in flight is what makes `STARTTLS` safe; see
    /// `Connection::next_octet`.
    async fn read_command(&mut self) -> Result<Pasted, ServerError> {
        loop {
            if self.command.is_empty() {
                self.line_state = LineState::Unopened;
            }
            // The codec wants the whole line, CRLF included: it takes the
            // client's frame as the frame, so the bytes here are exactly what
            // the client wrote.
            match CommandCodec::default().decode(&self.command) {
                Ok((_rest, _)) => {
                    // `rest` is what the codec left over: octets this reader
                    // took that the command does not claim. There are none for
                    // a client that framed its line correctly — the reader takes
                    // one line — and a client that did not has its leftovers
                    // read as the next command's start.
                    return Ok(Pasted::Complete {
                        bytes: std::mem::take(&mut self.command),
                    });
                }
                Err(CommandDecodeError::Incomplete | CommandDecodeError::LiteralFound { .. }) => {
                    // A command not yet complete is the ordinary case; what
                    // would loop is the codec accepting the octets our reader
                    // still holds. It cannot: the reader takes one octet at a
                    // time past the first line, so each pass either grows the
                    // command or ends it.
                }
                // The codec fails a command the moment it reads an atom it
                // does not know — `x9 FR` on its way to `x9 FROBNICATE` — so a
                // line that has not ended yet is not a refusal yet: it is only
                // refused once its CRLF says the client meant it.
                // The codec refuses a line the moment it reads an atom it does
                // not know (`x9 FR` on the way to `x9 FROBNICATE`), so a
                // failure before this command's line has ended is a *pending*
                // refusal: it is answered when the CRLF says the client meant
                // it. Answering earlier would tear the line the client is still
                // writing out from under it.
                Err(CommandDecodeError::Failed) if self.command.ends_with(b"\r\n") => {
                    // RFC 3501 §7.1: the tag is the client's, and this is the
                    // one path that answers before the session is asked.
                    let mut out = format!(
                        "{} BAD the command could not be parsed\r\n",
                        tag_of(&self.command)
                    );
                    self.stream.write_all(out.as_bytes()).await?;
                    self.stream.flush().await?;
                    out.clear();
                    self.command.clear();
                    continue;
                }
                Err(CommandDecodeError::Failed) => {}
            }
            if let Some((tag, length, mode)) = announcement(&self.command) {
                let length = length as usize;
                if self.command.len().saturating_add(length) > MAX_COMMAND_BYTES {
                    return Ok(Pasted::Refused(tag));
                }
                if mode == LiteralMode::Sync {
                    // The `+` is this reader's to send: the client will not
                    // produce the octets until it arrives, so it cannot be
                    // left to the caller after the command is assembled —
                    // assembling it waits for the octets.
                    let line = format!("+ Ready for {length} octets\r\n");
                    self.stream.write_all(line.as_bytes()).await?;
                    self.stream.flush().await?;
                }
                for _ in 0..length {
                    match self.next_octet().await? {
                        (Filled::Data, octet) => self.command.push(octet),
                        // A stream that ends mid-literal is a client that went
                        // away between the announcement and the octets.
                        (Filled::Eof, _) => return Ok(Pasted::Eof),
                        (Filled::TimedOut, _) => return Ok(Pasted::TimedOut),
                    }
                }
                self.line_state = LineState::Unopened;
                continue;
            }
            // The frame's own bound, checked at the only place it can be: a
            // line that has ended and is still not a command is refused on its
            // length, not on the codec's patience.
            if self.command.len() > MAX_LINE_BYTES && self.command.ends_with(b"\r\n") {
                return Ok(Pasted::Refused(tag_of(&self.command)));
            }
            match self.next_octet().await? {
                (Filled::Data, octet) => self.command.push(octet),
                (Filled::Eof, _) => return Ok(Pasted::Eof),
                (Filled::TimedOut, _) => return Ok(Pasted::TimedOut),
            }
        }
    }
}

/// An answer with no TLS upgrade: bytes to write and nothing else.
fn outcome_of(out: Vec<u8>) -> Outcome {
    Outcome::out(out)
}

/// An [`AString`](imap_codec::imap_types::core::AString) as text.
fn astring_of(value: &imap_codec::imap_types::core::AString<'_>) -> String {
    String::from_utf8_lossy(value.as_ref()).into_owned()
}

/// The literal announcement a client is waiting on, if `pending` ends with one.
///
/// Identical to [`crate::imap_session::announcement_of`]'s rule, applied to
/// the command being assembled: an announcement is the one part of a command
/// an *unfinished* buffer can hold, because the client stops there and will not
/// send the octets until it hears `+`. A `{5}` inside literal octets is never
/// at the end of a line, and `{}` with nothing in the braces is an empty flag
/// list.
fn announcement(pending: &[u8]) -> Option<(String, u32, LiteralMode)> {
    let body = pending.strip_suffix(b"\r\n").unwrap_or(pending);
    let line = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(at) => &body[at + 1..],
        None => body,
    };
    if !line.ends_with(b"}") {
        return None;
    }
    let open = line[..line.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'{')?;
    if open == 0 || line[open - 1] != b' ' {
        return None;
    }
    let (digits, mode) = match line[open + 1..line.len() - 1].strip_suffix(b"+") {
        Some(digits) => (digits, LiteralMode::NonSync),
        None => (&line[open + 1..line.len() - 1], LiteralMode::Sync),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((
        tag_of(pending),
        std::str::from_utf8(digits).ok()?.parse().ok()?,
        mode,
    ))
}

/// The command name in a line, when the codec had one to give — or `None` for
/// a body that carries no name of its own (which is why the fallback exists).
fn verb_of(line: &[u8]) -> Option<&'static str> {
    let line = String::from_utf8_lossy(line);
    let mut words = line.trim_end_matches("\r\n").split(' ');
    words.next()?;
    let verb = words.next()?.to_ascii_uppercase();
    const KNOWN: &[&str] = &[
        "SELECT",
        "EXAMINE",
        "FETCH",
        "STORE",
        "SEARCH",
        "COPY",
        "MOVE",
        "EXPUNGE",
        "CLOSE",
        "APPEND",
        "UNSELECT",
        "CREATE",
        "DELETE",
        "RENAME",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "LIST",
        "LSUB",
        "STATUS",
        "CHECK",
        "IDLE",
    ];
    KNOWN.iter().copied().find(|name| *name == verb)
}

/// The tag at the front of a partial command.
fn tag_of(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(bytes.len());
    // Whatever the client wrote at the front comes back, verbatim: RFC 3501
    // §7.1 leaves the tag to the client, and a tag this server tidied up would
    // be one the client could not match its command to.
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
