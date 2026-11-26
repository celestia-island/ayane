//! The tokio I/O driver: sockets, timers, TLS, limits.
//!
//! Everything that is a *policy* lives in [`crate::session`] (pure) and
//! [`crate::policy`] (router); this module only moves bytes and enforces the
//! three transport-level bounds RFC 5321 §4.5.3.2 asks for:
//!
//! | Bound | Operation limit | Reply / action |
//! |---|---|---|
//! | command | 5 min | `421` then close |
//! | mail transaction (`DATA`, `BDAT` chain) | 10 min | `421` then close |
//! | line | 1000 octets (512 relaxed to 1000) | `500 Line too long` then close |
//!
//! A `BDAT` chain is reassembled in memory, bounded twice: one chunk by
//! [`MAX_BDAT_BUFFER`] and the whole chain by the message-size limit (the same
//! ceiling `DATA` enforces). A chunk that breaks either bound is refused by
//! closing the connection with `421` — never by a second reply to a command
//! that was already answered, and never by reading octets nobody is going to
//! keep.
//!
//! Two more bounds are not RFC but are what keeps the process alive under an
//! attack: a per-IP concurrent connection cap and per-connection message /
//! recipient counts ([`crate::session::Limits`]), and — because a
//! per-connection count is reset by reconnecting — a per-IP AUTH failure
//! budget with a back-off ([`AuthGuard`]).
//!
//! # `DATA` and `BDAT` are one policy seen from two sides
//!
//! A message may arrive either as lines followed by `.` or as a chain of
//! opaque octets, and everything this module decides about it — the size, the
//! header section, the bare `LF` — is decided over the **same bytes**. So the
//! invariant is stronger than "both transports work": **for one wire form of a
//! message — its octets followed by a `.<CRLF>` terminator — `DATA` and `BDAT`
//! accept or reject it identically, with the same code, the same text and the
//! same effect on the queue.** Anything less is a probe a sender can run: send
//! the shape that gets `250` from one transport and the octets are in the queue
//! without ever meeting the rule the other transport applies, which is exactly
//! the shape of CVE-2023-51764 (an octet sequence that is one message to a
//! lenient reader and two to a strict one).
//!
//! # Where the two transports genuinely differ
//!
//! "One wire form" is doing real work in that sentence, and the difference is
//! protocol, not policy — no implementation can make it go away:
//!
//! - **`DATA` has a terminator and framing; `BDAT` has neither.** A `DATA`
//!   transfer ends at a `.<CRLF>` line, and a line that starts with `.` on the
//!   wire lost one dot to dot-stuffing. A chunk is opaque octets: a `.<CRLF>`
//!   inside one is message *content*, and `BDAT … LAST` is what ends the
//!   message. So a wire that contains a `.<CRLF>` is two different things to
//!   the two transports — which is why the duality above is stated for the
//!   octets **plus** a terminator, and why `tests/header_bound.rs` sends every
//!   compared message that way.
//! - **What may follow the end of a transfer.** In `DATA`, commands may
//!   already be pipelined behind the terminator, and a server must not read
//!   them as message content. In `BDAT`, the octets of the next chunk follow
//!   the command that asked for them, and nothing else does.
//!
//! What is **not** a license for the two to differ is the bytes of the message
//! itself: a bare `LF` anywhere in what the sender calls one message is refused
//! by both, in the head and in the body alike. That is the rule this module's
//! scans exist to keep symmetrical.
//!
//! One more boundary, because it reads like a violation and is not: after a
//! **failed** `DATA` transfer, the octets the sender wrote up to (and behind)
//! the next `<CRLF>.<CRLF>` are discarded rather than executed — the upload of
//! a refused message is never a channel for commands. That is stricter than
//! "what follows a terminator is commands", and deliberately so: nothing in a
//! failed transfer was acknowledged, so nothing in it can be trusted to be a
//! command.
//!
//! # Discarding a failed transfer: two places, on purpose
//!
//! A drain that ends by **finding the client's terminator** cannot be the whole
//! story, because it consumes that terminator and then has nothing left to
//! discard: a sender that splits its upload across writes still has the tail of
//! its message to send, and it arrives *after* the drain has returned. A
//! refusal is answered from there, so the tail would be read by the command
//! loop as if the sender had waited for the `554` — and a sender that writes a
//! whole forged transaction there gets it executed. (That was a real hole in
//! this module's first fix, and the one-piece test that covered it could not
//! see the hole: with one write the tail is in the kernel buffer *before* the
//! drain, and the drain discards it.)
//!
//! What the drain can see is the tail it already holds. What it cannot see is
//! the tail that is still on the way — and that is the one a sender controls,
//! because it is written before the sender has read the `554`. So a drain that
//! ends on the client's terminator leaves the connection in a state that says
//! so: `Connection::settling` (the next read's octets are the refused upload's
//! tail and are dropped as far as they are not a whole line) and
//! `Connection::refused` (a `MAIL FROM` in what remains opens nothing —
//! `503 Bad sequence`). Together they mean the tail can never start a
//! transaction, whatever it is split into, however late it arrives.
//!
//! The state lasts exactly one read, then one command. After that the connection
//! owes the client ordinary answers again: a client that read its `554` and
//! wants to send a new message gets a normal transaction out of it. See
//! `Connection::quarantine_refused_upload`.
//!
//! | Decision | `DATA` | `BDAT` |
//! |---|---|---|
//! | bare `LF` in the header section | refused on the line (`554 5.6.0`) | `header_len`, reported as `MalformedHead` |
//! | bare `LF` in the body | refused on the line (`554 5.6.0`) | `scan_record`, reported as `MalformedBody` |
//! | header section past the bound | charged per line (`552 5.3.4`) | `HeaderBudget::charge_message` (`552 5.3.4`) |
//! | message past the size | refused while reading (`552`) | declared size, by the session |
//! | a valid message | `250`, queued | `250`, queued |
//!
//! The names in the `BDAT` column are private functions of this module, so they
//! are plain code here rather than links: the table is about *where* the
//! decision is made, and the public surface does not need a second name for
//! any of it.
//!
//! The body row is the one that is easy to lose: a chunk has no line
//! structure, so nothing refuses a `LF` inside it unless a scan is written for
//! it, and the head's scan stops at the blank line by design. `DATA` refuses
//! the bare `LF` **wherever** it is in the transfer, so `BDAT` has to as well —
//! the check is not a courtesy to the header bound, it is the same rule over
//! the octets that bound does not cover.
//!
//! Both refusals leave the queue empty: the staged spool file is abandoned
//! before the reply goes out ([`StagedMessage::abandon`]), so a `554` from
//! either transport means the same thing — this server holds nothing.
//!
//! [`StagedMessage::abandon`]: crate::queue::StagedMessage::abandon
//!
//! # What looks like a runtime check and is not
//!
//! A few conditions in this module read like defence in depth and are worth
//! knowing about before anyone writes a test that expects them to answer
//! something. They are **invariants of the dispatch layer**, stated as
//! `debug_assert!` and compiled out of a production build, because no client
//! input can reach them:
//!
//! - A chunked session that is no longer in [`crate::session::Phase::Bdat`]
//!   when its octets are being read. The driver calls `receive_chunk` from one
//!   place only — the `Action::ReadChunk` arm — and the session returns that
//!   action only after it has admitted the chunk. A chunk it refuses is
//!   answered `552` with `Action::Continue`, so the transport is never asked to
//!   read octets the session has already refused.
//! - The whole-chain ceiling in `receive_chunk`. It is the session's own
//!   arithmetic written a second time, not a second bound: the session's
//!   running total is the sum of exactly the chunks the transport appended, and
//!   `max_bdat_total` is the message size raised to one chunk, so "declared
//!   total ≤ limit" and "held + this chunk ≤ max(limit, one chunk)" are one
//!   inequality. A chunk the session admitted is a chunk the chain can hold.
//! - The send chain left over from an abandoned transaction. A chain is only
//!   abandoned by `fail_data`, which always follows a reply that already
//!   answered its command, and the next transaction either continues the
//!   chain (still `Bdat`) or resets it through a path that drops the octets
//!   with it. There is no state where clearing it changes an outcome, which is
//!   why there is no line clearing it.
//!
//! What *is* a runtime bound in this area, and does have tests that fail
//! without it: one chunk larger than [`MAX_BDAT_BUFFER`]. The session admits it
//! whenever it fits in the message size — and on any deployment of sane size
//! it does — so the transport is the only thing that refuses it.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::authn::{self, PasswordVerifier};
use crate::command::{self, Command};
use crate::mailbox::Mailbox;
use crate::policy::{self, AddressPolicy, ListenerRole, RecipientVerdict};
use crate::queue::{Envelope, Spool, StagedMessage};
use crate::session::{
    Action, AuthContinuation, Extensions, Limits, Outcome, Reply, Session, Transaction,
};
use crate::verify::{PolicyVerdict, SessionFacts, Verifier, VerifyError};

/// The largest command line accepted, CRLF included (RFC 5321 §4.5.3.1.4
/// says 512; 1000 is what every relay in the field sends).
pub const MAX_COMMAND_LINE: usize = 1000;

/// The RFC 5321 §4.5.3.2 command timeout.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The RFC 5321 §4.5.3.2 mail transaction timeout.
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Everything a listener needs to run.
pub struct ServerConfig {
    /// The name in the greeting, `Received:` and the DMARC `authserv-id`.
    pub hostname: String,
    /// What this listener accepts: this is a role, not a flag.
    pub role: ListenerRole,
    /// The SIZE ceiling.
    pub max_message_size: u64,
    /// Per-session bounds.
    pub limits: Limits,
    /// Concurrent connections from one client IP.
    pub per_ip_limit: usize,
    /// Idle/command timeout.
    pub command_timeout: Duration,
    /// Mail transaction timeout.
    pub transaction_timeout: Duration,
    /// Where messages are spooled.
    pub spool: Spool,
    /// The submission sender binding and the hosted-domain list.
    pub policy: AddressPolicy,
    /// The routing snapshot the inbound recipient decision runs against
    /// (`ayane_mail::route`).
    pub state: ayane_proto::DesiredState,
    /// The submission credential check.
    pub passwords: Arc<dyn PasswordVerifier>,
    /// The SPF/DKIM/DMARC verifier; `None` disables verification (tests only).
    pub verifier: Option<Verifier>,
    /// The TLS acceptor; `None` unless the listener offers TLS.
    pub tls: Option<TlsAcceptor>,
    /// Refuse a message whose head already carries more `Received:` fields
    /// than this (mail loops).
    pub max_received_headers: usize,
    /// The largest header section (everything before the blank line that ends
    /// it) a message may carry. A message that reaches its blank line past
    /// this is refused with `552 5.3.4` and never verified or queued.
    ///
    /// This bound is the driver's to keep, not the verifier's: the streaming
    /// [`BodyHasher`](crate::verify::BodyHasher) buffers the **whole** header
    /// section before it can tell where the body starts, and a message with no
    /// blank line at all is buffered whole before `finish` can say it has no
    /// body. Without a bound here, a peer's `DATA` decides how much memory the
    /// verifier holds — for as long as it keeps sending. See
    /// [`DEFAULT_MAX_HEADER_BYTES`].
    pub max_header_bytes: u64,
    /// The per-IP AUTH failure budget and back-off; `None` disables it (tests
    /// that only exercise one connection, and never in a deployment).
    pub auth_guard: Option<Arc<AuthGuard>>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("hostname", &self.hostname)
            .field("role", &self.role)
            .field("max_message_size", &self.max_message_size)
            .field("limits", &self.limits)
            .field("per_ip_limit", &self.per_ip_limit)
            .field("tls", &self.tls.is_some())
            .field("verifier", &self.verifier.is_some())
            .field("max_received_headers", &self.max_received_headers)
            .field("max_header_bytes", &self.max_header_bytes)
            .field("auth_guard", &self.auth_guard.is_some())
            .field("domains", &self.state.domains.len())
            .finish_non_exhaustive()
    }
}

/// Errors a listener can fail with.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The socket could not be bound.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address asked for.
        addr: SocketAddr,
        /// The underlying error.
        source: io::Error,
    },
    /// The connection ended abnormally.
    #[error("connection error: {0}")]
    Io(#[from] io::Error),
    /// The TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    /// The verifier could not be built.
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// Serves connections until the task is cancelled. Each connection runs in its
/// own task; a panic in one is caught and only closes that connection.
///
/// # Errors
///
/// Returns [`ServerError::Io`] when accepting on the socket fails permanently.
pub async fn serve(listener: TcpListener, config: Arc<ServerConfig>) -> Result<(), ServerError> {
    let limiter = Arc::new(PerIpLimiter::new(config.per_ip_limit));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(permit) = limiter.acquire(peer.ip()) else {
            // Over the per-IP cap: greet-and-refuse is what the RFC allows;
            // closing immediately would look like a network fault to a
            // legitimate but misconfigured client.
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = stream
                    .write_all(b"421 4.7.0 Too many concurrent connections from your host\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
            continue;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _permit = permit;
            let mut connection = Connection::new(stream, peer, config);
            if let Err(err) = connection.run().await {
                tracing::debug!(%peer, "connection closed: {err}");
            }
        });
    }
}

/// Per-IP concurrent connection accounting, released on drop.
#[derive(Debug)]
pub struct PerIpLimiter {
    limit: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl PerIpLimiter {
    /// Creates a limiter.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Takes a slot for `ip`, or `None` when the IP is at the cap.
    #[must_use]
    pub fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PerIpPermit> {
        let mut counts = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(PerIpPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// The current count for `ip`, for tests.
    #[must_use]
    pub fn count(&self, ip: IpAddr) -> usize {
        let counts = self.counts.lock().unwrap_or_else(|err| err.into_inner());
        counts.get(&ip).copied().unwrap_or(0)
    }
}

/// A held connection slot.
#[derive(Debug)]
pub struct PerIpPermit {
    limiter: Arc<PerIpLimiter>,
    ip: IpAddr,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// How one peer address's failed AUTH attempts are accounted.
#[derive(Debug, Clone, Copy)]
struct AuthFailState {
    /// Attempts in the current window.
    failures: usize,
    /// When this address was last charged or asked about: the window that
    /// resets it is measured from here.
    last_touched: Instant,
}

/// What [`AuthGuard::admit`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthGate {
    /// Inside the budget, or the back-off has run out.
    Allowed,
    /// Over the budget: no further attempt is considered until `retry_after`.
    Refused {
        /// How long the address still has to wait before another attempt.
        retry_after: Duration,
    },
}

/// The per-peer bound on AUTH failures.
///
/// [`crate::session::Limits::max_auth_attempts`] counts attempts on **one
/// connection**, and a client that reconnects is a new connection: on its own
/// it bounds nothing but a single socket, and a password-guessing client gets
/// an unlimited number of tries for the price of a reconnect. This is the
/// bound that survives reconnecting: it counts failures per peer address in a
/// sliding window and, once the budget is spent, refuses the attempt without
/// looking at the credential until the window has turned over.
///
/// The table is bounded twice — at most `AuthGuard::capacity` addresses, and
/// every entry is dropped once it is older than the window (an address that
/// stops failing stops costing memory).
///
/// A **full** table does not make room for a new address. The count of an
/// address that is already in the table is what the budget acts on, and it is
/// only ever charged when that address itself fails, so an eviction policy is
/// a way to buy attempts: an attacker holding enough addresses fills the
/// table, the victim's entry is the quietest one in it, and the victim's spent
/// budget is thrown away with it. So a full table keeps every entry it holds,
/// for the whole window, and the entries already there are charged and
/// refused exactly as they were before it filled.
///
/// An address that is **not** in the table cannot be counted there — that is
/// what makes the table full — but leaving it unbounded would be a fail-open:
/// a table full of attacker addresses would let every further one guess
/// forever, which is the very thing this guard exists to stop. The unrecorded
/// traffic of a full table is therefore counted **globally**: one counter for
/// all of it, and once it passes [`AuthGuard::flood_budget`] every address
/// that is not in the table is refused for the rest of the window. The counter
/// is what is left of the per-address bound when the addresses have run out of
/// slots: it costs one integer, it cannot be evicted, and being over it is a
/// state an attacker reaches only by failing thousands of times from thousands
/// of addresses inside one window.
///
/// # Defaults
///
/// The default budget is [`AUTH_FAIL_BUDGET`] = fifty failures per address in
/// [`AUTH_FAIL_WINDOW`] = five minutes, which is the **NAT-friendly** setting
/// on purpose: every user behind one NAT address shares that address's
/// budget, so a lower number would lock out an office or a carrier-grade pool
/// for an ordinary afternoon of mistyped passwords. It does not weaken the
/// bound — an address over its budget is refused before the credential is
/// looked at, so the guesses inside the window never reach the password
/// verifier — and a public MX, where one address is one client, may tune it
/// down. The knobs are [`AuthGuard::set_policy`] (budget and window) and
/// [`AuthGuard::set_capacity`] (how many addresses are remembered); the
/// full-table budget follows the per-address one at
/// [`AUTH_FLOOD_BUDGET_FACTOR`] times its size.
///
/// Time comes in as an argument rather than from a clock, so the behaviour is
/// testable without waiting.
#[derive(Debug)]
pub struct AuthGuard {
    attempt: Mutex<(usize, Duration)>,
    capacity: Mutex<usize>,
    peers: Mutex<HashMap<IpAddr, AuthFailState>>,
    /// Failures from addresses the table had no room for, and the window they
    /// were counted in. Shared with the table's lock: both are read and
    /// written under it.
    flood: Mutex<AuthFailState>,
}

/// What a deployment gets when it sets no other bound: fifty failed attempts
/// from one address in five minutes, then that address waits out the window.
///
/// Fifty is the NAT-friendly setting: behind a large NAT one address is an
/// office, a campus or a carrier-grade pool, and ten wrong passwords across all
/// of it in five minutes is an ordinary afternoon, not an attack. The bound's
/// protection does not depend on the number being small — an address over the
/// budget is refused **before the credential is looked at**, so the window's
/// extra guesses never reach the password verifier — and an operator with a
/// public MX (one address per client, no shared egress) can lower it with
/// [`AuthGuard::set_policy`].
pub const AUTH_FAIL_BUDGET: usize = 50;

/// The window of [`AUTH_FAIL_BUDGET`].
pub const AUTH_FAIL_WINDOW: Duration = Duration::from_secs(5 * 60);

/// How many distinct addresses the guard remembers.
///
/// This is a bound on memory, not on coverage: a full table keeps the entries
/// it holds (see [`AuthGuard`]) and counts the addresses it had no room for
/// against one shared budget instead of dropping anything.
pub const AUTH_GUARD_CAPACITY: usize = 4096;

/// What a full table's shared budget is worth, as a multiple of the
/// per-address one: [`AuthGuard::flood_budget`] is this many times
/// [`AUTH_FAIL_BUDGET`].
///
/// Four is the smallest multiple that is a budget rather than a coincidence.
/// The unrecorded traffic is what arrives at a table already holding 4 096
/// addresses, and an address is only charged here after failing at least once,
/// so the counter is the sum of guesses from addresses that are themselves
/// attacking. At four times the per-address budget an attacker who is really
/// changing address reaches it long before the window turns over, while a
/// handful of ordinary clients that could not get a recorded slot do not: at
/// one times the budget the shared counter would refuse a single host that
/// mistyped fifty times — the exact NAT-friendly scenario the per-address
/// budget was raised to serve — and the point of not evicting was that a
/// partial loss of coverage must not become a total one.
pub const AUTH_FLOOD_BUDGET_FACTOR: usize = 4;

impl Default for AuthGuard {
    fn default() -> Self {
        Self::new(AUTH_FAIL_BUDGET, AUTH_FAIL_WINDOW)
    }
}

impl AuthGuard {
    /// A guard that refuses the `(budget + 1)`-th failure of one address
    /// inside `window`.
    #[must_use]
    pub fn new(budget: usize, window: Duration) -> Self {
        Self {
            attempt: Mutex::new((budget.max(1), window)),
            capacity: Mutex::new(AUTH_GUARD_CAPACITY),
            peers: Mutex::new(HashMap::new()),
            flood: Mutex::new(AuthFailState {
                failures: 0,
                last_touched: Instant::now(),
            }),
        }
    }

    /// Changes the budget and the window.
    ///
    /// A deployment behind a large NAT raises the budget here: the bound is
    /// per address, so every user behind the same address shares it.
    pub fn set_policy(&self, budget: usize, window: Duration) {
        let mut attempt = self.attempt.lock().unwrap_or_else(|err| err.into_inner());
        *attempt = (budget.max(1), window);
    }

    /// Changes how many addresses are remembered.
    pub fn set_capacity(&self, capacity: usize) {
        let mut slot = self.capacity.lock().unwrap_or_else(|err| err.into_inner());
        *slot = capacity.max(1);
    }

    fn policy(&self) -> (usize, Duration) {
        *self.attempt.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn capacity(&self) -> usize {
        *self.capacity.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// How many failures the **unrecorded** traffic of a full table may spend
    /// before every address that is not in the table is refused.
    ///
    /// It follows the per-address budget, so an operator who tunes the budget
    /// moves this with it instead of leaving a number that no longer matches.
    #[must_use]
    pub fn flood_budget(&self) -> usize {
        self.policy()
            .0
            .saturating_mul(AUTH_FLOOD_BUDGET_FACTOR)
            .max(1)
    }

    /// Whether `ip` may make an AUTH attempt now.
    ///
    /// An address the table holds answers from its own count. An address it
    /// does not hold is refused once the table is full **and** the shared
    /// counter it was charged against is over
    /// [`AuthGuard::flood_budget`]; a table with room in it never consults the
    /// counter, because an address that arrives with room is recorded and
    /// bound by its own entry.
    #[must_use]
    pub fn admit(&self, ip: IpAddr, now: Instant) -> AuthGate {
        let (budget, window) = self.policy();
        let capacity = self.capacity();
        let mut peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        Self::expire(&mut peers, now, window);
        if let Some(state) = peers.get_mut(&ip) {
            if state.failures < budget {
                state.last_touched = now;
                return AuthGate::Allowed;
            }
            // The window is measured from the *last* failure, so a client that
            // keeps hammering during the back-off pushes its own release
            // further out instead of sitting on a deadline it can already see.
            return AuthGate::Refused {
                retry_after: window
                    .saturating_sub(now.saturating_duration_since(state.last_touched)),
            };
        }
        if peers.len() < capacity {
            return AuthGate::Allowed;
        }
        self.flood_gate(now, window)
    }

    /// Charges one failed attempt to `ip`.
    ///
    /// An address that is already in the table is charged whatever the table
    /// holds: its count is the budget, and dropping it would hand back the
    /// attempts it already spent. An address that is **not** in the table is
    /// recorded when there is room; at capacity it costs the address nothing
    /// individually — nothing in the table is touched — and is charged once to
    /// the shared counter a full table keeps for exactly this traffic. See
    /// [`AuthGuard`] for why the pressure falls on the arriving address rather
    /// than on the quietest one already there, and why an uncounted address
    /// would be a fail-open rather than a saving.
    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let (_, window) = self.policy();
        let capacity = self.capacity();
        let mut peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        Self::expire(&mut peers, now, window);
        if let Some(state) = peers.get_mut(&ip) {
            state.failures = state.failures.saturating_add(1);
            state.last_touched = now;
            return;
        }
        if peers.len() >= capacity {
            // Full, and this address is new: it stays uncounted rather than
            // costing some recorded address its history. What it does cost is
            // a place in the shared budget — the whole reason the full table
            // is not an open door.
            let mut flood = self.flood.lock().unwrap_or_else(|err| err.into_inner());
            if now.saturating_duration_since(flood.last_touched) >= window {
                // The window the counter was counting in is over: the traffic
                // that spent it is old enough to be forgiven.
                *flood = AuthFailState {
                    failures: 0,
                    last_touched: now,
                };
            }
            flood.failures = flood.failures.saturating_add(1);
            flood.last_touched = now;
            if flood.failures > self.flood_budget() {
                tracing::warn!(
                    %ip,
                    capacity,
                    tracked = peers.len(),
                    failures = flood.failures,
                    "AUTH failure table is full and its shared budget is spent: \
                     refusing addresses that are not recorded"
                );
            }
            return;
        }
        peers.insert(
            ip,
            AuthFailState {
                failures: 1,
                last_touched: now,
            },
        );
    }

    /// Forgets an address's failures — a successful login is not part of a
    /// guessing run.
    pub fn record_success(&self, ip: IpAddr) {
        let mut peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.remove(&ip);
    }

    /// How many addresses the table holds, for tests and for tracing.
    #[must_use]
    pub fn tracked(&self) -> usize {
        let peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.len()
    }

    /// The failures currently charged to `ip`, for tests.
    #[must_use]
    pub fn failures(&self, ip: IpAddr) -> usize {
        let peers = self.peers.lock().unwrap_or_else(|err| err.into_inner());
        peers.get(&ip).map_or(0, |state| state.failures)
    }

    /// The failures the addresses the table had no room for have spent, for
    /// tests.
    #[must_use]
    pub fn unrecorded_failures(&self) -> usize {
        let flood = self.flood.lock().unwrap_or_else(|err| err.into_inner());
        flood.failures
    }

    /// The verdict for an address the table does not hold, on a full table.
    ///
    /// The caller holds the table's lock, which is what keeps this counter
    /// from moving under it.
    fn flood_gate(&self, now: Instant, window: Duration) -> AuthGate {
        let flood = self.flood.lock().unwrap_or_else(|err| err.into_inner());
        if now.saturating_duration_since(flood.last_touched) >= window {
            // Outside the window the counter was counting in: nothing of it
            // survives, and the next failure starts a fresh one.
            return AuthGate::Allowed;
        }
        if flood.failures <= self.flood_budget() {
            return AuthGate::Allowed;
        }
        AuthGate::Refused {
            retry_after: window.saturating_sub(now.saturating_duration_since(flood.last_touched)),
        }
    }

    fn expire(peers: &mut HashMap<IpAddr, AuthFailState>, now: Instant, window: Duration) {
        peers.retain(|_, state| now.saturating_duration_since(state.last_touched) < window);
    }
}

/// One client connection, after the optional TLS upgrade.
struct Connection {
    stream: Pin<Box<dyn AsyncStream>>,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    session: Session,
    /// Octets read from the socket but not yet consumed. STARTTLS discards it.
    read_buf: Vec<u8>,
    /// The rest of a message transfer that is being thrown away: octets read
    /// from the socket while a `DATA` upload is drained go here and nowhere
    /// else, so nothing in them is ever executed as a command. `None` outside
    /// a failed transfer.
    discard: Option<Vec<u8>>,
    /// A failed `DATA` transfer's drain ended on a terminator the **client**
    /// sent, and the connection has not yet read past it: octets that arrive
    /// for the next command are still the tail of the transfer whose
    /// terminator was just consumed (a sender that splits its upload across
    /// writes gets there). Spent by [`Connection::settle`] on that read.
    settling: bool,
    /// Armed with `settling`, and for one command longer: a `MAIL FROM` read
    /// from the refused upload's tail opens no transaction (`503`) — see
    /// [`Connection::quarantine_refused_upload`]. Spent on that first command.
    refused: bool,
    auth_state: Option<AuthState>,
    tls: bool,
    /// A second handle on the socket, for the failed-handshake close.
    socket: SocketHandle,
    /// The body of a BDAT chunk chain: at most `MAX_BDAT_BUFFER` from one
    /// chunk and at most the message-size limit overall, both enforced as the
    /// octets arrive.
    bdat_chain: Vec<u8>,
    /// How the header section of the message being received stands, for the
    /// [`ServerConfig::max_header_bytes`] bound.
    header: HeaderBudget,
}

/// How much of the header section a transfer has taken so far, and whether
/// the section has ended.
///
/// The bound exists because the streaming verifier holds the **whole** header
/// section (see [`BodyHasher`](crate::verify::BodyHasher)), so what is counted
/// here is not "how much do we want to keep" but "how much may a peer make us
/// hold". It is counted per line as the line arrives — before the octets are
/// written or hashed — so crossing the bound stops the transfer at the line
/// that crossed it rather than after the whole message is in.
#[derive(Debug, Default)]
struct HeaderBudget {
    /// Octets of the header section seen so far, blank line included.
    consumed: u64,
    /// The blank line that ends the header section has gone past: everything
    /// after it is body and is not counted.
    ended: bool,
}

impl HeaderBudget {
    /// Counts one received `DATA` line.
    ///
    /// Lines arrive one at a time there, so the section ends exactly on the
    /// line that is the blank one — and from that line on nothing is counted.
    fn consume(&mut self, octets: &[u8]) {
        if self.ended {
            return;
        }
        self.consumed = self.consumed.saturating_add(octets.len() as u64);
        if header_ends_at(octets) {
            self.ended = true;
        }
    }

    /// Charges the header section of a **whole** message assembled elsewhere.
    ///
    /// A `BDAT` chain is raw octets: by the time it is whole there are no line
    /// boundaries left to hand to [`HeaderBudget::consume`], so the section is
    /// measured over the message itself — [`header_len`] counts what `DATA`
    /// would have charged line by line, the blank line included.
    ///
    /// A head whose lines do not all end in `CRLF` is not a section this
    /// server will size, and it is not one it should accept either: `DATA`
    /// refuses a bare `LF` outright (RFC 5321 §2.3.8; guessing at it is the
    /// smuggling hole, CVE-2023-51764), and a chained message is the same
    /// octets. So an unmeasurable head is reported as [`MalformedHead`] and the
    /// caller refuses the message with the code `DATA` refuses it with — the
    /// two transports must reject the same message for the same reason, not
    /// merely agree about its size.
    ///
    /// **The bare-`LF` scan covers the whole transfer, and this is only its
    /// head half.** A head that measures fine says nothing about the body
    /// behind the blank line: that part has no line structure either, and it is
    /// where a smuggled envelope would be put. It is scanned separately, by
    /// [`scan_record`], on the octets after `section` — so a record is refused
    /// for a bare `LF` in the head (here, as [`MalformedHead`]) or in the body
    /// (there, as [`MalformedBody`]), whichever comes first, and both refusals
    /// are answered identically to `DATA` (`554 5.6.0 Transaction failed`
    /// through `fail_data` + `reply_end(false)`). Splitting the scan in two
    /// rather than scanning the whole record once is what keeps this function's
    /// answer — the size of the section — the *only* thing it decides.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedHead`] when a line of the section does not end in
    /// `CRLF`.
    fn charge_message(&mut self, message: &[u8]) -> Result<usize, MalformedHead> {
        if self.ended {
            // The section was already charged (line by line, by `DATA`, or by
            // an earlier record of the same chain); whatever `message` is, it
            // adds nothing to the section, and the body scan starts at its
            // first octet.
            return Ok(0);
        }
        let section = header_len(message).ok_or(MalformedHead)?;
        self.consumed = self.consumed.saturating_add(section as u64);
        self.ended = true;
        Ok(section)
    }

    /// Whether the header section has taken more than `limit` octets.
    fn over(&self, limit: u64) -> bool {
        self.consumed > limit
    }
}

/// What a reassembled record's bare-`LF` scan found.
///
/// A unit rather than a `bool`, for the same reason [`MalformedHead`] is one:
/// the caller cannot reach the "no bare `LF` at all" case by forgetting to
/// look at the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MalformedBody;

/// Scans the **body** of a reassembled message — everything after the blank
/// line that ends its header section — for a bare `LF`.
///
/// # Why this exists
///
/// `DATA` reads a message as lines and refuses, on the line that carries it, a
/// `LF` that is not the second octet of a `CRLF` ([`Connection::read_body_line`]):
/// treating one as a line break is the SMTP smuggling hole (CVE-2023-51764),
/// where `\r\n\r\nfirst\r\n\n.\nRCPT TO:…` becomes two messages to a receiver
/// that guesses. A `BDAT` chunk is opaque octets — [`HeaderBudget::charge_message`]
/// could only look at the head — so the same body was accepted and queued with
/// `250`. That asymmetry is the defect this scan closes: the body of a chained
/// message must be subject to the same "no bare `LF` anywhere" rule as the body
/// of a `DATA` transfer, or the two transports disagree about whether a message
/// is even readable.
///
/// # What it costs
///
/// One pass over the message: [`header_len`] stops at the blank line, and this
/// looks at the octets after it with [`has_bare_lf`], which is one `memchr`
/// over the `LF` octets and a one-octet look-behind at each, never a
/// `windows(2)` comparison per octet. Measured on a release build, a 25 MiB
/// body of lines and one bare `LF` costs about 4 ms — the same order as the
/// head scan it follows, and paid once per chained message, after the chunks
/// are already in memory. It is not on the `DATA` path, where lines are
/// refused as they arrive.
///
/// # Errors
///
/// Returns [`MalformedBody`] when a `\n` in the body is not directly preceded
/// by a `\r`, or when the body's first octet is a `\n` (an empty line whose
/// ending is a bare `LF`).
fn scan_record(record: &[u8], body_from: usize) -> Result<(), MalformedBody> {
    let body = record.get(body_from..).unwrap_or_default();
    if has_bare_lf(body) {
        return Err(MalformedBody);
    }
    Ok(())
}

/// How many octets of `message` are header section: up to and including the
/// blank line that ends it, or the whole message when it has none. `None` when
/// a line in the section does not end in `CRLF` — the message is not one
/// `DATA` would read (bare `LF` is refused outright), so there is no section
/// to measure.
///
/// **It is written to agree with the `DATA` path line for line**, because the
/// two transports must refuse the same message or a sender can shop for the
/// answer it likes:
///
/// | message | section | why |
/// |---|---|---|
/// | `\r\n<body>` | 2 | the first line is already the blank line, and a line's `CRLF` counts |
/// | `h\r\n\r\n<body>` | 5 | `h` + `CRLF`, then the blank line |
/// | `h1\r\n h2\r\n\r\n<body>` | 11 | a folded field is one line, and only the empty one ends the section |
/// | `no blank line` | all of it | no body, so the head is the message |
///
/// The blank line is the `CRLF` that *ends* an empty line — not the `CRLFCRLF`
/// you get by looking for two in a row, which swallows the first octets of the
/// body when the message starts with the blank line itself (that is the one
/// case the two searches disagree on, and it is exactly the empty-header
/// message). Walking line by line, an empty line is one whose `CRLF` sits
/// immediately at the line's start, which is one forward scan and needs no
/// look-behind.
///
/// That scan is single-pass and allocation-free, but it is one comparison per
/// octet: on a 25 MiB message that is tens of milliseconds in a release build
/// and **hundreds of milliseconds in a debug one**. It runs once per accepted
/// chained message, after the chunks are in memory already; it is not on the
/// `DATA` path, where lines are counted as they arrive.
fn header_len(message: &[u8]) -> Option<usize> {
    let mut line_start = 0usize;
    loop {
        // The end of the line starting at `line_start`: the next `CRLF`.
        let line_end = match find_crlf(message, line_start) {
            Some(found) => found + 2,
            // No `CRLF` left. A line of content running to the end without one
            // means the message has no blank line, so what is left is all
            // header — the case the bound exists for. (A message that ends
            // mid-line is the same answer: there is no body after a section
            // that never ended.)
            None => return Some(message.len()),
        };
        // The line is empty when there is nothing between its start and its
        // own `CRLF` — and it is the blank line that ends the section.
        if line_end - 2 == line_start {
            return Some(line_end);
        }
        // A section line may not carry a bare `LF`: `DATA` refuses the whole
        // transfer on one (RFC 5321 §2.3.8, CVE-2023-51764), so a chained
        // message with one is not a message this server reads, and there is no
        // section to measure.
        if has_bare_lf(&message[line_start..line_end - 2]) {
            return None;
        }
        line_start = line_end;
    }
}

/// The index of the first `CRLF` of `haystack` at or after `from`.
///
/// Anchored at each candidate `\r`, so the whole scan is one `memchr` per
/// octet searched for and nothing is rescanning a suffix: the loop is linear
/// in `haystack.len() - from`, restarting a search only where a `\r` was not
/// followed by `\n` (which, in a message with a bare `\r` and no `CRLF`, is
/// the number of `\r`s in it).
fn find_crlf(haystack: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(found) = memchr::memchr(b'\r', haystack.get(at..)?) {
        let index = at + found;
        if haystack.get(index + 1) == Some(&b'\n') {
            return Some(index);
        }
        at = index + 1;
    }
    None
}

/// Whether `octets` holds a bare `LF`: a `\n` whose predecessor — inside these
/// octets — is not a `\r`.
///
/// This is the whole bare-`LF` question for a run of octets with no line
/// structure left. Over a complete message it has to agree with the rule
/// `DATA` applies line by line:
///
/// - a line ending in `\n` that is not `\r\n` — the octet before that `\n` is
///   not a `\r`, or there is no octet before it; and
/// - a `\n` at the start of a line, because the line before ended `\n\n` or
///   began `\n`: in both cases some `\n` has no `\r` immediately before it.
///
/// So one rule covers both: **every `\n` in the message must be directly
/// preceded by a `\r`**, and that is exactly what this checks, in one `memchr`
/// pass over the `\n` octets with a one-octet look-behind at each.
///
/// # What it must be taken over
///
/// The precondition is that `octets` is a run that starts where a line starts
/// (the beginning of the message, or just after a `CRLF`). A run that starts
/// *inside* a line — a chunk boundary, say — cannot be judged alone: a `\n`
/// whose `\r` fell in the previous run looks bare here. So this is called with
/// a whole record, a whole `DATA` body line, or a line's content between two
/// CRLFs, never with an arbitrary fragment.
///
/// The look-behind is what keeps this from being a `contains(b'\n')`: every
/// legal line ending ends in `\n`, so a scan that forgot the `\r` would refuse
/// every message with a line in it.
fn has_bare_lf(octets: &[u8]) -> bool {
    let mut at = 0usize;
    while let Some(found) = memchr::memchr(b'\n', octets.get(at..).unwrap_or(&[])) {
        let index = at + found;
        // A `\n` at index 0 has no predecessor in this run: with the
        // precondition above, the octet before the run is either nothing (the
        // message's first octet) or the `\n` of a `CRLF` — neither is a
        // `\r`, so the line that ends here started with an `LF`.
        if index == 0 || octets[index - 1] != b'\r' {
            return true;
        }
        at = index + 1;
    }
    false
}

/// A reassembled message whose header section cannot be measured: one of its
/// lines does not end in `CRLF`.
///
/// A unit rather than a `bool`, so a caller cannot reach the "measurable" case
/// by forgetting to look at the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MalformedHead;

/// Whether a received line (CRLF included) is the blank line that ends the
/// message's header section.
///
/// A message whose first line is blank has no header fields at all; RFC 5322
/// §2.1 still ends its header section there, so the empty line counts the same
/// way at the start as after a field.
fn header_ends_at(octets: &[u8]) -> bool {
    octets == b"\r\n"
}

/// A boxed bidirectional stream so the driver runs over plain TCP and TLS with
/// the same code.
trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncStream for T {}

enum AuthState {
    /// Waiting for the base64 `authzid NUL authcid NUL passwd` message.
    Plain,
    /// Waiting for the base64 user name of `AUTH LOGIN`.
    LoginUser,
    /// Waiting for the base64 password of the user decoded just before.
    LoginPassword(String),
}

/// One data line without its CRLF, dot-unstuffed, or the terminator.
struct BodyLine {
    /// The octets to store (CRLF re-appended), or `None` for the terminator.
    octets: Option<Vec<u8>>,
    /// The `.` that ends the message.
    end_of_message: bool,
}

/// The largest single data line accepted before its terminator.
const MAX_BODY_LINE: usize = 64 * 1024;

/// How many octets of body are read from the socket at a time. The body goes
/// straight to the spool file, so this is the only body buffer the process
/// keeps; 64 KiB keeps a 25 MiB message at a few thousand reads instead of
/// tens of thousands without growing the resident set.
const BODY_READ_CHUNK: usize = 64 * 1024;

/// How much of the message head is kept in memory for header-level checks
/// (the `Received:` loop count); the body hashes are computed while writing.
///
/// This is a *read* bound, not the acceptance bound: it decides how much of
/// the head the driver keeps for itself, while
/// [`ServerConfig::max_header_bytes`] decides how large a header section the
/// listener accepts at all.
const MAX_HEADER_BUFFER: usize = 256 * 1024;

/// The header section size a listener accepts unless it is configured
/// otherwise: one mebibyte.
///
/// The number is a compromise between two real messages. Real mail sits far
/// below it — a long `Received:` chain from a mailing list is a few kilobytes,
/// and an authenticated submission with a full DKIM/ARC set is tens of
/// kilobytes. A mebibyte leaves an order of magnitude of headroom over both
/// while still being small enough that the streaming verifier's header buffer
/// (which holds the whole section before the body starts) cannot be turned
/// into an allocation a single peer chooses: the message size limit is 25 MiB
/// on a default deployment, and without this bound a 25 MiB message that never
/// ends its headers is 25 MiB of head.
pub const DEFAULT_MAX_HEADER_BYTES: u64 = 1024 * 1024;

/// How much of a client-supplied name (the EHLO argument, the authenticated
/// identity) a `Received:` field carries: a real one is far shorter, and a
/// field has a line-length bound.
const MAX_RECEIVED_TOKEN: usize = 254;

/// How many octets of one BDAT chunk are reassembled in memory. A larger
/// chunk is refused and the client has to use DATA.
pub const MAX_BDAT_BUFFER: usize = 1024 * 1024;

/// The most octets a whole BDAT chain may put in memory at once. It is the
/// message-size limit — the same ceiling `DATA` enforces, so a client cannot
/// send a message by chunks that it could not send at all — and never less
/// than [`MAX_BDAT_BUFFER`], because a chain can never be shorter than its
/// largest single chunk and a smaller ceiling would refuse the chunk the
/// single-chunk bound already admits.
#[must_use]
pub fn max_bdat_total(max_message_size: u64) -> u64 {
    max_message_size.max(MAX_BDAT_BUFFER as u64)
}

/// How a failed `DATA` transfer's drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainEnd {
    /// The client's terminator was found and consumed: the upload is over, but
    /// a sender that split its writes may still be sending its tail.
    Terminator,
    /// The client stopped sending (EOF) or the transaction timer ran out:
    /// nothing more is coming.
    NoMore,
    /// The transaction timer ran out while the client was still sending.
    TimedOut,
}

impl Connection {
    fn new(stream: TcpStream, peer: SocketAddr, config: Arc<ServerConfig>) -> Self {
        let socket = SocketHandle::of(&stream);
        Self::over(Box::pin(stream), peer, config, false, socket)
    }

    /// Performs the TLS handshake on the stream this connection is about to
    /// speak on, for a listener whose TLS comes before the protocol.
    ///
    /// Implicit TLS (RFC 8314 §3.3, the 465 shape) is the one case where the
    /// greeting is not the first octet of the session but the first octet
    /// *inside* it: the client's hello comes first and the server's hello is
    /// the answer to it. Writing the greeting before the handshake would put
    /// plaintext on a TLS port, which is both a protocol violation and a
    /// downgrade surface.
    ///
    /// The socket is kept on the side for the same reason `STARTTLS` keeps
    /// it: `TlsAcceptor::accept` consumes the stream, and a failed handshake
    /// consumes it for good. A client that gives up mid-handshake is closed
    /// here rather than left waiting on a socket whose server end was quietly
    /// dropped.
    async fn handshake(&mut self) -> Result<(), ServerError> {
        let acceptor = self
            .config
            .tls
            .clone()
            .ok_or_else(|| ServerError::Tls("no TLS configuration".to_owned()))?;
        let placeholder = || Box::pin(tokio::io::empty()) as Pin<Box<dyn AsyncStream>>;
        let owned = std::mem::replace(&mut self.stream, placeholder());
        let handle = self.socket.duplicate();
        let stream = match acceptor.accept(owned).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::info!(%err, "TLS handshake failed before the greeting");
                if let Some(mut socket) = handle {
                    let _ = socket.shutdown().await;
                }
                return Err(ServerError::Tls(err.to_string()));
            }
        };
        self.stream = Box::pin(PlainOrTls::Tls(Box::new(stream)));
        self.tls = true;
        Ok(())
    }

    fn over(
        stream: Pin<Box<dyn AsyncStream>>,
        peer: SocketAddr,
        config: Arc<ServerConfig>,
        mut tls: bool,
        socket: SocketHandle,
    ) -> Self {
        let implicit_tls = config.role == ListenerRole::SubmissionsTls;
        let extensions = Extensions {
            max_message_size: config.max_message_size,
            starttls: config.role == ListenerRole::Submission && config.tls.is_some() && !tls,
            auth: if config.role.offers_auth() {
                vec![
                    crate::command::AuthMechanism::Plain,
                    crate::command::AuthMechanism::Login,
                ]
            } else {
                Vec::new()
            },
            smtputf8: true,
            eight_bit_mime: true,
            hostname: config.hostname.clone(),
        };
        // A `SubmissionsTls` connection is TLS before it exists: the acceptor
        // wraps the socket and the handler is built over the wrapped stream,
        // so there is no upgrade left to record and `tls` arrives `false`.
        // Recording it here is what keeps the rest of the driver honest — the
        // greeting, the `Received:` protocol label and the `STARTTLS`
        // capability all read this one flag, and a handler that believed it
        // was still in the clear would label and advertise the opposite.
        tls |= implicit_tls;
        let mut session = Session::new(extensions, config.limits, config.policy.clone());
        if tls {
            session.set_tls_active();
        }
        let secure = tls;
        Self {
            stream,
            peer,
            config,
            session,
            read_buf: Vec::with_capacity(4096),
            discard: None,
            settling: false,
            refused: false,
            auth_state: None,
            tls: secure,
            socket,
            bdat_chain: Vec::new(),
            header: HeaderBudget::default(),
        }
    }

    async fn run(&mut self) -> Result<(), ServerError> {
        if self.config.role.needs_tls() {
            self.handshake().await?;
        }
        let greeting = Session::greeting(&self.config.hostname, self.tls);
        self.write(&greeting).await?;
        loop {
            if self.session.auth_attempts_left() == 0 && self.session.authenticated().is_none() {
                let reply = self.session.outcome(Outcome::AuthenticationLockout);
                self.write(&reply).await?;
                self.shutdown().await;
                return Ok(());
            }
            let Some(line) = self.read_command_line().await? else {
                return Ok(());
            };
            let line = match line {
                Ok(line) => line,
                Err(reason) => {
                    let reply = error_reply(500, "5.5.2", reason);
                    self.write(&reply).await?;
                    self.shutdown().await;
                    return Ok(());
                }
            };
            if let Some(state) = self.auth_state.take() {
                if self.handle_auth_response(state, &line).await? {
                    return Ok(());
                }
                continue;
            }
            let allow_utf8 = matches!(
                self.session.transaction(),
                Transaction::Open(envelope) if envelope.smtputf8
            );
            let text = String::from_utf8_lossy(&line).into_owned();
            let reply = match command::parse(&text, allow_utf8) {
                // Nothing in the tail of a refused upload starts an envelope:
                // see [`Connection::quarantine_refused_upload`]. Every other
                // command is answered normally — this is about who may open a
                // transaction, not about the connection being unusable.
                Ok(Command::Mail { .. }) if self.refused => Some(Reply {
                    code: 503,
                    enhanced: Some("5.5.1"),
                    text: "Bad sequence of commands".to_owned(),
                    lines: Vec::new(),
                    action: Action::Continue,
                }),
                Ok(command) => {
                    let judged_refused = self.refused;
                    let r = self.dispatch(&command).await?;
                    // The command this read carried has now been judged
                    // against `refused`; everything after it is the client
                    // talking again, on a connection that owes it the ordinary
                    // answers. (Cleared after the dispatch for exactly that
                    // reason: the arm above asks the flag, and this is the
                    // command it is asking about.)
                    if judged_refused {
                        self.refused = false;
                    }
                    r
                }
                Err(err) => Some(err.reply()),
            };
            if let Some(reply) = reply {
                let close = reply.action == Action::Close;
                self.write(&reply).await?;
                if close {
                    self.shutdown().await;
                    return Ok(());
                }
            }
        }
    }

    /// Runs one parsed command; returns the reply the driver still has to
    /// send, or `None` when the command already sent its own reply.
    async fn dispatch(&mut self, command: &Command) -> Result<Option<Reply>, ServerError> {
        // The recipient verdict is decided here, at RCPT time: the session
        // only knows the envelope, the router knows the mailboxes.
        //
        // The verdict is computed *before* the command runs (it needs the
        // envelope as it was) but applied *after*: running the command twice
        // would advance the session twice, which is how a BDAT chunk chain
        // once lost its phase.
        let verdict = match command {
            Command::Rcpt { path, .. }
                if self.is_rcpt_legal() && !self.session.at_recipient_limit() =>
            {
                Some(self.recipient_verdict(path))
            }
            _ => None,
        };
        let reply = self.session.command(command);
        if let (Some(verdict), true) = (verdict, reply.code == 250) {
            return Ok(Some(self.session.outcome(verdict)));
        }
        match reply.action.clone() {
            Action::Continue | Action::Close => Ok(Some(reply)),
            Action::StartTls => {
                // The reply is the session's to word; the driver's job is to
                // put it on the wire before the handshake starts. `write`
                // flushes, so the `220` is out of the userspace buffer before
                // the acceptor is handed the stream.
                self.write(&reply).await?;
                self.upgrade_tls().await?;
                Ok(None)
            }
            Action::ReadAuth(continuation) => {
                match continuation {
                    // The driver holds the base64 initial response of
                    // `AUTH PLAIN` (if the client sent one) — the session
                    // already consumed the command, so this is the only place
                    // that knows about it.
                    AuthContinuation::Plain => {
                        if let Command::Auth {
                            initial: Some(initial),
                            ..
                        } = command
                        {
                            if !matches!(initial.as_str(), "" | "=" | "*") {
                                // The response came with the command: verify
                                // it now, without a second round trip.
                                match authn::decode_plain(initial) {
                                    Ok((identity, password)) => {
                                        let outcome =
                                            self.check_password(&identity, &password).await;
                                        self.finish_auth(outcome).await?;
                                    }
                                    Err(_) => {
                                        self.finish_auth(Outcome::AuthenticationFailed).await?;
                                    }
                                }
                                return Ok(None);
                            }
                        }
                        self.auth_state = Some(AuthState::Plain);
                        Ok(Some(reply))
                    }
                    AuthContinuation::LoginUser => {
                        self.auth_state = Some(AuthState::LoginUser);
                        Ok(Some(reply))
                    }
                    AuthContinuation::LoginPassword => {
                        self.auth_state = Some(AuthState::LoginPassword(String::new()));
                        Ok(Some(reply))
                    }
                }
            }
            Action::ReadChunk(size) => {
                // `LAST` comes from the session, not from `command`: the octets
                // of a non-`LAST` chunk are read and acknowledged by this
                // driver, so by the time a later `BDAT … LAST` arrives the
                // session is the only place that knows which chunk is the end
                // of the message.
                let last = self.session.pending_chunk_is_last();
                self.receive_chunk(size, last).await.map(|()| None)
            }
            Action::ReadData => {
                self.write(&reply).await?;
                self.receive_data().await?;
                Ok(None)
            }
        }
    }

    /// Whether a `RCPT` may reach the router at all: the transaction is open
    /// and no content transfer is in progress.
    fn is_rcpt_legal(&self) -> bool {
        matches!(
            self.session.phase(),
            crate::session::Phase::Mail | crate::session::Phase::Rcpt
        ) && self.session.transaction() != &Transaction::Idle
    }

    /// The router's verdict for one recipient on this listener.
    fn recipient_verdict(&self, path: &Mailbox) -> Outcome {
        match self.config.role {
            ListenerRole::Inbound => {
                let sender = match self.session.transaction() {
                    Transaction::Open(envelope) => envelope.sender.clone(),
                    Transaction::Idle => Mailbox::Null,
                };
                // RFC 5321 §4.1.3: `<Postmaster>` with no domain is the
                // postmaster of *this* server, so it is accepted here on the
                // listener that greets for the host — never qualified with a
                // domain the client did not name. W1 stops at the queue: the
                // spool records it as `postmaster@<hostname>` (the name the
                // operator can give an account or alias in W2).
                if path.postmaster_domain().is_some() && self.session.greeted() {
                    return Outcome::RecipientAccepted;
                }
                match decide_recipient(&self.config.state, &sender, path) {
                    RecipientVerdict::Exists => Outcome::RecipientAccepted,
                    RecipientVerdict::Unknown => Outcome::RecipientUnknown,
                    RecipientVerdict::RelayDenied => Outcome::RelayDenied,
                }
            }
            ListenerRole::Submission | ListenerRole::SubmissionsTls => {
                if self.session.authenticated().is_none() {
                    return Outcome::RelayDenied;
                }
                match self.session.transaction() {
                    Transaction::Open(envelope) => {
                        let sender = envelope.sender.as_text();
                        if self.config.policy.may_submit_as(
                            self.session.authenticated().unwrap_or_default(),
                            &sender,
                        ) {
                            Outcome::RecipientAccepted
                        } else {
                            // A submission may not claim a From it does not own.
                            Outcome::RecipientInvalid
                        }
                    }
                    Transaction::Idle => Outcome::RelayDenied,
                }
            }
        }
    }

    // ── AUTH ─────────────────────────────────────────────────────────────

    /// Handles one SASL response line. Returns `true` when the connection
    /// must close.
    async fn handle_auth_response(
        &mut self,
        state: AuthState,
        line: &[u8],
    ) -> Result<bool, ServerError> {
        let response = String::from_utf8_lossy(line).trim().to_owned();
        match state {
            AuthState::Plain => match authn::decode_plain(&response) {
                Ok((identity, password)) => {
                    let outcome = self.check_password(&identity, &password).await;
                    self.finish_auth(outcome).await
                }
                Err(_) => self.finish_auth(Outcome::AuthenticationFailed).await,
            },
            AuthState::LoginUser => match authn::decode_login_field(&response) {
                Ok(user) => {
                    if !authn::valid_identity(&user) {
                        self.auth_state = None;
                        return self
                            .finish_auth(Outcome::AuthenticationIdentityInvalid)
                            .await;
                    }
                    self.auth_state = Some(AuthState::LoginPassword(user));
                    let challenge = Reply {
                        code: 334,
                        enhanced: None,
                        text: "UGFzc3dvcmQ6".to_owned(),
                        lines: Vec::new(),
                        action: Action::Continue,
                    };
                    self.write(&challenge).await?;
                    Ok(false)
                }
                Err(_) => self.finish_auth(Outcome::AuthenticationFailed).await,
            },
            AuthState::LoginPassword(user) => {
                let outcome = match authn::decode_login_field(&response) {
                    Ok(password) => self.check_password(&user, &password).await,
                    Err(_) => Outcome::AuthenticationFailed,
                };
                self.finish_auth(outcome).await
            }
        }
    }

    /// Runs the credential check, charging the outcome to the peer address.
    ///
    /// Every path into AUTH goes through here, which is what makes the
    /// per-address budget cover all of them (PLAIN with an initial response,
    /// the PLAIN continuation, both steps of LOGIN) rather than the one
    /// command shape a client happened to use.
    async fn check_password(&self, identity: &str, password: &str) -> Outcome {
        // Not a mailbox at all (`ops@example.com\r\nBcc: …`, a bare name, an
        // empty field): a syntax answer, before the credential — and before
        // the per-address failure budget, which counts guesses, not noise.
        if !authn::valid_identity(identity) {
            return Outcome::AuthenticationIdentityInvalid;
        }
        // An address that spent its budget is refused **before the credential
        // is looked at**: otherwise every guess would still reach the password
        // verifier for the whole window, which is the work the bound exists to
        // stop. A correct password from such an address is refused too — the
        // cost is one window of waiting, and the alternative is a client that
        // cannot be slowed down at all.
        if let Some(guard) = &self.config.auth_guard {
            if let AuthGate::Refused { retry_after } = guard.admit(self.peer.ip(), Instant::now()) {
                tracing::info!(
                    peer = %self.peer,
                    failures = guard.failures(self.peer.ip()),
                    "AUTH refusal budget spent, refusing further attempts"
                );
                return Outcome::PeerAuthenticationLockout { retry_after };
            }
        }
        let passwords = Arc::clone(&self.config.passwords);
        let identity = self.login_identity(identity);
        if passwords.verify(&identity, password).await {
            if let Some(guard) = &self.config.auth_guard {
                guard.record_success(self.peer.ip());
            }
            Outcome::Authenticated(identity.to_ascii_lowercase())
        } else {
            if let Some(guard) = &self.config.auth_guard {
                // The failure is counted; the *next* connection sees the
                // spent budget and is refused without a credential check at
                // all.
                guard.record_failure(self.peer.ip(), Instant::now());
            }
            Outcome::AuthenticationFailed
        }
    }

    /// The mailbox a login identity is looked up as.
    ///
    /// `Mailbox::parse` admits one identity the store cannot name as written:
    /// the bare `postmaster` of RFC 5321 §4.1.3, which has no domain and means
    /// "this server's". A path is qualified with the host the session greets
    /// for, and the identity is qualified the same way — through the same
    /// function, [`Session`]'s recorded recipient, rather than a second rule
    /// here — so the session that logs in as `postmaster` submits as
    /// `postmaster@<hostname>` exactly as it does after `MAIL FROM:<postmaster>`.
    /// Every other identity is looked up as written.
    fn login_identity(&self, identity: &str) -> String {
        match Mailbox::parse(identity, true) {
            Ok(mailbox @ Mailbox::Address { .. }) if mailbox.postmaster_domain().is_some() => {
                self.session.qualify(&mailbox).as_text()
            }
            _ => identity.to_owned(),
        }
    }

    async fn finish_auth(&mut self, outcome: Outcome) -> Result<bool, ServerError> {
        let reply = self.session.outcome(outcome);
        let close = reply.action == Action::Close;
        self.write(&reply).await?;
        if close {
            self.shutdown().await;
        }
        Ok(close)
    }

    // ── DATA ─────────────────────────────────────────────────────────────

    async fn receive_data(&mut self) -> Result<(), ServerError> {
        let Some(envelope) = self.session.envelope() else {
            self.session.fail_data();
            return self.reply_end(false).await;
        };
        let sender = envelope.sender.clone();
        let recipients: Vec<Mailbox> = envelope.recipients.to_vec();
        let declared_size = envelope.declared_size;
        let smtputf8 = envelope.smtputf8;

        let id = self.config.spool.next_id();
        let mut staged = match self
            .config
            .spool
            .stage(&id, Envelope::placeholder(&id, &self.config.hostname))
        {
            Ok(staged) => staged,
            Err(err) => {
                tracing::error!(%err, "cannot create spool file");
                self.session.fail_data();
                return self.reply_end(false).await;
            }
        };
        let mut hasher = crate::verify::BodyHasher::new();
        let mut head = Vec::with_capacity(4096);
        self.header = HeaderBudget::default();
        let deadline = tokio::time::Instant::now() + self.config.transaction_timeout;
        loop {
            let line = match tokio::time::timeout_at(deadline, self.read_body_line()).await {
                Err(_) => {
                    staged.abandon();
                    self.timeout_close().await?;
                    return Ok(());
                }
                Ok(line) => line?,
            };
            let Some(line) = line else {
                // The client hung up mid-body: nothing was acknowledged.
                staged.abandon();
                return Ok(());
            };
            let line = match line {
                Ok(line) => line,
                Err(reason) => {
                    tracing::info!(reason, "DATA transfer rejected");
                    staged.abandon();
                    // The rest of the upload is body, including any `.<CRLF>`
                    // line in it and everything behind that line: it is all
                    // drained into the discard buffer, never read back as
                    // commands. A bare `LF` is not a terminator, so a sender
                    // that puts one on the wire chooses where this drain ends
                    // — and for exactly that reason what it drains is thrown
                    // away rather than transacted (see
                    // [`Connection::discard_buffered_data`]).
                    self.finish_failed_transfer(deadline, true).await?;
                    self.session.fail_data();
                    self.reply_end(false).await?;
                    // The refused transfer leaves the session with **no
                    // envelope**, and it stays that way until the client asks
                    // for a new one. That is what makes a `MAIL FROM` arriving
                    // in the tail of the refused upload — a sender that
                    // writes after its terminator, or splits its writes — a
                    // `503 Bad sequence` this server answers instead of a
                    // transaction it runs. `end_of_message(false)` already
                    // reset the envelope; calling this makes that reset the
                    // state the next command is judged against.
                    self.quarantine_refused_upload();
                    return Ok(());
                }
            };
            if line.end_of_message {
                break;
            }
            let Some(octets) = line.octets else {
                continue;
            };
            if staged.size() + octets.len() as u64 > self.config.max_message_size {
                staged.abandon();
                // The refused message's remaining octets are body: they are
                // drained, never executed.
                self.finish_failed_transfer(deadline, false).await?;
                self.session.fail_data();
                return self.reply_end(false).await;
            }
            // The header bound is charged here, before the octets are written
            // or hashed, and it is charged whether or not this listener
            // verifies: the reason the bound exists is the verifier's buffer,
            // but a header section this large is not something to accept into
            // a mailbox either, and a bound that exists only when a verifier is
            // wired would be a bound a deployment can lose by misconfiguring
            // one `Option`.
            self.header.consume(&octets);
            if self.header.over(self.config.max_header_bytes) {
                tracing::info!(
                    consumed = self.header.consumed,
                    limit = self.config.max_header_bytes,
                    "header section over the bound, refusing the message"
                );
                staged.abandon();
                // The message is refused at the point its head outgrew the
                // bound; the rest of the upload is still body and is drained,
                // never executed.
                self.finish_failed_transfer(deadline, false).await?;
                self.session.fail_data();
                let reply = header_too_large();
                self.write(&reply).await?;
                return Ok(());
            }
            if let Err(err) = staged.write(&octets) {
                tracing::error!(%err, "spool write failed");
                staged.abandon();
                self.finish_failed_transfer(deadline, false).await?;
                self.session.fail_data();
                return self.reply_end(false).await;
            }
            hasher.write(&octets);
            if head.len() < MAX_HEADER_BUFFER {
                let take = (MAX_HEADER_BUFFER - head.len()).min(octets.len());
                head.extend_from_slice(&octets[..take]);
            }
        }
        let envelope = self.finish_envelope(&sender, &recipients, declared_size, smtputf8);
        self.complete(staged, hasher, &head, envelope).await
    }

    /// Reads one BDAT chunk and answers it.
    ///
    /// RFC 3030 §4.2: every chunk gets its own reply, and the reply to the
    /// `LAST` chunk is the transaction's answer (250 once the queue has
    /// accepted it, 552/554 otherwise). A chunk that is not `LAST` is
    /// acknowledged with 250 as soon as its octets are in, so a client that
    /// pipelines chunks learns about a failure before sending the rest.
    ///
    /// The session bounds the **declared** running total against the message
    /// size (RFC 1870) and answers that one with `552` before any octet is
    /// read, so this function is only entered for a chunk the session already
    /// admitted. What is left for the transport is the one bound the session
    /// cannot make: a single chunk larger than [`MAX_BDAT_BUFFER`] still fits
    /// inside a sane message size, and the connection must not be made to hold
    /// it. Such a chunk cannot be answered with `552`/`554` either — the
    /// command already has its `250`, and a second reply would desynchronise
    /// the client's own pipelining — so the connection closes with `421`
    /// instead, without reading a single octet of it: those octets are neither
    /// message content nor commands, they were never accepted as a chunk, and
    /// a client that sent none of them must not be made to wait for a timer.
    ///
    /// The whole-chain ceiling ([`max_bdat_total`]) is checked here too, but
    /// only as an assertion: it is the session's arithmetic written a second
    /// time, not a second bound (see the module note).
    async fn receive_chunk(&mut self, size: u64, last: bool) -> Result<(), ServerError> {
        // One refusal lives here, and it is the chunk the memory bound exists
        // for: a single chunk larger than [`MAX_BDAT_BUFFER`]. The session
        // admits it whenever the whole of it still fits in the message size —
        // the two ceilings are different numbers, and the message size is the
        // larger one on any deployment of sane size — so this is the line that
        // keeps a client from making the connection hold a chunk the process
        // was never meant to hold. Its octets are not part of any message yet
        // (RFC 3030 §4.2 wants the refusal before they are sent) and were
        // never accepted as a chunk, so they are not read at all: a client
        // that sends them is answered with the close, and a client that sends
        // none of them is not made to wait for a timer.
        //
        // The *other* two conditions this branch used to carry are not runtime
        // checks at all. A chunk the session refused — its declared running
        // total past the message size — got `552` from `Session::bdat` with
        // `Action::Continue`, so this function is never entered for it; and
        // the chain ceiling is the session's own arithmetic written a second
        // time, because the session's running total is the sum of exactly the
        // chunks this function appended and `max_bdat_total` is the message
        // size raised to one chunk. Both are stated as assertions below: a
        // debug build fails loudly if the dispatch contract ever changes, and
        // a production build pays nothing for them. Do not write a test that
        // expects either to answer a command — they cannot.
        let over_buffer = size > MAX_BDAT_BUFFER as u64;
        // The session has already admitted this chunk, so the chain is at its
        // first chunk exactly when no octets are held: that is where a new
        // message's header section starts.
        if self.bdat_chain.is_empty() {
            self.header = HeaderBudget::default();
        }
        debug_assert_eq!(
            self.session.phase(),
            crate::session::Phase::Bdat,
            "receive_chunk is only reached for a chunk the session admitted"
        );
        debug_assert!(
            (self.bdat_chain.len() as u64).saturating_add(size)
                <= max_bdat_total(self.config.max_message_size),
            "a chunk the session admitted is a chunk the chain can hold: got {size} \
             on top of {}, against {}",
            self.bdat_chain.len(),
            max_bdat_total(self.config.max_message_size)
        );
        if over_buffer {
            tracing::info!(
                chunk = size,
                max = MAX_BDAT_BUFFER,
                "BDAT chunk is larger than the chunk buffer, closing without reading it"
            );
            self.bdat_chain = Vec::new();
            let reply = self.session.chunk_abandon();
            self.write(&reply).await?;
            self.shutdown().await;
            return Ok(());
        }
        self.session.chunk_reading();
        let Some(envelope) = self.session.envelope() else {
            self.session.fail_data();
            return self.reply_end(false).await;
        };
        let sender = envelope.sender.clone();
        let recipients: Vec<Mailbox> = envelope.recipients.to_vec();
        let declared_size = envelope.declared_size;
        let smtputf8 = envelope.smtputf8;
        let mut chunk = vec![0u8; size as usize];
        let mut filled = 0usize;
        while filled < chunk.len() {
            let want = chunk.len() - filled;
            // Take what is already buffered first: `fill` appends, so asking it
            // for octets that are in `read_buf` parks on a read that never
            // completes while the client waits for its acknowledgement.
            let buffered = drain_front(&mut self.read_buf, want);
            if !buffered.is_empty() {
                let length = buffered.len();
                chunk[filled..filled + length].copy_from_slice(&buffered);
                filled += length;
                continue;
            }
            // The session admitted this chunk, so its octets are coming: the
            // transaction timer is the bound on a client that stops sending
            // part way through.
            let deadline = tokio::time::Instant::now() + self.config.transaction_timeout;
            let available = match self.fill(want, Some(deadline)).await {
                Ok(()) => self.read_buf.len(),
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    self.bdat_chain = Vec::new();
                    self.timeout_close().await?;
                    return Ok(());
                }
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => 0,
                Err(err) => return Err(err.into()),
            };
            if available == 0 {
                // The client hung up mid-chunk: nothing was acknowledged.
                self.bdat_chain = Vec::new();
                return Ok(());
            }
            let take = want.min(available);
            let piece = drain_front(&mut self.read_buf, take);
            let got = piece.len();
            chunk[filled..filled + got].copy_from_slice(&piece);
            filled += got;
        }
        self.session.chunk_received(size);
        self.bdat_chain.extend_from_slice(&chunk);
        if !last {
            // More chunks follow; nothing is staged until LAST arrives, and
            // this chunk is acknowledged as soon as its octets are in.
            return self.ack_chunk().await;
        }
        // The chunk chain is reassembled into the message as the client sent
        // it: chunks are raw octets, so they are concatenated, never
        // re-terminated or dot-unstuffed.
        let record = std::mem::take(&mut self.bdat_chain);
        let id = self.config.spool.next_id();
        let mut staged = match self
            .config
            .spool
            .stage(&id, Envelope::placeholder(&id, &self.config.hostname))
        {
            Ok(staged) => staged,
            Err(err) => {
                tracing::error!(%err, "cannot create spool file");
                self.session.fail_data();
                return self.reply_end(false).await;
            }
        };
        if let Err(err) = staged.write(&record) {
            tracing::error!(%err, "spool write failed");
            staged.abandon();
            self.session.fail_data();
            return self.reply_end(false).await;
        }
        // The header bound, applied to the reassembled message. It cannot be
        // charged line by line the way `DATA` charges it — a chunk is raw
        // octets with no line structure until the chain is whole — so the
        // blank line is located *in* the message here and only the section it
        // closes is charged ([`HeaderBudget::charge_message`]). Charging the
        // whole record instead would count every chained message's body as
        // header: the same message would be refused over `BDAT` and accepted
        // over `DATA`, which is a discrepancy a sender can see and a refusal a
        // legitimate chunking client can do nothing about.
        self.header = HeaderBudget::default();
        // Where the body starts, from the same function that sized the head:
        // every octet from there on is the part `DATA` would have read *as
        // body*, and it is scanned below for the bare `LF` the head's own scan
        // never looks at.
        let body_from = match self.header.charge_message(&record) {
            Ok(body_from) => body_from,
            Err(MalformedHead) => {
                // The same message over `DATA` would have been refused while it
                // was being read; refusing it here answers the same way. `554` is
                // the reply the session gives a transaction it did not complete
                // (`end_of_message(false)`), which is exactly what the `DATA` path
                // sends for a bare `LF` — so a client sees one answer per
                // transport, and not a `250` from the transport that never looked.
                tracing::info!("chained message has a bare LF in its header section, refusing");
                staged.abandon();
                self.session.fail_data();
                return self.reply_end(false).await;
            }
        };
        // The body half of the same rule. A chunk is opaque octets, so nothing
        // refused a `LF` in it that was not part of a `CRLF`; `DATA` refuses such
        // a body outright (CVE-2023-51764's smuggling shape lives here, not in
        // the head), and a record accepted over one transport and refused over
        // the other is a difference a sender can probe for. Same refusal, same
        // code and text, and the message is never spooled: `staged.abandon()`
        // removes the file and the transaction is reset with it.
        if scan_record(&record, body_from).is_err() {
            tracing::info!(
                from = body_from,
                size = record.len(),
                "chained message has a bare LF in its body, refusing"
            );
            staged.abandon();
            self.session.fail_data();
            return self.reply_end(false).await;
        }
        if self.header.over(self.config.max_header_bytes) {
            tracing::info!(
                consumed = self.header.consumed,
                limit = self.config.max_header_bytes,
                "header section over the bound, refusing the message"
            );
            staged.abandon();
            self.session.fail_data();
            let reply = header_too_large();
            self.write(&reply).await?;
            return Ok(());
        }
        let mut hasher = crate::verify::BodyHasher::new();
        hasher.write(&record);
        // Only the head of a message is kept for the header-level checks: the
        // `Received:` loop count reads the start of it, and nothing reads
        // past [`MAX_HEADER_BUFFER`].
        let head = &record[..record.len().min(MAX_HEADER_BUFFER)];
        let envelope = self.finish_envelope(&sender, &recipients, declared_size, smtputf8);
        self.complete(staged, hasher, head, envelope).await
    }

    /// The reply to a chunk that did not end the message.
    async fn ack_chunk(&mut self) -> Result<(), ServerError> {
        let reply = Reply {
            code: 250,
            enhanced: Some("2.0.0"),
            text: "OK".to_owned(),
            lines: Vec::new(),
            action: Action::Continue,
        };
        self.write(&reply).await
    }

    /// Throws away the rest of a failed `DATA` transfer up to its terminator,
    /// reading from the socket as needed. Returns `false` when the client
    /// stopped sending (EOF or the transaction timer), which the caller
    /// answers by closing rather than by waiting.
    async fn drain_until_dot(&mut self, deadline: tokio::time::Instant) -> DrainEnd {
        // A single read may return less than everything the client wrote, so
        // keep reading until the terminator is in the buffer or the stream
        // ends; the buffer is scanned before every read.
        //
        // Each pass starts three octets back from where the last one stopped
        // looking, which is all a terminator arriving in pieces needs: `\r`,
        // `\r\n` and `\r\n.` are the only prefixes that can turn into a hit
        // when more octets arrive, and the longest is three. The first pass
        // starts at 0 — the buffer's front is exactly where a `.<CRLF>` line
        // already sits when the failing transfer had one buffered
        // ([`Connection::discard_buffered_data`] hands this drain everything
        // that was ahead of it), and a cursor that started at the buffer's
        // length would step over that terminator: the drain would then wait out
        // the transaction timer for an answer the client had already supplied.
        let mut prefill = 64 * 1024;
        let mut scanned = 0usize;
        loop {
            let discard = self.discard.as_deref().unwrap_or_default();
            if let Some(position) = find_terminator(discard, scanned) {
                if let Some(buffer) = &mut self.discard {
                    buffer.drain(..position);
                }
                return DrainEnd::Terminator;
            }
            scanned = discard.len().saturating_sub(3);
            if prefill == 0 {
                return DrainEnd::NoMore;
            }
            match self.fill_available(prefill, deadline).await {
                Ok(0) => return DrainEnd::NoMore,
                Ok(read) => {
                    // Widen each read so a big body is not read a page at a
                    // time.
                    prefill = read.saturating_mul(4).min(1024 * 1024);
                }
                Err(err) if err.kind() == io::ErrorKind::TimedOut => return DrainEnd::TimedOut,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return DrainEnd::NoMore,
                Err(_) => return DrainEnd::NoMore,
            }
        }
    }

    /// Reads up to `want` octets with `deadline`, appending to `read_buf`.
    /// Unlike [`Connection::fill`] it reports EOF as zero octets, so a caller
    /// draining can tell "the client is done" from "the flush is early".
    async fn fill_available(
        &mut self,
        want: usize,
        deadline: tokio::time::Instant,
    ) -> io::Result<usize> {
        // The read fills a buffer of its own, and only the octets it says it
        // read are appended. Reading into the tail of `read_buf` would put the
        // socket's output straight into the vector while the vector's length
        // still says otherwise: a caller that checked the length first would
        // see an empty buffer and park on a second read of octets that already
        // arrived, and a caller that trusted the vector's length would read
        // padding as octets.
        //
        // A `read` that is cut by its timer reports the timeout and nothing
        // else: tokio rebuilds its `ReadBuf` on every poll, so a poll that put
        // octets in and returned `Pending` leaves them in `buffer` and the
        // caller appends none of them. That cannot happen on the socket this
        // runs over — a readable socket is polled once and reports `Ready`,
        // measured on loopback with the deadline 5 ms away — so the buffer is
        // read only on the `Ready` path, where `read` is the count of what
        // arrived.
        let mut buffer = vec![0u8; want.max(1)];
        let read = match tokio::time::timeout_at(deadline, self.stream.read(&mut buffer)).await {
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
            }
            Ok(Ok(read)) => read,
            Ok(Err(err)) => return Err(err),
        };
        // While a failed transfer is being drained, what arrives is message
        // octets, not commands: it goes to the discard buffer, which the
        // command reader never looks at. Reading it into `read_buf` would make
        // the octets a client sent *after* its terminator executable, which is
        // the second half of the smuggling this drain exists to prevent (see
        // [`Connection::discard_buffered_data`]).
        match &mut self.discard {
            Some(discard) => discard.extend_from_slice(&buffer[..read]),
            None => self.read_buf.extend_from_slice(&buffer[..read]),
        }
        Ok(read)
    }

    /// Runs verification and the queue commit, then answers the transaction.
    async fn complete(
        &mut self,
        mut staged: StagedMessage,
        hasher: crate::verify::BodyHasher,
        head: &[u8],
        envelope: Envelope,
    ) -> Result<(), ServerError> {
        if received_count(head) > self.config.max_received_headers {
            staged.abandon();
            self.session.fail_data();
            return self.reply_end(false).await;
        }
        let received = received_header(&self.config, self.peer, &self.session, self.tls);
        let verdict = match &self.config.verifier {
            Some(verifier) => {
                let facts = SessionFacts {
                    remote_ip: self.peer.ip(),
                    helo: self
                        .session
                        .hello()
                        .map_or_else(|| "unknown".to_owned(), |(_, name)| name.to_owned()),
                    mail_from: envelope.mail_from.clone(),
                    authenticated: envelope.authenticated.clone(),
                };
                let streamed = match hasher.finish() {
                    Ok(streamed) => streamed,
                    Err(err) => {
                        tracing::warn!(%err, "message has no parsable header");
                        staged.abandon();
                        self.session.fail_data();
                        return self.reply_end(false).await;
                    }
                };
                verifier.verify(streamed, &facts, &received).await
            }
            None => crate::verify::Verification {
                verdict: PolicyVerdict::Accept,
                prepend: Vec::new(),
                summary: "verification disabled".to_owned(),
            },
        };
        if verdict.verdict == PolicyVerdict::Reject {
            tracing::info!(summary = %verdict.summary, "message refused by DMARC policy");
            staged.abandon();
            self.session.fail_data();
            return self.reply_end(false).await;
        }
        let mut stored = envelope;
        stored.received = received;
        stored.auth_summary = verdict.summary;
        staged.set_envelope(stored);
        match staged.commit_with_prepend(&verdict.prepend) {
            Ok(queued) => {
                tracing::info!(
                    id = %queued.id,
                    size = queued.envelope.size,
                    recipients = queued.envelope.recipients.len(),
                    "message queued"
                );
                let reply = self.session.end_of_message(true);
                self.write(&reply).await?;
                if reply.action == Action::Close {
                    self.shutdown().await;
                }
                Ok(())
            }
            Err(err) => {
                tracing::error!(%err, "spool commit failed");
                self.session.fail_data();
                self.reply_end(false).await
            }
        }
    }

    fn finish_envelope(
        &self,
        sender: &Mailbox,
        recipients: &[Mailbox],
        declared_size: Option<u64>,
        smtputf8: bool,
    ) -> Envelope {
        let mut envelope = Envelope::placeholder("", &self.config.hostname);
        envelope.received_at = crate::server::received_now();
        envelope.mail_from = sender.as_text();
        envelope.mail_from_wire = sender.to_string();
        envelope.helo = self
            .session
            .hello()
            .map_or_else(|| "unknown".to_owned(), |(_, name)| name.to_owned());
        envelope.remote_ip = self.peer.ip().to_string();
        envelope.authenticated = self.session.authenticated().map(str::to_owned);
        envelope.recipients = recipients.iter().map(Mailbox::as_text).collect();
        envelope.declared_size = declared_size;
        envelope.smtputf8 = smtputf8;
        envelope
    }

    async fn reply_end(&mut self, ok: bool) -> Result<(), ServerError> {
        let reply = self.session.end_of_message(ok);
        let close = reply.action == Action::Close;
        self.write(&reply).await?;
        if close {
            self.shutdown().await;
        }
        Ok(())
    }

    async fn timeout_close(&mut self) -> Result<(), ServerError> {
        let reply = error_reply(
            421,
            "4.4.2",
            "Timeout while receiving message, closing connection",
        );
        self.write(&reply).await?;
        self.shutdown().await;
        Ok(())
    }

    /// Throws away everything already read past the end of a **failed**
    /// `DATA` transfer, up to and including the terminator, and stops the
    /// command reader from seeing anything the client sends after it.
    ///
    /// A body over a line bound, or a line with a bare `LF`, is failed *after*
    /// it was received; what the client already sent past the failing point is
    /// still in the read buffer and would otherwise be executed as commands —
    /// the exact desync a smuggling test looks for. Draining here makes the
    /// reset complete before the `554` goes out.
    ///
    /// # Why the octets after the terminator are discarded too
    ///
    /// The terminator that ends this drain is a **`.<CRLF>` line**, whatever
    /// came before it. A `DATA` transfer that is already failing therefore
    /// stops at the first `.<CRLF>` in the stream — including one the sender
    /// put behind a bare `LF` (`…\r\nprompt\n.\r\nMAIL FROM:<evil@…>\r\n…`),
    /// where the drain's first terminator candidate is that line. Everything
    /// from the failing octet to that line is body: it was never acknowledged,
    /// never queued, and it is being thrown away right here. Handing it, or
    /// what follows it, back to the command reader would turn "the server
    /// refused this transfer" into "the server transacted whatever the sender
    /// put behind its terminator", and a sender that controls the terminator
    /// can put a whole forged transaction there. So the drain's octets go to
    /// [`Connection::discard`] instead of [`Connection::read_buf`], and the
    /// buffer — including whatever `read_buf` already held past the failing
    /// point — is dropped.
    ///
    /// What that costs is pipelining *behind a failed transfer*, and that is
    /// the point: after a failure the only safe thing for a transfer to leave
    /// in the stream is nothing. A client that pipelines its next command
    /// behind an upload it has not been told about yet is not a client this
    /// server can keep in step — the connection is already in the middle of a
    /// message that is going to be discarded, and the next thing it would
    /// read is command text chosen by whoever wrote that message.
    ///
    /// When the transfer failed **on** the octets it sent, this is the same
    /// thing with a shorter drain: the `.<CRLF>` is the next thing in the
    /// buffer, so the drain ends immediately and the client is answered at
    /// once. There is deliberately no short-cut that skips the drain for that
    /// case — a bare `LF` is not a terminator, and the octets behind the one
    /// that follows it have to be discarded either way.
    fn discard_buffered_data(&mut self) {
        self.discard = Some(std::mem::take(&mut self.read_buf));
    }

    /// Marks the connection as having just refused a `DATA` transfer, so that
    /// nothing written into the tail of that upload starts a transaction.
    ///
    /// The drain consumed the client's terminator, which means anything the
    /// client still had queued was written **before** it read the `554` — it
    /// is the rest of the message the server just refused, and for a sender
    /// that writes a forged transaction there, it is the smuggling attempt
    /// itself. The session cannot tell those octets from a fresh envelope
    /// (both are `MAIL FROM:` lines), so the driver marks the connection
    /// instead: a `MAIL FROM` that arrives while `refused` is set is answered
    /// `503 Bad sequence` and opens nothing.
    ///
    /// `refused` is cleared by the read that consumes `settling`. Both flags
    /// arm together in [`Connection::finish_failed_transfer`]:
    ///
    /// - `settling` — the *read* that ends settling has its octets dropped, and
    /// - `refused` — every `MAIL FROM` from that read until the next one is
    ///   answered `503`.
    ///
    /// A command **already** in `read_buf` when the refusal went out is not
    /// affected: it was written before the drain could have consumed anything
    /// of it, and it is exactly the "new transaction after the answer" the
    /// rest of this module promises to serve.
    fn quarantine_refused_upload(&mut self) {
        self.session.end_after_refusal();
        self.refused = true;
    }

    /// Spends `settling` on one read: the octets that read brought are the
    /// tail of an upload this connection already refused, so nothing in them is
    /// executed.
    ///
    /// A *complete line* is kept. Nothing about a line's content can tell a
    /// tail from a command the client wrote — both are just an `LF`-terminated
    /// line — but a line that arrives **while a forged transaction in it would
    /// be pointless** is handled by the session instead: the refusal left the
    /// session with no envelope (see [`Session::end_after_refusal`]), so a
    /// `MAIL FROM` among them is answered `503 Bad sequence` and runs nothing.
    /// What survives here is a **new transaction the client starts after the
    /// refusal** — the case the attacker cannot gain from, because starting a
    /// transaction requires being allowed to send commands at all.
    fn settle(&mut self) {
        self.settling = false;
        if !self.read_buf.contains(&b'\n') {
            self.read_buf.clear();
        }
    }

    /// Throws away what is left of a failed transfer: the octets already
    /// buffered, and then — if the client is still uploading — the stream up
    /// to the terminator, bounded by the transaction timer.
    ///
    /// A message refused for its size is *not* drained: the octets already
    /// received are discarded and the answer goes out, because the client has
    /// tens of megabytes left to send and waiting for its terminator would let
    /// one connection hold the server's bandwidth for as long as the timer
    /// allows (the connection stays in the read-then-validate loop, which is
    /// what W2's size handling will keep). Its refusal ends the transaction on
    /// its own: the session has already failed it, so the next command the
    /// client sends is answered `554` rather than run.
    async fn finish_failed_transfer(
        &mut self,
        deadline: tokio::time::Instant,
        drain_stream: bool,
    ) -> Result<(), ServerError> {
        self.discard_buffered_data();
        self.settling = false;
        if !drain_stream {
            return Ok(());
        }
        // The stream is drained up to the client's terminator (or until the
        // client stops sending), and the drain buffer goes with it: there is
        // nothing left of the failed transfer to keep.
        let dbg_end = self.drain_until_dot(deadline).await;
        match dbg_end {
            DrainEnd::Terminator => {
                // The terminator was consumed, so the *next* octets to arrive
                // belong to a transfer the client wrote before it learned the
                // transfer failed: a sender that splits its upload across
                // writes lands here, with the tail of its message behind the
                // terminator it already sent. Nothing knows where that tail
                // ends, so nothing of it may be executed — the read that comes
                // next discards whatever arrived meanwhile
                // ([`Connection::settle`]).
                self.settling = true;
                self.refused = true;
            }
            // EOF or the transaction timer: nothing more is coming from this
            // upload, and a later octet is a new command (a clean transaction
            // the client starts after the refusal).
            DrainEnd::NoMore | DrainEnd::TimedOut => {}
        }
        self.discard = None;
        Ok(())
    }

    // ── TLS ──────────────────────────────────────────────────────────────

    /// Discards every buffered plaintext octet, then runs the handshake.
    ///
    /// This is the VU#555316 fix: a client that pipelines
    /// `STARTTLS\r\nMAIL FROM:…\r\n` in one write must not have the second
    /// line executed after the handshake (the session already forgets
    /// everything on STARTTLS, and dropping the buffer means the bytes can
    /// never be re-read as commands either).
    async fn upgrade_tls(&mut self) -> Result<(), ServerError> {
        self.read_buf.clear();
        self.settling = false;
        let acceptor = self
            .config
            .tls
            .clone()
            .ok_or_else(|| ServerError::Tls("no TLS configuration".to_owned()))?;
        // The handshake consumes the stream, and a failed one consumes it for
        // good: `TlsAcceptor::accept` drops what it was given. The real socket
        // is therefore held on the side — the handle taken when this
        // connection was created — so that a failed handshake can close the
        // connection the client is waiting on instead of leaving it to time
        // out on a socket whose server end was quietly dropped.
        let placeholder = || Box::pin(tokio::io::empty()) as Pin<Box<dyn AsyncStream>>;
        let owned = std::mem::replace(&mut self.stream, placeholder());
        let handle = self.socket.duplicate();
        let stream = match acceptor.accept(owned).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::info!(%err, "TLS handshake failed");
                match handle {
                    Some(mut socket) => {
                        // FIN reaches the client as soon as this returns.
                        let _ = socket.shutdown().await;
                    }
                    None => tracing::warn!("TLS handshake failed and the socket could not be kept"),
                }
                return Err(ServerError::Tls(err.to_string()));
            }
        };
        self.stream = Box::pin(PlainOrTls::Tls(Box::new(stream)));
        self.tls = true;
        Ok(())
    }

    // ── byte plumbing ────────────────────────────────────────────────────

    async fn write(&mut self, reply: &Reply) -> Result<(), ServerError> {
        self.stream.write_all(&reply.to_wire()).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// Reads more octets into `read_buf`, at most `want`.
    async fn fill(
        &mut self,
        want: usize,
        deadline: Option<tokio::time::Instant>,
    ) -> io::Result<()> {
        let buffer_end = self.read_buf.len();
        self.read_buf.resize(buffer_end + want.max(1), 0);
        let read = {
            let slice = &mut self.read_buf[buffer_end..];
            let result = match deadline {
                Some(deadline) => {
                    match tokio::time::timeout_at(deadline, self.stream.read(slice)).await {
                        Err(_) => {
                            self.read_buf.truncate(buffer_end);
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
                        }
                        Ok(read) => read,
                    }
                }
                None => self.stream.read(slice).await,
            };
            match result {
                Ok(read) => read,
                Err(err) => {
                    self.read_buf.truncate(buffer_end);
                    return Err(err);
                }
            }
        };
        self.read_buf.truncate(buffer_end + read);

        Ok(())
    }

    /// Reads one command line, enforcing the 1000-octet limit and the command
    /// timer. Returns `None` when the connection must end quietly.
    async fn read_command_line(
        &mut self,
    ) -> Result<Option<Result<Vec<u8>, &'static str>>, ServerError> {
        let deadline = tokio::time::Instant::now() + self.config.command_timeout;
        // A failed transfer whose drain ended on the client's terminator may
        // still have its tail on the way (`Connection::settling`). Two places
        // have to discard it, and this is the first: **unterminated** octets
        // already in `read_buf`. Only those can be a tail. A complete line is a
        // command the client wrote — pipelined in the same write as the
        // terminator, or brought by the same `read` — and dropping it would
        // silently eat the client's next request. Its length is not the
        // test: a command is whatever ends in a `CRLF`, and the parser is the
        // thing that answers a line that is too long.
        if self.settling && !self.read_buf.contains(&b'\n') && !self.read_buf.is_empty() {
            self.read_buf.clear();
        }

        loop {
            if let Some(position) = self.read_buf.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.read_buf.drain(..=position).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > MAX_COMMAND_LINE {
                    return Ok(Some(Err("Line too long")));
                }
                return Ok(Some(Ok(line)));
            }
            if self.read_buf.len() > MAX_COMMAND_LINE {
                return Ok(Some(Err("Line too long")));
            }
            let want = 1024;
            // Observed **before** the read, because this is the read that ends
            // `settling`: whatever it brings is the failed transfer's tail, so
            // it is thrown away with the flag and the loop reads again for the
            // next message. (Checking the flag *after* the read would always
            // see `false` — the read cleared it — and the tail would be read
            // as commands, which is how a second transaction got smuggled
            // through a connection the server had already refused.)
            let settled = self.settling;
            let outcome = tokio::time::timeout_at(deadline, self.fill(want, None)).await;
            if settled {
                self.settle();
            }
            match outcome {
                Err(_) => {
                    self.timeout_close().await?;
                    return Ok(None);
                }
                Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Ok(Err(err)) => return Err(err.into()),
                Ok(Ok(())) => {
                    // The settled read is discarded whole: loop for the next
                    // command rather than treating an empty buffer as EOF.
                    if settled {
                        continue;
                    }
                    if self.read_buf.is_empty() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Reads one line of message body, undoing dot-stuffing.
    ///
    /// The terminator is a bare `.` on a line of its own; a line starting with
    /// a dot lost one dot on the wire (RFC 5321 §4.5.2), so `..foo` becomes
    /// `.foo`. A LF that is not part of CRLF is refused rather than treated as
    /// a line break: guessing there is the SMTP smuggling hole
    /// (CVE-2023-51764), which is why the whole transfer fails instead.
    async fn read_body_line(
        &mut self,
    ) -> Result<Option<Result<BodyLine, &'static str>>, ServerError> {
        // Every complete line is drained as it is read, so the buffer holds
        // exactly one line being received plus whatever one read added. The
        // scan resumes where the previous one stopped: rescanning from the
        // buffer's start for every line made the cost of a body quadratic in
        // its size.
        let mut scanned = 0usize;
        loop {
            scanned = scanned.min(self.read_buf.len());
            if let Some(relative) = self.read_buf[scanned..]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let position = scanned + relative;
                // Refuse before copying: an over-long line must not make the
                // server copy tens of kilobytes per attempt.
                if position + 1 > MAX_BODY_LINE + 2 {
                    return Ok(Some(Err("Message line too long")));
                }
                let mut line: Vec<u8> = self.read_buf.drain(..=position).collect();
                line.pop();
                if line.last() != Some(&b'\r') {
                    return Ok(Some(Err("Bare LF in message data")));
                }
                line.pop();
                if octets_is_dot(&line) {
                    return Ok(Some(Ok(BodyLine {
                        octets: None,
                        end_of_message: true,
                    })));
                }
                let mut octets = line;
                if octets.first() == Some(&b'.') {
                    // Dot-unstuffing, in place: `Vec::remove(0)` is O(len) per
                    // line and made a big body quadratic.
                    octets.copy_within(1.., 0);
                    octets.pop();
                }
                octets.extend_from_slice(b"\r\n");
                return Ok(Some(Ok(BodyLine {
                    octets: Some(octets),
                    end_of_message: false,
                })));
            }
            // No newline yet. The line is over-long when more than the bound
            // arrived, not counting a terminator that is still arriving in
            // pieces (`\r`, `\r\n.`), which is not part of the line.
            let stub = terminator_stub(&self.read_buf);

            if self.read_buf.len() > MAX_BODY_LINE + 2 + stub {
                return Ok(Some(Err("Message line too long")));
            }
            // A read never runs more than a chunk past the line bound, so a
            // hostile line cannot make the buffer (or the drain above) grow
            // without limit.
            // A read never runs more than a chunk past the line bound, so a
            // hostile line cannot make the buffer (or the drain above) grow
            // without limit.
            let line_left = (MAX_BODY_LINE + 3).saturating_sub(self.read_buf.len());
            let want = BODY_READ_CHUNK.min(line_left.max(1)).max(1);

            let before = self.read_buf.len();
            match self.fill(want, None).await {
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(err.into()),
                Ok(()) => {
                    if self.read_buf.is_empty() {
                        return Ok(None);
                    }
                    scanned = before;
                }
            }
        }
    }
}

/// Whether a drained line (its `<CRLF>` removed) is the terminator `.`.
fn octets_is_dot(line: &[u8]) -> bool {
    line == b"."
}

/// How many trailing octets of `buffer` may be the start of a terminator
/// arriving in pieces (the empty prefix included), so a scan does not read a
/// half-received `\r\n.` as body.
fn terminator_stub(buffer: &[u8]) -> usize {
    const TERMINATOR: &[u8] = b"\r\n.\r\n";
    (0..TERMINATOR.len())
        .rev()
        .find(|length| {
            buffer.len() >= *length && TERMINATOR.starts_with(&buffer[buffer.len() - length..])
        })
        .unwrap_or(0)
}

/// Finds the end of the `<CRLF>.<CRLF>` that terminates `DATA` inside
/// `buffer`, starting at `from`, and returns the index just past it.
///
/// This is the body of [`Connection::drain_until_dot`], written over a slice so
/// it can be read and tested on its own. It accepts the three endings a client
/// may mean: `\r\n.\r\n`, `\r\n.\n` (a bare `LF` where the last `CRLF` should
/// be) and a `.\r\n` at the very front of the scan. A drain must stop at
/// everything a client could mean by "end of message", so that the octets after
/// it — whatever they are — are thrown away rather than executed.
fn find_terminator(buffer: &[u8], from: usize) -> Option<usize> {
    // A terminator that starts the scan is a bare `.` line: only possible when
    // the reader has already consumed the `<CRLF>` that would have preceded it.
    if buffer
        .get(from..)
        .is_some_and(|tail| tail.starts_with(b".\r\n"))
    {
        return Some(from + 3);
    }
    // Every `\r\n.` candidate: `\n.` is what a terminator looks like once the
    // CRLF before it is accounted for, and an `LF` that is **not** preceded by
    // a `\r` is line content, not a line end — it can never start a terminator.
    // (An earlier version walked `\n` and skipped the bare ones one octet at a
    // time; alongside the `\n.` search that skipped a legitimate terminator
    // sitting right after a bare `LF`, it restarted the scan *inside* the
    // candidate line it had just examined, so whether the drain ever ended
    // depended on which `seek_from` reported first. Two searches for one
    // thing is how a drain stops being a drain.)
    let mut at = from;
    while at + 1 < buffer.len() {
        let relative = memchr::memchr(b'\n', buffer.get(at..)?)?;
        let newline = at + relative;
        if newline == 0 || buffer[newline - 1] != b'\r' {
            at = newline + 1;
            continue;
        }
        if buffer.get(newline + 1) != Some(&b'.') {
            at = newline + 1;
            continue;
        }
        // The terminator is `\n.\r\n`: `newline` is the LF that ended the line
        // before it, the dot is at `newline + 1`, and the ending starts at
        // `newline + 2`.
        let ending = newline + 2;
        if buffer
            .get(ending..)
            .is_some_and(|tail| tail.starts_with(b"\r\n"))
        {
            return Some(ending + 2);
        }
        if buffer
            .get(ending..)
            .is_some_and(|tail| tail.starts_with(b"\n"))
        {
            // A bare LF is not a legal terminator, but the client meant one;
            // treat it as the end so nothing after it is executed.
            return Some(ending + 1);
        }
        // A dot that is still waiting for its ending is not a terminator yet:
        // the caller keeps reading.
        if ending >= buffer.len() {
            return None;
        }
        at = newline + 1;
    }
    None
}

/// Removes and returns up to `count` octets from the front of `buffer`.
fn drain_front(buffer: &mut Vec<u8>, count: usize) -> Vec<u8> {
    let count = count.min(buffer.len());
    let rest = buffer.split_off(count);
    std::mem::replace(buffer, rest)
}

/// The refusal for a header section over [`ServerConfig::max_header_bytes`].
///
/// `552` is RFC 5321 §4.3.2's "processing error" — the message was accepted in
/// principle and this server will not take this one — and `5.3.4` (RFC 3463)
/// says exactly which property: "message too big for system". The text names
/// the part, because a client that retries a truncated version of the same
/// message should truncate the headers, not the body.
fn header_too_large() -> Reply {
    error_reply(552, "5.3.4", "Header section too large")
}

fn error_reply(code: u16, enhanced: &'static str, text: impl Into<String>) -> Reply {
    Reply {
        code,
        enhanced: Some(enhanced),
        text: text.into(),
        lines: Vec::new(),
        action: Action::Continue,
    }
}

/// Counts `Received:` header fields in the head of a message (the first
/// `MAX_HEADER_BUFFER` octets), for the loop bound.
#[must_use]
pub fn received_count(head: &[u8]) -> usize {
    let mut count = 0;
    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() > 9 && line[..9].eq_ignore_ascii_case(b"received:") {
            // A continuation line starts with a blank and never matches.
            count += 1;
        }
    }
    count
}

/// A connection stream: TLS over whatever was underneath (a plain socket or a
/// `Box<dyn AsyncStream>`, which is what the handshake consumes).
type TlsOver = Box<TlsStream<Pin<Box<dyn AsyncStream>>>>;

/// The stream a [`Connection`] owns. Plain TCP is boxed into the same trait
/// object at construction, so this only has to add the TLS case.
enum PlainOrTls {
    /// A TLS session, possibly layered over an earlier one.
    Tls(TlsOver),
}

impl AsyncRead for PlainOrTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PlainOrTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A second handle on the socket a connection is running on.
///
/// `Connection` owns a boxed stream, so the socket underneath cannot be named
/// at the point where it is needed — and there is exactly one such point:
/// STARTTLS hands the stream to the handshake, and a failed handshake takes it
/// away with it. Without a handle on the side, the client would be left waiting
/// on a connection whose server end was quietly dropped, until its own
/// timeout. The handle is taken when the connection is created, from the one
/// stream type that is a socket.
struct SocketHandle(Option<tokio::net::TcpStream>);

impl fmt::Debug for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketHandle")
            .field("tcp", &self.0.is_some())
            .finish()
    }
}

impl SocketHandle {
    /// Duplicates the socket into a second, independent `tokio` handle: closing
    /// this one closes the connection, and the original is unaffected until the
    /// handshake consumes it.
    fn of(socket: &tokio::net::TcpStream) -> Self {
        Self(cloned(socket))
    }

    /// A second handle on the same connection, when this connection runs on a
    /// real socket. The answer is a fresh one: a shutdown needs an owner it
    /// may close.
    fn duplicate(&self) -> Option<tokio::net::TcpStream> {
        cloned(self.0.as_ref()?)
    }
}

/// Duplicates `socket` into a second handle.
///
/// `tokio`'s `TcpStream` has no `try_clone`; the descriptor is asked for
/// through `AsRawFd` and given an owner of its own, with no `unsafe` block.
#[cfg(unix)]
fn cloned(socket: &tokio::net::TcpStream) -> Option<tokio::net::TcpStream> {
    use std::os::fd::AsFd as _;
    let duplicate = socket.as_fd().try_clone_to_owned().ok()?;
    let descriptor: std::os::fd::OwnedFd = duplicate;
    tokio::net::TcpStream::from_std(std::net::TcpStream::from(descriptor)).ok()
}

/// Duplicates `socket` into a second handle (not implemented off Unix; the
/// failed handshake then falls back to dropping the stream).
#[cfg(not(unix))]
fn cloned(socket: &tokio::net::TcpStream) -> Option<tokio::net::TcpStream> {
    let _ = socket;
    None
}

/// Converts a mailbox into the router's address type.
///
/// `ayane_proto::Address` only accepts the ASCII mailbox alphabet, so an
/// SMTPUTF8 recipient (RFC 6531) has no `Address` form — and it also has no
/// entry in the account/shared/alias tables, which are ASCII by construction.
/// The sender, however, is only used for the policy rules; a forged non-ASCII
/// reverse-path may raise flags but must never make a **local** mailbox
/// vanish, so an unrepresentable sender is substituted with a name that no
/// deny rule is written for and an unrepresentable recipient is decided by
/// its domain being hosted or not.
#[must_use]
pub fn to_router_address(mailbox: &Mailbox) -> Option<ayane_proto::Address> {
    if matches!(mailbox, Mailbox::Null) {
        return None;
    }
    ayane_proto::Address::parse(&mailbox.as_text()).ok()
}

/// The address the deny rules see for a sender that has no `Address` form.
const OPAQUE_SENDER: &str = "unrepresentable-sender@invalid";

/// The inbound recipient decision, wired to the router snapshot.
#[must_use]
pub fn decide_recipient(
    state: &ayane_proto::DesiredState,
    sender: &Mailbox,
    recipient: &Mailbox,
) -> RecipientVerdict {
    let sender_addr = to_router_address(sender)
        .or_else(|| ayane_proto::Address::parse(OPAQUE_SENDER).ok())
        .unwrap_or_else(|| unreachable!("the opaque sender parses"));
    let recipient_addr = match to_router_address(recipient) {
        Some(address) => address,
        None => {
            // No ASCII form: the address cannot be in any table, so it is a
            // mailbox here only if its domain is hosted, which is still a
            // refusal — nothing to deliver to.
            let hosted = state.domains.iter().any(|domain| {
                domain.enabled && domain.name.eq_ignore_ascii_case(recipient.domain())
            });
            return if hosted || recipient.domain().is_empty() {
                RecipientVerdict::Unknown
            } else {
                RecipientVerdict::RelayDenied
            };
        }
    };
    policy::inbound_recipient(state, &sender_addr, &recipient_addr).verdict
}

/// The clock as the `Received:` header needs it.
#[must_use]
pub fn received_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc5322(now.as_secs())
}

/// Formats seconds since the epoch as RFC 5322 §3.3 date-time in UTC.
#[must_use]
pub fn format_rfc5322(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let weekday = WEEKDAYS[(days.rem_euclid(7)) as usize];
    format!(
        "{weekday}, {day:02} {} {year:04} {hour:02}:{minute:02}:{second:02} +0000",
        MONTHS[(month - 1) as usize]
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (y, m, d).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Turns text that came from the client into one that is safe inside a header
/// field value.
///
/// A `Received:` is assembled from strings the client chose — the EHLO name,
/// the authenticated identity — and a CR, LF or any other control character in
/// one of them would end the field and start a new header: header injection
/// straight into the message W2 will deliver. Those octets become `?`, long
/// runs are truncated, and everything else is left exactly as it was, so an
/// ordinary value is unchanged.
#[must_use]
pub fn sanitize_header_token(text: &str, max_len: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .take(max_len)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_owned()
    } else {
        cleaned
    }
}

/// The `Received:` value for one accepted message.
#[must_use]
pub fn received_header(
    config: &ServerConfig,
    peer: SocketAddr,
    session: &Session,
    tls: bool,
) -> String {
    let helo = session.hello().map_or_else(
        || "unknown".to_owned(),
        |(_, name)| sanitize_header_token(name, MAX_RECEIVED_TOKEN),
    );
    let protocol = if tls { "ESMTPS" } else { "ESMTP" };
    let auth = session
        .authenticated()
        .map_or_else(String::new, |identity| {
            format!(
                " auth={}",
                sanitize_header_token(identity, MAX_RECEIVED_TOKEN)
            )
        });
    format!(
        "from {helo} ([{}]) by {host} with {protocol}{auth} id ayane; {date}",
        peer.ip(),
        host = config.hostname,
        date = received_now()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_limit_is_rfc_sized() {
        assert_eq!(MAX_COMMAND_LINE, 1000);
        assert_eq!(COMMAND_TIMEOUT, Duration::from_secs(300));
        assert_eq!(TRANSACTION_TIMEOUT, Duration::from_secs(600));
    }

    #[test]
    fn rfc5322_dates_are_utc() {
        assert_eq!(format_rfc5322(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        // 2026-07-14T03:33:20Z, the epoch second this fixture pins.
        assert_eq!(
            format_rfc5322(1_784_000_000),
            "Tue, 14 Jul 2026 03:33:20 +0000"
        );
        // A leap day, which is where naive civil-date maths breaks.
        assert_eq!(
            format_rfc5322(1_835_395_200),
            "Tue, 29 Feb 2028 00:00:00 +0000"
        );
    }

    #[test]
    fn the_auth_guard_counts_failures_per_address_within_a_window() {
        let guard = AuthGuard::new(3, Duration::from_secs(60));
        let now = Instant::now();
        let peer: IpAddr = "192.0.2.10".parse().expect("ip");
        let other: IpAddr = "192.0.2.11".parse().expect("ip");
        for _ in 0..3 {
            assert_eq!(guard.admit(peer, now), AuthGate::Allowed);
            guard.record_failure(peer, now);
        }
        // Spent: the address is refused, the other one is not, and a success
        // on a different address cannot be confused with this one.
        assert!(matches!(
            guard.admit(peer, now),
            AuthGate::Refused { retry_after } if retry_after == Duration::from_secs(60)
        ));
        assert_eq!(guard.admit(other, now), AuthGate::Allowed);
        // The window is measured from the last failure, so hammering during
        // the back-off does not shorten it.
        let later = now + Duration::from_secs(30);
        guard.record_failure(peer, later);
        assert!(matches!(
            guard.admit(peer, later),
            AuthGate::Refused { retry_after } if retry_after == Duration::from_secs(60)
        ));
        // Once the window has turned over, the address is served again.
        let turned = later + Duration::from_secs(61);
        assert_eq!(guard.admit(peer, turned), AuthGate::Allowed);
        assert_eq!(guard.failures(peer), 0, "the expired entry is gone");
    }

    #[test]
    fn the_default_budget_is_fifty_failures_in_five_minutes() {
        // The NAT-friendly default: an office behind one address may mistype
        // fifty passwords in five minutes before the address waits out the
        // window. The bound is still a bound — the fifty-first attempt is
        // refused — and it is the *default* that changed, not the mechanism.
        let guard = AuthGuard::default();
        let now = Instant::now();
        let peer: IpAddr = "192.0.2.30".parse().expect("ip");
        for attempt in 1..=AUTH_FAIL_BUDGET {
            assert_eq!(
                guard.admit(peer, now),
                AuthGate::Allowed,
                "attempt {attempt} is inside the default budget"
            );
            guard.record_failure(peer, now);
        }
        assert_eq!(
            AUTH_FAIL_BUDGET, 50,
            "the default budget is the NAT-friendly fifty"
        );
        assert!(matches!(
            guard.admit(peer, now + Duration::from_secs(1)),
            AuthGate::Refused { .. }
        ));
        assert_eq!(AUTH_FAIL_WINDOW, Duration::from_secs(300));
    }

    #[test]
    fn the_auth_guard_forgets_a_successful_login() {
        let guard = AuthGuard::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let peer: IpAddr = "192.0.2.20".parse().expect("ip");
        guard.record_failure(peer, now);
        guard.record_failure(peer, now);
        assert!(matches!(guard.admit(peer, now), AuthGate::Refused { .. }));
        guard.record_success(peer);
        assert_eq!(guard.admit(peer, now), AuthGate::Allowed);
    }

    #[test]
    fn the_auth_guard_table_is_bounded() {
        // 20 000 distinct addresses against a table that holds 64: the table
        // never grows past its capacity, and the addresses that were recorded
        // first are the ones that stay — a full table refuses a new address
        // instead of evicting an older one.
        let guard = AuthGuard::new(5, Duration::from_secs(60));
        guard.set_capacity(64);
        let now = Instant::now();
        for index in 0..20_000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(index));
            guard.record_failure(ip, now);
            assert!(
                guard.tracked() <= 64,
                "the table grew to {} entries",
                guard.tracked()
            );
        }
        assert_eq!(guard.tracked(), 64);
        // The first 64 addresses filled the table and are the ones still
        // remembered; everything that arrived after it was full was not
        // recorded at all.
        let first = IpAddr::V4(std::net::Ipv4Addr::from(0u32));
        let newest = IpAddr::V4(std::net::Ipv4Addr::from(19_999u32));
        assert_eq!(guard.failures(first), 1, "the recorded entry was kept");
        assert_eq!(
            guard.failures(newest),
            0,
            "an address that arrived at a full table is not recorded"
        );
        // A recorded address is still charged after the table is full: the
        // budget of whoever is already in it keeps working.
        guard.record_failure(first, now);
        assert_eq!(guard.failures(first), 2);
        assert_eq!(guard.tracked(), 64, "charging does not need a new slot");
        // Entries older than the window are dropped as the table is touched
        // again, which is the only way an entry leaves early.
        guard.record_failure(
            "198.51.100.7".parse().expect("ip"),
            now + Duration::from_secs(61),
        );
        assert_eq!(guard.tracked(), 1, "everything outside the window expired");
    }

    #[test]
    fn a_full_auth_guard_never_drops_the_failures_it_has_already_counted() {
        // The attack this pins: a victim spends its budget, goes quiet, and an
        // attacker fills the table from 4 000 other addresses hoping the
        // victim's entry is the oldest one and gets thrown away — which would
        // reset the victim's budget and buy the guesses again.
        let guard = AuthGuard::new(3, Duration::from_secs(60));
        let capacity = 8;
        guard.set_capacity(capacity);
        let now = Instant::now();
        let victim: IpAddr = "192.0.2.200".parse().expect("ip");
        for _ in 0..3 {
            guard.record_failure(victim, now);
        }
        assert_eq!(guard.failures(victim), 3, "the budget is spent");
        assert!(matches!(guard.admit(victim, now), AuthGate::Refused { .. }));
        // The attacker keeps failing from fresh addresses — enough of them to
        // overflow the table several times over — and the victim's entry, the
        // oldest and quietest in it, has to still be there afterwards.
        for index in 0..u32::from(u16::MAX) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index));
            guard.record_failure(ip, now + Duration::from_secs(1));
        }
        assert_eq!(
            guard.failures(victim),
            3,
            "a full table must not buy the victim's spent budget back"
        );
        assert!(
            matches!(
                guard.admit(victim, now + Duration::from_secs(2)),
                AuthGate::Refused { .. }
            ),
            "and the victim is still refused"
        );
        // The table never exceeded its capacity, and the addresses that came
        // after it filled were not recorded — they were charged to the shared
        // budget instead.
        assert_eq!(guard.tracked(), capacity, "the table stopped at capacity");
        let late: IpAddr = "198.51.100.99".parse().expect("ip");
        assert_eq!(guard.failures(late), 0, "a new address is not recorded");
        assert!(
            guard.unrecorded_failures() > guard.flood_budget(),
            "the flood the table had no room for spent the shared budget: {}",
            guard.unrecorded_failures()
        );
        assert!(
            matches!(
                guard.admit(late, now + Duration::from_secs(2)),
                AuthGate::Refused { .. }
            ),
            "a full table past its shared budget is not an open door"
        );
        // The victim's count survives for the whole window and is dropped only
        // by it.
        assert!(matches!(
            guard.admit(victim, now + Duration::from_secs(59)),
            AuthGate::Refused { .. }
        ));
        assert_eq!(
            guard.admit(victim, now + Duration::from_secs(61)),
            AuthGate::Allowed
        );
        assert_eq!(
            guard.failures(victim),
            0,
            "the window, not pressure, forgot"
        );
    }

    #[test]
    fn a_full_auth_guard_bounds_the_addresses_it_cannot_record() {
        // The table's capacity is a bound on memory, not a licence to spend
        // unlimited guesses: an address that arrives at a full table has no
        // entry to be charged, so what it fails from is charged to one shared
        // counter, and past that counter every address the table does not hold
        // is refused — while every address it *does* hold keeps exactly the
        // count and the verdict it had before the table filled.
        let guard = AuthGuard::new(2, Duration::from_secs(60));
        let capacity = 8;
        guard.set_capacity(capacity);
        let now = Instant::now();
        let mut recorded = Vec::new();
        for index in 0..capacity as u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index));
            guard.record_failure(ip, now);
            recorded.push(ip);
        }
        assert_eq!(guard.tracked(), capacity, "the table is full");
        let spend = guard.flood_budget();
        assert_eq!(
            spend,
            2 * AUTH_FLOOD_BUDGET_FACTOR,
            "the shared budget follows the per-address one"
        );
        // Fresh addresses, one failure each, all the way through the shared
        // budget: inside it they are not refused (they simply have no entry),
        // and nothing in the table moves.
        for index in 0..spend as u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0c00_0000 + index));
            assert_eq!(
                guard.admit(ip, now),
                AuthGate::Allowed,
                "address {} is inside the shared budget",
                index + 1
            );
            guard.record_failure(ip, now);
        }
        assert_eq!(guard.unrecorded_failures(), spend);
        assert_eq!(guard.tracked(), capacity, "the table did not grow");
        for ip in &recorded {
            assert_eq!(guard.failures(*ip), 1, "no recorded entry was touched");
            assert_eq!(
                guard.admit(*ip, now),
                AuthGate::Allowed,
                "a recorded entry answers from its own count"
            );
        }
        // The failure past it closes the door for every address the table does
        // not hold, and it does not touch a single recorded entry either.
        let late: IpAddr = "198.51.100.99".parse().expect("ip");
        guard.record_failure(late, now);
        assert!(matches!(guard.admit(late, now), AuthGate::Refused { .. }));
        assert!(matches!(
            guard.admit("198.51.100.100".parse().expect("ip"), now),
            AuthGate::Refused { .. }
        ));
        for ip in &recorded {
            assert_eq!(guard.failures(*ip), 1, "still nobody else's business");
        }
        // And it lasts exactly the window it was counted in: one window after
        // the last failure to an unrecorded address, the address is served
        // again, and so is every recorded one.
        assert_eq!(
            guard.admit(late, now + Duration::from_secs(60)),
            AuthGate::Allowed,
            "the shared budget is not permanent"
        );
        assert_eq!(
            guard.admit(recorded[0], now + Duration::from_secs(60)),
            AuthGate::Allowed
        );
    }

    #[test]
    fn the_bdat_total_bound_is_the_message_limit() {
        assert_eq!(max_bdat_total(25 * 1024 * 1024), 25 * 1024 * 1024);
        // A limit below what one chunk may hold cannot refuse that chunk.
        assert_eq!(max_bdat_total(1024), MAX_BDAT_BUFFER as u64);
    }

    #[test]
    fn the_header_section_ends_with_the_blank_line_and_not_before_it() {
        // The table the `DATA` path produces, line by line: every line of the
        // section counts with its CRLF, and the blank line is one of them.
        // The first row is the one a `CRLFCRLF` search gets wrong — it takes
        // the blank line's own CRLF *and* the body's first one, so a message
        // with no header fields at all is charged four octets over `BDAT`
        // where `DATA` charges two.
        let cases: &[(&str, usize)] = &[
            // The blank line is the message's first line here, and it is the
            // whole section: two octets. A `CRLFCRLF` search would answer four.
            ("\r\nbody\r\n", 2),
            ("h\r\n\r\nbody\r\n", 5),
            ("h1\r\nh2\r\n\r\nbody\r\n", 10),
            ("h1: a\r\n h2: b\r\n\r\nbody\r\n", 17),
            // No blank line: the whole message is header section, and that is
            // the shape the bound exists for.
            ("no blank line anywhere\r\n", 24),
            // A trailing CRLF that the body happens to start with is not a
            // blank line of its own: the section ended at the *first* one.
            ("h\r\n\r\n\r\nstill body\r\n", 5),
            // Empty message: nothing to measure.
            ("", 0),
        ];
        for (message, expected) in cases {
            assert_eq!(
                header_len(message.as_bytes()),
                Some(*expected),
                "{message:?} is {expected} octets of header section"
            );
        }
    }

    #[test]
    fn a_head_with_a_bare_lf_has_no_measurable_section() {
        // `DATA` refuses a bare LF outright (RFC 5321 §2.3.8, CVE-2023-51764),
        // so a chained message carrying one has no header section this server
        // would size — and it must not be reported as a small one either.
        assert_eq!(header_len(b"h\n\r\nbody\r\n"), None);
        assert_eq!(header_len(b"h\r\nfold\n\r\nbody\r\n"), None);
        // A bare LF *after* the section does not make the section
        // unmeasurable — the section ended before it. It does not make the
        // *message* acceptable either: that is the body scan's question
        // (`scan_record`), which starts exactly where this answer ends. Kept
        // here so the two halves stay visibly separate: `header_len` answers
        // "how many octets are the section", never "is the body clean".
        assert_eq!(header_len(b"h\r\n\r\nbo\ndy\r\n"), Some(5));
        assert_eq!(scan_record(b"h\r\n\r\nbo\ndy\r\n", 5), Err(MalformedBody));
    }

    #[test]
    fn the_drain_finds_the_terminator_wherever_it_starts() {
        // The drain a failed `DATA` transfer runs stops at the first ending a
        // client could mean by "end of message". `.<CRLF>` at the buffer's
        // front is the case a sender reaches by putting a bare `LF` before it
        // (the `LF` is not a line break, so the `.` is at the start of what the
        // reader has left) — and a scan that started at the buffer's length
        // stepped over exactly that case, which is how the answer to a refused
        // transfer came to wait for the transaction timer.
        assert_eq!(find_terminator(b".\r\nrest", 0), Some(3));
        assert_eq!(find_terminator(b".\r\nrest", 1), None, "not at 1");
        // The ordinary shape: a line, then the terminator.
        assert_eq!(find_terminator(b"prompt\r\n.\r\nMAIL", 0), Some(11));
        assert_eq!(find_terminator(b"prompt\r\n.\r\nMAIL", 3), Some(11));
        // A bare `LF` *before* the dot does not stop the search: the dot line
        // is still the next `.<CRLF>` in the stream. (`\n` at index 0 has no
        // `\r` before it, so it is line content; the `.` after it is not at
        // the start of a line and is not a terminator candidate — the caller
        // arrives here with the bare `LF` already consumed.)
        assert_eq!(
            find_terminator(b"\n.\r\nMAIL", 0),
            None,
            "a `\n` with no `\r` before it is content, so this `.` is not a line"
        );
        // The two lenient endings a client may mean by the terminator.
        assert_eq!(
            find_terminator(b"x\r\n.\r\n", 0),
            Some(6),
            "past `x\r\n.\r\n`"
        );
        assert_eq!(find_terminator(b"x\r\n.\n", 0), Some(5), "bare LF ending");
        // A dot in line content is data, not a terminator.
        assert_eq!(find_terminator(b"a.b\r\n..c\r\n", 0), None);
        // Nothing at all, and a dot still waiting for its ending.
        assert_eq!(find_terminator(b"", 0), None);
        assert_eq!(find_terminator(b"x\r\n.", 0), None);
        assert_eq!(find_terminator(b"x\r\n.\r", 0), None);
    }

    #[test]
    fn a_body_with_any_bare_lf_is_refused_and_a_crlf_one_is_not() {
        // The table the `DATA` path produces, expressed over whole octets: a
        // `\n` must be directly preceded by a `\r`, and that is the entire
        // rule. The rows on the refusing side are the three measured shapes
        // (first body line, deep, and an `LF` at the start of a line), plus
        // the empty line whose ending is a bare `LF`.
        let refusing: &[&[u8]] = &[
            b"\nafter the blank line",
            b"first\nsecond\r\n",
            b"a\r\nb\r\nc\nd\r\n",
            b"line\r\n\n.\nMAIL FROM:<evil@example.net>\r\n",
            b"end\r\n\n",
        ];
        for body in refusing {
            assert_eq!(
                scan_record(body, 0),
                Err(MalformedBody),
                "{:?} carries a bare LF",
                String::from_utf8_lossy(body)
            );
        }
        // The accepting side: every line ends in CRLF, blank lines included,
        // and nothing else is a bare LF.
        let accepting: &[&[u8]] = &[
            b"",
            b"\r\n",
            b"only a crlf\r\n",
            b"a\r\n\r\nb\r\n",
            b"\r\n\r\n\r\n",
            b"ends without a line ending",
        ];
        for body in accepting {
            assert_eq!(
                scan_record(body, 0),
                Ok(()),
                "{:?} has no bare LF",
                String::from_utf8_lossy(body)
            );
        }
        // A carriage return on its own is not a bare LF: `DATA` reads it as
        // line content, and so does this. Two blank lines in a row are two
        // CRLFs, not a bare LF.
        assert_eq!(scan_record(b"a\rb\r\nc\r\n", 0), Ok(()));
        assert_eq!(scan_record(b"\r\n\r\n", 0), Ok(()));
    }

    #[test]
    fn the_body_scan_starts_where_the_header_section_ends() {
        // The defect this fixes lived at the seam: the head was scanned and the
        // body was not, so the octets *after* the blank line were the ones a
        // sender could fill with a bare LF. The offset `charge_message` returns
        // is that seam, and a record is judged by looking at both sides of it.
        let mut budget = HeaderBudget::default();
        let record = b"Subject: clean\r\n\r\nbody\r\nsmu\nggled\r\n";
        let body_from = budget.charge_message(record).expect("a clean head");
        assert_eq!(body_from, 18, "`Subject: clean\r\n` then the blank line");
        assert_eq!(&record[..body_from], b"Subject: clean\r\n\r\n");
        assert_eq!(budget.consumed, 18, "only the section is charged");
        assert_eq!(scan_record(record, body_from), Err(MalformedBody));

        // And the same record with a bare LF *in the head* stops earlier, in
        // the measurement itself: the two halves never both fire on one
        // octet.
        let mut budget = HeaderBudget::default();
        let head_dirty = b"Subject: bad\nhead\r\n\r\nbody\r\n";
        assert_eq!(budget.charge_message(head_dirty), Err(MalformedHead));
    }

    #[test]
    fn the_scans_are_linear_on_a_large_message() {
        // Both halves are one pass. A `windows(2)` comparison per octet, or a
        // rescan from every line start, is what this pins against: the first
        // would be tens of times slower, the second quadratic (minutes at
        // this size in a debug build). The assertions here are about the
        // answers; the cost is pinned by the size the test runs at — a
        // quadratic scan does not finish.
        let line = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n";
        let mut clean = Vec::with_capacity(25 * 1024 * 1024);
        clean.extend_from_slice(b"Subject: big\r\n\r\n");
        while clean.len() < 25 * 1024 * 1024 {
            clean.extend_from_slice(line);
        }
        let mut budget = HeaderBudget::default();
        let body_from = budget.charge_message(&clean).expect("a clean head");
        assert_eq!(body_from, b"Subject: big\r\n\r\n".len());
        assert_eq!(scan_record(&clean, body_from), Ok(()));

        // One bare LF at the very end: the scan has to walk the whole body to
        // find it, and find it.
        let mut dirty = clean.clone();
        let end = dirty.len() - 2;
        dirty[end] = b'\n';
        assert_eq!(scan_record(&dirty, body_from), Err(MalformedBody));
    }

    #[test]
    fn a_message_of_one_hundred_thousand_lines_is_measured_in_one_pass() {
        // The scan is linear; this pins that it stays linear (a quadratic
        // re-scan from every line start would take minutes here).
        let mut message = String::with_capacity(3 * 100_000);
        for _ in 0..100_000 {
            message.push_str("x\r\n");
        }
        message.push_str("\r\nbody\r\n");
        // 100 000 lines of `x` + CRLF, then the blank line: 3 octets each, and
        // the blank line's own `CRLF` ends the section at 300 002.
        assert_eq!(header_len(message.as_bytes()), Some(300_002));
    }

    #[test]
    fn header_tokens_never_carry_a_control_octet() {
        assert_eq!(sanitize_header_token("client.test", 254), "client.test");
        assert_eq!(
            sanitize_header_token("a@b\r\nBcc: victim@example.net", 254),
            "a@b??Bcc: victim@example.net"
        );
        assert_eq!(sanitize_header_token("", 254), "unknown");
        assert_eq!(sanitize_header_token(&"x".repeat(300), 254).len(), 254);
    }

    #[test]
    fn per_ip_limiter_releases_on_drop() {
        let limiter = Arc::new(PerIpLimiter::new(2));
        let ip: IpAddr = "192.0.2.5".parse().expect("ip");
        let first = limiter.acquire(ip).expect("first");
        let second = limiter.acquire(ip).expect("second");
        assert!(limiter.acquire(ip).is_none());
        assert_eq!(limiter.count(ip), 2);
        drop(first);
        assert_eq!(limiter.count(ip), 1);
        drop(second);
        assert_eq!(limiter.count(ip), 0);
    }
}
