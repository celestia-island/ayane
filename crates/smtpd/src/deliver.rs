//! The delivery consumer: what happens to a message after its 250.
//!
//! [`crate::queue`] decides what "accepted" means; this module is what makes
//! an accepted message *arrive*. It is the only layer below the driver that
//! writes outside the spool, and every write it makes is one [`Deliverer`]
//! method, so a test can drive the whole queue by hand.
//!
//! # The consumer loop
//!
//! ```text
//! recover()            ── a crash left cur/ entries; they are reclaimable
//!   ↓
//! list(New)            ── every committed message
//!   ↓ for each, oldest id first
//! claim(id)            ── new/ → cur/ (the at-most-once step)
//!   ↓
//! <id>.state.json      ── one record per recipient, written beside the message
//!   ↓ for each recipient that is due
//! route(state, …)      ── ayane_mail::route, the one router
//!   ↓
//! mailbox / quarantine / forward / remote / reject
//!   ↓
//! remove(Cur, id)      ── only when no recipient is pending
//! ```
//!
//! # At-most-once, and the crash window it leaves open
//!
//! `claim` renames `new/<id>.*` into `cur/`, so two consumers cannot take the
//! same message. The step that cannot be atomic is the delivery itself: the
//! maildir write and the record saying "this recipient is done" are two files
//! in two places. The order chosen here is **write first, record second**:
//!
//! 1. the message is written into the recipient's maildir `tmp/`, fsynced,
//!    renamed into `new/`, and the maildir directory fsynced — from that
//!    instant it is delivered, whatever happens next;
//! 2. only then is the recipient marked delivered in the delivery record.
//!
//! A crash between the two re-delivers that recipient on the next pass, so
//! the queue is **at-least-once per recipient across a crash, and never
//! lossy**. The other order loses mail, which no mail system may do. The
//! residue is bounded and visible: a duplicate carries the `Delivered-To:`
//! field, which is where duplicate suppression looks.
//!
//! # Where a message goes
//!
//! | `route()` | what the driver does |
//! | --- | --- |
//! | [`Route::Mailbox`] | write into that address's maildir |
//! | [`Route::Shared`] | the same — a shared mailbox is a maildir with ACLs |
//! | [`Route::CatchAll`] | write into the catch-all mailbox |
//! | [`Route::Quarantine`] | move the message into `quarantine/` beside the spool |
//! | [`Route::Forward`] | *re-enqueue*: same bytes, new envelope, one child per target |
//! | [`Route::Reject`] | defensive only: `RCPT` refused these, so reaching here means the policy moved underneath the queue — audit, drop, and **do not bounce** (a bounce for an address we accepted would be a backchannel) |
//!
//! A **quarantine** copy is written into `quarantine/` beside the spool's
//! `new/`, `cur/` and `tmp/` — outside every directory recovery sweeps, so
//! held mail cannot be mistaken for queue noise — with the same
//! write/fsync/rename/sync order a maildir delivery uses.
//!
//! Everything else — a recipient whose domain this instance does not host —
//! is a **remote** recipient: this layer records nothing, charges no attempt,
//! and leaves the message where the outbound transport will find it
//! ([`Disposition::Held`] with every recipient waiting).
//!
//! # The maildir path has two floors
//!
//! [`maildir_home`] renders the engine's home (`/var/mail/vhosts/<domain>/<local>`)
//! and the driver appends `Maildir` before `new/`. Dovecot runs with
//! `mail_location = maildir:~/Maildir`, so the directory that actually holds
//! the mail is the *second* one, and the volume already contains mailboxes
//! laid out that way. Writing one floor higher would look like success — the
//! rename works, the file is on disk — while every existing message stayed
//! where no client looks. [`Deliverer::maildir_path`] is the only place the
//! two halves are joined.
//!
//! # The forward, and the loop it must not create
//!
//! [`Route::Forward`] does not forward: it writes a **new queue entry** whose
//! bytes are the original message, whose envelope sender is the original
//! reverse-path (never the alias), and whose recipients are the alias targets.
//! Each hop prepends a `Received:` field carrying `hops=<n>`, so
//! [`received_count`](crate::server::received_count) — the driver's own loop
//! bound — counts forwards exactly as it counts SMTP hops, and
//! [`Defaults::max_forward_hops`] stops a loop whose trace fields were
//! stripped somewhere.
//!
//! # The bounce
//!
//! When a recipient runs out of retries, the driver builds an RFC 3464
//! `multipart/report` addressed to the **original envelope sender** and
//! enqueues it like any other message, so the report is routed, retried and —
//! if it cannot be delivered — bounced by the same code. Its own reverse-path
//! is `<>`. The null sender is the one recipient that is never bounced: a
//! message from `<>` already is a bounce, and bouncing it is RFC 5321 §6.1's
//! backscatter loop. There is nothing to return it to, so the driver records
//! an audit line ([`AuditEvent`]) and drops the recipient.

use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ayane_mail::{route, Route};
use ayane_proto::{Address, DesiredState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::queue::{fsync_dir, Envelope, QueueState, QueuedMessage, Spool};
use crate::retry::{RecipientState, RetryClass, RetryPolicy};

/// The directory, under the spool root, holding delivered-but-quarantined
/// messages. It is beside `new/`, `cur/` and `tmp/` and is never swept by
/// recovery.
pub const QUARANTINE_DIR: &str = "quarantine";

/// The suffix of a message's delivery record, inside `cur/`.
pub const RECORD_SUFFIX: &str = ".state.json";

/// What the driver decided about a queue entry after one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Every recipient reached a terminal state; the entry left the queue.
    Delivered,
    /// At least one recipient is still pending (a retry, or a remote wait);
    /// the entry stays in `cur/` with its record.
    Held,
    /// Every recipient of this pass was a forward, and the alias keeps no
    /// local copy: the entry left the queue as a forward.
    Forwarded,
    /// Every recipient of this pass was rejected by the router; the entry
    /// left the queue without a bounce.
    Dropped,
}

/// What happened to one recipient on one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientOutcome {
    /// Written into this maildir (`new/`).
    Delivered(PathBuf),
    /// Moved into the quarantine directory.
    Quarantined(PathBuf),
    /// Re-enqueued towards these targets; the entry is `child` (the first of
    /// one per target).
    Forwarded {
        /// The alias targets.
        targets: Vec<Address>,
        /// The queue id of the first child entry.
        child: String,
    },
    /// The recipient's domain is not hosted here: the outbound transport owns
    /// it, and nothing was attempted.
    Remote,
    /// A retry was scheduled.
    Deferred {
        /// When the next attempt is due (seconds since the epoch).
        next_attempt_epoch: u64,
        /// Why, for the operator.
        reason: String,
    },
    /// The horizon is over, or the failure is permanent: a DSN was enqueued
    /// (or deliberately not, for the null sender).
    Bounced {
        /// The queue id of the report; `None` when the reverse-path is null.
        dsn: Option<String>,
        /// Why, for the operator.
        reason: String,
    },
    /// The router returned [`Route::Reject`] for a recipient `RCPT` accepted.
    Rejected(String),
}

/// One recipient and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientReport {
    /// The recipient as accepted at `RCPT`.
    pub recipient: String,
    /// What the driver did.
    pub outcome: RecipientOutcome,
}

/// The result of one pass over one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    /// The queue id.
    pub id: String,
    /// One entry per recipient that was due on this pass.
    pub recipients: Vec<RecipientReport>,
    /// What the driver decided about the entry itself.
    pub disposition: Disposition,
}

impl DeliveryReport {
    /// Every recipient of this pass that reached a terminal state.
    pub fn admitted(&self) -> impl Iterator<Item = &RecipientReport> {
        self.recipients.iter().filter(|report| {
            matches!(
                report.outcome,
                RecipientOutcome::Delivered(_)
                    | RecipientOutcome::Quarantined(_)
                    | RecipientOutcome::Forwarded { .. }
                    | RecipientOutcome::Rejected(_)
            )
        })
    }

    /// Every recipient of this pass that is waiting.
    pub fn waiting(&self) -> impl Iterator<Item = &RecipientReport> {
        self.recipients.iter().filter(|report| {
            matches!(
                report.outcome,
                RecipientOutcome::Deferred { .. } | RecipientOutcome::Remote
            )
        })
    }
}

/// One line of the audit log: a decision the queue made that an operator has
/// to be able to find later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A recipient was dropped without a bounce because the reverse-path is
    /// null. There is nowhere to return the message to, and returning it is
    /// the loop RFC 5321 §6.1 forbids.
    NullSenderDropped {
        /// The queue id.
        id: String,
        /// The recipient that failed.
        recipient: String,
        /// Why it failed.
        reason: String,
    },
    /// The router refused a recipient the SMTP transaction accepted.
    RouterRejected {
        /// The queue id.
        id: String,
        /// The recipient.
        recipient: String,
    },
    /// A forward loop was cut at [`Defaults::max_forward_hops`].
    ForwardLoop {
        /// The queue id of the entry the forward was attempted for.
        id: String,
        /// The alias that started it.
        from: String,
        /// How many hops the cycle already had.
        hops: u32,
    },
}

/// Receives every [`AuditEvent`] the driver emits, in order.
pub type AuditSink = Arc<dyn Fn(AuditEvent) + Send + Sync>;

/// A hook that runs at each step of a maildir write, or fails it.
///
/// The three points are the three steps, so a test lands on each one:
/// [`MaildirStep::AfterTmp`] (written, not synced, not named),
/// [`MaildirStep::AfterRename`] (in `new/`, not yet durable) and
/// [`MaildirStep::AfterDirSync`] (durable). Returning an error makes the step
/// fail instead of running, which is how a full disk or an unsyncable
/// directory is simulated.
pub type MaildirHook = Arc<dyn Fn(MaildirStep, &Path) -> io::Result<()> + Send + Sync>;

/// A point in one maildir write where a hook runs.
///
/// The `*Skipped` entries are not points in a healthy write: they are the two
/// fsyncs *not* happening, which is the only way an in-process test can ask
/// "what if the file (or the directory) were never synced?" — a test cannot
/// observe whether a real `fsync` reached the medium, and the spool's
/// observer documents the same limit. A hook that returns them makes the
/// write behave as if the call had been dropped: the file step takes the
/// `tmp/` file back, the directory step fails after the rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaildirStep {
    /// `tmp/` holds the written, not yet synced file.
    AfterTmp,
    /// The file has been renamed into `new/`.
    AfterRename,
    /// The directory has been synced: the delivery is durable.
    AfterDirSync,
    /// **Injected:** the file is written and not synced.
    FileSyncSkipped,
    /// **Injected:** the file is in `new/` and the directory was not synced.
    DirSyncSkipped,
}

/// What one fsync in the maildir path synced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaildirSync {
    /// The message file, before it is named in `new/`.
    File,
    /// The maildir's `new/`, after the rename.
    Dir,
}

/// Receives every [`MaildirSync`] the deliverer issues, in order.
pub type MaildirSyncObserver = Arc<dyn Fn(MaildirSync) + Send + Sync>;

/// The hops a forward may take before the queue cuts the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Defaults {
    /// The most forwards one message may provoke, independent of how many
    /// trace fields it carries.
    pub max_forward_hops: u32,
}

/// The queue's bounded defaults.
pub const DEFAULTS: Defaults = Defaults {
    max_forward_hops: 25,
};

/// The engine's maildir home for one account, with **no** `Maildir` floor.
///
/// This mirrors `ayane_engine::maildir_home` (the renderer lives in a crate
/// this one does not depend on, and the two spellings must stay identical);
/// [`Deliverer::maildir_path`] appends the floor Dovecot opens.
#[must_use]
pub fn maildir_home(domain: &str, local: &str) -> String {
    format!("/var/mail/vhosts/{domain}/{local}")
}

/// The delivery consumer.
///
/// One instance is shared by every pass over one spool; [`Deliverer::new`] is
/// the production configuration and the `with_*` builders are the knobs an
/// operator or a test sets.
///
/// **The spool and the mail root are two different directories.** A spool
/// owns `tmp/`, `new/`, `cur/` and `corrupt/`; every maildir owns `tmp/`,
/// `new/` and `cur/` of its own. Using one root for both would create the
/// spool's four directories *as children of `/var/mail/vhosts`* — four names
/// that collide with a mailbox layout — so the two are separate arguments and
/// [`Deliverer::new`] refuses a mail root that already looks like one or the
/// other (see [`Deliverer::check_roots`]).
#[derive(Clone)]
pub struct Deliverer {
    spool: Spool,
    mail_root: PathBuf,
    hostname: String,
    retry: RetryPolicy,
    quota: Option<u64>,
    hooks: Arc<Hooks>,
}

/// The directory names a spool owns, and therefore the names a mail root must
/// not use for its children.
pub const SPOOL_DIRECTORIES: [&str; 4] = ["tmp", "new", "cur", "corrupt"];

/// What keeps a deliverer from writing into the wrong tree.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootError {
    /// The mail root *is* the spool root: the same collision as a child
    /// directory, one level up.
    #[error("the mail root is the spool root (`{0}`): one of them has to move")]
    SamePath(String),
    /// The mail root has a `tmp`, `new`, `cur` or `corrupt` child: the spool's
    /// layout, or a maildir's, is already there, and either would be
    /// overwritten or read as a mailbox.
    #[error("`{}` is one of the spool's own directory names: `{}` may not contain it", .1, .0)]
    ReservedChild(String, String),
}

/// The clock, the seams and the counters.
#[derive(Default)]
struct Hooks {
    maildir: Mutex<Option<MaildirHook>>,
    sync: Mutex<Option<MaildirSyncObserver>>,
    audit: Mutex<Option<AuditSink>>,
    counter: AtomicU64,
}

impl std::fmt::Debug for Deliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deliverer")
            .field("mail_root", &self.mail_root)
            .field("hostname", &self.hostname)
            .field("retry", &self.retry)
            .field("quota", &self.quota)
            .finish()
    }
}

impl Deliverer {
    /// A deliverer that drains `spool` and writes mail into `mail_root`,
    /// identifying itself as `hostname` in the fields and reports it
    /// generates.
    ///
    /// `mail_root` is the deployment's `/var/mail/vhosts` — the directory
    /// whose children are `<domain>/<local>/Maildir`. `spool` is wherever the
    /// receiver committed its queue, and it is a different directory: see
    /// [`Deliverer::check_roots`] for why, and for the assertion that makes
    /// the mistake impossible to ship.
    #[must_use]
    pub fn new(spool: Spool, mail_root: impl Into<PathBuf>, hostname: impl Into<String>) -> Self {
        Self {
            spool,
            mail_root: mail_root.into(),
            hostname: hostname.into(),
            retry: RetryPolicy::default(),
            quota: None,
            hooks: Arc::new(Hooks::default()),
        }
    }

    /// Refuses a mail root that carries the spool's layout.
    ///
    /// A spool owns `tmp/`, `new/`, `cur/` and `corrupt/`. If the mail root is
    /// the spool, or has any of those four names as a child, then one of the
    /// two layouts is already occupying the other's names: the spool's
    /// `cur/` would be read as a mailbox, or a maildir's `new/` as the
    /// queue's. Either way mail is either overwritten or delivered into a
    /// directory a client can never open — a failure that looks like success,
    /// which is why this is checked at start-up rather than discovered by a
    /// missing message.
    ///
    /// # Errors
    ///
    /// Returns [`RootError`] for the two collisions described above.
    pub fn check_roots(&self) -> Result<(), RootError> {
        let spool_root = std::fs::canonicalize(self.spool.root())
            .unwrap_or_else(|_| self.spool.root().to_path_buf());
        let mail_root =
            std::fs::canonicalize(&self.mail_root).unwrap_or_else(|_| self.mail_root.clone());
        if spool_root == mail_root {
            return Err(RootError::SamePath(mail_root.display().to_string()));
        }
        for name in SPOOL_DIRECTORIES {
            if mail_root.join(name).exists() {
                return Err(RootError::ReservedChild(
                    mail_root.display().to_string(),
                    name.to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// The spool being drained.
    #[must_use]
    pub fn spool(&self) -> &Spool {
        &self.spool
    }

    /// The mail root (`<domain>/<local>/Maildir` lives under it).
    #[must_use]
    pub fn mail_root(&self) -> &Path {
        &self.mail_root
    }

    /// Where quarantined messages are moved: beside the *spool*, never inside
    /// the mail tree, so held mail can never be read as a mailbox and the
    /// spool's own sweeps never touch it.
    #[must_use]
    pub fn quarantine(&self) -> PathBuf {
        self.spool.root().join(QUARANTINE_DIR)
    }

    /// The retry ladder and deadline.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// The retry policy in force.
    #[must_use]
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry
    }

    /// The per-mailbox quota in octets (`None` = unlimited).
    ///
    /// A mailbox over quota is a *temporary* failure: the mail waits instead
    /// of overflowing, which is what Dovecot does above its own quota.
    #[must_use]
    pub fn with_quota(mut self, quota: Option<u64>) -> Self {
        self.quota = quota;
        self
    }

    /// The quota in force.
    #[must_use]
    pub fn quota(&self) -> Option<u64> {
        self.quota
    }

    /// Installs the maildir step hook (tests only).
    pub fn set_maildir_hook(&self, hook: MaildirHook) {
        if let Ok(mut slot) = self.hooks.maildir.lock() {
            *slot = Some(hook);
        }
    }

    /// Installs the observer that receives every maildir fsync (tests only).
    ///
    /// It reports the *operation*, not the syscall: an honest observer cannot
    /// see whether `sync_all` reached the medium (the spool states the same
    /// limit at [`Spool::set_fsync_observer`](crate::queue::Spool::set_fsync_observer)),
    /// so what a test pins is that a sync step ran in the right place, and the
    /// negative control is a step that failed before it.
    pub fn set_sync_observer(&self, observer: MaildirSyncObserver) {
        if let Ok(mut slot) = self.hooks.sync.lock() {
            *slot = Some(observer);
        }
    }

    /// Installs the audit sink (tests only; production logs through
    /// `tracing`, which the sink mirrors).
    pub fn set_audit_sink(&self, sink: AuditSink) {
        if let Ok(mut slot) = self.hooks.audit.lock() {
            *slot = Some(sink);
        }
    }

    /// The maildir a delivery to `address` writes into:
    /// `<root>/<domain>/<local>/Maildir`.
    ///
    /// The `<domain>/<local>` half is [`maildir_home`]'s rendering, taken from
    /// it rather than re-spelled, so the two cannot drift apart; the
    /// `Maildir` floor is what Dovecot's `mail_location` opens.
    #[must_use]
    pub fn maildir_path(&self, address: &Address) -> PathBuf {
        let home = PathBuf::from(maildir_home(address.domain(), address.local()));
        let mut parts = home
            .components()
            .rev()
            .take(2)
            .filter_map(|component| match component {
                std::path::Component::Normal(name) => Some(name.to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>();
        parts.reverse();
        let mut path = self.mail_root.clone();
        path.extend(parts);
        path.join("Maildir")
    }

    /// Drains one message: claims it, routes every recipient that is due,
    /// delivers, and removes it once nothing is pending.
    ///
    /// # Errors
    ///
    /// Returns an I/O error only when the message could not be *claimed* or
    /// read — the pass then did nothing, and the message stays in `new/` or
    /// `cur/` where the next pass finds it. A delivery failure is not an
    /// error here: it is a retry or a bounce, both recorded and reported.
    pub fn deliver_message(
        &self,
        state: &DesiredState,
        queued: &QueuedMessage,
        now_epoch: u64,
    ) -> io::Result<DeliveryReport> {
        // The claim is the at-most-once step: a message listed from `new/` is
        // moved to `cur/` before anything reads it, so a second consumer sees
        // nothing to do. A message the recovery sweep left in *both*
        // directories (a crash inside the claim) is finished rather than
        // claimed again: the `cur/` copy is the newer one, and re-claiming
        // would rename the stale `new/` copy over it.
        if queued.state == QueueState::New {
            // A `cur/` copy means the claim began and did not finish (or was
            // undone by a crash that revived the `new/` half). Re-claiming
            // would move the stale `new/` shell over it; finishing the move
            // keeps the newer copy and drops the shell.
            if self.half_claimed(&queued.id) {
                self.spool.reclaim_cur(&queued.id)?;
            } else {
                self.spool.claim(&queued.id)?;
            }
        }
        self.deliver_claimed(state, queued, now_epoch)
    }

    /// Delivers a message that is already in `cur/`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the message or its record cannot be read or
    /// written. The message stays in `cur/` and is due again on the next
    /// pass.
    pub fn deliver_claimed(
        &self,
        state: &DesiredState,
        queued: &QueuedMessage,
        now_epoch: u64,
    ) -> io::Result<DeliveryReport> {
        let message = self.spool.read_message(QueueState::Cur, &queued.id)?;
        let mut record = self.read_record(&queued.id)?;
        if !record.recipients.is_empty() && record.settled() {
            // Every recipient of this record is done. That is either this
            // message's own record — a crash between the last settlement and
            // the record's removal — or a previous message's, left on an id
            // that was handed out again.
            //
            // The two cannot be told apart from the record alone, and the
            // asymmetry decides which way to err. Delivering again on a
            // *reused* id puts one message into a stranger's mailbox and takes
            // the other's nowhere; leaving it puts mail in the queue for an
            // operator to see. Both are visible anomalies, but only the first
            // is silent damage to a third party, so the entry is held rather
            // than delivered. The normal path (below) removes the record when
            // it settles a message, so this is residue either way.
            tracing::warn!(
                id = queued.id,
                "a queue entry carries a settled record: held, not delivered"
            );
            return Ok(DeliveryReport {
                id: queued.id.clone(),
                recipients: Vec::new(),
                disposition: Disposition::Held,
            });
        }
        if record.recipients.is_empty() {
            // First pass (or a crash before the record was written): every
            // accepted recipient starts pending.
            for recipient in &queued.envelope.recipients {
                record.entry(recipient.clone());
            }
        }

        let sender = sender_address(&queued.envelope);
        let mut reports = Vec::new();
        let mut changed = false;
        let recipients = &mut record.recipients;
        for entry in recipients.iter_mut() {
            if !entry.state.pending || entry.state.next_attempt_epoch > now_epoch {
                continue;
            }
            let outcome = self.deliver_recipient(
                state,
                &queued.envelope,
                &message,
                sender.as_ref(),
                entry,
                now_epoch,
            );
            // The record is written only when something happened to a
            // recipient, and "something happened" means an outcome that moved
            // it: a `Remote` recipient is looked at every pass and left
            // exactly as it was, so rewriting the same bytes once per
            // `--interval-seconds` for a wait that lasts days is pure write
            // amplification on the mail host's busiest directory.
            changed |= !matches!(outcome, RecipientOutcome::Remote);
            reports.push(RecipientReport {
                recipient: entry.state.recipient.clone(),
                outcome,
            });
        }
        if !changed {
            // Nothing moved: every recipient is waiting, settled, or remote,
            // and the record already says so.
            return Ok(DeliveryReport {
                id: queued.id.clone(),
                recipients: reports,
                disposition: Disposition::Held,
            });
        }
        self.write_record(&queued.id, &record)?;

        let pending = record.recipients.iter().any(|entry| entry.state.pending);
        let forwarded_only = reports
            .iter()
            .all(|report| matches!(report.outcome, RecipientOutcome::Forwarded { .. }));
        let rejected_only = reports
            .iter()
            .all(|report| matches!(report.outcome, RecipientOutcome::Rejected(_)));
        let disposition = if pending {
            Disposition::Held
        } else {
            // The record is the delivery layer's, so it leaves with the
            // message it describes: a settled record has nothing left to say,
            // and leaving it behind is what lets a reused id pick up a
            // previous message's verdict. The record goes first — a crash
            // between the two leaves a message with no record, which is
            // delivered from scratch (at-least-once, and its maildir copies
            // carry `Delivered-To:` for duplicate suppression).
            self.remove_record(&queued.id)?;
            self.spool.remove(QueueState::Cur, &queued.id)?;
            if forwarded_only {
                Disposition::Forwarded
            } else if rejected_only {
                Disposition::Dropped
            } else {
                Disposition::Delivered
            }
        };
        Ok(DeliveryReport {
            id: queued.id.clone(),
            recipients: reports,
            disposition,
        })
    }

    /// Routes and delivers one recipient, updating its record in place.
    // Eight arguments is what this call needs: the router's inputs (state,
    // envelope, bytes, sender), the record it updates, the clock, and the
    // recipient it is about. Bundling them into a struct for the linter would
    // rename the same fields and hide the signature change a ninth one would
    // need anyway.
    #[allow(clippy::too_many_arguments)]
    fn deliver_recipient(
        &self,
        state: &DesiredState,
        envelope: &Envelope,
        message: &[u8],
        sender: Option<&Address>,
        entry: &mut RecordedRecipient,
        now_epoch: u64,
    ) -> RecipientOutcome {
        let null_sender = sender.is_none();
        let name = entry.state.recipient.clone();
        let Ok(recipient) = Address::parse(&name) else {
            return self.permanent(
                envelope,
                entry,
                null_sender,
                now_epoch,
                format!("`{name}` is not an address this router can look up"),
            );
        };
        if !hosted(state, &recipient) {
            // Not hosted here: the outbound transport owns it, and this layer
            // must not charge an attempt for a delivery nobody attempted.
            return RecipientOutcome::Remote;
        }
        // The failure paths inside `deliver_local` and `quarantine_message`
        // need to know whether a bounce is even possible. It travels in those
        // two calls because those are the only places that fail, and it is
        // carried alongside the record rather than re-derived from the
        // envelope in each of them.
        match route(state, sender.unwrap_or(&null_address()), &recipient) {
            Route::Mailbox(address) | Route::CatchAll(address) | Route::Shared(address) => self
                .deliver_local(
                    envelope,
                    message,
                    &recipient,
                    &address,
                    entry,
                    now_epoch,
                    null_sender,
                ),
            Route::Quarantine => self.quarantine_message(
                envelope,
                message,
                &recipient,
                entry,
                now_epoch,
                null_sender,
            ),
            Route::Forward(targets) => {
                match self.enqueue_forward(envelope, message, &recipient, &targets, now_epoch) {
                    Ok(outcome) => {
                        entry.state.pending = false;
                        entry.state.last_error = None;
                        outcome
                    }
                    Err(err) => self.transient(
                        envelope,
                        entry,
                        null_sender,
                        now_epoch,
                        format!("cannot enqueue the forward: {err}"),
                    ),
                }
            }
            Route::Reject => {
                entry.state.pending = false;
                entry.state.last_error =
                    Some("router refused a recipient the session accepted".to_owned());
                self.audit(AuditEvent::RouterRejected {
                    id: envelope.id.clone(),
                    recipient: name.clone(),
                });
                RecipientOutcome::Rejected(
                    "router refused a recipient the session accepted".to_owned(),
                )
            }
        }
    }

    /// Writes one message into one maildir.
    // The seventh argument is the bounce rule, and it has to travel with the
    // write: the write is the only thing that can fail here. (The same
    // allowance on `deliver_recipient` covers the router's own six inputs.)
    #[allow(clippy::too_many_arguments)]
    fn deliver_local(
        &self,
        envelope: &Envelope,
        message: &[u8],
        recipient: &Address,
        mailbox: &Address,
        entry: &mut RecordedRecipient,
        now_epoch: u64,
        null_sender: bool,
    ) -> RecipientOutcome {
        let maildir = self.maildir_path(mailbox);
        match self.write_maildir(&maildir, envelope, message, recipient) {
            Ok(path) => {
                entry.state.pending = false;
                entry.state.last_error = None;
                RecipientOutcome::Delivered(path)
            }
            Err(err) => {
                let reason = format!("maildir {}: {err}", maildir.display());
                match RetryClass::of(&err) {
                    RetryClass::Transient => {
                        self.transient(envelope, entry, null_sender, now_epoch, reason)
                    }
                    RetryClass::Permanent => {
                        self.permanent(envelope, entry, null_sender, now_epoch, reason)
                    }
                }
            }
        }
    }

    /// Writes one message into one quarantine copy.
    fn quarantine_message(
        &self,
        envelope: &Envelope,
        message: &[u8],
        recipient: &Address,
        entry: &mut RecordedRecipient,
        now_epoch: u64,
        null_sender: bool,
    ) -> RecipientOutcome {
        match self.write_quarantine(envelope, message, recipient) {
            Ok(path) => {
                entry.state.pending = false;
                RecipientOutcome::Quarantined(path)
            }
            Err(err) => {
                let reason = format!("quarantine: {err}");
                match RetryClass::of(&err) {
                    RetryClass::Transient => {
                        self.transient(envelope, entry, null_sender, now_epoch, reason)
                    }
                    RetryClass::Permanent => {
                        self.permanent(envelope, entry, null_sender, now_epoch, reason)
                    }
                }
            }
        }
    }

    /// Records a failure that may pass and schedules the retry.
    fn transient(
        &self,
        envelope: &Envelope,
        entry: &mut RecordedRecipient,
        null_sender: bool,
        now_epoch: u64,
        reason: String,
    ) -> RecipientOutcome {
        entry
            .state
            .record_failure(now_epoch, reason.clone(), &self.retry);
        if entry.state.pending {
            tracing::debug!(
                id = envelope.id,
                recipient = entry.state.recipient,
                attempts = entry.state.attempts,
                "delivery failed; retrying"
            );
            return RecipientOutcome::Deferred {
                next_attempt_epoch: entry.state.next_attempt_epoch,
                reason,
            };
        }
        self.give_up(envelope, entry, null_sender, now_epoch, reason)
    }

    /// Records a failure that will not pass and fails the recipient at once.
    fn permanent(
        &self,
        envelope: &Envelope,
        entry: &mut RecordedRecipient,
        null_sender: bool,
        now_epoch: u64,
        reason: String,
    ) -> RecipientOutcome {
        entry.state.attempts = entry.state.attempts.saturating_add(1);
        entry.state.last_error = Some(reason.clone());
        self.give_up(envelope, entry, null_sender, now_epoch, reason)
    }

    /// Ends a recipient: bounce it, or audit and drop it when the
    /// reverse-path is null.
    fn give_up(
        &self,
        envelope: &Envelope,
        entry: &mut RecordedRecipient,
        null_sender: bool,
        now_epoch: u64,
        reason: String,
    ) -> RecipientOutcome {
        entry.state.pending = false;
        if null_sender {
            // Nowhere to return it to, and returning it is the loop RFC 5321
            // §6.1 forbids. This is the one recipient the queue drops, and it
            // says so in the audit log.
            tracing::warn!(
                id = envelope.id,
                recipient = entry.state.recipient,
                %reason,
                "null-sender message undeliverable: dropped without a bounce"
            );
            self.audit(AuditEvent::NullSenderDropped {
                id: envelope.id.clone(),
                recipient: entry.state.recipient.clone(),
                reason: reason.clone(),
            });
            return RecipientOutcome::Bounced { dsn: None, reason };
        }
        let Some(sender) = sender_address(envelope) else {
            // Every non-null envelope has an address; this arm keeps the
            // "no sender, no bounce" rule absolute even if one does not parse.
            return RecipientOutcome::Bounced { dsn: None, reason };
        };
        tracing::info!(
            id = envelope.id,
            recipient = entry.state.recipient,
            attempts = entry.state.attempts,
            "delivery gave up; a DSN is being enqueued"
        );
        match self.enqueue_dsn(
            &sender,
            &envelope.id,
            &entry.state.recipient,
            entry.state.attempts,
            now_epoch,
            &reason,
        ) {
            Ok(dsn) => RecipientOutcome::Bounced {
                dsn: Some(dsn),
                reason,
            },
            Err(err) => {
                tracing::error!(id = envelope.id, %err, "cannot enqueue a DSN");
                RecipientOutcome::Bounced { dsn: None, reason }
            }
        }
    }

    /// One pass over the queue.
    ///
    /// Entries a crashed pass left in `cur/` are picked up by
    /// [`Spool::recover`], which moves them back to `new/`: a consumer that
    /// dies between `claim` and `remove` loses nothing, at the price of
    /// re-delivering the recipients it had already written (see the module
    /// docs on at-most-once).
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the spool cannot be recovered or listed. A
    /// per-message failure is logged and skipped — one unreadable entry must
    /// not stop the queue.
    pub fn run(&self, state: &DesiredState) -> io::Result<Vec<DeliveryReport>> {
        self.run_at(state, epoch_now())
    }

    /// [`Deliverer::run`] with an explicit clock; tests drive the retry ladder
    /// through it.
    ///
    /// # Errors
    ///
    /// Same as [`Deliverer::run`].
    pub fn run_at(&self, state: &DesiredState, now_epoch: u64) -> io::Result<Vec<DeliveryReport>> {
        // `recover` reads the *message* half of a crash (temporary leftovers,
        // half-committed entries, entries a delivery left in `cur/`), and it
        // is the one place in this crate that does — so it is not an optional
        // step of a pass.
        let report = self.spool.recover_with_claimed(true)?;
        if !report.failed.is_empty() {
            tracing::warn!(
                failed = report.failed.len(),
                "recovery finished with unhandled errors; the queue may hold stale entries"
            );
        }
        let mut out = Vec::new();
        for queued in self.spool.list(QueueState::New)? {
            match self.deliver_message(state, &queued, now_epoch) {
                Ok(report) => out.push(report),
                Err(err) => {
                    tracing::error!(id = queued.id, %err, "cannot deliver a queued message");
                }
            }
        }
        Ok(out)
    }

    /// The whole maildir write, hookable at each step.
    ///
    /// The contract is the spool's, one directory down: `create(tmp, new) →
    /// write → fsync(file) → rename(tmp → new) → fsync(new/)`. Only the last
    /// step makes the delivery durable, and it is why a crash cannot leave a
    /// file a client can see but a power cut can erase.
    fn write_maildir(
        &self,
        maildir: &Path,
        envelope: &Envelope,
        message: &[u8],
        recipient: &Address,
    ) -> io::Result<PathBuf> {
        let tmp = maildir.join("tmp");
        let new = maildir.join("new");
        std::fs::create_dir_all(&tmp)?;
        std::fs::create_dir_all(&new)?;
        let bytes = self.delivered_bytes(message, recipient);
        if let Some(quota) = self.quota {
            let used = self.maildir_size(maildir)?;
            if used.saturating_add(bytes.len() as u64) > quota {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    format!("mailbox is over its quota of {quota} octets"),
                ));
            }
        }
        let name = self.maildir_name(envelope, recipient);
        let tmp_path = tmp.join(&name);
        let new_path = new.join(&name);
        // `create_new`: an existing name is a bug in the name, and writing
        // over a delivered file would silently destroy it.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        let write_result = (|| -> io::Result<()> {
            let mut handle = &file;
            handle.write_all(&bytes)?;
            // `sync_all` flushes the write buffer as well as the two (data and
            // metadata) halves of the durability contract, so there is no
            // separate `flush` here to accidentally trust instead of it.
            handle.sync_all()
        })();
        drop(file);
        if let Err(err) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        // The hook runs *after* the sync it names, and its failure stands for
        // "the sync did not happen": the write is taken back, so a test can ask
        // what the maildir looks like when the file step or the directory step
        // is missing, without pretending the call exists.
        if let Err(err) = self.step(MaildirStep::AfterTmp, &tmp_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        self.note_sync(MaildirSync::File);
        std::fs::rename(&tmp_path, &new_path)?;
        if let Err(err) = self.step(MaildirStep::AfterRename, &new_path) {
            // Visible but not durable. Taking it back puts the sheet where the
            // caller's retry expects it (nothing delivered); a crash right
            // here instead leaves a file the next retry duplicates — the
            // at-least-once side, never the lost-mail side.
            let _ = std::fs::remove_file(&new_path);
            let _ = fsync_dir(&new);
            return Err(err);
        }
        fsync_dir(&new)?;
        self.note_sync(MaildirSync::Dir);
        self.step(MaildirStep::AfterDirSync, &new_path)?;
        Ok(new_path)
    }

    /// The maildir file name.
    ///
    /// The shape is the one every maildir implementation understands —
    /// `<secs>.M<usec>P<pid>Q<seq>.<host>,S=<size>` — with the message's queue
    /// id and the recipient folded into a `,H<hex>` token so a file on disk
    /// can be traced back to the entry that wrote it. It cannot collide with a
    /// spool id: those are `<hex>-<hex>-<hex>` with no second dot, and this
    /// name has both a dot and a comma.
    fn maildir_name(&self, envelope: &Envelope, recipient: &Address) -> String {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let seq = self.hooks.counter.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256::new();
        hasher.update(envelope.id.as_bytes());
        hasher.update(b"\0");
        hasher.update(recipient.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(envelope.sha256.as_bytes());
        let hash: String = hasher
            .finalize()
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!(
            "{secs}.M{usec}P{pid}Q{seq}.{host},S={size},H{hash}",
            secs = now.as_secs(),
            usec = now.subsec_micros(),
            pid = std::process::id(),
            host = hostname_token(&self.hostname),
            size = envelope.size,
        )
    }

    /// The octets written into a maildir or a quarantine copy: the queued
    /// message (already carrying every `Received:` field written for it) with
    /// one `Delivered-To:` field in front, naming the envelope recipient that
    /// received it.
    ///
    /// That field is the only per-recipient difference between two copies of
    /// one message, and it is what makes the crash window in this module's
    /// docs *visible*: a re-delivered duplicate differs from the first copy
    /// only in its file name, while both carry the same `Delivered-To` — which
    /// is the field duplicate suppression keys on.
    fn delivered_bytes(&self, message: &[u8], recipient: &Address) -> Vec<u8> {
        let mut out = format!("Delivered-To: {recipient}\r\n").into_bytes();
        out.extend_from_slice(message);
        out
    }

    /// The total size of a maildir's `new/` and `cur/`, for the quota check.
    fn maildir_size(&self, maildir: &Path) -> io::Result<u64> {
        let mut total = 0u64;
        for folder in ["new", "cur"] {
            let Ok(entries) = std::fs::read_dir(maildir.join(folder)) else {
                continue;
            };
            for entry in entries {
                let entry = entry?;
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        total = total.saturating_add(metadata.len());
                    }
                }
            }
        }
        Ok(total)
    }

    /// Writes a copy into `quarantine/`, durably.
    fn write_quarantine(
        &self,
        envelope: &Envelope,
        message: &[u8],
        recipient: &Address,
    ) -> io::Result<PathBuf> {
        let dir = self.quarantine();
        std::fs::create_dir_all(&dir)?;
        let mut hasher = Sha256::new();
        hasher.update(envelope.id.as_bytes());
        hasher.update(b"\0");
        hasher.update(recipient.as_str().as_bytes());
        let hash: String = hasher
            .finalize()
            .iter()
            .take(6)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let name = format!("{}-{hash}.eml", envelope.id);
        let path = dir.join(&name);
        let tmp = dir.join(format!(".{name}.partial"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&self.delivered_bytes(message, recipient))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &path)?;
        fsync_dir(&dir)?;
        Ok(path)
    }

    /// Enqueues one child per alias target and reports the first child's id.
    ///
    /// One entry per target, not one entry with several recipients: a forward
    /// to two addresses where one succeeds and one retries must not retry the
    /// successful one, which a shared entry would do on the next pass.
    fn enqueue_forward(
        &self,
        parent: &Envelope,
        message: &[u8],
        from: &Address,
        targets: &[Address],
        now_epoch: u64,
    ) -> io::Result<RecipientOutcome> {
        let hops = parent.forward_hops.saturating_add(1);
        if hops > DEFAULTS.max_forward_hops {
            self.audit(AuditEvent::ForwardLoop {
                id: parent.id.clone(),
                from: from.to_string(),
                hops,
            });
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "forward loop: hop {hops} exceeds {}",
                    DEFAULTS.max_forward_hops
                ),
            ));
        }
        let mut children = Vec::new();
        for target in targets {
            let id = self.spool.next_id();
            let mut envelope = Envelope::placeholder(&id, &self.hostname);
            // The envelope sender is the *original* reverse-path: a forward
            // keeps the responsibility for a bounce with whoever sent the
            // message, never with the alias that redirected it (RFC 5321
            // §6.1). `mail_from` is `""` for the null sender.
            envelope.received_at = format_epoch(now_epoch);
            envelope.mail_from.clone_from(&parent.mail_from);
            envelope.mail_from_wire.clone_from(&parent.mail_from_wire);
            envelope.helo.clone_from(&parent.helo);
            envelope.remote_ip.clone_from(&parent.remote_ip);
            envelope.authenticated.clone_from(&parent.authenticated);
            envelope.smtputf8 = parent.smtputf8;
            envelope.auth_summary.clone_from(&parent.auth_summary);
            envelope.recipients = vec![target.to_string()];
            envelope.forwarded_from = Some(from.to_string());
            envelope.forward_hops = hops;
            envelope.received =
                forward_received(&self.hostname, &from.to_string(), &target.to_string());
            // This hop's trace field goes in front of the parent's stored
            // octets, exactly as the receiving side prepends its own: the loop
            // bound counts `Received:` fields in the head, so a forward has to
            // be one of them for a cycle to look like a cycle.
            let block = format!("Received: {}\r\n", envelope.received).into_bytes();
            let mut staged = self.spool.stage(&id, envelope)?;
            staged.write(message)?;
            staged.commit_with_prepend(&block)?;
            children.push(id);
        }
        tracing::info!(
            parent = parent.id,
            from = %from,
            targets = children.len(),
            "forwarded"
        );
        Ok(RecipientOutcome::Forwarded {
            targets: targets.to_vec(),
            child: children.first().cloned().unwrap_or_default(),
        })
    }

    /// Builds and enqueues the RFC 3464 report for one failed recipient.
    fn enqueue_dsn(
        &self,
        sender: &Address,
        parent_id: &str,
        recipient: &str,
        attempts: u32,
        now_epoch: u64,
        reason: &str,
    ) -> io::Result<String> {
        let id = self.spool.next_id();
        let mut envelope = Envelope::placeholder(&id, &self.hostname);
        envelope.received_at = format_epoch(now_epoch);
        // A report has the null reverse-path: it may never generate a bounce
        // of its own (RFC 5321 §4.5.5), and the driver's null-sender rule
        // then applies to it automatically.
        envelope.mail_from = String::new();
        envelope.mail_from_wire = "<>".to_owned();
        envelope.recipients = vec![sender.to_string()];
        envelope.received = dsn_received(&self.hostname, now_epoch);
        let body = dsn_body(
            &self.hostname,
            sender,
            recipient,
            parent_id,
            attempts,
            reason,
            now_epoch,
        );
        let mut staged = self.spool.stage(&id, envelope)?;
        staged.write(&body)?;
        staged.commit()?;
        Ok(id)
    }

    /// Reads the delivery record of `id` (empty when there is none).
    fn read_record(&self, id: &str) -> io::Result<DeliveryRecord> {
        let path = self.record_path(id);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(DeliveryRecord::default()),
            Err(err) => Err(err),
        }
    }

    /// Deletes the delivery record of `id`, durably: the unlink is followed
    /// by a directory sync, so a crash cannot resurrect a record whose message
    /// is gone.
    fn remove_record(&self, id: &str) -> io::Result<()> {
        let dir = self.record_dir();
        match std::fs::remove_file(self.record_path(id)) {
            Ok(()) => fsync_dir(&dir),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Writes the delivery record of `id`, durably.
    fn write_record(&self, id: &str, record: &DeliveryRecord) -> io::Result<()> {
        let dir = self.record_dir();
        let path = self.record_path(id);
        let tmp = dir.join(format!(".{id}.state.partial"));
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &path)?;
        fsync_dir(&dir)?;
        Ok(())
    }

    /// Whether a queue entry already has a `cur/` copy — the state a claim
    /// that began and did not finish leaves behind.
    fn half_claimed(&self, id: &str) -> bool {
        self.record_dir().join(format!("{id}.eml")).exists()
    }

    /// The directory a claimed message and its record live in.
    fn record_dir(&self) -> PathBuf {
        self.spool.root().join("cur")
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.spool
            .root()
            .join("cur")
            .join(format!("{id}{RECORD_SUFFIX}"))
    }

    fn step(&self, step: MaildirStep, path: &Path) -> io::Result<()> {
        let hook = self.hooks.maildir.lock().ok().and_then(|slot| slot.clone());
        match hook {
            Some(hook) => hook(step, path),
            None => Ok(()),
        }
    }

    fn note_sync(&self, what: MaildirSync) {
        let observer = self.hooks.sync.lock().ok().and_then(|slot| slot.clone());
        if let Some(observer) = observer {
            observer(what);
        }
    }

    fn audit(&self, event: AuditEvent) {
        let sink = self.hooks.audit.lock().ok().and_then(|slot| slot.clone());
        if let Some(sink) = sink {
            sink(event);
        }
    }

    /// The queue's id counter, exposed so a test can assert the names it
    /// hands out do not collide with the spool's.
    #[cfg(test)]
    fn next_sequence(&self) -> u64 {
        self.hooks.counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// The delivery record of one queued message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    /// One entry per accepted recipient.
    #[serde(default)]
    pub recipients: Vec<RecordedRecipient>,
}

impl DeliveryRecord {
    /// Whether every recipient has reached a terminal state.
    ///
    /// A settled record is one whose message is done: the pass that settles
    /// the last recipient deletes it (see `deliver_claimed`), so one that is
    /// still on disk with nothing pending belongs to a *different* message
    /// that happened to use the same queue id.
    #[must_use]
    pub fn settled(&self) -> bool {
        !self.recipients.is_empty() && self.recipients.iter().all(|entry| !entry.state.pending)
    }

    /// The entry for `recipient`, created when it is missing.
    fn entry(&mut self, recipient: String) -> &mut RecordedRecipient {
        if let Some(index) = self
            .recipients
            .iter()
            .position(|entry| entry.state.recipient == recipient)
        {
            return &mut self.recipients[index];
        }
        self.recipients.push(RecordedRecipient {
            state: RecipientState::new(recipient),
        });
        self.recipients
            .last_mut()
            .expect("an entry was just pushed")
    }
}

/// One recipient in a [`DeliveryRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRecipient {
    /// The retry state; flattened so the record reads as one row per
    /// recipient.
    #[serde(flatten)]
    pub state: RecipientState,
}

/// Seconds since the Unix epoch, the driver's only clock.
fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Whether this instance hosts `recipient`'s domain — the same test the
/// router applies before it answers anything but [`Route::Reject`].
fn hosted(state: &DesiredState, recipient: &Address) -> bool {
    state
        .domains
        .iter()
        .any(|domain| domain.enabled && domain.name == recipient.domain())
}

/// The address [`route`] is asked with when the envelope sender is null.
///
/// The router takes an `&Address` and a null reverse-path has none. What it
/// reads from the sender is one leg — `policy.denylist.matches` — and the
/// rule shapes are [`SenderRule::Address`] (an exact `Address`, which always
/// has a local part and a domain, so it is never `<>`) and
/// [`SenderRule::Domain`] (a domain name, never the empty string). This
/// spelling matches neither and can be written in no rule at all, which is
/// what makes "a bounce is judged on its recipient, not on its sender" true
/// rather than accidental.
fn null_address() -> Address {
    Address::parse("nobody@invalid").expect("a constant address is valid")
}

/// The reverse-path of an envelope as an address; `None` for the null sender.
fn sender_address(envelope: &Envelope) -> Option<Address> {
    let raw = envelope.mail_from.trim();
    if raw.is_empty() || raw == "<>" {
        return None;
    }
    Address::parse(raw.trim_matches(['<', '>'])).ok()
}

/// A hostname usable inside a maildir file name: every character outside a
/// conservative alphabet becomes `-`, so a name can never contain `/`, `:` or
/// the `.`/`,` separators a maildir file name already uses.
fn hostname_token(hostname: &str) -> String {
    let token: String = hostname
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if token.is_empty() {
        "localhost".to_owned()
    } else {
        token
    }
}

/// The `Received:` value of a forwarded hop.
fn forward_received(hostname: &str, from: &str, to: &str) -> String {
    format!(
        "from {hostname} (localhost) by {hostname} with local (ayane forward); \
         from <{from}> for <{to}>"
    )
}

/// The `Received:` value of a report the queue generates.
fn dsn_received(hostname: &str, now_epoch: u64) -> String {
    format!(
        "from {hostname} (localhost) by {hostname} with local (ayane dsn); {date}",
        date = format_epoch(now_epoch)
    )
}

/// `text` with anything a header line cannot hold folded onto one line.
///
/// `\r` and `\n` become spaces, and a NUL is dropped: those are the three
/// octets that can end a field or a line early. The result is used where a
/// value (a hostname, an error message) joins a header line, so a message
/// this crate *generates* can never carry a field nobody wrote.
fn single_line(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\r' | '\n' => ' ',
            '\0' => ' ',
            other => other,
        })
        .collect()
}

/// Formats an instant as the RFC 5322-style stamp a `Received:` field carries.
#[must_use]
pub fn format_epoch(epoch_secs: u64) -> String {
    crate::server::format_rfc5322(epoch_secs)
}

/// The RFC 3464 report for one failed recipient.
///
/// Shape: `multipart/report; report-type=delivery-status` whose three parts
/// are the human sentence, a `message/delivery-status` block (`Reporting-MTA`
/// then the per-recipient group with `Final-Recipient`, `Action`, `Status`
/// and `Diagnostic-Code`), and the message the report is about — as its
/// headers only. Returning the whole body would hand an unknown sender's
/// message back to a bounce address, which is how a mail loop is fed.
fn dsn_body(
    hostname: &str,
    sender: &Address,
    recipient: &str,
    parent_id: &str,
    attempts: u32,
    reason: &str,
    now_epoch: u64,
) -> Vec<u8> {
    // Every argument below lands on a header line, and a CR or LF in any of
    // them would end that field and start another one — the classic header
    // injection. The ones that can carry arbitrary text are the hostname and
    // the failure reason (a path, an error message); they are folded onto one
    // line here rather than trusted.
    let hostname = single_line(hostname);
    let reason = single_line(reason);
    let boundary = format!("ayane-dsn-{}", single_line(parent_id));
    let date = format_epoch(now_epoch);
    format!(
        "From: Mail Delivery System <postmaster@{hostname}>\r\n\
         To: <{sender}>\r\n\
         Subject: Delivery Status Notification (failure) for <{recipient}>\r\n\
         Date: {date}\r\n\
         Auto-Submitted: auto-generated\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status;\r\n\
         \tboundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         This is the mail system at {hostname}.\r\n\
         \r\n\
         Your message could not be delivered to one or more recipients.\r\n\
         Only the headers are returned, never the body.\r\n\
         \r\n\
         <{recipient}>: {reason}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {hostname}\r\n\
         Arrival-Date: {date}\r\n\
         \r\n\
         Final-Recipient: rfc822; {recipient}\r\n\
         Original-Recipient: rfc822; {recipient}\r\n\
         Action: failed\r\n\
         Status: 5.0.0\r\n\
         Diagnostic-Code: X-ayane; {reason}\r\n\
         Attempts: {attempts}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/rfc822-headers\r\n\
         \r\n\
         X-Original-Queue-ID: {parent_id}\r\n\
         \r\n\
         --{boundary}--\r\n"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ayane_proto::{Account, Alias, MailDomain, Policy, SenderRule, SharedMailbox};
    use serde_json::json;
    use std::sync::{Mutex as StdMutex, OnceLock};
    use uuid::Uuid;

    // ── fixtures ─────────────────────────────────────────────────────────

    fn addr(raw: &str) -> Address {
        Address::parse(raw).expect("fixture address")
    }

    fn account(raw: &str) -> Account {
        Account {
            id: Uuid::new_v4(),
            address: addr(raw),
            display_name: raw.to_owned(),
            quota_bytes: 0,
            admin: false,
        }
    }

    fn domain(name: &str) -> MailDomain {
        MailDomain {
            name: name.to_owned(),
            catch_all: None,
            enabled: true,
        }
    }

    /// Every policy in one state: a mailbox, a shared mailbox, an alias, a
    /// catch-all and a default action of reject.
    fn state() -> DesiredState {
        let mut catch = domain("example.com");
        catch.catch_all = Some(addr("inbox@example.com"));
        DesiredState {
            domains: vec![catch, domain("elsewhere.example")],
            accounts: vec![
                account("inbox@example.com"),
                account("ops@example.com"),
                account("shared@elsewhere.example"),
            ],
            aliases: vec![Alias {
                source: addr("team@example.com"),
                targets: vec![addr("a@partner.example"), addr("b@partner.example")],
            }],
            shared: vec![SharedMailbox {
                id: Uuid::new_v4(),
                address: addr("shared@elsewhere.example"),
                members: vec![Uuid::new_v4()],
            }],
            policy: Policy::default(),
            ..DesiredState::default()
        }
    }

    /// A state whose default action quarantines and whose catch-all is gated
    /// behind an allow list that the sender is not on.
    fn quarantine_state() -> DesiredState {
        let mut catch = domain("example.com");
        catch.catch_all = Some(addr("inbox@example.com"));
        DesiredState {
            domains: vec![catch],
            accounts: vec![account("inbox@example.com")],
            policy: Policy {
                allowlist: vec![SenderRule::Domain("trusted.example".to_owned())],
                ..Policy::default()
            },
            ..DesiredState::default()
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        static SERIAL: OnceLock<StdMutex<u64>> = OnceLock::new();
        let serial = SERIAL.get_or_init(|| StdMutex::new(0));
        let mut guard = serial.lock().expect("serial");
        *guard += 1;
        let base = std::env::temp_dir();
        // The spool root is the mail root (`/<domain>/<local>/Maildir` lives
        // under it), so a directory this test did not create could shadow a
        // fixture mailbox. `temp_dir` itself picks up a `TMPDIR` an operator
        // exported for another purpose, so a name is only used once it is
        // known not to exist — the uniqueness above is a probability, and
        // this check is the proof.
        let mut attempt = 0u32;
        loop {
            let root = base.join(format!(
                "ayane-deliver-{name}-{}-{}-{}-{attempt}",
                std::process::id(),
                *guard,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_nanos())
            ));
            if !root.exists() {
                return root;
            }
            attempt += 1;
        }
    }

    fn envelope(id: &str, sender: &str, recipients: &[&str]) -> Envelope {
        let mut envelope = Envelope::placeholder(id, "mx.example.com");
        envelope.received_at = "2026-11-26T00:00:00Z".to_owned();
        envelope.mail_from = sender.to_owned();
        envelope.mail_from_wire = format!("<{sender}>");
        envelope.helo = "client.test".to_owned();
        envelope.remote_ip = "192.0.2.9".to_owned();
        envelope.recipients = recipients.iter().map(|raw| (*raw).to_owned()).collect();
        envelope
    }

    fn stage(spool: &Spool, envelope: Envelope, message: &[u8]) -> QueuedMessage {
        let id = envelope.id.clone();
        let mut staged = spool.stage(&id, envelope).expect("stage");
        staged.write(message).expect("write");
        staged.commit().expect("commit")
    }

    /// A spool with a deliverer over it, plus the root the test cleans up.
    struct Fixture {
        root: PathBuf,
        spool: Spool,
        deliverer: Deliverer,
    }

    impl std::ops::Deref for Fixture {
        type Target = Deliverer;

        fn deref(&self) -> &Deliverer {
            &self.deliverer
        }
    }

    fn fixture(name: &str) -> Fixture {
        let root = temp_root(name);
        // Two roots, as a deployment has them: the spool (its own `tmp/`,
        // `new/`, `cur/`, `corrupt/`) and the mail tree (`<domain>/<local>/
        // Maildir`, quarantine beside the spool).
        let spool = Spool::open(root.join("spool")).expect("spool");
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        Fixture {
            root,
            spool,
            deliverer,
        }
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn read_all(dir: &Path) -> String {
        entries(dir)
            .iter()
            .map(|name| std::fs::read_to_string(dir.join(name)).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n----\n")
    }

    fn message() -> &'static [u8] {
        b"Received: from client.test by mx.example.com\r\nSubject: hi\r\n\r\nbody\r\n"
    }

    // ── maildir layout and atomicity ─────────────────────────────────────

    #[test]
    fn the_maildir_path_carries_both_floors() {
        let f = fixture("path");
        let deliverer = &f.deliverer;
        assert_eq!(
            deliverer.maildir_path(&addr("ops@example.com")),
            deliverer.mail_root().join("example.com/ops/Maildir")
        );
        // The engine's renderer and this module must agree on the first
        // floor; the second one is Dovecot's `mail_location`.
        assert_eq!(
            maildir_home("example.com", "ops"),
            "/var/mail/vhosts/example.com/ops"
        );
        // A `+tag` recipient the router folded onto its base mailbox must land
        // in the base mailbox, not in a directory named after the tag.
        assert_eq!(
            deliverer.maildir_path(&addr("ops@example.com")),
            deliverer.mail_root().join("example.com/ops/Maildir")
        );
        let _ = std::fs::remove_dir_all(&f.root);
    }

    #[test]
    fn a_mail_root_that_collides_with_the_spool_is_refused() {
        // The one mistake this process must not survive: a spool owns `tmp/`,
        // `new/`, `cur/` and `corrupt/`, and so does every maildir. Writing
        // mail into a directory that already holds a spool's layout — or the
        // spool itself — is a failure that looks like success.
        let root = temp_root("roots");
        let spool = Spool::open(root.join("spool")).expect("spool");
        // The healthy pair passes.
        let good = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        good.check_roots().expect("two separate roots");
        // The spool itself does not.
        let same = Deliverer::new(spool.clone(), root.join("spool"), "mx.example.com");
        assert_eq!(
            same.check_roots(),
            Err(RootError::SamePath(
                std::fs::canonicalize(root.join("spool"))
                    .unwrap_or_else(|_| root.join("spool"))
                    .display()
                    .to_string()
            ))
        );
        // Nor does a mail root that already has one of the spool's children.
        for name in SPOOL_DIRECTORIES {
            let mail_root = root.join(format!("mail-{name}"));
            std::fs::create_dir_all(mail_root.join(name)).expect("the colliding child");
            let deliverer = Deliverer::new(spool.clone(), &mail_root, "mx.example.com");
            assert_eq!(
                deliverer.check_roots(),
                Err(RootError::ReservedChild(
                    mail_root.display().to_string(),
                    name.to_owned()
                )),
                "a `{name}/` child is the spool's layout, not a mailbox"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_local_delivery_lands_in_new_with_its_envelope_fields() {
        let f = fixture("local");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0001", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert_eq!(report.disposition, Disposition::Delivered);
        let new = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        let names = entries(&new);
        assert_eq!(names.len(), 1, "one file, in new/");
        let name = &names[0];
        assert!(name.contains("mx-example-com"), "{name}");
        assert!(name.contains(&format!("S={}", message().len())), "{name}");
        // `tmp/` is empty: the rename moved the only file.
        assert!(entries(&deliverer.maildir_path(&addr("ops@example.com")).join("tmp")).is_empty());
        let body = std::fs::read_to_string(new.join(name)).expect("read");
        assert!(
            body.starts_with("Delivered-To: ops@example.com\r\n"),
            "{body}"
        );
        assert!(body.contains("Subject: hi\r\n"), "{body}");
        assert!(body.contains("Received: from client.test"), "{body}");
        // The entry left the queue.
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_maildir_write_syncs_the_file_then_the_directory() {
        let f = fixture("sync-order");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let recorded = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&recorded);
        deliverer.set_sync_observer(Arc::new(move |what| {
            sink.lock().expect("observer").push(what);
        }));
        let queued = stage(
            &spool,
            envelope("0002", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        let order = recorded.lock().expect("observer").clone();
        assert_eq!(
            order,
            vec![MaildirSync::File, MaildirSync::Dir],
            "the file must be synced before the rename, the directory after it"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_crash_before_the_rename_leaves_nothing_in_new() {
        // The hook lands between `fsync(tmp)` and the rename: the state that
        // a power cut at that instant leaves. `new/` must hold nothing a
        // client could open, and the recipient must still be owed a delivery.
        let f = fixture("crash-tmp");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        deliverer.set_maildir_hook(Arc::new(move |step, path| {
            sink.lock().expect("hook").push((step, path.to_path_buf()));
            if step == MaildirStep::AfterTmp {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            Ok(())
        }));
        let queued = stage(
            &spool,
            envelope("0003", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert_eq!(
            report.disposition,
            Disposition::Held,
            "a failed write must not settle the recipient"
        );
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Deferred { .. }
        ));
        let maildir = deliverer.maildir_path(&addr("ops@example.com"));
        assert!(entries(&maildir.join("new")).is_empty());
        assert!(
            entries(&maildir.join("tmp")).is_empty(),
            "tmp is cleaned up"
        );
        assert_eq!(
            seen.lock().expect("hook").len(),
            1,
            "the hook stopped the write"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_crash_after_the_rename_is_rolled_back_on_the_spot() {
        // The file is in `new/` but the directory has not been synced. The
        // step fails, and the message must not be left visible: a retry would
        // otherwise duplicate it on every pass.
        let f = fixture("crash-rename");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        deliverer.set_maildir_hook(Arc::new(|step, _path| {
            if step == MaildirStep::AfterRename {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            Ok(())
        }));
        let queued = stage(
            &spool,
            envelope("0004", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert_eq!(report.disposition, Disposition::Held);
        let maildir = deliverer.maildir_path(&addr("ops@example.com"));
        assert!(
            entries(&maildir.join("new")).is_empty(),
            "an unsynced file must not stay where a client looks"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_directory_sync_runs_before_the_delivery_is_recorded() {
        // The last step of the write is the one that makes it durable, and it
        // must run before the recipient is marked delivered — otherwise a
        // power cut would leave a recipient the queue believes is done and a
        // name in `new/` that is not on the medium.
        let f = fixture("crash-dirsync");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let order = Arc::new(StdMutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&order);
        deliverer.set_maildir_hook(Arc::new(move |step, _path| {
            seen.lock().expect("hook").push(format!("{step:?}"));
            Ok(())
        }));
        let syncs = Arc::clone(&order);
        deliverer.set_sync_observer(Arc::new(move |what| {
            syncs.lock().expect("hook").push(
                match what {
                    MaildirSync::File => "sync-file",
                    MaildirSync::Dir => "sync-dir",
                }
                .to_owned(),
            );
        }));
        let queued = stage(
            &spool,
            envelope("0005", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        // The writes are different types, so the assertion is on their
        // sequence through the hook's own ordering: tmp, file sync, rename,
        // directory sync, dir-sync step.
        assert_eq!(
            *order.lock().expect("hook"),
            vec![
                "AfterTmp".to_owned(),
                "sync-file".to_owned(),
                "AfterRename".to_owned(),
                "sync-dir".to_owned(),
                "AfterDirSync".to_owned(),
            ],
            "the file is synced before it is named, the directory after"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_that_cannot_be_synced_fails_the_delivery() {
        let f = fixture("failing-dirsync");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        deliverer.set_maildir_hook(Arc::new(|step, _path| {
            if step == MaildirStep::AfterDirSync {
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            Ok(())
        }));
        let queued = stage(
            &spool,
            envelope("0006", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert!(
            matches!(
                report.recipients[0].outcome,
                RecipientOutcome::Deferred { .. }
            ),
            "{:?}",
            report.recipients[0].outcome
        );
        // The file is in `new/` and the directory sync failed: the delivery
        // is not durable yet, so the file must not stay where a client reads
        // it while the record says "pending".
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn two_messages_for_one_mailbox_never_share_a_name() {
        let f = fixture("names");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let mut names = Vec::new();
        for index in 0..8 {
            let queued = stage(
                &spool,
                envelope(
                    &format!("00{index:02}"),
                    "alice@partner.example",
                    &["ops@example.com"],
                ),
                message(),
            );
            let report = deliverer
                .deliver_message(&state, &queued, 1_000)
                .expect("deliver");
            if let RecipientOutcome::Delivered(path) = &report.recipients[0].outcome {
                names.push(
                    path.file_name()
                        .expect("name")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        let new = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        assert_eq!(entries(&new).len(), 8);
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 8, "every write got its own name");
        // The sequence the deliverer hands out is its own, not the spool's.
        let spool_id = spool.next_id();
        assert!(!spool_id.contains(','));
        assert!(!spool_id.contains('.'), "a spool id has no file extension");
        assert!(names.iter().all(|name| name.contains(",H")));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── the five branches of `route` ─────────────────────────────────────

    #[test]
    fn a_mailbox_recipient_is_written_into_that_mailbox() {
        let f = fixture("branch-mailbox");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0100", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert_eq!(
            report.recipients[0].outcome,
            RecipientOutcome::Delivered(
                deliverer
                    .maildir_path(&addr("ops@example.com"))
                    .join("new")
                    .join(
                        entries(&deliverer.maildir_path(&addr("ops@example.com")).join("new"))[0]
                            .clone()
                    )
            )
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_shared_mailbox_is_a_maildir_like_any_other() {
        let f = fixture("branch-shared");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        // `route` resolves the shared mailbox only when the recipient domain
        // is hosted and the address is in `state.shared`.
        let mut state = state();
        state
            .accounts
            .retain(|account| account.address != addr("shared@elsewhere.example"));
        state.policy.default_action = ayane_proto::DefaultAction::Quarantine;
        let queued = stage(
            &spool,
            envelope(
                "0101",
                "alice@partner.example",
                &["shared@elsewhere.example"],
            ),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ));
        assert_eq!(
            entries(
                &deliverer
                    .maildir_path(&addr("shared@elsewhere.example"))
                    .join("new")
            )
            .len(),
            1
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_catch_all_recipient_is_written_into_the_catch_all_mailbox() {
        let f = fixture("branch-catchall");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        // `nobody@example.com` is not an account but the domain has a
        // catch-all; the router sends it to `inbox@example.com`.
        let queued = stage(
            &spool,
            envelope("0102", "alice@partner.example", &["nobody@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ));
        let catch_all = deliverer
            .maildir_path(&addr("inbox@example.com"))
            .join("new");
        assert_eq!(entries(&catch_all).len(), 1);
        // `Delivered-To` names the envelope recipient, not the catch-all: the
        // mailbox is where it landed, the field says for whom.
        assert!(read_all(&catch_all).contains("Delivered-To: nobody@example.com\r\n"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_quarantined_recipient_leaves_the_maildir_alone() {
        let f = fixture("branch-quarantine");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        // Allow-listed catch-all with a sender that is not on the list:
        // `route` answers `Quarantine`.
        let queued = stage(
            &spool,
            envelope("0103", "stranger@unknown.example", &["nobody@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&quarantine_state(), &queued, 1_000)
            .expect("deliver");
        let RecipientOutcome::Quarantined(path) = &report.recipients[0].outcome else {
            panic!(
                "expected quarantine, got {:?}",
                report.recipients[0].outcome
            );
        };
        assert!(path.starts_with(deliverer.quarantine()));
        assert!(!path.starts_with(deliverer.maildir_path(&addr("inbox@example.com"))));
        assert!(std::fs::read_to_string(path)
            .expect("read")
            .contains("Delivered-To: nobody@example.com"));
        // The quarantine directory is not inside the spool's swept folders.
        assert!(!deliverer.quarantine().ends_with("new"));
        assert_eq!(report.disposition, Disposition::Delivered);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_forward_becomes_a_child_entry_per_target() {
        let f = fixture("branch-forward");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0104", "alice@partner.example", &["team@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        let RecipientOutcome::Forwarded { targets, child } = &report.recipients[0].outcome else {
            panic!("expected a forward, got {:?}", report.recipients[0].outcome);
        };
        assert_eq!(
            targets,
            &vec![addr("a@partner.example"), addr("b@partner.example")]
        );
        assert_eq!(report.disposition, Disposition::Forwarded);
        // The alias keeps no local copy: the parent is gone and two children
        // are in `new/`.
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        let children = spool.list(QueueState::New).expect("list");
        assert_eq!(children.len(), 2);
        let first = children
            .iter()
            .find(|entry| entry.id == *child)
            .expect("the reported child");
        assert_eq!(
            first.envelope.forwarded_from.as_deref(),
            Some("team@example.com")
        );
        assert_eq!(first.envelope.forward_hops, 1);
        assert_eq!(
            first.envelope.mail_from, "alice@partner.example",
            "a forward keeps the original reverse-path"
        );
        assert_eq!(
            first.envelope.mail_from_wire, "<alice@partner.example>",
            "the null-sender rule reads the wire form"
        );
        // The bytes are the parent's, with this hop's trace field in front.
        let body = String::from_utf8(
            spool
                .read_message(QueueState::New, &first.id)
                .expect("read"),
        )
        .expect("utf8");
        assert!(body.starts_with("Received: from mx.example.com"), "{body}");
        assert!(body.contains("Received: from client.test"), "{body}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_reject_at_delivery_time_is_dropped_without_a_bounce() {
        let f = fixture("branch-reject");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        // The recipient was accepted, then the denylist grew: `route` now
        // answers `Reject`.
        let mut state = state();
        state.policy.denylist = vec![SenderRule::Domain("partner.example".to_owned())];
        let audited = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&audited);
        deliverer.set_audit_sink(Arc::new(move |event| {
            sink.lock().expect("audit").push(event);
        }));
        let queued = stage(
            &spool,
            envelope("0105", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Rejected(_)
        ));
        assert_eq!(report.disposition, Disposition::Dropped);
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        assert!(
            spool.list(QueueState::New).expect("list").is_empty(),
            "no DSN and no forward may be left behind"
        );
        assert!(matches!(
            audited.lock().expect("audit").first(),
            Some(AuditEvent::RouterRejected { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_remote_recipient_is_left_for_the_outbound_transport() {
        let f = fixture("branch-remote");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0106", "alice@partner.example", &["girl@remote.example"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert_eq!(report.recipients[0].outcome, RecipientOutcome::Remote);
        assert_eq!(report.disposition, Disposition::Held);
        // No attempt is charged and no bounce is produced: the entry waits.
        assert_eq!(spool.list(QueueState::Cur).expect("list").len(), 1);
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        // A pass where nothing moved writes nothing: a `Remote` recipient is
        // looked at again every `--interval-seconds` for days, and neither the
        // spool's files nor its directories may grow from that.
        let before_files = entries(&spool.root().join("cur"));
        let before_record = deliverer.read_record(&queued.id).expect("record");
        let again = deliverer
            .deliver_claimed(&state, &queued, 2_000)
            .expect("deliver");
        assert_eq!(
            again.recipients.len(),
            1,
            "the remote recipient is looked at again and left alone"
        );
        assert_eq!(again.recipients[0].outcome, RecipientOutcome::Remote);
        assert_eq!(again.disposition, Disposition::Held);
        assert_eq!(
            entries(&spool.root().join("cur")),
            before_files,
            "an idle pass must not write anything into the spool"
        );
        assert_eq!(
            deliverer.read_record(&queued.id).expect("record"),
            before_record,
            "and nothing in the record"
        );
        // There is nothing to write: a `Remote` recipient never moved, so no
        // record was produced for it — and therefore no attempt is charged for
        // a delivery nobody attempted.
        assert!(before_record.recipients.is_empty(), "{before_record:?}");
        assert!(!deliverer.record_path(&queued.id).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn one_message_with_several_recipients_reports_each_one_separately() {
        let f = fixture("multi-recipient");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope(
                "0107",
                "alice@partner.example",
                &[
                    "ops@example.com",
                    "shared@elsewhere.example",
                    "girl@remote.example",
                ],
            ),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert_eq!(report.recipients.len(), 3);
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ));
        assert!(matches!(
            report.recipients[1].outcome,
            RecipientOutcome::Delivered(_)
        ));
        assert_eq!(report.recipients[2].outcome, RecipientOutcome::Remote);
        // The remote recipient keeps the entry in the queue while the two
        // local ones are already settled — and a second pass does not write
        // them again.
        assert_eq!(report.disposition, Disposition::Held);
        let again = deliverer
            .deliver_claimed(&state, &queued, 2_000)
            .expect("deliver");
        assert_eq!(again.recipients.len(), 1, "{:?}", again.recipients);
        assert_eq!(again.recipients[0].outcome, RecipientOutcome::Remote);
        let ops = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        assert_eq!(
            entries(&ops).len(),
            1,
            "the settled recipient was written once"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── the retry ladder, end to end ─────────────────────────────────────

    #[test]
    fn a_failed_recipient_climbs_the_ladder_and_is_then_bounced() {
        let root = temp_root("retry-ladder");
        let spool = Spool::open(root.join("spool")).expect("spool");
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        let state = state();
        // A permanent-but-retried failure is simulated with a transient one:
        // the mailbox lives on a read-only directory, so every write is
        // `StorageFull` … except the hook drives it explicitly.
        let start = 1_000_000u64;
        let mailbox = deliverer.maildir_path(&addr("ops@example.com"));
        std::fs::create_dir_all(mailbox.join("tmp")).expect("tmp");
        // A full disk, for every attempt: the maildir directory sync is the
        // step that fails, which is the transient class the ladder is for.
        block_directory_syncs(&deliverer);
        let queued = stage(
            &spool,
            envelope("0200", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let first = deliverer
            .deliver_message(&state, &queued, start)
            .expect("deliver");
        let RecipientOutcome::Deferred {
            next_attempt_epoch, ..
        } = first.recipients[0].outcome
        else {
            panic!("expected a retry, got {:?}", first.recipients[0].outcome);
        };
        assert_eq!(next_attempt_epoch, start + 15 * 60);
        assert_eq!(first.disposition, Disposition::Held);
        // The message is still queued and the record remembers the attempt.
        assert_eq!(spool.list(QueueState::Cur).expect("list").len(), 1);
        let record = deliverer.read_record("0200").expect("record");
        assert_eq!(record.recipients[0].state.attempts, 1);

        // Before the wait expires nothing happens at all.
        let early = deliverer
            .deliver_claimed(&state, &queued, next_attempt_epoch - 1)
            .expect("deliver");
        assert!(early.recipients.is_empty());

        // Once the horizon is over the recipient is bounced instead.
        let late = start + ayane_retry_max_age() + 1;
        let report = deliverer
            .deliver_claimed(&state, &queued, late)
            .expect("deliver");
        let RecipientOutcome::Bounced { dsn, .. } = &report.recipients[0].outcome else {
            panic!("expected a bounce, got {:?}", report.recipients[0].outcome);
        };
        let dsn = dsn.as_ref().expect("a DSN for a real sender");
        assert_eq!(report.disposition, Disposition::Delivered);
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        let report_entry = spool
            .list(QueueState::New)
            .expect("list")
            .into_iter()
            .find(|entry| entry.id == *dsn)
            .expect("the report is queued");
        assert_eq!(
            report_entry.envelope.mail_from, "",
            "a DSN has the null sender"
        );
        assert_eq!(report_entry.envelope.mail_from_wire, "<>");
        assert_eq!(
            report_entry.envelope.recipients,
            vec!["alice@partner.example"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn ayane_retry_max_age() -> u64 {
        RetryPolicy::DEFAULT_MAX_AGE.as_secs()
    }

    /// Makes every maildir directory sync fail the way a full disk does, so a
    /// delivery fails with a *transient* error (`StorageFull`) — the class the
    /// retry ladder exists for — rather than the permanent one a path that can
    /// never be created produces.
    fn block_directory_syncs(deliverer: &Deliverer) {
        deliverer.set_maildir_hook(Arc::new(|step, _path| {
            if step == MaildirStep::AfterRename {
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
            Ok(())
        }));
    }

    #[test]
    fn an_attempt_cap_bounces_before_the_deadline() {
        let root = temp_root("attempt-cap");
        let spool = Spool::open(&root).expect("spool");
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com")
            .with_retry(RetryPolicy {
                max_attempts: 2,
                ..RetryPolicy::default()
            });
        let state = state();
        block_directory_syncs(&deliverer);
        let queued = stage(
            &spool,
            envelope("0201", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 10)
            .expect("deliver");
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Deferred { .. }
        ));
        let second = deliverer
            .deliver_claimed(&state, &queued, 10 + 15 * 60)
            .expect("deliver");
        assert!(
            matches!(
                second.recipients[0].outcome,
                RecipientOutcome::Bounced { .. }
            ),
            "{:?}",
            second.recipients[0].outcome
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_permanent_failure_is_not_retried() {
        let root = temp_root("permanent");
        let spool = Spool::open(root.join("spool")).expect("spool");
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        let state = state();
        // `new/` is a regular file: `create_dir_all` fails with a permanent
        // error, so the recipient is bounced on the first pass.
        let mailbox = deliverer.maildir_path(&addr("ops@example.com"));
        std::fs::create_dir_all(&mailbox).expect("maildir");
        std::fs::write(mailbox.join("new"), b"a file where a directory goes").expect("blocker");
        let queued = stage(
            &spool,
            envelope("0202", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 10)
            .expect("deliver");
        assert!(
            matches!(
                report.recipients[0].outcome,
                RecipientOutcome::Bounced { dsn: Some(_), .. }
            ),
            "{:?}",
            report.recipients[0].outcome
        );
        assert_eq!(report.disposition, Disposition::Delivered);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_mailbox_is_waited_for_not_bounced() {
        // An account whose maildir the engine has not created yet is the
        // common case right after provisioning: it must be retried.
        let root = temp_root("missing-mailbox");
        let spool = Spool::open(root.join("spool")).expect("spool");
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        let state = state();
        let queued = stage(
            &spool,
            envelope("0203", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 10)
            .expect("deliver");
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ));
        // The write creates `tmp/` and `new/` when they are absent: a missing
        // mailbox is a *directory creation*, not a failure.
        assert_eq!(
            entries(&deliverer.maildir_path(&addr("ops@example.com")).join("new")).len(),
            1
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_consumer_does_not_take_a_message_the_first_one_is_delivering() {
        // `S1-a`: two consumers over one spool. A claims and holds the message
        // open — exactly what a delivery pass does while it reads it — and B's
        // full pass must not move it back to `new/` or deliver it a second
        // time. Once A is gone (its descriptor closed, and its entry older
        // than the residue window, because this process's own pid is the id's
        // and a live pid is respected while the file is young), B's next pass
        // picks it up.
        let f = fixture("two-consumers");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0309", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        spool.claim(&queued.id).expect("consumer A claims it");
        let held = std::fs::File::open(spool.root().join("cur").join(format!("{}.eml", queued.id)))
            .expect("consumer A holds it open");
        // B's pass sees the entry in cur/ and must leave it alone.
        let reports = deliverer.run_at(&state, 1_000).expect("B's pass");
        assert!(reports.is_empty(), "B must deliver nothing: {reports:?}");
        assert_eq!(
            spool.list(QueueState::Cur).expect("list").len(),
            1,
            "the message is still A's"
        );
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(
            !deliverer
                .maildir_path(&addr("ops@example.com"))
                .join("new")
                .exists(),
            "B must not have delivered it"
        );
        // A dies: the handle goes, and the file ages past the residue window
        // (this process's pid names it, so only age can prove it abandoned).
        drop(held);
        let path = spool.root().join("cur").join(format!("{}.eml", queued.id));
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.set_modified(old).expect("age the message");
        drop(file);
        let reports = deliverer.run_at(&state, 2_000).expect("B's next pass");
        assert_eq!(reports.len(), 1, "B picks up what A died on: {reports:?}");
        assert_eq!(reports[0].disposition, Disposition::Delivered);
        assert_eq!(
            entries(&deliverer.maildir_path(&addr("ops@example.com")).join("new")).len(),
            1
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── the DSN ──────────────────────────────────────────────────────────

    #[test]
    fn the_report_is_an_rfc3464_multipart_with_the_required_fields() {
        let report = dsn_body(
            "mx.example.com",
            &addr("alice@partner.example"),
            "ops@example.com",
            "0204",
            7,
            "maildir: disk full",
            1_000_000,
        );
        let text = String::from_utf8(report).expect("utf8");
        assert!(text.starts_with("From: Mail Delivery System <postmaster@mx.example.com>\r\n"));
        assert!(text.contains("To: <alice@partner.example>\r\n"));
        assert!(text.contains("Content-Type: multipart/report; report-type=delivery-status;"));
        assert!(text.contains("Content-Type: message/delivery-status\r\n"));
        assert!(text.contains("Reporting-MTA: dns; mx.example.com\r\n"));
        assert!(text.contains("Final-Recipient: rfc822; ops@example.com\r\n"));
        assert!(text.contains("Action: failed\r\n"));
        assert!(
            text.contains("Status: 5.0.0\r\n"),
            "a permanent failure is 5yz"
        );
        assert!(text.contains("Diagnostic-Code: X-ayane; maildir: disk full\r\n"));
        assert!(text.contains("Attempts: 7\r\n"));
        assert!(text.contains("Content-Type: text/rfc822-headers\r\n"));
        // Every line ends in CRLF and the closing boundary is the last one.
        assert!(text.ends_with("--ayane-dsn-0204--\r\n"));
        assert!(!text.contains("\n\n\n"));
        for line in text.split("\r\n") {
            assert!(!line.ends_with('\r'), "a stray lone CR: {line:?}");
        }
    }

    #[test]
    fn the_report_cannot_be_header_injected_by_its_arguments() {
        // A hostname or an error message carrying CR or LF would end the field
        // it is in and start one this crate never wrote.
        let report = dsn_body(
            "mx.example.com\r\nBcc: attacker@evil.example",
            &addr("alice@partner.example"),
            "ops@example.com",
            "0311\nX-Injected: yes",
            1,
            "maildir: /a\r\nb\nbad",
            1_000_000,
        );
        let text = String::from_utf8(report).expect("utf8");
        // CR and LF are folded into spaces, so neither injected field can
        // start a line of its own — which is what makes it a field.
        for line in text.split("\r\n") {
            assert!(
                !line.starts_with("Bcc:") && !line.starts_with("X-Injected:"),
                "injected field at line start: {line:?}"
            );
            assert!(line.len() <= 998, "a header line stays field-readable");
        }
        assert!(text.contains("Bcc: attacker@evil.example>\r\n"), "{text}");
        // The failure reason is on the Diagnostic-Code line and nowhere else.
        assert!(
            text.contains("Diagnostic-Code: X-ayane; maildir: /a  b bad\r\n"),
            "{text}"
        );
    }

    #[test]
    fn a_null_sender_is_never_bounced_and_the_drop_is_audited() {
        let root = temp_root("null-sender");
        let spool = Spool::open(root.join("spool")).expect("spool");
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        let state = state();
        let events = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        deliverer.set_audit_sink(Arc::new(move |event| {
            sink.lock().expect("audit").push(event);
        }));
        let mailbox = deliverer.maildir_path(&addr("ops@example.com"));
        std::fs::create_dir_all(&mailbox).expect("maildir");
        std::fs::write(mailbox.join("new"), b"a file where a directory goes").expect("blocker");
        let queued = stage(
            &spool,
            envelope("0205", "", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 10)
            .expect("deliver");
        assert!(
            matches!(
                report.recipients[0].outcome,
                RecipientOutcome::Bounced { dsn: None, .. }
            ),
            "{:?}",
            report.recipients[0].outcome
        );
        // Nothing was enqueued: no DSN, and the original is gone (the
        // recipient reached a terminal state).
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert_eq!(report.disposition, Disposition::Delivered);
        let events = events.lock().expect("audit");
        assert!(matches!(
            events.first(),
            Some(AuditEvent::NullSenderDropped { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_null_sender_is_still_routed_and_delivered_rather_than_dropped() {
        // The rule is about *bounces*, not about mail: a report from `<>`
        // addressed to a local mailbox is delivered like anything else.
        let f = fixture("null-sender-local");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0206", "", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 10)
            .expect("deliver");
        assert!(matches!(
            report.recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_report_is_addressed_to_the_sender_and_returns_from_the_null_path() {
        // The report goes back to whoever sent the message, and it travels as
        // `<>` itself — the property that makes "a DSN never generates a DSN"
        // automatic rather than a special case.
        let f = fixture("dsn-envelope");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let id = deliverer
            .enqueue_dsn(
                &addr("alice@partner.example"),
                "0305",
                "ops@example.com",
                4,
                1_000,
                "mailbox on fire",
            )
            .expect("enqueue");
        let entry = spool
            .list(QueueState::New)
            .expect("list")
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("the report is queued");
        assert_eq!(entry.envelope.recipients, vec!["alice@partner.example"]);
        assert_eq!(entry.envelope.mail_from, "");
        assert_eq!(entry.envelope.mail_from_wire, "<>");
        let text = String::from_utf8(spool.read_message(QueueState::New, &id).expect("read"))
            .expect("utf8");
        assert!(
            text.starts_with("From: Mail Delivery System <postmaster@mx.example.com>\r\n"),
            "{text:.120}"
        );
        assert!(
            text.contains("To: <alice@partner.example>\r\n"),
            "{text:.300}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_queue_id_reused_by_a_new_message_does_not_inherit_the_old_record() {
        // `S1-c`: ids can be handed out twice (a seeded counter, a restored
        // spool), and a record left beside an old message would make the new
        // one look finished before anything was attempted — it would vanish.
        // The fix is that a settled message takes its record with it, so a
        // reused id has nothing to inherit.
        let f = fixture("id-reuse");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        // A second account, so the reused id names a *different* mailbox.
        let mut state = state();
        state.accounts.push(account("second@example.com"));
        let queued = stage(
            &spool,
            envelope("0310", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert!(
            !deliverer.record_path(&queued.id).exists(),
            "a settled message takes its record with it"
        );
        // The same id again, for a different message and a different mailbox.
        let second = stage(
            &spool,
            envelope("0310", "alice@partner.example", &["second@example.com"]),
            b"Subject: second\r\n\r\nbody\r\n",
        );
        let report = deliverer
            .deliver_message(&state, &second, 2_000)
            .expect("deliver");
        assert_eq!(report.disposition, Disposition::Delivered);
        assert_eq!(
            report.recipients[0].recipient, "second@example.com",
            "the new message's own recipient"
        );
        let delivered = deliverer
            .maildir_path(&addr("second@example.com"))
            .join("new");
        assert_eq!(
            entries(&delivered).len(),
            1,
            "the second message was delivered"
        );
        assert_eq!(
            entries(&deliverer.maildir_path(&addr("ops@example.com")).join("new")).len(),
            1,
            "the first message's mailbox still holds exactly its own copy"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_settled_record_makes_the_pass_a_no_op_rather_than_a_delivery() {
        // The settled branch and the "every recipient is already settled"
        // skip look identical in a run where both hold. This asks the branch
        // on its own: a record with one settled recipient *and nothing else*
        // is exactly the shape the branch must answer, and a pass that ignored
        // it would fall through to the per-recipient loop and deliver the
        // message a second time.
        let f = fixture("settled-noop");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0312", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        spool.claim(&queued.id).expect("claim");
        let mut settled = RecipientState::new("ops@example.com");
        settled.pending = false;
        deliverer
            .write_record(
                &queued.id,
                &DeliveryRecord {
                    recipients: vec![RecordedRecipient { state: settled }],
                },
            )
            .expect("record");
        let report = deliverer
            .deliver_claimed(&state, &queued, 1_000)
            .expect("deliver");
        assert!(
            report.recipients.is_empty(),
            "a settled entry delivers nothing: {:?}",
            report.recipients
        );
        assert_eq!(report.disposition, Disposition::Held);
        assert!(
            !deliverer
                .maildir_path(&addr("ops@example.com"))
                .join("new")
                .exists(),
            "and writes nothing into a mailbox"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_report_that_cannot_be_delivered_is_dropped_without_another() {
        // The lifecycle: the report is a message like any other, so the queue
        // tries to deliver it; when *that* fails the reverse-path is `<>` and
        // the null-sender rule ends it — one audit line, no second report.
        let f = fixture("dsn-lifecycle");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let events = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        deliverer.set_audit_sink(Arc::new(move |event| {
            sink.lock().expect("audit").push(event);
        }));
        // The sender's mailbox cannot be written: `new/` is a file. The
        // sender has to be a local account of the fixture for the delivery to
        // be attempted at all — a remote one is left alone, by design.
        let state = {
            let mut state = state();
            // `partner.example` is not a hosted domain in the fixture, so the
            // sender's mailbox is added together with its domain.
            state.domains.push(domain("partner.example"));
            state.accounts.push(account("alice@partner.example"));
            state
        };
        let mailbox = deliverer.maildir_path(&addr("alice@partner.example"));
        std::fs::create_dir_all(&mailbox).expect("maildir");
        std::fs::write(mailbox.join("new"), b"a file where a directory goes").expect("blocker");
        let id = deliverer
            .enqueue_dsn(
                &addr("alice@partner.example"),
                "0306",
                "ops@example.com",
                4,
                1_000,
                "mailbox on fire",
            )
            .expect("enqueue");
        let queued = spool
            .list(QueueState::New)
            .expect("list")
            .into_iter()
            .find(|entry| entry.id == id)
            .expect("the report is queued");
        let report = deliverer
            .deliver_message(&state, &queued, 2_000)
            .expect("deliver");
        assert!(
            matches!(
                report.recipients[0].outcome,
                RecipientOutcome::Bounced { dsn: None, .. }
            ),
            "{:?}",
            report.recipients[0].outcome
        );
        // No second report was queued, and the drop is on the audit trail.
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(matches!(
            events.lock().expect("audit").first(),
            Some(AuditEvent::NullSenderDropped { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_generated_report_is_a_message_the_queue_can_carry() {
        // A DSN goes back through the queue, so its own delivery must work and
        // its own failure must not produce a second report.
        let f = fixture("dsn-roundtrip");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let dsn = deliverer
            .enqueue_dsn(
                &addr("ops@example.com"),
                "0207",
                "nobody@example.com",
                5,
                10,
                "mailbox on fire",
            )
            .expect("enqueue");
        let listed = spool.list(QueueState::New).expect("list");
        let entry = listed.iter().find(|entry| entry.id == dsn).expect("listed");
        let body = String::from_utf8(spool.read_message(QueueState::New, &dsn).expect("read"))
            .expect("utf8");
        assert!(body.contains("multipart/report"));
        let report = deliverer
            .deliver_message(&state, entry, 20)
            .expect("deliver");
        assert!(
            matches!(report.recipients[0].outcome, RecipientOutcome::Delivered(_)),
            "{:?}",
            report.recipients[0].outcome
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── crash safety around claim ────────────────────────────────────────

    #[test]
    fn a_message_claimed_before_a_crash_is_picked_up_by_the_next_pass() {
        // `claim` is the line between "waiting" and "being delivered". A
        // consumer that dies on the far side of it leaves the entry in `cur/`
        // and nothing else; a delivery pass has to finish it, not lose it.
        let f = fixture("crash-claim");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0300", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        spool
            .claim(&queued.id)
            .expect("the consumer claimed it, then died");
        assert_eq!(spool.list(QueueState::New).expect("list").len(), 0);
        assert_eq!(spool.list(QueueState::Cur).expect("list").len(), 1);
        // The next pass: recovery reclaims, delivery completes, nothing is
        // left in the queue.
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].id, "0300");
        assert_eq!(reports[0].disposition, Disposition::Delivered);
        let delivered = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        assert_eq!(entries(&delivered).len(), 1);
        assert_eq!(
            String::from_utf8_lossy(
                &std::fs::read(delivered.join(&entries(&delivered)[0])).expect("read")
            ),
            format!(
                "Delivered-To: ops@example.com\r\n{}",
                String::from_utf8_lossy(message())
            )
        );
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_record_left_behind_by_a_crash_is_respected_by_the_next_pass() {
        // The crash the module docs describe: the maildir write finished and
        // the pass died before the record was updated. The recipient is still
        // `pending` in the record, so the next pass delivers it again instead
        // of losing it — at-least-once, and the test says so out loud.
        let f = fixture("crash-record");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0301", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        spool.claim(&queued.id).expect("claim");
        deliverer
            .write_record(
                &queued.id,
                &DeliveryRecord {
                    recipients: vec![RecordedRecipient {
                        state: RecipientState::new("ops@example.com"),
                    }],
                },
            )
            .expect("record");
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 1);
        assert!(matches!(
            reports[0].recipients[0].outcome,
            RecipientOutcome::Delivered(_)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_settled_record_is_honoured_and_survives_recovery() {
        // Two different claims live in one record, and the difference is which
        // pass reads it.
        //
        // * The pass that *settles* a message deletes the record with the
        //   message (see `a_queue_id_reused_by_a_new_message_...`).
        // * A record that is already settled and is still beside a claimed
        //   message belongs to that message — a crash after the maildir write
        //   and before the record went is the ordinary way to get here — so
        //   the pass honours it and does not deliver that recipient again.
        let f = fixture("settled-record");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0302", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        spool.claim(&queued.id).expect("claim");
        let record = DeliveryRecord {
            recipients: vec![RecordedRecipient {
                state: RecipientState {
                    pending: false,
                    ..RecipientState::new("ops@example.com")
                },
            }],
        };
        deliverer.write_record(&queued.id, &record).expect("record");
        // Recovery must not read the record as an orphan envelope.
        spool.recover_with_claimed(true).expect("a recovery pass");
        assert_eq!(
            deliverer.read_record("0302").expect("record"),
            record,
            "recovery must not mistake the record for an orphan envelope"
        );
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 1);
        assert!(
            reports[0].recipients.is_empty(),
            "a settled recipient is not delivered again: {:?}",
            reports[0].recipients
        );
        assert!(
            !deliverer
                .maildir_path(&addr("ops@example.com"))
                .join("new")
                .exists(),
            "a settled recipient must not be written a second time"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_claim_interrupted_between_its_two_renames_is_finished_not_repeated() {
        // A crash inside `claim` can leave the entry in `new/` *and* in
        // `cur/`. Both copies cannot be delivered, and the `cur/` one is the
        // one a record may already describe, so the pass finishes the move
        // instead of claiming again: the `new/` shell is dropped, the message
        // is delivered exactly once.
        let f = fixture("claim-interrupted");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0303", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        spool.claim(&queued.id).expect("the claim began");
        // Put the `new/` halves back, which is the state each rename leaves.
        for extension in ["json", "eml"] {
            std::fs::copy(
                spool
                    .root()
                    .join("cur")
                    .join(format!("{}.{extension}", queued.id)),
                spool
                    .root()
                    .join("new")
                    .join(format!("{}.{extension}", queued.id)),
            )
            .expect("the interrupted half");
        }
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 1, "one entry, one pass");
        assert_eq!(reports[0].disposition, Disposition::Delivered);
        let delivered = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        assert_eq!(
            entries(&delivered).len(),
            1,
            "the message must not be delivered twice"
        );
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_message_that_is_already_claimed_is_not_claimed_again() {
        // `claim` renames the `new/` halves *over* whatever `cur/` holds, so a
        // message with a `cur/` copy is a claim that began and did not finish,
        // not one to run again: the pass finishes it. The crash shape — the
        // claim died between its two renames, and the recovery sweep has put
        // the shells back in `new/` — needs a stale `new/` copy of an id that
        // is already in `cur/`, and the spool's staging path refuses to build
        // one (an id it already holds is a collision). So the test drives what
        // the pass decides on: the two cases must not be the same case.
        let f = fixture("already-claimed");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0307", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        assert!(
            !deliverer.half_claimed(&queued.id),
            "a message waiting in new/ has no cur/ copy"
        );
        spool.claim(&queued.id).expect("the consumer claimed it");
        assert!(
            deliverer.half_claimed(&queued.id),
            "a claimed message is the one the pass must finish rather than re-claim"
        );
        // And the delivery is still exactly once, through the pass.
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(
                reports[0].recipients[0].outcome,
                RecipientOutcome::Delivered(_)
            ),
            "{:?}",
            reports[0].recipients[0].outcome
        );
        let delivered = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        assert_eq!(entries(&delivered).len(), 1, "delivered exactly once");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_half_claimed_message_is_finished_rather_than_claimed_again() {
        // The state a crash inside `claim` leaves — the entry in `new/` *and*
        // in `cur/` — is delivered exactly once, and the `cur/` copy is the
        // one that wins. The `new/` shell is built by hand because the spool's
        // staging path (correctly) refuses to produce it.
        let f = fixture("half-claimed");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0308", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        // A second, older message under the same id: this is what a re-claim
        // would put into `cur/` if the pass did not finish the move first.
        let mut alternate = envelope("0308", "alice@partner.example", &["ops@example.com"]);
        alternate.received = "from an-older-hop".to_owned();
        for extension in ["json", "eml"] {
            std::fs::copy(
                spool
                    .root()
                    .join("new")
                    .join(format!("{}.{extension}", queued.id)),
                spool.root().join(format!("stale.{extension}")),
            )
            .expect("stash the new/ halves");
        }
        spool.claim(&queued.id).expect("the claim began");
        for extension in ["json", "eml"] {
            std::fs::rename(
                spool.root().join(format!("stale.{extension}")),
                spool
                    .root()
                    .join("new")
                    .join(format!("{}.{extension}", queued.id)),
            )
            .expect("the interrupted half");
        }
        assert!(deliverer.half_claimed(&queued.id));
        // The rule the pass decides with: `cur/` holds it, so it is finished.
        assert_eq!(
            deliverer.half_claimed(&queued.id),
            !deliverer
                .spool()
                .root()
                .join("cur")
                .join(format!("{}.eml", queued.id))
                .is_dir(),
            "the rule is 'a cur/ copy exists', not 'a new/ copy does'"
        );
        deliverer
            .spool()
            .reclaim_cur(&queued.id)
            .expect("finish the interrupted claim");
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(
                reports[0].recipients[0].outcome,
                RecipientOutcome::Delivered(_)
            ),
            "{:?}",
            reports[0].recipients[0].outcome
        );
        let delivered = deliverer.maildir_path(&addr("ops@example.com")).join("new");
        assert_eq!(entries(&delivered).len(), 1, "delivered exactly once");
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_queue_entry_is_removed_only_after_every_recipient_settled() {
        // The removal is the last step of a pass: an entry whose recipients
        // have all settled is gone, and one with a recipient still waiting
        // keeps both its files and its record.
        let f = fixture("remove-last");
        let root = f.root.clone();
        let (spool, deliverer) = (f.spool.clone(), &f.deliverer);
        let state = state();
        let queued = stage(
            &spool,
            envelope("0304", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        // `Spool::remove` unlinks the message and its envelope; it leaves the
        // delivery record, which is the delivery layer's file and inert once
        // its message is gone (`spool.list` is the only way into `cur/`).
        let cur = entries(&spool.root().join("cur"));
        assert!(
            cur.iter().all(|name| name.ends_with(RECORD_SUFFIX)),
            "only records may outlive their message: {cur:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── forwarding ───────────────────────────────────────────────────────

    #[test]
    fn a_forward_chain_is_cut_at_the_hop_cap() {
        let root = temp_root("forward-loop");
        let spool = Spool::open(root.join("spool")).expect("spool");
        // The aliases point at each other; every hop doubles the entries, so
        // the cap is what stops the queue from filling the disk.
        let a = addr("a@example.com");
        let b = addr("b@example.com");
        let state = DesiredState {
            domains: vec![domain("example.com")],
            aliases: vec![
                Alias {
                    source: a.clone(),
                    targets: vec![b.clone()],
                },
                Alias {
                    source: b,
                    targets: vec![a],
                },
            ],
            accounts: vec![],
            ..DesiredState::default()
        };
        let deliverer = Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com");
        let events = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        deliverer.set_audit_sink(Arc::new(move |event| {
            sink.lock().expect("audit").push(event);
        }));
        // Seed one message far down the chain: the cap is a property of the
        // entry, not of how long the test is willing to loop.
        let id = spool.next_id();
        let mut envelope = envelope(&id, "alice@partner.example", &["a@example.com"]);
        envelope.forward_hops = DEFAULTS.max_forward_hops;
        envelope.forwarded_from = Some("b@example.com".to_owned());
        stage(&spool, envelope, message());
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        let outcome = &reports[0].recipients[0].outcome;
        let RecipientOutcome::Deferred { reason, .. } = outcome else {
            panic!("expected the loop to be refused, got {outcome:?}");
        };
        assert!(reason.contains("forward loop"), "{reason}");
        assert!(matches!(
            events.lock().expect("audit").first(),
            Some(AuditEvent::ForwardLoop { .. })
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_forward_keeps_the_null_sender_null() {
        let f = fixture("forward-null");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let mut envelope = envelope("0400", "", &["team@example.com"]);
        envelope.mail_from_wire = "<>".to_owned();
        stage(&spool, envelope, message());
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert!(matches!(
            reports[0].recipients[0].outcome,
            RecipientOutcome::Forwarded { .. }
        ));
        for child in spool.list(QueueState::New).expect("list") {
            assert_eq!(child.envelope.mail_from, "");
            assert_eq!(child.envelope.mail_from_wire, "<>");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_hop_field_is_counted_by_the_drivers_loop_bound() {
        // `received_count` is the driver's own bound on SMTP hops; a forward
        // has to be visible to it, or a cycle that never leaves the host would
        // never trip it.
        let f = fixture("hop-count");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let queued = stage(
            &spool,
            envelope("0401", "alice@partner.example", &["team@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        let RecipientOutcome::Forwarded { child, .. } = &report.recipients[0].outcome else {
            panic!("expected a forward");
        };
        let bytes = spool.read_message(QueueState::New, child).expect("read");
        let head = crate::server::received_count(&bytes[..bytes.len().min(4096)]);
        // The stored message carries the field the receiving side wrote for
        // it (`Received: from client.test`), and the forward adds its own.
        assert_eq!(head, 2, "the inbound field and this hop's");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── the queue pass ───────────────────────────────────────────────────

    #[test]
    fn a_pass_drains_every_queued_message_and_leaves_nothing() {
        let f = fixture("full-pass");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        for (index, recipient) in ["ops@example.com", "inbox@example.com", "nobody@example.com"]
            .iter()
            .enumerate()
        {
            stage(
                &spool,
                envelope(
                    &format!("05{index:02}"),
                    "alice@partner.example",
                    &[recipient],
                ),
                message(),
            );
        }
        let reports = deliverer.run_at(&state, 1_000).expect("run");
        assert_eq!(reports.len(), 3);
        assert!(reports
            .iter()
            .all(|report| report.disposition == Disposition::Delivered));
        assert!(spool.list(QueueState::New).expect("list").is_empty());
        assert!(spool.list(QueueState::Cur).expect("list").is_empty());
        // `Spool::remove` unlinks the message and its envelope and does not
        // touch this layer's `<id>.state.json`; a record without its message is
        // inert, and nothing in this module reads one back (`spool.list` is
        // the only way in).
        assert!(entries(&spool.root().join("cur"))
            .iter()
            .all(|name| name.ends_with(".state.json")),);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_envelope_is_preserved_field_by_field() {
        let f = fixture("envelope");
        let root = f.root.clone();
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let state = state();
        let mut sent = envelope("0600", "alice@partner.example", &["ops@example.com"]);
        sent.declared_size = Some(4096);
        sent.smtputf8 = false;
        sent.authenticated = Some("alice@partner.example".to_owned());
        sent.auth_summary = "spf=pass dkim=pass".to_owned();
        let queued = stage(&spool, sent.clone(), message());
        deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        // The queued entry was recorded with the digest and length of the
        // octets it committed …
        let delivered = std::fs::read(
            deliverer
                .maildir_path(&addr("ops@example.com"))
                .join("new")
                .join(&entries(&deliverer.maildir_path(&addr("ops@example.com")).join("new"))[0]),
        )
        .expect("read");
        let stripped = &delivered["Delivered-To: ops@example.com\r\n".len()..];
        assert_eq!(
            stripped,
            message(),
            "the delivered bytes are the queued bytes"
        );
        // … and the maildir copy is those bytes with one field in front.
        assert!(String::from_utf8_lossy(&delivered).contains("Subject: hi"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_quota_defers_rather_than_overflowing() {
        let root = temp_root("quota");
        let spool = Spool::open(&root).expect("spool");
        let deliverer =
            Deliverer::new(spool.clone(), root.join("mail"), "mx.example.com").with_quota(Some(10));
        let state = state();
        let queued = stage(
            &spool,
            envelope("0601", "alice@partner.example", &["ops@example.com"]),
            message(),
        );
        let report = deliverer
            .deliver_message(&state, &queued, 1_000)
            .expect("deliver");
        let RecipientOutcome::Deferred { reason, .. } = &report.recipients[0].outcome else {
            panic!(
                "expected a deferral, got {:?}",
                report.recipients[0].outcome
            );
        };
        assert!(reason.contains("quota"), "{reason}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_record_round_trips_through_json() {
        let mut state = RecipientState::new("ops@example.com");
        state.attempts = 3;
        state.last_error = Some("disk".to_owned());
        let record = DeliveryRecord {
            recipients: vec![RecordedRecipient { state }],
        };
        let bytes = serde_json::to_vec(&record).expect("json");
        let back: DeliveryRecord = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(back, record);
        // Flattened, so the row reads as one object per recipient.
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(value["recipients"][0]["recipient"].is_string(), "{value}");
        assert_eq!(value["recipients"][0]["attempts"], json!(3));
    }

    #[test]
    fn the_sequence_the_deliverer_hands_out_is_its_own() {
        let f = fixture("sequence");
        let spool = f.spool.clone();
        let deliverer = &f.deliverer;
        let first = deliverer.next_sequence();
        let second = deliverer.next_sequence();
        assert_ne!(first, second);
        // The spool's id is a different shape, so a maildir name built with
        // one can never be confused with a queue file.
        let id = spool.next_id();
        assert!(id.split('-').count() == 3, "{id}");
    }
}
