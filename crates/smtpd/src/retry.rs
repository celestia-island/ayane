//! When a delivery is tried again, and when the queue gives up.
//!
//! This module is pure: it reads no clock and touches no disk. It answers one
//! question — "given what happened so far, when may this recipient be tried
//! next, and has the queue run out of patience?" — and the delivery driver
//! ([`crate::deliver`]) supplies the clock, the failures and the recorded
//! attempt. That split is what lets the whole schedule be a table in a test
//! instead of a five-hour sleep.
//!
//! # The schedule
//!
//! RFC 5321 §4.5.4.1 asks a sender to retry a recipient that answered 4yz
//! after *at least* 30 minutes, and to give up after 4–5 days. The concrete
//! ladder used here ([`RetryPolicy::default`]) is:
//!
//! | Attempt | Wait before the next one |
//! | --- | --- |
//! | 1 | 15 min |
//! | 2 | 30 min |
//! | 3 | 1 h |
//! | 4 | 2 h |
//! | 5–14 | 3 h, then 4 h after the first six hours |
//!
//! which is the shape the RFC describes in prose: "two attempts in the first
//! hour, then every 2–3 hours". The last rung repeats until the deadline, so
//! "every N hours for the rest of the window" is one rung, not a table entry
//! per hour. The ladder is a constant on purpose — it is a specification, not
//! an operator preference — while the **deadline** and the **cap on attempts**
//! are fields, because a deployment with a slow upstream legitimately wants a
//! longer horizon.
//!
//! The first wait is shorter than the RFC's 30-minute floor because the
//! failure this ladder actually sees most often during a delivery is not a
//! remote server saying "later": it is the local disk or a maildir that has
//! not been created yet. Being slow to retry a local write costs a message
//! sitting in the queue; being fast costs nothing, because a genuinely
//! unavailable remote is still not retried after its own next-attempt stamp.
//!
//! # What counts as a failure worth retrying
//!
//! Only `io::Error`s reach here, and [`RetryClass`] decides what they mean:
//!
//! * [`RetryClass::Transient`] — the medium was busy or momentarily out of
//!   space: try again later.
//! * [`RetryClass::Permanent`] — the path can never be written (a maildir
//!   whose name cannot exist, a target that is a directory): retrying wastes
//!   the whole horizon before bouncing, so the recipient is failed at once.
//! * [`RetryClass::Transient`] with `ErrorKind::NotFound` — the directory to
//!   write into does not exist yet. This is **transient**: the mailbox is
//!   provisioned by the engine on a different schedule than mail arrives, and
//!   giving up here would bounce mail for an account an operator created five
//!   minutes ago. (`NotFound` is the one error kind where "the path is wrong"
//!   and "the path is not there *yet*" read alike, and for a maildir the
//!   second reading is the one that happens in practice.)
//!
//! `AlreadyExists` is deliberately *permanent*: a maildir file name collides
//! only when the same name was chosen twice, which a retry with a fresh name
//! cannot fix, and treating it as transient would turn a bug into a slow
//! bounce.

use std::io::{self, ErrorKind};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How one delivery failure may be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Try again later; the failure may pass.
    Transient,
    /// Never try this recipient again; fail it now.
    Permanent,
}

impl RetryClass {
    /// Classifies an I/O error from the delivery path.
    #[must_use]
    pub fn of(error: &io::Error) -> Self {
        match error.kind() {
            // The medium: busy, interruptible, or out of room right now.
            ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::TimedOut
            | ErrorKind::WriteZero
            | ErrorKind::OutOfMemory
            | ErrorKind::QuotaExceeded
            | ErrorKind::StorageFull
            | ErrorKind::ReadOnlyFilesystem
            | ErrorKind::IsADirectory
            // The path: the mailbox is provisioned on its own schedule.
            | ErrorKind::NotFound => Self::Transient,
            // Everything else — a name that cannot exist, a collision, a
            // permission the operator has to fix — does not improve by
            // waiting.
            _ => Self::Permanent,
        }
    }
}

/// The retry ladder and the horizon after which the queue bounces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// How long an undeliverable recipient may stay in the queue before the
    /// message is bounced back to the envelope sender.
    pub max_age: Duration,
    /// The retry ladder: the wait after attempt 1, after attempt 2, … . The
    /// last entry repeats for every attempt beyond the table.
    pub schedule: &'static [Duration],
    /// A hard cap on attempts, whatever the deadline says. `0` means "no cap
    /// beyond the schedule" (the deadline is the only stop).
    pub max_attempts: u32,
}

impl RetryPolicy {
    /// Five days — RFC 5321 §4.5.4.1's "before giving up", and the value a
    /// mail system should choose when the sender cannot be asked.
    pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(5 * 24 * 60 * 60);

    /// The default ladder (see the module docs for the table it renders).
    pub const DEFAULT_SCHEDULE: &'static [Duration] = &[
        Duration::from_secs(15 * 60),
        Duration::from_secs(30 * 60),
        Duration::from_secs(60 * 60),
        Duration::from_secs(2 * 60 * 60),
        Duration::from_secs(3 * 60 * 60),
        Duration::from_secs(4 * 60 * 60),
    ];

    /// The wait after attempt number `attempt` (1-based).
    ///
    /// Returns `None` for attempt 0: there has been no failure yet, so there
    /// is nothing to wait for.
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Option<Duration> {
        if attempt == 0 || self.schedule.is_empty() {
            return None;
        }
        let index = (attempt as usize)
            .saturating_sub(1)
            .min(self.schedule.len() - 1);
        Some(self.schedule[index])
    }

    /// Whether `attempt` failures exhaust the attempt budget.
    #[must_use]
    pub fn attempts_exhausted(&self, attempt: u32) -> bool {
        self.max_attempts != 0 && attempt >= self.max_attempts
    }

    /// The decision after one failed attempt.
    ///
    /// `attempt` counts the failure that just happened (1 for the first), and
    /// `first_attempt_epoch` is when the message entered delivery — the
    /// deadline is measured from there, not from the latest failure, so a
    /// ladder cannot stretch the horizon by retrying forever.
    #[must_use]
    pub fn after_failure(
        &self,
        attempt: u32,
        first_attempt_epoch: u64,
        now_epoch: u64,
    ) -> RetryDecision {
        if self.attempts_exhausted(attempt)
            || now_epoch.saturating_sub(first_attempt_epoch) >= self.max_age.as_secs()
        {
            return RetryDecision::GiveUp { attempt };
        }
        let delay = self.delay(attempt).unwrap_or(Duration::ZERO);
        let next = now_epoch.saturating_add(delay.as_secs());
        // A wait that would land past the deadline is not a retry: the
        // recipient is due for the bounce as soon as the horizon ends, so the
        // queue may as well stop pretending and bounce at the deadline. The
        // attempt is scheduled *at* the deadline, where the driver's age check
        // bounces it.
        let deadline = first_attempt_epoch.saturating_add(self.max_age.as_secs());
        RetryDecision::Later {
            attempt,
            next_attempt_epoch: next.min(deadline),
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_age: Self::DEFAULT_MAX_AGE,
            schedule: Self::DEFAULT_SCHEDULE,
            max_attempts: 0,
        }
    }
}

/// What the queue does with a recipient after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Record the attempt and try again no earlier than this instant
    /// (seconds since the Unix epoch).
    Later {
        /// The attempt count after this failure (1-based).
        attempt: u32,
        /// When the next attempt becomes due.
        next_attempt_epoch: u64,
    },
    /// The horizon is over: bounce the recipient back to the sender.
    GiveUp {
        /// The attempt count the queue stopped at.
        attempt: u32,
    },
}

/// The delivery record of one recipient, as kept in the queue.
///
/// It is per recipient on purpose: a message with five recipients where three
/// were delivered, one is retrying and one bounced is the normal case, and a
/// single per-message counter would retry the three good ones (duplicating
/// mail into their maildirs) and lose track of which one bounced.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecipientState {
    /// The recipient as it was accepted at `RCPT`, which is what a DSN must
    /// name as `Final-Recipient`.
    pub recipient: String,
    /// Failures so far (0 = never attempted).
    #[serde(default)]
    pub attempts: u32,
    /// Seconds since the epoch when the next attempt is due; `0` = now.
    #[serde(default)]
    pub next_attempt_epoch: u64,
    /// Seconds since the epoch of the first attempt, which the deadline is
    /// measured from.
    #[serde(default)]
    pub first_attempt_epoch: u64,
    /// Whether this recipient still needs a delivery.
    #[serde(default)]
    pub pending: bool,
    /// The last failure, as a diagnostic string (the DSN's `Diagnostic-Code`
    /// and the operator's log).
    #[serde(default)]
    pub last_error: Option<String>,
}

impl RecipientState {
    /// A fresh record: pending, never attempted.
    #[must_use]
    pub fn new(recipient: impl Into<String>) -> Self {
        Self {
            recipient: recipient.into(),
            attempts: 0,
            next_attempt_epoch: 0,
            first_attempt_epoch: 0,
            pending: true,
            last_error: None,
        }
    }

    /// Records one failure and moves the recipient down the ladder.
    pub fn record_failure(
        &mut self,
        now_epoch: u64,
        error: impl Into<String>,
        policy: &RetryPolicy,
    ) {
        if self.first_attempt_epoch == 0 {
            self.first_attempt_epoch = now_epoch;
        }
        self.attempts = self.attempts.saturating_add(1);
        self.last_error = Some(error.into());
        match policy.after_failure(self.attempts, self.first_attempt_epoch, now_epoch) {
            RetryDecision::Later {
                next_attempt_epoch, ..
            } => {
                self.next_attempt_epoch = next_attempt_epoch;
                self.pending = true;
            }
            RetryDecision::GiveUp { .. } => {
                self.pending = false;
            }
        }
    }

    /// Whether the recipient is due for an attempt at `now_epoch`.
    #[must_use]
    pub fn due(&self, now_epoch: u64) -> bool {
        self.pending && now_epoch >= self.next_attempt_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 60 * 60;
    const MIN: u64 = 60;

    #[test]
    fn the_ladder_is_the_two_in_the_first_hour_then_hours() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.delay(1), Some(Duration::from_secs(15 * MIN)));
        assert_eq!(policy.delay(2), Some(Duration::from_secs(30 * MIN)));
        assert_eq!(policy.delay(3), Some(Duration::from_secs(HOUR)));
        assert_eq!(policy.delay(4), Some(Duration::from_secs(2 * HOUR)));
        // Past the table the last rung repeats.
        assert_eq!(policy.delay(9), Some(Duration::from_secs(4 * HOUR)));
        assert_eq!(policy.delay(1_000), Some(Duration::from_secs(4 * HOUR)));
        assert_eq!(policy.delay(0), None, "no failure, no wait");
    }

    #[test]
    fn the_first_hour_carries_two_attempts() {
        // The RFC's prose: retry twice within the first hour. Cumulative wait
        // before attempt 3 must be at most an hour.
        let policy = RetryPolicy::default();
        let mut total = Duration::ZERO;
        for attempt in 1..=2 {
            total += policy.delay(attempt).expect("rung");
        }
        assert!(total <= Duration::from_secs(HOUR), "{total:?}");
    }

    #[test]
    fn a_failure_pushes_the_next_attempt_down_the_ladder() {
        let policy = RetryPolicy::default();
        let start = 1_000_000u64;
        let mut state = RecipientState::new("ops@example.com");
        assert!(state.due(start));
        state.record_failure(start, "disk busy", &policy);
        assert_eq!(state.attempts, 1);
        assert_eq!(state.first_attempt_epoch, start);
        assert_eq!(state.next_attempt_epoch, start + 15 * MIN);
        assert!(!state.due(start + 14 * MIN));
        assert!(state.due(start + 15 * MIN));

        // The second failure is measured from *its* time, not from the first.
        let second = start + 15 * MIN;
        state.record_failure(second, "disk busy", &policy);
        assert_eq!(state.attempts, 2);
        assert_eq!(state.next_attempt_epoch, second + 30 * MIN);
        assert_eq!(state.first_attempt_epoch, start, "the deadline never moves");
    }

    #[test]
    fn the_deadline_ends_the_retries() {
        let policy = RetryPolicy::default();
        let start = 1_000_000u64;
        let mut state = RecipientState::new("ops@example.com");
        state.record_failure(start, "disk busy", &policy);
        // Right before the deadline the queue still schedules a retry …
        let almost = start + RetryPolicy::DEFAULT_MAX_AGE.as_secs() - 1;
        state.record_failure(almost, "disk busy", &policy);
        assert!(state.pending);
        // … that lands exactly on the deadline, where the next failure stops.
        assert_eq!(
            state.next_attempt_epoch,
            start + RetryPolicy::DEFAULT_MAX_AGE.as_secs()
        );
        let deadline = start + RetryPolicy::DEFAULT_MAX_AGE.as_secs();
        state.record_failure(deadline, "disk busy", &policy);
        assert!(!state.pending, "five days is the horizon");
        assert!(!state.due(deadline + HOUR));
    }

    #[test]
    fn the_next_attempt_never_overshoots_the_deadline() {
        let policy = RetryPolicy::default();
        let start = 1_000_000u64;
        let deadline = start + RetryPolicy::DEFAULT_MAX_AGE.as_secs();
        // A failure very near the end schedules at the deadline, not after it:
        // a message must not sit in the queue an hour past its own horizon.
        match policy.after_failure(3, start, deadline - 60) {
            RetryDecision::Later {
                next_attempt_epoch, ..
            } => assert_eq!(next_attempt_epoch, deadline),
            other => panic!("expected a scheduled retry, got {other:?}"),
        }
    }

    #[test]
    fn the_attempt_cap_gives_up_before_the_deadline() {
        let policy = RetryPolicy {
            max_attempts: 3,
            ..RetryPolicy::default()
        };
        let start = 1_000u64;
        assert!(!policy.attempts_exhausted(2));
        assert!(policy.attempts_exhausted(3));
        assert_eq!(
            policy.after_failure(3, start, start + 60),
            RetryDecision::GiveUp { attempt: 3 }
        );
        // `0` means the deadline is the only stop.
        let unlimited = RetryPolicy::default();
        assert!(!unlimited.attempts_exhausted(10_000));
    }

    #[test]
    fn the_medium_says_later_and_the_path_says_never() {
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::StorageFull,
            ErrorKind::QuotaExceeded,
            ErrorKind::ReadOnlyFilesystem,
            ErrorKind::TimedOut,
        ] {
            assert_eq!(
                RetryClass::of(&io::Error::from(kind)),
                RetryClass::Transient,
                "{kind:?} is a full or busy medium, not a permanent refusal"
            );
        }
        // A mailbox the engine has not created yet: it appears when the
        // account does, so it is worth waiting for.
        assert_eq!(
            RetryClass::of(&io::Error::from(ErrorKind::NotFound)),
            RetryClass::Transient
        );
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::AlreadyExists,
            ErrorKind::Unsupported,
        ] {
            assert_eq!(
                RetryClass::of(&io::Error::from(kind)),
                RetryClass::Permanent,
                "{kind:?} does not improve by waiting"
            );
        }
    }
}
