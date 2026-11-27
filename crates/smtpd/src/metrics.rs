//! Structured traffic counting: what the mail service did, as numbers.
//!
//! The control plane's 流量统计 page has to answer two questions — *who connects
//! to us*, and *where does our mail go* — and it used to answer them the way a
//! Postfix installation does: by parsing `postfix/smtpd[1]: connect from
//! unknown[203.0.113.9]` and `to=<a@b>, relay=mx.b:25, status=sent` out of a
//! log stream. That made the page a function of two things this service does
//! not own: the engine's log format, and whether anyone was still shipping
//! logs to it.
//!
//! This module is the replacement. [`Metrics`] is a set of atomics the layers
//! that already know an event happened increment as they handle it —
//! [`crate::server`] on every accepted connection and every answered
//! transaction, [`crate::deliver`] on every local delivery, every outbound
//! result and every bounce — and [`Metrics::snapshot`] turns them into the
//! report shape the page wants.
//!
//! ## Why atomics and not a queue
//!
//! Traffic is a counter, not an audit log: nothing reads an individual event
//! afterwards, and the page wants sums over a window. [`AtomicU64`] is what
//! makes "count this" free on the hot path (no lock, no allocation, no
//! channel), and a snapshot is a handful of relaxed loads that is allowed to
//! be *approximately* consistent — two counters read a microsecond apart can
//! describe one connection in one and not the other, and no reader cares.
//!
//! ## What the window means
//!
//! A window (`since`) is real for the series this counter keeps (the per-minute
//! ring below), and the snapshot reports what the window holds. Values are kept as a small
//! ring of fixed-width buckets — one per minute for the last day — so a
//! `24h` window is an exact sum over the buckets that are still inside it, and
//! a `72h` one is the sum of everything the ring still holds (which is the
//! whole ring, and that is reported honestly rather than padded: the
//! [`TrafficSnapshot::window_seconds`] field says how far back the answer
//! actually reaches).
//!
//! The buckets are indexed by wall clock (seconds since the epoch, divided by
//! [`BUCKET_SECONDS`]) rather than by a timer, so a process that is stopped and
//! restarted does not lose a day's history to a sleep it did not observe — a
//! bucket that has been overtaken is simply rewritten in place.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// How many seconds one traffic bucket covers.
///
/// One minute: fine enough that a 24-hour window is a real window rather than
/// "today", and coarse enough that the ring is 1 440 buckets — a few tens of
/// kilobytes, and rewritten in place rather than grown.
pub const BUCKET_SECONDS: u64 = 60;

/// How many buckets the ring keeps: one day of minutes.
///
/// A `24h` window fits exactly; a longer one (`72h`, `168h`) is answered from
/// everything the ring holds, and the snapshot says so. Keeping a week of
/// per-minute detail would be seven times the memory for a page that looks at
/// a day's worth of trend at most.
pub const BUCKETS: usize = 24 * 60;

/// Which of the counted events a bucket holds.
///
/// The names are the fields of [`TrafficSnapshot`] and of the two row types,
/// so an operator reading a snapshot can see which counter produced which
/// number. A `u8` so a bucket is a small `[u64; N]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Counter {
    /// An accepted inbound connection, from one peer address.
    Connects = 0,
    /// A message the listener queued (the transaction's final `250`).
    MessagesIn = 1,
    /// A recipient the listener accepted at `RCPT` (every recipient of a
    /// queued message is counted, once).
    RecipientsIn = 2,
    /// A `RCPT` the listener refused, for any reason.
    RecipientsRefused = 3,
    /// A message a local delivery wrote into a maildir.
    DeliveredLocal = 4,
    /// A recipient the outbound transport reported as delivered.
    OutboundSent = 5,
    /// A recipient the outbound transport deferred (or any transient local
    /// failure that will be retried).
    OutboundDeferred = 6,
    /// A recipient that ended in a bounce (permanent failure, or the retry
    /// horizon).
    OutboundBounced = 7,
}

impl Counter {
    /// Every counter, in the order a snapshot reports them.
    pub const ALL: [Self; 8] = [
        Self::Connects,
        Self::MessagesIn,
        Self::RecipientsIn,
        Self::RecipientsRefused,
        Self::DeliveredLocal,
        Self::OutboundSent,
        Self::OutboundDeferred,
        Self::OutboundBounced,
    ];

    /// The field name this counter is reported under.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Connects => "connects",
            Self::MessagesIn => "messages_in",
            Self::RecipientsIn => "recipients_in",
            Self::RecipientsRefused => "recipients_refused",
            Self::DeliveredLocal => "delivered_local",
            Self::OutboundSent => "outbound_sent",
            Self::OutboundDeferred => "outbound_deferred",
            Self::OutboundBounced => "outbound_bounced",
        }
    }
}

/// The number of counters, as an array length.
const COUNTERS: usize = Counter::ALL.len();

/// One row of the inbound table: a peer, and what it did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeerTraffic {
    /// The connecting address, as the socket named it (`203.0.113.9`).
    pub peer: String,
    /// Connections accepted from it in the window.
    pub connects: u64,
    /// Messages it got queued in the window.
    pub messages: u64,
    /// Recipients it got accepted in the window.
    pub recipients: u64,
    /// Recipients it was refused in the window.
    pub refused: u64,
}

/// One row of the outbound table: a destination domain, and what happened to
/// mail for it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DomainTraffic {
    /// The recipient domain the delivery was for.
    pub domain: String,
    /// Recipients a receiver accepted in the window.
    pub sent: u64,
    /// Recipients deferred in the window.
    pub deferred: u64,
    /// Recipients that ended in a bounce in the window.
    pub bounced: u64,
}

/// The totals over the window, as one row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct TrafficTotals {
    /// Accepted inbound connections.
    pub connects: u64,
    /// Messages queued by the listener.
    pub messages_in: u64,
    /// Recipients accepted at `RCPT`.
    pub recipients_in: u64,
    /// Recipients refused at `RCPT`.
    pub recipients_refused: u64,
    /// Messages written into a local maildir.
    pub delivered_local: u64,
    /// Recipients the outbound transport delivered.
    pub outbound_sent: u64,
    /// Recipients deferred.
    pub outbound_deferred: u64,
    /// Recipients bounced.
    pub outbound_bounced: u64,
}

/// The whole traffic report for one window.
///
/// `inbound` and `outbound` are the two tables the page draws. The rest is
/// what makes the report honest: how far back it actually reaches, which
/// counters are exact, and the totals a caller can show without summing rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct TrafficSnapshot {
    /// Seconds the window asked for.
    pub requested_seconds: u64,
    /// Seconds the answer actually covers — `min(requested, what the ring
    /// keeps)`, rounded down to the bucket grid.
    pub window_seconds: u64,
    /// Inbound peers in the window, busiest first.
    pub inbound: Vec<PeerTraffic>,
    /// Outbound destination domains in the window, busiest first.
    pub outbound: Vec<DomainTraffic>,
    /// Totals over the same window.
    pub totals: TrafficTotals,
}

/// One peer's per-minute history.
type PeerSeries = BTreeMap<u64, [u64; COUNTERS]>;

/// The traffic counters a running mail service keeps.
///
/// Shared by the listener, the delivery consumer and the control plane that
/// reports it: one `Arc<Metrics>` per process, passed to whichever layers a
/// deployment runs. A layer handed `None` counts nothing — which is what a
/// unit test that is not about traffic wants, and what the out-of-process
/// shapes (`ayane-smtpd --serve`) get when nobody is collecting.
#[derive(Debug)]
pub struct Metrics {
    /// Period totals of each counter (never reset; the ring is the window).
    totals: [AtomicU64; COUNTERS],
    /// The per-minute ring — only touched when a *series* (a per-peer or
    /// per-domain breakdown) is being recorded.
    ring: Mutex<Ring>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// A metrics set with nothing counted yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            totals: std::array::from_fn(|_| AtomicU64::new(0)),
            ring: Mutex::new(Ring::default()),
        }
    }

    /// Adds one to `counter`, without a series entry.
    ///
    /// This is the hot path — one relaxed `fetch_add` — and is what every
    /// counted event uses for its row-less totals.
    pub fn bump(&self, counter: Counter) {
        self.totals[counter as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `count` to `counter`.
    pub fn add(&self, counter: Counter, count: u64) {
        if count > 0 {
            self.totals[counter as usize].fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Records `count` of `counter` for one peer (a series entry).
    ///
    /// Called from the connection hot path, so the ring's lock is only taken
    /// once per *event* (not per octet) — a connection is accepted once and a
    /// transaction ends once, which is the rate the counter is for.
    pub fn record_peer(&self, peer: &str, counter: Counter, count: u64, now_epoch: u64) {
        if count == 0 {
            return;
        }
        self.add(counter, count);
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let series = ring.peers.entry(peer.to_owned()).or_default();
        let bucket = series.entry(bucket_of(now_epoch)).or_insert([0; COUNTERS]);
        bucket[counter as usize] = bucket[counter as usize].saturating_add(count);
        ring.trim(now_epoch);
    }

    /// Records `count` of `counter` for one destination domain (a series
    /// entry).
    pub fn record_domain(&self, domain: &str, counter: Counter, count: u64, now_epoch: u64) {
        if count == 0 {
            return;
        }
        self.add(counter, count);
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let series = ring.domains.entry(domain.to_owned()).or_default();
        let bucket = series.entry(bucket_of(now_epoch)).or_insert([0; COUNTERS]);
        bucket[counter as usize] = bucket[counter as usize].saturating_add(count);
        ring.trim(now_epoch);
    }

    /// The totals of every counter since the process started.
    #[must_use]
    pub fn total(&self, counter: Counter) -> u64 {
        self.totals[counter as usize].load(Ordering::Relaxed)
    }

    /// The report for a window ending now.
    #[must_use]
    pub fn snapshot(&self, now_epoch: u64, requested_seconds: u64) -> TrafficSnapshot {
        let window_seconds = requested_seconds
            .max(BUCKET_SECONDS)
            .min(BUCKET_SECONDS * BUCKETS as u64);
        let from = bucket_of(now_epoch.saturating_sub(window_seconds));
        let mut inbound: BTreeMap<String, [u64; COUNTERS]> = BTreeMap::new();
        let mut outbound: BTreeMap<String, [u64; COUNTERS]> = BTreeMap::new();
        let mut totals = TrafficTotals::default();
        {
            let ring = self
                .ring
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (peer, series) in &ring.peers {
                let mut sum = [0u64; COUNTERS];
                for (epoch, counts) in series {
                    if *epoch < from {
                        continue;
                    }
                    for (index, count) in counts.iter().enumerate() {
                        sum[index] = sum[index].saturating_add(*count);
                    }
                }
                if sum.iter().any(|count| *count > 0) {
                    inbound.insert(peer.clone(), sum);
                }
            }
            for (domain, series) in &ring.domains {
                let mut sum = [0u64; COUNTERS];
                for (epoch, counts) in series {
                    if *epoch < from {
                        continue;
                    }
                    for (index, count) in counts.iter().enumerate() {
                        sum[index] = sum[index].saturating_add(*count);
                    }
                }
                if sum.iter().any(|count| *count > 0) {
                    outbound.insert(domain.clone(), sum);
                }
            }
        }
        let mut inbound_rows: Vec<PeerTraffic> = inbound
            .into_iter()
            .map(|(peer, counts)| PeerTraffic {
                peer,
                connects: counts[Counter::Connects as usize],
                messages: counts[Counter::MessagesIn as usize],
                recipients: counts[Counter::RecipientsIn as usize],
                refused: counts[Counter::RecipientsRefused as usize],
            })
            .collect();
        inbound_rows.sort_by(|a, b| {
            (b.connects, b.messages)
                .cmp(&(a.connects, a.messages))
                .then(a.peer.cmp(&b.peer))
        });
        let mut outbound_rows: Vec<DomainTraffic> = outbound
            .into_iter()
            .map(|(domain, counts)| DomainTraffic {
                domain,
                sent: counts[Counter::OutboundSent as usize],
                deferred: counts[Counter::OutboundDeferred as usize],
                bounced: counts[Counter::OutboundBounced as usize],
            })
            .collect();
        outbound_rows.sort_by(|a, b| {
            (b.sent + b.deferred + b.bounced)
                .cmp(&(a.sent + a.deferred + a.bounced))
                .then(a.domain.cmp(&b.domain))
        });
        for row in &inbound_rows {
            totals.connects += row.connects;
            totals.messages_in += row.messages;
            totals.recipients_in += row.recipients;
            totals.recipients_refused += row.refused;
        }
        for row in &outbound_rows {
            totals.outbound_sent += row.sent;
            totals.outbound_deferred += row.deferred;
            totals.outbound_bounced += row.bounced;
        }
        // Local deliveries have no series (a mailbox is not a peer), so their
        // total is the counter's period total, which is what the page shows.
        totals.delivered_local = self.total(Counter::DeliveredLocal);
        TrafficSnapshot {
            requested_seconds,
            window_seconds,
            inbound: inbound_rows,
            outbound: outbound_rows,
            totals,
        }
    }
}

/// The delivery consumer's counters, installed as a
/// [`RemoteTransport`](crate::deliver::RemoteTransport) between the deliverer
/// and the transport it wraps.
///
/// Delivery counting has three of its four numbers outside the transport: a
/// maildir write, a quarantine and a bounce are [`RecipientOutcome`]s the
/// deliverer produces after it has already decided them, and nothing hands so
/// many as one event for the counters to see. The fourth — what a receiver did
/// with a message — is the transport's answer, which is exactly what a decorator
/// over [`crate::deliver::RemoteTransport::deliver_group`] sees.
///
/// Rather than thread a counter through every branch of `deliver.rs` (which
/// would put the counter's shape into a layer that has no traffic concept), the
/// one seam that already exists carries all four:
///
/// - the transport counts what each **receiver** said (`sent` / `deferred`),
///   keyed by the destination domain;
/// - [`MetricsDelivery::count_outcomes`] reads the reports the deliverer just
///   returned and counts, per [`RecipientOutcome`], the local delivery, the
///   bounce and the remaining deferral — the same information the control plane
///   would otherwise have to guess at from a log.
///
/// [`RecipientOutcome`]: crate::deliver::RecipientOutcome
#[derive(Clone)]
pub struct MetricsDelivery {
    metrics: std::sync::Arc<Metrics>,
    inner: std::sync::Arc<dyn crate::deliver::RemoteTransport>,
}

impl std::fmt::Debug for MetricsDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MetricsDelivery(..)")
    }
}

impl MetricsDelivery {
    /// Wraps `inner` so its answers are counted.
    #[must_use]
    pub fn new(
        metrics: std::sync::Arc<Metrics>,
        inner: std::sync::Arc<dyn crate::deliver::RemoteTransport>,
    ) -> Self {
        Self { metrics, inner }
    }

    /// The transport underneath.
    #[must_use]
    pub fn inner(&self) -> &std::sync::Arc<dyn crate::deliver::RemoteTransport> {
        &self.inner
    }
}

impl crate::deliver::RemoteTransport for MetricsDelivery {
    fn deliver_group(
        &self,
        request: &crate::deliver::RemoteRequest<'_>,
    ) -> std::io::Result<Vec<crate::deliver::RemoteReport>> {
        let reports = self.inner.deliver_group(request)?;
        let now = crate::server::received_now_epoch();
        for report in &reports {
            let counter = match report.reply {
                crate::deliver::RemoteReply::Delivered { .. } => Counter::OutboundSent,
                crate::deliver::RemoteReply::Deferred { .. } => Counter::OutboundDeferred,
                // A refusal is not a bounce yet: the deliverer decides, from
                // the retry policy and the reverse-path, whether it becomes a
                // DSN — so it is counted where that decision is made, by
                // [`MetricsDelivery::count_outcomes`].
                crate::deliver::RemoteReply::Refused { .. } => continue,
            };
            self.metrics.record_domain(request.domain, counter, 1, now);
        }
        Ok(reports)
    }
}

impl MetricsDelivery {
    /// Counts the outcomes the deliverer produced for one pass.
    ///
    /// Called with the reports [`crate::deliver::Deliverer::run`] returned:
    /// every terminal recipient is a local delivery or a bounce, and every
    /// waiting one that the transport did not already count is a deferral.
    /// The transport's own counts (sent / deferred) are not repeated here —
    /// `RecipientOutcome::Delivered(PathBuf::from("smtp://…"))` is how a
    /// remote success comes back, and it must count as `outbound_sent`, which
    /// the decorator above has already done.
    pub fn count_outcomes(metrics: &Metrics, reports: &[crate::deliver::DeliveryReport]) {
        let now = crate::server::received_now_epoch();
        for report in reports {
            for recipient in &report.recipients {
                match &recipient.outcome {
                    crate::deliver::RecipientOutcome::Delivered(path) => {
                        let remote = path.to_string_lossy().starts_with("smtp://");
                        if !remote {
                            metrics.bump(Counter::DeliveredLocal);
                        }
                    }
                    crate::deliver::RecipientOutcome::Bounced { .. } => {
                        let domain = recipient
                            .recipient
                            .rsplit_once('@')
                            .map_or_else(|| "-".to_owned(), |(_, domain)| domain.to_owned());
                        metrics.record_domain(&domain, Counter::OutboundBounced, 1, now);
                    }
                    crate::deliver::RecipientOutcome::Deferred { .. } => {
                        let domain = recipient
                            .recipient
                            .rsplit_once('@')
                            .map_or_else(|| "-".to_owned(), |(_, domain)| domain.to_owned());
                        metrics.record_domain(&domain, Counter::OutboundDeferred, 1, now);
                    }
                    crate::deliver::RecipientOutcome::Quarantined(_)
                    | crate::deliver::RecipientOutcome::Forwarded { .. }
                    | crate::deliver::RecipientOutcome::Remote
                    | crate::deliver::RecipientOutcome::Rejected(_) => {}
                }
            }
        }
    }
}

/// The bucket index a moment falls in: the start of its minute, in seconds.
fn bucket_of(now_epoch: u64) -> u64 {
    now_epoch / BUCKET_SECONDS * BUCKET_SECONDS
}

/// The per-minute series, with a bound on how many peers and domains they
/// keep.
#[derive(Debug, Default)]
struct Ring {
    peers: BTreeMap<String, PeerSeries>,
    domains: BTreeMap<String, PeerSeries>,
}

impl Ring {
    /// Drops series that have aged out of the ring, and evicts the least
    /// recently active series when the table is over [`MAX_SERIES`].
    ///
    /// The table is a public-facing counter fed by whoever connects, so it is
    /// bounded the same way [`crate::server::AuthGuard`] is: an address that
    /// stops connecting stops costing memory, and a table at its cap evicts
    /// the entry that has been quiet longest rather than growing without
    /// limit.
    fn trim(&mut self, now_epoch: u64) {
        let oldest = bucket_of(now_epoch).saturating_sub(BUCKET_SECONDS * BUCKETS as u64);
        fn prune(series: &mut PeerSeries, oldest: u64) {
            series.retain(|epoch, _| *epoch >= oldest);
        }
        self.peers.retain(|_, series| {
            prune(series, oldest);
            !series.is_empty()
        });
        self.domains.retain(|_, series| {
            prune(series, oldest);
            !series.is_empty()
        });
        evict_oldest(&mut self.peers);
        evict_oldest(&mut self.domains);
    }
}

/// How many rows one traffic series table keeps: 4 096 peers, and as many
/// destination domains.
pub const MAX_SERIES: usize = 4096;

/// Removes the quietest entries until the table is inside [`MAX_SERIES`].
fn evict_oldest(table: &mut BTreeMap<String, PeerSeries>) {
    while table.len() > MAX_SERIES {
        let victim = table
            .iter()
            .min_by_key(|(_, series)| series.keys().next_back().copied().unwrap_or(0))
            .map(|(name, _)| name.clone());
        match victim {
            Some(name) => {
                table.remove(&name);
            }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_add_up_and_a_snapshot_reports_them() {
        let metrics = Metrics::new();
        let now = 1_700_000_000u64;
        metrics.record_peer("203.0.113.9", Counter::Connects, 2, now);
        metrics.record_peer("203.0.113.9", Counter::MessagesIn, 1, now);
        metrics.record_peer("203.0.113.9", Counter::RecipientsIn, 3, now);
        metrics.record_peer("198.51.100.7", Counter::Connects, 1, now);
        metrics.record_peer("198.51.100.7", Counter::RecipientsRefused, 2, now);
        metrics.record_domain("dest.example", Counter::OutboundSent, 4, now);
        metrics.record_domain("dest.example", Counter::OutboundDeferred, 1, now);
        metrics.record_domain("other.example", Counter::OutboundBounced, 1, now);
        metrics.add(Counter::DeliveredLocal, 5);

        let snapshot = metrics.snapshot(now, 24 * 3600);
        assert_eq!(snapshot.requested_seconds, 24 * 3600);
        assert_eq!(snapshot.window_seconds, 24 * 3600);
        assert_eq!(snapshot.inbound.len(), 2);
        assert_eq!(snapshot.inbound[0].peer, "203.0.113.9", "busiest first");
        assert_eq!(snapshot.inbound[0].connects, 2);
        assert_eq!(snapshot.inbound[0].messages, 1);
        assert_eq!(snapshot.inbound[0].recipients, 3);
        assert_eq!(snapshot.inbound[1].refused, 2);
        assert_eq!(snapshot.outbound.len(), 2);
        assert_eq!(
            snapshot.outbound[0].domain, "dest.example",
            "busiest first (5 deliveries against 1)"
        );
        assert_eq!(snapshot.outbound[0].sent, 4);
        assert_eq!(snapshot.outbound[0].deferred, 1);
        assert_eq!(snapshot.outbound[1].domain, "other.example");
        assert_eq!(snapshot.outbound[1].bounced, 1);
        assert_eq!(snapshot.totals.connects, 3);
        assert_eq!(snapshot.totals.recipients_in, 3);
        assert_eq!(snapshot.totals.recipients_refused, 2);
        assert_eq!(snapshot.totals.delivered_local, 5);
        assert_eq!(snapshot.totals.outbound_sent, 4);
        assert_eq!(metrics.total(Counter::Connects), 3);
    }

    #[test]
    fn a_window_is_a_window() {
        let metrics = Metrics::new();
        let now = 1_700_000_000u64;
        // One minute ago and two hours ago, same peer.
        metrics.record_peer("203.0.113.9", Counter::Connects, 1, now - 60);
        metrics.record_peer("203.0.113.9", Counter::Connects, 1, now - 2 * 3600);
        let hour = metrics.snapshot(now, 3600);
        assert_eq!(hour.inbound[0].connects, 1, "only the last hour");
        let day = metrics.snapshot(now, 24 * 3600);
        assert_eq!(day.inbound[0].connects, 2, "both, inside a day");
        // A window longer than the ring is answered with what the ring holds,
        // and says so rather than pretending to reach further back.
        let week = metrics.snapshot(now, 7 * 24 * 3600);
        assert_eq!(week.requested_seconds, 7 * 24 * 3600);
        assert_eq!(week.window_seconds, BUCKET_SECONDS * BUCKETS as u64);
        assert_eq!(week.inbound[0].connects, 2);
    }

    #[test]
    fn a_bucket_is_rewritten_in_place_rather_than_grown() {
        let metrics = Metrics::new();
        let now = 1_700_000_000u64;
        // The same minute, twice: the ring must hold one bucket, not two.
        metrics.record_peer("203.0.113.9", Counter::Connects, 1, now);
        metrics.record_peer("203.0.113.9", Counter::Connects, 1, now + 1);
        let ring = metrics.ring.lock().expect("ring");
        let series = ring.peers.get("203.0.113.9").expect("series");
        assert_eq!(series.len(), 1, "{series:?}");
        assert_eq!(series.values().next().expect("bucket")[0], 2);
    }

    #[test]
    fn a_quiet_peer_ages_out_of_the_ring() {
        let metrics = Metrics::new();
        let now = 1_700_000_000u64;
        metrics.record_peer("203.0.113.9", Counter::Connects, 1, now);
        // A day and a minute later, the ring has moved past it: the snapshot
        // for that later moment does not invent a row for it.
        let later = now + 24 * 3600 + 60;
        metrics.record_peer("198.51.100.7", Counter::Connects, 1, later);
        let snapshot = metrics.snapshot(later, 3600);
        assert_eq!(snapshot.inbound.len(), 1, "{:?}", snapshot.inbound);
        assert_eq!(snapshot.inbound[0].peer, "198.51.100.7");
        // The period total never forgets, even though the window does.
        assert_eq!(metrics.total(Counter::Connects), 2);
    }

    #[test]
    fn the_series_tables_are_bounded() {
        let metrics = Metrics::new();
        let now = 1_700_000_000u64;
        for index in 0..(MAX_SERIES + 10) {
            metrics.record_peer(
                &format!("198.51.100.{index}"),
                Counter::Connects,
                1,
                now + index as u64,
            );
        }
        let ring = metrics.ring.lock().expect("ring");
        assert!(
            ring.peers.len() <= MAX_SERIES,
            "the peer table grew past its cap: {}",
            ring.peers.len()
        );
    }
}
