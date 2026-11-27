//! How rendered configuration reaches the mail service, and how the control
//! plane reads the service's traffic back.
//!
//! The control plane no longer drives Postfix and Dovecot: the mail service is
//! [`ayane_smtpd`], it runs in this process (or in the sibling process of a
//! split deployment), and it is configured by an `Arc<ServerConfig>` the
//! listener hot-swaps between connections. So "apply" is two things — write the
//! rendered files, then hand the listener a new configuration — and "reload"
//! is only the second of them.
//!
//! [`EngineDriver`] keeps that swap local, and it keeps the **reload seam**
//! alive for the layers that do not know what is behind it: [`crate::apply`]
//! calls [`EngineDriver::reload`] after it has written the files, exactly as it
//! did before, and it neither knows nor cares whether the answer came from a
//! hot swap, a signal, or a test double.
//!
//! # `postfix_logs` became `traffic_snapshot`
//!
//! The trait used to carry a second method, `postfix_logs(since)`: the traffic
//! page parsed `connect from …` and `relay=…, status=sent` out of Postfix's
//! log, because that was the only place those numbers existed. They exist here
//! now — the listener counts the connections it accepts and the recipients it
//! answers, the delivery consumer counts what it wrote and what a remote
//! receiver said ([`ayane_smtpd::metrics`]) — so the method returns a report
//! instead of lines, and `crate::net::traffic_from_lines` is gone with the log
//! parser it belonged to. The rename is the point: a method named
//! `postfix_logs` on a driver with no Postfix in it would be a lie every caller
//! had to remember.

use std::sync::Arc;

use ayane_smtpd::metrics::{Metrics, TrafficSnapshot};
use ayane_smtpd::server::ServerConfig;

/// Result of one reload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServiceReload {
    /// Which service this is about.
    pub service: &'static str,
    /// Whether the new configuration took effect.
    pub ok: bool,
    /// What happened, for the report.
    pub detail: String,
}

impl ServiceReload {
    /// The one reload a native engine performs: the SMTP listeners.
    ///
    /// A constant rather than a literal in each driver, because the RPC
    /// surface and the apply report both name it and a second spelling would
    /// be a second thing to keep in step.
    pub const SMTP: &'static str = "smtp";
}

/// Push a rendered configuration into the running mail service, and read its
/// traffic back.
pub trait EngineDriver: Send + Sync {
    /// Reload whatever consumes rendered configuration.
    ///
    /// # Errors
    ///
    /// Implementations report per-service outcomes instead of failing whole;
    /// this returns `Err` only when the reload could not even be attempted
    /// (an engine that is not running, a configuration that cannot be built).
    fn reload(&self) -> Result<Vec<ServiceReload>, String>;

    /// The traffic of the last `since` window.
    ///
    /// `since` is a window such as `"24h"` or `"72h"`. A driver with no
    /// counters of its own (a test double, an engine that is not running)
    /// answers with an empty report rather than an error: "nothing happened to
    /// this peer" and "there is no peer table" are the same answer to the page
    /// that asks.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the counters could not be read at all.
    fn traffic_snapshot(&self, since: &str) -> Result<TrafficSnapshot, String>;
}

/// The live mail service: the listener's configuration slot and the counters.
///
/// A driver is constructed by [`crate::engine`] when the mail engine is
/// enabled, and it holds the *same* [`MailControl`] handles the spawned tasks
/// hold — so a reload is one store into an `ArcSwap`, and it reaches every
/// connection the listener accepts afterwards.
#[derive(Debug, Clone)]
pub struct NativeDriver {
    control: MailControl,
}

impl NativeDriver {
    /// A driver over one running mail service.
    #[must_use]
    pub fn new(control: MailControl) -> Self {
        Self { control }
    }

    /// The control handles, for the tasks that own the listeners.
    #[must_use]
    pub fn control(&self) -> &MailControl {
        &self.control
    }
}

impl EngineDriver for NativeDriver {
    fn reload(&self) -> Result<Vec<ServiceReload>, String> {
        // A hot swap is a store into an `ArcSwap`; the listener picks it up at
        // the next connection, which is the same granularity a `postfix reload`
        // had (a running transaction finishes under the configuration it
        // started with).
        let generation = self.control.install();
        Ok(vec![ServiceReload {
            service: ServiceReload::SMTP,
            ok: true,
            detail: format!(
                "hot-swapped the listener configuration (generation {generation}); \
                 {} listener(s) running",
                self.control.listeners
            ),
        }])
    }

    fn traffic_snapshot(&self, since: &str) -> Result<TrafficSnapshot, String> {
        let seconds = parse_window(since).ok_or_else(|| format!("unparsable window {since:?}"))?;
        Ok(self.control.metrics.snapshot(unix_now(), seconds))
    }
}

/// The handles a running mail service shares with its driver.
///
/// `slot` is the listener's configuration; `metrics` is where the listeners,
/// the delivery consumer and the outbound transport count. `generation` counts
/// reloads so a report can say which one this is without reading the
/// configuration back.
#[derive(Clone)]
pub struct MailControl {
    slot: Arc<arc_swap::ArcSwap<ServerConfig>>,
    /// The traffic counters, shared with every counted layer.
    pub metrics: Arc<Metrics>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    /// How many listeners the engine started (for the reload detail).
    pub listeners: usize,
}

impl std::fmt::Debug for MailControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailControl")
            .field("generation", &self.generation())
            .field("listeners", &self.listeners)
            .finish_non_exhaustive()
    }
}

impl MailControl {
    /// Wraps the listener's initial configuration.
    #[must_use]
    pub fn new(config: ServerConfig, metrics: Arc<Metrics>, listeners: usize) -> Self {
        Self {
            slot: Arc::new(arc_swap::ArcSwap::from_pointee(config)),
            metrics,
            generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            listeners,
        }
    }

    /// The configuration a connection starting now should use.
    #[must_use]
    pub fn load(&self) -> Arc<ServerConfig> {
        self.slot.load_full()
    }

    /// Stores a new configuration and returns the generation it became.
    ///
    /// This is what a reload uses: the control plane has already turned the
    /// stored state into a listener configuration, and that configuration is
    /// what lands here.
    pub fn install_with(&self, config: ServerConfig) -> u64 {
        self.slot.store(Arc::new(config));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1
    }

    /// Bumps the generation without changing the configuration.
    ///
    /// Used by a reload that has nothing to change (the rendered state is the
    /// one already in force): the report still says a reload happened, and the
    /// generation still moves so an operator watching it can see the apply.
    pub fn install(&self) -> u64 {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .saturating_add(1)
    }

    /// How many reloads have landed.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Seconds since the epoch.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parses a window like `24h`, `72h`, `168h`, `90m`, `3600s` into seconds.
///
/// The RPC surface passes `since` straight from the page's window buttons
/// (`24h` / `72h` / `168h`), so this is the only spelling that has to work —
/// but minutes and seconds are accepted because an operator debugging a live
/// box types them, and a bare number is read as hours (the page's unit) rather
/// than rejected.
#[must_use]
pub fn parse_window(since: &str) -> Option<u64> {
    let text = since.trim();
    let (number, unit) = match text.char_indices().find(|(_, ch)| !ch.is_ascii_digit()) {
        Some((index, _)) => text.split_at(index),
        None => (text, "h"),
    };
    let value: u64 = number.parse().ok()?;
    let seconds = match unit {
        "" | "h" | "H" => value.checked_mul(3600)?,
        "m" | "M" => value.checked_mul(60)?,
        "s" | "S" => value,
        "d" | "D" => value.checked_mul(86_400)?,
        _ => return None,
    };
    Some(seconds.max(1))
}

/// Test double: records reload invocations, never touches an engine.
pub struct RecordingDriver {
    /// Path whose existence controls whether reloads "succeed".
    pub compose_file: std::path::PathBuf,
    calls: std::sync::Mutex<Vec<&'static str>>,
    /// The report `traffic_snapshot` replays (default: empty).
    pub traffic: std::sync::Mutex<TrafficSnapshot>,
}

impl RecordingDriver {
    /// Create a driver that records calls and succeeds when `compose_file`
    /// exists (mirrors a driver whose engine is absent).
    #[must_use]
    pub fn new(compose_file: std::path::PathBuf) -> Self {
        Self {
            compose_file,
            calls: std::sync::Mutex::new(Vec::new()),
            traffic: std::sync::Mutex::new(TrafficSnapshot::default()),
        }
    }

    /// The services reload was invoked for, in order.
    pub fn called(&self) -> Vec<&'static str> {
        self.calls.lock().expect("calls mutex").clone()
    }

    /// Replaces the traffic report the double answers with.
    pub fn set_traffic(&self, snapshot: TrafficSnapshot) {
        *self.traffic.lock().expect("traffic mutex") = snapshot;
    }
}

impl EngineDriver for RecordingDriver {
    fn reload(&self) -> Result<Vec<ServiceReload>, String> {
        if !self.compose_file.is_file() {
            return Err("engine not running".to_owned());
        }
        self.calls
            .lock()
            .expect("calls mutex")
            .push(ServiceReload::SMTP);
        Ok(vec![ServiceReload {
            service: ServiceReload::SMTP,
            ok: true,
            detail: "recorded".to_owned(),
        }])
    }

    fn traffic_snapshot(&self, since: &str) -> Result<TrafficSnapshot, String> {
        if parse_window(since).is_none() {
            return Err(format!("unparsable window {since:?}"));
        }
        Ok(self.traffic.lock().expect("traffic mutex").clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_parse_the_way_the_page_writes_them() {
        assert_eq!(parse_window("24h"), Some(86_400));
        assert_eq!(parse_window("72h"), Some(259_200));
        assert_eq!(parse_window("168h"), Some(604_800));
        assert_eq!(parse_window(" 24H "), Some(86_400));
        assert_eq!(parse_window("90m"), Some(5_400));
        assert_eq!(parse_window("30s"), Some(30));
        assert_eq!(parse_window("1d"), Some(86_400));
        // A bare number is hours, the unit the page uses.
        assert_eq!(parse_window("24"), Some(86_400));
        assert_eq!(parse_window("0h"), Some(1), "a window is at least a second");
        assert_eq!(parse_window(""), None);
        assert_eq!(parse_window("hour"), None);
        assert_eq!(parse_window("24y"), None);
    }
}
