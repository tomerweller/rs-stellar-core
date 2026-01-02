//! Logging setup for rs-stellar-core.
//!
//! Configures tracing-subscriber with appropriate log levels and formats.
//! Supports both text and JSON output formats, and provides progress
//! reporting utilities for long-running operations like catchup.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable text format.
    #[default]
    Text,
    /// Structured JSON format.
    Json,
}

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: Level,
    /// Output format.
    pub format: LogFormat,
    /// Enable ANSI colors (for text format).
    pub ansi_colors: bool,
    /// Include source location in logs.
    pub with_source_location: bool,
    /// Include thread IDs in logs.
    pub with_thread_ids: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            format: LogFormat::Text,
            ansi_colors: true,
            with_source_location: false,
            with_thread_ids: false,
        }
    }
}

impl LogConfig {
    /// Create a verbose debug configuration.
    pub fn verbose() -> Self {
        Self {
            level: Level::DEBUG,
            format: LogFormat::Text,
            ansi_colors: true,
            with_source_location: true,
            with_thread_ids: true,
        }
    }

    /// Create a JSON logging configuration (for production).
    pub fn json() -> Self {
        Self {
            level: Level::INFO,
            format: LogFormat::Json,
            ansi_colors: false,
            with_source_location: true,
            with_thread_ids: true,
        }
    }

    /// Set the log level from a string.
    pub fn with_level(mut self, level: &str) -> Self {
        self.level = match level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" | "warning" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        };
        self
    }
}

/// Initialize the global logging subscriber.
///
/// This should be called once at application startup.
pub fn init(config: &LogConfig) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(config.level.as_str())
            .add_directive("hyper=warn".parse().unwrap())
            .add_directive("reqwest=warn".parse().unwrap())
            .add_directive("h2=warn".parse().unwrap())
    });

    match config.format {
        LogFormat::Text => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_ansi(config.ansi_colors)
                .with_target(true)
                .with_thread_ids(config.with_thread_ids)
                .with_file(config.with_source_location)
                .with_line_number(config.with_source_location);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
        LogFormat::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_span_list(true)
                .with_current_span(true);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    }

    Ok(())
}

/// Progress tracker for long-running operations.
///
/// Provides periodic progress updates with rate estimation.
#[derive(Debug)]
pub struct ProgressTracker {
    /// Description of the operation.
    name: String,
    /// Total number of items to process (if known).
    total: Option<u64>,
    /// Number of items processed so far.
    processed: AtomicU64,
    /// Start time of the operation.
    start_time: Instant,
    /// Last time progress was reported.
    last_report: std::sync::Mutex<Instant>,
    /// Minimum interval between reports.
    report_interval: Duration,
    /// Whether the operation has completed.
    completed: AtomicBool,
}

impl ProgressTracker {
    /// Create a new progress tracker.
    pub fn new(name: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            name: name.into(),
            total: None,
            processed: AtomicU64::new(0),
            start_time: now,
            last_report: std::sync::Mutex::new(now),
            report_interval: Duration::from_secs(5),
            completed: AtomicBool::new(false),
        }
    }

    /// Create a progress tracker with a known total.
    pub fn with_total(name: impl Into<String>, total: u64) -> Self {
        let mut tracker = Self::new(name);
        tracker.total = Some(total);
        tracker
    }

    /// Set the minimum interval between progress reports.
    pub fn with_report_interval(mut self, interval: Duration) -> Self {
        self.report_interval = interval;
        self
    }

    /// Increment the processed count by one.
    pub fn inc(&self) {
        self.inc_by(1);
    }

    /// Increment the processed count by a given amount.
    pub fn inc_by(&self, n: u64) {
        let processed = self.processed.fetch_add(n, Ordering::Relaxed) + n;
        self.maybe_report(processed);
    }

    /// Set the processed count directly.
    pub fn set(&self, n: u64) {
        self.processed.store(n, Ordering::Relaxed);
        self.maybe_report(n);
    }

    /// Get the current processed count.
    pub fn processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    /// Mark the operation as complete.
    pub fn complete(&self) {
        self.completed.store(true, Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        let processed = self.processed.load(Ordering::Relaxed);

        if let Some(total) = self.total {
            tracing::info!(
                name = %self.name,
                processed = processed,
                total = total,
                elapsed_secs = elapsed.as_secs_f64(),
                "Operation completed"
            );
        } else {
            tracing::info!(
                name = %self.name,
                processed = processed,
                elapsed_secs = elapsed.as_secs_f64(),
                "Operation completed"
            );
        }
    }

    /// Report progress if enough time has elapsed.
    fn maybe_report(&self, processed: u64) {
        let mut last_report = self.last_report.lock().unwrap();
        let now = Instant::now();

        if now.duration_since(*last_report) >= self.report_interval {
            *last_report = now;
            drop(last_report);

            let elapsed = self.start_time.elapsed();
            let rate = if elapsed.as_secs_f64() > 0.0 {
                processed as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            if let Some(total) = self.total {
                let percent = (processed as f64 / total as f64) * 100.0;
                let eta_secs = if rate > 0.0 {
                    (total - processed) as f64 / rate
                } else {
                    0.0
                };

                tracing::info!(
                    name = %self.name,
                    processed = processed,
                    total = total,
                    percent = format!("{:.1}%", percent),
                    rate = format!("{:.1}/s", rate),
                    eta_secs = format!("{:.0}s", eta_secs),
                    "Progress"
                );
            } else {
                tracing::info!(
                    name = %self.name,
                    processed = processed,
                    rate = format!("{:.1}/s", rate),
                    "Progress"
                );
            }
        }
    }
}

/// Progress tracker for catchup operations.
#[derive(Debug)]
pub struct CatchupProgress {
    /// Current phase of catchup.
    phase: std::sync::Mutex<CatchupPhase>,
    /// Ledgers downloaded.
    ledgers_downloaded: AtomicU32,
    /// Ledgers applied.
    ledgers_applied: AtomicU32,
    /// Buckets downloaded.
    buckets_downloaded: AtomicU32,
    /// Total buckets to download.
    total_buckets: AtomicU32,
    /// Target ledger sequence.
    target_ledger: AtomicU32,
    /// Start time.
    start_time: Instant,
}

/// Phase of the catchup operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupPhase {
    /// Initializing catchup.
    Initializing,
    /// Downloading history archive state.
    DownloadingState,
    /// Downloading buckets.
    DownloadingBuckets,
    /// Applying buckets to ledger state.
    ApplyingBuckets,
    /// Downloading ledger headers and transactions.
    DownloadingLedgers,
    /// Replaying transactions.
    ReplayingLedgers,
    /// Verifying final state.
    Verifying,
    /// Catchup complete.
    Complete,
}

impl std::fmt::Display for CatchupPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatchupPhase::Initializing => write!(f, "Initializing"),
            CatchupPhase::DownloadingState => write!(f, "Downloading state"),
            CatchupPhase::DownloadingBuckets => write!(f, "Downloading buckets"),
            CatchupPhase::ApplyingBuckets => write!(f, "Applying buckets"),
            CatchupPhase::DownloadingLedgers => write!(f, "Downloading ledgers"),
            CatchupPhase::ReplayingLedgers => write!(f, "Replaying ledgers"),
            CatchupPhase::Verifying => write!(f, "Verifying"),
            CatchupPhase::Complete => write!(f, "Complete"),
        }
    }
}

impl CatchupProgress {
    /// Create a new catchup progress tracker.
    pub fn new() -> Self {
        Self {
            phase: std::sync::Mutex::new(CatchupPhase::Initializing),
            ledgers_downloaded: AtomicU32::new(0),
            ledgers_applied: AtomicU32::new(0),
            buckets_downloaded: AtomicU32::new(0),
            total_buckets: AtomicU32::new(0),
            target_ledger: AtomicU32::new(0),
            start_time: Instant::now(),
        }
    }

    /// Set the target ledger.
    pub fn set_target(&self, ledger: u32) {
        self.target_ledger.store(ledger, Ordering::Relaxed);
    }

    /// Set the total number of buckets to download.
    pub fn set_total_buckets(&self, count: u32) {
        self.total_buckets.store(count, Ordering::Relaxed);
    }

    /// Set the current phase.
    pub fn set_phase(&self, phase: CatchupPhase) {
        let mut current = self.phase.lock().unwrap();
        if *current != phase {
            tracing::info!(
                phase = %phase,
                target_ledger = self.target_ledger.load(Ordering::Relaxed),
                "Catchup phase changed"
            );
            *current = phase;
        }
    }

    /// Get the current phase.
    pub fn phase(&self) -> CatchupPhase {
        *self.phase.lock().unwrap()
    }

    /// Record a ledger download.
    pub fn ledger_downloaded(&self) {
        self.ledgers_downloaded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a ledger applied.
    pub fn ledger_applied(&self) {
        let applied = self.ledgers_applied.fetch_add(1, Ordering::Relaxed) + 1;
        if applied % 100 == 0 {
            let target = self.target_ledger.load(Ordering::Relaxed);
            tracing::info!(
                applied = applied,
                target = target,
                "Applied ledgers"
            );
        }
    }

    /// Record a bucket download.
    pub fn bucket_downloaded(&self) {
        let downloaded = self.buckets_downloaded.fetch_add(1, Ordering::Relaxed) + 1;
        let total = self.total_buckets.load(Ordering::Relaxed);
        if total > 0 && (downloaded % 10 == 0 || downloaded == total) {
            tracing::info!(
                downloaded = downloaded,
                total = total,
                percent = format!("{:.1}%", downloaded as f64 / total as f64 * 100.0),
                "Downloaded buckets"
            );
        }
    }

    /// Print a summary of the catchup.
    pub fn summary(&self) {
        let elapsed = self.start_time.elapsed();
        let applied = self.ledgers_applied.load(Ordering::Relaxed);
        let buckets = self.buckets_downloaded.load(Ordering::Relaxed);
        let target = self.target_ledger.load(Ordering::Relaxed);

        tracing::info!(
            target_ledger = target,
            ledgers_applied = applied,
            buckets_downloaded = buckets,
            elapsed_secs = elapsed.as_secs_f64(),
            "Catchup summary"
        );
    }
}

impl Default for CatchupProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Create an Arc-wrapped catchup progress tracker.
pub fn catchup_progress() -> Arc<CatchupProgress> {
    Arc::new(CatchupProgress::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_tracker() {
        let tracker = ProgressTracker::with_total("test", 100)
            .with_report_interval(Duration::from_millis(1));

        assert_eq!(tracker.processed(), 0);

        tracker.inc();
        assert_eq!(tracker.processed(), 1);

        tracker.inc_by(10);
        assert_eq!(tracker.processed(), 11);

        tracker.set(50);
        assert_eq!(tracker.processed(), 50);
    }

    #[test]
    fn test_catchup_phase_display() {
        assert_eq!(format!("{}", CatchupPhase::Initializing), "Initializing");
        assert_eq!(
            format!("{}", CatchupPhase::DownloadingBuckets),
            "Downloading buckets"
        );
    }
}
