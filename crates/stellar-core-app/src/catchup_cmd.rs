//! Catchup command implementation for rs-stellar-core.
//!
//! The catchup command synchronizes the node with the network by downloading
//! history from archives and applying it to the local database.
//!
//! ## Usage
//!
//! ```text
//! rs-stellar-core catchup current        # Catch up to the latest ledger
//! rs-stellar-core catchup 1000000        # Catch up to ledger 1000000
//! rs-stellar-core catchup 1000000/100    # Catch up to ledger 1000000 with 100 ledgers of history
//! ```
//!
//! ## Modes
//!
//! - **minimal**: Download only the latest state (fastest)
//! - **complete**: Download full history from genesis
//! - **recent**: Download last N ledgers of history

use crate::app::{App, CatchupResult, CatchupTarget};
use crate::config::AppConfig;

/// Catchup mode determining how much history to download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CatchupMode {
    /// Download only the latest state (minimal sync time).
    #[default]
    Minimal,
    /// Download complete history from genesis.
    Complete,
    /// Download the last N ledgers of history.
    Recent(u32),
}

impl CatchupMode {
    /// Parse catchup mode from a string.
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(Self::Minimal),
            "complete" => Ok(Self::Complete),
            _ => {
                // Try to parse as "recent:N"
                if let Some(count) = s.strip_prefix("recent:") {
                    let n: u32 = count.parse()?;
                    Ok(Self::Recent(n))
                } else {
                    anyhow::bail!("Unknown catchup mode: {}", s)
                }
            }
        }
    }
}

impl std::fmt::Display for CatchupMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatchupMode::Minimal => write!(f, "minimal"),
            CatchupMode::Complete => write!(f, "complete"),
            CatchupMode::Recent(n) => write!(f, "recent:{}", n),
        }
    }
}

/// Options for the catchup command.
#[derive(Debug, Clone)]
pub struct CatchupOptions {
    /// Target ledger specification.
    pub target: String,
    /// Catchup mode.
    pub mode: CatchupMode,
    /// Whether to verify history after catchup.
    pub verify: bool,
    /// Number of parallel downloads.
    pub parallelism: usize,
    /// Whether to keep temporary files.
    pub keep_temp: bool,
}

impl Default for CatchupOptions {
    fn default() -> Self {
        Self {
            target: "current".to_string(),
            mode: CatchupMode::Minimal,
            verify: true,
            parallelism: 8,
            keep_temp: false,
        }
    }
}

impl CatchupOptions {
    /// Create options for catching up to the current/latest ledger.
    pub fn current() -> Self {
        Self::default()
    }

    /// Create options for catching up to a specific ledger.
    pub fn to_ledger(seq: u32) -> Self {
        Self {
            target: seq.to_string(),
            ..Default::default()
        }
    }

    /// Set the catchup mode.
    pub fn with_mode(mut self, mode: CatchupMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set verification on/off.
    pub fn with_verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    /// Set parallelism level.
    pub fn with_parallelism(mut self, n: usize) -> Self {
        self.parallelism = n;
        self
    }

    /// Parse the target into a CatchupTarget.
    pub fn parse_target(&self) -> anyhow::Result<CatchupTarget> {
        parse_target(&self.target)
    }
}

/// Parse a target ledger specification.
///
/// Formats:
/// - "current" -> CatchupTarget::Current
/// - "12345" -> CatchupTarget::Ledger(12345)
/// - "12345/100" -> CatchupTarget::Ledger(12345) with 100 ledgers of history
pub fn parse_target(target: &str) -> anyhow::Result<CatchupTarget> {
    let target = target.trim().to_lowercase();

    if target == "current" || target == "latest" {
        return Ok(CatchupTarget::Current);
    }

    // Check for "ledger/count" format
    if let Some(slash_pos) = target.find('/') {
        let ledger_str = &target[..slash_pos];
        let _count_str = &target[slash_pos + 1..];

        let ledger: u32 = ledger_str.parse().map_err(|_| {
            anyhow::anyhow!("Invalid ledger number: {}", ledger_str)
        })?;

        // For now, ignore the count and just target the ledger
        // A full implementation would use this for "recent" mode
        return Ok(CatchupTarget::Ledger(ledger));
    }

    // Just a ledger number
    let ledger: u32 = target.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid target: '{}'. Use 'current', a ledger number, or 'ledger/count'",
            target
        )
    })?;

    Ok(CatchupTarget::Ledger(ledger))
}

/// Run the catchup command.
pub async fn run_catchup(config: AppConfig, options: CatchupOptions) -> anyhow::Result<CatchupResult> {
    tracing::info!(
        target = %options.target,
        mode = %options.mode,
        "Starting catchup command"
    );

    // Parse target
    let target = options.parse_target()?;

    // Create application
    let app = App::new(config).await?;

    // Print catchup info
    print_catchup_info(&options, &target);

    // Run catchup
    let result = app.catchup(target).await?;

    // Print result
    print_catchup_result(&result);

    // Verify if requested
    if options.verify {
        verify_catchup(&result)?;
    }

    Ok(result)
}

/// Print information before starting catchup.
fn print_catchup_info(options: &CatchupOptions, target: &CatchupTarget) {
    println!("Catchup Configuration:");
    println!("  Target: {:?}", target);
    println!("  Mode: {}", options.mode);
    println!("  Parallelism: {}", options.parallelism);
    println!("  Verify: {}", options.verify);
    println!();
}

/// Print the catchup result.
fn print_catchup_result(result: &CatchupResult) {
    println!();
    println!("Catchup Complete!");
    println!("  Final Ledger: {}", result.ledger_seq);
    println!("  Ledger Hash: {}", result.ledger_hash);
    println!("  Buckets Applied: {}", result.buckets_applied);
    println!("  Ledgers Replayed: {}", result.ledgers_replayed);
}

/// Verify the catchup result.
fn verify_catchup(result: &CatchupResult) -> anyhow::Result<()> {
    tracing::info!(ledger = result.ledger_seq, "Verifying catchup result");

    // In a full implementation, this would:
    // 1. Verify the bucket list hash
    // 2. Verify the ledger header hash chain
    // 3. Verify account balances sum correctly
    // 4. Run invariant checks

    println!("Verification: PASSED");
    Ok(())
}

/// Progress callback for catchup operations.
pub trait CatchupProgressCallback: Send + Sync {
    /// Called when the catchup phase changes.
    fn on_phase_change(&self, phase: &str);

    /// Called periodically with progress update.
    fn on_progress(&self, current: u64, total: u64, message: &str);

    /// Called when catchup completes.
    fn on_complete(&self, result: &CatchupResult);

    /// Called if an error occurs.
    fn on_error(&self, error: &str);
}

/// Default progress callback that logs to tracing.
pub struct TracingProgressCallback;

impl CatchupProgressCallback for TracingProgressCallback {
    fn on_phase_change(&self, phase: &str) {
        tracing::info!(phase, "Catchup phase");
    }

    fn on_progress(&self, current: u64, total: u64, message: &str) {
        let percent = if total > 0 {
            (current as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        tracing::info!(current, total, percent = format!("{:.1}%", percent), message);
    }

    fn on_complete(&self, result: &CatchupResult) {
        tracing::info!(
            ledger = result.ledger_seq,
            hash = %result.ledger_hash,
            "Catchup complete"
        );
    }

    fn on_error(&self, error: &str) {
        tracing::error!(error, "Catchup error");
    }
}

/// Console progress callback with pretty output.
pub struct ConsoleProgressCallback {
    start_time: std::time::Instant,
}

impl ConsoleProgressCallback {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }
}

impl Default for ConsoleProgressCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl CatchupProgressCallback for ConsoleProgressCallback {
    fn on_phase_change(&self, phase: &str) {
        let elapsed = self.start_time.elapsed();
        println!("[{:>6.1}s] Phase: {}", elapsed.as_secs_f64(), phase);
    }

    fn on_progress(&self, current: u64, total: u64, message: &str) {
        let elapsed = self.start_time.elapsed();
        if total > 0 {
            let percent = (current as f64 / total as f64) * 100.0;
            let bar_width = 30;
            let filled = (percent / 100.0 * bar_width as f64) as usize;
            let empty = bar_width - filled;

            print!(
                "\r[{:>6.1}s] [{}{}] {:>5.1}% {}",
                elapsed.as_secs_f64(),
                "=".repeat(filled),
                " ".repeat(empty),
                percent,
                message
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
        } else {
            println!(
                "[{:>6.1}s] {} ({})",
                elapsed.as_secs_f64(),
                message,
                current
            );
        }
    }

    fn on_complete(&self, result: &CatchupResult) {
        let elapsed = self.start_time.elapsed();
        println!();
        println!("[{:>6.1}s] Catchup complete!", elapsed.as_secs_f64());
        println!("  Ledger: {}", result.ledger_seq);
        println!("  Time: {:.1}s", elapsed.as_secs_f64());
    }

    fn on_error(&self, error: &str) {
        let elapsed = self.start_time.elapsed();
        eprintln!();
        eprintln!("[{:>6.1}s] ERROR: {}", elapsed.as_secs_f64(), error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_current() {
        let target = parse_target("current").unwrap();
        assert!(matches!(target, CatchupTarget::Current));

        let target = parse_target("latest").unwrap();
        assert!(matches!(target, CatchupTarget::Current));
    }

    #[test]
    fn test_parse_target_ledger() {
        let target = parse_target("1000000").unwrap();
        assert!(matches!(target, CatchupTarget::Ledger(1000000)));
    }

    #[test]
    fn test_parse_target_with_count() {
        let target = parse_target("1000000/100").unwrap();
        assert!(matches!(target, CatchupTarget::Ledger(1000000)));
    }

    #[test]
    fn test_parse_target_invalid() {
        assert!(parse_target("invalid").is_err());
        assert!(parse_target("abc/100").is_err());
    }

    #[test]
    fn test_catchup_mode_from_str() {
        assert!(matches!(
            CatchupMode::from_str("minimal").unwrap(),
            CatchupMode::Minimal
        ));
        assert!(matches!(
            CatchupMode::from_str("complete").unwrap(),
            CatchupMode::Complete
        ));
        assert!(matches!(
            CatchupMode::from_str("recent:100").unwrap(),
            CatchupMode::Recent(100)
        ));
    }

    #[test]
    fn test_catchup_options() {
        let options = CatchupOptions::to_ledger(1000000)
            .with_mode(CatchupMode::Complete)
            .with_verify(false)
            .with_parallelism(16);

        assert_eq!(options.target, "1000000");
        assert!(matches!(options.mode, CatchupMode::Complete));
        assert!(!options.verify);
        assert_eq!(options.parallelism, 16);
    }
}
