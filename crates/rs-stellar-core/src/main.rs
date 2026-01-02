//! rs-stellar-core - Pure Rust implementation of Stellar Core
//!
//! This binary provides a command-line interface for running a Stellar Core
//! validator node, catching up from history archives, and performing other
//! Stellar network operations.
//!
//! ## Usage
//!
//! ```text
//! rs-stellar-core run                     # Run the node
//! rs-stellar-core catchup current         # Catch up to latest ledger
//! rs-stellar-core catchup 1000000         # Catch up to specific ledger
//! rs-stellar-core new-db                  # Create a new database
//! rs-stellar-core info                    # Print node information
//! ```
//!
//! ## Configuration
//!
//! Configuration can be provided via a TOML file or environment variables.
//! See `rs-stellar-core --help` for more details.

mod quorum_intersection;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use stellar_xdr::curr::WriteXdr;

use stellar_core_app::{
    App,
    AppConfig,
    CatchupMode as CatchupModeInternal,
    CatchupOptions,
    LogConfig,
    LogFormat,
    RunMode,
    RunOptions,
    run_catchup,
    run_node,
    logging,
};

/// Pure Rust implementation of Stellar Core
#[derive(Parser)]
#[command(name = "rs-stellar-core")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Enable verbose logging (debug level)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable trace logging (most verbose)
    #[arg(long, global = true)]
    trace: bool,

    /// Log output format
    #[arg(long, default_value = "text", global = true)]
    log_format: CliLogFormat,

    /// Use testnet configuration (default)
    #[arg(long, global = true)]
    testnet: bool,

    /// Use mainnet configuration
    #[arg(long, global = true)]
    mainnet: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Log output format for CLI
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum CliLogFormat {
    #[default]
    Text,
    Json,
}

impl From<CliLogFormat> for LogFormat {
    fn from(fmt: CliLogFormat) -> Self {
        match fmt {
            CliLogFormat::Text => LogFormat::Text,
            CliLogFormat::Json => LogFormat::Json,
        }
    }
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Run the Stellar Core node
    Run {
        /// Run in validator mode (participate in consensus)
        #[arg(long)]
        validator: bool,

        /// Run in watcher mode (observe only, no catchup)
        #[arg(long)]
        watcher: bool,

        /// Force catchup even if state exists
        #[arg(long)]
        force_catchup: bool,
    },

    /// Catch up from history archives
    Catchup {
        /// Target ledger: "current", a ledger number, or "ledger/count"
        #[arg(value_name = "TARGET", default_value = "current")]
        target: String,

        /// Catchup mode: minimal, complete, or recent:N
        #[arg(long, default_value = "minimal")]
        mode: CliCatchupMode,

        /// Skip verification after catchup
        #[arg(long)]
        no_verify: bool,

        /// Number of parallel downloads
        #[arg(long, default_value = "8")]
        parallelism: usize,
    },

    /// Create a new database
    NewDb {
        /// Path to the database file (overrides config)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Force creation even if database exists
        #[arg(long)]
        force: bool,
    },

    /// Upgrade database schema
    UpgradeDb,

    /// Generate a new node keypair
    NewKeypair,

    /// Print node information
    Info,

    /// Verify history archives
    VerifyHistory {
        /// Start ledger sequence
        #[arg(long)]
        from: Option<u32>,

        /// End ledger sequence
        #[arg(long)]
        to: Option<u32>,
    },

    /// Publish history to archives (validators only)
    PublishHistory {
        /// Force republishing of existing checkpoints
        #[arg(long)]
        force: bool,
    },

    /// Check quorum intersection from a JSON file
    CheckQuorumIntersection {
        /// Path to the JSON file
        path: PathBuf,
    },

    /// Print sample configuration
    SampleConfig,

    /// Offline commands (no network required)
    #[command(subcommand)]
    Offline(OfflineCommands),
}

/// Catchup mode for CLI
#[derive(Clone, Debug, Default, clap::ValueEnum)]
enum CliCatchupMode {
    /// Download only the latest state
    #[default]
    Minimal,
    /// Download complete history from genesis
    Complete,
    /// Download recent history only (use --recent-count to specify)
    Recent,
}

/// Offline commands that don't require network access
#[derive(Subcommand)]
enum OfflineCommands {
    /// Convert Stellar keys between formats
    ConvertKey {
        /// The key to convert
        key: String,
    },

    /// Decode an XDR value
    DecodeXdr {
        /// XDR type name
        #[arg(long, value_name = "TYPE")]
        r#type: String,

        /// Base64-encoded XDR
        value: String,
    },

    /// Encode a value to XDR
    EncodeXdr {
        /// XDR type name
        #[arg(long, value_name = "TYPE")]
        r#type: String,

        /// JSON value to encode
        value: String,
    },

    /// Print bucket list information
    BucketInfo {
        /// Path to bucket directory
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli)?;

    // Load or create configuration
    let config = load_config(&cli)?;

    // Execute command
    match cli.command {
        Commands::Run {
            validator,
            watcher,
            force_catchup,
        } => cmd_run(config, validator, watcher, force_catchup).await,

        Commands::Catchup {
            target,
            mode,
            no_verify,
            parallelism,
        } => cmd_catchup(config, target, mode, !no_verify, parallelism).await,

        Commands::NewDb { path, force } => cmd_new_db(config, path, force).await,

        Commands::UpgradeDb => cmd_upgrade_db(config).await,

        Commands::NewKeypair => cmd_new_keypair(),

        Commands::Info => cmd_info(config).await,

        Commands::VerifyHistory { from, to } => cmd_verify_history(config, from, to).await,

        Commands::PublishHistory { force } => cmd_publish_history(config, force).await,

        Commands::CheckQuorumIntersection { path } => cmd_check_quorum_intersection(&path),

        Commands::SampleConfig => cmd_sample_config(),

        Commands::Offline(cmd) => cmd_offline(cmd),
    }
}

/// Initialize the logging subsystem.
fn init_logging(cli: &Cli) -> anyhow::Result<()> {
    let level = if cli.trace {
        "trace"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    let config = LogConfig::default()
        .with_level(level);

    let config = match cli.log_format {
        CliLogFormat::Text => config,
        CliLogFormat::Json => LogConfig {
            format: LogFormat::Json,
            ansi_colors: false,
            ..config
        },
    };

    logging::init(&config)?;

    tracing::debug!("Logging initialized");
    Ok(())
}

/// Load configuration from file or use defaults.
fn load_config(cli: &Cli) -> anyhow::Result<AppConfig> {
    let config = if let Some(ref config_path) = cli.config {
        tracing::info!(path = ?config_path, "Loading configuration from file");
        AppConfig::from_file_with_env(config_path)?
    } else if cli.mainnet {
        tracing::info!("Using mainnet configuration");
        let mut config = AppConfig::mainnet();
        config.apply_env_overrides();
        config
    } else {
        tracing::info!("Using testnet configuration (default)");
        let mut config = AppConfig::testnet();
        config.apply_env_overrides();
        config
    };

    Ok(config)
}

/// Run command handler.
async fn cmd_run(
    config: AppConfig,
    validator: bool,
    watcher: bool,
    force_catchup: bool,
) -> anyhow::Result<()> {
    if validator && watcher {
        anyhow::bail!("Cannot run as both validator and watcher");
    }

    let mode = if validator {
        RunMode::Validator
    } else if watcher {
        RunMode::Watcher
    } else {
        RunMode::Full
    };

    let options = RunOptions {
        mode,
        force_catchup,
        ..Default::default()
    };

    run_node(config, options).await
}

/// Catchup command handler.
async fn cmd_catchup(
    config: AppConfig,
    target: String,
    mode: CliCatchupMode,
    verify: bool,
    parallelism: usize,
) -> anyhow::Result<()> {
    let mode = match mode {
        CliCatchupMode::Minimal => CatchupModeInternal::Minimal,
        CliCatchupMode::Complete => CatchupModeInternal::Complete,
        CliCatchupMode::Recent => CatchupModeInternal::Recent(1000), // Default to 1000 ledgers
    };

    let options = CatchupOptions {
        target,
        mode,
        verify,
        parallelism,
        keep_temp: false,
    };

    let result = run_catchup(config, options).await?;
    println!("{}", result);
    Ok(())
}

/// New database command handler.
async fn cmd_new_db(
    mut config: AppConfig,
    path: Option<PathBuf>,
    force: bool,
) -> anyhow::Result<()> {
    // Override path if provided
    if let Some(p) = path {
        config.database.path = p;
    }

    let db_path = &config.database.path;

    // Check if database already exists
    if db_path.exists() {
        if force {
            tracing::warn!(path = ?db_path, "Removing existing database");
            std::fs::remove_file(db_path)?;
        } else {
            anyhow::bail!(
                "Database already exists at {:?}. Use --force to overwrite.",
                db_path
            );
        }
    }

    tracing::info!(path = ?db_path, "Creating new database");

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Create the database
    let _db = stellar_core_db::Database::open(db_path)?;

    println!("Database created successfully at: {}", db_path.display());
    Ok(())
}

/// Upgrade database command handler.
async fn cmd_upgrade_db(config: AppConfig) -> anyhow::Result<()> {
    tracing::info!(path = ?config.database.path, "Upgrading database schema");

    let db = stellar_core_db::Database::open(&config.database.path)?;

    // Database initialization already applies the latest schema
    // In a full implementation, this would run migrations

    println!("Database schema is up to date");
    Ok(())
}

/// Generate keypair command handler.
fn cmd_new_keypair() -> anyhow::Result<()> {
    let keypair = stellar_core_crypto::SecretKey::generate();

    println!("Generated new keypair:");
    println!();
    println!("Public Key:  {}", keypair.public_key().to_strkey());
    println!("Secret Seed: {}", keypair.to_strkey());
    println!();
    println!("IMPORTANT: Store the secret seed securely! It cannot be recovered.");

    Ok(())
}

/// Info command handler.
async fn cmd_info(config: AppConfig) -> anyhow::Result<()> {
    // Try to create app to get full info, or show basic info if that fails
    match App::new(config.clone()).await {
        Ok(app) => {
            let info = app.info();
            print!("{}", info);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Could not initialize app, showing basic info");

            println!("rs-stellar-core {}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Configuration:");
            println!("  Network: {}", config.network.passphrase);
            println!("  Database: {}", config.database.path.display());
            println!("  Validator: {}", config.node.is_validator);
            println!();

            if !config.database.path.exists() {
                println!("Note: Database does not exist. Run 'new-db' to create it.");
            }
        }
    }

    Ok(())
}

/// Verify history command handler.
async fn cmd_verify_history(
    config: AppConfig,
    from: Option<u32>,
    to: Option<u32>,
) -> anyhow::Result<()> {
    use stellar_core_history::{HistoryArchive, verify};
    use stellar_core_ledger::TransactionSetVariant;

    println!("Verifying history archives...");
    println!();

    // Create archive clients from config
    let archives: Vec<HistoryArchive> = config.history.archives
        .iter()
        .filter(|a| a.get_enabled)
        .filter_map(|a| {
            match HistoryArchive::new(&a.url) {
                Ok(archive) => Some(archive),
                Err(e) => {
                    println!("Warning: Failed to create archive {}: {}", a.url, e);
                    None
                }
            }
        })
        .collect();

    if archives.is_empty() {
        anyhow::bail!("No history archives available");
    }

    println!("Using {} archive(s)", archives.len());

    // Get the range to verify
    let archive = &archives[0];
    let root_has = archive.get_root_has().await?;
    let current_ledger = root_has.current_ledger;

    let start = from.unwrap_or(1);
    let end = to.unwrap_or(current_ledger);

    println!("Verifying ledger range: {} to {}", start, end);
    println!();

    // Verify in checkpoint intervals (64 ledgers)
    let mut verified_count = 0;
    let mut error_count = 0;

    // Calculate checkpoint-aligned start
    let start_checkpoint = stellar_core_history::checkpoint::checkpoint_containing(start);
    let end_checkpoint = stellar_core_history::checkpoint::checkpoint_containing(end);

    let mut checkpoint = start_checkpoint;
    while checkpoint <= end_checkpoint {
        // Get checkpoint HAS (History Archive State)
        match archive.get_checkpoint_has(checkpoint).await {
            Ok(has) => {
                // Verify the HAS structure
                match verify::verify_has_structure(&has) {
                    Ok(()) => {
                        // Verify checkpoint matches
                        match verify::verify_has_checkpoint(&has, checkpoint) {
                            Ok(()) => {
                                println!("  Checkpoint {}: OK", checkpoint);
                                verified_count += 1;
                            }
                            Err(e) => {
                                println!("  Checkpoint {}: FAIL - {}", checkpoint, e);
                                error_count += 1;
                            }
                        }
                    }
                    Err(e) => {
                        println!("  Checkpoint {}: FAIL (invalid structure) - {}", checkpoint, e);
                        error_count += 1;
                    }
                }

                // Get and verify ledger headers for this checkpoint range
                match archive.get_ledger_headers(checkpoint).await {
                    Ok(history_entries) => {
                        // Extract LedgerHeader from LedgerHeaderHistoryEntry
                        let headers: Vec<stellar_xdr::curr::LedgerHeader> = history_entries
                            .iter()
                            .map(|entry| entry.header.clone())
                            .collect();
                        if let Err(e) = verify::verify_header_chain(&headers) {
                            println!("    Header chain verification FAILED: {}", e);
                            error_count += 1;
                        }

                        match archive.get_transactions(checkpoint).await {
                            Ok(tx_entries) => {
                                match archive.get_results(checkpoint).await {
                                    Ok(tx_results) => {
                                        let tx_map = tx_entries
                                            .iter()
                                            .map(|entry| (entry.ledger_seq, entry))
                                            .collect::<std::collections::HashMap<_, _>>();
                                        let result_map = tx_results
                                            .iter()
                                            .map(|entry| (entry.ledger_seq, entry))
                                            .collect::<std::collections::HashMap<_, _>>();

                                        for header in &headers {
                                            let Some(tx_entry) = tx_map.get(&header.ledger_seq) else {
                                                println!(
                                                    "    Missing transaction history entry for ledger {}",
                                                    header.ledger_seq
                                                );
                                                error_count += 1;
                                                continue;
                                            };
                                            let Some(result_entry) = result_map.get(&header.ledger_seq) else {
                                                println!(
                                                    "    Missing transaction result entry for ledger {}",
                                                    header.ledger_seq
                                                );
                                                error_count += 1;
                                                continue;
                                            };

                                            let tx_set = match &tx_entry.ext {
                                                stellar_xdr::curr::TransactionHistoryEntryExt::V1(generalized) => {
                                                    TransactionSetVariant::Generalized(generalized.clone())
                                                }
                                                stellar_xdr::curr::TransactionHistoryEntryExt::V0 => {
                                                    TransactionSetVariant::Classic(tx_entry.tx_set.clone())
                                                }
                                            };
                                            if let Err(e) = verify::verify_tx_set(header, &tx_set) {
                                                println!(
                                                    "    Tx set hash verification FAILED (ledger {}): {}",
                                                    header.ledger_seq, e
                                                );
                                                error_count += 1;
                                            }

                                            let result_xdr = result_entry
                                                .tx_result_set
                                                .to_xdr(stellar_xdr::curr::Limits::none());
                                            match result_xdr {
                                                Ok(bytes) => {
                                                    if let Err(e) = verify::verify_tx_result_set(header, &bytes) {
                                                        println!(
                                                            "    Tx result hash verification FAILED (ledger {}): {}",
                                                            header.ledger_seq, e
                                                        );
                                                        error_count += 1;
                                                    }
                                                }
                                                Err(e) => {
                                                    println!(
                                                        "    Failed to encode tx result set for ledger {}: {}",
                                                        header.ledger_seq, e
                                                    );
                                                    error_count += 1;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        println!("    Warning: Could not verify tx results: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("    Warning: Could not verify transactions: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("    Warning: Could not verify headers: {}", e);
                    }
                }

                match archive.get_scp_history(checkpoint).await {
                    Ok(entries) => {
                        if let Err(e) = verify::verify_scp_history_entries(&entries) {
                            println!("    SCP history verification FAILED: {}", e);
                            error_count += 1;
                        }
                    }
                    Err(e) => {
                        println!("    Warning: Could not verify SCP history: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("  Checkpoint {}: ERROR - {}", checkpoint, e);
                error_count += 1;
            }
        }

        // Move to next checkpoint
        checkpoint = stellar_core_history::checkpoint::next_checkpoint(checkpoint);
    }

    println!();
    println!("Verification complete:");
    println!("  Checkpoints verified: {}", verified_count);
    println!("  Errors: {}", error_count);

    if error_count > 0 {
        anyhow::bail!("Verification failed with {} errors", error_count);
    }

    Ok(())
}

/// Publish history command handler.
async fn cmd_publish_history(config: AppConfig, force: bool) -> anyhow::Result<()> {
    use stellar_core_bucket::{BucketList, BucketManager};
    use stellar_core_history::archive_state::HistoryArchiveState;
    use stellar_core_history::checkpoint::{checkpoint_containing, next_checkpoint};
    use stellar_core_history::paths::root_has_path;
    use stellar_core_history::publish::{build_history_archive_state, PublishConfig, PublishManager};
    use stellar_core_history::verify;
    use stellar_core_history::CHECKPOINT_FREQUENCY;
    use stellar_core_ledger::compute_header_hash;
    use stellar_core_ledger::TransactionSetVariant;
    use stellar_core_common::Hash256;
    use std::fs;
    use std::path::PathBuf;
    use url::Url;
    use stellar_xdr::curr::TransactionHistoryEntryExt;

    if !config.node.is_validator {
        anyhow::bail!("Only validators can publish history");
    }

    println!("Publishing history to archives...");
    println!();

    // Check for writable archives
    let writable_archives: Vec<_> = config
        .history
        .archives
        .iter()
        .filter(|a| a.put_enabled)
        .collect();

    if writable_archives.is_empty() {
        anyhow::bail!("No writable history archives configured. Add 'put = true' to an archive config.");
    }

    let mut local_targets = Vec::new();
    let mut command_targets = Vec::new();
    for archive in &writable_archives {
        if let Some(put) = archive.put.clone() {
            command_targets.push(CommandArchiveTarget {
                name: archive.name.clone(),
                put,
                mkdir: archive.mkdir.clone(),
            });
            continue;
        }

        let path = match Url::parse(&archive.url) {
            Ok(url) if url.scheme() == "file" => url
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("Invalid file URL: {}", archive.url))?,
            Ok(_) => {
                tracing::warn!(archive = %archive.url, "Remote publish not supported (missing put command)");
                continue;
            }
            Err(_) => PathBuf::from(&archive.url),
        };
        local_targets.push((archive.url.as_str(), path));
    }

    if local_targets.is_empty() && command_targets.is_empty() {
        anyhow::bail!("No publish archives configured (local paths or put commands required).");
    }

    println!("Writable archives: {}", local_targets.len() + command_targets.len());
    for (url, _) in &local_targets {
        println!("  - {}", url);
    }
    for archive in &command_targets {
        println!("  - {} (command)", archive.name);
    }
    println!();

    // Open database to get current state
    let db = stellar_core_db::Database::open(&config.database.path)?;

    // Get current ledger from database
    let current_ledger = db.get_latest_ledger_seq()?
        .ok_or_else(|| anyhow::anyhow!("No ledger data in database. Run the node first."))?;

    println!("Current ledger in database: {}", current_ledger);

    // Calculate checkpoints to publish
    let latest_checkpoint = stellar_core_history::checkpoint::latest_checkpoint_before_or_at(current_ledger)
        .ok_or_else(|| anyhow::anyhow!("No checkpoint available for ledger {}", current_ledger))?;

    println!("Latest publishable checkpoint: {}", latest_checkpoint);

    let queued_checkpoints = db.load_publish_queue(None)?;
    let mut queued_checkpoints = queued_checkpoints
        .into_iter()
        .filter(|checkpoint| *checkpoint <= latest_checkpoint)
        .collect::<Vec<_>>();
    queued_checkpoints.sort_unstable();

    // Check what's already published across local archives.
    let mut published_ledger = latest_checkpoint;
    for (_, path) in &local_targets {
        let root_path = path.join(root_has_path());
        let ledger = if root_path.exists() {
            let json = fs::read_to_string(&root_path)?;
            let has = HistoryArchiveState::from_json(&json)?;
            has.current_ledger()
        } else {
            0
        };
        published_ledger = published_ledger.min(ledger);
    }

    println!("Already published up to: {}", published_ledger);

    if published_ledger >= latest_checkpoint && !force && queued_checkpoints.is_empty() {
        println!();
        println!("Archive is up to date. Use --force to republish.");
        return Ok(());
    }

    let mut checkpoints_to_publish = Vec::new();
    if !queued_checkpoints.is_empty() && !force {
        checkpoints_to_publish = queued_checkpoints;
    } else {
        // Calculate range to publish
        let start_checkpoint = if published_ledger > 0 && !force {
            next_checkpoint(published_ledger)
        } else {
            // Start from the first checkpoint we have
            checkpoint_containing(1)
        };

        if start_checkpoint > latest_checkpoint {
            println!("Nothing new to publish.");
            return Ok(());
        }

        let mut checkpoint = start_checkpoint;
        while checkpoint <= latest_checkpoint {
            checkpoints_to_publish.push(checkpoint);
            checkpoint = next_checkpoint(checkpoint);
        }
    }

    if checkpoints_to_publish.is_empty() {
        println!("Nothing queued to publish.");
        return Ok(());
    }

    println!();
    let first_checkpoint = *checkpoints_to_publish.first().unwrap();
    let last_checkpoint = *checkpoints_to_publish.last().unwrap();
    println!(
        "Publishing checkpoints {} to {}...",
        first_checkpoint, last_checkpoint
    );

    let bucket_manager = BucketManager::with_cache_size(
        config.buckets.directory.clone(),
        config.buckets.cache_size,
    )?;

    let mut published_count = 0;
    for checkpoint in checkpoints_to_publish {
        print!("  Publishing checkpoint {}... ", checkpoint);

        let start_ledger = checkpoint.saturating_sub(CHECKPOINT_FREQUENCY - 1);
        let start_ledger = if start_ledger == 0 { 1 } else { start_ledger };
        let mut headers = Vec::new();
        let mut tx_entries = Vec::new();
        let mut tx_results = Vec::new();

        for seq in start_ledger..=checkpoint {
            let header = db
                .get_ledger_header(seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header {}", seq))?;
            let hash = compute_header_hash(&header)?;
            headers.push(stellar_xdr::curr::LedgerHeaderHistoryEntry {
                header,
                hash: stellar_xdr::curr::Hash(hash.0),
                ext: stellar_xdr::curr::LedgerHeaderHistoryEntryExt::V0,
            });

            let tx_entry = db
                .get_tx_history_entry(seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing tx history entry {}", seq))?;
            tx_entries.push(tx_entry);

            let tx_result = db
                .get_tx_result_entry(seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing tx result entry {}", seq))?;
            tx_results.push(tx_result);
        }

        let scp_entries = build_scp_history_entries(&db, start_ledger, checkpoint)?;

        for idx in 0..headers.len() {
            let header_entry = &headers[idx];
            let tx_entry = &tx_entries[idx];
            let tx_result_entry = &tx_results[idx];
            let header = &header_entry.header;
            let tx_set = match &tx_entry.ext {
                TransactionHistoryEntryExt::V1(generalized) => {
                    TransactionSetVariant::Generalized(generalized.clone())
                }
                TransactionHistoryEntryExt::V0 => TransactionSetVariant::Classic(tx_entry.tx_set.clone()),
            };
            let tx_set_hash = verify::compute_tx_set_hash(&tx_set).unwrap_or(Hash256::ZERO);
            let expected_tx_set = Hash256::from(header.scp_value.tx_set_hash.0);
            if tx_set_hash != expected_tx_set {
                anyhow::bail!(
                    "Tx set hash mismatch at {} (expected {}, got {})",
                    header.ledger_seq,
                    expected_tx_set.to_hex(),
                    tx_set_hash.to_hex()
                );
            }

            let tx_result_hash =
                Hash256::hash_xdr(&tx_result_entry.tx_result_set).unwrap_or(Hash256::ZERO);
            let expected_tx_result = Hash256::from(header.tx_set_result_hash.0);
            if tx_result_hash != expected_tx_result {
                anyhow::bail!(
                    "Tx result hash mismatch at {} (expected {}, got {})",
                    header.ledger_seq,
                    expected_tx_result.to_hex(),
                    tx_result_hash.to_hex()
                );
            }
        }

        let levels = db
            .load_bucket_list(checkpoint)?
            .ok_or_else(|| anyhow::anyhow!("Missing bucket list snapshot {}", checkpoint))?;
        let mut bucket_list = BucketList::new();
        for (idx, (curr_hash, snap_hash)) in levels.iter().enumerate() {
            let curr_bucket = bucket_manager.load_bucket(curr_hash)?;
            let snap_bucket = bucket_manager.load_bucket(snap_hash)?;
            let level = bucket_list
                .level_mut(idx)
                .ok_or_else(|| anyhow::anyhow!("Missing bucket level {}", idx))?;
            level.set_curr((*curr_bucket).clone());
            level.set_snap((*snap_bucket).clone());
        }

        let expected_hash = Hash256::from(headers.last().unwrap().header.bucket_list_hash.0);
        let actual_hash = bucket_list.hash();
        if expected_hash != actual_hash {
            anyhow::bail!(
                "Bucket list hash mismatch at {} (expected {}, got {})",
                checkpoint,
                expected_hash.to_hex(),
                actual_hash.to_hex()
            );
        }

        let command_publish_dir = if command_targets.is_empty() {
            None
        } else {
            let sanitized_name = config
                .node
                .name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>();
            let publish_dir = std::env::temp_dir().join(format!(
                "rs-stellar-core-publish-{}-{}",
                sanitized_name, checkpoint
            ));
            if publish_dir.exists() {
                std::fs::remove_dir_all(&publish_dir)?;
            }
            std::fs::create_dir_all(&publish_dir)?;

            let publish_config = PublishConfig {
                local_path: publish_dir.clone(),
                network_passphrase: Some(config.network.passphrase.clone()),
                ..Default::default()
            };
            let manager = PublishManager::new(publish_config);
            manager
                .publish_checkpoint(checkpoint, &headers, &tx_entries, &tx_results, &bucket_list)
                .await?;

            let has = build_history_archive_state(
                checkpoint,
                &bucket_list,
                Some(config.network.passphrase.clone()),
            )?;
            let root_path = publish_dir.join(root_has_path());
            if let Some(parent) = root_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&root_path, has.to_json()?)?;
            Some(publish_dir)
        };

        let mut published_any = false;
        for (url, path) in &local_targets {
            let publish_config = PublishConfig {
                local_path: path.clone(),
                network_passphrase: Some(config.network.passphrase.clone()),
                ..Default::default()
            };
            let manager = PublishManager::new(publish_config);
            if !force && manager.is_published(checkpoint) {
                continue;
            }
            manager
                .publish_checkpoint(checkpoint, &headers, &tx_entries, &tx_results, &bucket_list)
                .await?;
            write_scp_history_file(path, checkpoint, &scp_entries)?;
            let has = build_history_archive_state(
                checkpoint,
                &bucket_list,
                Some(config.network.passphrase.clone()),
            )?;
            let root_path = path.join(root_has_path());
            if let Some(parent) = root_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&root_path, has.to_json()?)?;
            println!("OK ({})", url);
            published_any = true;
        }

        if let Some(ref publish_dir) = command_publish_dir {
            write_scp_history_file(publish_dir, checkpoint, &scp_entries)?;
            for archive in &command_targets {
                upload_publish_directory(archive, publish_dir)?;
                println!("OK (command: {})", archive.name);
                published_any = true;
            }
        }

        if let Some(publish_dir) = command_publish_dir {
            if let Err(err) = std::fs::remove_dir_all(&publish_dir) {
                tracing::warn!(
                    path = %publish_dir.display(),
                    error = %err,
                    "Failed to remove publish temp directory"
                );
            }
        }

        if published_any {
            published_count += 1;
        } else {
            println!("SKIP (already published)");
        }

        if let Err(err) = db.remove_publish(checkpoint) {
            tracing::warn!(checkpoint, error = %err, "Failed to remove publish queue entry");
        }
    }

    println!();
    println!("Publishing complete:");
    println!("  Checkpoints processed: {}", published_count);
    println!();

    Ok(())
}

fn build_scp_history_entries(
    db: &stellar_core_db::Database,
    start_ledger: u32,
    checkpoint: u32,
) -> anyhow::Result<Vec<stellar_xdr::curr::ScpHistoryEntry>> {
    use std::collections::HashSet;
    use stellar_core_common::Hash256;
    use stellar_xdr::curr::{LedgerScpMessages, ScpHistoryEntry, ScpHistoryEntryV0};

    let mut entries = Vec::new();
    for seq in start_ledger..=checkpoint {
        let envelopes = db.load_scp_history(seq)?;
        if envelopes.is_empty() {
            continue;
        }

        let mut qset_hashes = HashSet::new();
        for envelope in &envelopes {
            if let Some(hash) = scp_quorum_set_hash(&envelope.statement) {
                qset_hashes.insert(Hash256::from_bytes(hash.0));
            }
        }

        let mut qset_hashes = qset_hashes.into_iter().collect::<Vec<_>>();
        qset_hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));

        let mut qsets = Vec::new();
        for hash in qset_hashes {
            let qset = db
                .load_scp_quorum_set(&hash)?
                .ok_or_else(|| anyhow::anyhow!("Missing quorum set {}", hash.to_hex()))?;
            qsets.push(qset);
        }

        let quorum_sets = qsets
            .try_into()
            .map_err(|_| anyhow::anyhow!("Too many quorum sets for ledger {}", seq))?;
        let messages = envelopes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Too many SCP envelopes for ledger {}", seq))?;
        let entry = ScpHistoryEntry::V0(ScpHistoryEntryV0 {
            quorum_sets,
            ledger_messages: LedgerScpMessages {
                ledger_seq: seq,
                messages,
            },
        });
        entries.push(entry);
    }

    Ok(entries)
}

fn write_scp_history_file(
    base_dir: &std::path::Path,
    checkpoint: u32,
    entries: &[stellar_xdr::curr::ScpHistoryEntry],
) -> anyhow::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use stellar_core_history::paths::checkpoint_path;
    use stellar_xdr::curr::{Limits, WriteXdr};

    let path = base_dir.join(checkpoint_path("scp", checkpoint, "xdr.gz"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(&path)?;
    let mut encoder = GzEncoder::new(file, Compression::default());

    for entry in entries {
        let xdr = entry.to_xdr(Limits::none())?;
        encoder.write_all(&xdr)?;
    }
    encoder.finish()?;
    Ok(())
}

fn scp_quorum_set_hash(statement: &stellar_xdr::curr::ScpStatement) -> Option<stellar_xdr::curr::Hash> {
    match &statement.pledges {
        stellar_xdr::curr::ScpStatementPledges::Nominate(nom) => {
            Some(nom.quorum_set_hash.clone())
        }
        stellar_xdr::curr::ScpStatementPledges::Prepare(prep) => {
            Some(prep.quorum_set_hash.clone())
        }
        stellar_xdr::curr::ScpStatementPledges::Confirm(conf) => {
            Some(conf.quorum_set_hash.clone())
        }
        stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
            Some(ext.commit_quorum_set_hash.clone())
        }
    }
}

#[derive(Clone)]
struct CommandArchiveTarget {
    name: String,
    put: String,
    mkdir: Option<String>,
}

fn upload_publish_directory(
    target: &CommandArchiveTarget,
    publish_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use std::collections::HashSet;

    let mut files = collect_files(publish_dir)?;
    files.sort();

    let mut created_dirs = HashSet::new();
    for file in files {
        let rel = file
            .strip_prefix(publish_dir)
            .map_err(|e| anyhow::anyhow!("invalid publish path: {}", e))?;
        let rel_str = path_to_unix_string(rel)?;

        if let Some(ref mkdir_cmd) = target.mkdir {
            if let Some(parent) = rel.parent() {
                if !parent.as_os_str().is_empty() {
                    let remote_dir = path_to_unix_string(parent)?;
                    if created_dirs.insert(remote_dir.clone()) {
                        let cmd = render_mkdir_command(mkdir_cmd, &remote_dir);
                        run_shell_command(&cmd)?;
                    }
                }
            }
        }

        let cmd = render_put_command(&target.put, &file, &rel_str);
        run_shell_command(&cmd)?;
    }

    Ok(())
}

fn collect_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn path_to_unix_string(path: &std::path::Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let part = component.as_os_str().to_string_lossy();
        parts.push(part.to_string());
    }
    Ok(parts.join("/"))
}

fn render_put_command(template: &str, local_path: &std::path::Path, remote_path: &str) -> String {
    template
        .replace("{0}", local_path.to_string_lossy().as_ref())
        .replace("{1}", remote_path)
}

fn render_mkdir_command(template: &str, remote_dir: &str) -> String {
    template.replace("{0}", remote_dir)
}

fn run_shell_command(cmd: &str) -> anyhow::Result<()> {
    use std::process::Command;

    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("command failed (exit {}): {}", status, cmd);
    }
}

/// Sample config command handler.
fn cmd_sample_config() -> anyhow::Result<()> {
    let sample = AppConfig::sample_config();
    println!("{}", sample);
    Ok(())
}

/// Offline commands handler.
fn cmd_offline(cmd: OfflineCommands) -> anyhow::Result<()> {
    match cmd {
        OfflineCommands::ConvertKey { key } => {
            convert_key(&key)
        }
        OfflineCommands::DecodeXdr { r#type, value } => {
            decode_xdr(&r#type, &value)
        }
        OfflineCommands::EncodeXdr { r#type, value } => {
            encode_xdr(&r#type, &value)
        }
        OfflineCommands::BucketInfo { path } => {
            bucket_info(&path)
        }
    }
}

/// Convert a Stellar key between formats.
fn convert_key(key: &str) -> anyhow::Result<()> {
    let key = key.trim();

    if key.starts_with('G') {
        // Public key (account ID)
        let pk = stellar_core_crypto::PublicKey::from_strkey(key)?;
        println!("Type: Account ID (Public Key)");
        println!("StrKey: {}", pk.to_strkey());
        println!("Hex: {}", hex::encode(pk.as_bytes()));
    } else if key.starts_with('S') {
        // Secret seed
        let sk = stellar_core_crypto::SecretKey::from_strkey(key)?;
        let pk = sk.public_key();
        println!("Type: Secret Seed");
        println!("Public Key: {}", pk.to_strkey());
        println!("WARNING: Secret key detected, not displaying raw bytes");
    } else if key.len() == 64 {
        // Might be hex
        let bytes = hex::decode(key)?;
        if bytes.len() == 32 {
            if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(bytes.as_slice().try_into()?) {
                println!("Type: Public Key (from hex)");
                println!("StrKey: {}", pk.to_strkey());
            } else {
                println!("Type: 32-byte hash");
                println!("Hex: {}", key);
            }
        }
    } else {
        anyhow::bail!("Unknown key format: {}", key);
    }

    Ok(())
}

/// Decode XDR from base64.
fn decode_xdr(type_name: &str, value: &str) -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use stellar_xdr::curr::ReadXdr;

    let bytes = STANDARD.decode(value)?;

    // This is a simplified version - a full implementation would handle all XDR types
    match type_name.to_lowercase().as_str() {
        "ledgerheader" => {
            let header = stellar_xdr::curr::LedgerHeader::from_xdr(&bytes, stellar_xdr::curr::Limits::none())?;
            println!("{:#?}", header);
        }
        "transactionenvelope" => {
            let env = stellar_xdr::curr::TransactionEnvelope::from_xdr(&bytes, stellar_xdr::curr::Limits::none())?;
            println!("{:#?}", env);
        }
        "transactionresult" => {
            let result = stellar_xdr::curr::TransactionResult::from_xdr(&bytes, stellar_xdr::curr::Limits::none())?;
            println!("{:#?}", result);
        }
        _ => {
            anyhow::bail!("Unknown XDR type: {}. Supported types: LedgerHeader, TransactionEnvelope, TransactionResult", type_name);
        }
    }

    Ok(())
}

/// Encode a value to XDR.
fn encode_xdr(type_name: &str, value: &str) -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use stellar_xdr::curr::{WriteXdr, Limits};

    // Parse JSON and encode to XDR based on type
    match type_name.to_lowercase().as_str() {
        "ledgerheader" => {
            let header: stellar_xdr::curr::LedgerHeader = serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid JSON for LedgerHeader: {}", e))?;
            let xdr_bytes = header.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "transactionenvelope" => {
            let env: stellar_xdr::curr::TransactionEnvelope = serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid JSON for TransactionEnvelope: {}", e))?;
            let xdr_bytes = env.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "transactionresult" => {
            let result: stellar_xdr::curr::TransactionResult = serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid JSON for TransactionResult: {}", e))?;
            let xdr_bytes = result.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "accountid" => {
            // Parse from strkey (G...) format
            let pk = stellar_core_crypto::PublicKey::from_strkey(value.trim())?;
            let account_id = stellar_xdr::curr::AccountId(
                stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                    stellar_xdr::curr::Uint256(*pk.as_bytes())
                )
            );
            let xdr_bytes = account_id.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "muxedaccount" => {
            // Parse from strkey (G... or M...) format
            let value = value.trim();
            let muxed = if value.starts_with('G') {
                let pk = stellar_core_crypto::PublicKey::from_strkey(value)?;
                stellar_xdr::curr::MuxedAccount::Ed25519(
                    stellar_xdr::curr::Uint256(*pk.as_bytes())
                )
            } else {
                // For M... addresses, parse the muxed account
                anyhow::bail!("Muxed account (M...) parsing not yet supported");
            };
            let xdr_bytes = muxed.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "asset" => {
            // Parse asset in format "native" or "CODE:ISSUER"
            let value = value.trim();
            let asset = if value.to_lowercase() == "native" {
                stellar_xdr::curr::Asset::Native
            } else if let Some((code, issuer)) = value.split_once(':') {
                let issuer_pk = stellar_core_crypto::PublicKey::from_strkey(issuer)?;
                let issuer_id = stellar_xdr::curr::AccountId(
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                        stellar_xdr::curr::Uint256(*issuer_pk.as_bytes())
                    )
                );

                if code.len() <= 4 {
                    let mut asset_code = [0u8; 4];
                    asset_code[..code.len()].copy_from_slice(code.as_bytes());
                    stellar_xdr::curr::Asset::CreditAlphanum4(stellar_xdr::curr::AlphaNum4 {
                        asset_code: stellar_xdr::curr::AssetCode4(asset_code),
                        issuer: issuer_id,
                    })
                } else if code.len() <= 12 {
                    let mut asset_code = [0u8; 12];
                    asset_code[..code.len()].copy_from_slice(code.as_bytes());
                    stellar_xdr::curr::Asset::CreditAlphanum12(stellar_xdr::curr::AlphaNum12 {
                        asset_code: stellar_xdr::curr::AssetCode12(asset_code),
                        issuer: issuer_id,
                    })
                } else {
                    anyhow::bail!("Asset code too long (max 12 characters)");
                }
            } else {
                anyhow::bail!("Invalid asset format. Use 'native' or 'CODE:ISSUER'");
            };
            let xdr_bytes = asset.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "hash" | "uint256" => {
            // Parse from hex
            let value = value.trim();
            let bytes = hex::decode(value)
                .map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))?;
            if bytes.len() != 32 {
                anyhow::bail!("Hash must be exactly 32 bytes (64 hex characters)");
            }
            let hash = stellar_xdr::curr::Uint256(bytes.try_into().unwrap());
            let xdr_bytes = hash.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        _ => {
            anyhow::bail!(
                "Unknown XDR type: {}. Supported types: LedgerHeader, TransactionEnvelope, \
                TransactionResult, AccountId, MuxedAccount, Asset, Hash, Uint256",
                type_name
            );
        }
    }

    Ok(())
}

/// Print bucket information.
fn bucket_info(path: &PathBuf) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("Bucket path does not exist: {}", path.display());
    }

    if path.is_dir() {
        // List bucket files in directory
        println!("Bucket directory: {}", path.display());
        println!();

        let mut count = 0;
        let mut total_size = 0u64;

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                let name = entry.file_name();
                let size = metadata.len();
                println!("  {} ({} bytes)", name.to_string_lossy(), size);
                count += 1;
                total_size += size;
            }
        }

        println!();
        println!("Total: {} files, {} bytes", count, total_size);
    } else {
        // Single bucket file
        println!("Bucket file: {}", path.display());

        let metadata = std::fs::metadata(path)?;
        println!("Size: {} bytes", metadata.len());

        // Would parse and display bucket contents
        println!("(Bucket content parsing not yet implemented)");
    }

    Ok(())
}

/// Check quorum intersection from JSON.
fn cmd_check_quorum_intersection(path: &PathBuf) -> anyhow::Result<()> {
    let enjoys = quorum_intersection::check_quorum_intersection_from_json(path.as_path())?;
    if enjoys {
        println!("network enjoys quorum intersection");
        Ok(())
    } else {
        anyhow::bail!("quorum sets do not have intersection");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test basic parsing
        let cli = Cli::parse_from(["rs-stellar-core", "info"]);
        assert!(matches!(cli.command, Commands::Info));
    }

    #[test]
    fn test_cli_run_command() {
        let cli = Cli::parse_from(["rs-stellar-core", "run", "--validator"]);
        match cli.command {
            Commands::Run { validator, watcher, .. } => {
                assert!(validator);
                assert!(!watcher);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_cli_catchup_command() {
        let cli = Cli::parse_from(["rs-stellar-core", "catchup", "1000000", "--mode", "complete"]);
        match cli.command {
            Commands::Catchup { target, .. } => {
                assert_eq!(target, "1000000");
            }
            _ => panic!("Expected Catchup command"),
        }
    }

    #[test]
    fn test_cli_global_options() {
        let cli = Cli::parse_from(["rs-stellar-core", "--verbose", "--mainnet", "info"]);
        assert!(cli.verbose);
        assert!(cli.mainnet);
    }

    #[test]
    fn test_cli_check_quorum_intersection() {
        let cli = Cli::parse_from(["rs-stellar-core", "check-quorum-intersection", "foo.json"]);
        match cli.command {
            Commands::CheckQuorumIntersection { path } => {
                assert_eq!(path, PathBuf::from("foo.json"));
            }
            _ => panic!("Expected check-quorum-intersection command"),
        }
    }
}
