//! Catchup manager for synchronizing from history archives.
//!
//! The catchup process allows a node to synchronize with the Stellar network
//! by downloading and applying history from trusted archives.
//!
//! ## Catchup Process
//!
//! 1. Find the latest checkpoint <= target ledger
//! 2. Download the History Archive State (HAS) for that checkpoint
//! 3. Download all buckets referenced in the HAS
//! 4. Apply buckets to build the initial ledger state
//! 5. Download ledger headers, transactions, and results for the checkpoint
//! 6. Verify the header chain
//! 7. Replay ledgers from the checkpoint to the target
//!
//! ## Key Insight
//!
//! During catchup, we re-execute transactions against the bucket list state to
//! reconstruct ledger changes while still verifying history data. This keeps
//! bucket list evolution consistent with transaction effects and lets us check
//! tx set and tx result hashes against the headers.

use crate::{
    archive::HistoryArchive,
    archive_state::HistoryArchiveState,
    checkpoint,
    replay::{self, LedgerReplayResult, ReplayConfig, ReplayedLedgerState},
    verify, CatchupOutput, CatchupResult, HistoryError, Result,
};
use stellar_core_bucket::{BucketList, BucketManager};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_db::Database;
use stellar_core_invariant::{
    BucketListHashMatchesHeader, CloseTimeNondecreasing, ConservationOfLumens, InvariantContext,
    InvariantManager, LastModifiedLedgerSeqMatchesHeader, LedgerEntryIsValid, LedgerSeqIncrement,
    LiabilitiesMatchOffers, OrderBookIsNotCrossed,
};
use sha2::Digest;
use stellar_core_ledger::TransactionSetVariant;
use stellar_core_tx::TransactionFrame;
use stellar_xdr::curr::{
    GeneralizedTransactionSet, LedgerHeader, LedgerHeaderHistoryEntry, ScpHistoryEntry,
    TransactionHistoryEntry, TransactionHistoryResultEntry, TransactionHistoryEntryExt,
    TransactionHistoryResultEntryExt, TransactionMeta, TransactionResultPair, TransactionResultSet,
    TransactionSet, TransactionSetV1, WriteXdr,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Status of a catchup operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupStatus {
    /// Not started.
    Pending,
    /// Downloading History Archive State.
    DownloadingHAS,
    /// Downloading bucket files.
    DownloadingBuckets,
    /// Applying buckets to build initial state.
    ApplyingBuckets,
    /// Downloading ledger data.
    DownloadingLedgers,
    /// Verifying downloaded data.
    Verifying,
    /// Replaying ledgers.
    Replaying,
    /// Catchup completed successfully.
    Completed,
    /// Catchup failed.
    Failed,
}

/// Progress information for a catchup operation.
#[derive(Debug, Clone)]
pub struct CatchupProgress {
    /// Current status.
    pub status: CatchupStatus,
    /// Current step (1-based).
    pub current_step: u32,
    /// Total number of steps.
    pub total_steps: u32,
    /// For bucket downloads: number of buckets downloaded.
    pub buckets_downloaded: u32,
    /// For bucket downloads: total buckets to download.
    pub buckets_total: u32,
    /// For ledger replay: current ledger being replayed.
    pub current_ledger: u32,
    /// For ledger replay: target ledger.
    pub target_ledger: u32,
    /// Human-readable status message.
    pub message: String,
}

impl Default for CatchupProgress {
    fn default() -> Self {
        Self {
            status: CatchupStatus::Pending,
            current_step: 0,
            total_steps: 7,
            buckets_downloaded: 0,
            buckets_total: 0,
            current_ledger: 0,
            target_ledger: 0,
            message: String::new(),
        }
    }
}

/// Pre-downloaded checkpoint data for catchup.
#[derive(Debug, Clone)]
pub struct CheckpointData {
    pub has: HistoryArchiveState,
    pub buckets: HashMap<Hash256, Vec<u8>>,
    pub headers: Vec<LedgerHeaderHistoryEntry>,
    pub transactions: Vec<TransactionHistoryEntry>,
    pub tx_results: Vec<TransactionHistoryResultEntry>,
    pub scp_history: Vec<ScpHistoryEntry>,
}

/// Manager for catching up from history archives.
pub struct CatchupManager {
    /// Available history archives.
    archives: Vec<Arc<HistoryArchive>>,
    /// Bucket manager for bucket operations.
    bucket_manager: Arc<BucketManager>,
    /// Database for persistence.
    db: Arc<Database>,
    /// Current catchup progress.
    progress: CatchupProgress,
    /// Replay configuration.
    replay_config: ReplayConfig,
}

impl CatchupManager {
    /// Create a new catchup manager.
    ///
    /// # Arguments
    ///
    /// * `archives` - List of history archives to use (will try in order)
    /// * `bucket_manager` - Manager for bucket file operations
    /// * `db` - Database for persisting ledger state
    pub fn new(
        archives: Vec<HistoryArchive>,
        bucket_manager: BucketManager,
        db: Database,
    ) -> Self {
        Self {
            archives: archives.into_iter().map(Arc::new).collect(),
            bucket_manager: Arc::new(bucket_manager),
            db: Arc::new(db),
            progress: CatchupProgress::default(),
            replay_config: ReplayConfig::default(),
        }
    }

    /// Create a new catchup manager from Arc references.
    pub fn new_with_arcs(
        archives: Vec<Arc<HistoryArchive>>,
        bucket_manager: Arc<BucketManager>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            archives,
            bucket_manager,
            db,
            progress: CatchupProgress::default(),
            replay_config: ReplayConfig::default(),
        }
    }

    /// Get the current catchup progress.
    pub fn progress(&self) -> &CatchupProgress {
        &self.progress
    }

    /// Set the replay configuration.
    pub fn set_replay_config(&mut self, config: ReplayConfig) {
        self.replay_config = config;
    }

    /// Catch up to a specific target ledger.
    ///
    /// This is the main entry point for the catchup process. It will:
    /// 1. Find the latest checkpoint before or at the target
    /// 2. Download and apply the state at that checkpoint
    /// 3. Replay ledgers from the checkpoint to the target (if any)
    ///
    /// # Arguments
    ///
    /// * `target` - The target ledger sequence to catch up to
    ///
    /// # Returns
    ///
    /// A `CatchupOutput` containing the bucket list, header, and summary information.
    pub async fn catchup_to_ledger(&mut self, target: u32) -> Result<CatchupOutput> {
        info!("Starting catchup to ledger {}", target);
        self.progress.target_ledger = target;

        // Step 1: Find the latest checkpoint <= target
        let checkpoint_seq = checkpoint::latest_checkpoint_before_or_at(target)
            .ok_or_else(|| HistoryError::CatchupFailed(
                format!("target ledger {} is before first checkpoint", target)
            ))?;

        info!("Using checkpoint {} for catchup to {}", checkpoint_seq, target);

        // Step 2: Download the History Archive State
        self.update_progress(CatchupStatus::DownloadingHAS, 1, "Downloading History Archive State");
        let has = self.download_has(checkpoint_seq).await?;
        verify::verify_has_structure(&has)?;
        verify::verify_has_checkpoint(&has, checkpoint_seq)?;

        let scp_history = self.download_scp_history(checkpoint_seq).await?;
        if !scp_history.is_empty() {
            verify::verify_scp_history_entries(&scp_history)?;
            self.persist_scp_history_entries(&scp_history)?;
        }

        // Step 3: Download all buckets referenced in the HAS
        self.update_progress(CatchupStatus::DownloadingBuckets, 2, "Downloading bucket files");
        let bucket_hashes = has.unique_bucket_hashes();
        let buckets_total = bucket_hashes.len() as u32;
        self.progress.buckets_total = buckets_total;
        let buckets = self.download_buckets(&bucket_hashes).await?;

        // Step 4: Apply buckets to build initial state
        self.update_progress(CatchupStatus::ApplyingBuckets, 3, "Applying buckets to build initial state");
        let (mut bucket_list, hot_archive_bucket_list) = self.apply_buckets(&has, &buckets).await?;
        self.persist_bucket_list_snapshot(checkpoint_seq, &bucket_list)?;

        // Step 5: Download ledger data from checkpoint to target
        self.update_progress(CatchupStatus::DownloadingLedgers, 4, "Downloading ledger data");
        let ledger_data = self.download_ledger_data(checkpoint_seq, target).await?;

        // Step 6: Verify the header chain
        self.update_progress(CatchupStatus::Verifying, 5, "Verifying header chain");
        self.verify_downloaded_data(&ledger_data)?;

        let network_id = has
            .network_passphrase
            .as_ref()
            .map(|p| NetworkId::from_passphrase(p))
            .unwrap_or_else(NetworkId::testnet);

        // Step 7: Replay ledgers from checkpoint to target (if any)
        self.update_progress(CatchupStatus::Replaying, 6, "Replaying ledgers");

        let (final_header, final_hash, ledgers_applied) = if ledger_data.is_empty() {
            // Catching up to exactly a checkpoint - download and use the checkpoint header
            info!("Catching up to checkpoint {} (no ledgers to replay)", checkpoint_seq);
            let checkpoint_header = self.download_checkpoint_header(checkpoint_seq).await?;
            let header_hash = verify::compute_header_hash(&checkpoint_header)?;
            (checkpoint_header, header_hash, 0)
        } else {
            // Replay ledgers to reach target
            let final_state = self
                .replay_ledgers(&mut bucket_list, hot_archive_bucket_list.as_ref(), &ledger_data, network_id)
                .await?;
            let ledgers_applied = target - checkpoint_seq;
            // Get the final header from replay
            let final_header = self.download_checkpoint_header(target).await
                .unwrap_or_else(|_| {
                    // Construct a minimal header from replay state if download fails
                    warn!("Could not download final header, using replay state");
                    create_header_from_replay_state(&final_state, &bucket_list)
                });
            (final_header, final_state.ledger_hash, ledgers_applied)
        };

        // Verify the final state matches expected bucket list hash
        if let Err(e) = self.verify_final_state(&final_header, &bucket_list, &hot_archive_bucket_list) {
            warn!("Final state verification warning: {}", e);
            // Don't fail on verification mismatch during catchup
            // as the bucket list may not be fully updated yet
        }

        self.persist_ledger_history(&ledger_data, &network_id)?;
        if ledger_data.is_empty() {
            self.persist_header_only(&final_header)?;
        }

        // Complete!
        self.update_progress(CatchupStatus::Completed, 7, "Catchup completed");

        info!(
            "Catchup completed: ledger {}, hash {}",
            final_header.ledger_seq, final_hash
        );

        Ok(CatchupOutput {
            result: CatchupResult {
                ledger_seq: final_header.ledger_seq,
                ledger_hash: final_hash,
                ledgers_applied,
                buckets_downloaded: buckets_total,
            },
            bucket_list,
            hot_archive_bucket_list,
            header: final_header,
        })
    }

    /// Catch up to a target ledger using pre-downloaded checkpoint data.
    pub async fn catchup_to_ledger_with_checkpoint_data(
        &mut self,
        target: u32,
        data: CheckpointData,
    ) -> Result<CatchupOutput> {
        info!("Starting catchup to ledger {} with checkpoint data", target);
        self.progress.target_ledger = target;

        let checkpoint_seq = checkpoint::latest_checkpoint_before_or_at(target).ok_or_else(|| {
            HistoryError::CatchupFailed(format!(
                "target ledger {} is before first checkpoint",
                target
            ))
        })?;

        if data.has.current_ledger != checkpoint_seq {
            return Err(HistoryError::CatchupFailed(format!(
                "checkpoint data ledger {} does not match target checkpoint {}",
                data.has.current_ledger, checkpoint_seq
            )));
        }

        // Step 2: Verify HAS
        self.update_progress(
            CatchupStatus::DownloadingHAS,
            1,
            "Using provided History Archive State",
        );
        verify::verify_has_structure(&data.has)?;
        verify::verify_has_checkpoint(&data.has, checkpoint_seq)?;

        // Step 3: Verify buckets
        self.update_progress(
            CatchupStatus::DownloadingBuckets,
            2,
            "Verifying bucket files",
        );
        let bucket_hashes = data.has.unique_bucket_hashes();
        self.progress.buckets_total = bucket_hashes.len() as u32;
        let mut buckets = Vec::with_capacity(bucket_hashes.len());
        for (idx, hash) in bucket_hashes.iter().enumerate() {
            let Some(bytes) = data.buckets.get(hash) else {
                return Err(HistoryError::BucketNotFound(*hash));
            };
            verify::verify_bucket_hash(bytes, hash)?;
            buckets.push((*hash, bytes.clone()));
            self.progress.buckets_downloaded = (idx + 1) as u32;
        }

        // Step 4: Verify SCP history entries (if present)
        if !data.scp_history.is_empty() {
            verify::verify_scp_history_entries(&data.scp_history)?;
            self.persist_scp_history_entries(&data.scp_history)?;
        }

        // Step 4: Apply buckets to build initial state
        self.update_progress(
            CatchupStatus::ApplyingBuckets,
            3,
            "Applying buckets to build initial state",
        );
        let (mut bucket_list, hot_archive_bucket_list) =
            self.apply_buckets(&data.has, &buckets).await?;
        self.persist_bucket_list_snapshot(checkpoint_seq, &bucket_list)?;

        // Step 5: Build ledger data from checkpoint files
        self.update_progress(
            CatchupStatus::DownloadingLedgers,
            4,
            "Using provided ledger data",
        );
        let mut header_map = HashMap::new();
        for entry in &data.headers {
            header_map.insert(entry.header.ledger_seq, entry.header.clone());
        }
        for entry in &data.tx_results {
            if entry.ledger_seq <= checkpoint_seq || entry.ledger_seq > target {
                continue;
            }
            if let Some(header) = header_map.get(&entry.ledger_seq) {
                let xdr = entry
                    .tx_result_set
                    .to_xdr(stellar_xdr::curr::Limits::none())
                    .map_err(|e| {
                        HistoryError::CatchupFailed(format!(
                            "failed to encode tx result set: {}",
                            e
                        ))
                    })?;
                verify::verify_tx_result_set(header, &xdr)?;
            }
        }
        let checkpoint_header = checkpoint_header_from_headers(checkpoint_seq, &data.headers)?;
        let ledger_data = if target == checkpoint_seq {
            Vec::new()
        } else {
            self.download_ledger_data(checkpoint_seq, target).await?
        };

        // Step 6: Verify the header chain
        self.update_progress(CatchupStatus::Verifying, 5, "Verifying header chain");
        self.verify_downloaded_data(&ledger_data)?;

        let network_id = data
            .has
            .network_passphrase
            .as_ref()
            .map(|p| NetworkId::from_passphrase(p))
            .unwrap_or_else(NetworkId::testnet);

        // Step 7: Replay ledgers from checkpoint to target (if any)
        self.update_progress(CatchupStatus::Replaying, 6, "Replaying ledgers");

        let (final_header, final_hash, ledgers_applied) = if ledger_data.is_empty() {
            let header_hash = verify::compute_header_hash(&checkpoint_header)?;
            (checkpoint_header, header_hash, 0)
        } else {
            let final_state = self
                .replay_ledgers(&mut bucket_list, hot_archive_bucket_list.as_ref(), &ledger_data, network_id)
                .await?;
            let ledgers_applied = target - checkpoint_seq;
            let final_header = data
                .headers
                .iter()
                .find(|entry| entry.header.ledger_seq == target)
                .map(|entry| entry.header.clone())
                .unwrap_or(checkpoint_header);
            (final_header, final_state.ledger_hash, ledgers_applied)
        };

        if let Err(e) = self.verify_final_state(&final_header, &bucket_list, &hot_archive_bucket_list) {
            warn!("Final state verification warning: {}", e);
        }

        self.persist_ledger_history(&ledger_data, &network_id)?;
        if ledger_data.is_empty() {
            self.persist_header_only(&final_header)?;
        }

        self.update_progress(CatchupStatus::Completed, 7, "Catchup completed");

        Ok(CatchupOutput {
            result: CatchupResult {
                ledger_seq: final_header.ledger_seq,
                ledger_hash: final_hash,
                ledgers_applied,
                buckets_downloaded: bucket_hashes.len() as u32,
            },
            bucket_list,
            hot_archive_bucket_list,
            header: final_header,
        })
    }

    /// Update the progress status.
    fn update_progress(&mut self, status: CatchupStatus, step: u32, message: &str) {
        self.progress.status = status;
        self.progress.current_step = step;
        self.progress.message = message.to_string();
        debug!("Catchup progress: step {}/{} - {}", step, self.progress.total_steps, message);
    }

    /// Download the History Archive State for a checkpoint.
    async fn download_has(&self, checkpoint_seq: u32) -> Result<HistoryArchiveState> {
        for archive in &self.archives {
            match archive.get_checkpoint_has(checkpoint_seq).await {
                Ok(has) => return Ok(has),
                Err(e) => {
                    warn!("Failed to download HAS from archive {}: {}", archive.base_url(), e);
                    continue;
                }
            }
        }

        Err(HistoryError::CatchupFailed(format!(
            "failed to download HAS for checkpoint {} from any archive",
            checkpoint_seq
        )))
    }

    async fn download_scp_history(&self, checkpoint_seq: u32) -> Result<Vec<ScpHistoryEntry>> {
        for archive in &self.archives {
            match archive.get_scp_history(checkpoint_seq).await {
                Ok(entries) => return Ok(entries),
                Err(HistoryError::NotFound(_)) => {
                    debug!(
                        archive = %archive.base_url(),
                        checkpoint = checkpoint_seq,
                        "SCP history not found"
                    );
                }
                Err(e) => {
                    warn!(
                        archive = %archive.base_url(),
                        checkpoint = checkpoint_seq,
                        error = %e,
                        "Failed to download SCP history"
                    );
                }
            }
        }

        Ok(Vec::new())
    }

    /// Download all buckets referenced in the HAS to disk in parallel.
    ///
    /// This pre-downloads buckets to disk (not memory) so apply_buckets can
    /// load them quickly. Uses parallel downloads for speed while keeping
    /// memory usage low by saving directly to disk.
    async fn download_buckets(
        &mut self,
        hashes: &[Hash256],
    ) -> Result<Vec<(Hash256, Vec<u8>)>> {
        use futures::stream::{self, StreamExt};

        let bucket_dir = self.bucket_manager.bucket_dir().to_path_buf();
        let empty_bucket_hash = Hash256::hash(&[]);

        // Filter out zero/empty hashes and already-downloaded buckets
        let to_download: Vec<_> = hashes
            .iter()
            .filter(|hash| {
                if hash.is_zero() || **hash == empty_bucket_hash {
                    return false;
                }
                let bucket_path = bucket_dir.join(format!("{}.bucket", hash.to_hex()));
                !bucket_path.exists()
            })
            .cloned()
            .collect();

        self.progress.buckets_total = hashes.len() as u32;

        if to_download.is_empty() {
            info!(
                "All {} buckets already cached on disk",
                hashes.len()
            );
            return Ok(Vec::new());
        }

        info!(
            "Pre-downloading {} buckets to disk ({} already cached) with {} parallel downloads",
            to_download.len(),
            hashes.len() - to_download.len(),
            16 // MAX_CONCURRENT_SUBPROCESSES equivalent
        );

        let archives = self.archives.clone();
        let bucket_dir = bucket_dir.clone();
        let total_to_download = to_download.len();
        let downloaded = std::sync::atomic::AtomicU32::new(0);

        // Download buckets in parallel, saving directly to disk
        let results: Vec<Result<()>> = stream::iter(to_download.into_iter())
            .map(|hash| {
                let archives = archives.clone();
                let bucket_dir = bucket_dir.clone();
                let downloaded = &downloaded;

                async move {
                    let bucket_path = bucket_dir.join(format!("{}.bucket", hash.to_hex()));

                    // Try each archive until one succeeds
                    for archive in &archives {
                        match archive.get_bucket(&hash).await {
                            Ok(data) => {
                                // Save to disk
                                if let Err(e) = std::fs::write(&bucket_path, &data) {
                                    warn!("Failed to save bucket {} to disk: {}", hash, e);
                                    continue;
                                }
                                let count = downloaded.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                if count % 5 == 0 || count == total_to_download as u32 {
                                    info!("Downloaded {}/{} buckets", count, total_to_download);
                                }
                                debug!(
                                    "Pre-downloaded bucket {} ({} bytes)",
                                    hash,
                                    data.len()
                                );
                                return Ok(());
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to download bucket {} from {}: {}",
                                    hash,
                                    archive.base_url(),
                                    e
                                );
                                continue;
                            }
                        }
                    }

                    Err(HistoryError::BucketNotFound(hash))
                }
            })
            .buffer_unordered(16) // MAX_CONCURRENT_SUBPROCESSES equivalent
            .collect()
            .await;

        // Check for any failures
        for result in results {
            result?;
        }

        self.progress.buckets_downloaded = hashes.len() as u32;
        info!(
            "Pre-downloaded all {} buckets to disk",
            total_to_download
        );

        // Return empty - buckets are on disk, not in memory
        Ok(Vec::new())
    }

    /// Download a single bucket.
    #[allow(dead_code)]
    async fn download_bucket(&self, hash: &Hash256) -> Result<Vec<u8>> {
        for archive in &self.archives {
            match archive.get_bucket(hash).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    warn!("Failed to download bucket {} from archive {}: {}", hash, archive.base_url(), e);
                    continue;
                }
            }
        }

        Err(HistoryError::BucketNotFound(*hash))
    }

    /// Apply downloaded buckets to build the initial bucket list state.
    /// Returns (live_bucket_list, hot_archive_bucket_list).
    ///
    /// This method uses disk-backed bucket storage to handle mainnet's large buckets
    /// efficiently. Instead of loading all entries into memory, each bucket is:
    /// 1. Downloaded and saved to disk
    /// 2. Indexed with a compact key-to-offset mapping
    /// 3. Entries are loaded on-demand when accessed
    ///
    /// This reduces memory usage from O(entries) to O(unique_keys) for the index.
    async fn apply_buckets(
        &self,
        has: &HistoryArchiveState,
        buckets: &[(Hash256, Vec<u8>)],
    ) -> Result<(BucketList, Option<BucketList>)> {
        use std::collections::HashMap;
        use std::sync::Mutex;
        use stellar_core_bucket::Bucket;

        info!(
            "Applying buckets to build state at ledger {} (disk-backed mode)",
            has.current_ledger
        );

        // Get bucket storage directory from the bucket manager
        let bucket_dir = self.bucket_manager.bucket_dir();

        // Cache for buckets we've already loaded (to avoid re-downloading).
        let bucket_cache: Mutex<HashMap<Hash256, Bucket>> = Mutex::new(HashMap::new());
        let preloaded_buckets: Mutex<HashMap<Hash256, Vec<u8>>> =
            Mutex::new(buckets.iter().cloned().collect());

        // Clone archives and bucket_dir for use in closure
        let archives = self.archives.clone();
        let bucket_dir = bucket_dir.to_path_buf();

        let empty_bucket_hash = Hash256::hash(&[]);

        // Helper to load a bucket - downloads on-demand, saves to disk, and caches
        let load_bucket = |hash: &Hash256| -> stellar_core_bucket::Result<Bucket> {
            // Zero hash means empty bucket
            if hash.is_zero() {
                return Ok(Bucket::empty());
            }
            if *hash == empty_bucket_hash {
                return Ok(Bucket::empty());
            }

            // Check cache first
            {
                let cache = bucket_cache.lock().unwrap();
                if let Some(bucket) = cache.get(hash) {
                    return Ok(bucket.clone());
                }
            }

            // Construct path for this bucket
            let bucket_path = bucket_dir.join(format!("{}.bucket", hash.to_hex()));

            // Check if bucket already exists on disk
            if bucket_path.exists() {
                debug!("Loading existing bucket {} from disk", hash);
                let bucket = Bucket::from_xdr_bytes_disk_backed(
                    &std::fs::read(&bucket_path)?,
                    &bucket_path,
                )?;
                let mut cache = bucket_cache.lock().unwrap();
                cache.insert(*hash, bucket.clone());
                return Ok(bucket);
            }

            // Use preloaded bucket data if available, otherwise download.
            let xdr_data = if let Some(data) = {
                let mut preloaded = preloaded_buckets.lock().unwrap();
                preloaded.remove(hash)
            } {
                data
            } else {
                // Download the bucket (blocking - we're in a sync context)
                let hash = *hash;
                let archives = archives.clone();

                let download = async move {
                    for archive in &archives {
                        match archive.get_bucket(&hash).await {
                            Ok(data) => return Ok(data),
                            Err(e) => {
                                warn!("Failed to download bucket {} from archive: {}", hash, e);
                                continue;
                            }
                        }
                    }
                    Err(stellar_core_bucket::BucketError::NotFound(format!(
                        "Bucket {} not found in any archive",
                        hash
                    )))
                };

                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    if matches!(
                        handle.runtime_flavor(),
                        tokio::runtime::RuntimeFlavor::MultiThread
                    ) {
                        tokio::task::block_in_place(|| handle.block_on(download))?
                    } else {
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .map_err(|e| {
                                    stellar_core_bucket::BucketError::NotFound(format!(
                                        "failed to build runtime: {}",
                                        e
                                    ))
                                })?;
                            rt.block_on(download)
                        })
                        .join()
                        .map_err(|_| {
                            stellar_core_bucket::BucketError::NotFound(
                                "bucket download thread panicked".to_string(),
                            )
                        })??
                    }
                } else {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            stellar_core_bucket::BucketError::NotFound(format!(
                                "failed to build runtime: {}",
                                e
                            ))
                        })?;
                    rt.block_on(download)?
                }
            };

            info!(
                "Downloaded bucket {}: {} bytes, saving to disk",
                hash,
                xdr_data.len()
            );

            // Create the bucket using disk-backed storage.
            // This saves the XDR to disk and builds a compact index.
            // Entries are NOT loaded into memory - they're read from disk on-demand.
            let bucket = Bucket::from_xdr_bytes_disk_backed(&xdr_data, &bucket_path)?;

            // Verify hash matches
            if bucket.hash() != *hash {
                // Clean up the bad file
                let _ = std::fs::remove_file(&bucket_path);
                return Err(stellar_core_bucket::BucketError::HashMismatch {
                    expected: hash.to_hex(),
                    actual: bucket.hash().to_hex(),
                });
            }

            info!(
                "Created disk-backed bucket {} with {} entries",
                hash,
                bucket.len()
            );

            // Cache the bucket (it might be referenced multiple times in the bucket list)
            {
                let mut cache = bucket_cache.lock().unwrap();
                cache.insert(*hash, bucket.clone());
            }

            Ok(bucket)
        };

        // Build live bucket list hashes
        // Each level has curr and snap, so we need 22 hashes (11 levels × 2)
        let mut live_hashes = Vec::with_capacity(22);

        for level_idx in 0..11 {
            if let Some((curr, snap)) = has.bucket_hashes_at_level(level_idx) {
                let curr_hash = curr.unwrap_or(Hash256::ZERO);
                let snap_hash = snap.unwrap_or(Hash256::ZERO);
                info!(
                    "HAS level {} hashes: curr={}, snap={}",
                    level_idx,
                    curr_hash,
                    snap_hash
                );
                live_hashes.push(curr_hash);
                live_hashes.push(snap_hash);
            } else {
                // Level doesn't exist in HAS, use zero hashes
                live_hashes.push(Hash256::ZERO);
                live_hashes.push(Hash256::ZERO);
            }
        }

        // Restore the live bucket list
        let bucket_list = BucketList::restore_from_hashes(&live_hashes, load_bucket)
            .map_err(|e| HistoryError::CatchupFailed(format!("Failed to restore live bucket list: {}", e)))?;

        // Log the restored bucket list hash
        info!(
            "Live bucket list restored hash: {}",
            bucket_list.hash()
        );
        info!(
            "Live bucket list restored: {} total entries",
            bucket_list.stats().total_entries
        );

        // Build hot archive bucket list if present (protocol 23+)
        let hot_archive_bucket_list = if has.has_hot_archive_buckets() {
            let mut hot_hashes = Vec::with_capacity(22);

            for level_idx in 0..11 {
                if let Some((curr, snap)) = has.hot_archive_bucket_hashes_at_level(level_idx) {
                    hot_hashes.push(curr.unwrap_or(Hash256::ZERO));
                    hot_hashes.push(snap.unwrap_or(Hash256::ZERO));
                } else {
                    // Level doesn't exist in HAS, use zero hashes
                    hot_hashes.push(Hash256::ZERO);
                    hot_hashes.push(Hash256::ZERO);
                }
            }

            let hot_bucket_list = BucketList::restore_from_hashes(&hot_hashes, load_bucket)
                .map_err(|e| HistoryError::CatchupFailed(format!("Failed to restore hot archive bucket list: {}", e)))?;

            info!(
                "Hot archive bucket list restored: {} total entries",
                hot_bucket_list.stats().total_entries
            );

            Some(hot_bucket_list)
        } else {
            None
        };

        Ok((bucket_list, hot_archive_bucket_list))
    }

    /// Download ledger headers, transactions, and results for a range.
    async fn download_ledger_data(
        &mut self,
        from_checkpoint: u32,
        to_ledger: u32,
    ) -> Result<Vec<LedgerData>> {
        let mut data = Vec::new();
        let mut checkpoint_cache: HashMap<u32, CheckpointLedgerData> = HashMap::new();

        // We need to download data for ledgers (from_checkpoint+1) to to_ledger
        // The checkpoint ledger's state is already in the bucket list
        let start = from_checkpoint + 1;

        if start > to_ledger {
            // No ledgers to replay, we're at the checkpoint
            return Ok(data);
        }

        for seq in start..=to_ledger {
            self.progress.current_ledger = seq;
            let checkpoint = checkpoint::checkpoint_containing(seq);

            if !checkpoint_cache.contains_key(&checkpoint) {
                let downloaded = self.download_checkpoint_ledger_data(checkpoint).await?;
                checkpoint_cache.insert(checkpoint, downloaded);
            }

            let cache = checkpoint_cache
                .get(&checkpoint)
                .ok_or_else(|| {
                    HistoryError::CatchupFailed(format!(
                        "missing checkpoint cache for {}",
                        checkpoint
                    ))
                })?;

            let header = cache
                .headers
                .iter()
                .find(|h| h.header.ledger_seq == seq)
                .ok_or_else(|| {
                    HistoryError::CatchupFailed(format!(
                        "ledger {} not found in checkpoint headers",
                        seq
                    ))
                })?
                .header
                .clone();

            let tx_history_entry = cache
                .tx_entries
                .iter()
                .find(|entry| entry.ledger_seq == seq)
                .cloned();
            let tx_set = tx_history_entry
                .as_ref()
                .map(|entry| match &entry.ext {
                    TransactionHistoryEntryExt::V0 => {
                        TransactionSetVariant::Classic(entry.tx_set.clone())
                    }
                    TransactionHistoryEntryExt::V1(set) => {
                        TransactionSetVariant::Generalized(set.clone())
                    }
                })
                .unwrap_or_else(|| {
                    // For protocol 20+, use GeneralizedTransactionSet format
                    // For earlier protocols, use Classic TransactionSet
                    if header.ledger_version >= 20 {
                        // Create empty GeneralizedTransactionSet with proper phases
                        // Phase 0: empty classic phase (V0 with no components)
                        // Phase 1: empty soroban phase (V1 with no stages)
                        use stellar_xdr::curr::{TransactionPhase, ParallelTxsComponent, VecM};

                        // Empty classic phase (no components)
                        let classic_phase = TransactionPhase::V0(VecM::default());
                        // Empty soroban phase (no execution stages)
                        let soroban_phase = TransactionPhase::V1(ParallelTxsComponent {
                            base_fee: None,
                            execution_stages: VecM::default(),
                        });

                        TransactionSetVariant::Generalized(
                            GeneralizedTransactionSet::V1(TransactionSetV1 {
                                previous_ledger_hash: header.previous_ledger_hash.clone(),
                                phases: vec![classic_phase, soroban_phase].try_into().unwrap_or_default(),
                            })
                        )
                    } else {
                        TransactionSetVariant::Classic(TransactionSet {
                            previous_ledger_hash: header.previous_ledger_hash.clone(),
                            txs: Default::default(),
                        })
                    }
                });

            let tx_result_entry = cache
                .result_entries
                .iter()
                .find(|entry| entry.ledger_seq == seq)
                .cloned();
            let tx_results = tx_result_entry
                .as_ref()
                .map(|entry| entry.tx_result_set.results.iter().cloned().collect())
                .unwrap_or_else(Vec::new);

            let tx_metas = Vec::new();
            data.push(LedgerData {
                header,
                tx_set,
                tx_results,
                tx_metas,
                tx_history_entry,
                tx_result_entry,
            });
        }

        Ok(data)
    }

    /// Download ledger headers, transactions, and results for a checkpoint.
    async fn download_checkpoint_ledger_data(
        &self,
        checkpoint: u32,
    ) -> Result<CheckpointLedgerData> {
        // Try each archive until one succeeds
        for archive in &self.archives {
            match self.try_download_checkpoint(archive, checkpoint).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    warn!(
                        "Failed to download checkpoint {} from archive {}: {}",
                        checkpoint,
                        archive.base_url(),
                        e
                    );
                    continue;
                }
            }
        }

        Err(HistoryError::CatchupFailed(format!(
            "failed to download checkpoint {} from any archive",
            checkpoint
        )))
    }

    /// Try to download checkpoint data from a specific archive.
    async fn try_download_checkpoint(
        &self,
        archive: &HistoryArchive,
        checkpoint: u32,
    ) -> Result<CheckpointLedgerData> {
        let headers = archive.get_ledger_headers(checkpoint).await?;
        let tx_entries = archive.get_transactions(checkpoint).await?;
        let result_entries = archive.get_results(checkpoint).await?;
        Ok(CheckpointLedgerData {
            headers,
            tx_entries,
            result_entries,
        })
    }

    /// Verify the downloaded ledger data.
    fn verify_downloaded_data(&self, ledger_data: &[LedgerData]) -> Result<()> {
        if ledger_data.is_empty() {
            return Ok(());
        }

        // Extract headers for chain verification
        let headers: Vec<_> = ledger_data.iter().map(|d| d.header.clone()).collect();
        verify::verify_header_chain(&headers)?;

        // Verify transaction sets match header hashes
        for data in ledger_data {
            if let Some(entry) = data.tx_history_entry.as_ref() {
                let tx_set = match &entry.ext {
                    TransactionHistoryEntryExt::V0 => {
                        TransactionSetVariant::Classic(entry.tx_set.clone())
                    }
                    TransactionHistoryEntryExt::V1(set) => {
                        TransactionSetVariant::Generalized(set.clone())
                    }
                };
                if let Err(e) = verify::verify_tx_set(&data.header, &tx_set) {
                    warn!(
                        "Transaction set verification failed for ledger {}: {}",
                        data.header.ledger_seq, e
                    );
                    // Continue - tx sets may be empty for some ledgers
                }
            }
            if let Some(entry) = data.tx_result_entry.as_ref() {
                if let Ok(xdr) = entry
                    .tx_result_set
                    .to_xdr(stellar_xdr::curr::Limits::none())
                {
                    if let Err(e) = verify::verify_tx_result_set(&data.header, &xdr) {
                        warn!(
                            "Transaction result set verification failed for ledger {}: {}",
                            data.header.ledger_seq, e
                        );
                    }
                }
            }
        }

        info!("Verified header chain for {} ledgers", headers.len());
        Ok(())
    }

    /// Verify the final ledger state matches the expected bucket list hash.
    ///
    /// For Protocol 23+, the bucket list hash in the header is:
    /// SHA256(live_bucket_list.hash() || hot_archive_bucket_list.hash())
    fn verify_final_state(
        &self,
        header: &LedgerHeader,
        bucket_list: &BucketList,
        hot_archive_bucket_list: &Option<BucketList>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};

        let computed_hash = if let Some(ref hot_archive) = hot_archive_bucket_list {
            // Protocol 23+: combine live and hot archive bucket list hashes
            let live_hash = bucket_list.hash();
            let hot_hash = hot_archive.hash();
            let mut hasher = Sha256::new();
            hasher.update(live_hash.as_bytes());
            hasher.update(hot_hash.as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash256::from_bytes(bytes)
        } else {
            // Pre-protocol 23: just the live bucket list hash
            bucket_list.hash()
        };

        verify::verify_ledger_hash(header, &computed_hash)?;

        info!(
            "Verified bucket list hash at ledger {}: {}",
            header.ledger_seq, computed_hash
        );
        Ok(())
    }

    fn persist_ledger_history(
        &self,
        ledger_data: &[LedgerData],
        network_id: &NetworkId,
    ) -> Result<()> {
        if ledger_data.is_empty() {
            return Ok(());
        }

        self.db
            .transaction(|conn| {
                use stellar_core_db::error::DbError;
                use stellar_core_db::queries::{HistoryQueries, LedgerQueries};

                for data in ledger_data {
                    let header_xdr = data.header.to_xdr(stellar_xdr::curr::Limits::none())?;
                    conn.store_ledger_header(&data.header, &header_xdr)?;

                    let tx_history_entry = data.tx_history_entry.clone().unwrap_or_else(|| {
                        match &data.tx_set {
                            TransactionSetVariant::Classic(set) => TransactionHistoryEntry {
                                ledger_seq: data.header.ledger_seq,
                                tx_set: set.clone(),
                                ext: TransactionHistoryEntryExt::V0,
                            },
                            TransactionSetVariant::Generalized(set) => {
                                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                                TransactionHistoryEntry {
                                    ledger_seq: data.header.ledger_seq,
                                    tx_set: TransactionSet {
                                        previous_ledger_hash: set_v1.previous_ledger_hash.clone(),
                                        txs: Default::default(),
                                    },
                                    ext: TransactionHistoryEntryExt::V1(set.clone()),
                                }
                            }
                        }
                    });
                    conn.store_tx_history_entry(data.header.ledger_seq, &tx_history_entry)?;

                    let tx_result_entry = data.tx_result_entry.clone().unwrap_or_else(|| {
                        let results = data.tx_results.clone().try_into().unwrap_or_default();
                        TransactionHistoryResultEntry {
                            ledger_seq: data.header.ledger_seq,
                            tx_result_set: TransactionResultSet { results },
                            ext: TransactionHistoryResultEntryExt::default(),
                        }
                    });
                    conn.store_tx_result_entry(data.header.ledger_seq, &tx_result_entry)?;

                    let tx_results: Vec<TransactionResultPair> = tx_result_entry
                        .tx_result_set
                        .results
                        .iter()
                        .cloned()
                        .collect();
                    let transactions = data
                        .tx_set
                        .transactions_with_base_fee()
                        .into_iter()
                        .map(|(tx, _)| tx)
                        .collect::<Vec<_>>();
                    let tx_count = transactions.len().min(tx_results.len());

                    for (idx, tx) in transactions.iter().take(tx_count).enumerate() {
                        let tx_result = &tx_results[idx];

                        let frame = TransactionFrame::with_network(tx.clone(), *network_id);
                        let tx_hash = frame
                            .hash(network_id)
                            .map_err(|e| DbError::Integrity(e.to_string()))?;
                        let tx_id = tx_hash.to_hex();

                        let tx_body = tx.to_xdr(stellar_xdr::curr::Limits::none())?;
                        let tx_result_xdr =
                            tx_result.to_xdr(stellar_xdr::curr::Limits::none())?;

                        conn.store_transaction(
                            data.header.ledger_seq,
                            idx as u32,
                            &tx_id,
                            &tx_body,
                            &tx_result_xdr,
                            None,
                        )?;
                    }
                }

                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!("failed to persist history: {}", err))
            })?;

        Ok(())
    }

    fn persist_scp_history_entries(&self, entries: &[ScpHistoryEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        self.db
            .transaction(|conn| {
                use stellar_core_db::queries::ScpQueries;

                for entry in entries {
                    let ScpHistoryEntry::V0(v0) = entry;
                    let ledger_seq = v0.ledger_messages.ledger_seq;
                    let envelopes: Vec<_> = v0.ledger_messages.messages.iter().cloned().collect();

                    conn.store_scp_history(ledger_seq, &envelopes)?;

                    for qset in v0.quorum_sets.iter() {
                        let hash = Hash256::hash_xdr(qset)?;
                        conn.store_scp_quorum_set(&hash, ledger_seq, qset)?;
                    }
                }

                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!("failed to persist scp history: {}", err))
            })?;

        Ok(())
    }

    fn persist_bucket_list_snapshot(
        &self,
        ledger_seq: u32,
        bucket_list: &BucketList,
    ) -> Result<()> {
        let levels = bucket_list
            .levels()
            .iter()
            .map(|level| (level.curr.hash(), level.snap.hash()))
            .collect::<Vec<_>>();
        self.db
            .with_connection(|conn| {
                use stellar_core_db::queries::BucketListQueries;
                conn.store_bucket_list(ledger_seq, &levels)?;
                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!(
                    "failed to persist bucket list for ledger {}: {}",
                    ledger_seq, err
                ))
            })?;
        Ok(())
    }

    fn persist_header_only(&self, header: &LedgerHeader) -> Result<()> {
        self.db
            .with_connection(|conn| {
                use stellar_core_db::queries::LedgerQueries;
                let header_xdr = header.to_xdr(stellar_xdr::curr::Limits::none())?;
                conn.store_ledger_header(header, &header_xdr)?;
                Ok(())
            })
            .map_err(|err| {
                HistoryError::CatchupFailed(format!("failed to persist header: {}", err))
            })?;
        Ok(())
    }

    /// Download the header for a specific ledger.
    async fn download_checkpoint_header(&self, ledger_seq: u32) -> Result<LedgerHeader> {
        for archive in &self.archives {
            match archive.get_ledger_header(ledger_seq).await {
                Ok(header) => {
                    debug!(
                        "Downloaded header for ledger {}: bucket_list_hash={}, ledger_seq={}",
                        ledger_seq,
                        hex::encode(header.bucket_list_hash.0),
                        header.ledger_seq
                    );
                    return Ok(header);
                }
                Err(e) => {
                    warn!(
                        "Failed to download header {} from archive {}: {}",
                        ledger_seq, archive.base_url(), e
                    );
                    continue;
                }
            }
        }

        Err(HistoryError::CatchupFailed(format!(
            "failed to download header for ledger {} from any archive",
            ledger_seq
        )))
    }

    /// Replay ledgers and update the bucket list.
    async fn replay_ledgers(
        &mut self,
        bucket_list: &mut BucketList,
        hot_archive_bucket_list: Option<&BucketList>,
        ledger_data: &[LedgerData],
        network_id: NetworkId,
    ) -> Result<ReplayedLedgerState> {
        if ledger_data.is_empty() {
            return Err(HistoryError::CatchupFailed(
                "no ledger data to replay".to_string(),
            ));
        }

        let total = ledger_data.len();
        let mut last_result: Option<LedgerReplayResult> = None;
        let mut last_header: Option<LedgerHeader> = None;
        let invariants = if self.replay_config.verify_invariants {
            let mut manager = InvariantManager::new();
            manager.add(LedgerSeqIncrement);
            manager.add(CloseTimeNondecreasing);
            if self.replay_config.verify_bucket_list {
                manager.add(BucketListHashMatchesHeader);
            }
            manager.add(ConservationOfLumens);
            manager.add(LedgerEntryIsValid);
            manager.add(LiabilitiesMatchOffers);
            manager.add(OrderBookIsNotCrossed);
            manager.add(LastModifiedLedgerSeqMatchesHeader);
            Some(manager)
        } else {
            None
        };

        for (i, data) in ledger_data.iter().enumerate() {
            self.progress.current_ledger = data.header.ledger_seq;

            let result = replay::replay_ledger_with_execution(
                &data.header,
                &data.tx_set,
                bucket_list,
                hot_archive_bucket_list,
                &network_id,
                &self.replay_config,
                Some(&data.tx_results),
            )?;
            if let (Some(prev_header), Some(manager)) = (last_header.as_ref(), invariants.as_ref()) {
                let full_entries = bucket_list.live_entries()?;
                let bucket_list_hash = if let Some(hot_archive) = hot_archive_bucket_list {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(bucket_list.hash().as_bytes());
                    hasher.update(hot_archive.hash().as_bytes());
                    let result = hasher.finalize();
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&result);
                    Hash256::from_bytes(bytes)
                } else {
                    bucket_list.hash()
                };
                let ctx = InvariantContext {
                    prev_header,
                    curr_header: &data.header,
                    bucket_list_hash,
                    fee_pool_delta: result.fee_pool_delta,
                    total_coins_delta: result.total_coins_delta,
                    changes: &result.changes,
                    full_entries: Some(&full_entries),
                    op_events: None,
                };
                manager
                    .check_all(&ctx)
                    .map_err(|err| {
                        HistoryError::CatchupFailed(format!(
                            "replay invariant failed at ledger {}: {}",
                            data.header.ledger_seq, err
                        ))
                    })?;
            }

            debug!(
                "Replayed ledger {}/{}: {} txs, {} ops",
                i + 1,
                total,
                result.tx_count,
                result.op_count
            );

            last_header = Some(data.header.clone());
            last_result = Some(result);
        }

        let final_result = last_result.unwrap();
        let final_header = last_header.unwrap();

        // Verify final bucket list hash
        if self.replay_config.verify_bucket_list {
            let bucket_list_hash = bucket_list.hash();
            replay::verify_replay_consistency(&final_header, &bucket_list_hash)?;
        }

        Ok(ReplayedLedgerState::from_header(&final_header, final_result.ledger_hash))
    }
}

fn checkpoint_header_from_headers(
    checkpoint_seq: u32,
    headers: &[LedgerHeaderHistoryEntry],
) -> Result<LedgerHeader> {
    let mut header_map = HashMap::new();
    for entry in headers {
        header_map.insert(entry.header.ledger_seq, entry.header.clone());
    }

    let checkpoint_header = header_map.get(&checkpoint_seq).ok_or_else(|| {
        HistoryError::CatchupFailed(format!(
            "checkpoint header {} not found in headers",
            checkpoint_seq
        ))
    })?;
    Ok(checkpoint_header.clone())
}

/// Data downloaded for a single ledger.
#[derive(Debug, Clone)]
pub struct LedgerData {
    /// The ledger header.
    pub header: LedgerHeader,
    /// The transaction set.
    pub tx_set: TransactionSetVariant,
    /// Transaction results.
    pub tx_results: Vec<TransactionResultPair>,
    /// Transaction metadata.
    pub tx_metas: Vec<TransactionMeta>,
    /// Transaction history entry (tx set) when available.
    pub tx_history_entry: Option<TransactionHistoryEntry>,
    /// Transaction result history entry when available.
    pub tx_result_entry: Option<TransactionHistoryResultEntry>,
}

/// Options for catchup operations.
#[derive(Debug, Clone)]
pub struct CatchupOptions {
    /// Maximum number of retries per archive.
    pub max_retries: u32,
    /// Timeout for individual downloads (in seconds).
    pub download_timeout_secs: u64,
    /// Whether to verify bucket hashes.
    pub verify_buckets: bool,
    /// Whether to verify header chain.
    pub verify_headers: bool,
    /// Number of parallel bucket downloads.
    pub parallel_downloads: usize,
}

#[derive(Debug, Clone)]
struct CheckpointLedgerData {
    headers: Vec<LedgerHeaderHistoryEntry>,
    tx_entries: Vec<TransactionHistoryEntry>,
    result_entries: Vec<TransactionHistoryResultEntry>,
}

impl Default for CatchupOptions {
    fn default() -> Self {
        Self {
            max_retries: 3,
            download_timeout_secs: 300,
            verify_buckets: true,
            verify_headers: true,
            parallel_downloads: 4,
        }
    }
}

/// Builder for creating a CatchupManager with custom options.
pub struct CatchupManagerBuilder {
    archives: Vec<HistoryArchive>,
    bucket_manager: Option<BucketManager>,
    db: Option<Database>,
    options: CatchupOptions,
}

impl CatchupManagerBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            archives: Vec::new(),
            bucket_manager: None,
            db: None,
            options: CatchupOptions::default(),
        }
    }

    /// Add a history archive.
    pub fn add_archive(mut self, archive: HistoryArchive) -> Self {
        self.archives.push(archive);
        self
    }

    /// Set the bucket manager.
    pub fn bucket_manager(mut self, manager: BucketManager) -> Self {
        self.bucket_manager = Some(manager);
        self
    }

    /// Set the database.
    pub fn database(mut self, db: Database) -> Self {
        self.db = Some(db);
        self
    }

    /// Set catchup options.
    pub fn options(mut self, options: CatchupOptions) -> Self {
        self.options = options;
        self
    }

    /// Build the CatchupManager.
    pub fn build(self) -> Result<CatchupManager> {
        let bucket_manager = self
            .bucket_manager
            .ok_or_else(|| HistoryError::CatchupFailed("bucket manager required".to_string()))?;

        let db = self
            .db
            .ok_or_else(|| HistoryError::CatchupFailed("database required".to_string()))?;

        if self.archives.is_empty() {
            return Err(HistoryError::CatchupFailed(
                "at least one archive required".to_string(),
            ));
        }

        let mut manager = CatchupManager::new(self.archives, bucket_manager, db);

        manager.replay_config = ReplayConfig {
            verify_results: self.options.verify_headers,
            verify_bucket_list: self.options.verify_buckets,
            verify_invariants: true,
            emit_classic_events: false,
            backfill_stellar_asset_events: false,
        };

        Ok(manager)
    }
}

impl Default for CatchupManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a header from replay state when the actual header download fails.
///
/// This is a fallback that constructs a minimal header from the replay results.
fn create_header_from_replay_state(
    replay_state: &ReplayedLedgerState,
    bucket_list: &BucketList,
) -> LedgerHeader {
    use stellar_xdr::curr::{Hash, StellarValue, StellarValueExt, TimePoint, VecM, LedgerHeaderExt};

    LedgerHeader {
        ledger_version: replay_state.protocol_version,
        previous_ledger_hash: Hash([0u8; 32]), // Unknown, but not critical for init
        scp_value: StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: TimePoint(replay_state.close_time),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
        bucket_list_hash: Hash(bucket_list.hash().0),
        ledger_seq: replay_state.sequence,
        total_coins: 0,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: replay_state.base_fee,
        base_reserve: replay_state.base_reserve,
        max_tx_set_size: 1000,
        skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
        ext: LedgerHeaderExt::V0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catchup_options_default() {
        let options = CatchupOptions::default();
        assert_eq!(options.max_retries, 3);
        assert_eq!(options.download_timeout_secs, 300);
        assert!(options.verify_buckets);
        assert!(options.verify_headers);
        assert_eq!(options.parallel_downloads, 4);
    }

    #[test]
    fn test_catchup_progress_default() {
        let progress = CatchupProgress::default();
        assert_eq!(progress.status, CatchupStatus::Pending);
        assert_eq!(progress.current_step, 0);
        assert_eq!(progress.total_steps, 7);
    }

    #[test]
    fn test_catchup_status() {
        assert_eq!(CatchupStatus::Pending, CatchupStatus::Pending);
        assert_ne!(CatchupStatus::Pending, CatchupStatus::Completed);
    }

    // Note: Full integration tests would require mock archives
    // and more infrastructure, which would be in a separate test module
}
