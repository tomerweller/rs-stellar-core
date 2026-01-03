//! LedgerManager - Core ledger state management.
//!
//! The LedgerManager is responsible for:
//! - Managing the current ledger state
//! - Loading and storing ledger entries
//! - Coordinating ledger close operations
//! - Maintaining consistency between bucket list and database

use crate::{
    close::{LedgerCloseData, LedgerCloseResult, LedgerCloseStats, TransactionSetVariant, UpgradeContext},
    delta::{EntryChange, LedgerDelta},
    execution::{execute_transaction_set, OperationInvariantRunner, TransactionExecutionResult},
    header::{compute_header_hash, create_next_header},
    snapshot::{LedgerSnapshot, SnapshotHandle, SnapshotManager},
    LedgerError, Result,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use stellar_core_bucket::{BucketList, BucketManager};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_db::Database;
use stellar_core_tx::soroban::SorobanConfig;
use stellar_core_invariant::{
    AccountSubEntriesCountIsValid, BucketListHashMatchesHeader, CloseTimeNondecreasing,
    ConservationOfLumens, ConstantProductInvariant, Invariant, InvariantContext, InvariantManager,
    LastModifiedLedgerSeqMatchesHeader, LedgerEntryIsValid, LedgerEntryChange, LedgerSeqIncrement,
    LiabilitiesMatchOffers, OrderBookIsNotCrossed, SponsorshipCountIsValid,
};
use stellar_xdr::curr::{
    AccountEntry, AccountId, BucketListType, ConfigSettingEntry, ConfigSettingId,
    ConfigSettingScpTiming, GeneralizedTransactionSet, Hash, LedgerCloseMeta, LedgerCloseMetaExt,
    LedgerCloseMetaV2, LedgerEntry, LedgerEntryData, LedgerHeader, LedgerHeaderHistoryEntry,
    LedgerHeaderHistoryEntryExt, LedgerKey, LedgerKeyConfigSetting, Limits, ScpHistoryEntry,
    TransactionPhase, TransactionResultMetaV1, TransactionSetV1, TxSetComponent,
    TxSetComponentTxsMaybeDiscountedFee, UpgradeEntryMeta, VecM, WriteXdr,
};
use tracing::{debug, info, warn};

/// Configuration for the LedgerManager.
#[derive(Debug, Clone)]
pub struct LedgerManagerConfig {
    /// Maximum number of snapshots to retain.
    pub max_snapshots: usize,

    /// Whether to validate bucket list hashes.
    pub validate_bucket_hash: bool,

    /// Whether to validate invariants on ledger close.
    pub validate_invariants: bool,

    /// Whether to persist to database.
    pub persist_to_db: bool,
}

impl Default for LedgerManagerConfig {
    fn default() -> Self {
        Self {
            max_snapshots: 10,
            validate_bucket_hash: true,
            validate_invariants: true,
            persist_to_db: true,
        }
    }
}

/// Internal state of the ledger manager.
struct LedgerState {
    /// Current ledger header.
    header: LedgerHeader,

    /// Hash of the current header.
    header_hash: Hash256,

    /// Whether the ledger has been initialized.
    initialized: bool,
}

/// The core ledger manager.
///
/// This manages all ledger state, coordinating between:
/// - In-memory state cache
/// - Bucket list for Merkle tree integrity
/// - Database for persistence
pub struct LedgerManager {
    /// Database for persistence.
    db: Database,

    /// Bucket manager for bucket list operations.
    bucket_manager: Arc<BucketManager>,

    /// Bucket list for ledger state (wrapped in Arc for sharing with snapshots).
    bucket_list: Arc<RwLock<BucketList>>,

    /// Network passphrase for transaction signing.
    network_passphrase: String,

    /// Network ID derived from passphrase.
    network_id: NetworkId,

    /// Current ledger state.
    state: RwLock<LedgerState>,

    /// In-memory entry cache.
    entry_cache: RwLock<HashMap<Vec<u8>, LedgerEntry>>,

    /// Snapshot manager.
    snapshots: SnapshotManager,

    /// Invariant manager.
    invariants: RwLock<InvariantManager>,

    /// Configuration.
    config: LedgerManagerConfig,
}

impl LedgerManager {
    /// Create a new ledger manager.
    ///
    /// The ledger starts uninitialized and must be initialized via
    /// `initialize_from_buckets` or by loading from the database.
    pub fn new(
        db: Database,
        bucket_manager: Arc<BucketManager>,
        network_passphrase: String,
    ) -> Self {
        Self::with_config(db, bucket_manager, network_passphrase, LedgerManagerConfig::default())
    }

    /// Create a new ledger manager with custom configuration.
    pub fn with_config(
        db: Database,
        bucket_manager: Arc<BucketManager>,
        network_passphrase: String,
        config: LedgerManagerConfig,
    ) -> Self {
        let network_id = NetworkId::from_passphrase(&network_passphrase);
        let mut invariants = InvariantManager::new();
        invariants.add(LedgerSeqIncrement);
        invariants.add(CloseTimeNondecreasing);
        invariants.add(BucketListHashMatchesHeader);
        invariants.add(ConservationOfLumens);
        invariants.add(LedgerEntryIsValid);
        invariants.add(SponsorshipCountIsValid);
        invariants.add(AccountSubEntriesCountIsValid);
        invariants.add(LiabilitiesMatchOffers);
        invariants.add(OrderBookIsNotCrossed);
        invariants.add(ConstantProductInvariant);
        invariants.add(LastModifiedLedgerSeqMatchesHeader);

        Self {
            db,
            bucket_manager,
            bucket_list: Arc::new(RwLock::new(BucketList::default())),
            network_passphrase,
            network_id,
            state: RwLock::new(LedgerState {
                header: create_genesis_header(),
                header_hash: Hash256::ZERO,
                initialized: false,
            }),
            entry_cache: RwLock::new(HashMap::new()),
            snapshots: SnapshotManager::new(config.max_snapshots),
            invariants: RwLock::new(invariants),
            config,
        }
    }

    /// Get the network ID.
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }

    /// Get the network passphrase.
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Check if the ledger has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.read().initialized
    }

    /// Get the current ledger sequence number.
    pub fn current_ledger_seq(&self) -> u32 {
        self.state.read().header.ledger_seq
    }

    /// Set the current ledger sequence number.
    /// This is used when fast-forwarding to catch up with the network.
    pub fn set_ledger_sequence(&self, seq: u32) {
        let mut state = self.state.write();
        state.header.ledger_seq = seq;
        state.initialized = true;
        tracing::info!(ledger_seq = seq, "Fast-forwarded ledger sequence");
    }

    /// Get the current ledger header.
    pub fn current_header(&self) -> LedgerHeader {
        self.state.read().header.clone()
    }

    /// Get the current header hash.
    pub fn current_header_hash(&self) -> Hash256 {
        self.state.read().header_hash
    }

    /// Get the SCP timing configuration from the current ledger state.
    pub fn scp_timing(&self) -> Option<ConfigSettingScpTiming> {
        if !self.is_initialized() {
            return None;
        }

        let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ScpTiming,
        });
        let key_bytes = key.to_xdr(Limits::none()).ok()?;

        if let Some(entry) = self.entry_cache.read().get(&key_bytes) {
            return extract_scp_timing(entry);
        }

        let entry = self.bucket_list.read().get(&key).ok()??;
        extract_scp_timing(&entry)
    }

    /// Get the bucket list hash.
    pub fn bucket_list_hash(&self) -> Hash256 {
        self.bucket_list.read().hash()
    }

    /// Get bucket list level hashes (curr, snap) for persistence.
    pub fn bucket_list_levels(&self) -> Vec<(Hash256, Hash256)> {
        let bucket_list = self.bucket_list.read();
        bucket_list
            .levels()
            .iter()
            .map(|level| (level.curr.hash(), level.snap.hash()))
            .collect()
    }

    /// Load a ledger entry by key.
    pub fn load_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        // First check the cache
        let key_bytes = key.to_xdr(Limits::none())?;
        if let Some(entry) = self.entry_cache.read().get(&key_bytes) {
            return Ok(Some(entry.clone()));
        }

        // Then check the bucket list
        let entry = self.bucket_list.read().get(key)?;

        // Cache the result if found
        if let Some(ref entry) = entry {
            self.entry_cache.write().insert(key_bytes, entry.clone());
        }

        Ok(entry)
    }

    /// Load an account by ID.
    pub fn load_account(&self, id: &AccountId) -> Result<Option<AccountEntry>> {
        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: id.clone(),
        });

        if let Some(entry) = self.load_entry(&key)? {
            if let LedgerEntryData::Account(account) = entry.data {
                return Ok(Some(account));
            }
        }

        Ok(None)
    }

    /// Initialize the ledger from bucket list state.
    ///
    /// This is used during catchup from history archives.
    ///
    /// # Arguments
    ///
    /// * `bucket_list` - The live bucket list
    /// * `hot_archive_bucket_list` - The hot archive bucket list (protocol 23+)
    /// * `header` - The ledger header to initialize with
    pub fn initialize_from_buckets(
        &self,
        bucket_list: BucketList,
        hot_archive_bucket_list: Option<BucketList>,
        header: LedgerHeader,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};

        let mut state = self.state.write();
        if state.initialized {
            return Err(LedgerError::AlreadyInitialized);
        }

        // Compute combined bucket list hash for verification
        let live_hash = bucket_list.hash();
        let computed_hash = if let Some(ref hot_archive) = hot_archive_bucket_list {
            // Protocol 23+: combine both hashes
            let hot_hash = hot_archive.hash();
            let mut hasher = Sha256::new();
            hasher.update(live_hash.as_bytes());
            hasher.update(hot_hash.as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Hash256::from_bytes(bytes)
        } else {
            // Pre-protocol 23: just live hash
            live_hash
        };

        let expected_hash = Hash256::from(header.bucket_list_hash.0);

        // Debug: log the bucket level hashes
        tracing::debug!(
            header_ledger_seq = header.ledger_seq,
            expected = %expected_hash.to_hex(),
            computed = %computed_hash.to_hex(),
            live_hash = %live_hash.to_hex(),
            hot_archive = hot_archive_bucket_list.is_some(),
            "Verifying bucket list hash"
        );
        for level_idx in 0..bucket_list.levels().len() {
            if let Some(level) = bucket_list.level(level_idx) {
                tracing::debug!(
                    level = level_idx,
                    curr_hash = %level.curr.hash().to_hex(),
                    snap_hash = %level.snap.hash().to_hex(),
                    level_hash = %level.hash().to_hex(),
                    "Live level hash"
                );
            }
        }
        if let Some(ref hot_archive) = hot_archive_bucket_list {
            tracing::debug!(
                hot_archive_hash = %hot_archive.hash().to_hex(),
                "Hot archive bucket list hash"
            );
        }

        if self.config.validate_bucket_hash && computed_hash != expected_hash {
            return Err(LedgerError::HashMismatch {
                expected: expected_hash.to_hex(),
                actual: computed_hash.to_hex(),
            });
        }

        // Compute header hash
        let header_hash = compute_header_hash(&header)?;

        // Update state
        *self.bucket_list.write() = bucket_list;
        state.header = header;
        state.header_hash = header_hash;
        state.initialized = true;

        // Clear cache
        self.entry_cache.write().clear();

        info!(
            ledger_seq = state.header.ledger_seq,
            "Ledger initialized from buckets"
        );

        Ok(())
    }

    /// Reinitialize the ledger from bucket list state.
    ///
    /// This is used when catchup needs to reset state while the ledger manager
    /// was already initialized (e.g., after falling behind in live mode).
    pub fn reinitialize_from_buckets(
        &self,
        bucket_list: BucketList,
        hot_archive_bucket_list: Option<BucketList>,
        header: LedgerHeader,
    ) -> Result<()> {
        self.reset_for_catchup();
        self.initialize_from_buckets(bucket_list, hot_archive_bucket_list, header)
    }

    /// Initialize the ledger from bucket list state, skipping hash verification.
    ///
    /// This is a temporary workaround for debugging hash mismatches.
    pub fn initialize_from_buckets_skip_verify(
        &self,
        bucket_list: BucketList,
        header: LedgerHeader,
    ) -> Result<()> {
        let mut state = self.state.write();
        if state.initialized {
            return Err(LedgerError::AlreadyInitialized);
        }

        tracing::warn!(
            ledger_seq = header.ledger_seq,
            "Initializing ledger WITHOUT bucket hash verification"
        );

        // Compute header hash
        let header_hash = compute_header_hash(&header)?;

        // Update state
        *self.bucket_list.write() = bucket_list;
        state.header = header;
        state.header_hash = header_hash;
        state.initialized = true;

        // Clear cache
        self.entry_cache.write().clear();

        info!(
            ledger_seq = state.header.ledger_seq,
            "Ledger initialized from buckets (verification skipped)"
        );

        Ok(())
    }

    fn reset_for_catchup(&self) {
        *self.bucket_list.write() = BucketList::default();
        self.entry_cache.write().clear();
        self.snapshots.clear();

        let mut state = self.state.write();
        state.header = create_genesis_header();
        state.header_hash = Hash256::ZERO;
        state.initialized = false;
    }

    /// Apply a ledger from history (replay mode).
    ///
    /// This is used during catchup to replay historical ledgers.
    pub fn apply_ledger(
        &self,
        header: LedgerHeader,
        tx_set: TransactionSetVariant,
        _results: Vec<stellar_xdr::curr::TransactionResultPair>,
    ) -> Result<LedgerCloseResult> {
        let state = self.state.read();
        if !state.initialized {
            return Err(LedgerError::NotInitialized);
        }

        // Validate sequence
        let expected_seq = state.header.ledger_seq + 1;
        if header.ledger_seq != expected_seq {
            return Err(LedgerError::InvalidSequence {
                expected: expected_seq,
                actual: header.ledger_seq,
            });
        }

        // Validate previous hash
        let expected_prev = state.header_hash;
        let actual_prev = Hash256::from(header.previous_ledger_hash.0);
        if actual_prev != expected_prev {
            return Err(LedgerError::HashMismatch {
                expected: expected_prev.to_hex(),
                actual: actual_prev.to_hex(),
            });
        }

        drop(state);

        // In replay mode, we trust the header is correct
        // and just update our state to match
        let header_hash = compute_header_hash(&header)?;

        // Create close result
        let result = LedgerCloseResult::new(header.clone(), header_hash);

        // Update state
        let mut state = self.state.write();
        state.header = header;
        state.header_hash = header_hash;

        info!(
            ledger_seq = state.header.ledger_seq,
            "Applied historical ledger"
        );

        Ok(result)
    }

    /// Begin closing a new ledger.
    ///
    /// Returns a LedgerCloseContext for applying transactions and
    /// committing the ledger.
    pub fn begin_close(&self, close_data: LedgerCloseData) -> Result<LedgerCloseContext> {
        let state = self.state.read();
        if !state.initialized {
            return Err(LedgerError::NotInitialized);
        }

        // Validate sequence
        let expected_seq = state.header.ledger_seq + 1;
        if close_data.ledger_seq != expected_seq {
            return Err(LedgerError::InvalidSequence {
                expected: expected_seq,
                actual: close_data.ledger_seq,
            });
        }

        // Validate previous hash
        if close_data.prev_ledger_hash != state.header_hash {
            // Debug: Log header details to help diagnose hash mismatch
            tracing::error!(
                current_seq = state.header.ledger_seq,
                close_seq = close_data.ledger_seq,
                our_hash = %state.header_hash.to_hex(),
                network_prev_hash = %close_data.prev_ledger_hash.to_hex(),
                header_version = state.header.ledger_version,
                header_bucket_list_hash = %Hash256::from(state.header.bucket_list_hash.0).to_hex(),
                header_tx_result_hash = %Hash256::from(state.header.tx_set_result_hash.0).to_hex(),
                header_total_coins = state.header.total_coins,
                header_fee_pool = state.header.fee_pool,
                header_close_time = state.header.scp_value.close_time.0,
                header_tx_set_hash = %Hash256::from(state.header.scp_value.tx_set_hash.0).to_hex(),
                header_upgrades_count = state.header.scp_value.upgrades.len(),
                "Hash mismatch - our computed header hash differs from network's prev_ledger_hash"
            );
            return Err(LedgerError::HashMismatch {
                expected: state.header_hash.to_hex(),
                actual: close_data.prev_ledger_hash.to_hex(),
            });
        }

        // Create snapshot of current state for reading during close
        let snapshot = self.create_snapshot()?;

        let mut upgrade_ctx = UpgradeContext::new(state.header.ledger_version);
        for upgrade in &close_data.upgrades {
            upgrade_ctx.add_upgrade(upgrade.clone());
        }

        Ok(LedgerCloseContext {
            manager: self,
            close_data,
            prev_header: state.header.clone(),
            prev_header_hash: state.header_hash,
            delta: LedgerDelta::new(expected_seq),
            snapshot,
            stats: LedgerCloseStats::new(),
            upgrade_ctx,
            id_pool: state.header.id_pool,
            tx_results: Vec::new(),
            tx_result_metas: Vec::new(),
        })
    }

    /// Create a snapshot of the current ledger state.
    ///
    /// The snapshot includes a lookup function for entries not in the cache,
    /// which queries the bucket list for the entry.
    pub fn create_snapshot(&self) -> Result<SnapshotHandle> {
        let state = self.state.read();
        let entries = self.entry_cache.read().clone();

        let snapshot = LedgerSnapshot::new(
            state.header.clone(),
            state.header_hash,
            entries,
        );

        // Create a lookup function that queries the bucket list
        let bucket_list = self.bucket_list.clone();
        let lookup_fn: crate::snapshot::EntryLookupFn = Arc::new(move |key: &LedgerKey| {
            bucket_list.read().get(key).map_err(LedgerError::Bucket)
        });

        // Create a lookup function that queries the ledger header table
        let db = self.db.clone();
        let header_lookup_fn: crate::snapshot::LedgerHeaderLookupFn = Arc::new(move |seq: u32| {
            db.get_ledger_header(seq).map_err(LedgerError::from)
        });

        Ok(SnapshotHandle::with_lookups(
            snapshot,
            lookup_fn,
            header_lookup_fn,
        ))
    }

    /// Get a historical snapshot by sequence number.
    pub fn get_snapshot(&self, seq: u32) -> Option<SnapshotHandle> {
        self.snapshots.get(seq)
    }

    /// Commit a ledger close.
    ///
    /// This is called by LedgerCloseContext::commit().
    fn commit_close(
        &self,
        delta: LedgerDelta,
        new_header: LedgerHeader,
        new_header_hash: Hash256,
    ) -> Result<()> {
        // Note: Bucket list was already updated in LedgerCloseContext::commit()
        // Just validate the hash if configured
        if self.config.validate_bucket_hash {
            let bucket_list = self.bucket_list.read();
            let computed = bucket_list.hash();
            let expected = Hash256::from(new_header.bucket_list_hash.0);
            if computed != expected {
                return Err(LedgerError::HashMismatch {
                    expected: expected.to_hex(),
                    actual: computed.to_hex(),
                });
            }
        }

        // Update entry cache with changes
        {
            let mut cache = self.entry_cache.write();
            for change in delta.changes() {
                let key = change.key()?;
                let key_bytes = key.to_xdr(Limits::none())?;

                match change {
                    EntryChange::Created(entry) | EntryChange::Updated { current: entry, .. } => {
                        cache.insert(key_bytes, entry.clone());
                    }
                    EntryChange::Deleted { .. } => {
                        cache.remove(&key_bytes);
                    }
                }
            }
        }

        // Update state
        {
            let mut state = self.state.write();
            state.header = new_header;
            state.header_hash = new_header_hash;
        }

        Ok(())
    }

    /// Get the database handle.
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Get statistics about the current state.
    pub fn stats(&self) -> LedgerManagerStats {
        LedgerManagerStats {
            ledger_seq: self.current_ledger_seq(),
            cached_entries: self.entry_cache.read().len(),
            active_snapshots: self.snapshots.count(),
        }
    }

    /// Register an additional invariant to enforce on ledger close.
    pub fn add_invariant<I: Invariant + 'static>(&self, invariant: I) {
        self.invariants.write().add(invariant);
    }
}

/// Statistics about the ledger manager.
#[derive(Debug, Clone)]
pub struct LedgerManagerStats {
    /// Current ledger sequence.
    pub ledger_seq: u32,

    /// Number of entries in cache.
    pub cached_entries: usize,

    /// Number of active snapshots.
    pub active_snapshots: usize,
}

/// Context for closing a ledger.
///
/// This is returned by `LedgerManager::begin_close()` and provides
/// methods for applying transactions and committing the ledger.
pub struct LedgerCloseContext<'a> {
    manager: &'a LedgerManager,
    close_data: LedgerCloseData,
    prev_header: LedgerHeader,
    prev_header_hash: Hash256,
    delta: LedgerDelta,
    snapshot: SnapshotHandle,
    stats: LedgerCloseStats,
    upgrade_ctx: UpgradeContext,
    id_pool: u64,
    tx_results: Vec<stellar_xdr::curr::TransactionResultPair>,
    tx_result_metas: Vec<stellar_xdr::curr::TransactionResultMetaV1>,
}

impl<'a> LedgerCloseContext<'a> {
    /// Get the ledger sequence being closed.
    pub fn ledger_seq(&self) -> u32 {
        self.close_data.ledger_seq
    }

    /// Get the close time.
    pub fn close_time(&self) -> u64 {
        self.close_data.close_time
    }

    /// Get the snapshot for reading state.
    pub fn snapshot(&self) -> &SnapshotHandle {
        &self.snapshot
    }

    /// Get the delta for recording changes.
    pub fn delta(&self) -> &LedgerDelta {
        &self.delta
    }

    /// Get a mutable reference to the delta.
    pub fn delta_mut(&mut self) -> &mut LedgerDelta {
        &mut self.delta
    }

    /// Get the stats.
    pub fn stats(&self) -> &LedgerCloseStats {
        &self.stats
    }

    /// Get a mutable reference to the stats.
    pub fn stats_mut(&mut self) -> &mut LedgerCloseStats {
        &mut self.stats
    }

    /// Load an entry from the snapshot.
    pub fn load_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        // First check if we have a pending change
        if let Some(change) = self.delta.get_change(key)? {
            return Ok(change.current_entry().cloned());
        }

        // Otherwise read from snapshot
        Ok(self.snapshot.get_entry(key)?)
    }

    /// Load an account from the snapshot.
    pub fn load_account(&self, id: &AccountId) -> Result<Option<AccountEntry>> {
        let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: id.clone(),
        });

        if let Some(entry) = self.load_entry(&key)? {
            if let LedgerEntryData::Account(account) = entry.data {
                return Ok(Some(account));
            }
        }

        Ok(None)
    }

    /// Record creation of a new entry.
    pub fn record_create(&mut self, entry: LedgerEntry) -> Result<()> {
        self.delta.record_create(entry)
    }

    /// Record update of an existing entry.
    pub fn record_update(&mut self, previous: LedgerEntry, current: LedgerEntry) -> Result<()> {
        self.delta.record_update(previous, current)
    }

    /// Record deletion of an entry.
    pub fn record_delete(&mut self, entry: LedgerEntry) -> Result<()> {
        self.delta.record_delete(entry)
    }

    /// Add an upgrade to apply.
    pub fn add_upgrade(&mut self, upgrade: stellar_xdr::curr::LedgerUpgrade) {
        self.upgrade_ctx.add_upgrade(upgrade);
    }

    /// Apply transactions from the transaction set.
    ///
    /// This executes all transactions in order, recording state changes
    /// to the delta and collecting results.
    pub fn apply_transactions(&mut self) -> Result<Vec<TransactionExecutionResult>> {
        let transactions = self
            .close_data
            .tx_set
            .transactions_with_base_fee();

        if transactions.is_empty() {
            self.tx_results.clear();
            return Ok(vec![]);
        }

        let op_invariants = if self.manager.config.validate_invariants {
            let entries = self.manager.bucket_list.read().live_entries()?;
            Some(OperationInvariantRunner::new(
                entries,
                self.prev_header.clone(),
                self.manager.network_id,
            )?)
        } else {
            None
        };

        // Load SorobanConfig from ledger ConfigSettingEntry for accurate Soroban execution
        let soroban_config = crate::execution::load_soroban_config(&self.snapshot);
        // Use transaction set hash as base PRNG seed for Soroban execution
        let soroban_base_prng_seed = self.close_data.tx_set_hash();
        let (results, tx_results, tx_result_metas, id_pool) = execute_transaction_set(
            &self.snapshot,
            &transactions,
            self.close_data.ledger_seq,
            self.close_data.close_time,
            self.prev_header.base_fee,
            self.prev_header.base_reserve,
            self.prev_header.ledger_version,
            self.manager.network_id.clone(),
            &mut self.delta,
            soroban_config,
            soroban_base_prng_seed.0,
            op_invariants,
        )?;
        self.id_pool = id_pool;
        self.tx_results = tx_results;
        self.tx_result_metas = tx_result_metas;

        // Update stats
        let tx_count = results.len();
        let success_count = results.iter().filter(|r| r.success).count();
        let op_count: usize = results.iter().map(|r| r.operation_results.len()).sum();
        let fees_collected: i64 = results.iter().map(|r| r.fee_charged).sum();

        self.stats.record_transactions(tx_count, success_count, op_count);
        self.stats.record_fees(fees_collected);

        Ok(results)
    }

    /// Commit the ledger close and produce the new header.
    pub fn commit(mut self) -> Result<LedgerCloseResult> {
        let start = std::time::Instant::now();

        // Compute transaction result hash
        let result_set = stellar_xdr::curr::TransactionResultSet {
            results: self.tx_results.clone().try_into().unwrap_or_default(),
        };
        let tx_result_hash = Hash256::hash_xdr(&result_set).unwrap_or(Hash256::ZERO);

        let mut upgraded_header = self.prev_header.clone();
        self.upgrade_ctx.apply_to_header(&mut upgraded_header);
        let protocol_version = upgraded_header.ledger_version;

        // Apply delta to bucket list FIRST, then compute its hash
        // This ensures the bucket_list_hash in the header matches the actual state
        let bucket_list_hash = {
            let mut bucket_list = self.manager.bucket_list.write();
            let init_entries = self.delta.init_entries();
            let live_entries = self.delta.live_entries();
            let dead_entries = self.delta.dead_entries();

            bucket_list.add_batch(
                self.close_data.ledger_seq,
                protocol_version,
                BucketListType::Live,
                init_entries,
                live_entries,
                dead_entries,
            )?;

            bucket_list.hash()
        };

        // Create the new header
        let mut new_header = create_next_header(
            &self.prev_header,
            self.prev_header_hash,
            self.close_data.close_time,
            self.close_data.tx_set_hash(),
            bucket_list_hash,
            tx_result_hash,
            self.prev_header.total_coins + self.delta.total_coins_delta(),
            self.prev_header.fee_pool + self.delta.fee_pool_delta(),
            self.prev_header.inflation_seq,
        );

        // Apply upgrades to header fields (e.g., ledger_version, base_fee)
        self.upgrade_ctx.apply_to_header(&mut new_header);

        // Also set the raw upgrades in scp_value.upgrades for correct header hash
        // The upgrades need to be XDR-encoded as UpgradeType (opaque bytes)
        let raw_upgrades: Vec<stellar_xdr::curr::UpgradeType> = self
            .close_data
            .upgrades
            .iter()
            .filter_map(|upgrade| {
                use stellar_xdr::curr::WriteXdr;
                upgrade
                    .to_xdr(stellar_xdr::curr::Limits::none())
                    .ok()
                    .and_then(|bytes| stellar_xdr::curr::UpgradeType::try_from(bytes).ok())
            })
            .collect();
        if let Ok(upgrades_vec) = raw_upgrades.try_into() {
            new_header.scp_value.upgrades = upgrades_vec;
        }

        new_header.id_pool = self.id_pool;

        // Compute header hash
        let header_hash = compute_header_hash(&new_header)?;

        if self.manager.config.validate_invariants {
            let full_entries = {
                let bucket_list = self.manager.bucket_list.read();
                bucket_list.live_entries()?
            };
            let changes = self
                .delta
                .changes()
                .map(|change| match change {
                    EntryChange::Created(entry) => LedgerEntryChange::Created {
                        current: entry.clone(),
                    },
                    EntryChange::Updated { previous, current } => LedgerEntryChange::Updated {
                        previous: previous.clone(),
                        current: current.clone(),
                    },
                    EntryChange::Deleted { previous } => LedgerEntryChange::Deleted {
                        previous: previous.clone(),
                    },
                })
                .collect::<Vec<_>>();
            let ctx = InvariantContext {
                prev_header: &self.prev_header,
                curr_header: &new_header,
                bucket_list_hash,
                fee_pool_delta: self.delta.fee_pool_delta(),
                total_coins_delta: self.delta.total_coins_delta(),
                changes: &changes,
                full_entries: Some(&full_entries),
                op_events: None,
            };
            self.manager.invariants.read().check_all(&ctx)?;
        }

        // Record stats
        let entries_created = self.delta.changes().filter(|c| c.is_created()).count();
        let entries_updated = self.delta.changes().filter(|c| c.is_updated()).count();
        let entries_deleted = self.delta.changes().filter(|c| c.is_deleted()).count();
        self.stats.record_entry_changes(entries_created, entries_updated, entries_deleted);

        // Commit to manager
        self.manager.commit_close(self.delta, new_header.clone(), header_hash)?;

        self.stats.set_close_time(start.elapsed().as_millis() as u64);

        info!(
            ledger_seq = new_header.ledger_seq,
            tx_count = self.stats.tx_count,
            close_time_ms = self.stats.close_time_ms,
            computed_hash = %header_hash.to_hex(),
            bucket_list_hash = %bucket_list_hash.to_hex(),
            tx_result_hash = %tx_result_hash.to_hex(),
            total_coins = new_header.total_coins,
            fee_pool = new_header.fee_pool,
            close_time = new_header.scp_value.close_time.0,
            tx_set_hash = %Hash256::from(new_header.scp_value.tx_set_hash.0).to_hex(),
            upgrades_count = new_header.scp_value.upgrades.len(),
            "Ledger closed"
        );

        let meta = build_ledger_close_meta(&self.close_data, &new_header, header_hash, &self.tx_result_metas);

        Ok(
            LedgerCloseResult::new(new_header, header_hash)
                .with_tx_results(self.tx_results)
                .with_meta(meta),
        )
    }

    /// Abort the ledger close without committing.
    pub fn abort(self) {
        debug!(
            ledger_seq = self.close_data.ledger_seq,
            "Ledger close aborted"
        );
        // Delta is dropped, no changes are committed
    }
}

fn build_generalized_tx_set(tx_set: &TransactionSetVariant) -> GeneralizedTransactionSet {
    match tx_set {
        TransactionSetVariant::Generalized(set) => set.clone(),
        TransactionSetVariant::Classic(set) => {
            let component = TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
                TxSetComponentTxsMaybeDiscountedFee {
                    base_fee: None,
                    txs: set.txs.clone(),
                },
            );
            let phase = TransactionPhase::V0(vec![component].try_into().unwrap_or_default());
            GeneralizedTransactionSet::V1(TransactionSetV1 {
                previous_ledger_hash: set.previous_ledger_hash.clone(),
                phases: vec![phase].try_into().unwrap_or_default(),
            })
        }
    }
}

fn build_ledger_close_meta(
    close_data: &LedgerCloseData,
    header: &LedgerHeader,
    header_hash: Hash256,
    tx_result_metas: &[TransactionResultMetaV1],
) -> LedgerCloseMeta {
    let ledger_header = LedgerHeaderHistoryEntry {
        hash: Hash::from(header_hash),
        header: header.clone(),
        ext: LedgerHeaderHistoryEntryExt::V0,
    };

    let tx_set = build_generalized_tx_set(&close_data.tx_set);

    LedgerCloseMeta::V2(LedgerCloseMetaV2 {
        ext: LedgerCloseMetaExt::V0,
        ledger_header,
        tx_set,
        tx_processing: tx_result_metas.to_vec().try_into().unwrap_or_default(),
        upgrades_processing: VecM::<UpgradeEntryMeta>::default(),
        scp_info: VecM::<ScpHistoryEntry>::default(),
        total_byte_size_of_live_soroban_state: 0,
        evicted_keys: VecM::default(),
    })
}

/// Create a genesis ledger header.
fn create_genesis_header() -> LedgerHeader {
    LedgerHeader {
        ledger_version: 0,
        previous_ledger_hash: Hash([0u8; 32]),
        scp_value: stellar_xdr::curr::StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: stellar_xdr::curr::TimePoint(0),
            upgrades: stellar_xdr::curr::VecM::default(),
            ext: stellar_xdr::curr::StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
        bucket_list_hash: Hash([0u8; 32]),
        ledger_seq: 0,
        total_coins: 0,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: 100,
        base_reserve: 5_000_000,
        max_tx_set_size: 1000,
        skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
        ext: stellar_xdr::curr::LedgerHeaderExt::V0,
    }
}

fn extract_scp_timing(entry: &LedgerEntry) -> Option<ConfigSettingScpTiming> {
    match &entry.data {
        LedgerEntryData::ConfigSetting(ConfigSettingEntry::ScpTiming(timing)) => {
            Some(timing.clone())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Note: These tests require proper mocking of BucketManager and Database
    // For now they are placeholder tests

    #[test]
    fn test_genesis_header() {
        let header = create_genesis_header();
        assert_eq!(header.ledger_seq, 0);
        assert_eq!(header.base_fee, 100);
    }

    #[test]
    fn test_ledger_manager_config_default() {
        let config = LedgerManagerConfig::default();
        assert_eq!(config.max_snapshots, 10);
        assert!(config.validate_bucket_hash);
        assert!(config.validate_invariants);
        assert!(config.persist_to_db);
    }
}
