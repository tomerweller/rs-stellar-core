//! Ledger replay for history catchup.
//!
//! This module handles replaying ledgers from history during catchup.
//!
//! Key approach: During catchup, we re-execute transactions against the current
//! bucket list to reconstruct state changes, while still verifying history data.
//! This keeps the bucket list consistent with transaction effects and lets us
//! validate both the tx set hash and tx result set hash from the headers.
//!
//! We still support a metadata-only replay path (`replay_ledger`) for tests and
//! future alternative flows.

use crate::{verify, HistoryError, Result};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_invariant::LedgerEntryChange;
use stellar_core_ledger::{
    execution::{execute_transaction_set, load_soroban_config},
    LedgerDelta, LedgerError, LedgerSnapshot, SnapshotHandle, TransactionSetVariant,
};
use stellar_xdr::curr::{
    BucketListType, LedgerEntry, LedgerHeader, LedgerKey, TransactionEnvelope, TransactionMeta,
    TransactionResultPair, TransactionResultSet, WriteXdr,
};
use sha2::{Digest, Sha256};

/// The result of replaying a single ledger.
#[derive(Debug, Clone)]
pub struct LedgerReplayResult {
    /// The ledger sequence that was replayed.
    pub sequence: u32,
    /// Protocol version for this ledger.
    pub protocol_version: u32,
    /// Hash of the ledger after replay.
    pub ledger_hash: Hash256,
    /// Number of transactions in the ledger.
    pub tx_count: u32,
    /// Number of operations in the ledger.
    pub op_count: u32,
    /// Change in fee pool during the replayed ledger.
    pub fee_pool_delta: i64,
    /// Change in total coins during the replayed ledger.
    pub total_coins_delta: i64,
    /// Init entries to apply to the bucket list.
    pub init_entries: Vec<LedgerEntry>,
    /// Live entries to apply to the bucket list.
    pub live_entries: Vec<LedgerEntry>,
    /// Keys to mark as dead in the bucket list.
    pub dead_entries: Vec<LedgerKey>,
    /// Detailed entry changes for invariants.
    pub changes: Vec<LedgerEntryChange>,
}

/// Configuration for ledger replay.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Whether to verify transaction results.
    pub verify_results: bool,
    /// Whether to verify bucket list hashes.
    pub verify_bucket_list: bool,
    /// Whether to enforce invariants during replay.
    pub verify_invariants: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            verify_results: true,
            verify_bucket_list: true,
            verify_invariants: true,
        }
    }
}

const FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION: u32 = 23;

fn combined_bucket_list_hash(
    live_bucket_list: &stellar_core_bucket::BucketList,
    hot_archive_bucket_list: Option<&stellar_core_bucket::BucketList>,
    protocol_version: u32,
) -> Hash256 {
    if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
        if let Some(hot_archive) = hot_archive_bucket_list {
            let mut hasher = Sha256::new();
            hasher.update(live_bucket_list.hash().as_bytes());
            hasher.update(hot_archive.hash().as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            return Hash256::from_bytes(bytes);
        }
    }

    live_bucket_list.hash()
}

/// Replays a single ledger from history data.
///
/// This applies the transaction results to extract ledger entry changes,
/// which can then be applied to the bucket list.
///
/// # Arguments
///
/// * `header` - The ledger header
/// * `tx_set` - The transaction set for this ledger
/// * `tx_results` - The transaction results from history
/// * `tx_metas` - Transaction metadata containing ledger entry changes
/// * `config` - Replay configuration
///
/// # Returns
///
/// A `LedgerReplayResult` containing the changes to apply to ledger state.
pub fn replay_ledger(
    header: &LedgerHeader,
    tx_set: &TransactionSetVariant,
    tx_results: &[TransactionResultPair],
    tx_metas: &[TransactionMeta],
    config: &ReplayConfig,
) -> Result<LedgerReplayResult> {
    // Verify the transaction set hash matches the header
    if config.verify_results {
        verify::verify_tx_set(header, tx_set)?;

        let result_set = TransactionResultSet {
            results: tx_results
                .to_vec()
                .try_into()
                .map_err(|_| HistoryError::CatchupFailed("tx result set too large".to_string()))?,
        };
        let xdr = result_set
            .to_xdr(stellar_xdr::curr::Limits::none())
            .map_err(|e| HistoryError::CatchupFailed(format!("failed to encode tx result set: {}", e)))?;
        verify::verify_tx_result_set(header, &xdr)?;
    }

    // Extract ledger entry changes from transaction metadata
    let (init_entries, live_entries, dead_entries) = extract_ledger_changes(tx_metas)?;

    // Count transactions and operations
    let tx_count = tx_set.num_transactions() as u32;
    let op_count = count_operations(tx_set);

    // Compute the ledger hash
    let ledger_hash = verify::compute_header_hash(header)?;

    Ok(LedgerReplayResult {
        sequence: header.ledger_seq,
        protocol_version: header.ledger_version,
        ledger_hash,
        tx_count,
        op_count,
        fee_pool_delta: 0,
        total_coins_delta: 0,
        init_entries,
        live_entries,
        dead_entries,
        changes: Vec::new(),
    })
}

/// Replay a ledger by re-executing transactions against the current bucket list.
pub fn replay_ledger_with_execution(
    header: &LedgerHeader,
    tx_set: &TransactionSetVariant,
    bucket_list: &mut stellar_core_bucket::BucketList,
    hot_archive_bucket_list: Option<&stellar_core_bucket::BucketList>,
    network_id: &NetworkId,
    config: &ReplayConfig,
    expected_tx_results: Option<&[TransactionResultPair]>,
) -> Result<LedgerReplayResult> {
    if config.verify_results {
        verify::verify_tx_set(header, tx_set)?;
    }

    let snapshot = LedgerSnapshot::empty(header.ledger_seq);
    let bucket_list_ref = std::sync::Arc::new(std::sync::RwLock::new(bucket_list.clone()));
    let lookup_fn = std::sync::Arc::new(move |key: &LedgerKey| {
        bucket_list_ref
            .read()
            .map_err(|_| LedgerError::Snapshot("bucket list lock poisoned".to_string()))?
            .get(key)
            .map_err(LedgerError::Bucket)
    });
    let snapshot = SnapshotHandle::with_lookup(snapshot, lookup_fn);

    let mut delta = LedgerDelta::new(header.ledger_seq);
    let transactions = tx_set.transactions_with_base_fee();
    // Load SorobanConfig from ledger ConfigSettingEntry for accurate Soroban execution
    let soroban_config = load_soroban_config(&snapshot);
    let (results, tx_results, _tx_result_metas, _total_fees) = execute_transaction_set(
        &snapshot,
        &transactions,
        header.ledger_seq,
        header.scp_value.close_time.0,
        header.base_fee,
        header.base_reserve,
        header.ledger_version,
        *network_id,
        &mut delta,
        soroban_config,
    )
    .map_err(|e| HistoryError::CatchupFailed(format!("replay execution failed: {}", e)))?;

    if config.verify_results {
        let result_set = TransactionResultSet {
            results: tx_results
                .clone()
                .try_into()
                .map_err(|_| HistoryError::CatchupFailed("tx result set too large".to_string()))?,
        };
        let xdr = result_set
            .to_xdr(stellar_xdr::curr::Limits::none())
            .map_err(|e| HistoryError::CatchupFailed(format!("failed to encode tx result set: {}", e)))?;
        if let Err(err) = verify::verify_tx_result_set(header, &xdr) {
            if let Some(expected) = expected_tx_results {
                log_tx_result_mismatch(header, expected, &tx_results, &transactions);
            }
            return Err(err);
        }
    }

    let fee_pool_delta = delta.fee_pool_delta();
    let total_coins_delta = delta.total_coins_delta();
    let changes = delta
        .changes()
        .map(|change| match change {
            stellar_core_ledger::EntryChange::Created(entry) => {
                LedgerEntryChange::Created {
                    current: entry.clone(),
                }
            }
            stellar_core_ledger::EntryChange::Updated { previous, current } => {
                LedgerEntryChange::Updated {
                    previous: previous.clone(),
                    current: current.clone(),
                }
            }
            stellar_core_ledger::EntryChange::Deleted { previous } => {
                LedgerEntryChange::Deleted {
                    previous: previous.clone(),
                }
            }
        })
        .collect::<Vec<_>>();
    let init_entries = delta.init_entries();
    let live_entries = delta.live_entries();
    let dead_entries = delta.dead_entries();
    bucket_list
        .add_batch(
            header.ledger_seq,
            header.ledger_version,
            BucketListType::Live,
            init_entries.clone(),
            live_entries.clone(),
            dead_entries.clone(),
        )
        .map_err(HistoryError::Bucket)?;
    if config.verify_bucket_list {
        let expected = Hash256::from(header.bucket_list_hash.0);
        let actual = combined_bucket_list_hash(
            bucket_list,
            hot_archive_bucket_list,
            header.ledger_version,
        );
        if actual != expected {
            return Err(HistoryError::VerificationFailed(format!(
                "bucket list hash mismatch at ledger {} (expected {}, got {})",
                header.ledger_seq,
                expected.to_hex(),
                actual.to_hex()
            )));
        }
    }

    let tx_count = results.len() as u32;
    let op_count: u32 = results.iter().map(|r| r.operation_results.len() as u32).sum();
    let ledger_hash = verify::compute_header_hash(header)?;

    Ok(LedgerReplayResult {
        sequence: header.ledger_seq,
        protocol_version: header.ledger_version,
        ledger_hash,
        tx_count,
        op_count,
        fee_pool_delta,
        total_coins_delta,
        init_entries,
        live_entries,
        dead_entries,
        changes,
    })
}

fn log_tx_result_mismatch(
    header: &LedgerHeader,
    expected: &[TransactionResultPair],
    actual: &[TransactionResultPair],
    transactions: &[(TransactionEnvelope, Option<u32>)],
) {
    use tracing::warn;

    if expected.len() != actual.len() {
        warn!(
            ledger_seq = header.ledger_seq,
            expected_len = expected.len(),
            actual_len = actual.len(),
            "Transaction result count mismatch"
        );
    }

    let limit = expected.len().min(actual.len());
    for (idx, (expected_item, actual_item)) in expected
        .iter()
        .zip(actual.iter())
        .take(limit)
        .enumerate()
    {
        let expected_hash = Hash256::hash_xdr(expected_item).unwrap_or(Hash256::ZERO);
        let actual_hash = Hash256::hash_xdr(actual_item).unwrap_or(Hash256::ZERO);
        if expected_hash != actual_hash {
            let expected_tx_hash = Hash256::from(expected_item.transaction_hash.0).to_hex();
            let actual_tx_hash = Hash256::from(actual_item.transaction_hash.0).to_hex();
            let expected_code = format!("{:?}", expected_item.result.result);
            let actual_code = format!("{:?}", actual_item.result.result);
            let op_summaries = transactions
                .get(idx)
                .map(|(tx, _)| summarize_operations(tx))
                .unwrap_or_default();
            warn!(
                ledger_seq = header.ledger_seq,
                index = idx,
                expected_tx_hash = %expected_tx_hash,
                actual_tx_hash = %actual_tx_hash,
                expected_code = %expected_code,
                actual_code = %actual_code,
                expected_hash = %expected_hash.to_hex(),
                actual_hash = %actual_hash.to_hex(),
                operations = ?op_summaries,
                "Transaction result mismatch"
            );
            break;
        }
    }
}

fn summarize_operations(tx: &TransactionEnvelope) -> Vec<String> {
    let ops = match tx {
        TransactionEnvelope::TxV0(env) => env.tx.operations.as_slice(),
        TransactionEnvelope::Tx(env) => env.tx.operations.as_slice(),
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.operations.as_slice(),
        },
    };

    ops.iter()
        .map(|op| {
            let source = op.source_account.as_ref().map(|a| format!("{:?}", a));
            let body = format!("{:?}", op.body);
            format!("source={:?} body={}", source, body)
        })
        .collect()
}

/// Extract ledger entry changes from transaction metadata.
///
/// Returns (init_entries, live_entries, dead_entries) where:
/// - init_entries: Entries that were created
/// - live_entries: Entries that were updated or restored
/// - dead_entries: Keys of entries that were deleted
fn extract_ledger_changes(
    tx_metas: &[TransactionMeta],
) -> Result<(Vec<LedgerEntry>, Vec<LedgerEntry>, Vec<LedgerKey>)> {
    let mut init_entries = Vec::new();
    let mut live_entries = Vec::new();
    let mut dead_entries = Vec::new();

    for meta in tx_metas {
        match meta {
            TransactionMeta::V0(operations) => {
                // V0: VecM<OperationMeta> - each OperationMeta has a changes field
                for op_meta in operations.iter() {
                    for change in op_meta.changes.iter() {
                        process_ledger_entry_change(
                            change,
                            &mut init_entries,
                            &mut live_entries,
                            &mut dead_entries,
                        );
                    }
                }
            }
            TransactionMeta::V1(v1) => {
                // Process txChanges (before)
                for change in v1.tx_changes.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
                // Process operation changes
                for op_changes in v1.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(
                            change,
                            &mut init_entries,
                            &mut live_entries,
                            &mut dead_entries,
                        );
                    }
                }
            }
            TransactionMeta::V2(v2) => {
                // Process txChangesBefore
                for change in v2.tx_changes_before.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
                // Process operation changes
                for op_changes in v2.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(
                            change,
                            &mut init_entries,
                            &mut live_entries,
                            &mut dead_entries,
                        );
                    }
                }
                // Process txChangesAfter
                for change in v2.tx_changes_after.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
            }
            TransactionMeta::V3(v3) => {
                // Process txChangesBefore
                for change in v3.tx_changes_before.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
                // Process operation changes
                for op_changes in v3.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(
                            change,
                            &mut init_entries,
                            &mut live_entries,
                            &mut dead_entries,
                        );
                    }
                }
                // Process txChangesAfter
                for change in v3.tx_changes_after.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
                // Note: sorobanMeta is handled separately if needed
            }
            TransactionMeta::V4(v4) => {
                // V4 follows the same pattern as V3
                for change in v4.tx_changes_before.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
                for op_changes in v4.operations.iter() {
                    for change in op_changes.changes.iter() {
                        process_ledger_entry_change(
                            change,
                            &mut init_entries,
                            &mut live_entries,
                            &mut dead_entries,
                        );
                    }
                }
                for change in v4.tx_changes_after.iter() {
                    process_ledger_entry_change(
                        change,
                        &mut init_entries,
                        &mut live_entries,
                        &mut dead_entries,
                    );
                }
            }
        }
    }

    Ok((init_entries, live_entries, dead_entries))
}

/// Process a single ledger entry change.
fn process_ledger_entry_change(
    change: &stellar_xdr::curr::LedgerEntryChange,
    init_entries: &mut Vec<LedgerEntry>,
    live_entries: &mut Vec<LedgerEntry>,
    dead_entries: &mut Vec<LedgerKey>,
) {
    use stellar_xdr::curr::LedgerEntryChange;

    match change {
        LedgerEntryChange::Created(entry) => {
            init_entries.push(entry.clone());
        }
        LedgerEntryChange::Updated(entry) => {
            live_entries.push(entry.clone());
        }
        LedgerEntryChange::Removed(key) => {
            dead_entries.push(key.clone());
        }
        LedgerEntryChange::State(_) => {
            // State entries represent the state before a change,
            // we don't need to process them for replay
        }
        LedgerEntryChange::Restored(entry) => {
            // Restored entries (from Soroban) are treated as live entries
            live_entries.push(entry.clone());
        }
    }
}

/// Count the total number of operations in a transaction set.
fn count_operations(tx_set: &TransactionSetVariant) -> u32 {
    let mut count = 0;

    for tx_env in tx_set.transactions().into_iter() {
        use stellar_xdr::curr::TransactionEnvelope;
        match tx_env {
            TransactionEnvelope::TxV0(tx) => {
                count += tx.tx.operations.len() as u32;
            }
            TransactionEnvelope::Tx(tx) => {
                count += tx.tx.operations.len() as u32;
            }
            TransactionEnvelope::TxFeeBump(tx) => {
                // Fee bump wraps an inner transaction
                match &tx.tx.inner_tx {
                    stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                        count += inner.tx.operations.len() as u32;
                    }
                }
            }
        }
    }

    count
}

/// Replay a batch of ledgers.
///
/// This is used during catchup to replay all ledgers from a checkpoint
/// to the target ledger.
///
/// # Arguments
///
/// * `ledgers` - Slice of (header, tx_set, results, metas) tuples
/// * `config` - Replay configuration
/// * `progress_callback` - Optional callback for progress updates
pub fn replay_ledgers<F>(
    ledgers: &[(LedgerHeader, TransactionSetVariant, Vec<TransactionResultPair>, Vec<TransactionMeta>)],
    config: &ReplayConfig,
    mut progress_callback: Option<F>,
) -> Result<Vec<LedgerReplayResult>>
where
    F: FnMut(u32, u32), // (current, total)
{
    let total = ledgers.len() as u32;
    let mut results = Vec::with_capacity(ledgers.len());

    for (i, (header, tx_set, tx_results, tx_metas)) in ledgers.iter().enumerate() {
        let result = replay_ledger(header, tx_set, tx_results, tx_metas, config)?;
        results.push(result);

        if let Some(ref mut callback) = progress_callback {
            callback(i as u32 + 1, total);
        }
    }

    Ok(results)
}

/// Verify ledger consistency after replay.
///
/// Checks that the final bucket list hash matches the expected hash
/// from the last replayed ledger header.
pub fn verify_replay_consistency(
    final_header: &LedgerHeader,
    computed_bucket_list_hash: &Hash256,
) -> Result<()> {
    verify::verify_ledger_hash(final_header, computed_bucket_list_hash)
}

/// Apply replay results to the bucket list.
///
/// This takes the changes from ledger replay and applies them to the
/// bucket list to update the ledger state.
pub fn apply_replay_to_bucket_list(
    bucket_list: &mut stellar_core_bucket::BucketList,
    replay_result: &LedgerReplayResult,
) -> Result<()> {
    bucket_list
        .add_batch(
            replay_result.sequence,
            replay_result.protocol_version,
            BucketListType::Live,
            replay_result.init_entries.clone(),
            replay_result.live_entries.clone(),
            replay_result.dead_entries.clone(),
        )
        .map_err(HistoryError::Bucket)
}

/// Prepare a ledger close based on replay data.
///
/// This is used when we've replayed history and want to set up the
/// ledger manager to continue from that point.
#[derive(Debug, Clone)]
pub struct ReplayedLedgerState {
    /// The ledger sequence we replayed to.
    pub sequence: u32,
    /// Hash of the final ledger.
    pub ledger_hash: Hash256,
    /// Hash of the bucket list.
    pub bucket_list_hash: Hash256,
    /// Close time of the final ledger.
    pub close_time: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Base fee.
    pub base_fee: u32,
    /// Base reserve.
    pub base_reserve: u32,
}

impl ReplayedLedgerState {
    /// Create from a final ledger header after replay.
    pub fn from_header(header: &LedgerHeader, ledger_hash: Hash256) -> Self {
        Self {
            sequence: header.ledger_seq,
            ledger_hash,
            bucket_list_hash: Hash256::from(header.bucket_list_hash.clone()),
            close_time: header.scp_value.close_time.0,
            protocol_version: header.ledger_version,
            base_fee: header.base_fee,
            base_reserve: header.base_reserve,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_bucket::BucketList;
    use stellar_core_common::NetworkId;
    use stellar_xdr::curr::{
        GeneralizedTransactionSet, Hash, StellarValue, TimePoint, TransactionResultSet, TransactionSet,
        TransactionSetV1, VecM, WriteXdr,
    };

    fn make_test_header(seq: u32) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 20,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(1234567890),
                upgrades: VecM::default(),
                ext: stellar_xdr::curr::StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash([0u8; 32]),
            ledger_seq: seq,
            total_coins: 0,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 5000000,
            max_tx_set_size: 100,
            skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
            ext: stellar_xdr::curr::LedgerHeaderExt::V0,
        }
    }

    fn make_header_with_hashes(
        seq: u32,
        tx_set_hash: Hash,
        tx_result_hash: Hash,
    ) -> LedgerHeader {
        let mut header = make_test_header(seq);
        header.scp_value.tx_set_hash = tx_set_hash;
        header.tx_set_result_hash = tx_result_hash;
        header
    }

    fn make_empty_tx_set() -> TransactionSet {
        TransactionSet {
            previous_ledger_hash: Hash([0u8; 32]),
            txs: VecM::default(),
        }
    }

    #[test]
    fn test_replay_empty_ledger() {
        let header = make_test_header(100);
        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        let tx_results = vec![];
        let tx_metas = vec![];

        let config = ReplayConfig {
            verify_results: false, // Skip verification for test
            verify_bucket_list: false,
            verify_invariants: false,
        };

        let result = replay_ledger(&header, &tx_set, &tx_results, &tx_metas, &config).unwrap();

        assert_eq!(result.sequence, 100);
        assert_eq!(result.tx_count, 0);
        assert_eq!(result.op_count, 0);
        assert!(result.init_entries.is_empty());
        assert!(result.live_entries.is_empty());
        assert!(result.dead_entries.is_empty());
    }

    #[test]
    fn test_count_operations_empty() {
        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        assert_eq!(count_operations(&tx_set), 0);
    }

    #[test]
    fn test_replayed_ledger_state_from_header() {
        let header = make_test_header(42);
        let hash = Hash256::hash(b"test");

        let state = ReplayedLedgerState::from_header(&header, hash);

        assert_eq!(state.sequence, 42);
        assert_eq!(state.ledger_hash, hash);
        assert_eq!(state.close_time, 1234567890);
        assert_eq!(state.protocol_version, 20);
        assert_eq!(state.base_fee, 100);
    }

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();
        assert!(config.verify_results);
        assert!(config.verify_bucket_list);
        assert!(config.verify_invariants);
    }

    #[test]
    fn test_replay_ledger_rejects_tx_set_hash_mismatch() {
        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        let tx_results = vec![];
        let tx_metas = vec![];

        let tx_set_hash = verify::compute_tx_set_hash(&tx_set).expect("tx set hash");
        let header = make_header_with_hashes(
            100,
            Hash([1u8; 32]),
            Hash(*tx_set_hash.as_bytes()),
        );

        let config = ReplayConfig::default();
        let result = replay_ledger(&header, &tx_set, &tx_results, &tx_metas, &config);
        assert!(matches!(result, Err(HistoryError::InvalidTxSetHash { .. })));
    }

    #[test]
    fn test_replay_ledger_rejects_tx_result_hash_mismatch() {
        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        let tx_results = vec![];
        let tx_metas = vec![];

        let tx_set_hash = verify::compute_tx_set_hash(&tx_set).expect("tx set hash");

        let header = make_header_with_hashes(
            100,
            Hash(*tx_set_hash.as_bytes()),
            Hash([2u8; 32]),
        );

        let config = ReplayConfig::default();
        let result = replay_ledger(&header, &tx_set, &tx_results, &tx_metas, &config);
        assert!(matches!(result, Err(HistoryError::VerificationFailed(_))));
    }

    #[test]
    fn test_replay_ledger_accepts_generalized_tx_set() {
        let gen_set = GeneralizedTransactionSet::V1(TransactionSetV1 {
            previous_ledger_hash: Hash([0u8; 32]),
            phases: VecM::default(),
        });
        let tx_set = TransactionSetVariant::Generalized(gen_set);
        let tx_results = vec![];
        let tx_metas = vec![];

        let tx_set_hash = verify::compute_tx_set_hash(&tx_set).expect("tx set hash");

        let result_set = TransactionResultSet {
            results: VecM::default(),
        };
        let result_xdr = result_set
            .to_xdr(stellar_xdr::curr::Limits::none())
            .expect("tx result set xdr");
        let result_hash = Hash256::hash(&result_xdr);

        let header = make_header_with_hashes(
            100,
            Hash(*tx_set_hash.as_bytes()),
            Hash(*result_hash.as_bytes()),
        );

        let config = ReplayConfig::default();
        let result = replay_ledger(&header, &tx_set, &tx_results, &tx_metas, &config).unwrap();
        assert_eq!(result.tx_count, 0);
        assert_eq!(result.op_count, 0);
    }

    #[test]
    fn test_replay_ledger_with_execution_bucket_hash_mismatch() {
        let mut header = make_test_header(100);
        header.bucket_list_hash = Hash([1u8; 32]);

        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        let mut bucket_list = BucketList::new();

        let config = ReplayConfig {
            verify_results: false,
            verify_bucket_list: true,
            verify_invariants: false,
        };

        let result = replay_ledger_with_execution(
            &header,
            &tx_set,
            &mut bucket_list,
            None,
            &NetworkId::testnet(),
            &config,
            None,
        );

        assert!(matches!(result, Err(HistoryError::VerificationFailed(_))));
    }

    #[test]
    fn test_replay_ledger_with_execution_tx_set_hash_mismatch() {
        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        let mut header = make_test_header(100);
        header.scp_value.tx_set_hash = Hash([2u8; 32]);

        let mut bucket_list = BucketList::new();
        let config = ReplayConfig {
            verify_results: true,
            verify_bucket_list: false,
            verify_invariants: false,
        };

        let result = replay_ledger_with_execution(
            &header,
            &tx_set,
            &mut bucket_list,
            None,
            &NetworkId::testnet(),
            &config,
            None,
        );

        assert!(matches!(result, Err(HistoryError::InvalidTxSetHash { .. })));
    }

    #[test]
    fn test_replay_ledger_with_execution_tx_result_hash_mismatch() {
        let tx_set = TransactionSetVariant::Classic(make_empty_tx_set());
        let tx_set_hash = verify::compute_tx_set_hash(&tx_set).expect("tx set hash");

        let mut header = make_test_header(100);
        header.scp_value.tx_set_hash = Hash(*tx_set_hash.as_bytes());
        header.tx_set_result_hash = Hash([3u8; 32]);

        let mut bucket_list = BucketList::new();
        let config = ReplayConfig {
            verify_results: true,
            verify_bucket_list: false,
            verify_invariants: false,
        };

        let result = replay_ledger_with_execution(
            &header,
            &tx_set,
            &mut bucket_list,
            None,
            &NetworkId::testnet(),
            &config,
            None,
        );

        assert!(matches!(result, Err(HistoryError::VerificationFailed(_))));
    }
}
