//! BucketList implementation - the full hierarchical bucket structure.
//!
//! The BucketList is Stellar's core data structure for storing ledger state.
//! It consists of 11 levels, where each level contains two buckets (curr and snap).
//!
//! Spill boundaries follow stellar-core's `levelShouldSpill` rules based on
//! level size and half-size, rather than a simple fixed period.
//!
//! This creates a log-structured merge tree that efficiently handles
//! incremental updates while maintaining full history integrity.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use stellar_xdr::curr::{
    BucketListType, BucketMetadata, BucketMetadataExt, LedgerEntry, LedgerKey, Limits, WriteXdr,
};

use stellar_core_common::Hash256;

use crate::bucket::Bucket;
use crate::entry::BucketEntry;
use crate::merge::merge_buckets;
use crate::{BucketError, Result};

/// Number of levels in the BucketList.
pub const BUCKET_LIST_LEVELS: usize = 11;

const FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY: u32 = 11;
const FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION: u32 = 23;

/// A level in the BucketList, containing curr and snap buckets.
#[derive(Clone, Debug)]
pub struct BucketLevel {
    /// The current bucket being filled.
    pub curr: Bucket,
    /// The snapshot from the previous merge.
    pub snap: Bucket,
    /// The next bucket produced by a merge, awaiting commit.
    next: Option<Bucket>,
    /// The level number (0-10).
    level: usize,
}

impl BucketLevel {
    /// Create a new empty level.
    pub fn new(level: usize) -> Self {
        Self {
            curr: Bucket::empty(),
            snap: Bucket::empty(),
            next: None,
            level,
        }
    }

    /// Get the hash of this level: SHA256(curr_hash || snap_hash).
    ///
    /// This matches stellar-core's BucketLevel::getHash() implementation.
    pub fn hash(&self) -> Hash256 {
        let curr_hash = self.curr.hash();
        let snap_hash = self.snap.hash();

        // SHA256(curr_hash || snap_hash)
        let mut hasher = Sha256::new();
        hasher.update(curr_hash.as_bytes());
        hasher.update(snap_hash.as_bytes());
        let result = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Set the curr bucket.
    pub fn set_curr(&mut self, bucket: Bucket) {
        self.curr = bucket;
    }

    /// Set the snap bucket.
    pub fn set_snap(&mut self, bucket: Bucket) {
        self.snap = bucket;
    }

    /// Get the level number.
    pub fn level_number(&self) -> usize {
        self.level
    }

    /// Promote the prepared bucket into curr, if any.
    fn commit(&mut self) {
        if let Some(next) = self.next.take() {
            self.curr = next;
        }
    }

    /// Snap the current bucket and clear curr.
    fn snap(&mut self) -> Bucket {
        let curr = std::mem::replace(&mut self.curr, Bucket::empty());
        self.snap = curr.clone();
        curr
    }

    /// Prepare the next bucket for this level.
    ///
    /// This merges the current bucket (self.curr) with the incoming snap bucket.
    /// The curr may be empty if this level was already snapped from a higher level's
    /// processing - this is handled naturally by processing levels from high to low.
    fn prepare(
        &mut self,
        _ledger_seq: u32,
        protocol_version: u32,
        snap: Bucket,
        keep_dead_entries: bool,
    ) -> Result<()> {
        if self.next.is_some() {
            return Err(BucketError::Merge("bucket merge already in progress".to_string()));
        }

        // Merge curr with the incoming snap
        // curr may be empty if this level was already snapped
        let merged = merge_buckets(&self.curr, &snap, keep_dead_entries, protocol_version)?;
        self.next = Some(merged);
        Ok(())
    }
}

impl Default for BucketLevel {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The complete BucketList structure.
///
/// Contains 11 levels of buckets that together represent
/// the entire ledger state at a given point in time.
///
/// Each level contains:
/// - `curr`: The current bucket being filled
/// - `snap`: The snapshot from the previous spill
///
/// Spill frequency:
/// - Level 0 spills every ledger
/// - Level N spills every 2^(2N) ledgers
#[derive(Clone)]
pub struct BucketList {
    /// The levels in the bucket list.
    levels: Vec<BucketLevel>,
    /// The current ledger sequence.
    ledger_seq: u32,
}

impl BucketList {
    /// Number of levels in the BucketList.
    pub const NUM_LEVELS: usize = BUCKET_LIST_LEVELS;

    /// Create a new empty BucketList.
    pub fn new() -> Self {
        let levels = (0..BUCKET_LIST_LEVELS)
            .map(BucketLevel::new)
            .collect();

        Self {
            levels,
            ledger_seq: 0,
        }
    }

    /// Get the hash of the entire BucketList.
    ///
    /// This is computed by hashing all level hashes together.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha256::new();

        for level in &self.levels {
            hasher.update(level.hash().as_bytes());
        }

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Hash256::from_bytes(bytes)
    }

    /// Get the current ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Get a reference to a level.
    pub fn level(&self, idx: usize) -> Option<&BucketLevel> {
        self.levels.get(idx)
    }

    /// Get a mutable reference to a level.
    pub fn level_mut(&mut self, idx: usize) -> Option<&mut BucketLevel> {
        self.levels.get_mut(idx)
    }

    /// Get all levels.
    pub fn levels(&self) -> &[BucketLevel] {
        &self.levels
    }

    /// Look up an entry by its key.
    ///
    /// Searches from the newest (level 0) to oldest levels.
    /// Returns the first matching entry found, or None if not found.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        // Search from newest to oldest
        for level in &self.levels {
            // Check curr bucket first (newer)
            if let Some(entry) = level.curr.get(key)? {
                return match entry {
                    BucketEntry::Live(e) | BucketEntry::Init(e) => Ok(Some(e.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Entry is deleted
                    BucketEntry::Metadata(_) => continue,
                };
            }

            // Then check snap bucket
            if let Some(entry) = level.snap.get(key)? {
                return match entry {
                    BucketEntry::Live(e) | BucketEntry::Init(e) => Ok(Some(e.clone())),
                    BucketEntry::Dead(_) => Ok(None), // Entry is deleted
                    BucketEntry::Metadata(_) => continue,
                };
            }
        }

        Ok(None)
    }

    /// Return all live entries as of the current bucket list state.
    pub fn live_entries(&self) -> Result<Vec<LedgerEntry>> {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut entries = Vec::new();

        for level in &self.levels {
            for bucket in [&level.curr, &level.snap] {
                for entry in bucket.iter() {
                    match entry {
                        BucketEntry::Live(live) | BucketEntry::Init(live) => {
                            let Some(key) = crate::entry::ledger_entry_to_key(&live) else {
                                continue;
                            };
                            let key_bytes = key.to_xdr(Limits::none()).map_err(|e| {
                                BucketError::Serialization(format!(
                                    "failed to serialize ledger key: {}",
                                    e
                                ))
                            })?;
                            if seen.insert(key_bytes) {
                                entries.push(live);
                            }
                        }
                        BucketEntry::Dead(dead) => {
                            let key_bytes = dead.to_xdr(Limits::none()).map_err(|e| {
                                BucketError::Serialization(format!(
                                    "failed to serialize ledger key: {}",
                                    e
                                ))
                            })?;
                            seen.insert(key_bytes);
                        }
                        BucketEntry::Metadata(_) => {}
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Check if an entry exists (is live) for the given key.
    pub fn contains(&self, key: &LedgerKey) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Add ledger entries from a newly closed ledger.
    ///
    /// This mirrors stellar-core's bucket list update pipeline, preparing
    /// merges on spill boundaries and committing prior merges as needed.
    pub fn add_batch(
        &mut self,
        ledger_seq: u32,
        protocol_version: u32,
        bucket_list_type: BucketListType,
        init_entries: Vec<LedgerEntry>,
        live_entries: Vec<LedgerEntry>,
        dead_entries: Vec<LedgerKey>,
    ) -> Result<()> {
        let use_init = protocol_version >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY;

        // If there are no entries to add, use an empty bucket
        // Metadata is only included when there are actual entries
        let has_entries = !init_entries.is_empty() || !live_entries.is_empty() || !dead_entries.is_empty();

        let new_bucket = if !has_entries {
            Bucket::empty()
        } else {
            let mut entries: Vec<BucketEntry> = Vec::new();

            if use_init {
                let mut meta = BucketMetadata {
                    ledger_version: protocol_version,
                    ext: BucketMetadataExt::V0,
                };
                if protocol_version >= FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION {
                    meta.ext = BucketMetadataExt::V1(bucket_list_type);
                }
                entries.push(BucketEntry::Metadata(meta));
            }

            if use_init {
                entries.extend(init_entries.into_iter().map(BucketEntry::Init));
            } else {
                entries.extend(init_entries.into_iter().map(BucketEntry::Live));
            }

            entries.extend(live_entries.into_iter().map(BucketEntry::Live));
            entries.extend(dead_entries.into_iter().map(BucketEntry::Dead));

            Bucket::from_entries(entries)?
        };

        self.add_batch_internal(ledger_seq, protocol_version, new_bucket)?;
        self.ledger_seq = ledger_seq;
        Ok(())
    }

    fn add_batch_internal(
        &mut self,
        ledger_seq: u32,
        protocol_version: u32,
        new_bucket: Bucket,
    ) -> Result<()> {
        if ledger_seq == 0 {
            return Err(BucketError::Merge("ledger sequence must be > 0".to_string()));
        }

        tracing::debug!(
            ledger_seq = ledger_seq,
            "add_batch_internal: starting spill processing"
        );

        // Step 1: First, apply new entries to level 0
        // Level 0's curr is merged with the new bucket
        tracing::debug!(
            curr_hash = %self.levels[0].curr.hash(),
            snap_hash = %self.levels[0].snap.hash(),
            new_bucket_hash = %new_bucket.hash(),
            "Level 0 before"
        );

        self.levels[0].commit();
        let keep_dead_0 = Self::keep_tombstone_entries(0);
        self.levels[0].prepare(ledger_seq, protocol_version, new_bucket, keep_dead_0)?;
        self.levels[0].commit();

        tracing::debug!(
            curr_hash = %self.levels[0].curr.hash(),
            snap_hash = %self.levels[0].snap.hash(),
            "Level 0 after merge"
        );

        // Step 2: Process spills from level 0 upward
        // Each level that spills sends its ORIGINAL curr to the next level.
        // The receiving level merges with its ORIGINAL curr (not a cascaded result).
        //
        // Algorithm:
        //   1. Collect all ORIGINAL curr values for both spilling and receiving levels
        //   2. Snap each spilling level (curr -> snap, curr = empty)
        //   3. For each receiving level, merge its ORIGINAL curr with incoming spill

        // Collect original curr values
        let original_currs: Vec<Bucket> = self.levels.iter()
            .map(|level| level.curr.clone())
            .collect();

        // Snap each level that needs to spill
        for i in 0..(BUCKET_LIST_LEVELS - 1) {
            if Self::level_should_spill(ledger_seq, i) {
                // snap: curr -> snap, curr = empty
                self.levels[i].snap();
                tracing::debug!(
                    level = i,
                    new_snap_hash = %self.levels[i].snap.hash(),
                    "After snap"
                );
            }
        }

        // Merge into next levels using ORIGINAL curr values
        for i in 0..(BUCKET_LIST_LEVELS - 1) {
            if Self::level_should_spill(ledger_seq, i) {
                let spilling = &original_currs[i];
                let next_level = i + 1;
                let next_original_curr = &original_currs[next_level];

                tracing::debug!(
                    level = next_level,
                    spilling_hash = %spilling.hash(),
                    original_curr_hash = %next_original_curr.hash(),
                    "Before merge"
                );

                // Merge original curr with incoming spill
                let keep_dead = Self::keep_tombstone_entries(next_level);
                let merged = merge_buckets(next_original_curr, spilling, keep_dead, protocol_version)?;

                // Set the merged result as the new curr
                self.levels[next_level].curr = merged;

                tracing::debug!(
                    level = next_level,
                    new_curr_hash = %self.levels[next_level].curr.hash(),
                    "After merge"
                );
            }
        }

        // Log final state of all levels
        tracing::info!(ledger_seq = ledger_seq, "Final bucket list state after add_batch");
        for i in 0..BUCKET_LIST_LEVELS {
            tracing::info!(
                level = i,
                curr_hash = %self.levels[i].curr.hash(),
                snap_hash = %self.levels[i].snap.hash(),
                "Level state"
            );
        }

        Ok(())
    }

    /// Round down `value` to the nearest multiple of `modulus`.
    fn round_down(value: u32, modulus: u32) -> u32 {
        if modulus == 0 {
            return 0;
        }
        value & !(modulus - 1)
    }

    /// Idealized size of a level for spill boundaries.
    fn level_size(level: usize) -> u32 {
        1u32 << (2 * (level + 1))
    }

    /// Half the idealized size of a level.
    fn level_half(level: usize) -> u32 {
        Self::level_size(level) >> 1
    }

    /// Returns true if a level should spill at a given ledger.
    fn level_should_spill(ledger_seq: u32, level: usize) -> bool {
        if level == BUCKET_LIST_LEVELS - 1 {
            return false;
        }

        let half = Self::level_half(level);
        let size = Self::level_size(level);
        ledger_seq == Self::round_down(ledger_seq, half)
            || ledger_seq == Self::round_down(ledger_seq, size)
    }

    fn keep_tombstone_entries(level: usize) -> bool {
        level < BUCKET_LIST_LEVELS - 1
    }

    /// Get all hashes in the bucket list (for serialization).
    pub fn all_bucket_hashes(&self) -> Vec<Hash256> {
        let mut hashes = Vec::with_capacity(BUCKET_LIST_LEVELS * 2);
        for level in &self.levels {
            hashes.push(level.curr.hash());
            hashes.push(level.snap.hash());
        }
        hashes
    }

    /// Restore a bucket list from hashes and a bucket lookup function.
    pub fn restore_from_hashes<F>(hashes: &[Hash256], mut load_bucket: F) -> Result<Self>
    where
        F: FnMut(&Hash256) -> Result<Bucket>,
    {
        if hashes.len() != BUCKET_LIST_LEVELS * 2 {
            return Err(BucketError::Serialization(format!(
                "Expected {} bucket hashes, got {}",
                BUCKET_LIST_LEVELS * 2,
                hashes.len()
            )));
        }

        let mut levels = Vec::with_capacity(BUCKET_LIST_LEVELS);

        for (i, chunk) in hashes.chunks(2).enumerate() {
            let curr_hash = &chunk[0];
            let snap_hash = &chunk[1];

            let curr = if curr_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(curr_hash)?
            };

            let snap = if snap_hash.is_zero() {
                Bucket::empty()
            } else {
                load_bucket(snap_hash)?
            };

            let mut level = BucketLevel::new(i);
            level.curr = curr;
            level.snap = snap;
            levels.push(level);
        }

        Ok(Self { levels, ledger_seq: 0 })
    }

    /// Get statistics about the bucket list.
    pub fn stats(&self) -> BucketListStats {
        let mut total_entries = 0;
        let mut total_buckets = 0;

        for level in &self.levels {
            if !level.curr.is_empty() {
                total_entries += level.curr.len();
                total_buckets += 1;
            }
            if !level.snap.is_empty() {
                total_entries += level.snap.len();
                total_buckets += 1;
            }
        }

        BucketListStats {
            num_levels: BUCKET_LIST_LEVELS,
            total_entries,
            total_buckets,
        }
    }
}

impl Default for BucketList {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BucketList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketList")
            .field("ledger_seq", &self.ledger_seq)
            .field("hash", &self.hash().to_hex())
            .field("stats", &self.stats())
            .finish()
    }
}

/// Statistics about a BucketList.
#[derive(Debug, Clone)]
pub struct BucketListStats {
    /// Number of levels.
    pub num_levels: usize,
    /// Total number of entries across all buckets.
    pub total_entries: usize,
    /// Total number of non-empty buckets.
    pub total_buckets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    const TEST_PROTOCOL: u32 = 25;

    fn make_account_id(bytes: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_account_entry(bytes: [u8; 32], balance: i64) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(bytes),
                balance,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: Vec::new().try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    fn make_account_key(bytes: [u8; 32]) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id(bytes),
        })
    }

    #[test]
    fn test_new_bucket_list() {
        let bl = BucketList::new();
        assert_eq!(bl.levels().len(), BUCKET_LIST_LEVELS);
        assert_eq!(bl.ledger_seq(), 0);
    }

    #[test]
    fn test_add_batch_simple() {
        let mut bl = BucketList::new();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, TEST_PROTOCOL, BucketListType::Live, vec![entry], vec![], vec![])
            .unwrap();

        let key = make_account_key([1u8; 32]);
        let found = bl.get(&key).unwrap().unwrap();

        if let LedgerEntryData::Account(account) = &found.data {
            assert_eq!(account.balance, 100);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_add_batch_update() {
        let mut bl = BucketList::new();

        // Add initial entry
        let entry1 = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, TEST_PROTOCOL, BucketListType::Live, vec![entry1], vec![], vec![])
            .unwrap();

        // Update entry
        let entry2 = make_account_entry([1u8; 32], 200);
        bl.add_batch(2, TEST_PROTOCOL, BucketListType::Live, vec![], vec![entry2], vec![])
            .unwrap();

        let key = make_account_key([1u8; 32]);
        let found = bl.get(&key).unwrap().unwrap();

        if let LedgerEntryData::Account(account) = &found.data {
            assert_eq!(account.balance, 200);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_live_entries_respects_deletes() {
        let mut bl = BucketList::new();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, TEST_PROTOCOL, BucketListType::Live, vec![entry], vec![], vec![])
            .unwrap();

        let dead = make_account_key([1u8; 32]);
        bl.add_batch(2, TEST_PROTOCOL, BucketListType::Live, vec![], vec![], vec![dead])
            .unwrap();

        let entries = bl.live_entries().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_add_batch_delete() {
        let mut bl = BucketList::new();

        // Add entry
        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, TEST_PROTOCOL, BucketListType::Live, vec![entry], vec![], vec![])
            .unwrap();

        // Delete entry
        let key = make_account_key([1u8; 32]);
        bl.add_batch(
            2,
            TEST_PROTOCOL,
            BucketListType::Live,
            vec![],
            vec![],
            vec![key.clone()],
        )
        .unwrap();

        // Should not be found
        let found = bl.get(&key).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn test_level_sizes() {
        assert_eq!(BucketList::level_size(0), 4);
        assert_eq!(BucketList::level_size(1), 16);
        assert_eq!(BucketList::level_size(2), 64);
        assert_eq!(BucketList::level_size(3), 256);
        assert_eq!(BucketList::level_half(0), 2);
        assert_eq!(BucketList::level_half(1), 8);
        assert_eq!(BucketList::level_half(2), 32);
        assert_eq!(BucketList::level_half(3), 128);
    }

    #[test]
    fn test_bucket_list_hash_changes() {
        let mut bl = BucketList::new();
        let hash1 = bl.hash();

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, TEST_PROTOCOL, BucketListType::Live, vec![entry], vec![], vec![])
            .unwrap();
        let hash2 = bl.hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_contains() {
        let mut bl = BucketList::new();

        let key = make_account_key([1u8; 32]);
        assert!(!bl.contains(&key).unwrap());

        let entry = make_account_entry([1u8; 32], 100);
        bl.add_batch(1, TEST_PROTOCOL, BucketListType::Live, vec![entry], vec![], vec![])
            .unwrap();

        assert!(bl.contains(&key).unwrap());
    }

    #[test]
    fn test_multiple_levels() {
        let mut bl = BucketList::new();

        // Add many entries to trigger spills to higher levels
        for i in 1..=20u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let entry = make_account_entry(id, i as i64 * 100);
            bl.add_batch(
                i,
                TEST_PROTOCOL,
                BucketListType::Live,
                vec![entry],
                vec![],
                vec![],
            )
            .unwrap();
        }

        // Verify all entries are accessible
        for i in 1..=20u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            let found = bl.get(&key).unwrap();
            assert!(found.is_some(), "Entry {} not found", i);
        }
    }
}
