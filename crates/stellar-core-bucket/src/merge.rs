//! Bucket merging implementation.
//!
//! Merging is a critical operation in the BucketList that combines two buckets
//! while handling shadowing semantics:
//! - Newer entries shadow older entries with the same key
//! - Dead entries (tombstones) can either be kept or removed based on context
//! - Init entries have special merge semantics

use std::cmp::Ordering;

use stellar_xdr::curr::{BucketMetadata, BucketMetadataExt};

use crate::bucket::Bucket;
use crate::entry::{compare_keys, BucketEntry};
use crate::{BucketError, Result};

const FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY: u32 = 11;
const FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION: u32 = 23;

/// Merge two buckets into a new bucket.
///
/// The `new_bucket` contains newer entries that shadow entries in `old_bucket`.
///
/// # Arguments
/// * `old_bucket` - The older bucket (entries may be shadowed)
/// * `new_bucket` - The newer bucket (entries take precedence)
/// * `keep_dead_entries` - Whether to keep dead entries in the output
/// * `max_protocol_version` - Maximum protocol version allowed for the merge
///
/// # Merge Semantics
/// - When keys match, the newer entry wins
/// - Dead entries shadow live entries (the entry is deleted)
/// - If `keep_dead_entries` is false and a dead entry shadows nothing, it's removed
/// - Init entries are converted to Live entries when merged with older buckets
pub fn merge_buckets(
    old_bucket: &Bucket,
    new_bucket: &Bucket,
    keep_dead_entries: bool,
    max_protocol_version: u32,
) -> Result<Bucket> {
    // Fast path: if new is empty, return old unchanged.
    if new_bucket.is_empty() {
        return Ok(old_bucket.clone());
    }

    // Note: We cannot use a fast path when old is empty because we need to
    // convert any Init entries in new to Live entries (they're crossing a
    // merge boundary). The merge logic below handles this via normalize_entry().

    // Get entries from both buckets (already sorted)
    // Note: use iter() instead of entries() to support disk-backed buckets
    let old_entries: Vec<BucketEntry> = old_bucket.iter().collect();
    let new_entries: Vec<BucketEntry> = new_bucket.iter().collect();

    tracing::trace!(
        old_hash = %old_bucket.hash(),
        new_hash = %new_bucket.hash(),
        old_entries = old_entries.len(),
        new_entries = new_entries.len(),
        "merge_buckets starting"
    );

    let old_meta = extract_metadata(&old_entries);
    let new_meta = extract_metadata(&new_entries);
    let (_, output_meta) =
        build_output_metadata(old_meta.as_ref(), new_meta.as_ref(), max_protocol_version)?;

    let mut merged = Vec::with_capacity(
        old_entries.len() + new_entries.len() + output_meta.as_ref().map(|_| 1).unwrap_or(0),
    );

    if let Some(meta) = output_meta {
        merged.push(meta);
    }

    let mut old_idx = 0;
    let mut new_idx = 0;

    // Skip metadata entries from old and new buckets; we'll insert output metadata ourselves.
    while old_idx < old_entries.len() && old_entries[old_idx].is_metadata() {
        old_idx += 1;
    }

    while new_idx < new_entries.len() && new_entries[new_idx].is_metadata() {
        new_idx += 1;
    }

    // Merge the remaining entries
    while old_idx < old_entries.len() && new_idx < new_entries.len() {
        let old_entry = &old_entries[old_idx];
        let new_entry = &new_entries[new_idx];

        let old_key = old_entry.key();
        let new_key = new_entry.key();

        match (old_key, new_key) {
            (Some(ref ok), Some(ref nk)) => {
                match compare_keys(ok, nk) {
                    Ordering::Less => {
                        // Old entry comes first, no shadow
                        // DON'T normalize old entries - they should stay as-is
                        // Init entries in old bucket are from before this merge boundary
                        merged.push(old_entry.clone());
                        old_idx += 1;
                    }
                    Ordering::Greater => {
                        // New entry comes first
                        if should_keep_entry(new_entry, keep_dead_entries) {
                            merged.push(normalize_entry(new_entry.clone()));
                        }
                        new_idx += 1;
                    }
                    Ordering::Equal => {
                        // Keys match - new entry shadows old entry
                        // Apply merge semantics (per CAP-0020)
                        if let Some(merged_entry) =
                            merge_entries(old_entry, new_entry, keep_dead_entries)
                        {
                            merged.push(merged_entry);
                        }
                        old_idx += 1;
                        new_idx += 1;
                    }
                }
            }
            (None, Some(_)) => old_idx += 1,
            (Some(_), None) => new_idx += 1,
            (None, None) => {
                old_idx += 1;
                new_idx += 1;
            }
        }
    }

    // Add remaining old entries
    while old_idx < old_entries.len() {
        let entry = &old_entries[old_idx];
        if !entry.is_metadata() {
            merged.push(entry.clone());
        }
        old_idx += 1;
    }

    // Add remaining new entries
    while new_idx < new_entries.len() {
        let entry = &new_entries[new_idx];
        if !entry.is_metadata() && should_keep_entry(entry, keep_dead_entries) {
            merged.push(normalize_entry(entry.clone()));
        }
        new_idx += 1;
    }

    if merged.is_empty() {
        return Ok(Bucket::empty());
    }

    let result = Bucket::from_entries(merged)?;
    tracing::trace!(
        result_hash = %result.hash(),
        result_entries = result.len(),
        "merge_buckets complete"
    );
    Ok(result)
}

/// Check if an entry should be kept in the merged output.
fn should_keep_entry(entry: &BucketEntry, keep_dead_entries: bool) -> bool {
    match entry {
        BucketEntry::Dead(_) => keep_dead_entries,
        _ => true,
    }
}

/// Normalize an entry (convert Init to Live).
fn normalize_entry(entry: BucketEntry) -> BucketEntry {
    match entry {
        BucketEntry::Init(e) => BucketEntry::Live(e),
        other => other,
    }
}

/// Merge two entries with the same key.
///
/// Returns the merged entry, or None if the entry should be removed.
///
/// Merge semantics per CAP-0020:
/// - INITENTRY + DEADENTRY → Both annihilated (nothing output)
/// - INITENTRY=x + LIVEENTRY=y → Output as INITENTRY=y (preserves INIT status)
/// - DEADENTRY + INITENTRY=x → Output as LIVEENTRY=x
/// - LIVEENTRY + DEADENTRY → Dead (if keep_dead_entries) or nothing
/// - Any + LIVEENTRY → LIVEENTRY wins
fn merge_entries(
    old: &BucketEntry,
    new: &BucketEntry,
    keep_dead_entries: bool,
) -> Option<BucketEntry> {
    match (old, new) {
        // CAP-0020: INITENTRY + DEADENTRY → Both annihilated
        // This is a key optimization: if we created and then deleted in the same
        // merge window, we output nothing at all.
        (BucketEntry::Init(_), BucketEntry::Dead(_)) => None,

        // CAP-0020: DEADENTRY + INITENTRY=x → Output as LIVEENTRY=x
        // The old tombstone is cancelled by the new creation
        (BucketEntry::Dead(_), BucketEntry::Init(entry)) => {
            Some(BucketEntry::Live(entry.clone()))
        }

        // CAP-0020: INITENTRY=x + LIVEENTRY=y → Output as INITENTRY=y
        // Preserve the INIT status (entry was created in this merge range)
        (BucketEntry::Init(_), BucketEntry::Live(entry)) => {
            Some(BucketEntry::Init(entry.clone()))
        }

        // New Live shadows old Live - new wins
        (BucketEntry::Live(_), BucketEntry::Live(entry)) => {
            Some(BucketEntry::Live(entry.clone()))
        }

        // New Live shadows old Dead - live wins
        (BucketEntry::Dead(_), BucketEntry::Live(entry)) => {
            Some(BucketEntry::Live(entry.clone()))
        }

        // Any old + new Init (not covered above) → convert to Live
        (_, BucketEntry::Init(entry)) => Some(BucketEntry::Live(entry.clone())),

        // LIVEENTRY + DEADENTRY → Dead entry (tombstone) if keeping, else nothing
        (BucketEntry::Live(_), BucketEntry::Dead(key)) => {
            if keep_dead_entries {
                Some(BucketEntry::Dead(key.clone()))
            } else {
                None
            }
        }

        // Dead shadows Dead - keep newest if needed
        (BucketEntry::Dead(_), BucketEntry::Dead(key)) => {
            if keep_dead_entries {
                Some(BucketEntry::Dead(key.clone()))
            } else {
                None
            }
        }

        // Metadata shouldn't have matching keys
        (BucketEntry::Metadata(_), _) | (_, BucketEntry::Metadata(_)) => None,
    }
}

/// Output iterator for streaming merge.
///
/// Note: For disk-backed buckets, entries are collected upfront. For in-memory
/// buckets, this is still memory-efficient as it references existing entries.
pub struct MergeIterator {
    old_entries: Vec<BucketEntry>,
    new_entries: Vec<BucketEntry>,
    old_idx: usize,
    new_idx: usize,
    keep_dead_entries: bool,
    output_metadata: Option<BucketEntry>,
}

impl MergeIterator {
    /// Create a new merge iterator.
    pub fn new(
        old_bucket: &Bucket,
        new_bucket: &Bucket,
        keep_dead_entries: bool,
        max_protocol_version: u32,
    ) -> Self {
        // Collect entries - works for both in-memory and disk-backed buckets
        let old_entries: Vec<BucketEntry> = old_bucket.iter().collect();
        let new_entries: Vec<BucketEntry> = new_bucket.iter().collect();
        let old_meta = extract_metadata(&old_entries);
        let new_meta = extract_metadata(&new_entries);
        let (_, output_metadata) = build_output_metadata(
            old_meta.as_ref(),
            new_meta.as_ref(),
            max_protocol_version,
        )
        .unwrap_or((0, None));

        Self {
            old_entries,
            new_entries,
            old_idx: 0,
            new_idx: 0,
            keep_dead_entries,
            output_metadata,
        }
    }
}

impl Iterator for MergeIterator {
    type Item = BucketEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(meta) = self.output_metadata.take() {
            while self.old_idx < self.old_entries.len()
                && self.old_entries[self.old_idx].is_metadata()
            {
                self.old_idx += 1;
            }
            while self.new_idx < self.new_entries.len()
                && self.new_entries[self.new_idx].is_metadata()
            {
                self.new_idx += 1;
            }
            return Some(meta);
        }

        loop {
            // Check if we're done with both
            if self.old_idx >= self.old_entries.len() && self.new_idx >= self.new_entries.len() {
                return None;
            }

            // Only old entries left
            if self.new_idx >= self.new_entries.len() {
                let entry = self.old_entries[self.old_idx].clone();
                self.old_idx += 1;
                if !entry.is_metadata() {
                    return Some(entry);
                }
                continue;
            }

            // Only new entries left
            if self.old_idx >= self.old_entries.len() {
                let entry = self.new_entries[self.new_idx].clone();
                self.new_idx += 1;
                if !entry.is_metadata() && should_keep_entry(&entry, self.keep_dead_entries) {
                    return Some(normalize_entry(entry));
                }
                continue;
            }

            // Both have entries
            let old_entry = &self.old_entries[self.old_idx];
            let new_entry = &self.new_entries[self.new_idx];

            let old_key = old_entry.key();
            let new_key = new_entry.key();

            match (old_key, new_key) {
                (Some(ref ok), Some(ref nk)) => {
                    match compare_keys(ok, nk) {
                        Ordering::Less => {
                            self.old_idx += 1;
                            return Some(old_entry.clone());
                        }
                        Ordering::Greater => {
                            self.new_idx += 1;
                            if should_keep_entry(new_entry, self.keep_dead_entries) {
                                return Some(normalize_entry(new_entry.clone()));
                            }
                            continue;
                        }
                        Ordering::Equal => {
                            self.old_idx += 1;
                            self.new_idx += 1;
                            if let Some(merged) =
                                merge_entries(old_entry, new_entry, self.keep_dead_entries)
                            {
                                return Some(merged);
                            }
                            continue;
                        }
                    }
                }
                (None, Some(_)) => {
                    self.old_idx += 1;
                    continue;
                }
                (Some(_), None) => {
                    self.new_idx += 1;
                    continue;
                }
                (None, None) => {
                    self.old_idx += 1;
                    self.new_idx += 1;
                    continue;
                }
            }
        }
    }
}

/// Merge multiple buckets in order (first is oldest).
pub fn merge_multiple(
    buckets: &[&Bucket],
    keep_dead_entries: bool,
    max_protocol_version: u32,
) -> Result<Bucket> {
    if buckets.is_empty() {
        return Ok(Bucket::empty());
    }

    let mut result = buckets[0].clone();

    for bucket in &buckets[1..] {
        result = merge_buckets(&result, bucket, keep_dead_entries, max_protocol_version)?;
    }

    Ok(result)
}

fn extract_metadata(entries: &[BucketEntry]) -> Option<BucketMetadata> {
    entries.iter().find_map(|entry| match entry {
        BucketEntry::Metadata(meta) => Some(meta.clone()),
        _ => None,
    })
}

fn build_output_metadata(
    old_meta: Option<&BucketMetadata>,
    new_meta: Option<&BucketMetadata>,
    max_protocol_version: u32,
) -> Result<(u32, Option<BucketEntry>)> {
    let mut protocol_version = 0u32;
    if let Some(meta) = old_meta {
        protocol_version = protocol_version.max(meta.ledger_version);
    }
    if let Some(meta) = new_meta {
        protocol_version = protocol_version.max(meta.ledger_version);
    }

    if protocol_version == 0 {
        protocol_version = max_protocol_version;
    }

    if max_protocol_version != 0 && protocol_version > max_protocol_version {
        return Err(BucketError::Merge(format!(
            "bucket protocol version {} exceeds maxProtocolVersion {}",
            protocol_version, max_protocol_version
        )));
    }

    let use_meta = protocol_version >= FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY;
    if !use_meta {
        return Ok((protocol_version, None));
    }

    let mut output = BucketMetadata {
        ledger_version: protocol_version,
        ext: BucketMetadataExt::V0,
    };

    if let Some(meta) = new_meta.filter(|meta| matches!(meta.ext, BucketMetadataExt::V1(_))) {
        if max_protocol_version != 0
            && max_protocol_version < FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION
        {
            return Err(BucketError::Merge(
                "bucket metadata ext v1 requires protocol >= 23".to_string(),
            ));
        }
        output.ext = meta.ext.clone();
    } else if let Some(meta) =
        old_meta.filter(|meta| matches!(meta.ext, BucketMetadataExt::V1(_)))
    {
        if max_protocol_version != 0
            && max_protocol_version < FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION
        {
            return Err(BucketError::Merge(
                "bucket metadata ext v1 requires protocol >= 23".to_string(),
            ));
        }
        output.ext = meta.ext.clone();
    }

    Ok((protocol_version, Some(BucketEntry::Metadata(output))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry

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
    fn test_merge_empty_buckets() {
        let empty1 = Bucket::empty();
        let empty2 = Bucket::empty();

        let merged = merge_buckets(&empty1, &empty2, true, 0).unwrap();
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_with_empty() {
        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let bucket = Bucket::from_entries(entries).unwrap();
        let empty = Bucket::empty();

        // New is empty
        let merged = merge_buckets(&bucket, &empty, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Old is empty
        let merged = merge_buckets(&empty, &bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_no_overlap() {
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_shadow() {
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Verify new entry won
        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 200);
        } else {
            panic!("Expected Account entry");
        }
    }

    #[test]
    fn test_merge_dead_shadows_live() {
        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        // With keep_dead_entries = true
        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);
        assert!(merged.entries()[0].is_dead());

        // With keep_dead_entries = false
        let merged = merge_buckets(&old_bucket, &new_bucket, false, 0).unwrap();
        assert_eq!(merged.len(), 0);
    }

    #[test]
    fn test_merge_init_to_live() {
        let entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let bucket = Bucket::from_entries(entries).unwrap();

        let merged = merge_buckets(&Bucket::empty(), &bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Init should be converted to Live
        assert!(merged.entries()[0].is_live());
    }

    #[test]
    fn test_merge_complex() {
        let old_entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
            BucketEntry::Live(make_account_entry([3u8; 32], 300)),
        ];

        let new_entries = vec![
            BucketEntry::Dead(make_account_key([1u8; 32])),            // Delete first
            BucketEntry::Live(make_account_entry([2u8; 32], 250)),     // Update second
            BucketEntry::Live(make_account_entry([4u8; 32], 400)),     // Add new
        ];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();

        // Should have: Dead(1), Live(2, 250), Live(3, 300), Live(4, 400)
        assert_eq!(merged.len(), 4);

        // Verify entries
        let key1 = make_account_key([1u8; 32]);
        assert!(merged.get(&key1).unwrap().unwrap().is_dead());

        let key2 = make_account_key([2u8; 32]);
        let entry2 = merged.get_entry(&key2).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry2.data {
            assert_eq!(account.balance, 250);
        }

        let key3 = make_account_key([3u8; 32]);
        let entry3 = merged.get_entry(&key3).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry3.data {
            assert_eq!(account.balance, 300);
        }

        let key4 = make_account_key([4u8; 32]);
        let entry4 = merged.get_entry(&key4).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry4.data {
            assert_eq!(account.balance, 400);
        }
    }

    #[test]
    fn test_merge_iterator() {
        let old_entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([3u8; 32], 300)),
        ];

        let new_entries = vec![
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let iter = MergeIterator::new(&old_bucket, &new_bucket, true, 0);
        let merged: Vec<_> = iter.collect();

        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn test_merge_multiple() {
        let bucket1 = Bucket::from_entries(vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
        ])
        .unwrap();

        let bucket2 = Bucket::from_entries(vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 200)),
        ])
        .unwrap();

        let bucket3 = Bucket::from_entries(vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 300)),
        ])
        .unwrap();

        let buckets = vec![&bucket1, &bucket2, &bucket3];
        let merged = merge_multiple(&buckets, true, 0).unwrap();

        assert_eq!(merged.len(), 1);

        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 300); // Newest wins
        }
    }

    // ============ CAP-0020 INITENTRY Tests ============

    #[test]
    fn test_cap0020_init_plus_dead_annihilation() {
        // CAP-0020: INITENTRY + DEADENTRY → Both annihilated
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        // Even with keep_dead_entries = true, INIT + DEAD should annihilate
        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 0, "INIT + DEAD should produce nothing");
    }

    #[test]
    fn test_cap0020_dead_plus_init_becomes_live() {
        // CAP-0020: DEADENTRY + INITENTRY=x → Output as LIVEENTRY=x
        let old_entries = vec![BucketEntry::Dead(make_account_key([1u8; 32]))];
        let new_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);
        assert!(merged.entries()[0].is_live(), "DEAD + INIT should become LIVE");

        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 200);
        }
    }

    #[test]
    fn test_cap0020_init_plus_live_preserves_init() {
        // CAP-0020: INITENTRY=x + LIVEENTRY=y → Output as INITENTRY=y
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // Should preserve INIT status with new value
        let entry = &merged.entries()[0];
        assert!(entry.is_init(), "INIT + LIVE should preserve INIT status");

        let _key = make_account_key([1u8; 32]);
        if let BucketEntry::Init(ledger_entry) = entry {
            if let LedgerEntryData::Account(account) = &ledger_entry.data {
                assert_eq!(account.balance, 200, "Should have new value");
            }
        }
    }

    #[test]
    fn test_cap0020_init_init_undefined() {
        // Two INITs for the same key should not happen in practice (it's undefined behavior).
        // Our implementation converts it to LIVE through the catch-all case.
        let old_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Init(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();
        assert_eq!(merged.len(), 1);

        // New entry wins and becomes LIVE (via catch-all)
        let entry = &merged.entries()[0];
        assert!(entry.is_live(), "INIT + INIT should become LIVE (undefined case)");

        let key = make_account_key([1u8; 32]);
        let ledger_entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &ledger_entry.data {
            assert_eq!(account.balance, 200, "New value should win");
        }
    }

    #[test]
    fn test_cap0020_complex_scenario() {
        // Complex scenario testing multiple CAP-0020 rules
        let old_entries = vec![
            BucketEntry::Init(make_account_entry([1u8; 32], 100)),   // Will be deleted (annihilated)
            BucketEntry::Dead(make_account_key([2u8; 32])),          // Will be recreated
            BucketEntry::Init(make_account_entry([3u8; 32], 300)),   // Will be updated (preserve INIT)
            BucketEntry::Live(make_account_entry([4u8; 32], 400)),   // Will be deleted
        ];

        let new_entries = vec![
            BucketEntry::Dead(make_account_key([1u8; 32])),          // Annihilates with old INIT
            BucketEntry::Init(make_account_entry([2u8; 32], 200)),   // Recreates, becomes LIVE
            BucketEntry::Live(make_account_entry([3u8; 32], 350)),   // Updates, preserves INIT
            BucketEntry::Dead(make_account_key([4u8; 32])),          // Deletes LIVE
        ];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = merge_buckets(&old_bucket, &new_bucket, true, 0).unwrap();

        // Entry 1: INIT + DEAD = nothing (annihilated)
        let key1 = make_account_key([1u8; 32]);
        assert!(merged.get(&key1).unwrap().is_none(), "Entry 1 should be annihilated");

        // Entry 2: DEAD + INIT = LIVE
        let key2 = make_account_key([2u8; 32]);
        let entry2 = merged.get(&key2).unwrap().unwrap();
        assert!(entry2.is_live(), "Entry 2 should be LIVE");

        // Entry 3: INIT + LIVE = INIT (preserved)
        let key3 = make_account_key([3u8; 32]);
        let entry3 = merged.get(&key3).unwrap().unwrap();
        assert!(entry3.is_init(), "Entry 3 should preserve INIT");

        // Entry 4: LIVE + DEAD = DEAD
        let key4 = make_account_key([4u8; 32]);
        let entry4 = merged.get(&key4).unwrap().unwrap();
        assert!(entry4.is_dead(), "Entry 4 should be DEAD");
    }
}
