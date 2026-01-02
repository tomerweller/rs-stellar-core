//! BucketList implementation for rs-stellar-core.
//!
//! The BucketList is Stellar's core data structure for storing ledger state.
//! It provides:
//!
//! - Efficient incremental updates as ledgers close
//! - Merkle tree structure for integrity verification
//! - Hierarchical organization with multiple levels
//! - Support for live entries, dead entries, and init entries
//!
//! ## Structure
//!
//! The BucketList consists of multiple levels, where each level contains two buckets:
//! - `curr`: The current bucket being filled
//! - `snap`: The snapshot bucket from the previous merge
//!
//! Lower levels update more frequently, while higher levels contain older data
//! and update less often (similar to a log-structured merge tree).
//!
//! ## Spill Frequency
//!
//! Levels spill on a schedule derived from their size and half-size boundaries
//! (see `BucketList::level_size` and `BucketList::level_half`). This matches
//! stellar-core's `BucketListBase::levelShouldSpill` logic.
//!
//! ## Entry Types
//!
//! - `LiveEntry`: A live ledger entry
//! - `DeadEntry`: A tombstone marking deletion
//! - `InitEntry`: Like LiveEntry but with different merge semantics
//! - `Metadata`: Bucket metadata (protocol version, etc.)
//!
//! ## Example
//!
//! ```ignore
//! use stellar_core_bucket::{BucketList, BucketManager};
//!
//! // Create a bucket manager
//! let manager = BucketManager::new("/tmp/buckets".into())?;
//!
//! // Create a new bucket list
//! let mut bucket_list = BucketList::new();
//!
//! // Add entries from a closed ledger
//! bucket_list.add_batch(1, protocol_version, BucketListType::Live, init_entries, live_entries, dead_entries)?;
//!
//! // Look up an entry
//! if let Some(entry) = bucket_list.get(&key)? {
//!     // Use the entry
//! }
//!
//! // Get the bucket list hash for verification
//! let hash = bucket_list.hash();
//! ```

mod bucket;
mod bucket_list;
mod disk_bucket;
mod entry;
mod error;
mod manager;
mod merge;

// Re-export main types
pub use bucket::Bucket;
pub use bucket_list::{BucketLevel, BucketList, BucketListStats, BUCKET_LIST_LEVELS};
pub use disk_bucket::{DiskBucket, DiskBucketIter};
pub use entry::{compare_entries, compare_keys, ledger_entry_to_key, BucketEntry};
pub use error::BucketError;
pub use manager::{BucketManager, BucketManagerStats};
pub use merge::{merge_buckets, merge_multiple, MergeIterator};

/// Result type for bucket operations.
pub type Result<T> = std::result::Result<T, BucketError>;

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry

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
    fn test_integration_bucket_list_with_manager() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = BucketManager::new(temp_dir.path().to_path_buf()).unwrap();

        // Create entries
        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        // Create bucket through manager
        let bucket = manager.create_bucket(entries).unwrap();
        assert_eq!(bucket.len(), 2);

        // Verify bucket is on disk
        assert!(manager.bucket_exists(&bucket.hash()));

        // Load bucket
        manager.clear_cache();
        let loaded = manager.load_bucket(&bucket.hash()).unwrap();
        assert_eq!(loaded.hash(), bucket.hash());
    }

    #[test]
    fn test_integration_full_workflow() {
        // Create a bucket list and add entries over multiple ledgers
        let mut bucket_list = BucketList::new();

        // Add entries for ledgers 1-10
        for i in 1..=10u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let entry = make_account_entry(id, i as i64 * 100);
            bucket_list
                .add_batch(i, TEST_PROTOCOL, BucketListType::Live, vec![entry], vec![], vec![])
                .unwrap();
        }

        // Verify all entries are accessible
        for i in 1..=10u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            let entry = bucket_list.get(&key).unwrap().unwrap();
            if let LedgerEntryData::Account(account) = &entry.data {
                assert_eq!(account.balance, i as i64 * 100);
            }
        }

        // Update some entries
        for i in 1..=5u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let entry = make_account_entry(id, i as i64 * 1000);
            bucket_list
                .add_batch(
                    10 + i,
                    TEST_PROTOCOL,
                    BucketListType::Live,
                    vec![],
                    vec![entry],
                    vec![],
                )
                .unwrap();
        }

        // Verify updates
        for i in 1..=5u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            let entry = bucket_list.get(&key).unwrap().unwrap();
            if let LedgerEntryData::Account(account) = &entry.data {
                assert_eq!(account.balance, i as i64 * 1000);
            }
        }

        // Delete some entries
        for i in 6..=8u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            bucket_list
                .add_batch(
                    10 + i,
                    TEST_PROTOCOL,
                    BucketListType::Live,
                    vec![],
                    vec![],
                    vec![key],
                )
                .unwrap();
        }

        // Verify deletions
        for i in 6..=8u32 {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            assert!(bucket_list.get(&key).unwrap().is_none());
        }

        // Remaining entries should still exist
        for i in [9u32, 10] {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&i.to_be_bytes());
            let key = make_account_key(id);
            assert!(bucket_list.get(&key).unwrap().is_some());
        }
    }

    #[test]
    fn test_bucket_list_constants() {
        assert_eq!(BUCKET_LIST_LEVELS, 11);
        assert_eq!(BucketList::NUM_LEVELS, 11);
    }

    #[test]
    fn test_bucket_entry_types() {
        let entry = make_account_entry([1u8; 32], 100);
        let key = make_account_key([1u8; 32]);

        let live = BucketEntry::Live(entry.clone());
        assert!(live.is_live());
        assert!(!live.is_dead());
        assert!(!live.is_init());
        assert!(!live.is_metadata());

        let dead = BucketEntry::Dead(key);
        assert!(!dead.is_live());
        assert!(dead.is_dead());
        assert!(!dead.is_init());

        let init = BucketEntry::Init(entry);
        assert!(!init.is_live());
        assert!(!init.is_dead());
        assert!(init.is_init());
    }
}
