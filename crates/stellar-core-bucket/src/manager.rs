//! BucketManager - manages bucket files on disk.
//!
//! The BucketManager handles:
//! - Creating buckets from entries (sort, serialize, compress, write)
//! - Loading buckets by hash
//! - Caching loaded buckets in memory
//! - Cleaning up unused bucket files

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use stellar_xdr::curr::{LedgerEntry, LedgerKey};

use stellar_core_common::Hash256;

use crate::bucket::Bucket;
use crate::entry::BucketEntry;
use crate::merge::merge_buckets;
use crate::{BucketError, Result};

/// Manager for bucket files on disk.
///
/// The BucketManager is responsible for:
/// - Storing bucket files in a directory
/// - Loading buckets by their content hash
/// - Caching buckets in memory
/// - Creating new buckets from entries
pub struct BucketManager {
    /// Directory where bucket files are stored.
    bucket_dir: PathBuf,
    /// Cache of loaded buckets, keyed by hash.
    cache: RwLock<HashMap<Hash256, Arc<Bucket>>>,
    /// Maximum number of buckets to cache.
    max_cache_size: usize,
}

impl BucketManager {
    /// Default maximum cache size.
    pub const DEFAULT_MAX_CACHE_SIZE: usize = 100;

    /// Create a new BucketManager with the given directory.
    pub fn new(bucket_dir: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&bucket_dir)?;

        Ok(Self {
            bucket_dir,
            cache: RwLock::new(HashMap::new()),
            max_cache_size: Self::DEFAULT_MAX_CACHE_SIZE,
        })
    }

    /// Create a new BucketManager with a custom cache size.
    pub fn with_cache_size(bucket_dir: PathBuf, max_cache_size: usize) -> Result<Self> {
        std::fs::create_dir_all(&bucket_dir)?;

        Ok(Self {
            bucket_dir,
            cache: RwLock::new(HashMap::new()),
            max_cache_size,
        })
    }

    /// Get the bucket directory path.
    pub fn bucket_dir(&self) -> &Path {
        &self.bucket_dir
    }

    /// Get the file path for a bucket with the given hash.
    pub fn bucket_path(&self, hash: &Hash256) -> PathBuf {
        self.bucket_dir.join(format!("{}.bucket.gz", hash.to_hex()))
    }

    /// Create a bucket from entries.
    ///
    /// This will:
    /// 1. Sort entries by key
    /// 2. Create the bucket
    /// 3. Save to disk
    /// 4. Add to cache
    pub fn create_bucket(&self, entries: Vec<BucketEntry>) -> Result<Arc<Bucket>> {
        if entries.is_empty() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Create bucket (entries will be sorted)
        let bucket = Bucket::from_entries(entries)?;
        let hash = bucket.hash();

        // Check if already cached
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&hash) {
                return Ok(Arc::clone(cached));
            }
        }

        // Save to disk
        let path = self.bucket_path(&hash);
        bucket.save_to_file(&path)?;

        // Add to cache
        let bucket = Arc::new(bucket);
        self.add_to_cache(hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Create a bucket from live and dead entries.
    pub fn create_bucket_from_ledger_entries(
        &self,
        live_entries: Vec<LedgerEntry>,
        dead_entries: Vec<LedgerKey>,
    ) -> Result<Arc<Bucket>> {
        let mut entries: Vec<BucketEntry> = live_entries
            .into_iter()
            .map(BucketEntry::Live)
            .collect();

        entries.extend(dead_entries.into_iter().map(BucketEntry::Dead));

        self.create_bucket(entries)
    }

    /// Load a bucket by its hash.
    ///
    /// First checks the cache, then loads from disk if not cached.
    pub fn load_bucket(&self, hash: &Hash256) -> Result<Arc<Bucket>> {
        // Check if it's the empty bucket
        if hash.is_zero() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(bucket) = cache.get(hash) {
                return Ok(Arc::clone(bucket));
            }
        }

        // Load from disk
        let path = self.bucket_path(hash);
        if !path.exists() {
            return Err(BucketError::NotFound(hash.to_hex()));
        }

        let bucket = Bucket::load_from_file(&path)?;

        // Verify hash matches
        if bucket.hash() != *hash {
            return Err(BucketError::HashMismatch {
                expected: hash.to_hex(),
                actual: bucket.hash().to_hex(),
            });
        }

        // Add to cache
        let bucket = Arc::new(bucket);
        self.add_to_cache(*hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Check if a bucket exists (in cache or on disk).
    pub fn bucket_exists(&self, hash: &Hash256) -> bool {
        if hash.is_zero() {
            return true; // Empty bucket always "exists"
        }

        // Check cache
        {
            let cache = self.cache.read().unwrap();
            if cache.contains_key(hash) {
                return true;
            }
        }

        // Check disk
        self.bucket_path(hash).exists()
    }

    /// Merge two buckets and create a new bucket.
    pub fn merge(
        &self,
        old: &Bucket,
        new: &Bucket,
        max_protocol_version: u32,
    ) -> Result<Arc<Bucket>> {
        let merged = merge_buckets(old, new, true, max_protocol_version)?;

        if merged.is_empty() {
            return Ok(Arc::new(Bucket::empty()));
        }

        // Check if already cached
        let hash = merged.hash();
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&hash) {
                return Ok(Arc::clone(cached));
            }
        }

        // Save to disk
        let path = self.bucket_path(&hash);
        merged.save_to_file(&path)?;

        // Add to cache
        let bucket = Arc::new(merged);
        self.add_to_cache(hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Merge two buckets asynchronously.
    pub async fn merge_async(
        &self,
        old: &Bucket,
        new: &Bucket,
        max_protocol_version: u32,
    ) -> Result<Arc<Bucket>> {
        // For now, just call the sync version
        // In the future, this could use tokio::task::spawn_blocking
        self.merge(old, new, max_protocol_version)
    }

    /// Add a bucket to the cache.
    fn add_to_cache(&self, hash: Hash256, bucket: Arc<Bucket>) {
        let mut cache = self.cache.write().unwrap();

        // Evict if cache is full (simple LRU would be better)
        if cache.len() >= self.max_cache_size {
            // Remove a random entry (not ideal, but simple)
            if let Some(key) = cache.keys().next().cloned() {
                cache.remove(&key);
            }
        }

        cache.insert(hash, bucket);
    }

    /// Clear the bucket cache.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }

    /// Get the number of cached buckets.
    pub fn cache_size(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    /// List all bucket files in the directory.
    pub fn list_buckets(&self) -> Result<Vec<Hash256>> {
        let mut hashes = Vec::new();

        for entry in std::fs::read_dir(&self.bucket_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".bucket.gz") {
                    let hash_str = name.trim_end_matches(".bucket.gz");
                    if let Ok(hash) = Hash256::from_hex(hash_str) {
                        hashes.push(hash);
                    }
                }
            }
        }

        Ok(hashes)
    }

    /// Delete a bucket file.
    ///
    /// This also removes the bucket from the cache.
    pub fn delete_bucket(&self, hash: &Hash256) -> Result<()> {
        // Remove from cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.remove(hash);
        }

        // Delete file
        let path = self.bucket_path(hash);
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        Ok(())
    }

    /// Delete all bucket files not in the given set of hashes.
    ///
    /// This is useful for garbage collection.
    pub fn retain_buckets(&self, keep: &[Hash256]) -> Result<usize> {
        let keep_set: std::collections::HashSet<_> = keep.iter().collect();
        let all_buckets = self.list_buckets()?;
        let mut deleted = 0;

        for hash in all_buckets {
            if !keep_set.contains(&hash) {
                self.delete_bucket(&hash)?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Get statistics about the bucket manager.
    pub fn stats(&self) -> BucketManagerStats {
        let cached = self.cache_size();
        let on_disk = self.list_buckets().map(|v| v.len()).unwrap_or(0);

        BucketManagerStats {
            cached_buckets: cached,
            disk_buckets: on_disk,
            bucket_dir: self.bucket_dir.clone(),
        }
    }

    /// Import a bucket from raw XDR bytes.
    pub fn import_bucket(&self, xdr_bytes: &[u8]) -> Result<Arc<Bucket>> {
        let bucket = Bucket::from_xdr_bytes(xdr_bytes)?;
        let hash = bucket.hash();

        // Check cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(&hash) {
                return Ok(Arc::clone(cached));
            }
        }

        // Save to disk
        let path = self.bucket_path(&hash);
        bucket.save_to_file(&path)?;

        // Add to cache
        let bucket = Arc::new(bucket);
        self.add_to_cache(hash, Arc::clone(&bucket));

        Ok(bucket)
    }

    /// Export a bucket to raw XDR bytes.
    pub fn export_bucket(&self, hash: &Hash256) -> Result<Vec<u8>> {
        let bucket = self.load_bucket(hash)?;
        bucket.to_xdr_bytes()
    }
}

impl std::fmt::Debug for BucketManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BucketManager")
            .field("bucket_dir", &self.bucket_dir)
            .field("cache_size", &self.cache_size())
            .field("max_cache_size", &self.max_cache_size)
            .finish()
    }
}

/// Statistics about a BucketManager.
#[derive(Debug, Clone)]
pub struct BucketManagerStats {
    /// Number of buckets in the cache.
    pub cached_buckets: usize,
    /// Number of bucket files on disk.
    pub disk_buckets: usize,
    /// The bucket directory path.
    pub bucket_dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry
    use tempfile::TempDir;

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

    fn create_manager() -> (TempDir, BucketManager) {
        let temp_dir = TempDir::new().unwrap();
        let manager = BucketManager::new(temp_dir.path().to_path_buf()).unwrap();
        (temp_dir, manager)
    }

    #[test]
    fn test_create_bucket() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let bucket = manager.create_bucket(entries).unwrap();
        assert_eq!(bucket.len(), 2);
        assert!(!bucket.hash().is_zero());
    }

    #[test]
    fn test_load_bucket() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];

        let bucket = manager.create_bucket(entries).unwrap();
        let hash = bucket.hash();

        // Clear cache to force disk load
        manager.clear_cache();

        let loaded = manager.load_bucket(&hash).unwrap();
        assert_eq!(loaded.hash(), hash);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn test_bucket_caching() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];

        let bucket = manager.create_bucket(entries).unwrap();
        let hash = bucket.hash();

        assert_eq!(manager.cache_size(), 1);

        // Loading again should use cache
        let loaded = manager.load_bucket(&hash).unwrap();
        assert!(Arc::ptr_eq(&bucket, &loaded));
    }

    #[test]
    fn test_bucket_exists() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];

        let bucket = manager.create_bucket(entries).unwrap();
        let hash = bucket.hash();

        assert!(manager.bucket_exists(&hash));
        assert!(!manager.bucket_exists(&Hash256::hash(b"nonexistent")));
        assert!(manager.bucket_exists(&Hash256::ZERO)); // Empty bucket
    }

    #[test]
    fn test_merge_buckets() {
        let (_temp_dir, manager) = create_manager();

        let old_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let new_entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 200))];

        let old_bucket = Bucket::from_entries(old_entries).unwrap();
        let new_bucket = Bucket::from_entries(new_entries).unwrap();

        let merged = manager.merge(&old_bucket, &new_bucket, 0).unwrap();
        assert_eq!(merged.len(), 1);

        let key = make_account_key([1u8; 32]);
        let entry = merged.get_entry(&key).unwrap().unwrap();
        if let LedgerEntryData::Account(account) = &entry.data {
            assert_eq!(account.balance, 200);
        }
    }

    #[test]
    fn test_list_and_delete_buckets() {
        let (_temp_dir, manager) = create_manager();

        let entries1 = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let entries2 = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];

        let bucket1 = manager.create_bucket(entries1).unwrap();
        let bucket2 = manager.create_bucket(entries2).unwrap();

        let buckets = manager.list_buckets().unwrap();
        assert_eq!(buckets.len(), 2);

        manager.delete_bucket(&bucket1.hash()).unwrap();

        let buckets = manager.list_buckets().unwrap();
        assert_eq!(buckets.len(), 1);
        assert!(buckets.contains(&bucket2.hash()));
    }

    #[test]
    fn test_retain_buckets() {
        let (_temp_dir, manager) = create_manager();

        let entries1 = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        let entries2 = vec![BucketEntry::Live(make_account_entry([2u8; 32], 200))];
        let entries3 = vec![BucketEntry::Live(make_account_entry([3u8; 32], 300))];

        let bucket1 = manager.create_bucket(entries1).unwrap();
        let bucket2 = manager.create_bucket(entries2).unwrap();
        let _bucket3 = manager.create_bucket(entries3).unwrap();

        // Keep only bucket1 and bucket2
        let deleted = manager
            .retain_buckets(&[bucket1.hash(), bucket2.hash()])
            .unwrap();
        assert_eq!(deleted, 1);

        let buckets = manager.list_buckets().unwrap();
        assert_eq!(buckets.len(), 2);
    }

    #[test]
    fn test_import_export_bucket() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![
            BucketEntry::Live(make_account_entry([1u8; 32], 100)),
            BucketEntry::Live(make_account_entry([2u8; 32], 200)),
        ];

        let original = manager.create_bucket(entries).unwrap();
        let hash = original.hash();

        // Export
        let xdr_bytes = manager.export_bucket(&hash).unwrap();

        // Import (create new manager)
        let temp_dir2 = TempDir::new().unwrap();
        let manager2 = BucketManager::new(temp_dir2.path().to_path_buf()).unwrap();

        let imported = manager2.import_bucket(&xdr_bytes).unwrap();
        assert_eq!(imported.hash(), hash);
        assert_eq!(imported.len(), 2);
    }

    #[test]
    fn test_empty_bucket() {
        let (_temp_dir, manager) = create_manager();

        let bucket = manager.create_bucket(vec![]).unwrap();
        assert!(bucket.is_empty());
        assert_eq!(bucket.hash(), Hash256::ZERO);

        // Loading empty bucket should work
        let loaded = manager.load_bucket(&Hash256::ZERO).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_stats() {
        let (_temp_dir, manager) = create_manager();

        let entries = vec![BucketEntry::Live(make_account_entry([1u8; 32], 100))];
        manager.create_bucket(entries).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.cached_buckets, 1);
        assert_eq!(stats.disk_buckets, 1);
    }
}
