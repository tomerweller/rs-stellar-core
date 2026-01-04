//! Disk-backed bucket implementation for memory-efficient storage.
//!
//! This module provides a bucket implementation that stores entries on disk
//! and uses an index for efficient lookups, similar to stellar-core's approach.
//!
//! Instead of loading all entries into memory, we:
//! 1. Store the bucket XDR file on disk
//! 2. Build an index mapping keys to file offsets
//! 3. Read entries from disk on-demand
//!
//! This reduces memory usage from O(entries) to O(unique_keys) for the index,
//! which is much smaller since we only store key hashes and offsets.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};
use stellar_xdr::curr::{LedgerEntry, LedgerKey, ReadXdr, Limits};

use stellar_core_common::Hash256;

use crate::entry::BucketEntry;
use crate::{BucketError, Result};

/// Entry in the bucket index: offset and length in the file.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    /// Byte offset in the bucket file where this entry starts.
    offset: u64,
    /// Length of the XDR record (not including the 4-byte record mark).
    length: u32,
}

/// A disk-backed bucket that stores entries on disk with an in-memory index.
///
/// This is much more memory efficient than the in-memory Bucket for large buckets.
/// The index maps key hashes to file offsets, allowing O(1) lookups with minimal
/// memory overhead.
#[derive(Clone)]
pub struct DiskBucket {
    /// The hash of this bucket's contents.
    hash: Hash256,
    /// Path to the bucket file on disk.
    file_path: PathBuf,
    /// Index mapping key hashes to (offset, length) in the file.
    /// Key is the first 8 bytes of SHA256(key_xdr) for compact storage.
    index: Arc<BTreeMap<u64, IndexEntry>>,
    /// Number of entries in this bucket.
    entry_count: usize,
    /// Cached file handle for reads (wrapped in RwLock for thread safety).
    #[allow(dead_code)]
    file_cache: Arc<RwLock<Option<File>>>,
}

impl DiskBucket {
    /// Create a disk bucket from an XDR file.
    ///
    /// This parses the file to build the index but doesn't keep entries in memory.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut reader = BufReader::new(file);

        // Read entire file for hash computation
        let mut bytes = Vec::with_capacity(file_len as usize);
        reader.read_to_end(&mut bytes)?;

        // Compute hash
        let hash = Hash256::hash(&bytes);

        // Build index by scanning the file
        let (index, entry_count) = Self::build_index(&bytes)?;

        Ok(Self {
            hash,
            file_path: path.to_path_buf(),
            index: Arc::new(index),
            entry_count,
            file_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a disk bucket from raw XDR bytes, saving to the specified path.
    pub fn from_xdr_bytes(bytes: &[u8], save_path: impl AsRef<Path>) -> Result<Self> {
        use std::io::Write;

        let save_path = save_path.as_ref();

        // Compute hash
        let hash = Hash256::hash(bytes);

        // Build index
        let (index, entry_count) = Self::build_index(bytes)?;

        // Save to disk
        let mut file = File::create(save_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;

        Ok(Self {
            hash,
            file_path: save_path.to_path_buf(),
            index: Arc::new(index),
            entry_count,
            file_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Build an index from XDR bytes.
    ///
    /// Returns (index, entry_count).
    fn build_index(bytes: &[u8]) -> Result<(BTreeMap<u64, IndexEntry>, usize)> {
        use tracing::debug;

        if bytes.is_empty() {
            return Ok((BTreeMap::new(), 0));
        }

        let mut index = BTreeMap::new();
        let mut offset: u64 = 0;
        let mut entry_count = 0;

        // Check if the file uses XDR record marking
        let uses_record_marks = bytes.len() >= 4 && (bytes[0] & 0x80) != 0;

        if uses_record_marks {
            debug!("Building index for bucket with XDR record marking format");

            while (offset as usize) + 4 <= bytes.len() {
                let record_start = offset;

                // Read 4-byte record mark
                let record_mark = u32::from_be_bytes([
                    bytes[offset as usize],
                    bytes[offset as usize + 1],
                    bytes[offset as usize + 2],
                    bytes[offset as usize + 3],
                ]);
                offset += 4;

                let record_len = (record_mark & 0x7FFFFFFF) as usize;

                if (offset as usize) + record_len > bytes.len() {
                    break;
                }

                // Parse just enough to get the key
                let record_data = &bytes[offset as usize..(offset as usize) + record_len];
                if let Ok(xdr_entry) = stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none()) {
                    if let Some(key) = Self::extract_key(&xdr_entry) {
                        // Use first 8 bytes of key hash as index key
                        let key_hash = Self::hash_key(&key);
                        index.insert(key_hash, IndexEntry {
                            offset: record_start,
                            length: record_len as u32,
                        });
                    }
                    entry_count += 1;
                }

                offset += record_len as u64;
            }
        } else {
            // Raw XDR format - need to parse sequentially
            debug!("Building index for bucket with raw XDR format");

            use stellar_xdr::curr::Limited;
            let cursor = std::io::Cursor::new(bytes);
            let mut limited = Limited::new(cursor, Limits::none());

            while limited.inner.position() < bytes.len() as u64 {
                let entry_start = limited.inner.position();

                match stellar_xdr::curr::BucketEntry::read_xdr(&mut limited) {
                    Ok(xdr_entry) => {
                        let entry_end = limited.inner.position();
                        if let Some(key) = Self::extract_key(&xdr_entry) {
                            let key_hash = Self::hash_key(&key);
                            index.insert(key_hash, IndexEntry {
                                offset: entry_start,
                                length: (entry_end - entry_start) as u32,
                            });
                        }
                        entry_count += 1;
                    }
                    Err(_) => break,
                }
            }
        }

        debug!("Built index with {} entries", entry_count);
        Ok((index, entry_count))
    }

    /// Extract the key from a bucket entry.
    fn extract_key(entry: &stellar_xdr::curr::BucketEntry) -> Option<LedgerKey> {
        use stellar_xdr::curr::BucketEntry as XdrBucketEntry;
        use crate::entry::ledger_entry_to_key;

        match entry {
            XdrBucketEntry::Liveentry(e) | XdrBucketEntry::Initentry(e) => ledger_entry_to_key(e),
            XdrBucketEntry::Deadentry(k) => Some(k.clone()),
            XdrBucketEntry::Metaentry(_) => None,
        }
    }

    /// Compute a compact hash of a key for index lookup.
    fn hash_key(key: &LedgerKey) -> u64 {
        use stellar_xdr::curr::WriteXdr;
        let key_bytes = key.to_xdr(Limits::none()).unwrap_or_default();
        let hash = Sha256::digest(&key_bytes);
        u64::from_be_bytes(hash[0..8].try_into().unwrap())
    }

    /// Get the hash of this bucket.
    pub fn hash(&self) -> Hash256 {
        self.hash
    }

    /// Check if this bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0 || self.hash.is_zero()
    }

    /// Get the number of entries in this bucket.
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /// Get the path to the bucket file.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Look up an entry by key.
    ///
    /// This reads from disk using the index.
    pub fn get(&self, key: &LedgerKey) -> Result<Option<BucketEntry>> {
        let key_hash = Self::hash_key(key);

        let index_entry = match self.index.get(&key_hash) {
            Some(e) => e,
            None => return Ok(None),
        };

        // Read the entry from disk
        let mut file = File::open(&self.file_path)?;
        file.seek(SeekFrom::Start(index_entry.offset))?;

        // Read record mark if present
        let mut mark_buf = [0u8; 4];
        file.read_exact(&mut mark_buf)?;

        let (record_len, data_offset) = if mark_buf[0] & 0x80 != 0 {
            // Has record mark
            let mark = u32::from_be_bytes(mark_buf);
            ((mark & 0x7FFFFFFF) as usize, 4u64)
        } else {
            // No record mark - use stored length
            (index_entry.length as usize, 0u64)
        };

        // Seek to data start if needed
        if data_offset == 0 {
            file.seek(SeekFrom::Start(index_entry.offset))?;
        }

        // Read the entry data
        let mut data = vec![0u8; record_len];
        file.read_exact(&mut data)?;

        // Parse the entry
        let xdr_entry = stellar_xdr::curr::BucketEntry::from_xdr(&data, Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to parse entry: {}", e)))?;

        // Convert to our BucketEntry type
        let entry = BucketEntry::from_xdr_entry(xdr_entry)?;

        // Verify this is the right entry (hash collisions are possible)
        if let Some(entry_key) = entry.key() {
            if &entry_key == key {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Look up a ledger entry by key.
    pub fn get_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>> {
        match self.get(key)? {
            Some(BucketEntry::Live(entry)) | Some(BucketEntry::Init(entry)) => Ok(Some(entry)),
            Some(BucketEntry::Dead(_)) => Ok(None),
            Some(BucketEntry::Metadata(_)) => Ok(None),
            None => Ok(None),
        }
    }

    /// Iterate over all entries in this bucket.
    ///
    /// This reads from disk sequentially.
    pub fn iter(&self) -> Result<DiskBucketIter> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);

        // Read file to check format
        let mut bytes = Vec::new();
        let mut reader = reader;
        reader.read_to_end(&mut bytes)?;

        let uses_record_marks = bytes.len() >= 4 && (bytes[0] & 0x80) != 0;

        Ok(DiskBucketIter {
            bytes,
            offset: 0,
            uses_record_marks,
        })
    }
}

impl std::fmt::Debug for DiskBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskBucket")
            .field("hash", &self.hash.to_hex())
            .field("entries", &self.entry_count)
            .field("file", &self.file_path)
            .finish()
    }
}

/// Iterator over entries in a disk bucket.
pub struct DiskBucketIter {
    bytes: Vec<u8>,
    offset: usize,
    uses_record_marks: bool,
}

impl Iterator for DiskBucketIter {
    type Item = Result<BucketEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        if self.uses_record_marks {
            if self.offset + 4 > self.bytes.len() {
                return None;
            }

            let record_mark = u32::from_be_bytes([
                self.bytes[self.offset],
                self.bytes[self.offset + 1],
                self.bytes[self.offset + 2],
                self.bytes[self.offset + 3],
            ]);
            self.offset += 4;

            let record_len = (record_mark & 0x7FFFFFFF) as usize;

            if self.offset + record_len > self.bytes.len() {
                return None;
            }

            let record_data = &self.bytes[self.offset..self.offset + record_len];
            self.offset += record_len;

            match stellar_xdr::curr::BucketEntry::from_xdr(record_data, Limits::none()) {
                Ok(xdr_entry) => Some(BucketEntry::from_xdr_entry(xdr_entry)),
                Err(e) => Some(Err(BucketError::Serialization(format!("Failed to parse: {}", e)))),
            }
        } else {
            use stellar_xdr::curr::Limited;
            let cursor = std::io::Cursor::new(&self.bytes[self.offset..]);
            let mut limited = Limited::new(cursor, Limits::none());

            match stellar_xdr::curr::BucketEntry::read_xdr(&mut limited) {
                Ok(xdr_entry) => {
                    self.offset += limited.inner.position() as usize;
                    Some(BucketEntry::from_xdr_entry(xdr_entry))
                }
                Err(_) => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use tempfile::tempdir;

    fn make_test_bucket_bytes() -> Vec<u8> {
        use stellar_xdr::curr::WriteXdr;

        let mut bytes = Vec::new();

        // Create a simple account entry
        let account = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
            balance: 100,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: Vec::new().try_into().unwrap(),
            ext: AccountEntryExt::V0,
        };

        let entry = LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(account),
            ext: LedgerEntryExt::V0,
        };

        let bucket_entry = stellar_xdr::curr::BucketEntry::Liveentry(entry);
        let entry_bytes = bucket_entry.to_xdr(Limits::none()).unwrap();

        // Write with record mark
        let record_mark = (entry_bytes.len() as u32) | 0x80000000;
        bytes.extend_from_slice(&record_mark.to_be_bytes());
        bytes.extend_from_slice(&entry_bytes);

        bytes
    }

    #[test]
    fn test_disk_bucket_creation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let bytes = make_test_bucket_bytes();
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        assert!(!bucket.is_empty());
        assert_eq!(bucket.len(), 1);
        assert!(path.exists());
    }

    #[test]
    fn test_disk_bucket_lookup() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bucket");

        let bytes = make_test_bucket_bytes();
        let bucket = DiskBucket::from_xdr_bytes(&bytes, &path).unwrap();

        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
        });

        let entry = bucket.get(&key).unwrap();
        assert!(entry.is_some());
    }
}
