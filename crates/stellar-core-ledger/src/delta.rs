//! LedgerDelta - Track entry changes during ledger close.
//!
//! LedgerDelta accumulates all changes to ledger entries during the
//! processing of a single ledger. These changes are then used to:
//! - Update the bucket list
//! - Generate transaction metadata
//! - Update the database

use crate::{LedgerError, Result};
use std::collections::HashMap;
use stellar_xdr::curr::{LedgerEntry, LedgerKey, Limits, WriteXdr};

/// Represents a change to a single ledger entry.
#[derive(Debug, Clone)]
pub enum EntryChange {
    /// A new entry was created.
    Created(LedgerEntry),
    /// An existing entry was updated.
    Updated {
        /// The entry before the update.
        previous: LedgerEntry,
        /// The entry after the update.
        current: LedgerEntry,
    },
    /// An entry was deleted.
    Deleted {
        /// The entry that was deleted.
        previous: LedgerEntry,
    },
}

impl EntryChange {
    /// Get the ledger key for this change.
    pub fn key(&self) -> Result<LedgerKey> {
        match self {
            EntryChange::Created(entry) => entry_to_key(entry),
            EntryChange::Updated { current, .. } => entry_to_key(current),
            EntryChange::Deleted { previous } => entry_to_key(previous),
        }
    }

    /// Get the current entry value, if any.
    pub fn current_entry(&self) -> Option<&LedgerEntry> {
        match self {
            EntryChange::Created(entry) => Some(entry),
            EntryChange::Updated { current, .. } => Some(current),
            EntryChange::Deleted { .. } => None,
        }
    }

    /// Get the previous entry value, if any.
    pub fn previous_entry(&self) -> Option<&LedgerEntry> {
        match self {
            EntryChange::Created(_) => None,
            EntryChange::Updated { previous, .. } => Some(previous),
            EntryChange::Deleted { previous } => Some(previous),
        }
    }

    /// Check if this is a creation.
    pub fn is_created(&self) -> bool {
        matches!(self, EntryChange::Created(_))
    }

    /// Check if this is an update.
    pub fn is_updated(&self) -> bool {
        matches!(self, EntryChange::Updated { .. })
    }

    /// Check if this is a deletion.
    pub fn is_deleted(&self) -> bool {
        matches!(self, EntryChange::Deleted { .. })
    }
}

/// Extract the ledger key from an entry.
pub fn entry_to_key(entry: &LedgerEntry) -> Result<LedgerKey> {
    use stellar_xdr::curr::LedgerEntryData;

    let key = match &entry.data {
        LedgerEntryData::Account(account) => LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account.account_id.clone(),
        }),
        LedgerEntryData::Trustline(trustline) => {
            LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
                account_id: trustline.account_id.clone(),
                asset: trustline.asset.clone(),
            })
        }
        LedgerEntryData::Offer(offer) => LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
            seller_id: offer.seller_id.clone(),
            offer_id: offer.offer_id,
        }),
        LedgerEntryData::Data(data) => LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
            account_id: data.account_id.clone(),
            data_name: data.data_name.clone(),
        }),
        LedgerEntryData::ClaimableBalance(cb) => {
            LedgerKey::ClaimableBalance(stellar_xdr::curr::LedgerKeyClaimableBalance {
                balance_id: cb.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(pool) => {
            LedgerKey::LiquidityPool(stellar_xdr::curr::LedgerKeyLiquidityPool {
                liquidity_pool_id: pool.liquidity_pool_id.clone(),
            })
        }
        LedgerEntryData::ContractData(data) => {
            LedgerKey::ContractData(stellar_xdr::curr::LedgerKeyContractData {
                contract: data.contract.clone(),
                key: data.key.clone(),
                durability: data.durability.clone(),
            })
        }
        LedgerEntryData::ContractCode(code) => {
            LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                hash: code.hash.clone(),
            })
        }
        LedgerEntryData::ConfigSetting(setting) => {
            use stellar_xdr::curr::Discriminant;
            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: setting.discriminant(),
            })
        }
        LedgerEntryData::Ttl(ttl) => LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
            key_hash: ttl.key_hash.clone(),
        }),
    };

    Ok(key)
}

/// Serialize a ledger key to bytes for use as a map key.
fn key_to_bytes(key: &LedgerKey) -> Result<Vec<u8>> {
    key.to_xdr(Limits::none())
        .map_err(|e| LedgerError::Serialization(e.to_string()))
}

/// Tracks all changes to ledger entries during a ledger close.
///
/// This accumulates creates, updates, and deletes, then provides
/// a consolidated view of all changes for bucket list and database updates.
#[derive(Debug)]
pub struct LedgerDelta {
    /// The ledger sequence being modified.
    ledger_seq: u32,

    /// All entry changes, keyed by serialized LedgerKey.
    changes: HashMap<Vec<u8>, EntryChange>,

    /// Order in which changes were recorded (for deterministic iteration).
    change_order: Vec<Vec<u8>>,

    /// Total fees collected during this ledger.
    fee_pool_delta: i64,

    /// Total coins burned (via fee charging).
    total_coins_delta: i64,
}

impl LedgerDelta {
    /// Create a new empty LedgerDelta.
    pub fn new(ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            changes: HashMap::new(),
            change_order: Vec::new(),
            fee_pool_delta: 0,
            total_coins_delta: 0,
        }
    }

    /// Get the ledger sequence this delta is for.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Record the creation of a new entry.
    pub fn record_create(&mut self, entry: LedgerEntry) -> Result<()> {
        let key = entry_to_key(&entry)?;
        let key_bytes = key_to_bytes(&key)?;

        if self.changes.contains_key(&key_bytes) {
            return Err(LedgerError::DuplicateEntry(format!(
                "entry already exists in delta: {:?}",
                key
            )));
        }

        self.change_order.push(key_bytes.clone());
        self.changes.insert(key_bytes, EntryChange::Created(entry));
        Ok(())
    }

    /// Record an update to an existing entry.
    pub fn record_update(&mut self, previous: LedgerEntry, current: LedgerEntry) -> Result<()> {
        let key = entry_to_key(&current)?;
        let key_bytes = key_to_bytes(&key)?;

        // Check if we already have a change for this entry
        if let Some(existing) = self.changes.get(&key_bytes) {
            match existing {
                EntryChange::Created(_) => {
                    // If we created and then updated, just record as created with new value
                    self.changes
                        .insert(key_bytes, EntryChange::Created(current));
                }
                EntryChange::Updated { previous: orig, .. } => {
                    // Update the current value, keep original previous
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Updated {
                            previous: orig.clone(),
                            current,
                        },
                    );
                }
                EntryChange::Deleted { .. } => {
                    return Err(LedgerError::Internal(
                        "cannot update a deleted entry".to_string(),
                    ));
                }
            }
        } else {
            self.change_order.push(key_bytes.clone());
            self.changes
                .insert(key_bytes, EntryChange::Updated { previous, current });
        }

        Ok(())
    }

    /// Record the deletion of an entry.
    pub fn record_delete(&mut self, entry: LedgerEntry) -> Result<()> {
        let key = entry_to_key(&entry)?;
        let key_bytes = key_to_bytes(&key)?;

        // Check if we already have a change for this entry
        if let Some(existing) = self.changes.get(&key_bytes) {
            match existing {
                EntryChange::Created(_) => {
                    // If we created and then deleted, remove from delta entirely
                    self.changes.remove(&key_bytes);
                    self.change_order.retain(|k| k != &key_bytes);
                }
                EntryChange::Updated { previous, .. } => {
                    // If we updated and then deleted, record as deleted with original previous
                    self.changes.insert(
                        key_bytes,
                        EntryChange::Deleted {
                            previous: previous.clone(),
                        },
                    );
                }
                EntryChange::Deleted { .. } => {
                    return Err(LedgerError::Internal(
                        "cannot delete an already deleted entry".to_string(),
                    ));
                }
            }
        } else {
            self.change_order.push(key_bytes.clone());
            self.changes
                .insert(key_bytes, EntryChange::Deleted { previous: entry });
        }

        Ok(())
    }

    /// Record a fee pool change.
    pub fn record_fee_pool_delta(&mut self, delta: i64) {
        self.fee_pool_delta += delta;
    }

    /// Record a total coins change (e.g., from inflation).
    pub fn record_total_coins_delta(&mut self, delta: i64) {
        self.total_coins_delta += delta;
    }

    /// Get the fee pool delta.
    pub fn fee_pool_delta(&self) -> i64 {
        self.fee_pool_delta
    }

    /// Get the total coins delta.
    pub fn total_coins_delta(&self) -> i64 {
        self.total_coins_delta
    }

    /// Get all entry changes in the order they were recorded.
    pub fn changes(&self) -> impl Iterator<Item = &EntryChange> {
        self.change_order
            .iter()
            .filter_map(|k| self.changes.get(k))
    }

    /// Get the number of changes.
    pub fn num_changes(&self) -> usize {
        self.changes.len()
    }

    /// Check if there are any changes.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Get all init entries (created) for bucket list update.
    pub fn init_entries(&self) -> Vec<LedgerEntry> {
        self.changes()
            .filter(|change| change.is_created())
            .filter_map(|change| change.current_entry().cloned())
            .collect()
    }

    /// Get all live entries (updated) for bucket list update.
    pub fn live_entries(&self) -> Vec<LedgerEntry> {
        self.changes()
            .filter(|change| change.is_updated())
            .filter_map(|change| change.current_entry().cloned())
            .collect()
    }

    /// Get all dead entries (deleted keys) for bucket list update.
    pub fn dead_entries(&self) -> Vec<LedgerKey> {
        self.changes()
            .filter(|change| change.is_deleted())
            .filter_map(|change| change.key().ok())
            .collect()
    }

    /// Get a specific change by key.
    pub fn get_change(&self, key: &LedgerKey) -> Result<Option<&EntryChange>> {
        let key_bytes = key_to_bytes(key)?;
        Ok(self.changes.get(&key_bytes))
    }

    /// Merge another delta into this one.
    ///
    /// This is useful when combining changes from multiple operations.
    pub fn merge(&mut self, other: LedgerDelta) -> Result<()> {
        for key_bytes in other.change_order {
            if let Some(change) = other.changes.get(&key_bytes) {
                match change {
                    EntryChange::Created(entry) => {
                        if let Some(existing) = self.changes.get(&key_bytes) {
                            match existing {
                                EntryChange::Deleted { previous } => {
                                    // Deleted then created = update
                                    self.changes.insert(
                                        key_bytes,
                                        EntryChange::Updated {
                                            previous: previous.clone(),
                                            current: entry.clone(),
                                        },
                                    );
                                }
                                _ => {
                                    return Err(LedgerError::Internal(
                                        "invalid merge: create on existing entry".to_string(),
                                    ));
                                }
                            }
                        } else {
                            self.change_order.push(key_bytes.clone());
                            self.changes
                                .insert(key_bytes, EntryChange::Created(entry.clone()));
                        }
                    }
                    EntryChange::Updated { current, .. } => {
                        if let Some(existing) = self.changes.get(&key_bytes) {
                            match existing {
                                EntryChange::Created(_) => {
                                    self.changes
                                        .insert(key_bytes, EntryChange::Created(current.clone()));
                                }
                                EntryChange::Updated { previous, .. } => {
                                    self.changes.insert(
                                        key_bytes,
                                        EntryChange::Updated {
                                            previous: previous.clone(),
                                            current: current.clone(),
                                        },
                                    );
                                }
                                EntryChange::Deleted { .. } => {
                                    return Err(LedgerError::Internal(
                                        "invalid merge: update on deleted entry".to_string(),
                                    ));
                                }
                            }
                        } else {
                            return Err(LedgerError::MissingEntry(
                                "update on non-existent entry".to_string(),
                            ));
                        }
                    }
                    EntryChange::Deleted { previous } => {
                        if let Some(existing) = self.changes.get(&key_bytes) {
                            match existing {
                                EntryChange::Created(_) => {
                                    // Created then deleted = no change
                                    self.changes.remove(&key_bytes);
                                    self.change_order.retain(|k| k != &key_bytes);
                                }
                                EntryChange::Updated { previous: orig, .. } => {
                                    self.changes.insert(
                                        key_bytes,
                                        EntryChange::Deleted {
                                            previous: orig.clone(),
                                        },
                                    );
                                }
                                EntryChange::Deleted { .. } => {
                                    return Err(LedgerError::Internal(
                                        "invalid merge: delete on deleted entry".to_string(),
                                    ));
                                }
                            }
                        } else {
                            self.change_order.push(key_bytes.clone());
                            self.changes.insert(
                                key_bytes,
                                EntryChange::Deleted {
                                    previous: previous.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        self.fee_pool_delta += other.fee_pool_delta;
        self.total_coins_delta += other.total_coins_delta;

        Ok(())
    }

    /// Clear all changes.
    pub fn clear(&mut self) {
        self.changes.clear();
        self.change_order.clear();
        self.fee_pool_delta = 0;
        self.total_coins_delta = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, LedgerEntryExt, PublicKey,
        SequenceNumber, Thresholds, Uint256,
    };

    fn create_test_account(seed: u8) -> LedgerEntry {
        let mut key = [0u8; 32];
        key[0] = seed;

        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))),
                balance: 1000000000,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: stellar_xdr::curr::String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: stellar_xdr::curr::VecM::default(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_record_create() {
        let mut delta = LedgerDelta::new(1);
        let entry = create_test_account(1);

        delta.record_create(entry.clone()).unwrap();
        assert_eq!(delta.num_changes(), 1);

        let init = delta.init_entries();
        assert_eq!(init.len(), 1);
    }

    #[test]
    fn test_record_update() {
        let mut delta = LedgerDelta::new(1);
        let entry1 = create_test_account(1);
        let mut entry2 = entry1.clone();
        if let LedgerEntryData::Account(ref mut acc) = entry2.data {
            acc.balance = 2000000000;
        }

        delta.record_update(entry1, entry2).unwrap();
        assert_eq!(delta.num_changes(), 1);

        let changes: Vec<_> = delta.changes().collect();
        assert!(changes[0].is_updated());
    }

    #[test]
    fn test_record_delete() {
        let mut delta = LedgerDelta::new(1);
        let entry = create_test_account(1);

        delta.record_delete(entry).unwrap();
        assert_eq!(delta.num_changes(), 1);

        let dead = delta.dead_entries();
        assert_eq!(dead.len(), 1);
    }

    #[test]
    fn test_create_then_delete() {
        let mut delta = LedgerDelta::new(1);
        let entry = create_test_account(1);

        delta.record_create(entry.clone()).unwrap();
        delta.record_delete(entry).unwrap();

        // Should cancel out
        assert!(delta.is_empty());
    }

    #[test]
    fn test_create_then_update() {
        let mut delta = LedgerDelta::new(1);
        let entry1 = create_test_account(1);
        let mut entry2 = entry1.clone();
        if let LedgerEntryData::Account(ref mut acc) = entry2.data {
            acc.balance = 2000000000;
        }

        delta.record_create(entry1.clone()).unwrap();
        delta.record_update(entry1, entry2.clone()).unwrap();

        // Should be recorded as a create with the final value
        assert_eq!(delta.num_changes(), 1);
        let changes: Vec<_> = delta.changes().collect();
        assert!(changes[0].is_created());
    }
}
