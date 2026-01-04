//! BucketEntry implementation for bucket storage.
//!
//! This module handles bucket entries which can be live entries, dead entries
//! (tombstones), init entries, or metadata entries.

use std::cmp::Ordering;

use stellar_xdr::curr::{
    BucketEntry as XdrBucketEntry, BucketEntryType, BucketMetadata, LedgerEntry,
    LedgerKey, ReadXdr, WriteXdr, Limits,
};

use crate::{BucketError, Result};

/// An entry in a bucket.
///
/// Bucket entries are sorted by key for efficient merging and lookup.
/// The entry types determine merge semantics:
/// - LiveEntry: A live ledger entry
/// - DeadEntry: A tombstone marking deletion
/// - InitEntry: Like LiveEntry but with different merge semantics
/// - Metadata: Bucket metadata (protocol version, etc.)
#[derive(Debug, Clone)]
pub enum BucketEntry {
    /// A live ledger entry.
    Live(LedgerEntry),
    /// A dead (deleted) entry, identified by its key.
    Dead(LedgerKey),
    /// An initialization entry (for merge semantics).
    /// Init entries are used to establish initial state that can be shadowed.
    Init(LedgerEntry),
    /// Bucket metadata (protocol version, etc.)
    Metadata(BucketMetadata),
}

impl BucketEntry {
    /// Parse a BucketEntry from XDR bytes.
    pub fn from_xdr(bytes: &[u8]) -> Result<Self> {
        let xdr_entry = XdrBucketEntry::from_xdr(bytes, Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to parse XDR: {}", e)))?;
        Self::from_xdr_entry(xdr_entry)
    }

    /// Convert from XDR BucketEntry.
    pub fn from_xdr_entry(xdr: XdrBucketEntry) -> Result<Self> {
        match xdr {
            XdrBucketEntry::Liveentry(entry) => Ok(BucketEntry::Live(entry)),
            XdrBucketEntry::Initentry(entry) => Ok(BucketEntry::Init(entry)),
            XdrBucketEntry::Deadentry(key) => Ok(BucketEntry::Dead(key)),
            XdrBucketEntry::Metaentry(meta) => Ok(BucketEntry::Metadata(meta)),
        }
    }

    /// Convert to XDR BucketEntry.
    pub fn to_xdr_entry(&self) -> XdrBucketEntry {
        match self {
            BucketEntry::Live(entry) => XdrBucketEntry::Liveentry(entry.clone()),
            BucketEntry::Init(entry) => XdrBucketEntry::Initentry(entry.clone()),
            BucketEntry::Dead(key) => XdrBucketEntry::Deadentry(key.clone()),
            BucketEntry::Metadata(meta) => XdrBucketEntry::Metaentry(meta.clone()),
        }
    }

    /// Serialize to XDR bytes.
    pub fn to_xdr(&self) -> Result<Vec<u8>> {
        self.to_xdr_entry()
            .to_xdr(Limits::none())
            .map_err(|e| BucketError::Serialization(format!("Failed to serialize XDR: {}", e)))
    }

    /// Get the LedgerKey for this entry.
    ///
    /// Returns None for metadata entries since they don't have a key.
    pub fn key(&self) -> Option<LedgerKey> {
        match self {
            BucketEntry::Live(entry) | BucketEntry::Init(entry) => {
                ledger_entry_to_key(entry)
            }
            BucketEntry::Dead(key) => Some(key.clone()),
            BucketEntry::Metadata(_) => None,
        }
    }

    /// Check if this entry is a metadata entry.
    pub fn is_metadata(&self) -> bool {
        matches!(self, BucketEntry::Metadata(_))
    }

    /// Check if this is a dead entry (tombstone).
    pub fn is_dead(&self) -> bool {
        matches!(self, BucketEntry::Dead(_))
    }

    /// Check if this is a live entry.
    pub fn is_live(&self) -> bool {
        matches!(self, BucketEntry::Live(_))
    }

    /// Check if this is an init entry.
    pub fn is_init(&self) -> bool {
        matches!(self, BucketEntry::Init(_))
    }

    /// Get the ledger entry if this is a live or init entry.
    pub fn as_ledger_entry(&self) -> Option<&LedgerEntry> {
        match self {
            BucketEntry::Live(entry) | BucketEntry::Init(entry) => Some(entry),
            _ => None,
        }
    }

    /// Get the bucket entry type.
    pub fn entry_type(&self) -> BucketEntryType {
        match self {
            BucketEntry::Live(_) => BucketEntryType::Liveentry,
            BucketEntry::Dead(_) => BucketEntryType::Deadentry,
            BucketEntry::Init(_) => BucketEntryType::Initentry,
            BucketEntry::Metadata(_) => BucketEntryType::Metaentry,
        }
    }
}

/// Extract a LedgerKey from a LedgerEntry.
pub fn ledger_entry_to_key(entry: &LedgerEntry) -> Option<LedgerKey> {
    use stellar_xdr::curr::*;

    let key = match &entry.data {
        LedgerEntryData::Account(account) => {
            LedgerKey::Account(LedgerKeyAccount {
                account_id: account.account_id.clone(),
            })
        }
        LedgerEntryData::Trustline(trustline) => {
            LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: trustline.account_id.clone(),
                asset: trustline.asset.clone(),
            })
        }
        LedgerEntryData::Offer(offer) => {
            LedgerKey::Offer(LedgerKeyOffer {
                seller_id: offer.seller_id.clone(),
                offer_id: offer.offer_id,
            })
        }
        LedgerEntryData::Data(data) => {
            LedgerKey::Data(LedgerKeyData {
                account_id: data.account_id.clone(),
                data_name: data.data_name.clone(),
            })
        }
        LedgerEntryData::ClaimableBalance(cb) => {
            LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: cb.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(pool) => {
            LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
                liquidity_pool_id: pool.liquidity_pool_id.clone(),
            })
        }
        LedgerEntryData::ContractData(contract_data) => {
            LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract_data.contract.clone(),
                key: contract_data.key.clone(),
                durability: contract_data.durability,
            })
        }
        LedgerEntryData::ContractCode(contract_code) => {
            LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: contract_code.hash.clone(),
            })
        }
        LedgerEntryData::ConfigSetting(config) => {
            LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                config_setting_id: config.discriminant(),
            })
        }
        LedgerEntryData::Ttl(ttl) => {
            LedgerKey::Ttl(LedgerKeyTtl {
                key_hash: ttl.key_hash.clone(),
            })
        }
    };

    Some(key)
}

/// Compare two LedgerKeys for ordering.
///
/// Keys are sorted first by type discriminant, then by type-specific fields.
/// This ordering is critical for bucket merging to work correctly.
pub fn compare_keys(a: &LedgerKey, b: &LedgerKey) -> Ordering {
    use stellar_xdr::curr::*;

    // First compare by discriminant
    let disc_a = key_discriminant(a);
    let disc_b = key_discriminant(b);

    match disc_a.cmp(&disc_b) {
        Ordering::Equal => {}
        other => return other,
    }

    // Then compare by type-specific fields
    match (a, b) {
        (LedgerKey::Account(a), LedgerKey::Account(b)) => {
            compare_account_id(&a.account_id, &b.account_id)
        }
        (LedgerKey::Trustline(a), LedgerKey::Trustline(b)) => {
            compare_account_id(&a.account_id, &b.account_id)
                .then_with(|| compare_trust_line_asset(&a.asset, &b.asset))
        }
        (LedgerKey::Offer(a), LedgerKey::Offer(b)) => {
            compare_account_id(&a.seller_id, &b.seller_id)
                .then_with(|| a.offer_id.cmp(&b.offer_id))
        }
        (LedgerKey::Data(a), LedgerKey::Data(b)) => {
            compare_account_id(&a.account_id, &b.account_id)
                .then_with(|| a.data_name.as_slice().cmp(b.data_name.as_slice()))
        }
        (LedgerKey::ClaimableBalance(a), LedgerKey::ClaimableBalance(b)) => {
            compare_claimable_balance_id(&a.balance_id, &b.balance_id)
        }
        (LedgerKey::LiquidityPool(a), LedgerKey::LiquidityPool(b)) => {
            a.liquidity_pool_id.0.cmp(&b.liquidity_pool_id.0)
        }
        (LedgerKey::ContractData(a), LedgerKey::ContractData(b)) => {
            compare_sc_address(&a.contract, &b.contract)
                .then_with(|| compare_sc_val(&a.key, &b.key))
                .then_with(|| (a.durability as i32).cmp(&(b.durability as i32)))
        }
        (LedgerKey::ContractCode(a), LedgerKey::ContractCode(b)) => {
            a.hash.0.cmp(&b.hash.0)
        }
        (LedgerKey::ConfigSetting(a), LedgerKey::ConfigSetting(b)) => {
            (a.config_setting_id as i32).cmp(&(b.config_setting_id as i32))
        }
        (LedgerKey::Ttl(a), LedgerKey::Ttl(b)) => {
            a.key_hash.0.cmp(&b.key_hash.0)
        }
        _ => Ordering::Equal, // Should not happen if discriminants match
    }
}

/// Get a numeric discriminant for a LedgerKey type.
fn key_discriminant(key: &LedgerKey) -> i32 {
    use stellar_xdr::curr::*;
    match key {
        LedgerKey::Account(_) => LedgerEntryType::Account as i32,
        LedgerKey::Trustline(_) => LedgerEntryType::Trustline as i32,
        LedgerKey::Offer(_) => LedgerEntryType::Offer as i32,
        LedgerKey::Data(_) => LedgerEntryType::Data as i32,
        LedgerKey::ClaimableBalance(_) => LedgerEntryType::ClaimableBalance as i32,
        LedgerKey::LiquidityPool(_) => LedgerEntryType::LiquidityPool as i32,
        LedgerKey::ContractData(_) => LedgerEntryType::ContractData as i32,
        LedgerKey::ContractCode(_) => LedgerEntryType::ContractCode as i32,
        LedgerKey::ConfigSetting(_) => LedgerEntryType::ConfigSetting as i32,
        LedgerKey::Ttl(_) => LedgerEntryType::Ttl as i32,
    }
}

/// Compare two AccountId values.
fn compare_account_id(
    a: &stellar_xdr::curr::AccountId,
    b: &stellar_xdr::curr::AccountId,
) -> Ordering {
    // AccountId is PublicKey which is an enum
    use stellar_xdr::curr::PublicKey;
    match (&a.0, &b.0) {
        (PublicKey::PublicKeyTypeEd25519(a), PublicKey::PublicKeyTypeEd25519(b)) => {
            a.0.cmp(&b.0)
        }
    }
}

/// Compare two TrustLineAsset values.
fn compare_trust_line_asset(
    a: &stellar_xdr::curr::TrustLineAsset,
    b: &stellar_xdr::curr::TrustLineAsset,
) -> Ordering {
    use stellar_xdr::curr::TrustLineAsset;

    let disc_a = match a {
        TrustLineAsset::Native => 0,
        TrustLineAsset::CreditAlphanum4(_) => 1,
        TrustLineAsset::CreditAlphanum12(_) => 2,
        TrustLineAsset::PoolShare(_) => 3,
    };
    let disc_b = match b {
        TrustLineAsset::Native => 0,
        TrustLineAsset::CreditAlphanum4(_) => 1,
        TrustLineAsset::CreditAlphanum12(_) => 2,
        TrustLineAsset::PoolShare(_) => 3,
    };

    match disc_a.cmp(&disc_b) {
        Ordering::Equal => {}
        other => return other,
    }

    match (a, b) {
        (TrustLineAsset::Native, TrustLineAsset::Native) => Ordering::Equal,
        (TrustLineAsset::CreditAlphanum4(a), TrustLineAsset::CreditAlphanum4(b)) => {
            a.asset_code.as_slice().cmp(b.asset_code.as_slice())
                .then_with(|| compare_account_id(&a.issuer, &b.issuer))
        }
        (TrustLineAsset::CreditAlphanum12(a), TrustLineAsset::CreditAlphanum12(b)) => {
            a.asset_code.as_slice().cmp(b.asset_code.as_slice())
                .then_with(|| compare_account_id(&a.issuer, &b.issuer))
        }
        (TrustLineAsset::PoolShare(a), TrustLineAsset::PoolShare(b)) => {
            a.0.cmp(&b.0)
        }
        _ => Ordering::Equal, // Should not happen
    }
}

/// Compare two ClaimableBalanceId values.
fn compare_claimable_balance_id(
    a: &stellar_xdr::curr::ClaimableBalanceId,
    b: &stellar_xdr::curr::ClaimableBalanceId,
) -> Ordering {
    use stellar_xdr::curr::ClaimableBalanceId;
    match (a, b) {
        (
            ClaimableBalanceId::ClaimableBalanceIdTypeV0(a),
            ClaimableBalanceId::ClaimableBalanceIdTypeV0(b),
        ) => a.0.cmp(&b.0),
    }
}

/// Compare two ScAddress values.
fn compare_sc_address(
    a: &stellar_xdr::curr::ScAddress,
    b: &stellar_xdr::curr::ScAddress,
) -> Ordering {
    use stellar_xdr::curr::ScAddress;

    // Assign discriminant values for ordering
    let disc_a = match a {
        ScAddress::Account(_) => 0,
        ScAddress::Contract(_) => 1,
        ScAddress::MuxedAccount(_) => 2,
        ScAddress::ClaimableBalance(_) => 3,
        ScAddress::LiquidityPool(_) => 4,
    };
    let disc_b = match b {
        ScAddress::Account(_) => 0,
        ScAddress::Contract(_) => 1,
        ScAddress::MuxedAccount(_) => 2,
        ScAddress::ClaimableBalance(_) => 3,
        ScAddress::LiquidityPool(_) => 4,
    };

    match disc_a.cmp(&disc_b) {
        Ordering::Equal => {}
        other => return other,
    }

    match (a, b) {
        (ScAddress::Account(a), ScAddress::Account(b)) => compare_account_id(a, b),
        (ScAddress::Contract(a), ScAddress::Contract(b)) => a.0.cmp(&b.0),
        (ScAddress::MuxedAccount(a), ScAddress::MuxedAccount(b)) => {
            // Compare by the inner muxed account ID
            a.to_string().cmp(&b.to_string())
        }
        (ScAddress::ClaimableBalance(a), ScAddress::ClaimableBalance(b)) => {
            // ClaimableBalanceId is an enum, extract the hash for comparison
            match (a, b) {
                (
                    stellar_xdr::curr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(ha),
                    stellar_xdr::curr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(hb),
                ) => ha.0.cmp(&hb.0),
            }
        }
        (ScAddress::LiquidityPool(a), ScAddress::LiquidityPool(b)) => a.0.cmp(&b.0),
        _ => Ordering::Equal,
    }
}

/// Compare two ScVal values (simplified comparison).
fn compare_sc_val(
    a: &stellar_xdr::curr::ScVal,
    b: &stellar_xdr::curr::ScVal,
) -> Ordering {
    // For simplicity, we compare the XDR bytes
    // This matches stellar-core's behavior of using XDR for comparison
    let a_bytes = a.to_xdr(Limits::none()).unwrap_or_default();
    let b_bytes = b.to_xdr(Limits::none()).unwrap_or_default();
    a_bytes.cmp(&b_bytes)
}

/// Compare two BucketEntry values by key.
///
/// Metadata entries are always sorted first.
/// Returns None if either entry is metadata and the other is not.
pub fn compare_entries(a: &BucketEntry, b: &BucketEntry) -> Ordering {
    match (a.key(), b.key()) {
        (Some(key_a), Some(key_b)) => compare_keys(&key_a, &key_b),
        (None, Some(_)) => Ordering::Less,  // Metadata comes first
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,    // Both metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::BucketEntry; // Re-import to shadow XDR's BucketEntry

    fn make_account_id(bytes: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_account_entry(bytes: [u8; 32]) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: make_account_id(bytes),
                balance: 100,
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

    #[test]
    fn test_bucket_entry_key() {
        let entry = make_account_entry([1u8; 32]);
        let bucket_entry = BucketEntry::Live(entry.clone());

        let key = bucket_entry.key().unwrap();
        if let LedgerKey::Account(account_key) = key {
            assert_eq!(account_key.account_id, make_account_id([1u8; 32]));
        } else {
            panic!("Expected Account key");
        }
    }

    #[test]
    fn test_bucket_entry_dead() {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([2u8; 32]),
        });
        let bucket_entry = BucketEntry::Dead(key.clone());

        assert!(bucket_entry.is_dead());
        assert!(!bucket_entry.is_live());
        assert_eq!(bucket_entry.key().unwrap(), key);
    }

    #[test]
    fn test_compare_keys_same_type() {
        let key1 = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([1u8; 32]),
        });
        let key2 = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([2u8; 32]),
        });

        assert_eq!(compare_keys(&key1, &key2), Ordering::Less);
        assert_eq!(compare_keys(&key2, &key1), Ordering::Greater);
        assert_eq!(compare_keys(&key1, &key1), Ordering::Equal);
    }

    #[test]
    fn test_compare_entries() {
        let entry1 = BucketEntry::Live(make_account_entry([1u8; 32]));
        let entry2 = BucketEntry::Live(make_account_entry([2u8; 32]));

        assert_eq!(compare_entries(&entry1, &entry2), Ordering::Less);
    }

    #[test]
    fn test_entry_type() {
        let live = BucketEntry::Live(make_account_entry([1u8; 32]));
        let dead = BucketEntry::Dead(LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([1u8; 32]),
        }));
        let init = BucketEntry::Init(make_account_entry([1u8; 32]));

        assert_eq!(live.entry_type(), BucketEntryType::Liveentry);
        assert_eq!(dead.entry_type(), BucketEntryType::Deadentry);
        assert_eq!(init.entry_type(), BucketEntryType::Initentry);
    }

    #[test]
    fn test_ledger_entry_type_discriminants() {
        // These values MUST match stellar-core's XDR definition for correct sorting
        // See Stellar-ledger-entries.x in stellar/stellar-xdr
        assert_eq!(LedgerEntryType::Account as i32, 0);
        assert_eq!(LedgerEntryType::Trustline as i32, 1);
        assert_eq!(LedgerEntryType::Offer as i32, 2);
        assert_eq!(LedgerEntryType::Data as i32, 3);
        assert_eq!(LedgerEntryType::ClaimableBalance as i32, 4);
        assert_eq!(LedgerEntryType::LiquidityPool as i32, 5);
        assert_eq!(LedgerEntryType::ContractData as i32, 6);
        assert_eq!(LedgerEntryType::ContractCode as i32, 7);
        assert_eq!(LedgerEntryType::ConfigSetting as i32, 8);
        assert_eq!(LedgerEntryType::Ttl as i32, 9);
    }

    #[test]
    fn test_compare_keys_different_types() {
        // Ensure keys of different types are compared by type discriminant first
        let account_key = LedgerKey::Account(LedgerKeyAccount {
            account_id: make_account_id([255u8; 32]), // Highest possible account
        });
        let trustline_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: make_account_id([0u8; 32]), // Lowest possible account
            asset: TrustLineAsset::Native,
        });

        // Account (type 0) should sort before Trustline (type 1), regardless of account bytes
        assert_eq!(compare_keys(&account_key, &trustline_key), Ordering::Less);
        assert_eq!(compare_keys(&trustline_key, &account_key), Ordering::Greater);
    }
}
