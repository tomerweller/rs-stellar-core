//! Transaction application for replay/catchup mode.
//!
//! During catchup, we apply transactions by replaying the historical results
//! from the archive. We don't re-execute the transactions; instead, we apply
//! the state changes recorded in the transaction meta.

use stellar_xdr::curr::{
    AccountEntry, LedgerEntry, LedgerEntryChange, LedgerEntryChanges, LedgerEntryData, LedgerKey,
    LedgerKeyAccount, LedgerKeyClaimableBalance, LedgerKeyContractCode, LedgerKeyContractData,
    LedgerKeyData, LedgerKeyLiquidityPool, LedgerKeyOffer, LedgerKeyTrustLine, LedgerKeyTtl,
    TransactionMeta, TransactionResult,
};

use crate::frame::TransactionFrame;
use crate::result::{TxApplyResult, TxResultWrapper};
use crate::Result;

/// Delta type alias for state changes.
#[derive(Clone)]
pub struct LedgerDelta {
    /// Ledger sequence this delta applies to.
    ledger_seq: u32,
    /// Entries created.
    created: Vec<LedgerEntry>,
    /// Entries updated.
    updated: Vec<LedgerEntry>,
    /// Entries deleted.
    deleted: Vec<LedgerKey>,
    /// Fee charged.
    fee_charged: i64,
}

impl LedgerDelta {
    /// Create a new delta for the given ledger sequence.
    pub fn new(ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            created: Vec::new(),
            updated: Vec::new(),
            deleted: Vec::new(),
            fee_charged: 0,
        }
    }

    /// Get the ledger sequence.
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    /// Record a created entry.
    pub fn record_create(&mut self, entry: LedgerEntry) {
        self.created.push(entry);
    }

    /// Record an updated entry.
    pub fn record_update(&mut self, entry: LedgerEntry) {
        self.updated.push(entry);
    }

    /// Record a deleted entry.
    pub fn record_delete(&mut self, key: LedgerKey) {
        self.deleted.push(key);
    }

    /// Add fee charged.
    pub fn add_fee(&mut self, fee: i64) {
        self.fee_charged += fee;
    }

    /// Get all created entries.
    pub fn created_entries(&self) -> &[LedgerEntry] {
        &self.created
    }

    /// Get all updated entries.
    pub fn updated_entries(&self) -> &[LedgerEntry] {
        &self.updated
    }

    /// Get all deleted keys.
    pub fn deleted_keys(&self) -> &[LedgerKey] {
        &self.deleted
    }

    /// Get total fee charged.
    pub fn fee_charged(&self) -> i64 {
        self.fee_charged
    }

    /// Get the total number of changes.
    pub fn change_count(&self) -> usize {
        self.created.len() + self.updated.len() + self.deleted.len()
    }

    /// Check if this delta has any changes.
    pub fn has_changes(&self) -> bool {
        !self.created.is_empty() || !self.updated.is_empty() || !self.deleted.is_empty()
    }

    /// Merge another delta into this one.
    pub fn merge(&mut self, other: LedgerDelta) {
        self.created.extend(other.created);
        self.updated.extend(other.updated);
        self.deleted.extend(other.deleted);
        self.fee_charged += other.fee_charged;
    }
}

/// Context for applying transactions during catchup.
pub struct ApplyContext {
    /// Current ledger sequence.
    pub ledger_seq: u32,
    /// Ledger close time.
    pub close_time: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Base fee.
    pub base_fee: u32,
    /// Base reserve.
    pub base_reserve: u32,
    /// Network ID bytes.
    pub network_id: [u8; 32],
}

impl ApplyContext {
    /// Create a new apply context.
    pub fn new(
        ledger_seq: u32,
        close_time: u64,
        protocol_version: u32,
        base_fee: u32,
        base_reserve: u32,
        network_id: [u8; 32],
    ) -> Self {
        Self {
            ledger_seq,
            close_time,
            protocol_version,
            base_fee,
            base_reserve,
            network_id,
        }
    }
}

/// Apply a transaction from history.
///
/// This is the main entry point for catchup mode. We trust the historical
/// results and just apply the state changes from the transaction meta.
pub fn apply_from_history(
    _frame: &TransactionFrame,
    result: &TransactionResult,
    meta: &TransactionMeta,
    delta: &mut LedgerDelta,
) -> Result<TxApplyResult> {
    // Add fee to delta
    delta.add_fee(result.fee_charged);

    // Apply state changes from meta
    apply_meta_changes(meta, delta)?;

    // Create result wrapper
    let wrapper = TxResultWrapper::from_xdr(result.clone());
    let success = wrapper.is_success();

    Ok(TxApplyResult {
        success,
        fee_charged: result.fee_charged,
        result: wrapper,
    })
}

/// Apply state changes from transaction meta.
fn apply_meta_changes(meta: &TransactionMeta, delta: &mut LedgerDelta) -> Result<()> {
    match meta {
        TransactionMeta::V0(changes) => {
            for op_meta in changes.iter() {
                apply_ledger_entry_changes(&op_meta.changes, delta)?;
            }
        }
        TransactionMeta::V1(v1) => {
            apply_ledger_entry_changes(&v1.tx_changes, delta)?;
            for op_meta in v1.operations.iter() {
                apply_ledger_entry_changes(&op_meta.changes, delta)?;
            }
        }
        TransactionMeta::V2(v2) => {
            apply_ledger_entry_changes(&v2.tx_changes_before, delta)?;
            for op_meta in v2.operations.iter() {
                apply_ledger_entry_changes(&op_meta.changes, delta)?;
            }
            apply_ledger_entry_changes(&v2.tx_changes_after, delta)?;
        }
        TransactionMeta::V3(v3) => {
            apply_ledger_entry_changes(&v3.tx_changes_before, delta)?;
            for op_meta in v3.operations.iter() {
                apply_ledger_entry_changes(&op_meta.changes, delta)?;
            }
            apply_ledger_entry_changes(&v3.tx_changes_after, delta)?;
        }
        TransactionMeta::V4(v4) => {
            apply_ledger_entry_changes(&v4.tx_changes_before, delta)?;
            for op_meta in v4.operations.iter() {
                apply_ledger_entry_changes(&op_meta.changes, delta)?;
            }
            apply_ledger_entry_changes(&v4.tx_changes_after, delta)?;
        }
    }

    Ok(())
}

/// Apply a set of ledger entry changes to the delta.
fn apply_ledger_entry_changes(changes: &LedgerEntryChanges, delta: &mut LedgerDelta) -> Result<()> {
    for change in changes.iter() {
        match change {
            LedgerEntryChange::Created(entry) => {
                delta.record_create(entry.clone());
            }
            LedgerEntryChange::Updated(entry) => {
                delta.record_update(entry.clone());
            }
            LedgerEntryChange::Removed(key) => {
                delta.record_delete(key.clone());
            }
            LedgerEntryChange::State(_) => {
                // State entries are for debugging/diagnostics
            }
            LedgerEntryChange::Restored(entry) => {
                delta.record_create(entry.clone());
            }
        }
    }

    Ok(())
}

/// Apply fee-only for a failed transaction.
pub fn apply_fee_only(
    frame: &TransactionFrame,
    delta: &mut LedgerDelta,
    _source_account: &AccountEntry,
) -> Result<()> {
    let fee = frame.total_fee();
    delta.add_fee(fee);
    Ok(())
}

/// Extract the ledger key from a ledger entry.
pub fn entry_to_key(entry: &LedgerEntry) -> LedgerKey {
    match &entry.data {
        LedgerEntryData::Account(a) => LedgerKey::Account(LedgerKeyAccount {
            account_id: a.account_id.clone(),
        }),
        LedgerEntryData::Trustline(t) => LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: t.account_id.clone(),
            asset: t.asset.clone(),
        }),
        LedgerEntryData::Offer(o) => LedgerKey::Offer(LedgerKeyOffer {
            seller_id: o.seller_id.clone(),
            offer_id: o.offer_id,
        }),
        LedgerEntryData::Data(d) => LedgerKey::Data(LedgerKeyData {
            account_id: d.account_id.clone(),
            data_name: d.data_name.clone(),
        }),
        LedgerEntryData::ClaimableBalance(c) => {
            LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: c.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(l) => LedgerKey::LiquidityPool(LedgerKeyLiquidityPool {
            liquidity_pool_id: l.liquidity_pool_id.clone(),
        }),
        LedgerEntryData::ContractData(c) => LedgerKey::ContractData(LedgerKeyContractData {
            contract: c.contract.clone(),
            key: c.key.clone(),
            durability: c.durability.clone(),
        }),
        LedgerEntryData::ContractCode(c) => LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: c.hash.clone(),
        }),
        LedgerEntryData::ConfigSetting(c) => {
            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: c.discriminant(),
            })
        }
        LedgerEntryData::Ttl(t) => LedgerKey::Ttl(LedgerKeyTtl {
            key_hash: t.key_hash.clone(),
        }),
    }
}

/// Convert AccountId to lookup key
pub fn account_id_to_key(account_id: &stellar_xdr::curr::AccountId) -> [u8; 32] {
    match &account_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Asset key for lookups
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum AssetKey {
    Native,
    CreditAlphanum4([u8; 4], [u8; 32]),
    CreditAlphanum12([u8; 12], [u8; 32]),
}

impl AssetKey {
    pub fn from_asset(asset: &stellar_xdr::curr::Asset) -> Self {
        match asset {
            stellar_xdr::curr::Asset::Native => AssetKey::Native,
            stellar_xdr::curr::Asset::CreditAlphanum4(a) => {
                let mut code = [0u8; 4];
                code.copy_from_slice(&a.asset_code.0);
                let issuer = account_id_to_key(&a.issuer);
                AssetKey::CreditAlphanum4(code, issuer)
            }
            stellar_xdr::curr::Asset::CreditAlphanum12(a) => {
                let mut code = [0u8; 12];
                code.copy_from_slice(&a.asset_code.0);
                let issuer = account_id_to_key(&a.issuer);
                AssetKey::CreditAlphanum12(code, issuer)
            }
        }
    }
}

/// Batch apply multiple transactions from history.
pub fn apply_transaction_set_from_history(
    transactions: &[(TransactionFrame, TransactionResult, TransactionMeta)],
    delta: &mut LedgerDelta,
) -> Result<Vec<TxApplyResult>> {
    let mut results = Vec::with_capacity(transactions.len());

    for (frame, result, meta) in transactions {
        let apply_result = apply_from_history(frame, result, meta, delta)?;
        results.push(apply_result);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    #[test]
    fn test_ledger_delta_creation() {
        let delta = LedgerDelta::new(100);
        assert_eq!(delta.ledger_seq(), 100);
        assert!(!delta.has_changes());
        assert_eq!(delta.change_count(), 0);
    }

    #[test]
    fn test_ledger_delta_changes() {
        let mut delta = LedgerDelta::new(100);

        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])));
        let entry = LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: account_id.clone(),
                balance: 1000000000,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: vec![].try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        };

        delta.record_create(entry.clone());
        assert!(delta.has_changes());
        assert_eq!(delta.change_count(), 1);
        assert_eq!(delta.created_entries().len(), 1);

        delta.record_update(entry.clone());
        assert_eq!(delta.change_count(), 2);
        assert_eq!(delta.updated_entries().len(), 1);

        let key = LedgerKey::Account(LedgerKeyAccount { account_id });
        delta.record_delete(key);
        assert_eq!(delta.change_count(), 3);
        assert_eq!(delta.deleted_keys().len(), 1);
    }

    #[test]
    fn test_ledger_delta_fee() {
        let mut delta = LedgerDelta::new(100);
        assert_eq!(delta.fee_charged(), 0);

        delta.add_fee(100);
        assert_eq!(delta.fee_charged(), 100);

        delta.add_fee(50);
        assert_eq!(delta.fee_charged(), 150);
    }

    #[test]
    fn test_ledger_delta_merge() {
        let mut delta1 = LedgerDelta::new(100);
        delta1.add_fee(100);

        let mut delta2 = LedgerDelta::new(100);
        delta2.add_fee(200);

        delta1.merge(delta2);
        assert_eq!(delta1.fee_charged(), 300);
    }

    #[test]
    fn test_entry_to_key() {
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])));
        let entry = LedgerEntry {
            last_modified_ledger_seq: 100,
            data: LedgerEntryData::Account(AccountEntry {
                account_id: account_id.clone(),
                balance: 1000000000,
                seq_num: SequenceNumber(1),
                num_sub_entries: 0,
                inflation_dest: None,
                flags: 0,
                home_domain: String32::default(),
                thresholds: Thresholds([1, 0, 0, 0]),
                signers: vec![].try_into().unwrap(),
                ext: AccountEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        };

        let key = entry_to_key(&entry);
        match key {
            LedgerKey::Account(k) => {
                assert_eq!(k.account_id, account_id);
            }
            _ => panic!("Expected Account key"),
        }
    }
}
