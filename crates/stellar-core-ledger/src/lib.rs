//! Ledger management for rs-stellar-core.
//!
//! This crate handles ledger state management, including:
//!
//! - Ledger header construction and validation
//! - Ledger state snapshots (via BucketList integration)
//! - Ledger close operations
//! - Fee and reserve calculations
//!
//! ## Ledger Close Process
//!
//! 1. Receive the externalized transaction set from Herder
//! 2. Apply each transaction to the ledger state
//! 3. Update the BucketList with state changes
//! 4. Compute the new ledger header hash
//! 5. Persist the ledger and prepare for the next round
//!
//! ## State Model
//!
//! Ledger state consists of ledger entries:
//! - Accounts
//! - Trustlines
//! - Offers
//! - Data entries
//! - Claimable balances
//! - Liquidity pools
//! - Contract data (Soroban)
//!
//! ## Example Usage
//!
//! ```ignore
//! use stellar_core_ledger::{LedgerManager, LedgerCloseData, TransactionSetVariant};
//!
//! // Create a ledger manager
//! let manager = LedgerManager::new(db, bucket_manager, network_passphrase);
//!
//! // Initialize from buckets (during catchup)
//! manager.initialize_from_buckets(bucket_list, header)?;
//!
//! // Begin a ledger close
//! let close_data = LedgerCloseData::new(seq, tx_set, close_time, prev_hash);
//! let mut ctx = manager.begin_close(close_data)?;
//!
//! // Apply transactions and record changes
//! ctx.record_create(new_entry)?;
//! ctx.record_update(old_entry, new_entry)?;
//!
//! // Commit the ledger
//! let result = ctx.commit()?;
//! ```

mod close;
mod delta;
mod error;
pub mod execution;
mod header;
mod manager;
mod snapshot;

// Re-export main types
pub use close::{
    LedgerCloseData, LedgerCloseResult, LedgerCloseStats, TransactionSetVariant, UpgradeContext,
};
pub use delta::{entry_to_key, EntryChange, LedgerDelta};
pub use error::LedgerError;
pub use header::{
    close_time, compute_header_hash, compute_skip_list, create_next_header,
    is_before_protocol_version, protocol_version, skip_list_target_seq, verify_header_chain,
    verify_skip_list, SKIP_LIST_SIZE,
};
pub use manager::{LedgerCloseContext, LedgerManager, LedgerManagerConfig, LedgerManagerStats};
pub use snapshot::{
    LedgerSnapshot, SnapshotBuilder, SnapshotHandle, SnapshotManager,
};

/// Result type for ledger operations.
pub type Result<T> = std::result::Result<T, LedgerError>;

/// Current ledger header information (simplified view).
#[derive(Debug, Clone)]
pub struct LedgerInfo {
    /// Ledger sequence number.
    pub sequence: u32,
    /// Hash of the previous ledger.
    pub previous_ledger_hash: stellar_core_common::Hash256,
    /// Bucket list hash.
    pub bucket_list_hash: stellar_core_common::Hash256,
    /// Ledger close time (Unix timestamp).
    pub close_time: u64,
    /// Base fee in stroops.
    pub base_fee: u32,
    /// Base reserve in stroops.
    pub base_reserve: u32,
    /// Protocol version.
    pub protocol_version: u32,
}

impl From<&stellar_xdr::curr::LedgerHeader> for LedgerInfo {
    fn from(header: &stellar_xdr::curr::LedgerHeader) -> Self {
        Self {
            sequence: header.ledger_seq,
            previous_ledger_hash: stellar_core_common::Hash256::from(header.previous_ledger_hash.0),
            bucket_list_hash: stellar_core_common::Hash256::from(header.bucket_list_hash.0),
            close_time: header.scp_value.close_time.0,
            base_fee: header.base_fee,
            base_reserve: header.base_reserve,
            protocol_version: header.ledger_version,
        }
    }
}

/// A change to a ledger entry (simplified wrapper for use in lib.rs).
#[derive(Debug, Clone)]
pub enum LedgerChange {
    /// Create a new entry.
    Create(stellar_xdr::curr::LedgerEntry),
    /// Update an existing entry.
    Update(stellar_xdr::curr::LedgerEntry),
    /// Delete an entry.
    Delete(stellar_xdr::curr::LedgerKey),
}

/// Fee calculation utilities.
pub mod fees {
    use stellar_xdr::curr::{AccountEntry, Transaction, TransactionEnvelope};

    /// Calculate the fee for a transaction.
    ///
    /// The fee is calculated as: num_operations * base_fee
    /// But the actual charged fee is limited by the transaction's fee field.
    pub fn calculate_fee(tx: &Transaction, base_fee: u32) -> u64 {
        let num_ops = tx.operations.len() as u64;
        let min_fee = num_ops * base_fee as u64;

        // The transaction's fee field is the maximum the user is willing to pay
        std::cmp::min(tx.fee as u64, min_fee)
    }

    /// Calculate the fee for a transaction envelope.
    pub fn calculate_envelope_fee(env: &TransactionEnvelope, base_fee: u32) -> u64 {
        match env {
            TransactionEnvelope::TxV0(tx) => {
                let num_ops = tx.tx.operations.len() as u64;
                num_ops * base_fee as u64
            }
            TransactionEnvelope::Tx(tx) => calculate_fee(&tx.tx, base_fee),
            TransactionEnvelope::TxFeeBump(tx) => {
                // For fee bump, use the outer fee
                tx.tx.fee as u64
            }
        }
    }

    /// Check if an account can afford the fee.
    pub fn can_afford_fee(account: &AccountEntry, fee: u64) -> bool {
        // Account must have enough XLM to pay the fee
        // considering selling liabilities
        let available = available_balance(account);
        available >= fee as i64
    }

    /// Calculate the available balance (excluding reserves and liabilities).
    pub fn available_balance(account: &AccountEntry) -> i64 {
        let selling_liabilities = match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => 0,
            stellar_xdr::curr::AccountEntryExt::V1(v1) => v1.liabilities.selling,
        };

        // Available = balance - selling_liabilities
        // (reserves are checked separately)
        account.balance - selling_liabilities
    }
}

/// Reserve calculation utilities.
pub mod reserves {
    use stellar_xdr::curr::AccountEntry;

    /// Number of stroops per XLM.
    pub const STROOPS_PER_XLM: i64 = 10_000_000;

    /// Calculate the minimum balance for an account.
    ///
    /// Minimum balance = (2 + num_sub_entries + num_sponsoring - num_sponsored) * base_reserve
    pub fn minimum_balance(account: &AccountEntry, base_reserve: u32) -> i64 {
        let base = base_reserve as i64;

        // Get sponsorship info if available
        let (num_sponsoring, num_sponsored) = match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => (0, 0),
            stellar_xdr::curr::AccountEntryExt::V1(v1) => match &v1.ext {
                stellar_xdr::curr::AccountEntryExtensionV1Ext::V0 => (0, 0),
                stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) => {
                    (v2.num_sponsoring as i64, v2.num_sponsored as i64)
                }
            },
        };

        // Base account entries (2) + sub entries + sponsoring - sponsored
        let num_entries = 2 + account.num_sub_entries as i64 + num_sponsoring - num_sponsored;

        num_entries * base
    }

    /// Calculate the selling liabilities for an account (native asset).
    pub fn selling_liabilities(account: &AccountEntry) -> i64 {
        match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => 0,
            stellar_xdr::curr::AccountEntryExt::V1(v1) => v1.liabilities.selling,
        }
    }

    /// Calculate the buying liabilities for an account (native asset).
    pub fn buying_liabilities(account: &AccountEntry) -> i64 {
        match &account.ext {
            stellar_xdr::curr::AccountEntryExt::V0 => 0,
            stellar_xdr::curr::AccountEntryExt::V1(v1) => v1.liabilities.buying,
        }
    }

    /// Calculate the available balance to send.
    ///
    /// Available = balance - minimum_balance - selling_liabilities
    pub fn available_to_send(account: &AccountEntry, base_reserve: u32) -> i64 {
        let min_bal = minimum_balance(account, base_reserve);
        let sell_liab = selling_liabilities(account);

        account.balance.saturating_sub(min_bal).saturating_sub(sell_liab)
    }

    /// Calculate the available capacity to receive.
    ///
    /// Available = i64::MAX - balance - buying_liabilities
    pub fn available_to_receive(account: &AccountEntry) -> i64 {
        let buy_liab = buying_liabilities(account);
        i64::MAX
            .saturating_sub(account.balance)
            .saturating_sub(buy_liab)
    }

    /// Check if an account can afford to add a sub-entry.
    pub fn can_add_sub_entry(account: &AccountEntry, base_reserve: u32) -> bool {
        let current_min = minimum_balance(account, base_reserve);
        let new_min = current_min + base_reserve as i64;
        let sell_liab = selling_liabilities(account);

        account.balance >= new_min + sell_liab
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountId, PublicKey, SequenceNumber, Thresholds, Uint256,
    };

    fn create_test_account(balance: i64, num_sub_entries: u32) -> AccountEntry {
        AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32]))),
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries,
            inflation_dest: None,
            flags: 0,
            home_domain: stellar_xdr::curr::String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: stellar_xdr::curr::VecM::default(),
            ext: AccountEntryExt::V0,
        }
    }

    #[test]
    fn test_minimum_balance() {
        let account = create_test_account(100_000_000, 0);
        let base_reserve = 5_000_000; // 0.5 XLM

        // (2 + 0) * 5_000_000 = 10_000_000
        assert_eq!(reserves::minimum_balance(&account, base_reserve), 10_000_000);

        let account2 = create_test_account(100_000_000, 3);
        // (2 + 3) * 5_000_000 = 25_000_000
        assert_eq!(reserves::minimum_balance(&account2, base_reserve), 25_000_000);
    }

    #[test]
    fn test_available_to_send() {
        let account = create_test_account(100_000_000, 0);
        let base_reserve = 5_000_000;

        // 100_000_000 - 10_000_000 - 0 = 90_000_000
        assert_eq!(reserves::available_to_send(&account, base_reserve), 90_000_000);
    }

    #[test]
    fn test_can_afford_fee() {
        let account = create_test_account(10_000, 0);
        assert!(fees::can_afford_fee(&account, 1000));
        assert!(fees::can_afford_fee(&account, 10_000));
        assert!(!fees::can_afford_fee(&account, 10_001));
    }
}
