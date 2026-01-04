//! Shared types for protocol-versioned host implementations.

use stellar_xdr::curr::{ContractEvent, LedgerEntry, LedgerKey, ScVal};

/// Output from invoking a Soroban host function.
#[derive(Debug, Clone)]
pub struct InvokeHostFunctionOutput {
    /// The return value from the contract execution.
    pub return_value: ScVal,
    /// Changes to ledger entries.
    pub ledger_changes: Vec<LedgerEntryChange>,
    /// Decoded contract events for hash computation (Contract and System types only).
    /// These are the events that go into InvokeHostFunctionSuccessPreImage.
    pub contract_events: Vec<ContractEvent>,
    /// All encoded contract events (for diagnostic purposes).
    pub encoded_contract_events: Vec<EncodedContractEvent>,
    /// CPU instructions consumed.
    pub cpu_insns: u64,
    /// Memory bytes consumed.
    pub mem_bytes: u64,
}

/// A change to a ledger entry from contract execution.
#[derive(Debug, Clone)]
pub struct LedgerEntryChange {
    /// The ledger key that was changed.
    pub key: LedgerKey,
    /// The new entry value (None if deleted).
    pub new_entry: Option<LedgerEntry>,
    /// TTL change information if applicable.
    pub ttl_change: Option<TtlChange>,
    /// Old entry size for rent calculation.
    pub old_entry_size_bytes: u32,
}

/// TTL change information for a ledger entry.
#[derive(Debug, Clone, Copy)]
pub struct TtlChange {
    /// The new live_until ledger number.
    pub new_live_until_ledger: u32,
}

/// An encoded contract event from execution.
#[derive(Debug, Clone)]
pub struct EncodedContractEvent {
    /// The XDR-encoded event bytes.
    pub encoded_event: Vec<u8>,
    /// Whether this event was in a successful contract call.
    pub in_successful_call: bool,
}
