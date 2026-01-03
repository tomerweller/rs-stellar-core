//! Soroban Host execution integration.
//!
//! This module provides the integration between our ledger state and the
//! soroban-env-host crate for executing Soroban smart contracts.
//!
//! ## Protocol Versioning
//!
//! The actual execution is delegated to protocol-versioned implementations
//! in the `protocol` submodule. This ensures deterministic replay by using
//! the exact same soroban-env-host version as C++ stellar-core.

use soroban_env_host::{events::Events, HostError};

use stellar_xdr::curr::{
    AccountId, ContractEvent, Hash, HostFunction, LedgerEntry, LedgerKey, ScVal,
    SorobanAuthorizationEntry, SorobanTransactionData,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use super::SorobanConfig;
use super::protocol::{self, InvokeHostFunctionOutput, LedgerEntryChange};

/// Result of Soroban host function execution.
pub struct SorobanExecutionResult {
    /// The return value of the function.
    pub return_value: ScVal,
    /// Storage changes made during execution.
    pub storage_changes: Vec<StorageChange>,
    /// Contract events for hash computation (Contract and System types only).
    pub contract_events: Vec<ContractEvent>,
    /// Events emitted during execution (for meta/diagnostics).
    pub events: Events,
    /// CPU instructions consumed.
    pub cpu_insns: u64,
    /// Memory bytes consumed.
    pub mem_bytes: u64,
}

/// A single storage change from Soroban execution.
pub struct StorageChange {
    /// The ledger key.
    pub key: LedgerKey,
    /// The new entry (None if deleted).
    pub new_entry: Option<LedgerEntry>,
    /// The new live_until ledger (for TTL).
    pub live_until: Option<u32>,
}

/// Execute a Soroban host function using the appropriate protocol-versioned host.
///
/// This function delegates to the protocol-versioned implementation based on
/// the ledger's protocol version.
///
/// # Arguments
///
/// * `host_function` - The host function to execute
/// * `auth_entries` - Authorization entries for the invocation
/// * `source` - Source account for the transaction
/// * `state` - Ledger state manager for reading entries
/// * `context` - Ledger context with sequence, close time, etc.
/// * `soroban_data` - Soroban transaction data with footprint and resources
/// * `soroban_config` - Network configuration with cost parameters
///
/// # Returns
///
/// Returns the execution result including return value, storage changes, and events.
/// Returns an error if the host function fails or budget is exceeded.
pub fn execute_host_function(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<SorobanExecutionResult, HostError> {
    // Delegate to protocol-versioned implementation
    let output = protocol::execute_host_function(
        host_function,
        auth_entries,
        source,
        state,
        context,
        soroban_data,
        soroban_config,
    )?;

    // Convert to our result type
    Ok(convert_output(output))
}

/// Convert the protocol-versioned output to our result type.
fn convert_output(output: InvokeHostFunctionOutput) -> SorobanExecutionResult {
    let storage_changes = output.ledger_changes
        .into_iter()
        .map(convert_ledger_change)
        .collect();

    SorobanExecutionResult {
        return_value: output.return_value,
        storage_changes,
        contract_events: output.contract_events,
        events: Events::default(), // TODO: convert from encoded_contract_events for diagnostics
        cpu_insns: output.cpu_insns,
        mem_bytes: output.mem_bytes,
    }
}

/// Convert a ledger entry change to a storage change.
fn convert_ledger_change(change: LedgerEntryChange) -> StorageChange {
    StorageChange {
        key: change.key,
        new_entry: change.new_entry,
        live_until: change.ttl_change.map(|ttl| ttl.new_live_until_ledger),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{Limits, WriteXdr};

    /// Compute the hash of a ledger key for TTL lookup.
    fn compute_key_hash(key: &LedgerKey) -> Hash {
        let mut hasher = Sha256::new();
        if let Ok(bytes) = key.to_xdr(Limits::none()) {
            hasher.update(&bytes);
        }
        Hash(hasher.finalize().into())
    }

    #[test]
    fn test_compute_key_hash() {
        let key = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });
        let hash = compute_key_hash(&key);
        assert_ne!(hash.0, [0u8; 32]);
    }
}
