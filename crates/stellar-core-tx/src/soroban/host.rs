//! Soroban Host execution integration.
//!
//! This module provides the integration between our ledger state and the
//! soroban-env-host crate for executing Soroban smart contracts.

use std::rc::Rc;

use sha2::{Digest, Sha256};

// Use soroban-env-host types for Host interaction
use soroban_env_host::{
    budget::Budget,
    e2e_invoke::{self},
    fees::{compute_rent_fee, LedgerEntryRentChange},
    events::Events,
    storage::{AccessType, EntryWithLiveUntil, Footprint, FootprintMap, SnapshotSource, StorageMap},
    HostError, LedgerInfo,
    xdr::DiagnosticEvent,
};

// Both soroban-env-host v25 and our code use stellar-xdr v25, so we can use types directly
use stellar_xdr::curr::{
    AccountId, Hash, HostFunction, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerFootprint,
    LedgerKey, Limits, ReadXdr, ScVal, SorobanAuthorizationEntry, SorobanTransactionData,
    SorobanTransactionDataExt, WriteXdr,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use super::SorobanConfig;

/// Result of Soroban host function execution.
pub struct SorobanExecutionResult {
    /// The return value of the function.
    pub return_value: ScVal,
    /// Storage changes made during execution.
    pub storage_changes: Vec<StorageChange>,
    /// Contract and system events emitted during execution.
    pub contract_events: Vec<stellar_xdr::curr::ContractEvent>,
    /// Events emitted during execution.
    pub events: Events,
    /// Diagnostic events emitted during execution.
    pub diagnostic_events: Vec<DiagnosticEvent>,
    /// CPU instructions consumed.
    pub cpu_insns: u64,
    /// Memory bytes consumed.
    pub mem_bytes: u64,
    /// Contract events + return value size in bytes.
    pub contract_events_and_return_value_size: u32,
    /// Rent fee charged for storage changes.
    pub rent_fee: i64,
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

/// Adapter that provides snapshot access to our ledger state for Soroban.
pub struct LedgerSnapshotAdapter<'a> {
    state: &'a LedgerStateManager,
    current_ledger: u32,
}

impl<'a> LedgerSnapshotAdapter<'a> {
    pub fn new(state: &'a LedgerStateManager, current_ledger: u32) -> Self {
        Self {
            state,
            current_ledger,
        }
    }
}

impl<'a> SnapshotSource for LedgerSnapshotAdapter<'a> {
    fn get(&self, key: &Rc<LedgerKey>) -> Result<Option<EntryWithLiveUntil>, HostError> {
        // Look up the entry in our state
        let entry = match key.as_ref() {
            LedgerKey::Account(account_key) => {
                self.state.get_account(&account_key.account_id).map(|acc| {
                    LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Account(acc.clone()),
                        ext: LedgerEntryExt::V0,
                    }
                })
            }
            LedgerKey::Trustline(tl_key) => {
                self.state
                    .get_trustline_by_trustline_asset(&tl_key.account_id, &tl_key.asset)
                    .map(|tl| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Trustline(tl.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractData(cd_key) => {
                self.state
                    .get_contract_data(&cd_key.contract, &cd_key.key, cd_key.durability.clone())
                    .map(|cd| LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractData(cd.clone()),
                        ext: LedgerEntryExt::V0,
                    })
            }
            LedgerKey::ContractCode(cc_key) => {
                self.state.get_contract_code(&cc_key.hash).map(|code| {
                    LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::ContractCode(code.clone()),
                        ext: LedgerEntryExt::V0,
                    }
                })
            }
            LedgerKey::Ttl(ttl_key) => {
                self.state.get_ttl(&ttl_key.key_hash).map(|ttl| {
                    LedgerEntry {
                        last_modified_ledger_seq: self.current_ledger,
                        data: LedgerEntryData::Ttl(ttl.clone()),
                        ext: LedgerEntryExt::V0,
                    }
                })
            }
            _ => None,
        };

        match entry {
            Some(e) => {
                // Get TTL for contract entries
                let live_until = get_entry_ttl(self.state, key.as_ref(), self.current_ledger);
                Ok(Some((Rc::new(e), live_until)))
            }
            None => Ok(None),
        }
    }
}

/// Get the TTL for a ledger entry.
fn get_entry_ttl(state: &LedgerStateManager, key: &LedgerKey, current_ledger: u32) -> Option<u32> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            // Compute key hash for TTL lookup
            let key_hash = compute_key_hash(key);
            let ttl = state.get_ttl(&key_hash).map(|ttl| ttl.live_until_ledger_seq);
            if let Some(live_until) = ttl {
                if live_until < current_ledger {
                    tracing::warn!(
                        current_ledger,
                        live_until,
                        key_type = if matches!(key, LedgerKey::ContractCode(_)) { "ContractCode" } else { "ContractData" },
                        "Soroban entry TTL is EXPIRED"
                    );
                }
            } else {
                tracing::warn!(
                    key_type = if matches!(key, LedgerKey::ContractCode(_)) { "ContractCode" } else { "ContractData" },
                    "Soroban entry has NO TTL record"
                );
            }
            ttl
        }
        _ => None,
    }
}

/// Compute the hash of a ledger key for TTL lookup.
fn compute_key_hash(key: &LedgerKey) -> Hash {
    let mut hasher = Sha256::new();
    if let Ok(bytes) = key.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Build a Soroban storage footprint from transaction resources.
#[allow(dead_code)]
pub fn build_footprint(
    budget: &Budget,
    ledger_footprint: &LedgerFootprint,
) -> Result<Footprint, HostError> {
    let mut footprint_map = FootprintMap::new();

    // Add read-only entries
    for key in ledger_footprint.read_only.iter() {
        footprint_map = footprint_map.insert(Rc::new(key.clone()), AccessType::ReadOnly, budget)?;
    }

    // Add read-write entries
    for key in ledger_footprint.read_write.iter() {
        footprint_map = footprint_map.insert(Rc::new(key.clone()), AccessType::ReadWrite, budget)?;
    }

    Ok(Footprint(footprint_map))
}

/// Build a storage map from the ledger state using the footprint.
#[allow(dead_code)]
pub fn build_storage_map(
    budget: &Budget,
    footprint: &Footprint,
    snapshot: &impl SnapshotSource,
) -> Result<StorageMap, HostError> {
    let mut storage_map = StorageMap::new();
    let mut found_count = 0;
    let mut missing_count = 0;

    for (key, access_type) in footprint.0.iter(budget)? {
        let entry = snapshot.get(key)?;
        let key_type = match key.as_ref() {
            LedgerKey::Account(_) => "Account",
            LedgerKey::Trustline(_) => "Trustline",
            LedgerKey::ContractData(_) => "ContractData",
            LedgerKey::ContractCode(_) => "ContractCode",
            LedgerKey::Ttl(_) => "Ttl",
            _ => "Other",
        };

        if let Some((ref e, ref ttl)) = entry {
            found_count += 1;
            let has_ext = !matches!(e.ext, LedgerEntryExt::V0);
            tracing::trace!(
                key_type,
                access = ?access_type,
                last_modified = e.last_modified_ledger_seq,
                has_ext,
                live_until = ?ttl,
                "Soroban footprint entry found"
            );
        } else {
            missing_count += 1;
            tracing::warn!(
                key_type,
                access = ?access_type,
                "Soroban footprint entry MISSING from storage"
            );
        }
        storage_map = storage_map.insert(key.clone(), entry, budget)?;
    }

    tracing::debug!(
        found_count,
        missing_count,
        total = found_count + missing_count,
        "Soroban storage map built from footprint"
    );

    Ok(storage_map)
}

/// Execute a Soroban host function using soroban-env-host's e2e_invoke API.
///
/// This uses the same high-level API that C++ stellar-core uses, which handles
/// all the internal setup correctly.
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
    // Create budget with network cost parameters
    // Use a larger budget for the e2e_invoke call which includes XDR parsing overhead
    // The transaction's instruction limit is for contract execution only, but e2e_invoke
    // also meters the setup operations (XDR parsing, storage map building, etc.)
    let instruction_limit = soroban_config.tx_max_instructions * 2; // Double for setup overhead
    let memory_limit = soroban_config.tx_max_memory_bytes * 2; // Double for setup overhead

    let budget = if soroban_config.has_valid_cost_params() {
        Budget::try_from_configs(
            instruction_limit,
            memory_limit,
            soroban_config.cpu_cost_params.clone(),
            soroban_config.mem_cost_params.clone(),
        )?
    } else {
        tracing::warn!(
            "Using default Soroban budget - cost parameters not loaded from network."
        );
        Budget::default()
    };

    // Build ledger info
    let ledger_info = LedgerInfo {
        protocol_version: context.protocol_version,
        sequence_number: context.sequence,
        timestamp: context.close_time,
        network_id: context.network_id.0.0,
        base_reserve: context.base_reserve,
        min_temp_entry_ttl: soroban_config.min_temp_entry_ttl,
        min_persistent_entry_ttl: soroban_config.min_persistent_entry_ttl,
        max_entry_ttl: soroban_config.max_entry_ttl,
    };
    tracing::debug!(
        protocol_version = context.protocol_version,
        sequence_number = context.sequence,
        timestamp = context.close_time,
        instruction_limit,
        memory_limit,
        has_cost_params = soroban_config.has_valid_cost_params(),
        "Soroban host ledger info configured"
    );

    // Use PRNG seed from context if provided (computed as subSha256(txSetHash, txIndex)),
    // otherwise fall back to a deterministic but incorrect seed based on ledger info.
    let seed: Vec<u8> = if let Some(prng_seed) = context.soroban_prng_seed {
        prng_seed.to_vec()
    } else {
        // Fallback: use ledger info to generate a deterministic but incorrect seed.
        // This will cause Soroban contract results to differ from C++ stellar-core.
        tracing::warn!(
            "Using fallback PRNG seed - results may differ from C++ stellar-core"
        );
        let mut hasher = Sha256::new();
        hasher.update(&context.network_id.0.0);
        hasher.update(&context.sequence.to_le_bytes());
        hasher.update(&context.close_time.to_le_bytes());
        hasher.finalize().to_vec()
    };

    // Encode all data to XDR bytes for e2e_invoke
    let encoded_host_fn = host_function.to_xdr(Limits::none())
        .map_err(|_e| HostError::from(soroban_env_host::Error::from_type_and_code(
            soroban_env_host::xdr::ScErrorType::Context,
            soroban_env_host::xdr::ScErrorCode::InternalError,
        )))?;

    let encoded_resources = soroban_data.resources.to_xdr(Limits::none())
        .map_err(|_e| HostError::from(soroban_env_host::Error::from_type_and_code(
            soroban_env_host::xdr::ScErrorType::Context,
            soroban_env_host::xdr::ScErrorCode::InternalError,
        )))?;

    let encoded_source = source.to_xdr(Limits::none())
        .map_err(|_e| HostError::from(soroban_env_host::Error::from_type_and_code(
            soroban_env_host::xdr::ScErrorType::Context,
            soroban_env_host::xdr::ScErrorCode::InternalError,
        )))?;

    // Encode auth entries
    let encoded_auth_entries: Vec<Vec<u8>> = auth_entries
        .iter()
        .map(|e| e.to_xdr(Limits::none()))
        .collect::<Result<_, _>>()
        .map_err(|_e| HostError::from(soroban_env_host::Error::from_type_and_code(
            soroban_env_host::xdr::ScErrorType::Context,
            soroban_env_host::xdr::ScErrorCode::InternalError,
        )))?;

    // Create snapshot adapter to get ledger entries
    let snapshot = LedgerSnapshotAdapter::new(state, context.sequence);

    // Collect and encode ledger entries from the footprint
    // IMPORTANT: e2e_invoke expects exactly one TTL entry for each ledger entry (they are zipped)
    // For non-contract entries (Account, etc), we pass empty bytes for TTL
    let mut encoded_ledger_entries = Vec::new();
    let mut encoded_ttl_entries = Vec::new();

    // Helper to encode an entry and its TTL
    let mut add_entry = |key: &LedgerKey, entry: &LedgerEntry, live_until: Option<u32>| -> Result<(), HostError> {
        encoded_ledger_entries.push(entry.to_xdr(Limits::none())
            .map_err(|_| HostError::from(soroban_env_host::Error::from_type_and_code(
                soroban_env_host::xdr::ScErrorType::Context,
                soroban_env_host::xdr::ScErrorCode::InternalError,
            )))?);

        // Encode TTL entry if present, otherwise push empty bytes
        // e2e_invoke zips entries with TTLs, so we need exactly one TTL per entry
        let ttl_bytes = if let Some(lu) = live_until {
            let key_hash = compute_key_hash(key);
            let ttl_entry = stellar_xdr::curr::TtlEntry {
                key_hash,
                live_until_ledger_seq: lu,
            };
            ttl_entry.to_xdr(Limits::none())
                .map_err(|_| HostError::from(soroban_env_host::Error::from_type_and_code(
                    soroban_env_host::xdr::ScErrorType::Context,
                    soroban_env_host::xdr::ScErrorCode::InternalError,
                )))?
        } else {
            // Empty bytes for entries that don't need TTL (non-contract entries)
            Vec::new()
        };
        encoded_ttl_entries.push(ttl_bytes);
        Ok(())
    };

    for key in soroban_data.resources.footprint.read_only.iter() {
        if let Some((entry, live_until)) = snapshot.get(&Rc::new(key.clone()))? {
            add_entry(key, &entry, live_until)?;
        }
    }

    for key in soroban_data.resources.footprint.read_write.iter() {
        if let Some((entry, live_until)) = snapshot.get(&Rc::new(key.clone()))? {
            add_entry(key, &entry, live_until)?;
        }
    }

    tracing::debug!(
        ledger_entries_count = encoded_ledger_entries.len(),
        ttl_entries_count = encoded_ttl_entries.len(),
        "Prepared entries for e2e_invoke"
    );

    // Extract archived entry indices from soroban_data.ext for TTL restoration
    // These are indices into the read_write footprint entries that need their TTL restored
    let restored_rw_entry_indices: Vec<u32> = match &soroban_data.ext {
        SorobanTransactionDataExt::V1(ext) => {
            ext.archived_soroban_entries.iter().copied().collect()
        }
        SorobanTransactionDataExt::V0 => Vec::new(),
    };

    // Call e2e_invoke - iterator yields &Vec<u8> which implements AsRef<[u8]>
    let mut diagnostic_events = Vec::new();
    let result = match e2e_invoke::invoke_host_function(
        &budget,
        true, // enable_diagnostics
        &encoded_host_fn,
        &encoded_resources,
        &restored_rw_entry_indices,
        &encoded_source,
        encoded_auth_entries.iter(),
        ledger_info,
        encoded_ledger_entries.iter(),
        encoded_ttl_entries.iter(),
        &seed,
        &mut diagnostic_events,
        None, // trace_hook
        None, // module_cache - let host load from storage
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                cpu_consumed = budget.get_cpu_insns_consumed().unwrap_or(0),
                mem_consumed = budget.get_mem_bytes_consumed().unwrap_or(0),
                diagnostic_events = diagnostic_events.len(),
                "Soroban e2e_invoke failed"
            );
            return Err(e);
        }
    };

    // Parse the result
    let (return_value, return_value_size) = match result.encoded_invoke_result {
        Ok(ref bytes) => {
            let val = ScVal::from_xdr(bytes, Limits::none()).unwrap_or(ScVal::Void);
            (val, bytes.len() as u32)
        }
        Err(ref e) => {
            return Err(e.clone());
        }
    };

    let mut contract_events = Vec::new();
    let mut contract_events_size = 0u32;
    for buf in result.encoded_contract_events.iter() {
        contract_events_size = contract_events_size.saturating_add(buf.len() as u32);
        if let Ok(event) = stellar_xdr::curr::ContractEvent::from_xdr(buf, Limits::none()) {
            contract_events.push(event);
        }
    }

    let host_events: Vec<soroban_env_host::events::HostEvent> = contract_events
        .into_iter()
        .map(|event| soroban_env_host::events::HostEvent {
            event,
            failed_call: false,
        })
        .collect();

    let rent_changes: Vec<LedgerEntryRentChange> = e2e_invoke::extract_rent_changes(&result.ledger_changes);

    // Convert ledger changes to our format
    let storage_changes = result.ledger_changes
        .into_iter()
        .filter_map(|change| {
            // Include if there's a new value or if it was modified (has old entry size)
            if change.encoded_new_value.is_some() || change.old_entry_size_bytes_for_rent > 0 {
                let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).ok()?;
                let new_entry = change.encoded_new_value.and_then(|bytes| {
                    LedgerEntry::from_xdr(&bytes, Limits::none()).ok()
                });
                // Get TTL from ttl_change if present
                let live_until = change.ttl_change.map(|ttl| ttl.new_live_until_ledger);
                Some(StorageChange {
                    key,
                    new_entry,
                    live_until,
                })
            } else {
                None
            }
        })
        .collect();

    // Get budget consumption
    let cpu_insns = budget.get_cpu_insns_consumed().unwrap_or(0);
    let mem_bytes = budget.get_mem_bytes_consumed().unwrap_or(0);
    let contract_events_and_return_value_size = contract_events_size.saturating_add(return_value_size);
    let rent_fee = compute_rent_fee(
        &rent_changes,
        &soroban_config.rent_fee_config,
        context.sequence,
    );

    Ok(SorobanExecutionResult {
        return_value,
        storage_changes,
        contract_events: host_events
            .iter()
            .map(|event| event.event.clone())
            .collect(),
        events: Events(host_events),
        diagnostic_events,
        cpu_insns,
        mem_bytes,
        contract_events_and_return_value_size,
        rent_fee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_key_hash() {
        let key = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([1u8; 32]),
        });
        let hash = compute_key_hash(&key);
        assert_ne!(hash.0, [0u8; 32]);
    }
}
