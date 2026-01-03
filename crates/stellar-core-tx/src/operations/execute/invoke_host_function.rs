//! InvokeHostFunction operation execution.
//!
//! This module implements the execution logic for the InvokeHostFunction operation,
//! which executes Soroban smart contract functions.

use stellar_xdr::curr::{
    AccountId, ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractEvent,
    ContractEventType, DiagnosticEvent, Hash, HostFunction, InvokeHostFunctionOp,
    InvokeHostFunctionResult, InvokeHostFunctionResultCode, InvokeHostFunctionSuccessPreImage,
    LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, OperationResult,
    OperationResultTr, ScAddress, ScVal, SorobanTransactionData, TtlEntry, VecM, WriteXdr,
};

use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;
use super::{OperationExecutionResult, SorobanOperationMeta};

/// Default TTL for newly created contract entries (in ledgers).
const DEFAULT_CONTRACT_TTL: u32 = 518400; // ~30 days at 5-second ledger close

/// Execute an InvokeHostFunction operation.
///
/// This operation invokes a Soroban smart contract function, which can:
/// - Call an existing contract
/// - Create a new contract
/// - Upload contract code
///
/// # Arguments
///
/// * `op` - The InvokeHostFunction operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
/// * `soroban_data` - The Soroban transaction data
/// * `soroban_config` - The Soroban network configuration with cost parameters
///
/// # Returns
///
/// Returns the operation result with the function's return value on success,
/// or a specific failure reason.
pub fn execute_invoke_host_function(
    op: &InvokeHostFunctionOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: Option<&SorobanTransactionData>,
    soroban_config: &SorobanConfig,
) -> Result<OperationExecutionResult> {
    // Validate we have Soroban data for footprint
    let soroban_data = match soroban_data {
        Some(data) => data,
        None => {
            return Ok(OperationExecutionResult::new(make_result(
                InvokeHostFunctionResultCode::Malformed,
                Hash([0u8; 32]),
            )));
        }
    };

    // Dispatch based on host function type
    match &op.host_function {
        HostFunction::InvokeContract(_)
        | HostFunction::CreateContract(_)
        | HostFunction::CreateContractV2(_) => {
            // For contract operations, use soroban-env-host
            execute_contract_invocation(op, source, state, context, soroban_data, soroban_config)
        }
        HostFunction::UploadContractWasm(wasm) => {
            // WASM upload can be handled locally without full host
            execute_upload_wasm(wasm, source, state, context)
        }
    }
}

/// Execute a contract invocation using soroban-env-host.
fn execute_contract_invocation(
    op: &InvokeHostFunctionOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<OperationExecutionResult> {
    use crate::soroban::execute_host_function;
    use sha2::{Digest, Sha256};

    // Convert auth entries to a slice
    let auth_entries: Vec<_> = op.auth.iter().cloned().collect();

    if footprint_has_unrestored_archived_entries(
        state,
        &soroban_data.resources.footprint,
        &soroban_data.ext,
        context.sequence,
    ) {
        return Ok(OperationExecutionResult::new(make_result(
            InvokeHostFunctionResultCode::EntryArchived,
            Hash([0u8; 32]),
        )));
    }

    // Execute via soroban-env-host
    match execute_host_function(
        &op.host_function,
        &auth_entries,
        source,
        state,
        context,
        soroban_data,
        soroban_config,
    ) {
        Ok(result) => {
            // Apply storage changes back to our state.
            apply_soroban_storage_changes(state, &result.storage_changes);

            // Compute result hash from success preimage (return value + events)
            let result_hash = compute_success_preimage_hash(
                &result.return_value,
                &result.contract_events,
            );

            tracing::info!(
                cpu_insns = result.cpu_insns,
                mem_bytes = result.mem_bytes,
                events_count = result.contract_events.len(),
                "Soroban contract executed successfully"
            );

            Ok(OperationExecutionResult::with_soroban_meta(
                make_result(InvokeHostFunctionResultCode::Success, result_hash),
                build_soroban_operation_meta(&result),
            ))
        }
        Err(host_error) => {
            // Print detailed error info to help debug
            eprintln!(
                "=== SOROBAN EXECUTION FAILED ===\n\
                 Error: {:?}\n\
                 Host function: {:?}\n\
                 Ledger: {}\n\
                 =================================",
                host_error,
                &op.host_function,
                context.sequence
            );
            tracing::warn!(
                error = %host_error,
                "Soroban contract execution failed"
            );

            // Map host error to appropriate result code
            Ok(OperationExecutionResult::new(make_result(
                map_host_error_to_result_code(&host_error),
                Hash([0u8; 32]),
            )))
        }
    }
}

/// Execute WASM upload.
fn execute_upload_wasm(
    wasm: &stellar_xdr::curr::BytesM,
    _source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationExecutionResult> {
    use sha2::{Digest, Sha256};

    // Hash the WASM code
    let mut hasher = Sha256::new();
    hasher.update(wasm.as_slice());
    let code_hash = Hash(hasher.finalize().into());

    // Check if this code already exists
    if state.get_contract_code(&code_hash).is_some() {
        // Code already exists, just return success with the hash
        return Ok(OperationExecutionResult::new(make_result(
            InvokeHostFunctionResultCode::Success,
            code_hash,
        )));
    }

    // Create the contract code entry
    let code_entry = ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash: code_hash.clone(),
        code: wasm.clone(),
    };
    state.create_contract_code(code_entry);

    // Create TTL for the code
    let code_key_hash = compute_contract_code_key_hash(&code_hash);
    let ttl_entry = TtlEntry {
        key_hash: code_key_hash,
        live_until_ledger_seq: context.sequence + DEFAULT_CONTRACT_TTL,
    };
    state.create_ttl(ttl_entry);

    // Return success with the code hash
    Ok(OperationExecutionResult::new(make_result(
        InvokeHostFunctionResultCode::Success,
        code_hash,
    )))
}

/// Compute the hash of a ledger key for TTL lookup.
fn compute_key_hash(key: &LedgerKey) -> Hash {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    if let Ok(bytes) = key.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Compute the hash of the success preimage (return value + events).
///
/// This matches how C++ stellar-core computes the InvokeHostFunction success result:
/// the hash is SHA256 of the XDR-encoded InvokeHostFunctionSuccessPreImage,
/// which contains both the return value and the contract events.
fn compute_success_preimage_hash(return_value: &ScVal, events: &[ContractEvent]) -> Hash {
    use sha2::{Digest, Sha256};

    // Build the success preimage
    let preimage = InvokeHostFunctionSuccessPreImage {
        return_value: return_value.clone(),
        events: events.to_vec().try_into().unwrap_or_default(),
    };

    // Hash the XDR-encoded preimage
    let mut hasher = Sha256::new();
    if let Ok(bytes) = preimage.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

fn build_soroban_operation_meta(
    result: &crate::soroban::SorobanExecutionResult,
) -> SorobanOperationMeta {
    let mut events = Vec::new();
    let mut diagnostic_events = Vec::new();

    for host_event in result.events.0.iter() {
        let event = host_event.event.clone();
        if matches!(event.type_, ContractEventType::Contract | ContractEventType::System) {
            events.push(event.clone());
        }
        diagnostic_events.push(DiagnosticEvent {
            in_successful_contract_call: !host_event.failed_call,
            event,
        });
    }

    SorobanOperationMeta {
        events,
        diagnostic_events,
        return_value: Some(result.return_value.clone()),
    }
}

fn apply_soroban_storage_changes(
    state: &mut LedgerStateManager,
    changes: &[crate::soroban::StorageChange],
) {
    for change in changes {
        apply_soroban_storage_change(state, change);
    }
}

fn apply_soroban_storage_change(
    state: &mut LedgerStateManager,
    change: &crate::soroban::StorageChange,
) {
    if let Some(entry) = &change.new_entry {
        // Handle contract data and code entries.
        match &entry.data {
            stellar_xdr::curr::LedgerEntryData::ContractData(cd) => {
                if state.get_contract_data(&cd.contract, &cd.key, cd.durability.clone()).is_some() {
                    state.update_contract_data(cd.clone());
                } else {
                    state.create_contract_data(cd.clone());
                }
            }
            stellar_xdr::curr::LedgerEntryData::ContractCode(cc) => {
                if state.get_contract_code(&cc.hash).is_some() {
                    state.update_contract_code(cc.clone());
                } else {
                    state.create_contract_code(cc.clone());
                }
            }
            stellar_xdr::curr::LedgerEntryData::Ttl(ttl) => {
                if state.get_ttl(&ttl.key_hash).is_some() {
                    state.update_ttl(ttl.clone());
                } else {
                    state.create_ttl(ttl.clone());
                }
            }
            _ => {}
        }

        // Apply TTL if present for contract entries.
        if let Some(live_until) = change.live_until {
            let key_hash = compute_key_hash(&change.key);
            let ttl = TtlEntry {
                key_hash,
                live_until_ledger_seq: live_until,
            };
            if state.get_ttl(&ttl.key_hash).is_some() {
                state.update_ttl(ttl);
            } else {
                state.create_ttl(ttl);
            }
        }
    } else {
        match &change.key {
            LedgerKey::ContractData(key) => {
                state.delete_contract_data(&key.contract, &key.key, key.durability.clone());
                let key_hash = compute_key_hash(&change.key);
                state.delete_ttl(&key_hash);
            }
            LedgerKey::ContractCode(key) => {
                state.delete_contract_code(&key.hash);
                let key_hash = compute_key_hash(&change.key);
                state.delete_ttl(&key_hash);
            }
            LedgerKey::Ttl(key) => {
                state.delete_ttl(&key.key_hash);
            }
            _ => {}
        }
    }
}

fn footprint_has_unrestored_archived_entries(
    state: &LedgerStateManager,
    footprint: &stellar_xdr::curr::LedgerFootprint,
    ext: &stellar_xdr::curr::SorobanTransactionDataExt,
    current_ledger: u32,
) -> bool {
    let mut archived_rw = std::collections::HashSet::new();
    if let stellar_xdr::curr::SorobanTransactionDataExt::V1(resources_ext) = ext {
        for index in resources_ext.archived_soroban_entries.iter() {
            archived_rw.insert(*index as usize);
        }
    }

    if footprint
        .read_only
        .iter()
        .any(|key| is_archived_contract_entry(state, key, current_ledger))
    {
        return true;
    }

    for (index, key) in footprint.read_write.iter().enumerate() {
        if !is_archived_contract_entry(state, key, current_ledger) {
            continue;
        }
        if !archived_rw.contains(&index) {
            return true;
        }
    }

    false
}

fn is_archived_contract_entry(
    state: &LedgerStateManager,
    key: &LedgerKey,
    current_ledger: u32,
) -> bool {
    match key {
        LedgerKey::ContractData(cd) => {
            if state
                .get_contract_data(&cd.contract, &cd.key, cd.durability.clone())
                .is_none()
            {
                return false;
            }
        }
        LedgerKey::ContractCode(cc) => {
            if state.get_contract_code(&cc.hash).is_none() {
                return false;
            }
        }
        _ => return false,
    }

    let key_hash = compute_key_hash(key);
    match state.get_ttl(&key_hash) {
        Some(ttl) => ttl.live_until_ledger_seq < current_ledger,
        None => true,
    }
}

/// Compute the hash of a contract code key for TTL lookup.
fn compute_contract_code_key_hash(code_hash: &Hash) -> Hash {
    use sha2::{Digest, Sha256};

    let ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: code_hash.clone(),
    });

    let mut hasher = Sha256::new();
    if let Ok(bytes) = ledger_key.to_xdr(Limits::none()) {
        hasher.update(&bytes);
    }
    Hash(hasher.finalize().into())
}

/// Create an OperationResult from an InvokeHostFunctionResultCode.
fn make_result(code: InvokeHostFunctionResultCode, success_hash: Hash) -> OperationResult {
    let result = match code {
        InvokeHostFunctionResultCode::Success => InvokeHostFunctionResult::Success(success_hash),
        InvokeHostFunctionResultCode::Malformed => InvokeHostFunctionResult::Malformed,
        InvokeHostFunctionResultCode::Trapped => InvokeHostFunctionResult::Trapped,
        InvokeHostFunctionResultCode::ResourceLimitExceeded => {
            InvokeHostFunctionResult::ResourceLimitExceeded
        }
        InvokeHostFunctionResultCode::EntryArchived => InvokeHostFunctionResult::EntryArchived,
        InvokeHostFunctionResultCode::InsufficientRefundableFee => {
            InvokeHostFunctionResult::InsufficientRefundableFee
        }
    };

    OperationResult::OpInner(OperationResultTr::InvokeHostFunction(result))
}

fn map_host_error_to_result_code(host_error: &soroban_env_host::HostError) -> InvokeHostFunctionResultCode {
    use soroban_env_host::xdr::{ScErrorCode, ScErrorType};

    if host_error.error.is_type(ScErrorType::Budget)
        && host_error.error.is_code(ScErrorCode::ExceededLimit)
    {
        return InvokeHostFunctionResultCode::ResourceLimitExceeded;
    }

    if host_error.error.is_type(ScErrorType::Storage)
        && host_error.error.is_code(ScErrorCode::ExceededLimit)
    {
        return InvokeHostFunctionResultCode::ResourceLimitExceeded;
    }

    InvokeHostFunctionResultCode::Trapped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soroban::StorageChange;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    fn create_test_soroban_config() -> SorobanConfig {
        SorobanConfig::default()
    }

    #[test]
    fn test_invoke_host_function_no_soroban_data() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);
        let config = create_test_soroban_config();

        let op = InvokeHostFunctionOp {
            host_function: HostFunction::UploadContractWasm(vec![0u8; 100].try_into().unwrap()),
            auth: vec![].try_into().unwrap(),
        };

        let result = execute_invoke_host_function(&op, &source, &mut state, &context, None, &config)
            .expect("invoke host function");

        match result.result {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(r)) => {
                assert!(matches!(r, InvokeHostFunctionResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_upload_wasm_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);
        let config = create_test_soroban_config();

        // Create minimal valid WASM
        let wasm_bytes: Vec<u8> = vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic number
            0x01, 0x00, 0x00, 0x00, // WASM version
        ];

        let op = InvokeHostFunctionOp {
            host_function: HostFunction::UploadContractWasm(wasm_bytes.try_into().unwrap()),
            auth: vec![].try_into().unwrap(),
        };

        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![].try_into().unwrap(),
                    read_write: vec![].try_into().unwrap(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result =
            execute_invoke_host_function(&op, &source, &mut state, &context, Some(&soroban_data), &config)
                .expect("invoke host function");

        match result.result {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(r)) => {
                assert!(matches!(r, InvokeHostFunctionResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_invoke_host_function_entry_archived() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);
        let config = create_test_soroban_config();

        let contract_id = ScAddress::Contract(ContractId(Hash([1u8; 32])));
        let contract_key = ScVal::U32(42);
        let durability = ContractDataDurability::Persistent;

        let cd_entry = ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract_id.clone(),
            key: contract_key.clone(),
            durability: durability.clone(),
            val: ScVal::I32(7),
        };
        state.create_contract_data(cd_entry);

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract_id.clone(),
            key: contract_key.clone(),
            durability,
        });
        let key_hash = compute_key_hash(&key);
        state.create_ttl(TtlEntry {
            key_hash,
            live_until_ledger_seq: context.sequence - 1,
        });

        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: contract_id,
            function_name: ScSymbol(StringM::try_from("noop".to_string()).unwrap()),
            args: VecM::default(),
        });

        let op = InvokeHostFunctionOp {
            host_function,
            auth: VecM::default(),
        };

        let footprint = LedgerFootprint {
            read_only: vec![key].try_into().unwrap(),
            read_write: VecM::default(),
        };
        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint,
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result = execute_invoke_host_function(&op, &source, &mut state, &context, Some(&soroban_data), &config)
            .expect("invoke host function");

        match result.result {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(r)) => {
                assert!(matches!(r, InvokeHostFunctionResult::EntryArchived));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_invoke_host_function_archived_allowed_when_marked() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();
        let source = create_test_account_id(0);
        let config = create_test_soroban_config();

        let contract_id = ScAddress::Contract(ContractId(Hash([2u8; 32])));
        let contract_key = ScVal::U32(5);
        let durability = ContractDataDurability::Persistent;

        let cd_entry = ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract_id.clone(),
            key: contract_key.clone(),
            durability: durability.clone(),
            val: ScVal::I32(1),
        };
        state.create_contract_data(cd_entry);

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract_id.clone(),
            key: contract_key.clone(),
            durability,
        });
        let key_hash = compute_key_hash(&key);
        state.create_ttl(TtlEntry {
            key_hash,
            live_until_ledger_seq: context.sequence - 1,
        });

        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: contract_id,
            function_name: ScSymbol(StringM::try_from("noop".to_string()).unwrap()),
            args: VecM::default(),
        });

        let op = InvokeHostFunctionOp {
            host_function,
            auth: VecM::default(),
        };

        let footprint = LedgerFootprint {
            read_only: VecM::default(),
            read_write: vec![key].try_into().unwrap(),
        };
        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                archived_soroban_entries: vec![0u32].try_into().unwrap(),
            }),
            resources: SorobanResources {
                footprint,
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };

        let result = execute_invoke_host_function(&op, &source, &mut state, &context, Some(&soroban_data), &config)
            .expect("invoke host function");

        match result.result {
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(r)) => {
                assert!(matches!(r, InvokeHostFunctionResult::Trapped));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_map_host_error_to_result_code_resource_limit() {
        let host_error = soroban_env_host::HostError::from((
            soroban_env_host::xdr::ScErrorType::Budget,
            soroban_env_host::xdr::ScErrorCode::ExceededLimit,
        ));
        assert_eq!(
            map_host_error_to_result_code(&host_error),
            InvokeHostFunctionResultCode::ResourceLimitExceeded
        );
    }

    #[test]
    fn test_map_host_error_to_result_code_trapped() {
        let host_error = soroban_env_host::HostError::from((
            soroban_env_host::xdr::ScErrorType::Storage,
            soroban_env_host::xdr::ScErrorCode::MissingValue,
        ));
        assert_eq!(
            map_host_error_to_result_code(&host_error),
            InvokeHostFunctionResultCode::Trapped
        );
    }

    #[test]
    fn test_apply_soroban_storage_change_deletes() {
        let mut state = LedgerStateManager::new(5_000_000, 100);

        let contract_id = ScAddress::Contract(ContractId(Hash([1u8; 32])));
        let contract_key = ScVal::U32(7);
        let durability = ContractDataDurability::Persistent;

        let cd_entry = ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract_id.clone(),
            key: contract_key.clone(),
            durability: durability.clone(),
            val: ScVal::I32(1),
        };

        let ledger_entry = LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::ContractData(cd_entry.clone()),
            ext: LedgerEntryExt::V0,
        };

        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract_id.clone(),
            key: contract_key.clone(),
            durability: durability.clone(),
        });

        let change = StorageChange {
            key: key.clone(),
            new_entry: Some(ledger_entry),
            live_until: Some(200),
        };

        apply_soroban_storage_change(&mut state, &change);
        assert!(state
            .get_contract_data(&contract_id, &contract_key, durability.clone())
            .is_some());

        let ttl_key = compute_key_hash(&key);
        assert!(state.get_ttl(&ttl_key).is_some());

        let delete_change = StorageChange {
            key,
            new_entry: None,
            live_until: None,
        };

        apply_soroban_storage_change(&mut state, &delete_change);
        assert!(state
            .get_contract_data(&contract_id, &contract_key, durability)
            .is_none());
        assert!(state.get_ttl(&ttl_key).is_none());
    }
}
