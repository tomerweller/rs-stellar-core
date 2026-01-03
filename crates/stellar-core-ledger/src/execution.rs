//! Transaction execution during ledger close.
//!
//! This module integrates the transaction processing from stellar-core-tx
//! with the ledger close process.

use std::collections::{HashMap, HashSet};

use stellar_core_common::{Hash256, NetworkId};
use stellar_core_invariant::{
    ConstantProductInvariant, EventsAreConsistentWithEntryDiffs, InvariantContext, InvariantManager,
    LedgerEntryChange as InvariantLedgerEntryChange, LiabilitiesMatchOffers,
    OrderBookIsNotCrossed,
};
use stellar_core_tx::{
    soroban::SorobanConfig,
    validation::{self, LedgerContext as ValidationContext},
    LedgerContext, LedgerStateManager, TransactionFrame, TxError,
};
use stellar_xdr::curr::{
    AccountEntry, AccountId, ConfigSettingEntry, ConfigSettingId, ContractCostParams,
    DataEntry, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerHeader,
    ContractEvent, DiagnosticEvent, ExtensionPoint, LedgerEntryChange, LedgerEntryChanges,
    TransactionEvent, TransactionEventStage,
    LedgerKey, LedgerKeyConfigSetting, OfferEntry, OperationBody, OperationMeta, OperationMetaV2,
    OperationResult, Preconditions, SignerKey, SorobanTransactionMetaExt, SorobanTransactionMetaV2,
    TransactionEnvelope, TransactionMeta, TransactionMetaV3, TransactionMetaV4, TransactionResult,
    TransactionResultCode, TransactionResultExt, TransactionResultMetaV1, TransactionResultPair,
    TransactionResultResult, TrustLineEntry, VecM, WriteXdr, Limits, InnerTransactionResult,
    InnerTransactionResultExt,
    InnerTransactionResultPair, InnerTransactionResultResult,
};
use tracing::{debug, info, warn};

use crate::delta::LedgerDelta;
use crate::snapshot::SnapshotHandle;
use crate::{LedgerError, Result};

/// Load a ConfigSettingEntry from the snapshot by ID.
fn load_config_setting(snapshot: &SnapshotHandle, id: ConfigSettingId) -> Option<ConfigSettingEntry> {
    let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: id,
    });
    match snapshot.get_entry(&key) {
        Ok(Some(entry)) => {
            if let LedgerEntryData::ConfigSetting(config) = entry.data {
                Some(config)
            } else {
                None
            }
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

/// Load SorobanConfig from the ledger's ConfigSettingEntry entries.
///
/// This loads the cost parameters and limits from the ledger state,
/// which are required for accurate Soroban transaction execution.
/// If any required settings are missing, returns a default config.
pub fn load_soroban_config(snapshot: &SnapshotHandle) -> SorobanConfig {
    // Load CPU cost params
    let cpu_cost_params = load_config_setting(snapshot, ConfigSettingId::ContractCostParamsCpuInstructions)
        .and_then(|cs| {
            if let ConfigSettingEntry::ContractCostParamsCpuInstructions(params) = cs {
                Some(params)
            } else {
                None
            }
        })
        .unwrap_or_else(|| ContractCostParams(vec![].try_into().unwrap_or_default()));

    // Load memory cost params
    let mem_cost_params = load_config_setting(snapshot, ConfigSettingId::ContractCostParamsMemoryBytes)
        .and_then(|cs| {
            if let ConfigSettingEntry::ContractCostParamsMemoryBytes(params) = cs {
                Some(params)
            } else {
                None
            }
        })
        .unwrap_or_else(|| ContractCostParams(vec![].try_into().unwrap_or_default()));

    // Load compute limits
    let (tx_max_instructions, tx_max_memory_bytes) = load_config_setting(snapshot, ConfigSettingId::ContractComputeV0)
        .and_then(|cs| {
            if let ConfigSettingEntry::ContractComputeV0(compute) = cs {
                Some((compute.tx_max_instructions as u64, compute.tx_memory_limit as u64))
            } else {
                None
            }
        })
        .unwrap_or((100_000_000, 40 * 1024 * 1024)); // Default limits

    // Load state archival TTL settings
    let (min_temp_entry_ttl, min_persistent_entry_ttl, max_entry_ttl) =
        load_config_setting(snapshot, ConfigSettingId::StateArchival)
            .and_then(|cs| {
                if let ConfigSettingEntry::StateArchival(archival) = cs {
                    Some((
                        archival.min_temporary_ttl,
                        archival.min_persistent_ttl,
                        archival.max_entry_ttl,
                    ))
                } else {
                    None
                }
            })
            .unwrap_or((16, 120960, 6312000)); // Default TTL values

    let config = SorobanConfig {
        cpu_cost_params,
        mem_cost_params,
        tx_max_instructions,
        tx_max_memory_bytes,
        min_temp_entry_ttl,
        min_persistent_entry_ttl,
        max_entry_ttl,
    };

    // Log whether we found valid cost params
    if config.has_valid_cost_params() {
        debug!(
            cpu_cost_params_count = config.cpu_cost_params.0.len(),
            mem_cost_params_count = config.mem_cost_params.0.len(),
            tx_max_instructions = config.tx_max_instructions,
            "Loaded Soroban config from ledger"
        );
    } else {
        warn!(
            "No Soroban cost parameters found in ledger - using defaults. \
             Soroban transaction results may not match network."
        );
    }

    config
}

/// Result of executing a transaction.
#[derive(Debug, Clone)]
pub struct TransactionExecutionResult {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Fee charged (always charged even on failure).
    pub fee_charged: i64,
    /// Operation results.
    pub operation_results: Vec<OperationResult>,
    /// Error message if failed.
    pub error: Option<String>,
    /// Failure reason for mapping to XDR result codes.
    pub failure: Option<ExecutionFailure>,
    /// Transaction meta (for ledger close meta).
    pub tx_meta: Option<TransactionMeta>,
    /// Fee processing changes (for ledger close meta).
    pub fee_changes: Option<LedgerEntryChanges>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailure {
    Malformed,
    MissingOperation,
    InvalidSignature,
    BadAuthExtra,
    BadMinSeqAgeOrGap,
    BadSequence,
    InsufficientFee,
    InsufficientBalance,
    NoAccount,
    TooEarly,
    TooLate,
    NotSupported,
    BadSponsorship,
    OperationFailed,
}

/// Context for executing transactions during ledger close.
pub struct TransactionExecutor {
    /// Ledger sequence being processed.
    ledger_seq: u32,
    /// Close time.
    close_time: u64,
    /// Base fee.
    base_fee: u32,
    /// Base reserve.
    base_reserve: u32,
    /// Protocol version.
    protocol_version: u32,
    /// Network ID.
    network_id: NetworkId,
    /// State manager for execution.
    state: LedgerStateManager,
    /// Accounts loaded from snapshot.
    loaded_accounts: HashMap<[u8; 32], bool>,
    /// Soroban network configuration for contract execution.
    soroban_config: SorobanConfig,
    /// Optional operation-level invariants runner.
    op_invariants: Option<OperationInvariantRunner>,
}

impl TransactionExecutor {
    /// Create a new transaction executor.
    pub fn new(
        ledger_seq: u32,
        close_time: u64,
        base_fee: u32,
        base_reserve: u32,
        protocol_version: u32,
        network_id: NetworkId,
        id_pool: u64,
        soroban_config: SorobanConfig,
        op_invariants: Option<OperationInvariantRunner>,
    ) -> Self {
        let mut state = LedgerStateManager::new(base_reserve as i64, ledger_seq);
        state.set_id_pool(id_pool);
        Self {
            ledger_seq,
            close_time,
            base_fee,
            base_reserve,
            protocol_version,
            network_id,
            state,
            loaded_accounts: HashMap::new(),
            soroban_config,
            op_invariants,
        }
    }

    /// Load an account from the snapshot into the state manager.
    pub fn load_account(&mut self, snapshot: &SnapshotHandle, account_id: &AccountId) -> Result<bool> {
        let key_bytes = account_id_to_key(account_id);

        // Check if already loaded
        if self.loaded_accounts.contains_key(&key_bytes) {
            return Ok(self.state.get_account(account_id).is_some());
        }

        // Mark as loaded (even if not found)
        self.loaded_accounts.insert(key_bytes, true);

        // Try to load from snapshot
        let key = stellar_xdr::curr::LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        if let Some(entry) = snapshot.get_entry(&key)? {
            self.state.load_entry(entry);
            return Ok(true);
        }

        Ok(false)
    }

    /// Load a trustline from the snapshot into the state manager.
    pub fn load_trustline(
        &mut self,
        snapshot: &SnapshotHandle,
        account_id: &AccountId,
        asset: &stellar_xdr::curr::TrustLineAsset,
    ) -> Result<bool> {
        if self
            .state
            .get_trustline_by_trustline_asset(account_id, asset)
            .is_some()
        {
            return Ok(true);
        }

        let key = stellar_xdr::curr::LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
            account_id: account_id.clone(),
            asset: asset.clone(),
        });

        if let Some(entry) = snapshot.get_entry(&key)? {
            self.state.load_entry(entry);
            return Ok(true);
        }

        Ok(false)
    }

    /// Load a ledger entry from the snapshot into the state manager.
    ///
    /// This handles all entry types including contract data, contract code, and TTL entries.
    /// Returns true if the entry was found and loaded.
    pub fn load_entry(&mut self, snapshot: &SnapshotHandle, key: &LedgerKey) -> Result<bool> {
        if let Some(entry) = snapshot.get_entry(key)? {
            match &entry.data {
                LedgerEntryData::Account(account) => {
                    if self.state.get_account(&account.account_id).is_none() {
                        self.state.create_account(account.clone());
                    }
                }
                LedgerEntryData::Trustline(trustline) => {
                    if self.state.get_trustline_by_trustline_asset(
                        &trustline.account_id,
                        &trustline.asset,
                    ).is_none() {
                        self.state.create_trustline(trustline.clone());
                    }
                }
                LedgerEntryData::ContractData(cd) => {
                    if self.state.get_contract_data(&cd.contract, &cd.key, cd.durability.clone()).is_none() {
                        self.state.create_contract_data(cd.clone());
                    }
                }
                LedgerEntryData::ContractCode(cc) => {
                    if self.state.get_contract_code(&cc.hash).is_none() {
                        self.state.create_contract_code(cc.clone());
                    }
                }
                LedgerEntryData::Ttl(ttl) => {
                    if self.state.get_ttl(&ttl.key_hash).is_none() {
                        self.state.create_ttl(ttl.clone());
                    }
                }
                LedgerEntryData::Data(data) => {
                    let name_str = std::str::from_utf8(data.data_name.as_slice()).unwrap_or("");
                    if self.state.get_data(&data.account_id, name_str).is_none() {
                        self.state.create_data(data.clone());
                    }
                }
                LedgerEntryData::Offer(offer) => {
                    if self.state.get_offer(&offer.seller_id, offer.offer_id).is_none() {
                        self.state.create_offer(offer.clone());
                    }
                }
                LedgerEntryData::ClaimableBalance(_cb) => {
                    // ClaimableBalance loading handled separately
                }
                LedgerEntryData::ConfigSetting(_) | LedgerEntryData::LiquidityPool(_) => {
                    // ConfigSetting and LiquidityPool handled by specialized loaders
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Load all entries from a Soroban footprint into the state manager.
    ///
    /// This is essential for Soroban transaction execution - the footprint specifies
    /// which ledger entries the transaction will read or write, and they must be
    /// loaded before the Soroban host can access them.
    pub fn load_soroban_footprint(
        &mut self,
        snapshot: &SnapshotHandle,
        footprint: &stellar_xdr::curr::LedgerFootprint,
    ) -> Result<()> {
        // Load read-only entries
        for key in footprint.read_only.iter() {
            self.load_entry(snapshot, key)?;
            // Also load TTL for contract entries
            self.load_ttl_for_key(snapshot, key)?;
        }

        // Load read-write entries
        for key in footprint.read_write.iter() {
            self.load_entry(snapshot, key)?;
            // Also load TTL for contract entries
            self.load_ttl_for_key(snapshot, key)?;
        }

        Ok(())
    }

    /// Load the TTL entry for a contract data or code key.
    fn load_ttl_for_key(&mut self, snapshot: &SnapshotHandle, key: &LedgerKey) -> Result<()> {
        match key {
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
                use sha2::{Digest, Sha256};
                // Compute the key hash for TTL lookup
                let key_bytes = key.to_xdr(Limits::none())
                    .map_err(|e| LedgerError::Serialization(e.to_string()))?;
                let key_hash = stellar_xdr::curr::Hash(Sha256::digest(&key_bytes).into());

                let ttl_key = LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl { key_hash });
                self.load_entry(snapshot, &ttl_key)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Execute a transaction.
    ///
    /// # Arguments
    ///
    /// * `soroban_prng_seed` - Optional PRNG seed for Soroban execution.
    ///   Computed as subSha256(txSetHash, txIndex) at the transaction set level.
    pub fn execute_transaction(
        &mut self,
        snapshot: &SnapshotHandle,
        tx_envelope: &TransactionEnvelope,
        base_fee: u32,
        soroban_prng_seed: Option<[u8; 32]>,
    ) -> Result<TransactionExecutionResult> {
        let mut frame = TransactionFrame::with_network(tx_envelope.clone(), self.network_id.clone());
        let fee_source_id = stellar_core_tx::muxed_to_account_id(&frame.fee_source_account());
        let inner_source_id = stellar_core_tx::muxed_to_account_id(&frame.inner_source_account());

        if !frame.is_valid_structure() {
            let failure = if frame.operations().is_empty() {
                ExecutionFailure::MissingOperation
            } else {
                ExecutionFailure::Malformed
            };
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Invalid transaction structure".into()),
                failure: Some(failure),
                tx_meta: None,
                fee_changes: None,
            });
        }

        // Load source account
        if !self.load_account(snapshot, &fee_source_id)? {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Source account not found".into()),
                failure: Some(ExecutionFailure::NoAccount),
                tx_meta: None,
                fee_changes: None,
            });
        }

        if !self.load_account(snapshot, &inner_source_id)? {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Source account not found".into()),
                failure: Some(ExecutionFailure::NoAccount),
                tx_meta: None,
                fee_changes: None,
            });
        }

        // Get accounts for validation
        let fee_source_account = match self.state.get_account(&fee_source_id) {
            Some(acc) => acc.clone(),
            None => {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    operation_results: vec![],
                    error: Some("Source account not found".into()),
                    failure: Some(ExecutionFailure::NoAccount),
                    tx_meta: None,
                    fee_changes: None,
                });
            }
        };

        let source_account = match self.state.get_account(&inner_source_id) {
            Some(acc) => acc.clone(),
            None => {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    operation_results: vec![],
                    error: Some("Source account not found".into()),
                    failure: Some(ExecutionFailure::NoAccount),
                    tx_meta: None,
                    fee_changes: None,
                });
            }
        };

        let source_last_modified_seq = {
            let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                account_id: inner_source_id.clone(),
            });
            match snapshot.get_entry(&key)? {
                Some(entry) => entry.last_modified_ledger_seq,
                None => {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        operation_results: vec![],
                        error: Some("Source account not found".into()),
                        failure: Some(ExecutionFailure::NoAccount),
                        tx_meta: None,
                        fee_changes: None,
                    });
                }
            }
        };

        // Validate fee
        let required_fee = frame.operation_count() as u32 * base_fee;
        if frame.is_fee_bump() {
            if frame.inner_fee() < required_fee {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    operation_results: vec![],
                    error: Some("Insufficient fee".into()),
                    failure: Some(ExecutionFailure::InsufficientFee),
                    tx_meta: None,
                    fee_changes: None,
                });
            }
            if frame.total_fee() < frame.inner_fee() as i64 {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    operation_results: vec![],
                    error: Some("Insufficient fee".into()),
                    failure: Some(ExecutionFailure::InsufficientFee),
                    tx_meta: None,
                    fee_changes: None,
                });
            }
        } else if frame.fee() < required_fee {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Insufficient fee".into()),
                failure: Some(ExecutionFailure::InsufficientFee),
                tx_meta: None,
                fee_changes: None,
            });
        }

        let validation_ctx = ValidationContext::new(
            self.ledger_seq,
            self.close_time,
            base_fee,
            self.base_reserve,
            self.protocol_version,
            self.network_id.clone(),
        );

        if let Err(e) = validation::validate_time_bounds(&frame, &validation_ctx) {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Time bounds invalid".into()),
                failure: Some(match e {
                    validation::ValidationError::TooEarly { .. } => ExecutionFailure::TooEarly,
                    validation::ValidationError::TooLate { .. } => ExecutionFailure::TooLate,
                    _ => ExecutionFailure::OperationFailed,
                }),
                tx_meta: None,
                fee_changes: None,
            });
        }

        if let Err(e) = validation::validate_ledger_bounds(&frame, &validation_ctx) {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Ledger bounds invalid".into()),
                failure: Some(match e {
                    validation::ValidationError::BadLedgerBounds { min, max, current } => {
                        if max > 0 && current > max {
                            ExecutionFailure::TooLate
                        } else if min > 0 && current < min {
                            ExecutionFailure::TooEarly
                        } else {
                            ExecutionFailure::OperationFailed
                        }
                    }
                    _ => ExecutionFailure::OperationFailed,
                }),
                tx_meta: None,
                fee_changes: None,
            });
        }

        if let Preconditions::V2(cond) = frame.preconditions() {
            if let Some(min_seq) = cond.min_seq_num {
                if source_account.seq_num.0 < min_seq.0 {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        operation_results: vec![],
                        error: Some("Minimum sequence number not met".into()),
                        failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                        tx_meta: None,
                        fee_changes: None,
                    });
                }
            }

            if cond.min_seq_age.0 > 0 {
                let last_header = snapshot.get_ledger_header(source_last_modified_seq)?;
                let last_close_time = match last_header {
                    Some(header) => header.scp_value.close_time.0,
                    None => {
                        return Ok(TransactionExecutionResult {
                            success: false,
                            fee_charged: 0,
                            operation_results: vec![],
                            error: Some("Minimum sequence age unavailable".into()),
                            failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                            tx_meta: None,
                            fee_changes: None,
                        });
                    }
                };

                let age = self.close_time.saturating_sub(last_close_time);
                if age < cond.min_seq_age.0 {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        operation_results: vec![],
                        error: Some("Minimum sequence age not met".into()),
                        failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                        tx_meta: None,
                        fee_changes: None,
                    });
                }
            }

            if cond.min_seq_ledger_gap > 0 {
                let gap = self.ledger_seq.saturating_sub(source_last_modified_seq);
                if gap < cond.min_seq_ledger_gap {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        operation_results: vec![],
                        error: Some("Minimum sequence ledger gap not met".into()),
                        failure: Some(ExecutionFailure::BadMinSeqAgeOrGap),
                        tx_meta: None,
                        fee_changes: None,
                    });
                }
            }
        }

        // Validate sequence number
        let expected_seq = source_account.seq_num.0 + 1;
        if frame.sequence_number() != expected_seq {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some(format!(
                    "Bad sequence: expected {}, got {}",
                    expected_seq,
                    frame.sequence_number()
                )),
                failure: Some(ExecutionFailure::BadSequence),
                tx_meta: None,
                fee_changes: None,
            });
        }

        // Basic signature validation (master key only).
        if validation::validate_signatures(&frame, &validation_ctx).is_err() {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Invalid signature".into()),
                failure: Some(ExecutionFailure::InvalidSignature),
                tx_meta: None,
                fee_changes: None,
            });
        }

        let outer_hash = frame
            .hash(&self.network_id)
            .map_err(|e| LedgerError::Internal(format!("tx hash error: {}", e)))?;
        let outer_threshold = threshold_low(&fee_source_account);
        if !has_sufficient_signer_weight(
            &outer_hash,
            frame.signatures(),
            &fee_source_account,
            outer_threshold,
        ) {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Invalid signature".into()),
                failure: Some(ExecutionFailure::InvalidSignature),
                tx_meta: None,
                fee_changes: None,
            });
        }

        if frame.is_fee_bump() {
            let inner_hash = fee_bump_inner_hash(&frame, &self.network_id)?;
            let inner_threshold = threshold_medium(&source_account);
            if !has_sufficient_signer_weight(
                &inner_hash,
                frame.inner_signatures(),
                &source_account,
                inner_threshold,
            ) {
                return Ok(TransactionExecutionResult {
                    success: false,
                    fee_charged: 0,
                    operation_results: vec![],
                    error: Some("Invalid inner signature".into()),
                    failure: Some(ExecutionFailure::InvalidSignature),
                    tx_meta: None,
                    fee_changes: None,
                });
            }
        }

        let required_weight = threshold_medium(&source_account);
        if !frame.is_fee_bump()
            && !has_sufficient_signer_weight(
                &outer_hash,
                frame.signatures(),
                &source_account,
                required_weight,
            )
        {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Invalid signature".into()),
                failure: Some(ExecutionFailure::InvalidSignature),
                tx_meta: None,
                fee_changes: None,
            });
        }

        if let Preconditions::V2(cond) = frame.preconditions() {
            if !cond.extra_signers.is_empty() {
                let extra_hash = if frame.is_fee_bump() {
                    fee_bump_inner_hash(&frame, &self.network_id)?
                } else {
                    outer_hash
                };
                let extra_signatures = if frame.is_fee_bump() {
                    frame.inner_signatures()
                } else {
                    frame.signatures()
                };
                if !has_required_extra_signers(&extra_hash, extra_signatures, &cond.extra_signers) {
                    return Ok(TransactionExecutionResult {
                        success: false,
                        fee_charged: 0,
                        operation_results: vec![],
                        error: Some("Missing extra signer".into()),
                        failure: Some(ExecutionFailure::BadAuthExtra),
                        tx_meta: None,
                        fee_changes: None,
                    });
                }
            }
        }

        let required_fee =
            base_fee as i64 * std::cmp::max(1, frame.operation_count() as i64);
        let inclusion_fee = frame.inclusion_fee();
        let fee = if frame.is_soroban() {
            frame.declared_soroban_resource_fee() + std::cmp::min(inclusion_fee, required_fee)
        } else {
            std::cmp::min(inclusion_fee, required_fee)
        };
        if fee_source_account.balance < fee {
            return Ok(TransactionExecutionResult {
                success: false,
                fee_charged: 0,
                operation_results: vec![],
                error: Some("Insufficient balance for fee".into()),
                failure: Some(ExecutionFailure::InsufficientBalance),
                tx_meta: None,
                fee_changes: None,
            });
        }

        let delta_before_fee = delta_snapshot(&self.state);

        // Deduct fee and increment sequence
        if let Some(acc) = self.state.get_account_mut(&fee_source_id) {
            acc.balance -= fee;
        }
        if let Some(acc) = self.state.get_account_mut(&inner_source_id) {
            acc.seq_num.0 += 1;
            stellar_core_tx::state::update_account_seq_info(acc, self.ledger_seq, self.close_time);
        }

        self.state.flush_modified_entries();
        let delta_after_fee = delta_snapshot(&self.state);
        let (fee_created, fee_updated, fee_deleted) =
            delta_changes_between(self.state.delta(), delta_before_fee, delta_after_fee);
        let fee_changes = build_entry_changes(&fee_created, &fee_updated, &fee_deleted);

        // Commit fee changes so rollback doesn't revert them.
        self.state.commit();

        // Create ledger context for operation execution
        let ledger_context = if let Some(prng_seed) = soroban_prng_seed {
            LedgerContext::with_prng_seed(
                self.ledger_seq,
                self.close_time,
                base_fee,
                self.base_reserve,
                self.protocol_version,
                self.network_id.clone(),
                prng_seed,
            )
        } else {
            LedgerContext::new(
                self.ledger_seq,
                self.close_time,
                base_fee,
                self.base_reserve,
                self.protocol_version,
                self.network_id.clone(),
            )
        };

        let soroban_data = frame.soroban_data();

        // For Soroban transactions, load all footprint entries from the snapshot
        // before executing operations. This ensures contract data, code, and TTLs
        // are available to the Soroban host.
        if let Some(ref data) = soroban_data {
            self.load_soroban_footprint(snapshot, &data.resources.footprint)?;
        }

        self.state.clear_sponsorship_stack();

        // Execute operations
        let mut operation_results = Vec::new();
        let mut op_changes = Vec::with_capacity(frame.operations().len());
        let mut op_events: Vec<Vec<ContractEvent>> = Vec::with_capacity(frame.operations().len());
        let mut diagnostic_events: Vec<DiagnosticEvent> = Vec::new();
        let mut soroban_return_value = None;
        let mut all_success = true;
        let mut failure = None;
        let op_invariant_snapshot = self
            .op_invariants
            .as_ref()
            .map(|runner| runner.snapshot());

        let tx_seq = frame.sequence_number();
        for (op_index, op) in frame.operations().iter().enumerate() {
            let op_delta_before = delta_snapshot(&self.state);

            // Load any accounts needed for this operation
            self.load_operation_accounts(snapshot, op, &inner_source_id)?;

            // Get operation source
            let op_source = op
                .source_account
                .as_ref()
                .map(|m| stellar_core_tx::muxed_to_account_id(m))
                .unwrap_or_else(|| inner_source_id.clone());

            // Execute the operation
            let op_index = u32::try_from(op_index).unwrap_or(u32::MAX);
            let result = self.execute_single_operation(
                op,
                &op_source,
                &inner_source_id,
                tx_seq,
                op_index,
                &ledger_context,
                soroban_data,
            );

            match result {
                Ok(op_exec) => {
                    self.state.flush_modified_entries();
                    let op_result = op_exec.result;
                    // Check if operation succeeded
                    if !is_operation_success(&op_result) {
                        all_success = false;
                        if matches!(op_result, OperationResult::OpNotSupported) {
                            failure = Some(ExecutionFailure::NotSupported);
                        }
                    }
                    operation_results.push(op_result);

                    let op_delta_after = delta_snapshot(&self.state);
                    let (created, updated, deleted) =
                        delta_changes_between(self.state.delta(), op_delta_before, op_delta_after);
                    let op_changes_local = build_entry_changes(&created, &updated, &deleted);

                    if let Some(runner) = self.op_invariants.as_mut() {
                        let op_event_slice = op_exec
                            .soroban_meta
                            .as_ref()
                            .map(|meta| meta.events.as_slice())
                            .unwrap_or(&[]);
                        runner.apply_and_check(&op_changes_local, op_event_slice)?;
                    }

                    if all_success {
                        op_changes.push(op_changes_local);

                        if let Some(meta) = op_exec.soroban_meta {
                            op_events.push(meta.events.clone());
                            diagnostic_events.extend(meta.diagnostic_events.into_iter());
                            soroban_return_value = meta.return_value.or(soroban_return_value);
                        } else {
                            op_events.push(Vec::new());
                        }
                    } else {
                        op_changes.push(empty_entry_changes());
                        op_events.push(Vec::new());
                    }
                }
                Err(e) => {
                    all_success = false;
                    warn!(error = %e, "Operation execution failed");
                    operation_results.push(OperationResult::OpNotSupported);
                    op_changes.push(empty_entry_changes());
                    op_events.push(Vec::new());
                    failure = Some(ExecutionFailure::NotSupported);
                }
            }

        }

        if all_success
            && self.protocol_version >= 14
            && self.state.has_pending_sponsorship()
        {
            all_success = false;
            failure = Some(ExecutionFailure::BadSponsorship);
        }

        if !all_success {
            let tx_hash = frame
                .hash(&self.network_id)
                .map(|hash| hash.to_hex())
                .unwrap_or_else(|_| "unknown".to_string());
            warn!(
                tx_hash = %tx_hash,
                fee_source = ?fee_source_id,
                inner_source = ?inner_source_id,
                results = ?operation_results,
                "Transaction failed; rolling back changes"
            );
            self.state.rollback();
            restore_delta_entries(&mut self.state, &fee_created, &fee_updated, &fee_deleted);
            if let (Some(runner), Some(snapshot)) =
                (self.op_invariants.as_mut(), op_invariant_snapshot)
            {
                runner.restore(snapshot);
            }
            op_changes = vec![empty_entry_changes(); frame.operations().len()];
            op_events = vec![Vec::new(); frame.operations().len()];
            diagnostic_events.clear();
            soroban_return_value = None;
        } else {
            self.state.commit();
        }

        let tx_meta = build_transaction_meta(
            fee_changes.clone(),
            op_changes,
            op_events,
            soroban_return_value,
            diagnostic_events,
        );

        Ok(TransactionExecutionResult {
            success: all_success,
            fee_charged: fee,
            operation_results,
            error: if all_success {
                None
            } else {
                Some("One or more operations failed".into())
            },
            failure: if all_success {
                None
            } else {
                Some(failure.unwrap_or(ExecutionFailure::OperationFailed))
            },
            tx_meta: Some(tx_meta),
            fee_changes: Some(fee_changes),
        })
    }

    /// Load accounts needed for an operation.
    fn load_operation_accounts(
        &mut self,
        snapshot: &SnapshotHandle,
        op: &stellar_xdr::curr::Operation,
        source_id: &AccountId,
    ) -> Result<()> {
        let op_source = op
            .source_account
            .as_ref()
            .map(stellar_core_tx::muxed_to_account_id)
            .unwrap_or_else(|| source_id.clone());

        // Load operation source if different from transaction source
        if let Some(ref muxed) = op.source_account {
            let op_source = stellar_core_tx::muxed_to_account_id(muxed);
            self.load_account(snapshot, &op_source)?;
        }

        // Load destination accounts based on operation type
        match &op.body {
            OperationBody::CreateAccount(op_data) => {
                // Don't load destination - it shouldn't exist
            }
            OperationBody::BeginSponsoringFutureReserves(op_data) => {
                self.load_account(snapshot, &op_data.sponsored_id)?;
            }
            OperationBody::Payment(op_data) => {
                let dest = stellar_core_tx::muxed_to_account_id(&op_data.destination);
                self.load_account(snapshot, &dest)?;
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.asset) {
                    self.load_trustline(snapshot, &op_source, &tl_asset)?;
                    self.load_trustline(snapshot, &dest, &tl_asset)?;
                }
            }
            OperationBody::AccountMerge(dest) => {
                let dest = stellar_core_tx::muxed_to_account_id(dest);
                self.load_account(snapshot, &dest)?;
            }
            OperationBody::CreateClaimableBalance(op_data) => {
                if let Some(tl_asset) = asset_to_trustline_asset(&op_data.asset) {
                    self.load_trustline(snapshot, &op_source, &tl_asset)?;
                }
            }
            _ => {
                // Other operations typically work on source account
            }
        }

        Ok(())
    }

    /// Execute a single operation using the central dispatcher.
    fn execute_single_operation(
        &mut self,
        op: &stellar_xdr::curr::Operation,
        source: &AccountId,
        tx_source: &AccountId,
        tx_seq: i64,
        op_index: u32,
        context: &LedgerContext,
        soroban_data: Option<&stellar_xdr::curr::SorobanTransactionData>,
    ) -> std::result::Result<stellar_core_tx::operations::execute::OperationExecutionResult, TxError>
    {
        // Use the central operation dispatcher which handles all operation types
        stellar_core_tx::operations::execute::execute_operation_with_soroban(
            op,
            source,
            tx_source,
            tx_seq,
            op_index,
            &mut self.state,
            context,
            soroban_data,
            Some(&self.soroban_config),
        )
    }

    /// Apply all state changes to the delta.
    pub fn apply_to_delta(
        &self,
        snapshot: &SnapshotHandle,
        delta: &mut LedgerDelta,
    ) -> Result<()> {
        let state_delta = self.state.delta();

        // Apply created entries
        for entry in state_delta.created_entries() {
            delta.record_create(entry.clone())?;
        }

        // Apply updated entries
        for entry in state_delta.updated_entries() {
            let key = crate::delta::entry_to_key(entry)?;
            if let Some(prev) = snapshot.get_entry(&key)? {
                delta.record_update(prev, entry.clone())?;
            } else {
                delta.record_create(entry.clone())?;
            }
        }

        // Apply deleted entries
        for key in state_delta.deleted_keys() {
            // We need the previous entry for deletion
            if let Some(prev) = snapshot.get_entry(key)? {
                delta.record_delete(prev)?;
            }
        }

        Ok(())
    }

    /// Get total fees collected.
    pub fn total_fees(&self) -> i64 {
        self.state.delta().fee_charged()
    }

    /// Get the updated ID pool after execution.
    pub fn id_pool(&self) -> u64 {
        self.state.id_pool()
    }

    /// Get the state manager.
    pub fn state(&self) -> &LedgerStateManager {
        &self.state
    }

    /// Get mutable state manager.
    pub fn state_mut(&mut self) -> &mut LedgerStateManager {
        &mut self.state
    }
}

fn asset_to_trustline_asset(asset: &stellar_xdr::curr::Asset) -> Option<stellar_xdr::curr::TrustLineAsset> {
    match asset {
        stellar_xdr::curr::Asset::Native => None,
        stellar_xdr::curr::Asset::CreditAlphanum4(a) => {
            Some(stellar_xdr::curr::TrustLineAsset::CreditAlphanum4(a.clone()))
        }
        stellar_xdr::curr::Asset::CreditAlphanum12(a) => {
            Some(stellar_xdr::curr::TrustLineAsset::CreditAlphanum12(a.clone()))
        }
    }
}

#[derive(Clone, Copy)]
struct DeltaSnapshot {
    created: usize,
    updated: usize,
    deleted: usize,
}

fn delta_snapshot(state: &LedgerStateManager) -> DeltaSnapshot {
    let delta = state.delta();
    DeltaSnapshot {
        created: delta.created_entries().len(),
        updated: delta.updated_entries().len(),
        deleted: delta.deleted_keys().len(),
    }
}

fn delta_changes_between(
    delta: &stellar_core_tx::LedgerDelta,
    start: DeltaSnapshot,
    end: DeltaSnapshot,
) -> (Vec<LedgerEntry>, Vec<LedgerEntry>, Vec<LedgerKey>) {
    let created = delta.created_entries()[start.created..end.created].to_vec();
    let updated = delta.updated_entries()[start.updated..end.updated].to_vec();
    let deleted = delta.deleted_keys()[start.deleted..end.deleted].to_vec();
    (created, updated, deleted)
}

fn restore_delta_entries(
    state: &mut LedgerStateManager,
    created: &[LedgerEntry],
    updated: &[LedgerEntry],
    deleted: &[LedgerKey],
) {
    let delta = state.delta_mut();
    for entry in created {
        delta.record_create(entry.clone());
    }
    for entry in updated {
        delta.record_update(entry.clone());
    }
    for key in deleted {
        delta.record_delete(key.clone());
    }
}

pub struct OperationInvariantRunner {
    manager: InvariantManager,
    entries: HashMap<Vec<u8>, LedgerEntry>,
    header: LedgerHeader,
}

impl OperationInvariantRunner {
    pub fn new(entries: Vec<LedgerEntry>, header: LedgerHeader, network_id: NetworkId) -> Result<Self> {
        let mut manager = InvariantManager::new();
        manager.add(LiabilitiesMatchOffers);
        manager.add(OrderBookIsNotCrossed);
        manager.add(ConstantProductInvariant);
        manager.add(EventsAreConsistentWithEntryDiffs::new(network_id.0));

        let mut map = HashMap::new();
        for entry in entries {
            let key = crate::delta::entry_to_key(&entry)?;
            let key_bytes = key.to_xdr(Limits::none())?;
            map.insert(key_bytes, entry);
        }

        Ok(Self {
            manager,
            entries: map,
            header,
        })
    }

    fn snapshot(&self) -> HashMap<Vec<u8>, LedgerEntry> {
        self.entries.clone()
    }

    fn restore(&mut self, snapshot: HashMap<Vec<u8>, LedgerEntry>) {
        self.entries = snapshot;
    }

    fn apply_and_check(&mut self, changes: &LedgerEntryChanges, op_events: &[ContractEvent]) -> Result<()> {
        let mut invariant_changes = Vec::new();
        for change in changes.0.iter() {
            match change {
                LedgerEntryChange::Created(entry)
                | LedgerEntryChange::Updated(entry)
                | LedgerEntryChange::State(entry)
                | LedgerEntryChange::Restored(entry) => {
                    let key = crate::delta::entry_to_key(entry)?;
                    let key_bytes = key.to_xdr(Limits::none())?;
                    let previous = self.entries.get(&key_bytes).cloned();
                    self.entries.insert(key_bytes, entry.clone());
                    match previous {
                        Some(prev) => invariant_changes.push(InvariantLedgerEntryChange::Updated {
                            previous: prev,
                            current: entry.clone(),
                        }),
                        None => invariant_changes.push(InvariantLedgerEntryChange::Created {
                            current: entry.clone(),
                        }),
                    }
                }
                LedgerEntryChange::Removed(key) => {
                    let key_bytes = key.to_xdr(Limits::none())?;
                    if let Some(previous) = self.entries.remove(&key_bytes) {
                        invariant_changes.push(InvariantLedgerEntryChange::Deleted { previous });
                    }
                }
            }
        }

        if invariant_changes.is_empty() {
            return Ok(());
        }

        let entries: Vec<LedgerEntry> = self.entries.values().cloned().collect();
        let ctx = InvariantContext {
            prev_header: &self.header,
            curr_header: &self.header,
            bucket_list_hash: Hash256::ZERO,
            fee_pool_delta: 0,
            total_coins_delta: 0,
            changes: &invariant_changes,
            full_entries: Some(&entries),
            op_events: Some(op_events),
        };
        self.manager.check_all(&ctx)?;
        Ok(())
    }
}

fn build_entry_changes(
    created: &[LedgerEntry],
    updated: &[LedgerEntry],
    deleted: &[LedgerKey],
) -> LedgerEntryChanges {
    let mut changes: Vec<(Vec<u8>, LedgerEntryChange)> = Vec::new();

    for entry in created {
        let key_bytes = crate::delta::entry_to_key(entry)
            .map(|key| key.to_xdr(Limits::none()).unwrap_or_default())
            .unwrap_or_else(|_| entry.to_xdr(Limits::none()).unwrap_or_default());
        changes.push((key_bytes, LedgerEntryChange::Created(entry.clone())));
    }

    for entry in updated {
        let key_bytes = crate::delta::entry_to_key(entry)
            .map(|key| key.to_xdr(Limits::none()).unwrap_or_default())
            .unwrap_or_else(|_| entry.to_xdr(Limits::none()).unwrap_or_default());
        changes.push((key_bytes, LedgerEntryChange::Updated(entry.clone())));
    }

    for key in deleted {
        let key_bytes = key.to_xdr(Limits::none()).unwrap_or_default();
        changes.push((key_bytes, LedgerEntryChange::Removed(key.clone())));
    }

    changes.sort_by(|a, b| a.0.cmp(&b.0));
    let ordered = changes.into_iter().map(|(_, change)| change);
    LedgerEntryChanges(ordered.collect::<Vec<_>>().try_into().unwrap_or_default())
}

fn empty_entry_changes() -> LedgerEntryChanges {
    LedgerEntryChanges(VecM::default())
}

fn build_transaction_meta(
    tx_changes_before: LedgerEntryChanges,
    op_changes: Vec<LedgerEntryChanges>,
    op_events: Vec<Vec<ContractEvent>>,
    soroban_return_value: Option<stellar_xdr::curr::ScVal>,
    diagnostic_events: Vec<DiagnosticEvent>,
) -> TransactionMeta {
    let operations: Vec<OperationMetaV2> = op_changes
        .into_iter()
        .zip(op_events.into_iter())
        .map(|(changes, events)| OperationMetaV2 {
            ext: ExtensionPoint::V0,
            changes,
            events: events.try_into().unwrap_or_default(),
        })
        .collect();

    let tx_events: Vec<TransactionEvent> = operations
        .iter()
        .flat_map(|op_meta| op_meta.events.iter().cloned())
        .map(|event| TransactionEvent {
            stage: TransactionEventStage::AfterTx,
            event,
        })
        .collect();

    let has_soroban = soroban_return_value.is_some() || !diagnostic_events.is_empty();
    let soroban_meta = if has_soroban {
        Some(SorobanTransactionMetaV2 {
            ext: SorobanTransactionMetaExt::V0,
            return_value: soroban_return_value,
        })
    } else {
        None
    };

    TransactionMeta::V4(TransactionMetaV4 {
        ext: ExtensionPoint::V0,
        tx_changes_before,
        operations: operations.try_into().unwrap_or_default(),
        tx_changes_after: empty_entry_changes(),
        soroban_meta,
        events: tx_events.try_into().unwrap_or_default(),
        diagnostic_events: diagnostic_events.try_into().unwrap_or_default(),
    })
}

fn empty_transaction_meta(op_count: usize) -> TransactionMeta {
    let mut op_changes = Vec::with_capacity(op_count);
    let mut op_events = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        op_changes.push(empty_entry_changes());
        op_events.push(Vec::new());
    }
    build_transaction_meta(empty_entry_changes(), op_changes, op_events, None, Vec::new())
}

fn map_failure_to_result(
    failure: &ExecutionFailure,
) -> TransactionResultResult {
    match failure {
        ExecutionFailure::Malformed => TransactionResultResult::TxMalformed,
        ExecutionFailure::MissingOperation => TransactionResultResult::TxMissingOperation,
        ExecutionFailure::InvalidSignature => TransactionResultResult::TxBadAuth,
        ExecutionFailure::BadAuthExtra => TransactionResultResult::TxBadAuthExtra,
        ExecutionFailure::BadMinSeqAgeOrGap => TransactionResultResult::TxBadMinSeqAgeOrGap,
        ExecutionFailure::TooEarly => TransactionResultResult::TxTooEarly,
        ExecutionFailure::TooLate => TransactionResultResult::TxTooLate,
        ExecutionFailure::BadSequence => TransactionResultResult::TxBadSeq,
        ExecutionFailure::InsufficientFee => TransactionResultResult::TxInsufficientFee,
        ExecutionFailure::InsufficientBalance => TransactionResultResult::TxInsufficientBalance,
        ExecutionFailure::NoAccount => TransactionResultResult::TxNoAccount,
        ExecutionFailure::NotSupported => TransactionResultResult::TxNotSupported,
        ExecutionFailure::BadSponsorship => TransactionResultResult::TxBadSponsorship,
        ExecutionFailure::OperationFailed => TransactionResultResult::TxFailed(Vec::new().try_into().unwrap()),
    }
}

fn map_failure_to_inner_result(
    failure: &ExecutionFailure,
    op_results: &[OperationResult],
) -> InnerTransactionResultResult {
    match failure {
        ExecutionFailure::Malformed => InnerTransactionResultResult::TxMalformed,
        ExecutionFailure::MissingOperation => InnerTransactionResultResult::TxMissingOperation,
        ExecutionFailure::InvalidSignature => InnerTransactionResultResult::TxBadAuth,
        ExecutionFailure::BadAuthExtra => InnerTransactionResultResult::TxBadAuthExtra,
        ExecutionFailure::BadMinSeqAgeOrGap => InnerTransactionResultResult::TxBadMinSeqAgeOrGap,
        ExecutionFailure::TooEarly => InnerTransactionResultResult::TxTooEarly,
        ExecutionFailure::TooLate => InnerTransactionResultResult::TxTooLate,
        ExecutionFailure::BadSequence => InnerTransactionResultResult::TxBadSeq,
        ExecutionFailure::InsufficientFee => InnerTransactionResultResult::TxInsufficientFee,
        ExecutionFailure::InsufficientBalance => InnerTransactionResultResult::TxInsufficientBalance,
        ExecutionFailure::NoAccount => InnerTransactionResultResult::TxNoAccount,
        ExecutionFailure::NotSupported => InnerTransactionResultResult::TxNotSupported,
        ExecutionFailure::BadSponsorship => InnerTransactionResultResult::TxBadSponsorship,
        ExecutionFailure::OperationFailed => {
            InnerTransactionResultResult::TxFailed(op_results.to_vec().try_into().unwrap_or_default())
        }
    }
}

pub fn build_tx_result_pair(
    frame: &TransactionFrame,
    network_id: &NetworkId,
    exec: &TransactionExecutionResult,
) -> Result<TransactionResultPair> {
    let tx_hash = frame
        .hash(network_id)
        .map_err(|e| LedgerError::Internal(format!("tx hash error: {}", e)))?;
    let op_results: Vec<OperationResult> = exec.operation_results.clone();

    let result = if frame.is_fee_bump() {
        let inner_hash = fee_bump_inner_hash(frame, network_id)?;
        let inner_result = if exec.success {
            InnerTransactionResultResult::TxSuccess(op_results.clone().try_into().unwrap_or_default())
        } else if let Some(failure) = &exec.failure {
            map_failure_to_inner_result(failure, &op_results)
        } else {
            InnerTransactionResultResult::TxFailed(op_results.clone().try_into().unwrap_or_default())
        };

        let inner_pair = InnerTransactionResultPair {
            transaction_hash: stellar_xdr::curr::Hash(inner_hash.0),
            result: InnerTransactionResult {
                fee_charged: frame.inner_fee() as i64,
                result: inner_result,
                ext: InnerTransactionResultExt::V0,
            },
        };

        let result = if exec.success {
            TransactionResultResult::TxFeeBumpInnerSuccess(inner_pair)
        } else {
            TransactionResultResult::TxFeeBumpInnerFailed(inner_pair)
        };

        TransactionResult {
            fee_charged: exec.fee_charged,
            result,
            ext: TransactionResultExt::V0,
        }
    } else if exec.success {
        TransactionResult {
            fee_charged: exec.fee_charged,
            result: TransactionResultResult::TxSuccess(
                op_results.try_into().unwrap_or_default(),
            ),
            ext: TransactionResultExt::V0,
        }
    } else if let Some(failure) = &exec.failure {
        let result = match failure {
            ExecutionFailure::OperationFailed => {
                TransactionResultResult::TxFailed(op_results.try_into().unwrap_or_default())
            }
            _ => map_failure_to_result(failure),
        };
        TransactionResult {
            fee_charged: exec.fee_charged,
            result,
            ext: TransactionResultExt::V0,
        }
    } else {
        TransactionResult {
            fee_charged: exec.fee_charged,
            result: TransactionResultResult::TxFailed(op_results.try_into().unwrap_or_default()),
            ext: TransactionResultExt::V0,
        }
    };

    Ok(TransactionResultPair {
        transaction_hash: stellar_xdr::curr::Hash(tx_hash.0),
        result,
    })
}

/// Convert AccountId to key bytes.
fn account_id_to_key(account_id: &AccountId) -> [u8; 32] {
    match &account_id.0 {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
    }
}

/// Check if an operation result indicates success.
fn is_operation_success(result: &OperationResult) -> bool {
    match result {
        OperationResult::OpInner(inner) => {
            use stellar_xdr::curr::OperationResultTr;
            use stellar_xdr::curr::*;
            match inner {
                OperationResultTr::CreateAccount(r) => {
                    matches!(r, CreateAccountResult::Success)
                }
                OperationResultTr::Payment(r) => {
                    matches!(r, PaymentResult::Success)
                }
                OperationResultTr::PathPaymentStrictReceive(r) => {
                    matches!(r, PathPaymentStrictReceiveResult::Success(_))
                }
                OperationResultTr::ManageSellOffer(r) => {
                    matches!(r, ManageSellOfferResult::Success(_))
                }
                OperationResultTr::CreatePassiveSellOffer(r) => {
                    matches!(r, ManageSellOfferResult::Success(_))
                }
                OperationResultTr::SetOptions(r) => {
                    matches!(r, SetOptionsResult::Success)
                }
                OperationResultTr::ChangeTrust(r) => {
                    matches!(r, ChangeTrustResult::Success)
                }
                OperationResultTr::AllowTrust(r) => {
                    matches!(r, AllowTrustResult::Success)
                }
                OperationResultTr::AccountMerge(r) => {
                    matches!(r, AccountMergeResult::Success(_))
                }
                OperationResultTr::Inflation(r) => {
                    matches!(r, InflationResult::Success(_))
                }
                OperationResultTr::ManageData(r) => {
                    matches!(r, ManageDataResult::Success)
                }
                OperationResultTr::BumpSequence(r) => {
                    matches!(r, BumpSequenceResult::Success)
                }
                OperationResultTr::ManageBuyOffer(r) => {
                    matches!(r, ManageBuyOfferResult::Success(_))
                }
                OperationResultTr::PathPaymentStrictSend(r) => {
                    matches!(r, PathPaymentStrictSendResult::Success(_))
                }
                OperationResultTr::CreateClaimableBalance(r) => {
                    matches!(r, CreateClaimableBalanceResult::Success(_))
                }
                OperationResultTr::ClaimClaimableBalance(r) => {
                    matches!(r, ClaimClaimableBalanceResult::Success)
                }
                OperationResultTr::BeginSponsoringFutureReserves(r) => {
                    matches!(r, BeginSponsoringFutureReservesResult::Success)
                }
                OperationResultTr::EndSponsoringFutureReserves(r) => {
                    matches!(r, EndSponsoringFutureReservesResult::Success)
                }
                OperationResultTr::RevokeSponsorship(r) => {
                    matches!(r, RevokeSponsorshipResult::Success)
                }
                OperationResultTr::Clawback(r) => {
                    matches!(r, ClawbackResult::Success)
                }
                OperationResultTr::ClawbackClaimableBalance(r) => {
                    matches!(r, ClawbackClaimableBalanceResult::Success)
                }
                OperationResultTr::SetTrustLineFlags(r) => {
                    matches!(r, SetTrustLineFlagsResult::Success)
                }
                OperationResultTr::LiquidityPoolDeposit(r) => {
                    matches!(r, LiquidityPoolDepositResult::Success)
                }
                OperationResultTr::LiquidityPoolWithdraw(r) => {
                    matches!(r, LiquidityPoolWithdrawResult::Success)
                }
                OperationResultTr::InvokeHostFunction(r) => {
                    matches!(r, InvokeHostFunctionResult::Success(_))
                }
                OperationResultTr::ExtendFootprintTtl(r) => {
                    matches!(r, ExtendFootprintTtlResult::Success)
                }
                OperationResultTr::RestoreFootprint(r) => {
                    matches!(r, RestoreFootprintResult::Success)
                }
            }
        }
        OperationResult::OpNotSupported => false, // Unsupported operations fail
        _ => false,
    }
}

fn has_sufficient_signer_weight(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    account: &AccountEntry,
    required_weight: u32,
) -> bool {
    let mut total = 0u32;
    let mut counted: HashSet<Hash256> = HashSet::new();

    // Master key signer.
    if let Ok(pk) = stellar_core_crypto::PublicKey::try_from(&account.account_id.0) {
        let master_weight = account.thresholds.0[0] as u32;
        if master_weight > 0 {
            if has_ed25519_signature(tx_hash, signatures, &pk) {
                let id = signer_key_id(&SignerKey::Ed25519(stellar_xdr::curr::Uint256(*pk.as_bytes())));
                if counted.insert(id) {
                    total = total.saturating_add(master_weight);
                }
            }
        }
    }

    for signer in account.signers.iter() {
        if signer.weight == 0 {
            continue;
        }
        let key = &signer.key;
        let id = signer_key_id(key);

        if counted.contains(&id) {
            continue;
        }

        match key {
            SignerKey::Ed25519(key) => {
                if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(&key.0) {
                    if has_ed25519_signature(tx_hash, signatures, &pk) {
                        if counted.insert(id) {
                            total = total.saturating_add(signer.weight as u32);
                        }
                    }
                }
            }
            SignerKey::PreAuthTx(key) => {
                if key.0 == tx_hash.0 {
                    if counted.insert(id) {
                        total = total.saturating_add(signer.weight as u32);
                    }
                }
            }
            SignerKey::HashX(key) => {
                if has_hashx_signature(signatures, key) {
                    if counted.insert(id) {
                        total = total.saturating_add(signer.weight as u32);
                    }
                }
            }
            SignerKey::Ed25519SignedPayload(payload) => {
                if has_signed_payload_signature(tx_hash, signatures, payload) {
                    if counted.insert(id) {
                        total = total.saturating_add(signer.weight as u32);
                    }
                }
            }
        }

        if total >= required_weight && total > 0 {
            return true;
        }
    }

    total >= required_weight && total > 0
}

fn has_required_extra_signers(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    extra_signers: &[SignerKey],
) -> bool {
    extra_signers.iter().all(|signer| match signer {
        SignerKey::Ed25519(key) => {
            if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(&key.0) {
                has_ed25519_signature(tx_hash, signatures, &pk)
            } else {
                false
            }
        }
        SignerKey::PreAuthTx(key) => key.0 == tx_hash.0,
        SignerKey::HashX(key) => has_hashx_signature(signatures, key),
        SignerKey::Ed25519SignedPayload(payload) => {
            has_signed_payload_signature(tx_hash, signatures, payload)
        }
    })
}

fn fee_bump_inner_hash(frame: &TransactionFrame, network_id: &NetworkId) -> Result<Hash256> {
    match frame.envelope() {
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                let inner_env = TransactionEnvelope::Tx(inner.clone());
                let inner_frame = TransactionFrame::with_network(inner_env, *network_id);
                inner_frame
                    .hash(network_id)
                    .map_err(|e| LedgerError::Internal(format!("inner tx hash error: {}", e)))
            }
        },
        _ => frame
            .hash(network_id)
            .map_err(|e| LedgerError::Internal(format!("tx hash error: {}", e))),
    }
}

fn threshold_low(account: &AccountEntry) -> u32 {
    account.thresholds.0[1] as u32
}

fn threshold_medium(account: &AccountEntry) -> u32 {
    account.thresholds.0[2] as u32
}

fn signer_key_id(key: &SignerKey) -> Hash256 {
    let bytes = key
        .to_xdr(stellar_xdr::curr::Limits::none())
        .unwrap_or_default();
    Hash256::hash(&bytes)
}

fn has_ed25519_signature(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    pk: &stellar_core_crypto::PublicKey,
) -> bool {
    signatures
        .iter()
        .any(|sig| validation::verify_signature_with_key(tx_hash, sig, pk))
}

fn has_hashx_signature(
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    key: &stellar_xdr::curr::Uint256,
) -> bool {
    signatures.iter().any(|sig| {
        if sig.signature.0.len() != 32 {
            return false;
        }
        let expected_hint = [key.0[28], key.0[29], key.0[30], key.0[31]];
        if sig.hint.0 != expected_hint {
            return false;
        }
        let hash = Hash256::hash(&sig.signature.0);
        hash.0 == key.0
    })
}

fn has_signed_payload_signature(
    tx_hash: &Hash256,
    signatures: &[stellar_xdr::curr::DecoratedSignature],
    payload: &stellar_xdr::curr::SignerKeyEd25519SignedPayload,
) -> bool {
    let pk = match stellar_core_crypto::PublicKey::from_bytes(&payload.ed25519.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let mut data = Vec::with_capacity(32 + payload.payload.len());
    data.extend_from_slice(&tx_hash.0);
    data.extend_from_slice(&payload.payload);
    let payload_hash = Hash256::hash(&data);

    signatures
        .iter()
        .any(|sig| validation::verify_signature_with_key(&payload_hash, sig, &pk))
}

/// Compute subSha256(baseSeed, index) as used by C++ stellar-core for PRNG seeds.
///
/// This computes SHA256(baseSeed || index) where index is encoded as 4 big-endian bytes
/// (matching C++ network byte order used in XDR).
fn sub_sha256(base_seed: &[u8; 32], index: u32) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(base_seed);
    hasher.update(&index.to_be_bytes()); // 4 bytes big-endian (XDR byte order)
    hasher.finalize().into()
}

/// Execute a full transaction set.
///
/// # Arguments
///
/// * `soroban_base_prng_seed` - The transaction set hash used as base seed for Soroban PRNG.
///   Each transaction gets its own seed computed as subSha256(baseSeed, txIndex).
pub fn execute_transaction_set(
    snapshot: &SnapshotHandle,
    transactions: &[(TransactionEnvelope, Option<u32>)],
    ledger_seq: u32,
    close_time: u64,
    base_fee: u32,
    base_reserve: u32,
    protocol_version: u32,
    network_id: NetworkId,
    delta: &mut LedgerDelta,
    soroban_config: SorobanConfig,
    soroban_base_prng_seed: [u8; 32],
    op_invariants: Option<OperationInvariantRunner>,
) -> Result<(
    Vec<TransactionExecutionResult>,
    Vec<TransactionResultPair>,
    Vec<TransactionResultMetaV1>,
    u64,
)> {
    let id_pool = snapshot.header().id_pool;
    let mut executor = TransactionExecutor::new(
        ledger_seq,
        close_time,
        base_fee,
        base_reserve,
        protocol_version,
        network_id,
        id_pool,
        soroban_config,
        op_invariants,
    );

    let mut results = Vec::with_capacity(transactions.len());
    let mut tx_results = Vec::with_capacity(transactions.len());
    let mut tx_result_metas = Vec::with_capacity(transactions.len());

    for (tx_index, (tx, tx_base_fee)) in transactions.iter().enumerate() {
        let tx_fee = tx_base_fee.unwrap_or(base_fee);
        // Compute per-transaction PRNG seed: subSha256(basePrngSeed, txIndex)
        let tx_prng_seed = sub_sha256(&soroban_base_prng_seed, tx_index as u32);
        let result = executor.execute_transaction(snapshot, tx, tx_fee, Some(tx_prng_seed))?;
        let frame = TransactionFrame::with_network(tx.clone(), executor.network_id.clone());
        let tx_result = build_tx_result_pair(&frame, &executor.network_id, &result)?;
        let tx_meta = result
            .tx_meta
            .clone()
            .unwrap_or_else(|| empty_transaction_meta(frame.operations().len()));
        let fee_changes = result
            .fee_changes
            .clone()
            .unwrap_or_else(empty_entry_changes);
        let tx_result_meta = TransactionResultMetaV1 {
            ext: ExtensionPoint::V0,
            result: tx_result.clone(),
            fee_processing: fee_changes,
            tx_apply_processing: tx_meta,
            post_tx_apply_fee_processing: empty_entry_changes(),
        };

        info!(
            success = result.success,
            fee = result.fee_charged,
            ops = result.operation_results.len(),
            "Executed transaction"
        );

        results.push(result);
        tx_results.push(tx_result);
        tx_result_metas.push(tx_result_meta);
    }

    // Apply all changes to the delta
    executor.apply_to_delta(snapshot, delta)?;

    // Add fees to fee pool
    let total_fees = executor.total_fees();
    delta.record_fee_pool_delta(total_fees);

    Ok((results, tx_results, tx_result_metas, executor.id_pool()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        AccountId, Asset, AssetCode4, AlphaNum4, LedgerEntry, LedgerEntryData, LedgerEntryExt,
        OfferEntry, OfferEntryExt, Price, PublicKey, Uint256, VecM, LedgerEntryChange,
    };

    #[test]
    fn test_transaction_executor_creation() {
        let executor = TransactionExecutor::new(
            100,
            1234567890,
            100,
            5_000_000,
            21,
            NetworkId::testnet(),
            0,
            SorobanConfig::default(),
            None,
        );

        assert_eq!(executor.ledger_seq, 100);
        assert_eq!(executor.close_time, 1234567890);
    }

    fn make_account_id(byte: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])))
    }

    fn make_asset(code: &[u8; 4], issuer: u8) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*code),
            issuer: make_account_id(issuer),
        })
    }

    fn make_offer(
        offer_id: i64,
        selling: Asset,
        buying: Asset,
        price: Price,
        flags: u32,
    ) -> LedgerEntry {
        LedgerEntry {
            last_modified_ledger_seq: 1,
            data: LedgerEntryData::Offer(OfferEntry {
                seller_id: make_account_id(9),
                offer_id,
                selling,
                buying,
                amount: 100,
                price,
                flags,
                ext: OfferEntryExt::V0,
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    #[test]
    fn test_operation_invariant_runner_detects_crossed_order_book() {
        let asset_a = make_asset(b"ABCD", 1);
        let asset_b = make_asset(b"WXYZ", 2);

        let ask = make_offer(1, asset_a.clone(), asset_b.clone(), Price { n: 1, d: 1 }, 0);
        let bid = make_offer(2, asset_b.clone(), asset_a.clone(), Price { n: 1, d: 1 }, 0);

        let runner = OperationInvariantRunner::new(
            vec![ask],
            LedgerHeader::default(),
            NetworkId::testnet(),
        )
        .unwrap();
        let mut runner = runner;

        let changes = LedgerEntryChanges(
            vec![LedgerEntryChange::Created(bid)]
                .try_into()
                .unwrap_or_default(),
        );

        assert!(runner.apply_and_check(&changes, &[]).is_err());
    }
}
