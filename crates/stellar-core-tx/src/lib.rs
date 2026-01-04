//! Transaction processing for rs-stellar-core.
//!
//! This crate handles transaction validation and execution, including:
//!
//! - Transaction validation (signatures, fees, sequence numbers)
//! - Operation execution (all Stellar operation types)
//! - Soroban smart contract execution
//! - Transaction result generation
//!
//! ## Overview
//!
//! For catchup/sync mode, the main workflow is:
//!
//! 1. Parse transactions from history archives
//! 2. Create `TransactionFrame` wrappers for each transaction
//! 3. Apply the known results using `apply_from_history`
//! 4. State changes are recorded in `LedgerDelta`
//!
//! ## Classic Operations
//!
//! - CreateAccount, Payment, PathPayment
//! - ManageSellOffer, ManageBuyOffer, CreatePassiveSellOffer
//! - SetOptions, ChangeTrust, AllowTrust
//! - AccountMerge, Inflation, ManageData
//! - BumpSequence, CreateClaimableBalance, ClaimClaimableBalance
//! - BeginSponsoringFutureReserves, EndSponsoringFutureReserves
//! - RevokeSponsorship, Clawback, SetTrustLineFlags
//! - LiquidityPoolDeposit, LiquidityPoolWithdraw
//!
//! ## Soroban Operations
//!
//! - InvokeHostFunction: Smart contract execution
//! - ExtendFootprintTtl: Extend state TTL
//! - RestoreFootprint: Restore archived state
//!
//! ## Example
//!
//! ```ignore
//! use stellar_core_tx::{TransactionFrame, apply_from_history, LedgerDelta};
//! use stellar_xdr::curr::{TransactionEnvelope, TransactionResult, TransactionMeta};
//!
//! // Parse transaction from archive
//! let envelope: TransactionEnvelope = /* from archive */;
//! let result: TransactionResult = /* from archive */;
//! let meta: TransactionMeta = /* from archive */;
//!
//! // Create frame
//! let frame = TransactionFrame::new(envelope);
//!
//! // Apply from history
//! let mut delta = LedgerDelta::new(ledger_seq);
//! let apply_result = apply_from_history(&frame, &result, &meta, &mut delta)?;
//!
//! // Delta now contains all state changes
//! for entry in delta.created_entries() {
//!     // Process created entries
//! }
//! ```

mod apply;
mod error;
mod events;
mod frame;
pub mod operations;
mod result;
pub mod soroban;
pub mod state;
pub mod validation;

// Re-export error types
pub use error::TxError;
pub use events::{
    make_account_address, make_claimable_balance_address, make_muxed_account_address,
    ClassicEventConfig, OpEventManager, TxEventManager,
};

// Re-export frame types
pub use frame::{muxed_to_account_id, muxed_to_ed25519, TransactionFrame};

// Re-export apply types and functions
pub use apply::{
    apply_fee_only, apply_from_history, apply_transaction_set_from_history,
    account_id_to_key, entry_to_key, ApplyContext, AssetKey, LedgerDelta,
};

// Re-export result types
pub use result::{
    OpResultCode, OpResultWrapper, TxApplyResult, TxResultCode, TxResultWrapper,
    TxSetResultSummary,
};

// Re-export validation types and functions
pub use validation::{
    validate_basic, validate_fee, validate_full, validate_ledger_bounds, validate_sequence,
    validate_signatures, validate_structure, validate_time_bounds, verify_signature_with_key,
    LedgerContext, ValidationError,
};

// Re-export operation types
pub use operations::{
    get_operation_source, validate_operation, OperationType, OperationValidationError,
};

// Re-export state types
pub use state::{LedgerReader, LedgerStateManager};

/// Result type for transaction operations.
pub type Result<T> = std::result::Result<T, TxError>;

/// Transaction validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Transaction is valid and can be applied.
    Valid,
    /// Transaction has invalid signature(s).
    InvalidSignature,
    /// Transaction fee is too low.
    InsufficientFee,
    /// Source account sequence number is wrong.
    BadSequence,
    /// Source account doesn't exist.
    NoAccount,
    /// Source account has insufficient balance.
    InsufficientBalance,
    /// Transaction has expired (time bounds).
    TooLate,
    /// Transaction is not yet valid (time bounds).
    TooEarly,
    /// Minimum sequence age or ledger gap not met.
    BadMinSeqAgeOrGap,
    /// Extra signer requirements not met.
    BadAuthExtra,
    /// Other validation error.
    Invalid,
}

impl From<ValidationError> for ValidationResult {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::InvalidStructure(_) => ValidationResult::Invalid,
            ValidationError::InvalidSignature => ValidationResult::InvalidSignature,
            ValidationError::MissingSignatures => ValidationResult::InvalidSignature,
            ValidationError::BadSequence { .. } => ValidationResult::BadSequence,
            ValidationError::InsufficientFee { .. } => ValidationResult::InsufficientFee,
            ValidationError::SourceAccountNotFound => ValidationResult::NoAccount,
            ValidationError::InsufficientBalance => ValidationResult::InsufficientBalance,
            ValidationError::TooLate { .. } => ValidationResult::TooLate,
            ValidationError::TooEarly { .. } => ValidationResult::TooEarly,
            ValidationError::BadLedgerBounds { min, max, current } => {
                if max > 0 && current > max {
                    ValidationResult::TooLate
                } else if min > 0 && current < min {
                    ValidationResult::TooEarly
                } else {
                    ValidationResult::Invalid
                }
            }
            ValidationError::BadMinAccountSequence => ValidationResult::BadSequence,
            ValidationError::BadMinAccountSequenceAge => ValidationResult::BadMinSeqAgeOrGap,
            ValidationError::BadMinAccountSequenceLedgerGap => ValidationResult::BadMinSeqAgeOrGap,
            ValidationError::ExtraSignersNotMet => ValidationResult::BadAuthExtra,
        }
    }
}

/// Validates a transaction before application.
pub struct TransactionValidator {
    /// Network context for validation.
    context: LedgerContext,
}

impl TransactionValidator {
    /// Create a new validator with the given ledger context.
    pub fn new(context: LedgerContext) -> Self {
        Self { context }
    }

    /// Create a validator for testnet.
    pub fn testnet(sequence: u32, close_time: u64) -> Self {
        Self {
            context: LedgerContext::testnet(sequence, close_time),
        }
    }

    /// Create a validator for mainnet.
    pub fn mainnet(sequence: u32, close_time: u64) -> Self {
        Self {
            context: LedgerContext::mainnet(sequence, close_time),
        }
    }

    /// Validate a transaction envelope (basic checks only).
    pub fn validate(&self, tx: &stellar_xdr::curr::TransactionEnvelope) -> ValidationResult {
        let frame = TransactionFrame::new(tx.clone());

        match validate_basic(&frame, &self.context) {
            Ok(()) => ValidationResult::Valid,
            Err(errors) => {
                // Return the first error
                if let Some(err) = errors.into_iter().next() {
                    err.into()
                } else {
                    ValidationResult::Invalid
                }
            }
        }
    }

    /// Full validation with account data.
    pub fn validate_with_account(
        &self,
        tx: &stellar_xdr::curr::TransactionEnvelope,
        source_account: &stellar_xdr::curr::AccountEntry,
    ) -> ValidationResult {
        let frame = TransactionFrame::new(tx.clone());

        match validate_full(&frame, &self.context, source_account) {
            Ok(()) => ValidationResult::Valid,
            Err(errors) => {
                if let Some(err) = errors.into_iter().next() {
                    err.into()
                } else {
                    ValidationResult::Invalid
                }
            }
        }
    }

    /// Check if all required signatures are present.
    pub fn check_signatures(
        &self,
        tx: &stellar_xdr::curr::TransactionEnvelope,
    ) -> bool {
        let frame = TransactionFrame::new(tx.clone());
        validate_signatures(&frame, &self.context).is_ok()
    }
}

/// Executes transactions and produces results.
pub struct TransactionExecutor {
    /// Context for execution.
    #[allow(dead_code)]
    context: ApplyContext,
}

impl TransactionExecutor {
    /// Create a new executor with the given context.
    pub fn new(context: ApplyContext) -> Self {
        Self { context }
    }

    /// Execute a transaction and return the result.
    ///
    /// Note: For full live execution, use `execute_with_state` which provides
    /// a state reader. This method returns an error indicating state is required.
    pub fn execute(
        &self,
        _tx: &stellar_xdr::curr::TransactionEnvelope,
        _delta: &mut LedgerDelta,
    ) -> Result<TxApplyResult> {
        // Full execution requires a state reader - use execute_with_state for live execution
        // or apply_from_history for catchup mode
        Err(TxError::OperationFailed("use execute_with_state or apply_from_history".into()))
    }

    /// Apply a transaction from history (for catchup).
    pub fn apply_historical(
        &self,
        tx: &stellar_xdr::curr::TransactionEnvelope,
        result: &stellar_xdr::curr::TransactionResult,
        meta: &stellar_xdr::curr::TransactionMeta,
        delta: &mut LedgerDelta,
    ) -> Result<TxApplyResult> {
        let frame = TransactionFrame::new(tx.clone());
        apply_from_history(&frame, result, meta, delta)
    }
}

/// Result of executing a transaction (legacy compatibility).
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// The fee charged.
    pub fee_charged: i64,
    /// Result of each operation.
    pub operation_results: Vec<OperationResult>,
    /// Whether the transaction succeeded.
    pub success: bool,
}

impl From<TxApplyResult> for TransactionResult {
    fn from(result: TxApplyResult) -> Self {
        Self {
            fee_charged: result.fee_charged,
            operation_results: result
                .result
                .operation_results()
                .map(|ops| {
                    ops.into_iter()
                        .map(|op| {
                            if op.is_success() {
                                OperationResult::Success
                            } else {
                                OperationResult::Failed(OperationError::OpFailed)
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
            success: result.success,
        }
    }
}

/// Result of executing an operation.
#[derive(Debug, Clone)]
pub enum OperationResult {
    /// Operation succeeded.
    Success,
    /// Operation failed with a specific error.
    Failed(OperationError),
}

/// Operation-specific error types.
#[derive(Debug, Clone)]
pub enum OperationError {
    /// Generic operation failure.
    OpFailed,
    /// Account doesn't exist.
    NoAccount,
    /// Insufficient balance.
    Underfunded,
    /// Line is full (trustline/offer limit).
    LineFull,
    /// Asset is not authorized.
    NotAuthorized,
    /// Other operation-specific error.
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use crate::operations::OperationType; // Re-import to shadow XDR's OperationType

    fn create_test_envelope() -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
        let dest = MuxedAccount::Ed25519(Uint256([1u8; 32]));

        let payment_op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: dest,
                asset: Asset::Native,
                amount: 1000,
            }),
        };

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![payment_op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        })
    }

    #[test]
    fn test_validator_creation() {
        let validator = TransactionValidator::testnet(1, 1000);
        let envelope = create_test_envelope();

        // Basic validation should pass
        let result = validator.validate(&envelope);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_frame_creation_and_properties() {
        let envelope = create_test_envelope();
        let frame = TransactionFrame::new(envelope);

        assert_eq!(frame.operation_count(), 1);
        assert_eq!(frame.fee(), 100);
        assert_eq!(frame.sequence_number(), 1);
        assert!(!frame.is_soroban());
        assert!(!frame.is_fee_bump());
    }

    #[test]
    fn test_ledger_delta() {
        let mut delta = LedgerDelta::new(100);

        assert_eq!(delta.ledger_seq(), 100);
        assert!(!delta.has_changes());

        delta.add_fee(500);
        assert_eq!(delta.fee_charged(), 500);
    }

    #[test]
    fn test_operation_type() {
        assert!(OperationType::InvokeHostFunction.is_soroban());
        assert!(!OperationType::Payment.is_soroban());
        assert_eq!(OperationType::Payment.name(), "Payment");
    }
}
