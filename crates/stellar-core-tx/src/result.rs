//! Transaction and operation result types.
//!
//! This module provides wrappers around XDR result types for easier
//! handling and inspection.

use stellar_xdr::curr::{
    InnerTransactionResultResult, OperationResult, OperationResultTr, TransactionResult,
    TransactionResultResult,
};

/// Result of applying a transaction.
#[derive(Debug, Clone)]
pub struct TxApplyResult {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Fee charged (in stroops).
    pub fee_charged: i64,
    /// The transaction result.
    pub result: TxResultWrapper,
}

impl TxApplyResult {
    /// Create a successful result.
    pub fn success(fee_charged: i64, result: TxResultWrapper) -> Self {
        Self {
            success: true,
            fee_charged,
            result,
        }
    }

    /// Create a failed result.
    pub fn failure(fee_charged: i64, result: TxResultWrapper) -> Self {
        Self {
            success: false,
            fee_charged,
            result,
        }
    }
}

/// Wrapper around TransactionResult for easier inspection.
#[derive(Debug, Clone)]
pub struct TxResultWrapper {
    inner: TransactionResult,
}

impl TxResultWrapper {
    /// Create from XDR TransactionResult.
    pub fn from_xdr(result: TransactionResult) -> Self {
        Self { inner: result }
    }

    /// Create a success result.
    pub fn success() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxSuccess(vec![].try_into().unwrap()),
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Create a fee error result.
    pub fn fee_error() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxInsufficientFee,
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Create a time bounds error result.
    pub fn time_bounds_error() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxTooLate,
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Create a no account error result.
    pub fn no_account_error() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxNoAccount,
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Create a bad sequence error result.
    pub fn bad_seq_error() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxBadSeq,
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Create an insufficient balance error result.
    pub fn insufficient_balance_error() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxInsufficientBalance,
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Create an operation failed result.
    pub fn operation_failed() -> Self {
        Self {
            inner: TransactionResult {
                fee_charged: 0,
                result: TransactionResultResult::TxFailed(vec![].try_into().unwrap()),
                ext: stellar_xdr::curr::TransactionResultExt::V0,
            },
        }
    }

    /// Get the underlying XDR result.
    pub fn into_xdr(self) -> TransactionResult {
        self.inner
    }

    /// Get a reference to the underlying XDR result.
    pub fn as_xdr(&self) -> &TransactionResult {
        &self.inner
    }

    /// Get the fee charged.
    pub fn fee_charged(&self) -> i64 {
        self.inner.fee_charged
    }

    /// Check if the transaction succeeded.
    pub fn is_success(&self) -> bool {
        matches!(
            &self.inner.result,
            TransactionResultResult::TxSuccess(_)
                | TransactionResultResult::TxFeeBumpInnerSuccess(_)
        )
    }

    /// Check if the transaction failed.
    pub fn is_failure(&self) -> bool {
        !self.is_success()
    }

    /// Get the result code.
    pub fn result_code(&self) -> TxResultCode {
        match &self.inner.result {
            TransactionResultResult::TxFeeBumpInnerSuccess(_) => TxResultCode::TxFeeBumpInnerSuccess,
            TransactionResultResult::TxFeeBumpInnerFailed(_) => TxResultCode::TxFeeBumpInnerFailed,
            TransactionResultResult::TxSuccess(_) => TxResultCode::TxSuccess,
            TransactionResultResult::TxFailed(_) => TxResultCode::TxFailed,
            TransactionResultResult::TxTooEarly => TxResultCode::TxTooEarly,
            TransactionResultResult::TxTooLate => TxResultCode::TxTooLate,
            TransactionResultResult::TxMissingOperation => TxResultCode::TxMissingOperation,
            TransactionResultResult::TxBadSeq => TxResultCode::TxBadSeq,
            TransactionResultResult::TxBadAuth => TxResultCode::TxBadAuth,
            TransactionResultResult::TxInsufficientBalance => TxResultCode::TxInsufficientBalance,
            TransactionResultResult::TxNoAccount => TxResultCode::TxNoAccount,
            TransactionResultResult::TxInsufficientFee => TxResultCode::TxInsufficientFee,
            TransactionResultResult::TxBadAuthExtra => TxResultCode::TxBadAuthExtra,
            TransactionResultResult::TxInternalError => TxResultCode::TxInternalError,
            TransactionResultResult::TxNotSupported => TxResultCode::TxNotSupported,
            TransactionResultResult::TxBadSponsorship => TxResultCode::TxBadSponsorship,
            TransactionResultResult::TxBadMinSeqAgeOrGap => TxResultCode::TxBadMinSeqAgeOrGap,
            TransactionResultResult::TxMalformed => TxResultCode::TxMalformed,
            TransactionResultResult::TxSorobanInvalid => TxResultCode::TxSorobanInvalid,
        }
    }

    /// Get the operation results if the transaction was executed.
    pub fn operation_results(&self) -> Option<Vec<OpResultWrapper>> {
        match &self.inner.result {
            TransactionResultResult::TxSuccess(results)
            | TransactionResultResult::TxFailed(results) => Some(
                results
                    .iter()
                    .map(|r| OpResultWrapper::from_xdr(r.clone()))
                    .collect(),
            ),
            TransactionResultResult::TxFeeBumpInnerSuccess(inner)
            | TransactionResultResult::TxFeeBumpInnerFailed(inner) => {
                match &inner.result.result {
                    InnerTransactionResultResult::TxSuccess(results)
                    | InnerTransactionResultResult::TxFailed(results) => Some(
                        results
                            .iter()
                            .map(|r| OpResultWrapper::from_xdr(r.clone()))
                            .collect(),
                    ),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Get the number of operations that succeeded.
    pub fn successful_operation_count(&self) -> usize {
        self.operation_results()
            .map(|results| results.iter().filter(|r| r.is_success()).count())
            .unwrap_or(0)
    }

    /// Get the number of operations that failed.
    pub fn failed_operation_count(&self) -> usize {
        self.operation_results()
            .map(|results| results.iter().filter(|r| !r.is_success()).count())
            .unwrap_or(0)
    }
}

/// Transaction result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxResultCode {
    TxFeeBumpInnerSuccess,
    TxFeeBumpInnerFailed,
    TxSuccess,
    TxFailed,
    TxTooEarly,
    TxTooLate,
    TxMissingOperation,
    TxBadSeq,
    TxBadAuth,
    TxInsufficientBalance,
    TxNoAccount,
    TxInsufficientFee,
    TxBadAuthExtra,
    TxInternalError,
    TxNotSupported,
    TxBadSponsorship,
    TxBadMinSeqAgeOrGap,
    TxMalformed,
    TxSorobanInvalid,
}

impl TxResultCode {
    /// Check if this is a success code.
    pub fn is_success(&self) -> bool {
        matches!(self, TxResultCode::TxSuccess | TxResultCode::TxFeeBumpInnerSuccess)
    }

    /// Get a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            TxResultCode::TxFeeBumpInnerSuccess => "txFeeBumpInnerSuccess",
            TxResultCode::TxFeeBumpInnerFailed => "txFeeBumpInnerFailed",
            TxResultCode::TxSuccess => "txSuccess",
            TxResultCode::TxFailed => "txFailed",
            TxResultCode::TxTooEarly => "txTooEarly",
            TxResultCode::TxTooLate => "txTooLate",
            TxResultCode::TxMissingOperation => "txMissingOperation",
            TxResultCode::TxBadSeq => "txBadSeq",
            TxResultCode::TxBadAuth => "txBadAuth",
            TxResultCode::TxInsufficientBalance => "txInsufficientBalance",
            TxResultCode::TxNoAccount => "txNoAccount",
            TxResultCode::TxInsufficientFee => "txInsufficientFee",
            TxResultCode::TxBadAuthExtra => "txBadAuthExtra",
            TxResultCode::TxInternalError => "txInternalError",
            TxResultCode::TxNotSupported => "txNotSupported",
            TxResultCode::TxBadSponsorship => "txBadSponsorship",
            TxResultCode::TxBadMinSeqAgeOrGap => "txBadMinSeqAgeOrGap",
            TxResultCode::TxMalformed => "txMalformed",
            TxResultCode::TxSorobanInvalid => "txSorobanInvalid",
        }
    }
}

impl std::fmt::Display for TxResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Wrapper around OperationResult for easier inspection.
#[derive(Debug, Clone)]
pub struct OpResultWrapper {
    inner: OperationResult,
}

impl OpResultWrapper {
    /// Create from XDR OperationResult.
    pub fn from_xdr(result: OperationResult) -> Self {
        Self { inner: result }
    }

    /// Get the underlying XDR result.
    pub fn into_xdr(self) -> OperationResult {
        self.inner
    }

    /// Get a reference to the underlying XDR result.
    pub fn as_xdr(&self) -> &OperationResult {
        &self.inner
    }

    /// Check if the operation succeeded.
    pub fn is_success(&self) -> bool {
        match &self.inner {
            OperationResult::OpInner(tr) => self.is_tr_success(tr),
            _ => false,
        }
    }

    /// Check if the inner result is a success.
    fn is_tr_success(&self, tr: &OperationResultTr) -> bool {
        match tr {
            OperationResultTr::CreateAccount(r) => {
                matches!(r, stellar_xdr::curr::CreateAccountResult::Success)
            }
            OperationResultTr::Payment(r) => {
                matches!(r, stellar_xdr::curr::PaymentResult::Success)
            }
            OperationResultTr::PathPaymentStrictReceive(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::PathPaymentStrictReceiveResult::Success(_)
                )
            }
            OperationResultTr::ManageSellOffer(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::ManageSellOfferResult::Success(_)
                )
            }
            OperationResultTr::CreatePassiveSellOffer(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::ManageSellOfferResult::Success(_)
                )
            }
            OperationResultTr::SetOptions(r) => {
                matches!(r, stellar_xdr::curr::SetOptionsResult::Success)
            }
            OperationResultTr::ChangeTrust(r) => {
                matches!(r, stellar_xdr::curr::ChangeTrustResult::Success)
            }
            OperationResultTr::AllowTrust(r) => {
                matches!(r, stellar_xdr::curr::AllowTrustResult::Success)
            }
            OperationResultTr::AccountMerge(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::AccountMergeResult::Success(_)
                )
            }
            OperationResultTr::Inflation(r) => {
                matches!(r, stellar_xdr::curr::InflationResult::Success(_))
            }
            OperationResultTr::ManageData(r) => {
                matches!(r, stellar_xdr::curr::ManageDataResult::Success)
            }
            OperationResultTr::BumpSequence(r) => {
                matches!(r, stellar_xdr::curr::BumpSequenceResult::Success)
            }
            OperationResultTr::ManageBuyOffer(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::ManageBuyOfferResult::Success(_)
                )
            }
            OperationResultTr::PathPaymentStrictSend(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::PathPaymentStrictSendResult::Success(_)
                )
            }
            OperationResultTr::CreateClaimableBalance(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::CreateClaimableBalanceResult::Success(_)
                )
            }
            OperationResultTr::ClaimClaimableBalance(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::ClaimClaimableBalanceResult::Success
                )
            }
            OperationResultTr::BeginSponsoringFutureReserves(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::BeginSponsoringFutureReservesResult::Success
                )
            }
            OperationResultTr::EndSponsoringFutureReserves(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::EndSponsoringFutureReservesResult::Success
                )
            }
            OperationResultTr::RevokeSponsorship(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::RevokeSponsorshipResult::Success
                )
            }
            OperationResultTr::Clawback(r) => {
                matches!(r, stellar_xdr::curr::ClawbackResult::Success)
            }
            OperationResultTr::ClawbackClaimableBalance(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::ClawbackClaimableBalanceResult::Success
                )
            }
            OperationResultTr::SetTrustLineFlags(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::SetTrustLineFlagsResult::Success
                )
            }
            OperationResultTr::LiquidityPoolDeposit(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::LiquidityPoolDepositResult::Success
                )
            }
            OperationResultTr::LiquidityPoolWithdraw(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::LiquidityPoolWithdrawResult::Success
                )
            }
            OperationResultTr::InvokeHostFunction(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::InvokeHostFunctionResult::Success(_)
                )
            }
            OperationResultTr::ExtendFootprintTtl(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::ExtendFootprintTtlResult::Success
                )
            }
            OperationResultTr::RestoreFootprint(r) => {
                matches!(
                    r,
                    stellar_xdr::curr::RestoreFootprintResult::Success
                )
            }
        }
    }

    /// Get the result code.
    pub fn result_code(&self) -> OpResultCode {
        match &self.inner {
            OperationResult::OpInner(_) => OpResultCode::OpInner,
            OperationResult::OpBadAuth => OpResultCode::OpBadAuth,
            OperationResult::OpNoAccount => OpResultCode::OpNoAccount,
            OperationResult::OpNotSupported => OpResultCode::OpNotSupported,
            OperationResult::OpTooManySubentries => OpResultCode::OpTooManySubentries,
            OperationResult::OpExceededWorkLimit => OpResultCode::OpExceededWorkLimit,
            OperationResult::OpTooManySponsoring => OpResultCode::OpTooManySponsoring,
        }
    }
}

/// Operation result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpResultCode {
    OpInner,
    OpBadAuth,
    OpNoAccount,
    OpNotSupported,
    OpTooManySubentries,
    OpExceededWorkLimit,
    OpTooManySponsoring,
}

impl OpResultCode {
    /// Get a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            OpResultCode::OpInner => "opInner",
            OpResultCode::OpBadAuth => "opBadAuth",
            OpResultCode::OpNoAccount => "opNoAccount",
            OpResultCode::OpNotSupported => "opNotSupported",
            OpResultCode::OpTooManySubentries => "opTooManySubentries",
            OpResultCode::OpExceededWorkLimit => "opExceededWorkLimit",
            OpResultCode::OpTooManySponsoring => "opTooManySponsoring",
        }
    }
}

impl std::fmt::Display for OpResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Summary of transaction results for a transaction set.
#[derive(Debug, Clone, Default)]
pub struct TxSetResultSummary {
    /// Total transactions.
    pub total: usize,
    /// Successful transactions.
    pub successful: usize,
    /// Failed transactions.
    pub failed: usize,
    /// Total fee charged.
    pub total_fee: i64,
    /// Total operations.
    pub total_operations: usize,
    /// Successful operations.
    pub successful_operations: usize,
}

impl TxSetResultSummary {
    /// Create a new empty summary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a transaction result to the summary.
    pub fn add(&mut self, result: &TxApplyResult, op_count: usize) {
        self.total += 1;
        self.total_fee += result.fee_charged;
        self.total_operations += op_count;

        if result.success {
            self.successful += 1;
            self.successful_operations += result.result.successful_operation_count();
        } else {
            self.failed += 1;
        }
    }

    /// Get the success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.successful as f64 / self.total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_success_result() -> TransactionResult {
        TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxSuccess(vec![].try_into().unwrap()),
            ext: TransactionResultExt::V0,
        }
    }

    fn create_failed_result() -> TransactionResult {
        TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxBadSeq,
            ext: TransactionResultExt::V0,
        }
    }

    #[test]
    fn test_tx_result_wrapper_success() {
        let result = create_success_result();
        let wrapper = TxResultWrapper::from_xdr(result);

        assert!(wrapper.is_success());
        assert!(!wrapper.is_failure());
        assert_eq!(wrapper.fee_charged(), 100);
        assert_eq!(wrapper.result_code(), TxResultCode::TxSuccess);
    }

    #[test]
    fn test_tx_result_wrapper_failure() {
        let result = create_failed_result();
        let wrapper = TxResultWrapper::from_xdr(result);

        assert!(!wrapper.is_success());
        assert!(wrapper.is_failure());
        assert_eq!(wrapper.result_code(), TxResultCode::TxBadSeq);
    }

    #[test]
    fn test_tx_apply_result() {
        let result = create_success_result();
        let wrapper = TxResultWrapper::from_xdr(result);

        let apply_result = TxApplyResult::success(100, wrapper);
        assert!(apply_result.success);
        assert_eq!(apply_result.fee_charged, 100);
    }

    #[test]
    fn test_tx_set_result_summary() {
        let mut summary = TxSetResultSummary::new();

        let success_result = TxApplyResult {
            success: true,
            fee_charged: 100,
            result: TxResultWrapper::from_xdr(create_success_result()),
        };

        let failed_result = TxApplyResult {
            success: false,
            fee_charged: 100,
            result: TxResultWrapper::from_xdr(create_failed_result()),
        };

        summary.add(&success_result, 1);
        summary.add(&failed_result, 2);

        assert_eq!(summary.total, 2);
        assert_eq!(summary.successful, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.total_fee, 200);
        assert_eq!(summary.total_operations, 3);
        assert_eq!(summary.success_rate(), 50.0);
    }

    #[test]
    fn test_result_code_names() {
        assert_eq!(TxResultCode::TxSuccess.name(), "txSuccess");
        assert_eq!(TxResultCode::TxBadSeq.name(), "txBadSeq");
        assert_eq!(OpResultCode::OpBadAuth.name(), "opBadAuth");
    }
}
