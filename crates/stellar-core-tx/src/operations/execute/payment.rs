//! Payment operation execution.
//!
//! This module implements the execution logic for the Payment operation,
//! which transfers assets between accounts.

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, Asset, Liabilities, OperationResult,
    OperationResultTr, PaymentOp, PaymentResult, PaymentResultCode, TrustLineEntry,
    TrustLineEntryExt, TrustLineFlags,
};

use crate::frame::muxed_to_account_id;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a Payment operation.
///
/// This operation transfers assets from the source account to the destination.
/// For native assets, the transfer is direct. For credit assets, both accounts
/// must have trustlines for the asset.
///
/// # Arguments
///
/// * `op` - The Payment operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_payment(
    op: &PaymentOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let dest = muxed_to_account_id(&op.destination);

    // Amount must be positive
    if op.amount <= 0 {
        return Ok(make_result(PaymentResultCode::Malformed));
    }

    match &op.asset {
        Asset::Native => execute_native_payment(source, &dest, op.amount, state, context),
        Asset::CreditAlphanum4(_) | Asset::CreditAlphanum12(_) => {
            execute_credit_payment(source, &dest, &op.asset, op.amount, state)
        }
    }
}

/// Execute a native (XLM) payment.
fn execute_native_payment(
    source: &AccountId,
    dest: &AccountId,
    amount: i64,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Check destination exists
    if state.get_account(dest).is_none() {
        return Ok(make_result(PaymentResultCode::NoDestination));
    }

    // Get source account and check balance
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check source has sufficient available balance
    let source_min_balance =
        state.minimum_balance_for_account(source_account, context.protocol_version, 0)?;
    let available =
        source_account.balance - source_min_balance - account_liabilities(source_account).selling;
    if available < amount {
        return Ok(make_result(PaymentResultCode::Underfunded));
    }

    // Deduct from source
    let source_account_mut = state
        .get_account_mut(source)
        .ok_or(TxError::SourceAccountNotFound)?;
    source_account_mut.balance -= amount;

    // Credit to destination
    let dest_account = state
        .get_account(dest)
        .ok_or_else(|| TxError::Internal("destination account disappeared".into()))?;
    let max_receive = i64::MAX - dest_account.balance - account_liabilities(dest_account).buying;
    if max_receive < amount {
        return Ok(make_result(PaymentResultCode::LineFull));
    }
    let dest_account_mut = state
        .get_account_mut(dest)
        .ok_or_else(|| TxError::Internal("destination account disappeared".into()))?;
    dest_account_mut.balance += amount;

    Ok(make_result(PaymentResultCode::Success))
}

/// Execute a credit asset payment.
fn execute_credit_payment(
    source: &AccountId,
    dest: &AccountId,
    asset: &Asset,
    amount: i64,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    let issuer = match asset {
        Asset::CreditAlphanum4(a) => &a.issuer,
        Asset::CreditAlphanum12(a) => &a.issuer,
        Asset::Native => return Ok(make_result(PaymentResultCode::Malformed)),
    };

    let issuer_account = match state.get_account(issuer) {
        Some(account) => account,
        None => return Ok(make_result(PaymentResultCode::NoIssuer)),
    };

    // Check destination exists
    if issuer != dest && state.get_account(dest).is_none() {
        return Ok(make_result(PaymentResultCode::NoDestination));
    }

    // Check source trustline exists
    let auth_required = issuer_account.flags & AUTH_REQUIRED_FLAG != 0;
    if issuer != source {
        let source_trustline = match state.get_trustline(source, asset) {
            Some(tl) => tl,
            None => return Ok(make_result(PaymentResultCode::SrcNoTrust)),
        };

        if auth_required && !is_trustline_authorized(source_trustline.flags) {
            return Ok(make_result(PaymentResultCode::SrcNotAuthorized));
        }

        // Check source has sufficient balance
        let available = source_trustline.balance - trustline_liabilities(source_trustline).selling;
        if available < amount {
            return Ok(make_result(PaymentResultCode::Underfunded));
        }
    }

    // Check destination trustline exists
    if issuer != dest {
        let dest_trustline = match state.get_trustline(dest, asset) {
            Some(tl) => tl,
            None => return Ok(make_result(PaymentResultCode::NoTrust)),
        };

        if auth_required && !is_trustline_authorized(dest_trustline.flags) {
            return Ok(make_result(PaymentResultCode::NotAuthorized));
        }

        // Check destination trustline has room (limit check)
        let dest_available =
            dest_trustline.limit - dest_trustline.balance - trustline_liabilities(dest_trustline).buying;
        if dest_available < amount {
            return Ok(make_result(PaymentResultCode::LineFull));
        }
    }

    if issuer != source {
        // Update source trustline balance
        let source_trustline_mut = state
            .get_trustline_mut(source, asset)
            .ok_or_else(|| TxError::Internal("source trustline disappeared".into()))?;
        source_trustline_mut.balance -= amount;
    }

    if issuer != dest {
        // Update destination trustline balance
        let dest_trustline_mut = state
            .get_trustline_mut(dest, asset)
            .ok_or_else(|| TxError::Internal("destination trustline disappeared".into()))?;
        dest_trustline_mut.balance += amount;
    }

    Ok(make_result(PaymentResultCode::Success))
}

const AUTH_REQUIRED_FLAG: u32 = 0x1;
const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;

fn is_trustline_authorized(flags: u32) -> bool {
    flags & AUTHORIZED_FLAG != 0
}

fn account_liabilities(account: &AccountEntry) -> Liabilities {
    match &account.ext {
        AccountEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        AccountEntryExt::V1(v1) => v1.liabilities.clone(),
    }
}

fn trustline_liabilities(trustline: &TrustLineEntry) -> Liabilities {
    match &trustline.ext {
        TrustLineEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        TrustLineEntryExt::V1(v1) => v1.liabilities.clone(),
    }
}

/// Create an OperationResult from a PaymentResultCode.
fn make_result(code: PaymentResultCode) -> OperationResult {
    let result = match code {
        PaymentResultCode::Success => PaymentResult::Success,
        PaymentResultCode::Malformed => PaymentResult::Malformed,
        PaymentResultCode::Underfunded => PaymentResult::Underfunded,
        PaymentResultCode::SrcNoTrust => PaymentResult::SrcNoTrust,
        PaymentResultCode::SrcNotAuthorized => PaymentResult::SrcNotAuthorized,
        PaymentResultCode::NoDestination => PaymentResult::NoDestination,
        PaymentResultCode::NoTrust => PaymentResult::NoTrust,
        PaymentResultCode::NotAuthorized => PaymentResult::NotAuthorized,
        PaymentResultCode::LineFull => PaymentResult::LineFull,
        PaymentResultCode::NoIssuer => PaymentResult::NoIssuer,
    };

    OperationResult::OpInner(OperationResultTr::Payment(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_muxed_account(seed: u8) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256([seed; 32]))
    }

    fn create_test_account(account_id: AccountId, balance: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        }
    }

    fn create_test_account_with_liabilities(
        account_id: AccountId,
        balance: i64,
        buying: i64,
        selling: i64,
    ) -> AccountEntry {
        let mut account = create_test_account(account_id, balance);
        account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
            liabilities: Liabilities { buying, selling },
            ext: AccountEntryExtensionV1Ext::V0,
        });
        account
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    fn create_test_trustline(
        account_id: AccountId,
        asset: TrustLineAsset,
        balance: i64,
        limit: i64,
        flags: u32,
    ) -> TrustLineEntry {
        TrustLineEntry {
            account_id,
            asset,
            balance,
            limit,
            flags,
            ext: TrustLineEntryExt::V0,
        }
    }

    fn create_test_trustline_with_liabilities(
        account_id: AccountId,
        asset: TrustLineAsset,
        balance: i64,
        limit: i64,
        flags: u32,
        buying: i64,
        selling: i64,
    ) -> TrustLineEntry {
        TrustLineEntry {
            account_id,
            asset,
            balance,
            limit,
            flags,
            ext: TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities { buying, selling },
                ext: TrustLineEntryV1Ext::V0,
            }),
        }
    }

    #[test]
    fn test_native_payment_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        // Create both accounts
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 10_000_000,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify balances changed
        assert_eq!(state.get_account(&source_id).unwrap().balance, 90_000_000);
        assert_eq!(state.get_account(&dest_id).unwrap().balance, 60_000_000);
    }

    #[test]
    fn test_payment_no_destination() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1), // Non-existent destination
            asset: Asset::Native,
            amount: 10_000_000,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::NoDestination));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_payment_underfunded() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        // Source has 15M, minimum is 10M, so only 5M available
        state.create_account(create_test_account(source_id.clone(), 15_000_000));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 10_000_000, // More than available
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Underfunded));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_payment_underfunded_with_liabilities() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);

        let min_balance = state
            .minimum_balance_with_counts(context.protocol_version, 0, 0, 0)
            .unwrap();
        state.create_account(create_test_account_with_liabilities(
            source_id.clone(),
            min_balance + 1_000_000,
            0,
            900_000,
        ));
        state.create_account(create_test_account(dest_id.clone(), 50_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 200_000,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Underfunded));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_payment_malformed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset: Asset::Native,
            amount: 0, // Invalid amount
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_no_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset,
            amount: 10,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::NoIssuer));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_src_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            0,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset,
            amount: 10,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::SrcNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_not_authorized_dest() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            0,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset,
            amount: 10,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::NotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_line_full_with_liabilities() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline_with_liabilities(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            90,
            100,
            AUTHORIZED_FLAG,
            10,
            0,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset,
            amount: 1,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::LineFull));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_success_no_auth_required() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            0,
        ));
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            0,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset,
            amount: 10,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_from_issuer_without_trustline() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let dest_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(dest_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            dest_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            0,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(1),
            asset,
            amount: 10,
        };

        let result = execute_payment(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_credit_payment_to_issuer_without_trustline() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            0,
        ));

        let op = PaymentOp {
            destination: create_test_muxed_account(9),
            asset,
            amount: 10,
        };

        let result = execute_payment(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::Payment(r)) => {
                assert!(matches!(r, PaymentResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
