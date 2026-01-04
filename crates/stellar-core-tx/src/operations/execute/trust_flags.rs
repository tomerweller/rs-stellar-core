//! Trust line flag operations execution.
//!
//! This module implements the execution logic for:
//! - AllowTrust (deprecated, but still supported)
//! - SetTrustLineFlags

use stellar_xdr::curr::{
    AccountId, AllowTrustOp, AllowTrustResult, AllowTrustResultCode, Asset, Liabilities,
    OperationResult, OperationResultTr, SetTrustLineFlagsOp, SetTrustLineFlagsResult,
    SetTrustLineFlagsResultCode, TrustLineEntry, TrustLineEntryExt, TrustLineFlags,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Trust line flag constants
const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;
const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 =
    TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;
#[allow(dead_code)]
const TRUSTLINE_CLAWBACK_ENABLED_FLAG: u32 = TrustLineFlags::TrustlineClawbackEnabledFlag as u32;
const AUTH_REQUIRED_FLAG: u32 = 0x1;

/// Execute an AllowTrust operation (deprecated).
///
/// This operation sets the authorized flag on a trustline. It has been
/// deprecated in favor of SetTrustLineFlags but is still supported.
pub fn execute_allow_trust(
    op: &AllowTrustOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check source account exists (the issuer)
    let issuer = match state.get_account(source) {
        Some(a) => a.clone(),
        None => {
            return Ok(make_allow_trust_result(AllowTrustResultCode::Malformed));
        }
    };

    // Check if issuer has AUTH_REQUIRED flag
    if issuer.flags & AUTH_REQUIRED_FLAG == 0 {
        return Ok(make_allow_trust_result(AllowTrustResultCode::TrustNotRequired));
    }

    if &op.trustor == source {
        return Ok(make_allow_trust_result(AllowTrustResultCode::SelfNotAllowed));
    }

    // Convert the asset code to a full Asset
    let asset = match &op.asset {
        stellar_xdr::curr::AssetCode::CreditAlphanum4(code) => {
            Asset::CreditAlphanum4(stellar_xdr::curr::AlphaNum4 {
                asset_code: code.clone(),
                issuer: source.clone(),
            })
        }
        stellar_xdr::curr::AssetCode::CreditAlphanum12(code) => {
            Asset::CreditAlphanum12(stellar_xdr::curr::AlphaNum12 {
                asset_code: code.clone(),
                issuer: source.clone(),
            })
        }
    };

    // Get the trustline
    let trustline = match state.get_trustline(&op.trustor, &asset) {
        Some(tl) => tl.clone(),
        None => {
            return Ok(make_allow_trust_result(AllowTrustResultCode::NoTrustLine));
        }
    };

    // Update the trustline flags based on the authorize value
    let mut new_flags = trustline.flags;

    // Clear existing auth flags
    new_flags &= !(AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG);

    // Set new auth flags based on authorize value
    // authorize is a u32 that can be:
    // 0 = not authorized
    // 1 = authorized
    // 2 = authorized to maintain liabilities only
    match op.authorize {
        0 => {
            // Deauthorize - flags already cleared
        }
        1 => {
            new_flags |= AUTHORIZED_FLAG;
        }
        _ => {
            // Authorized to maintain liabilities
            new_flags |= AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG;
        }
    }

    if op.authorize == 0 && has_liabilities(&trustline) {
        return Ok(make_allow_trust_result(AllowTrustResultCode::CantRevoke));
    }

    // Update the trustline
    if let Some(tl) = state.get_trustline_mut(&op.trustor, &asset) {
        tl.flags = new_flags;
    }

    Ok(make_allow_trust_result(AllowTrustResultCode::Success))
}

/// Execute a SetTrustLineFlags operation.
///
/// This operation sets or clears specific flags on a trustline.
pub fn execute_set_trust_line_flags(
    op: &SetTrustLineFlagsOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Check source account exists (the issuer)
    if state.get_account(source).is_none() {
        return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::Malformed));
    }

    // The source must be the issuer of the asset
    let issuer = match &op.asset {
        Asset::Native => {
            return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::Malformed));
        }
        Asset::CreditAlphanum4(a) => &a.issuer,
        Asset::CreditAlphanum12(a) => &a.issuer,
    };

    if issuer != source {
        return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::Malformed));
    }

    // Get the trustline
    let trustline = match state.get_trustline(&op.trustor, &op.asset) {
        Some(tl) => tl.clone(),
        None => {
            return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::NoTrustLine));
        }
    };

    // Cannot set both AUTHORIZED and AUTHORIZED_TO_MAINTAIN_LIABILITIES
    if (op.set_flags & AUTHORIZED_FLAG != 0)
        && (op.set_flags & AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG != 0)
    {
        return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::Malformed));
    }

    // Cannot clear and set the same flag
    if (op.set_flags & op.clear_flags) != 0 {
        return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::Malformed));
    }

    // Calculate new flags
    let mut new_flags = trustline.flags;
    new_flags &= !op.clear_flags;
    new_flags |= op.set_flags;

    // If setting AUTHORIZED, must clear AUTHORIZED_TO_MAINTAIN_LIABILITIES
    if op.set_flags & AUTHORIZED_FLAG != 0 {
        new_flags &= !AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG;
    }

    // If setting AUTHORIZED_TO_MAINTAIN_LIABILITIES, must clear AUTHORIZED
    if op.set_flags & AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG != 0 {
        new_flags &= !AUTHORIZED_FLAG;
    }

    if !is_authorized_to_maintain_liabilities(new_flags) && has_liabilities(&trustline) {
        return Ok(make_set_flags_result(SetTrustLineFlagsResultCode::CantRevoke));
    }

    // Update the trustline
    if let Some(tl) = state.get_trustline_mut(&op.trustor, &op.asset) {
        tl.flags = new_flags;
    }

    Ok(make_set_flags_result(SetTrustLineFlagsResultCode::Success))
}

/// Create an AllowTrust result.
fn make_allow_trust_result(code: AllowTrustResultCode) -> OperationResult {
    let result = match code {
        AllowTrustResultCode::Success => AllowTrustResult::Success,
        AllowTrustResultCode::Malformed => AllowTrustResult::Malformed,
        AllowTrustResultCode::NoTrustLine => AllowTrustResult::NoTrustLine,
        AllowTrustResultCode::TrustNotRequired => AllowTrustResult::TrustNotRequired,
        AllowTrustResultCode::CantRevoke => AllowTrustResult::CantRevoke,
        AllowTrustResultCode::SelfNotAllowed => AllowTrustResult::SelfNotAllowed,
        AllowTrustResultCode::LowReserve => AllowTrustResult::LowReserve,
    };

    OperationResult::OpInner(OperationResultTr::AllowTrust(result))
}

/// Create a SetTrustLineFlags result.
fn make_set_flags_result(code: SetTrustLineFlagsResultCode) -> OperationResult {
    let result = match code {
        SetTrustLineFlagsResultCode::Success => SetTrustLineFlagsResult::Success,
        SetTrustLineFlagsResultCode::Malformed => SetTrustLineFlagsResult::Malformed,
        SetTrustLineFlagsResultCode::NoTrustLine => SetTrustLineFlagsResult::NoTrustLine,
        SetTrustLineFlagsResultCode::CantRevoke => SetTrustLineFlagsResult::CantRevoke,
        SetTrustLineFlagsResultCode::InvalidState => SetTrustLineFlagsResult::InvalidState,
        SetTrustLineFlagsResultCode::LowReserve => SetTrustLineFlagsResult::LowReserve,
    };

    OperationResult::OpInner(OperationResultTr::SetTrustLineFlags(result))
}

fn has_liabilities(trustline: &TrustLineEntry) -> bool {
    let liab = match &trustline.ext {
        TrustLineEntryExt::V0 => Liabilities {
            buying: 0,
            selling: 0,
        },
        TrustLineEntryExt::V1(v1) => v1.liabilities.clone(),
    };
    liab.buying != 0 || liab.selling != 0
}

fn is_authorized_to_maintain_liabilities(flags: u32) -> bool {
    flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
    }

    fn create_test_account(account_id: AccountId, balance: i64, flags: u32) -> AccountEntry {
        AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
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

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    #[test]
    fn test_allow_trust_no_auth_required() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let trustor_id = create_test_account_id(1);

        // Issuer without AUTH_REQUIRED flag
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(trustor_id.clone(), 10_000_000, 0));

        let op = AllowTrustOp {
            trustor: trustor_id,
            asset: AssetCode::CreditAlphanum4(AssetCode4([b'U', b'S', b'D', b'C'])),
            authorize: 1,
        };

        let result = execute_allow_trust(&op, &issuer_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::AllowTrust(r)) => {
                assert!(matches!(r, AllowTrustResult::TrustNotRequired));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_allow_trust_cant_revoke_with_liabilities() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let trustor_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, AUTH_REQUIRED_FLAG));
        state.create_account(create_test_account(trustor_id.clone(), 100_000_000, 0));

        let _asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        state.create_trustline(create_test_trustline_with_liabilities(
            trustor_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
            0,
            1,
        ));

        let op = AllowTrustOp {
            trustor: trustor_id.clone(),
            asset: stellar_xdr::curr::AssetCode::CreditAlphanum4(AssetCode4([b'U', b'S', b'D', b'C'])),
            authorize: 0,
        };

        let result = execute_allow_trust(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::AllowTrust(r)) => {
                assert!(matches!(r, AllowTrustResult::CantRevoke));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_allow_trust_self_not_allowed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        state.create_account(create_test_account(
            issuer_id.clone(),
            100_000_000,
            AUTH_REQUIRED_FLAG,
        ));

        let op = AllowTrustOp {
            trustor: issuer_id.clone(),
            asset: AssetCode::CreditAlphanum4(AssetCode4([b'U', b'S', b'D', b'C'])),
            authorize: 1,
        };

        let result = execute_allow_trust(&op, &issuer_id, &mut state, &context)
            .expect("allow trust");
        match result {
            OperationResult::OpInner(OperationResultTr::AllowTrust(r)) => {
                assert!(matches!(r, AllowTrustResult::SelfNotAllowed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_set_trust_line_flags_cant_revoke_with_liabilities() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let trustor_id = create_test_account_id(1);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(trustor_id.clone(), 100_000_000, 0));

        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        state.create_trustline(create_test_trustline_with_liabilities(
            trustor_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_FLAG,
            0,
            1,
        ));

        let op = SetTrustLineFlagsOp {
            trustor: trustor_id.clone(),
            asset,
            clear_flags: AUTHORIZED_FLAG,
            set_flags: 0,
        };

        let result = execute_set_trust_line_flags(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::SetTrustLineFlags(r)) => {
                assert!(matches!(r, SetTrustLineFlagsResult::CantRevoke));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_set_trust_line_flags_success() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(0);
        let trustor_id = create_test_account_id(1);

        state.create_account(create_test_account(issuer_id.clone(), 100_000_000, 0x1)); // AUTH_REQUIRED
        state.create_account(create_test_account(trustor_id.clone(), 10_000_000, 0));

        // Create the asset and trustline
        let asset = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        let trustline = TrustLineEntry {
            account_id: trustor_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            balance: 0,
            limit: i64::MAX,
            flags: 0, // Not authorized
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);

        let op = SetTrustLineFlagsOp {
            trustor: trustor_id.clone(),
            asset: asset.clone(),
            clear_flags: 0,
            set_flags: AUTHORIZED_FLAG,
        };

        let result = execute_set_trust_line_flags(&op, &issuer_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetTrustLineFlags(r)) => {
                assert!(matches!(r, SetTrustLineFlagsResult::Success));
            }
            _ => panic!("Unexpected result type"),
        }

        // Verify the flag was set
        let tl = state.get_trustline(&trustor_id, &asset).unwrap();
        assert_eq!(tl.flags & AUTHORIZED_FLAG, AUTHORIZED_FLAG);
    }
}
