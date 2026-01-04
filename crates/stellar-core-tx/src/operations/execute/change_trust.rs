//! ChangeTrust operation execution.

use stellar_xdr::curr::{
    AccountId, Asset, ChangeTrustAsset, ChangeTrustOp, ChangeTrustResult, ChangeTrustResultCode,
    Liabilities, LiquidityPoolEntry, LiquidityPoolEntryBody, LiquidityPoolEntryConstantProduct,
    LiquidityPoolParameters, OperationResult, OperationResultTr, TrustLineAsset, TrustLineEntry,
    TrustLineEntryExt, TrustLineEntryExtensionV2, TrustLineEntryExtensionV2Ext, TrustLineEntryV1,
    TrustLineEntryV1Ext, TrustLineFlags, LedgerKey, LedgerKeyTrustLine,
};

use crate::apply::account_id_to_key;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Execute a ChangeTrust operation.
pub fn execute_change_trust(
    op: &ChangeTrustOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate limit
    if op.limit < 0 {
        return Ok(make_result(ChangeTrustResultCode::Malformed));
    }

    let (maybe_asset, pool_params) = match &op.line {
        ChangeTrustAsset::Native => {
            return Ok(make_result(ChangeTrustResultCode::Malformed));
        }
        ChangeTrustAsset::CreditAlphanum4(a) => (Some(Asset::CreditAlphanum4(a.clone())), None),
        ChangeTrustAsset::CreditAlphanum12(a) => (Some(Asset::CreditAlphanum12(a.clone())), None),
        ChangeTrustAsset::PoolShare(params) => (None, Some(params)),
    };
    let is_pool_share = pool_params.is_some();
    let multiplier: i64 = if is_pool_share { 2 } else { 1 };
    let tl_asset = change_trust_asset_to_trust_line_asset(&op.line);

    // Check not trusting self
    if let Some(asset) = &maybe_asset {
        let issuer = get_asset_issuer(asset);
        if let Some(issuer_id) = issuer {
            let source_key = account_id_to_key(source);
            let issuer_key = account_id_to_key(&issuer_id);
            if source_key == issuer_key {
                return Ok(make_result(if context.protocol_version >= 16 {
                    ChangeTrustResultCode::Malformed
                } else {
                    ChangeTrustResultCode::SelfNotAllowed
                }));
            }
        }
    }

    // Check source account exists
    if state.get_account(source).is_none() {
        return Err(TxError::SourceAccountNotFound);
    }

    // Get existing trustline if any
    let existing = state.get_trustline_by_trustline_asset(source, &tl_asset);

    if op.limit == 0 {
        // Removing trustline
        let Some(tl) = existing else {
            return Ok(make_result(ChangeTrustResultCode::InvalidLimit));
        };
        if tl.balance > 0 {
            // Can't remove trustline with balance
            return Ok(make_result(ChangeTrustResultCode::InvalidLimit));
        }
        if trustline_liabilities(tl).buying > 0 {
            return Ok(make_result(ChangeTrustResultCode::InvalidLimit));
        }

        if !is_pool_share && liquidity_pool_use_count(tl) != 0 {
            return Ok(make_result(ChangeTrustResultCode::CannotDelete));
        }

        if is_pool_share && !manage_pool_on_deleted_trustline(state, &tl_asset) {
            return Ok(make_result(ChangeTrustResultCode::CannotDelete));
        }

        if is_pool_share {
            let params = pool_params.expect("pool params must exist");
            decrement_pool_use_counts(state, source, params)?;
        }

        let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
            account_id: source.clone(),
            asset: tl_asset.clone(),
        });
        if state.entry_sponsor(&ledger_key).is_some() {
            state.remove_entry_sponsorship_and_update_counts(
                &ledger_key,
                source,
                multiplier,
            )?;
        }

        state.delete_trustline_by_trustline_asset(source, &tl_asset);

        // Decrease sub-entries
        if let Some(account) = state.get_account_mut(source) {
            if account.num_sub_entries >= multiplier as u32 {
                account.num_sub_entries -= multiplier as u32;
            } else {
                return Err(TxError::Internal(
                    "negative subentry count while deleting trustline".to_string(),
                ));
            }
        }
    } else if existing.is_some() {
        // Updating existing trustline
        let existing_balance = existing.map(|tl| tl.balance).unwrap_or(0);
        let existing_buying_liab = existing.map(trustline_liabilities).map(|l| l.buying).unwrap_or(0);
        if op.limit < existing_balance.saturating_add(existing_buying_liab) {
            return Ok(make_result(ChangeTrustResultCode::InvalidLimit));
        }

        if !is_pool_share {
            let asset = maybe_asset.as_ref().expect("asset must exist");
            let issuer = get_asset_issuer(asset);
            if let Some(issuer_id) = issuer {
                if state.get_account(&issuer_id).is_none() {
                    return Ok(make_result(ChangeTrustResultCode::NoIssuer));
                }
            }
        }

        if let Some(tl) = state.get_trustline_by_trustline_asset_mut(source, &tl_asset) {
            tl.limit = op.limit;
        }
    } else {
        // Creating new trustline
        if is_pool_share {
            let params = pool_params.expect("pool params must exist");
            if let Err(code) = validate_pool_share_trustlines(source, params, state) {
                return Ok(make_result(code));
            }
            increment_pool_use_counts(state, source, params)?;
        } else {
            let asset = maybe_asset.as_ref().expect("asset must exist");
            let issuer = get_asset_issuer(asset);
            if let Some(issuer_id) = issuer {
                if state.get_account(&issuer_id).is_none() {
                    return Ok(make_result(ChangeTrustResultCode::NoIssuer));
                }
            }
        }

        // Check source can afford new sub-entry
        let sponsor = state.active_sponsor_for(source);
        if let Some(sponsor) = &sponsor {
            let sponsor_account = state
                .get_account(sponsor)
                .ok_or(TxError::SourceAccountNotFound)?;
            let new_min_balance = state.minimum_balance_for_account_with_deltas(
                sponsor_account,
                context.protocol_version,
                0,
                multiplier,
                0,
            )?;
            if sponsor_account.balance < new_min_balance {
                return Ok(make_result(ChangeTrustResultCode::LowReserve));
            }
        } else {
            let source_account = state
                .get_account(source)
                .ok_or(TxError::SourceAccountNotFound)?;
            let new_min_balance = state.minimum_balance_for_account(
                source_account,
                context.protocol_version,
                multiplier,
            )?;
            if source_account.balance < new_min_balance {
                return Ok(make_result(ChangeTrustResultCode::LowReserve));
            }
        }

        // Create trustline
        let trustline = TrustLineEntry {
            account_id: source.clone(),
            asset: tl_asset.clone(),
            balance: 0,
            limit: op.limit,
            flags: build_trustline_flags(maybe_asset.as_ref(), state),
            ext: TrustLineEntryExt::V0,
        };

        state.create_trustline(trustline);
        if sponsor.is_some() {
            let ledger_key = LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: source.clone(),
                asset: tl_asset.clone(),
            });
            state.apply_entry_sponsorship(ledger_key, source, multiplier)?;
        }

        if is_pool_share {
            let params = pool_params.expect("pool params must exist");
            manage_pool_on_new_trustline(state, &tl_asset, params);
        }

        // Increase sub-entries
        if let Some(account) = state.get_account_mut(source) {
            account.num_sub_entries += multiplier as u32;
        }
    }

    Ok(make_result(ChangeTrustResultCode::Success))
}

fn change_trust_asset_to_trust_line_asset(
    asset: &ChangeTrustAsset,
) -> stellar_xdr::curr::TrustLineAsset {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{Limits, PoolId, Hash, WriteXdr};

    match asset {
        ChangeTrustAsset::Native => stellar_xdr::curr::TrustLineAsset::Native,
        ChangeTrustAsset::CreditAlphanum4(a) => {
            stellar_xdr::curr::TrustLineAsset::CreditAlphanum4(a.clone())
        }
        ChangeTrustAsset::CreditAlphanum12(a) => {
            stellar_xdr::curr::TrustLineAsset::CreditAlphanum12(a.clone())
        }
        ChangeTrustAsset::PoolShare(params) => {
            // Compute pool ID as SHA256 hash of the liquidity pool parameters XDR
            let pool_id = if let Ok(xdr_bytes) = params.to_xdr(Limits::none()) {
                let mut hasher = Sha256::new();
                hasher.update(&xdr_bytes);
                Hash(hasher.finalize().into())
            } else {
                Hash([0u8; 32])
            };
            stellar_xdr::curr::TrustLineAsset::PoolShare(PoolId(pool_id))
        }
    }
}

fn get_asset_issuer(asset: &Asset) -> Option<AccountId> {
    match asset {
        Asset::Native => None,
        Asset::CreditAlphanum4(a) => Some(a.issuer.clone()),
        Asset::CreditAlphanum12(a) => Some(a.issuer.clone()),
    }
}

const AUTH_REQUIRED_FLAG: u32 = 0x1;
const AUTH_CLAWBACK_FLAG: u32 = 0x8;
const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;
const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 =
    TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;
const TRUSTLINE_CLAWBACK_ENABLED_FLAG: u32 = TrustLineFlags::TrustlineClawbackEnabledFlag as u32;

fn build_trustline_flags(asset: Option<&Asset>, state: &LedgerStateManager) -> u32 {
    let Some(asset) = asset else {
        return 0;
    };
    let issuer = match get_asset_issuer(asset) {
        Some(issuer_id) => issuer_id,
        None => return 0,
    };
    let Some(issuer_account) = state.get_account(&issuer) else {
        return 0;
    };
    let mut flags = 0;
    if issuer_account.flags & AUTH_REQUIRED_FLAG == 0 {
        flags |= AUTHORIZED_FLAG;
    }
    if issuer_account.flags & AUTH_CLAWBACK_FLAG != 0 {
        flags |= TRUSTLINE_CLAWBACK_ENABLED_FLAG;
    }
    flags
}

fn is_authorized_to_maintain_liabilities(flags: u32) -> bool {
    flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
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

fn validate_pool_share_trustlines(
    source: &AccountId,
    params: &LiquidityPoolParameters,
    state: &LedgerStateManager,
) -> std::result::Result<(), ChangeTrustResultCode> {
    let LiquidityPoolParameters::LiquidityPoolConstantProduct(cp) = params;
    validate_pool_asset_trustline(source, &cp.asset_a, state)?;
    validate_pool_asset_trustline(source, &cp.asset_b, state)?;
    Ok(())
}

fn validate_pool_asset_trustline(
    source: &AccountId,
    asset: &Asset,
    state: &LedgerStateManager,
) -> std::result::Result<(), ChangeTrustResultCode> {
    if matches!(asset, Asset::Native) {
        return Ok(());
    }
    if let Some(issuer) = get_asset_issuer(asset) {
        if account_id_to_key(&issuer) == account_id_to_key(source) {
            return Ok(());
        }
    }
    let trustline = state
        .get_trustline(source, asset)
        .ok_or(ChangeTrustResultCode::TrustLineMissing)?;
    if !is_authorized_to_maintain_liabilities(trustline.flags) {
        return Err(ChangeTrustResultCode::NotAuthMaintainLiabilities);
    }
    Ok(())
}

fn increment_pool_use_counts(
    state: &mut LedgerStateManager,
    source: &AccountId,
    params: &LiquidityPoolParameters,
) -> Result<()> {
    let LiquidityPoolParameters::LiquidityPoolConstantProduct(cp) = params;
    increment_pool_use_count(state, source, &cp.asset_a)?;
    increment_pool_use_count(state, source, &cp.asset_b)?;
    Ok(())
}

fn decrement_pool_use_counts(
    state: &mut LedgerStateManager,
    source: &AccountId,
    params: &LiquidityPoolParameters,
) -> Result<()> {
    let LiquidityPoolParameters::LiquidityPoolConstantProduct(cp) = params;
    decrement_pool_use_count(state, source, &cp.asset_a)?;
    decrement_pool_use_count(state, source, &cp.asset_b)?;
    Ok(())
}

fn increment_pool_use_count(
    state: &mut LedgerStateManager,
    source: &AccountId,
    asset: &Asset,
) -> Result<()> {
    if matches!(asset, Asset::Native) {
        return Ok(());
    }
    if let Some(issuer) = get_asset_issuer(asset) {
        if account_id_to_key(&issuer) == account_id_to_key(source) {
            return Ok(());
        }
    }
    let trustline = state
        .get_trustline_mut(source, asset)
        .ok_or_else(|| TxError::Internal("missing trustline".into()))?;
    let v2 = ensure_trustline_ext_v2(trustline);
    if v2.liquidity_pool_use_count == i32::MAX {
        return Err(TxError::Internal(
            "liquidity pool use count overflow".into(),
        ));
    }
    v2.liquidity_pool_use_count += 1;
    Ok(())
}

fn decrement_pool_use_count(
    state: &mut LedgerStateManager,
    source: &AccountId,
    asset: &Asset,
) -> Result<()> {
    if matches!(asset, Asset::Native) {
        return Ok(());
    }
    if let Some(issuer) = get_asset_issuer(asset) {
        if account_id_to_key(&issuer) == account_id_to_key(source) {
            return Ok(());
        }
    }
    let trustline = state
        .get_trustline_mut(source, asset)
        .ok_or_else(|| TxError::Internal("missing trustline".into()))?;
    let v2 = ensure_trustline_ext_v2(trustline);
    if v2.liquidity_pool_use_count == 0 {
        return Ok(());
    }
    v2.liquidity_pool_use_count -= 1;
    Ok(())
}

fn liquidity_pool_use_count(trustline: &TrustLineEntry) -> i32 {
    match &trustline.ext {
        TrustLineEntryExt::V0 => 0,
        TrustLineEntryExt::V1(v1) => match &v1.ext {
            TrustLineEntryV1Ext::V0 => 0,
            TrustLineEntryV1Ext::V2(v2) => v2.liquidity_pool_use_count,
        },
    }
}

fn ensure_trustline_ext_v2(trustline: &mut TrustLineEntry) -> &mut TrustLineEntryExtensionV2 {
    match &mut trustline.ext {
        TrustLineEntryExt::V0 => {
            trustline.ext = TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: TrustLineEntryV1Ext::V2(TrustLineEntryExtensionV2 {
                    liquidity_pool_use_count: 0,
                    ext: TrustLineEntryExtensionV2Ext::V0,
                }),
            });
        }
        TrustLineEntryExt::V1(v1) => match v1.ext {
            TrustLineEntryV1Ext::V0 => {
                v1.ext = TrustLineEntryV1Ext::V2(TrustLineEntryExtensionV2 {
                    liquidity_pool_use_count: 0,
                    ext: TrustLineEntryExtensionV2Ext::V0,
                });
            }
            TrustLineEntryV1Ext::V2(_) => {}
        },
    }

    match &mut trustline.ext {
        TrustLineEntryExt::V1(v1) => match &mut v1.ext {
            TrustLineEntryV1Ext::V2(v2) => v2,
            TrustLineEntryV1Ext::V0 => {
                unreachable!("trustline v2 ext was not initialized")
            }
        },
        TrustLineEntryExt::V0 => unreachable!("trustline v1 ext was not initialized"),
    }
}

fn manage_pool_on_new_trustline(
    state: &mut LedgerStateManager,
    tl_asset: &TrustLineAsset,
    params: &LiquidityPoolParameters,
) {
    let pool_id = match tl_asset {
        TrustLineAsset::PoolShare(pool_id) => pool_id.clone(),
        _ => return,
    };

    if let Some(pool) = state.get_liquidity_pool_mut(&pool_id) {
        let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &mut pool.body;
        cp.pool_shares_trust_line_count += 1;
        return;
    }

    let LiquidityPoolParameters::LiquidityPoolConstantProduct(cp_params) = params;
    let entry = LiquidityPoolEntry {
        liquidity_pool_id: pool_id.clone(),
        body: LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
            LiquidityPoolEntryConstantProduct {
                params: cp_params.clone(),
                reserve_a: 0,
                reserve_b: 0,
                total_pool_shares: 0,
                pool_shares_trust_line_count: 1,
            },
        ),
    };
    state.create_liquidity_pool(entry);
}

fn manage_pool_on_deleted_trustline(
    state: &mut LedgerStateManager,
    tl_asset: &TrustLineAsset,
) -> bool {
    let pool_id = match tl_asset {
        TrustLineAsset::PoolShare(pool_id) => pool_id.clone(),
        _ => return true,
    };

    let Some(pool) = state.get_liquidity_pool_mut(&pool_id) else {
        return false;
    };
    let LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) = &mut pool.body;
    if cp.pool_shares_trust_line_count == 0 {
        return false;
    }
    cp.pool_shares_trust_line_count -= 1;
    true
}

fn make_result(code: ChangeTrustResultCode) -> OperationResult {
    let result = match code {
        ChangeTrustResultCode::Success => ChangeTrustResult::Success,
        ChangeTrustResultCode::Malformed => ChangeTrustResult::Malformed,
        ChangeTrustResultCode::NoIssuer => ChangeTrustResult::NoIssuer,
        ChangeTrustResultCode::InvalidLimit => ChangeTrustResult::InvalidLimit,
        ChangeTrustResultCode::LowReserve => ChangeTrustResult::LowReserve,
        ChangeTrustResultCode::SelfNotAllowed => ChangeTrustResult::SelfNotAllowed,
        ChangeTrustResultCode::TrustLineMissing => ChangeTrustResult::TrustLineMissing,
        ChangeTrustResultCode::CannotDelete => ChangeTrustResult::CannotDelete,
        ChangeTrustResultCode::NotAuthMaintainLiabilities => {
            ChangeTrustResult::NotAuthMaintainLiabilities
        }
    };
    OperationResult::OpInner(OperationResultTr::ChangeTrust(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;
    use sha2::{Digest, Sha256};
    use crate::operations::execute::manage_offer::execute_manage_sell_offer;

    fn create_test_account_id(seed: u8) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([seed; 32])))
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

    fn create_test_account_with_flags(
        account_id: AccountId,
        balance: i64,
        flags: u32,
    ) -> AccountEntry {
        let mut entry = create_test_account(account_id, balance);
        entry.flags = flags;
        entry
    }

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    fn pool_id_from_params(params: &LiquidityPoolParameters) -> PoolId {
        let xdr = params.to_xdr(Limits::none()).expect("pool params xdr");
        let mut hasher = Sha256::new();
        hasher.update(&xdr);
        PoolId(Hash(hasher.finalize().into()))
    }

    fn trustline_with_pool_use_count(
        account_id: AccountId,
        asset: TrustLineAsset,
        balance: i64,
        limit: i64,
        flags: u32,
        pool_use_count: i32,
    ) -> TrustLineEntry {
        TrustLineEntry {
            account_id,
            asset,
            balance,
            limit,
            flags,
            ext: TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: TrustLineEntryV1Ext::V2(TrustLineEntryExtensionV2 {
                    liquidity_pool_use_count: pool_use_count,
                    ext: TrustLineEntryExtensionV2Ext::V0,
                }),
            }),
        }
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

    #[test]
    fn test_change_trust_create() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 1_000_000_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        // Verify sub-entries increased
        assert_eq!(state.get_account(&source_id).unwrap().num_sub_entries, 1);
    }

    #[test]
    fn test_change_trust_invalid_limit_no_trustline() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 0,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::InvalidLimit));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_no_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::NoIssuer));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_self_issuer_malformed_protocol_16_plus() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 23;

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: source_id.clone(),
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::Malformed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_self_issuer_not_allowed_pre_16() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 15;

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: source_id.clone(),
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::SelfNotAllowed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_limit_below_buying_liabilities_or_delete() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        let min_balance = state
            .minimum_balance_with_counts(context.protocol_version, 0, 0, 0)
            .unwrap();
        state.create_account(create_test_account(
            source_id.clone(),
            min_balance + 20_000_000,
        ));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"IDR\0"),
            issuer: issuer_id.clone(),
        };
        let trust_asset = Asset::CreditAlphanum4(asset.clone());
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(asset.clone()),
            0,
            1_000,
            TrustLineFlags::AuthorizedFlag as u32,
        ));
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 1;

        let offer = ManageSellOfferOp {
            selling: Asset::Native,
            buying: trust_asset.clone(),
            amount: 500,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };
        let offer_result =
            execute_manage_sell_offer(&offer, &source_id, &mut state, &context).unwrap();
        match offer_result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)), "{r:?}");
            }
            other => panic!("unexpected result: {:?}", other),
        }

        let reduce_ok = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset.clone()),
            limit: 500,
        };
        let reduce_ok_res = execute_change_trust(&reduce_ok, &source_id, &mut state, &context);
        match reduce_ok_res.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::Success));
            }
            other => panic!("unexpected result: {:?}", other),
        }

        let reduce_bad = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset.clone()),
            limit: 499,
        };
        let reduce_bad_res = execute_change_trust(&reduce_bad, &source_id, &mut state, &context);
        match reduce_bad_res.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::InvalidLimit));
            }
            other => panic!("unexpected result: {:?}", other),
        }

        let delete_bad = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 0,
        };
        let delete_bad_res = execute_change_trust(&delete_bad, &source_id, &mut state, &context);
        match delete_bad_res.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::InvalidLimit));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_native_asset_malformed() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::Native,
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::Malformed));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_delete_with_balance_invalid() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        };

        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(asset.clone()),
            100,
            1_000,
            TrustLineFlags::AuthorizedFlag as u32,
        ));
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 1;

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 0,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::InvalidLimit));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_limit_below_balance() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id.clone(),
        };

        let trustline = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(asset.clone()),
            balance: 500,
            limit: 1_000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 1;

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 100,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::InvalidLimit));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_sets_authorized_flag() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account_with_flags(
            issuer_id.clone(),
            100_000_000,
            0,
        ));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id.clone(),
        };

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset.clone()),
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let trustline = state.get_trustline(&source_id, &Asset::CreditAlphanum4(asset));
        assert!(trustline.is_some());
        let flags = trustline.unwrap().flags;
        assert!(flags & TrustLineFlags::AuthorizedFlag as u32 != 0);
    }

    #[test]
    fn test_change_trust_pool_share_creates_pool() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_a = create_test_account_id(1);
        let issuer_b = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_a.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

        let asset_a = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_a,
        });
        let asset_b = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"EUR\0"),
            issuer: issuer_b,
        });

        let trustline_a = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(match &asset_a {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            balance: 0,
            limit: 10_000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        let trustline_b = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(match &asset_b {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            balance: 0,
            limit: 10_000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline_a);
        state.create_trustline(trustline_b);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 2;

        let params =
            LiquidityPoolParameters::LiquidityPoolConstantProduct(LiquidityPoolConstantProductParameters {
                asset_a: asset_a.clone(),
                asset_b: asset_b.clone(),
                fee: 30,
            });
        let pool_id = pool_id_from_params(&params);
        let op = ChangeTrustOp {
            line: ChangeTrustAsset::PoolShare(params),
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let pool = state.get_liquidity_pool(&pool_id);
        assert!(pool.is_some());
        let tl_asset = TrustLineAsset::PoolShare(pool_id.clone());
        let trustline = state.get_trustline_by_trustline_asset(&source_id, &tl_asset);
        assert!(trustline.is_some());
    }

    #[test]
    fn test_change_trust_cannot_delete_with_pool_use_count() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_id,
        };
        let trustline = trustline_with_pool_use_count(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(asset.clone()),
            0,
            1_000,
            TrustLineFlags::AuthorizedFlag as u32,
            1,
        );
        state.create_trustline(trustline);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 1;

        let op = ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset),
            limit: 0,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ChangeTrust(r)) => {
                assert!(matches!(r, ChangeTrustResult::CannotDelete));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_change_trust_pool_share_increments_use_count() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_a = create_test_account_id(1);
        let issuer_b = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_a.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_b.clone(), 100_000_000));

        let asset_a = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_a,
        });
        let asset_b = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"EUR\0"),
            issuer: issuer_b,
        });

        let tl_a = trustline_with_pool_use_count(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(match &asset_a {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            0,
            10_000,
            TrustLineFlags::AuthorizedFlag as u32,
            0,
        );
        let tl_b = trustline_with_pool_use_count(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(match &asset_b {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            0,
            10_000,
            TrustLineFlags::AuthorizedFlag as u32,
            0,
        );
        state.create_trustline(tl_a);
        state.create_trustline(tl_b);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 2;

        let params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
            LiquidityPoolConstantProductParameters {
                asset_a: asset_a.clone(),
                asset_b: asset_b.clone(),
                fee: 30,
            },
        );
        let op = ChangeTrustOp {
            line: ChangeTrustAsset::PoolShare(params),
            limit: 1_000,
        };

        let result = execute_change_trust(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let tl_a_after = state.get_trustline(&source_id, &asset_a).unwrap();
        let tl_b_after = state.get_trustline(&source_id, &asset_b).unwrap();
        assert_eq!(liquidity_pool_use_count(tl_a_after), 1);
        assert_eq!(liquidity_pool_use_count(tl_b_after), 1);
    }
}
