//! Liquidity Pool operation execution.
//!
//! This module implements the execution logic for:
//! - LiquidityPoolDeposit
//! - LiquidityPoolWithdraw

use stellar_xdr::curr::{
    AccountId, Asset, LiquidityPoolDepositOp, LiquidityPoolDepositResult,
    LiquidityPoolDepositResultCode, LiquidityPoolWithdrawOp,
    LiquidityPoolWithdrawResult, LiquidityPoolWithdrawResultCode, OperationResult,
    OperationResultTr, Price, TrustLineAsset, TrustLineFlags,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::Result;

/// Execute a LiquidityPoolDeposit operation.
///
/// This operation deposits assets into a liquidity pool in exchange for
/// pool shares.
pub fn execute_liquidity_pool_deposit(
    op: &LiquidityPoolDepositOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate amounts
    if op.max_amount_a <= 0 || op.max_amount_b <= 0 {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Malformed));
    }

    // Check min/max price bounds
    if op.min_price.n <= 0
        || op.min_price.d <= 0
        || op.max_price.n <= 0
        || op.max_price.d <= 0
    {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Malformed));
    }

    // minPrice must not exceed maxPrice
    if (op.min_price.n as i128) * (op.max_price.d as i128)
        > (op.min_price.d as i128) * (op.max_price.n as i128)
    {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Malformed));
    }

    // Get the liquidity pool
    let pool = match state.get_liquidity_pool(&op.liquidity_pool_id) {
        Some(p) => p.clone(),
        None => {
            return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
        }
    };

    // Get pool parameters
    let (asset_a, asset_b, reserve_a, reserve_b, total_shares, _fee) = match &pool.body {
        stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
            let params = &cp.params;
            (
                params.asset_a.clone(),
                params.asset_b.clone(),
                cp.reserve_a,
                cp.reserve_b,
                cp.total_pool_shares,
                params.fee,
            )
        }
    };

    // Check source has pool share trustline
    let pool_share_asset = TrustLineAsset::PoolShare(op.liquidity_pool_id.clone());
    let pool_share_trustline =
        match state.get_trustline_by_trustline_asset(source, &pool_share_asset) {
            Some(tl) => tl,
            None => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
            }
        };

    // Check source has trustlines for both assets (unless native)
    let trustline_a = if matches!(&asset_a, Asset::Native) {
        None
    } else {
        match state.get_trustline(source, &asset_a) {
            Some(tl) => Some(tl),
            None => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
            }
        }
    };

    let trustline_b = if matches!(&asset_b, Asset::Native) {
        None
    } else {
        match state.get_trustline(source, &asset_b) {
            Some(tl) => Some(tl),
            None => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::NoTrust));
            }
        }
    };

    if is_auth_required(&asset_a, state)
        && trustline_a
            .map(|tl| !is_trustline_authorized(tl.flags))
            .unwrap_or(false)
    {
        return Ok(make_deposit_result(
            LiquidityPoolDepositResultCode::NotAuthorized,
        ));
    }

    if is_auth_required(&asset_b, state)
        && trustline_b
            .map(|tl| !is_trustline_authorized(tl.flags))
            .unwrap_or(false)
    {
        return Ok(make_deposit_result(
            LiquidityPoolDepositResultCode::NotAuthorized,
        ));
    }

    let available_a = match &asset_a {
        Asset::Native => available_native_balance(source, state, context)?,
        _ => trustline_a.map(|tl| tl.balance).unwrap_or(0),
    };
    let available_b = match &asset_b {
        Asset::Native => available_native_balance(source, state, context)?,
        _ => trustline_b.map(|tl| tl.balance).unwrap_or(0),
    };
    let available_pool_share_limit = pool_share_trustline
        .limit
        .saturating_sub(pool_share_trustline.balance);

    let (deposit_a, deposit_b, shares_received) = if total_shares == 0 {
        match deposit_into_empty_pool(
            op.max_amount_a,
            op.max_amount_b,
            available_a,
            available_b,
            available_pool_share_limit,
            &op.min_price,
            &op.max_price,
        )? {
            DepositOutcome::Success { a, b, shares } => (a, b, shares),
            DepositOutcome::Underfunded => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Underfunded));
            }
            DepositOutcome::BadPrice => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::BadPrice));
            }
            DepositOutcome::LineFull => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::LineFull));
            }
        }
    } else {
        match deposit_into_non_empty_pool(
            op.max_amount_a,
            op.max_amount_b,
            available_a,
            available_b,
            available_pool_share_limit,
            reserve_a,
            reserve_b,
            total_shares,
            &op.min_price,
            &op.max_price,
        )? {
            DepositOutcome::Success { a, b, shares } => (a, b, shares),
            DepositOutcome::Underfunded => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::Underfunded));
            }
            DepositOutcome::BadPrice => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::BadPrice));
            }
            DepositOutcome::LineFull => {
                return Ok(make_deposit_result(LiquidityPoolDepositResultCode::LineFull));
            }
        }
    };

    if i64::MAX - reserve_a < deposit_a
        || i64::MAX - reserve_b < deposit_b
        || i64::MAX - total_shares < shares_received
    {
        return Ok(make_deposit_result(LiquidityPoolDepositResultCode::PoolFull));
    }

    // Deduct assets from source
    if matches!(&asset_a, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            if account.balance < deposit_a {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            account.balance -= deposit_a;
        }
    } else {
        if let Some(tl) = state.get_trustline_mut(source, &asset_a) {
            if tl.balance < deposit_a {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            tl.balance -= deposit_a;
        }
    }

    if matches!(&asset_b, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            if account.balance < deposit_b {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            account.balance -= deposit_b;
        }
    } else {
        if let Some(tl) = state.get_trustline_mut(source, &asset_b) {
            if tl.balance < deposit_b {
                return Ok(make_deposit_result(
                    LiquidityPoolDepositResultCode::Underfunded,
                ));
            }
            tl.balance -= deposit_b;
        }
    }

    // Credit pool shares to source
    if let Some(tl) = state.get_trustline_by_trustline_asset_mut(source, &pool_share_asset) {
        tl.balance += shares_received;
    }

    // Update pool reserves
    if let Some(pool_mut) = state.get_liquidity_pool_mut(&op.liquidity_pool_id) {
        match &mut pool_mut.body {
            stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                cp.reserve_a += deposit_a;
                cp.reserve_b += deposit_b;
                cp.total_pool_shares += shares_received;
            }
        }
    }

    Ok(make_deposit_result(LiquidityPoolDepositResultCode::Success))
}

/// Execute a LiquidityPoolWithdraw operation.
///
/// This operation withdraws assets from a liquidity pool by redeeming
/// pool shares.
pub fn execute_liquidity_pool_withdraw(
    op: &LiquidityPoolWithdrawOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    _context: &LedgerContext,
) -> Result<OperationResult> {
    // Validate amounts
    if op.amount <= 0 {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::Malformed,
        ));
    }

    if op.min_amount_a < 0 || op.min_amount_b < 0 {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::Malformed,
        ));
    }

    // Get the liquidity pool
    let pool = match state.get_liquidity_pool(&op.liquidity_pool_id) {
        Some(p) => p.clone(),
        None => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
    };

    // Get pool parameters
    let (asset_a, asset_b, reserve_a, reserve_b, total_shares) = match &pool.body {
        stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
            let params = &cp.params;
            (
                params.asset_a.clone(),
                params.asset_b.clone(),
                cp.reserve_a,
                cp.reserve_b,
                cp.total_pool_shares,
            )
        }
    };

    // Check source has pool share trustline with sufficient balance
    let pool_share_asset = TrustLineAsset::PoolShare(op.liquidity_pool_id.clone());
    let shares_balance = match state.get_trustline_by_trustline_asset(source, &pool_share_asset) {
        Some(tl) => tl.balance,
        None => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
    };

    if shares_balance < op.amount {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::Underfunded,
        ));
    }

    let withdraw_a = get_pool_withdrawal_amount(op.amount, total_shares, reserve_a);
    let withdraw_b = get_pool_withdrawal_amount(op.amount, total_shares, reserve_b);

    if withdraw_a < op.min_amount_a || withdraw_b < op.min_amount_b {
        return Ok(make_withdraw_result(
            LiquidityPoolWithdrawResultCode::UnderMinimum,
        ));
    }

    match can_credit_asset(state, source, &asset_a, withdraw_a) {
        WithdrawAssetCheck::Ok => {}
        WithdrawAssetCheck::NoTrust => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
        WithdrawAssetCheck::LineFull => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::LineFull));
        }
    }

    match can_credit_asset(state, source, &asset_b, withdraw_b) {
        WithdrawAssetCheck::Ok => {}
        WithdrawAssetCheck::NoTrust => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::NoTrust));
        }
        WithdrawAssetCheck::LineFull => {
            return Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::LineFull));
        }
    }

    credit_asset(state, source, &asset_a, withdraw_a);
    credit_asset(state, source, &asset_b, withdraw_b);

    // Deduct pool shares from source
    if let Some(tl) = state.get_trustline_by_trustline_asset_mut(source, &pool_share_asset) {
        tl.balance -= op.amount;
    }

    // Update pool reserves
    if let Some(pool_mut) = state.get_liquidity_pool_mut(&op.liquidity_pool_id) {
        match &mut pool_mut.body {
            stellar_xdr::curr::LiquidityPoolEntryBody::LiquidityPoolConstantProduct(cp) => {
                cp.reserve_a -= withdraw_a;
                cp.reserve_b -= withdraw_b;
                cp.total_pool_shares -= op.amount;
            }
        }
    }

    Ok(make_withdraw_result(LiquidityPoolWithdrawResultCode::Success))
}

const AUTH_REQUIRED_FLAG: u32 = 0x1;
const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;
const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 =
    TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;

fn is_trustline_authorized(flags: u32) -> bool {
    flags & AUTHORIZED_FLAG != 0
}

fn is_trustline_authorized_to_maintain_liabilities(flags: u32) -> bool {
    flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
}

fn is_auth_required(asset: &Asset, state: &LedgerStateManager) -> bool {
    let issuer = match asset {
        Asset::Native => return false,
        Asset::CreditAlphanum4(a) => &a.issuer,
        Asset::CreditAlphanum12(a) => &a.issuer,
    };
    state
        .get_account(issuer)
        .map(|account| account.flags & AUTH_REQUIRED_FLAG != 0)
        .unwrap_or(false)
}

fn available_native_balance(
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
) -> Result<i64> {
    let Some(account) = state.get_account(source) else {
        return Ok(0);
    };
    let min_balance =
        state.minimum_balance_for_account(account, context.protocol_version, 0)?;
    Ok(account.balance.saturating_sub(min_balance))
}

fn is_bad_price(amount_a: i64, amount_b: i64, min_price: &Price, max_price: &Price) -> bool {
    if amount_a == 0 || amount_b == 0 {
        return true;
    }

    let amount_a = amount_a as i128;
    let amount_b = amount_b as i128;
    let min_n = min_price.n as i128;
    let min_d = min_price.d as i128;
    let max_n = max_price.n as i128;
    let max_d = max_price.d as i128;

    amount_a * min_d < amount_b * min_n || amount_a * max_d > amount_b * max_n
}

enum DepositOutcome {
    Success { a: i64, b: i64, shares: i64 },
    Underfunded,
    BadPrice,
    LineFull,
}

fn deposit_into_empty_pool(
    max_amount_a: i64,
    max_amount_b: i64,
    available_a: i64,
    available_b: i64,
    available_pool_share_limit: i64,
    min_price: &Price,
    max_price: &Price,
) -> Result<DepositOutcome> {
    if available_a < max_amount_a || available_b < max_amount_b {
        return Ok(DepositOutcome::Underfunded);
    }

    if is_bad_price(max_amount_a, max_amount_b, min_price, max_price) {
        return Ok(DepositOutcome::BadPrice);
    }

    let shares = big_square_root(max_amount_a, max_amount_b);
    if available_pool_share_limit < shares {
        return Ok(DepositOutcome::LineFull);
    }

    Ok(DepositOutcome::Success {
        a: max_amount_a,
        b: max_amount_b,
        shares,
    })
}

fn deposit_into_non_empty_pool(
    max_amount_a: i64,
    max_amount_b: i64,
    available_a: i64,
    available_b: i64,
    available_pool_share_limit: i64,
    reserve_a: i64,
    reserve_b: i64,
    total_shares: i64,
    min_price: &Price,
    max_price: &Price,
) -> Result<DepositOutcome> {
    let shares_a = big_divide(total_shares, max_amount_a, reserve_a, Round::Down)?;
    let shares_b = big_divide(total_shares, max_amount_b, reserve_b, Round::Down)?;
    let pool_shares = shares_a.min(shares_b);

    let amount_a = big_divide(pool_shares, reserve_a, total_shares, Round::Up)?;
    let amount_b = big_divide(pool_shares, reserve_b, total_shares, Round::Up)?;

    if available_a < amount_a || available_b < amount_b {
        return Ok(DepositOutcome::Underfunded);
    }

    if is_bad_price(amount_a, amount_b, min_price, max_price) {
        return Ok(DepositOutcome::BadPrice);
    }

    if available_pool_share_limit < pool_shares {
        return Ok(DepositOutcome::LineFull);
    }

    Ok(DepositOutcome::Success {
        a: amount_a,
        b: amount_b,
        shares: pool_shares,
    })
}

fn get_pool_withdrawal_amount(amount: i64, total_shares: i64, reserve: i64) -> i64 {
    big_divide(amount, reserve, total_shares, Round::Down).unwrap_or(0)
}

enum WithdrawAssetCheck {
    Ok,
    NoTrust,
    LineFull,
}

fn can_credit_asset(
    state: &LedgerStateManager,
    source: &AccountId,
    asset: &Asset,
    amount: i64,
) -> WithdrawAssetCheck {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return WithdrawAssetCheck::NoTrust;
        };
        if i64::MAX - account.balance < amount {
            return WithdrawAssetCheck::LineFull;
        }
        return WithdrawAssetCheck::Ok;
    }

    let Some(tl) = state.get_trustline(source, asset) else {
        return WithdrawAssetCheck::NoTrust;
    };
    if !is_trustline_authorized_to_maintain_liabilities(tl.flags) {
        return WithdrawAssetCheck::LineFull;
    }
    if tl.limit - tl.balance < amount {
        return WithdrawAssetCheck::LineFull;
    }
    WithdrawAssetCheck::Ok
}

fn credit_asset(
    state: &mut LedgerStateManager,
    source: &AccountId,
    asset: &Asset,
    amount: i64,
) {
    if matches!(asset, Asset::Native) {
        if let Some(account) = state.get_account_mut(source) {
            account.balance += amount;
        }
        return;
    }

    if let Some(tl) = state.get_trustline_mut(source, asset) {
        tl.balance += amount;
    }
}

#[derive(Clone, Copy)]
enum Round {
    Down,
    Up,
}

fn big_divide(a: i64, b: i64, c: i64, round: Round) -> Result<i64> {
    if c == 0 {
        return Ok(0);
    }
    let numerator = (a as i128) * (b as i128);
    let denominator = c as i128;
    let result = match round {
        Round::Down => numerator / denominator,
        Round::Up => {
            if numerator == 0 {
                0
            } else {
                (numerator + denominator - 1) / denominator
            }
        }
    };
    if result > i64::MAX as i128 {
        return Ok(0);
    }
    Ok(result as i64)
}

fn big_square_root(a: i64, b: i64) -> i64 {
    let product = (a as i128) * (b as i128);
    let mut low: i128 = 0;
    let mut high: i128 = product;
    while low <= high {
        let mid = (low + high) / 2;
        let sq = mid * mid;
        if sq == product {
            return mid as i64;
        }
        if sq < product {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    high.max(0) as i64
}

/// Create a LiquidityPoolDeposit result.
fn make_deposit_result(code: LiquidityPoolDepositResultCode) -> OperationResult {
    let result = match code {
        LiquidityPoolDepositResultCode::Success => LiquidityPoolDepositResult::Success,
        LiquidityPoolDepositResultCode::Malformed => LiquidityPoolDepositResult::Malformed,
        LiquidityPoolDepositResultCode::NoTrust => LiquidityPoolDepositResult::NoTrust,
        LiquidityPoolDepositResultCode::NotAuthorized => LiquidityPoolDepositResult::NotAuthorized,
        LiquidityPoolDepositResultCode::Underfunded => LiquidityPoolDepositResult::Underfunded,
        LiquidityPoolDepositResultCode::LineFull => LiquidityPoolDepositResult::LineFull,
        LiquidityPoolDepositResultCode::BadPrice => LiquidityPoolDepositResult::BadPrice,
        LiquidityPoolDepositResultCode::PoolFull => LiquidityPoolDepositResult::PoolFull,
    };

    OperationResult::OpInner(OperationResultTr::LiquidityPoolDeposit(result))
}

/// Create a LiquidityPoolWithdraw result.
fn make_withdraw_result(code: LiquidityPoolWithdrawResultCode) -> OperationResult {
    let result = match code {
        LiquidityPoolWithdrawResultCode::Success => LiquidityPoolWithdrawResult::Success,
        LiquidityPoolWithdrawResultCode::Malformed => LiquidityPoolWithdrawResult::Malformed,
        LiquidityPoolWithdrawResultCode::NoTrust => LiquidityPoolWithdrawResult::NoTrust,
        LiquidityPoolWithdrawResultCode::Underfunded => LiquidityPoolWithdrawResult::Underfunded,
        LiquidityPoolWithdrawResultCode::LineFull => LiquidityPoolWithdrawResult::LineFull,
        LiquidityPoolWithdrawResultCode::UnderMinimum => LiquidityPoolWithdrawResult::UnderMinimum,
    };

    OperationResult::OpInner(OperationResultTr::LiquidityPoolWithdraw(result))
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

    fn create_test_context() -> LedgerContext {
        LedgerContext::testnet(1, 1000)
    }

    fn create_pool_entry(
        pool_id: PoolId,
        asset_a: Asset,
        asset_b: Asset,
        reserve_a: i64,
        reserve_b: i64,
        total_shares: i64,
    ) -> LiquidityPoolEntry {
        LiquidityPoolEntry {
            liquidity_pool_id: pool_id,
            body: LiquidityPoolEntryBody::LiquidityPoolConstantProduct(
                LiquidityPoolEntryConstantProduct {
                    params: LiquidityPoolConstantProductParameters {
                        asset_a,
                        asset_b,
                        fee: 30,
                    },
                    reserve_a,
                    reserve_b,
                    total_pool_shares: total_shares,
                    pool_shares_trust_line_count: 1,
                },
            ),
        }
    }

    #[test]
    fn test_liquidity_pool_deposit_no_pool() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);

        let op = LiquidityPoolDepositOp {
            liquidity_pool_id: PoolId(Hash([0u8; 32])),
            max_amount_a: 1000,
            max_amount_b: 1000,
            min_price: Price { n: 1, d: 2 },
            max_price: Price { n: 2, d: 1 },
        };

        let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolDeposit(r)) => {
                assert!(matches!(r, LiquidityPoolDepositResult::NoTrust));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_liquidity_pool_withdraw_no_pool() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);

        let op = LiquidityPoolWithdrawOp {
            liquidity_pool_id: PoolId(Hash([0u8; 32])),
            amount: 100,
            min_amount_a: 0,
            min_amount_b: 0,
        };

        let result = execute_liquidity_pool_withdraw(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolWithdraw(r)) => {
                assert!(matches!(r, LiquidityPoolWithdrawResult::NoTrust));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_liquidity_pool_deposit_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_a = create_test_account_id(1);
        let issuer_b = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(issuer_a.clone(), 100_000_000, AUTH_REQUIRED_FLAG));
        state.create_account(create_test_account(issuer_b.clone(), 100_000_000, 0));

        let asset_a = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_a,
        });
        let asset_b = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"EUR\0"),
            issuer: issuer_b,
        });
        let pool_id = PoolId(Hash([1u8; 32]));
        state.create_liquidity_pool(create_pool_entry(
            pool_id.clone(),
            asset_a.clone(),
            asset_b.clone(),
            0,
            0,
            0,
        ));

        let trustline_a = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(match &asset_a {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            balance: 1_000,
            limit: 10_000,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        let trustline_b = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(match &asset_b {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            balance: 1_000,
            limit: 10_000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        let pool_share_tl = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::PoolShare(pool_id.clone()),
            balance: 0,
            limit: 10_000,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline_a);
        state.create_trustline(trustline_b);
        state.create_trustline(pool_share_tl);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 3;

        let op = LiquidityPoolDepositOp {
            liquidity_pool_id: pool_id,
            max_amount_a: 100,
            max_amount_b: 100,
            min_price: Price { n: 1, d: 1 },
            max_price: Price { n: 1, d: 1 },
        };

        let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolDeposit(r)) => {
                assert!(matches!(r, LiquidityPoolDepositResult::NotAuthorized));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_liquidity_pool_deposit_line_full() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_a = create_test_account_id(1);
        let issuer_b = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(issuer_a.clone(), 100_000_000, 0));
        state.create_account(create_test_account(issuer_b.clone(), 100_000_000, 0));

        let asset_a = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_a,
        });
        let asset_b = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"EUR\0"),
            issuer: issuer_b,
        });
        let pool_id = PoolId(Hash([2u8; 32]));
        state.create_liquidity_pool(create_pool_entry(
            pool_id.clone(),
            asset_a.clone(),
            asset_b.clone(),
            0,
            0,
            0,
        ));

        let trustline_a = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(match &asset_a {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            balance: 1_000,
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
            balance: 1_000,
            limit: 10_000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        let pool_share_tl = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::PoolShare(pool_id.clone()),
            balance: 0,
            limit: 1,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline_a);
        state.create_trustline(trustline_b);
        state.create_trustline(pool_share_tl);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 3;

        let op = LiquidityPoolDepositOp {
            liquidity_pool_id: pool_id,
            max_amount_a: 100,
            max_amount_b: 100,
            min_price: Price { n: 1, d: 1 },
            max_price: Price { n: 1, d: 1 },
        };

        let result = execute_liquidity_pool_deposit(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolDeposit(r)) => {
                assert!(matches!(r, LiquidityPoolDepositResult::LineFull));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_liquidity_pool_withdraw_line_full() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_a = create_test_account_id(1);
        let issuer_b = create_test_account_id(2);
        state.create_account(create_test_account(source_id.clone(), 100_000_000, 0));
        state.create_account(create_test_account(issuer_a.clone(), 100_000_000, 0));
        state.create_account(create_test_account(issuer_b.clone(), 100_000_000, 0));

        let asset_a = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: issuer_a,
        });
        let asset_b = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"EUR\0"),
            issuer: issuer_b,
        });
        let pool_id = PoolId(Hash([3u8; 32]));
        state.create_liquidity_pool(create_pool_entry(
            pool_id.clone(),
            asset_a.clone(),
            asset_b.clone(),
            100,
            100,
            100,
        ));

        let trustline_a = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::CreditAlphanum4(match &asset_a {
                Asset::CreditAlphanum4(a) => a.clone(),
                _ => unreachable!(),
            }),
            balance: 10,
            limit: 10,
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
            limit: 1_000,
            flags: TrustLineFlags::AuthorizedFlag as u32,
            ext: TrustLineEntryExt::V0,
        };
        let pool_share_tl = TrustLineEntry {
            account_id: source_id.clone(),
            asset: TrustLineAsset::PoolShare(pool_id.clone()),
            balance: 10,
            limit: 10_000,
            flags: 0,
            ext: TrustLineEntryExt::V0,
        };
        state.create_trustline(trustline_a);
        state.create_trustline(trustline_b);
        state.create_trustline(pool_share_tl);
        state.get_account_mut(&source_id).unwrap().num_sub_entries += 3;

        let op = LiquidityPoolWithdrawOp {
            liquidity_pool_id: pool_id,
            amount: 10,
            min_amount_a: 0,
            min_amount_b: 0,
        };

        let result = execute_liquidity_pool_withdraw(&op, &source_id, &mut state, &context);
        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::LiquidityPoolWithdraw(r)) => {
                assert!(matches!(r, LiquidityPoolWithdrawResult::LineFull));
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }
}
