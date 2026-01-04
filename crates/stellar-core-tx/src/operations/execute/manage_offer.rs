//! Manage Offer operation execution.
//!
//! This module implements the execution logic for ManageSellOffer, ManageBuyOffer,
//! and CreatePassiveSellOffer operations for the Stellar DEX.

use std::cmp::Ordering;
use std::collections::HashSet;

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1, AccountEntryExtensionV1Ext, AccountId,
    Asset, ClaimAtom, ClaimOfferAtom, CreatePassiveSellOfferOp, Liabilities, ManageBuyOfferOp,
    ManageOfferSuccessResult, ManageOfferSuccessResultOffer, ManageSellOfferOp,
    ManageSellOfferResult, ManageSellOfferResultCode, OfferEntry, OfferEntryExt, OfferEntryFlags,
    OperationResult, OperationResultTr, Price, TrustLineEntry, TrustLineEntryExt, TrustLineEntryV1,
    TrustLineEntryV1Ext, TrustLineFlags, LedgerKey, LedgerKeyOffer,
};

use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use crate::{Result, TxError};
use super::offer_exchange::{
    adjust_offer_amount, exchange_v10, exchange_v10_without_price_error_thresholds, ExchangeError,
    RoundingType,
};

/// Execute a ManageSellOffer operation.
///
/// This operation creates, updates, or deletes an offer to sell one asset for another.
pub fn execute_manage_sell_offer(
    op: &ManageSellOfferOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    execute_manage_offer(
        source,
        &op.selling,
        &op.buying,
        op.offer_id,
        &op.price,
        OfferKind::Sell { amount: op.amount },
        false,
        state,
        context,
    )
}

fn execute_manage_offer(
    source: &AccountId,
    selling: &Asset,
    buying: &Asset,
    offer_id: i64,
    price: &Price,
    offer_kind: OfferKind,
    passive: bool,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let offer_amount = offer_kind.amount();

    // Validate the offer parameters
    if let Err(code) = validate_offer(selling, buying, offer_amount, price) {
        return Ok(make_sell_offer_result(code, None));
    }

    // Check if this is a delete operation (amount = 0 with existing offer_id)
    if offer_amount == 0 {
        if offer_id == 0 {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::Malformed,
                None,
            ));
        }
        return delete_offer(source, offer_id, state);
    }

    // Check source account exists
    if state.get_account(source).is_none() {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::Underfunded,
            None,
        ));
    }

    if context.protocol_version < 13 {
        if let Some(issuer) = issuer_for_asset(selling) {
            if state.get_account(issuer).is_none() {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::SellNoIssuer,
                    None,
                ));
            }
        }

        if let Some(issuer) = issuer_for_asset(buying) {
            if state.get_account(issuer).is_none() {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::BuyNoIssuer,
                    None,
                ));
            }
        }
    }

    let old_offer = if offer_id != 0 {
        state.get_offer(source, offer_id).cloned()
    } else {
        None
    };
    if offer_id != 0 && old_offer.is_none() {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::NotFound,
            None,
        ));
    }
    let sponsor = if old_offer.is_none() {
        state.active_sponsor_for(source)
    } else {
        None
    };
    let reserve_subentry = old_offer.is_none() && sponsor.is_none();

    // For selling non-native assets, check trustline exists and has balance
    if !matches!(selling, Asset::Native) {
        if issuer_for_asset(selling) == Some(source) {
            // Issuer can always sell its own asset.
        } else {
        let trustline = match state.get_trustline(source, selling) {
            Some(tl) => tl,
            None => {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::SellNoTrust,
                    None,
                ));
            }
        };

        if !is_trustline_authorized(trustline.flags) {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::SellNotAuthorized,
                None,
            ));
        }
        }
    } else {
        // For native asset, check account exists
        let account = state.get_account(source).unwrap();
        let min_balance = state.minimum_balance_for_account(
            account,
            context.protocol_version,
            if reserve_subentry { 1 } else { 0 },
        )?;
        if account.balance < min_balance {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::Underfunded,
                None,
            ));
        }
    }

    // For buying non-native assets, check trustline exists
    if !matches!(buying, Asset::Native) {
        if issuer_for_asset(buying) == Some(source) {
            // Issuer can always receive its own asset.
        } else {
        let trustline = match state.get_trustline(source, buying) {
            Some(tl) => tl,
            None => {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::BuyNoTrust,
                    None,
                ));
            }
        };

        if !is_trustline_authorized(trustline.flags) {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::BuyNotAuthorized,
                None,
            ));
        }
        }
    }

    if old_offer.is_none() {
        if let Some(sponsor) = &sponsor {
            let sponsor_account = state
                .get_account(sponsor)
                .ok_or(TxError::SourceAccountNotFound)?;
            let min_balance = state.minimum_balance_for_account_with_deltas(
                sponsor_account,
                context.protocol_version,
                0,
                1,
                0,
            )?;
            if sponsor_account.balance < min_balance {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::LowReserve,
                    None,
                ));
            }
        } else if let Some(account) = state.get_account(source) {
            let min_balance =
                state.minimum_balance_for_account(account, context.protocol_version, 1)?;
            if account.balance < min_balance {
                return Ok(make_sell_offer_result(
                    ManageSellOfferResultCode::LowReserve,
                    None,
                ));
            }
        }
    }

    let (mut offer_flags, was_passive) = if let Some(old) = &old_offer {
        (old.flags, (old.flags & (OfferEntryFlags::PassiveFlag as u32)) != 0)
    } else {
        (0, false)
    };
    let passive = if old_offer.is_some() { was_passive } else { passive };

    if passive {
        offer_flags |= OfferEntryFlags::PassiveFlag as u32;
    }

    if let Some(old) = &old_offer {
        let (old_selling, old_buying) = offer_liabilities_sell(old.amount, &old.price)?;
        apply_liabilities_delta(
            source,
            &old.selling,
            &old.buying,
            -old_selling,
            -old_buying,
            state,
        )?;
    }

    let (selling_liab, buying_liab) = offer_kind.offer_liabilities(price)?;
    if !has_selling_capacity(
        source,
        selling,
        selling_liab,
        0,
        reserve_subentry,
        state,
        context,
    )? {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::Underfunded,
            None,
        ));
    }

    if !has_buying_capacity(source, buying, buying_liab, 0, state) {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::LineFull,
            None,
        ));
    }

    let mut max_sheep_send = can_sell_at_most(source, selling, state, context)?;
    let mut max_wheat_receive = can_buy_at_most(source, buying, state);
    offer_kind.apply_limits(&mut max_sheep_send, 0, &mut max_wheat_receive, 0);
    if max_wheat_receive == 0 {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::LineFull,
            None,
        ));
    }

    let mut offer_trail = Vec::new();
    let mut sheep_sent = 0;
    let mut wheat_received = 0;
    let max_wheat_price = Price {
        n: price.d,
        d: price.n,
    };

    let convert_res = convert_with_offers(
        source,
        selling,
        max_sheep_send,
        &mut sheep_sent,
        buying,
        max_wheat_receive,
        &mut wheat_received,
        RoundingType::Normal,
        offer_id,
        passive,
        &max_wheat_price,
        &mut offer_trail,
        state,
        context,
    )?;

    let sheep_stays = match convert_res {
        ConvertResult::Ok => false,
        ConvertResult::Partial => true,
        ConvertResult::FilterStopBadPrice => true,
        ConvertResult::FilterStopCrossSelf => {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::CrossSelf,
                None,
            ));
        }
        ConvertResult::CrossedTooMany => {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::Malformed,
                None,
            ));
        }
    };

    if wheat_received > 0 {
        apply_balance_delta(source, buying, wheat_received, state)?;
        apply_balance_delta(source, selling, -sheep_sent, state)?;
    }

    let amount = if sheep_stays {
        let mut sheep_limit = can_sell_at_most(source, selling, state, context)?;
        let mut wheat_limit = can_buy_at_most(source, buying, state);
        offer_kind.apply_limits(
            &mut sheep_limit,
            sheep_sent,
            &mut wheat_limit,
            wheat_received,
        );
        adjust_offer_amount(price.clone(), sheep_limit, wheat_limit)
            .map_err(map_exchange_error)?
    } else {
        0
    };

    let result = if amount > 0 {
        let offer_id = if old_offer.is_none() {
            generate_offer_id(state)
        } else {
            offer_id
        };
        let offer = OfferEntry {
            seller_id: source.clone(),
            offer_id,
            selling: selling.clone(),
            buying: buying.clone(),
            amount,
            price: price.clone(),
            flags: offer_flags,
            ext: OfferEntryExt::V0,
        };

        if old_offer.is_none() {
            state.create_offer(offer);
            if let Some(account) = state.get_account_mut(source) {
                account.num_sub_entries += 1;
            }
            if let Some(sponsor) = sponsor {
                let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
                    seller_id: source.clone(),
                    offer_id,
                });
                state.apply_entry_sponsorship_with_sponsor(
                    ledger_key,
                    &sponsor,
                    Some(source),
                    1,
                )?;
            }
            ManageOfferSuccessResultOffer::Created(create_offer_entry(
                source, offer_id, selling, buying, amount, price,
            ))
        } else {
            state.update_offer(offer);
            ManageOfferSuccessResultOffer::Updated(create_offer_entry(
                source, offer_id, selling, buying, amount, price,
            ))
        }
    } else {
        if old_offer.is_some() {
            let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
                seller_id: source.clone(),
                offer_id,
            });
            if state.entry_sponsor(&ledger_key).is_some() {
                state.remove_entry_sponsorship_and_update_counts(&ledger_key, source, 1)?;
            }
            state.delete_offer(source, offer_id);
            if let Some(account) = state.get_account_mut(source) {
                if account.num_sub_entries > 0 {
                    account.num_sub_entries -= 1;
                }
            }
        }
        ManageOfferSuccessResultOffer::Deleted
    };

    if amount > 0 {
        let (new_selling, new_buying) = offer_liabilities_sell(amount, price)?;
        apply_liabilities_delta(
            source,
            selling,
            buying,
            new_selling,
            new_buying,
            state,
        )?;
    }

    let success = ManageOfferSuccessResult {
        offers_claimed: offer_trail.try_into().unwrap(),
        offer: result,
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Execute a ManageBuyOffer operation.
///
/// This operation creates, updates, or deletes an offer to buy one asset with another.
pub fn execute_manage_buy_offer(
    op: &ManageBuyOfferOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let effective_price = invert_price(&op.price);

    let result = execute_manage_offer(
        source,
        &op.selling,
        &op.buying,
        op.offer_id,
        &effective_price,
        OfferKind::Buy {
            buy_amount: op.buy_amount,
        },
        false,
        state,
        context,
    )?;

    match result {
        OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => Ok(
            OperationResult::OpInner(OperationResultTr::ManageBuyOffer(convert_sell_to_buy_result(
                r,
            ))),
        ),
        other => Ok(other),
    }
}

/// Execute a CreatePassiveSellOffer operation.
///
/// This operation creates a passive sell offer that doesn't cross existing offers.
pub fn execute_create_passive_sell_offer(
    op: &CreatePassiveSellOfferOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    execute_manage_offer(
        source,
        &op.selling,
        &op.buying,
        0,
        &op.price,
        OfferKind::Sell { amount: op.amount },
        true,
        state,
        context,
    )
}

#[derive(Clone, Copy, Debug)]
enum OfferKind {
    Sell { amount: i64 },
    Buy { buy_amount: i64 },
}

impl OfferKind {
    fn amount(self) -> i64 {
        match self {
            OfferKind::Sell { amount } => amount,
            OfferKind::Buy { buy_amount } => buy_amount,
        }
    }

    fn offer_liabilities(self, price: &Price) -> Result<(i64, i64)> {
        match self {
            OfferKind::Sell { amount } => offer_liabilities_sell(amount, price),
            OfferKind::Buy { buy_amount } => offer_liabilities_buy(buy_amount, price),
        }
    }

    fn apply_limits(
        self,
        max_sheep_send: &mut i64,
        sheep_sent: i64,
        max_wheat_receive: &mut i64,
        wheat_received: i64,
    ) {
        match self {
            OfferKind::Sell { amount } => {
                *max_sheep_send = (*max_sheep_send).min(amount.saturating_sub(sheep_sent));
            }
            OfferKind::Buy { buy_amount } => {
                *max_wheat_receive = (*max_wheat_receive).min(buy_amount.saturating_sub(wheat_received));
            }
        }
    }
}

/// Validate offer parameters.
fn validate_offer(
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
) -> std::result::Result<(), ManageSellOfferResultCode> {
    // Cannot trade an asset for itself
    if selling == buying {
        return Err(ManageSellOfferResultCode::Malformed);
    }

    // Amount must be non-negative (0 is valid for deleting)
    if amount < 0 {
        return Err(ManageSellOfferResultCode::Malformed);
    }

    // Price must be positive
    if price.n <= 0 || price.d <= 0 {
        return Err(ManageSellOfferResultCode::Malformed);
    }

    Ok(())
}

#[allow(dead_code)]
const AUTH_REQUIRED_FLAG: u32 = 0x1;
const AUTHORIZED_FLAG: u32 = TrustLineFlags::AuthorizedFlag as u32;
const AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG: u32 =
    TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag as u32;

fn is_trustline_authorized(flags: u32) -> bool {
    flags & AUTHORIZED_FLAG != 0
}

fn is_authorized_to_maintain_liabilities(flags: u32) -> bool {
    flags & (AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
}

fn issuer_for_asset(asset: &Asset) -> Option<&AccountId> {
    match asset {
        Asset::Native => None,
        Asset::CreditAlphanum4(a) => Some(&a.issuer),
        Asset::CreditAlphanum12(a) => Some(&a.issuer),
    }
}


/// Create a new offer.
#[allow(dead_code)]
fn create_offer(
    source: &AccountId,
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let sponsor = state.active_sponsor_for(source);
    if let Some(sponsor) = &sponsor {
        let sponsor_account = state
            .get_account(sponsor)
            .ok_or(TxError::SourceAccountNotFound)?;
        let min_balance = state.minimum_balance_for_account_with_deltas(
            sponsor_account,
            context.protocol_version,
            0,
            1,
            0,
        )?;
        if sponsor_account.balance < min_balance {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::LowReserve,
                None,
            ));
        }
    } else if let Some(account) = state.get_account(source) {
        let min_balance =
            state.minimum_balance_for_account(account, context.protocol_version, 1)?;
        if account.balance < min_balance {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::LowReserve,
                None,
            ));
        }
    } else {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::Underfunded,
            None,
        ));
    }

    // Generate a new offer ID (in production this should be deterministic based on ledger state)
    let offer_id = generate_offer_id(state);

    let offer = OfferEntry {
        seller_id: source.clone(),
        offer_id,
        selling: selling.clone(),
        buying: buying.clone(),
        amount,
        price: price.clone(),
        flags: 0,
        ext: OfferEntryExt::V0,
    };

    state.create_offer(offer);

    // Increment the source account's sub-entries
    if let Some(account) = state.get_account_mut(source) {
        account.num_sub_entries += 1;
    }
    if let Some(sponsor) = sponsor {
        let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
            seller_id: source.clone(),
            offer_id,
        });
        state.apply_entry_sponsorship_with_sponsor(ledger_key, &sponsor, Some(source), 1)?;
    }

    let success = ManageOfferSuccessResult {
        offers_claimed: vec![].try_into().unwrap(),
        offer: ManageOfferSuccessResultOffer::Created(create_offer_entry(
            source, offer_id, selling, buying, amount, price,
        )),
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Update an existing offer.
#[allow(dead_code)]
fn update_offer(
    source: &AccountId,
    offer_id: i64,
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    // Check offer exists and belongs to source
    if state.get_offer(source, offer_id).is_none() {
        return Ok(make_sell_offer_result(
            ManageSellOfferResultCode::NotFound,
            None,
        ));
    }

    let offer = OfferEntry {
        seller_id: source.clone(),
        offer_id,
        selling: selling.clone(),
        buying: buying.clone(),
        amount,
        price: price.clone(),
        flags: 0,
        ext: OfferEntryExt::V0,
    };

    state.update_offer(offer);

    let success = ManageOfferSuccessResult {
        offers_claimed: vec![].try_into().unwrap(),
        offer: ManageOfferSuccessResultOffer::Updated(create_offer_entry(
            source, offer_id, selling, buying, amount, price,
        )),
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Delete an existing offer.
fn delete_offer(
    source: &AccountId,
    offer_id: i64,
    state: &mut LedgerStateManager,
) -> Result<OperationResult> {
    // Check offer exists and belongs to source
    let offer = match state.get_offer(source, offer_id).cloned() {
        Some(offer) => offer,
        None => {
            return Ok(make_sell_offer_result(
                ManageSellOfferResultCode::NotFound,
                None,
            ));
        }
    };

    let (selling_liab, buying_liab) = offer_liabilities_sell(offer.amount, &offer.price)?;
    apply_liabilities_delta(
        source,
        &offer.selling,
        &offer.buying,
        -selling_liab,
        -buying_liab,
        state,
    )?;

    let ledger_key = LedgerKey::Offer(LedgerKeyOffer {
        seller_id: source.clone(),
        offer_id,
    });
    if state.entry_sponsor(&ledger_key).is_some() {
        state.remove_entry_sponsorship_and_update_counts(&ledger_key, source, 1)?;
    }

    state.delete_offer(source, offer_id);

    // Decrement the source account's sub-entries
    if let Some(account) = state.get_account_mut(source) {
        if account.num_sub_entries > 0 {
            account.num_sub_entries -= 1;
        }
    }

    let success = ManageOfferSuccessResult {
        offers_claimed: vec![].try_into().unwrap(),
        offer: ManageOfferSuccessResultOffer::Deleted,
    };

    Ok(make_sell_offer_result(
        ManageSellOfferResultCode::Success,
        Some(success),
    ))
}

/// Generate a new offer ID.
fn generate_offer_id(state: &mut LedgerStateManager) -> i64 {
    state.next_id()
}

fn invert_price(price: &Price) -> Price {
    Price {
        n: price.d,
        d: price.n,
    }
}

fn offer_liabilities_sell(amount: i64, price: &Price) -> Result<(i64, i64)> {
    let res = exchange_v10_without_price_error_thresholds(
        price.clone(),
        amount,
        i64::MAX,
        i64::MAX,
        i64::MAX,
        RoundingType::Normal,
    )
    .map_err(map_exchange_error)?;
    Ok((res.num_wheat_received, res.num_sheep_send))
}

fn offer_liabilities_buy(buy_amount: i64, price: &Price) -> Result<(i64, i64)> {
    let res = exchange_v10_without_price_error_thresholds(
        price.clone(),
        i64::MAX,
        i64::MAX,
        i64::MAX,
        buy_amount,
        RoundingType::Normal,
    )
    .map_err(map_exchange_error)?;
    Ok((res.num_wheat_received, res.num_sheep_send))
}

fn has_selling_capacity(
    source: &AccountId,
    selling: &Asset,
    selling_liab: i64,
    old_selling_liab: i64,
    reserve_subentry: bool,
    state: &LedgerStateManager,
    context: &LedgerContext,
) -> Result<bool> {
    if matches!(selling, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return Ok(false);
        };
        let min_balance = state.minimum_balance_for_account(
            account,
            context.protocol_version,
            if reserve_subentry { 1 } else { 0 },
        )?;
        let current_liab = account_liabilities(account).selling;
        let effective_liab = current_liab.saturating_sub(old_selling_liab);
        let available = account.balance - min_balance - effective_liab;
        return Ok(available >= selling_liab);
    }

    if issuer_for_asset(selling) == Some(source) {
        return Ok(true);
    }

    let Some(trustline) = state.get_trustline(source, selling) else {
        return Ok(false);
    };
    let current_liab = trustline_liabilities(trustline).selling;
    let effective_liab = current_liab.saturating_sub(old_selling_liab);
    let available = trustline.balance - effective_liab;
    Ok(available >= selling_liab)
}

fn has_buying_capacity(
    source: &AccountId,
    buying: &Asset,
    buying_liab: i64,
    old_buying_liab: i64,
    state: &LedgerStateManager,
) -> bool {
    if matches!(buying, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return false;
        };
        let current_liab = account_liabilities(account).buying;
        let effective_liab = current_liab.saturating_sub(old_buying_liab);
        let available = i64::MAX - account.balance - effective_liab;
        return available >= buying_liab;
    }

    if issuer_for_asset(buying) == Some(source) {
        return true;
    }

    let Some(trustline) = state.get_trustline(source, buying) else {
        return false;
    };
    let current_liab = trustline_liabilities(trustline).buying;
    let effective_liab = current_liab.saturating_sub(old_buying_liab);
    let available = trustline.limit - trustline.balance - effective_liab;
    available >= buying_liab
}

fn can_sell_at_most(
    source: &AccountId,
    asset: &Asset,
    state: &LedgerStateManager,
    context: &LedgerContext,
) -> Result<i64> {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return Ok(0);
        };
        let min_balance =
            state.minimum_balance_for_account(account, context.protocol_version, 0)?;
        let available = account.balance - min_balance - account_liabilities(account).selling;
        return Ok(available.max(0));
    }

    if issuer_for_asset(asset) == Some(source) {
        return Ok(i64::MAX);
    }

    let Some(trustline) = state.get_trustline(source, asset) else {
        return Ok(0);
    };
    if !is_authorized_to_maintain_liabilities(trustline.flags) {
        return Ok(0);
    }
    let available = trustline.balance - trustline_liabilities(trustline).selling;
    Ok(available.max(0))
}

fn can_buy_at_most(source: &AccountId, asset: &Asset, state: &LedgerStateManager) -> i64 {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account(source) else {
            return 0;
        };
        let available =
            i64::MAX - account.balance - account_liabilities(account).buying;
        return available.max(0);
    }

    if issuer_for_asset(asset) == Some(source) {
        return i64::MAX;
    }

    let Some(trustline) = state.get_trustline(source, asset) else {
        return 0;
    };
    if !is_authorized_to_maintain_liabilities(trustline.flags) {
        return 0;
    }
    let available =
        trustline.limit - trustline.balance - trustline_liabilities(trustline).buying;
    available.max(0)
}

fn apply_balance_delta(
    account_id: &AccountId,
    asset: &Asset,
    amount: i64,
    state: &mut LedgerStateManager,
) -> Result<()> {
    if matches!(asset, Asset::Native) {
        let Some(account) = state.get_account_mut(account_id) else {
            return Err(TxError::Internal("missing account for balance update".into()));
        };
        let new_balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| TxError::Internal("balance overflow".into()))?;
        if new_balance < 0 {
            return Err(TxError::Internal("balance underflow".into()));
        }
        account.balance = new_balance;
        return Ok(());
    }

    if issuer_for_asset(asset) == Some(account_id) {
        return Ok(());
    }

    let Some(tl) = state.get_trustline_mut(account_id, asset) else {
        return Err(TxError::Internal("missing trustline for balance update".into()));
    };
    let new_balance = tl
        .balance
        .checked_add(amount)
        .ok_or_else(|| TxError::Internal("trustline balance overflow".into()))?;
    if new_balance < 0 || new_balance > tl.limit {
        return Err(TxError::Internal("trustline balance out of bounds".into()));
    }
    tl.balance = new_balance;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum ConvertResult {
    Ok,
    Partial,
    FilterStopBadPrice,
    FilterStopCrossSelf,
    CrossedTooMany,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum OfferFilterResult {
    Keep,
    Skip,
    StopBadPrice,
    StopCrossSelf,
}

fn convert_with_offers(
    source: &AccountId,
    selling: &Asset,
    max_sheep_send: i64,
    sheep_sent: &mut i64,
    buying: &Asset,
    max_wheat_receive: i64,
    wheat_received: &mut i64,
    round: RoundingType,
    updating_offer_id: i64,
    passive: bool,
    max_wheat_price: &Price,
    offer_trail: &mut Vec<ClaimAtom>,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<ConvertResult> {
    offer_trail.clear();
    *sheep_sent = 0;
    *wheat_received = 0;

    let mut max_sheep_send = max_sheep_send;
    let mut max_wheat_receive = max_wheat_receive;
    let mut need_more = max_sheep_send > 0 && max_wheat_receive > 0;
    let mut ignored = HashSet::new();

    while need_more {
        let offer = state.best_offer_filtered(selling, buying, |offer| {
            if offer.seller_id == *source && offer.offer_id == updating_offer_id {
                return false;
            }
            !ignored.contains(&(offer.seller_id.clone(), offer.offer_id))
        });

        let Some(offer) = offer else {
            break;
        };

        match offer_filter(source, &offer, passive, max_wheat_price) {
            OfferFilterResult::Keep => {}
            OfferFilterResult::Skip => {
                ignored.insert((offer.seller_id, offer.offer_id));
                continue;
            }
            OfferFilterResult::StopBadPrice => return Ok(ConvertResult::FilterStopBadPrice),
            OfferFilterResult::StopCrossSelf => return Ok(ConvertResult::FilterStopCrossSelf),
        }

        let (num_wheat_received, num_sheep_send, wheat_stays) = cross_offer_v10(
            &offer,
            max_wheat_receive,
            max_sheep_send,
            round,
            offer_trail,
            state,
            context,
        )?;
        if num_wheat_received == 0 && num_sheep_send == 0 {
            return Ok(ConvertResult::Partial);
        }

        *sheep_sent += num_sheep_send;
        *wheat_received += num_wheat_received;
        max_sheep_send -= num_sheep_send;
        max_wheat_receive -= num_wheat_received;

        need_more = !wheat_stays && max_wheat_receive > 0 && max_sheep_send > 0;
        if !need_more {
            return Ok(ConvertResult::Ok);
        }
        if wheat_stays {
            return Ok(ConvertResult::Partial);
        }
    }

    Ok(if need_more {
        ConvertResult::Partial
    } else {
        ConvertResult::Ok
    })
}

fn offer_filter(
    source: &AccountId,
    offer: &OfferEntry,
    passive: bool,
    max_wheat_price: &Price,
) -> OfferFilterResult {
    if offer.seller_id == *source {
        return OfferFilterResult::StopCrossSelf;
    }

    let price_cmp = compare_price(&offer.price, max_wheat_price);
    if (passive && price_cmp != Ordering::Less) || (!passive && price_cmp == Ordering::Greater) {
        return OfferFilterResult::StopBadPrice;
    }

    OfferFilterResult::Keep
}

fn cross_offer_v10(
    offer: &OfferEntry,
    max_wheat_receive: i64,
    max_sheep_send: i64,
    round: RoundingType,
    offer_trail: &mut Vec<ClaimAtom>,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<(i64, i64, bool)> {
    let sheep = offer.buying.clone();
    let wheat = offer.selling.clone();
    let seller = offer.seller_id.clone();

    let (selling_liab, buying_liab) = offer_liabilities_sell(offer.amount, &offer.price)?;
    apply_liabilities_delta(
        &seller,
        &offer.selling,
        &offer.buying,
        -selling_liab,
        -buying_liab,
        state,
    )?;

    let max_wheat_send =
        offer.amount.min(can_sell_at_most(&seller, &wheat, state, context)?);
    let max_sheep_receive = can_buy_at_most(&seller, &sheep, state);
    let exchange = exchange_v10(
        offer.price.clone(),
        max_wheat_send,
        max_wheat_receive,
        max_sheep_send,
        max_sheep_receive,
        round,
    )
    .map_err(map_exchange_error)?;

    let num_wheat_received = exchange.num_wheat_received;
    let num_sheep_send = exchange.num_sheep_send;
    let wheat_stays = exchange.wheat_stays;

    if num_sheep_send != 0 {
        apply_balance_delta(&seller, &sheep, num_sheep_send, state)?;
    }

    if num_wheat_received != 0 {
        apply_balance_delta(&seller, &wheat, -num_wheat_received, state)?;
    }

    let mut new_amount = offer.amount;
    if wheat_stays {
        new_amount = new_amount.saturating_sub(num_wheat_received);
    } else {
        new_amount = 0;
    }

    if new_amount == 0 {
        state.delete_offer(&seller, offer.offer_id);
        if let Some(account) = state.get_account_mut(&seller) {
            if account.num_sub_entries > 0 {
                account.num_sub_entries -= 1;
            }
        }
    } else {
        let updated = OfferEntry {
            amount: new_amount,
            ..offer.clone()
        };
        state.update_offer(updated);
        let (new_selling, new_buying) = offer_liabilities_sell(new_amount, &offer.price)?;
        apply_liabilities_delta(
            &seller,
            &offer.selling,
            &offer.buying,
            new_selling,
            new_buying,
            state,
        )?;
    }

    if num_wheat_received > 0 && num_sheep_send > 0 {
        offer_trail.push(ClaimAtom::OrderBook(ClaimOfferAtom {
            seller_id: seller,
            offer_id: offer.offer_id,
            asset_sold: wheat,
            amount_sold: num_wheat_received,
            asset_bought: sheep,
            amount_bought: num_sheep_send,
        }));
    }

    Ok((num_wheat_received, num_sheep_send, wheat_stays))
}

fn compare_price(lhs: &Price, rhs: &Price) -> Ordering {
    let lhs_value = i128::from(lhs.n) * i128::from(rhs.d);
    let rhs_value = i128::from(rhs.n) * i128::from(lhs.d);
    lhs_value.cmp(&rhs_value)
}

fn map_exchange_error(err: ExchangeError) -> TxError {
    TxError::Internal(format!("offer exchange error: {err:?}"))
}

fn apply_liabilities_delta(
    source: &AccountId,
    selling: &Asset,
    buying: &Asset,
    selling_delta: i64,
    buying_delta: i64,
    state: &mut LedgerStateManager,
) -> Result<()> {
    if matches!(selling, Asset::Native) {
        let account = state
            .get_account_mut(source)
            .ok_or_else(|| TxError::Internal("missing account".into()))?;
        let liab = ensure_account_liabilities(account);
        update_liabilities(liab, 0, selling_delta)?;
    } else if issuer_for_asset(selling) != Some(source) {
        let trustline = state
            .get_trustline_mut(source, selling)
            .ok_or_else(|| TxError::Internal("missing trustline".into()))?;
        let liab = ensure_trustline_liabilities(trustline);
        update_liabilities(liab, 0, selling_delta)?;
    }

    if matches!(buying, Asset::Native) {
        let account = state
            .get_account_mut(source)
            .ok_or_else(|| TxError::Internal("missing account".into()))?;
        let liab = ensure_account_liabilities(account);
        update_liabilities(liab, buying_delta, 0)?;
    } else if issuer_for_asset(buying) != Some(source) {
        let trustline = state
            .get_trustline_mut(source, buying)
            .ok_or_else(|| TxError::Internal("missing trustline".into()))?;
        let liab = ensure_trustline_liabilities(trustline);
        update_liabilities(liab, buying_delta, 0)?;
    }
    Ok(())
}

fn update_liabilities(liab: &mut Liabilities, buying_delta: i64, selling_delta: i64) -> Result<()> {
    let buying = liab.buying + buying_delta;
    let selling = liab.selling + selling_delta;
    if buying < 0 || selling < 0 {
        return Err(TxError::Internal("liabilities underflow".into()));
    }
    liab.buying = buying;
    liab.selling = selling;
    Ok(())
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

fn ensure_account_liabilities(account: &mut AccountEntry) -> &mut Liabilities {
    match &mut account.ext {
        AccountEntryExt::V0 => {
            account.ext = AccountEntryExt::V1(AccountEntryExtensionV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: AccountEntryExtensionV1Ext::V0,
            });
        }
        AccountEntryExt::V1(_) => {}
    }
    match &mut account.ext {
        AccountEntryExt::V1(v1) => &mut v1.liabilities,
        AccountEntryExt::V0 => unreachable!("account liabilities not initialized"),
    }
}

fn ensure_trustline_liabilities(trustline: &mut TrustLineEntry) -> &mut Liabilities {
    match &mut trustline.ext {
        TrustLineEntryExt::V0 => {
            trustline.ext = TrustLineEntryExt::V1(TrustLineEntryV1 {
                liabilities: Liabilities {
                    buying: 0,
                    selling: 0,
                },
                ext: TrustLineEntryV1Ext::V0,
            });
        }
        TrustLineEntryExt::V1(_) => {}
    }
    match &mut trustline.ext {
        TrustLineEntryExt::V1(v1) => &mut v1.liabilities,
        TrustLineEntryExt::V0 => unreachable!("trustline liabilities not initialized"),
    }
}

/// Create an OfferEntry for result.
fn create_offer_entry(
    source: &AccountId,
    offer_id: i64,
    selling: &Asset,
    buying: &Asset,
    amount: i64,
    price: &Price,
) -> OfferEntry {
    OfferEntry {
        seller_id: source.clone(),
        offer_id,
        selling: selling.clone(),
        buying: buying.clone(),
        amount,
        price: price.clone(),
        flags: 0,
        ext: OfferEntryExt::V0,
    }
}

/// Convert ManageSellOfferResult to ManageBuyOfferResult.
fn convert_sell_to_buy_result(
    result: ManageSellOfferResult,
) -> stellar_xdr::curr::ManageBuyOfferResult {
    use stellar_xdr::curr::ManageBuyOfferResult;

    match result {
        ManageSellOfferResult::Success(s) => ManageBuyOfferResult::Success(s),
        ManageSellOfferResult::Malformed => ManageBuyOfferResult::Malformed,
        ManageSellOfferResult::SellNoTrust => ManageBuyOfferResult::SellNoTrust,
        ManageSellOfferResult::BuyNoTrust => ManageBuyOfferResult::BuyNoTrust,
        ManageSellOfferResult::SellNotAuthorized => ManageBuyOfferResult::SellNotAuthorized,
        ManageSellOfferResult::BuyNotAuthorized => ManageBuyOfferResult::BuyNotAuthorized,
        ManageSellOfferResult::LineFull => ManageBuyOfferResult::LineFull,
        ManageSellOfferResult::Underfunded => ManageBuyOfferResult::Underfunded,
        ManageSellOfferResult::CrossSelf => ManageBuyOfferResult::CrossSelf,
        ManageSellOfferResult::SellNoIssuer => ManageBuyOfferResult::SellNoIssuer,
        ManageSellOfferResult::BuyNoIssuer => ManageBuyOfferResult::BuyNoIssuer,
        ManageSellOfferResult::NotFound => ManageBuyOfferResult::NotFound,
        ManageSellOfferResult::LowReserve => ManageBuyOfferResult::LowReserve,
    }
}

/// Create a ManageSellOffer result.
fn make_sell_offer_result(
    code: ManageSellOfferResultCode,
    success: Option<ManageOfferSuccessResult>,
) -> OperationResult {
    let result = match code {
        ManageSellOfferResultCode::Success => ManageSellOfferResult::Success(success.unwrap()),
        ManageSellOfferResultCode::Malformed => ManageSellOfferResult::Malformed,
        ManageSellOfferResultCode::SellNoTrust => ManageSellOfferResult::SellNoTrust,
        ManageSellOfferResultCode::BuyNoTrust => ManageSellOfferResult::BuyNoTrust,
        ManageSellOfferResultCode::SellNotAuthorized => ManageSellOfferResult::SellNotAuthorized,
        ManageSellOfferResultCode::BuyNotAuthorized => ManageSellOfferResult::BuyNotAuthorized,
        ManageSellOfferResultCode::LineFull => ManageSellOfferResult::LineFull,
        ManageSellOfferResultCode::Underfunded => ManageSellOfferResult::Underfunded,
        ManageSellOfferResultCode::CrossSelf => ManageSellOfferResult::CrossSelf,
        ManageSellOfferResultCode::SellNoIssuer => ManageSellOfferResult::SellNoIssuer,
        ManageSellOfferResultCode::BuyNoIssuer => ManageSellOfferResult::BuyNoIssuer,
        ManageSellOfferResultCode::NotFound => ManageSellOfferResult::NotFound,
        ManageSellOfferResultCode::LowReserve => ManageSellOfferResult::LowReserve,
    };

    OperationResult::OpInner(OperationResultTr::ManageSellOffer(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

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

    fn create_asset(issuer: &AccountId) -> Asset {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer.clone(),
        })
    }

    #[test]
    fn test_manage_sell_offer_malformed_same_asset() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: Asset::Native, // Same as selling
            amount: 10_000_000,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Malformed));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_create() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        // Create trustline for the buying asset
        let issuer_id = create_test_account_id(99);
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        let buying_asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            i64::MAX,
            AUTHORIZED_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: buying_asset,
            amount: 10_000_000,
            price: Price { n: 1, d: 2 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_issuer_can_sell_without_trustline() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let min_balance = state
            .minimum_balance_with_counts(context.protocol_version, 0, 0, 0)
            .unwrap();
        state.create_account(create_test_account(issuer_id.clone(), min_balance + 10_000_000));

        let selling = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        let op = ManageSellOfferOp {
            selling,
            buying: Asset::Native,
            amount: 100,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_issuer_can_buy_without_trustline() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let issuer_id = create_test_account_id(9);
        let min_balance = state
            .minimum_balance_with_counts(context.protocol_version, 0, 0, 0)
            .unwrap();
        state.create_account(create_test_account(issuer_id.clone(), min_balance + 10_000_000));

        let buying = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
            issuer: issuer_id.clone(),
        });

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying,
            amount: 100,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &issuer_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_sell_no_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 12;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
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

        let op = ManageSellOfferOp {
            selling: asset,
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::SellNoIssuer));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_sell_missing_issuer_protocol_13_ok() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
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

        let op = ManageSellOfferOp {
            selling: asset,
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_buy_no_issuer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 12;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: asset,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::BuyNoIssuer));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_buy_missing_issuer_protocol_13_ok() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: asset,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::Success(_)));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_sell_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
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

        let op = ManageSellOfferOp {
            selling: asset,
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::SellNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_sell_authorized_to_maintain_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            100,
            1_000_000,
            AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling: asset,
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::SellNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_buy_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            0,
        ));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: asset,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::BuyNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_buy_authorized_to_maintain_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: asset,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::BuyNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_update_denied_when_selling_maintain_only() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
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

        let create = ManageSellOfferOp {
            selling: asset.clone(),
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };
        let created = execute_manage_sell_offer(&create, &source_id, &mut state, &context).unwrap();
        let offer_id = match created {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(ManageSellOfferResult::Success(
                ManageOfferSuccessResult { offer, .. },
            ))) => match offer {
                ManageOfferSuccessResultOffer::Created(entry) => entry.offer_id,
                _ => panic!("expected created offer"),
            },
            _ => panic!("unexpected result type"),
        };

        let tl = state
            .get_trustline_by_trustline_asset_mut(
                &source_id,
                &TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                    issuer: issuer_id.clone(),
                }),
            )
            .expect("trustline exists");
        tl.flags = AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG;

        let update = ManageSellOfferOp {
            selling: asset,
            buying: Asset::Native,
            amount: 11,
            price: Price { n: 1, d: 1 },
            offer_id,
        };

        let result = execute_manage_sell_offer(&update, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::SellNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_update_denied_when_buying_maintain_only() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            0,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        let create = ManageSellOfferOp {
            selling: Asset::Native,
            buying: asset.clone(),
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };
        let created = execute_manage_sell_offer(&create, &source_id, &mut state, &context).unwrap();
        let offer_id = match created {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(ManageSellOfferResult::Success(
                ManageOfferSuccessResult { offer, .. },
            ))) => match offer {
                ManageOfferSuccessResultOffer::Created(entry) => entry.offer_id,
                _ => panic!("expected created offer"),
            },
            _ => panic!("unexpected result type"),
        };

        let tl = state
            .get_trustline_by_trustline_asset_mut(
                &source_id,
                &TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                    issuer: issuer_id.clone(),
                }),
            )
            .expect("trustline exists");
        tl.flags = AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG;

        let update = ManageSellOfferOp {
            selling: Asset::Native,
            buying: asset,
            amount: 11,
            price: Price { n: 1, d: 1 },
            offer_id,
        };

        let result = execute_manage_sell_offer(&update, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::BuyNotAuthorized));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_delete_allowed_when_not_authorized() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let mut context = create_test_context();
        context.protocol_version = 13;

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));
        state
            .get_account_mut(&issuer_id)
            .unwrap()
            .flags = AUTH_REQUIRED_FLAG;

        let asset = create_asset(&issuer_id);
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

        let create = ManageSellOfferOp {
            selling: asset.clone(),
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };
        let created = execute_manage_sell_offer(&create, &source_id, &mut state, &context).unwrap();
        let offer_id = match created {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(ManageSellOfferResult::Success(
                ManageOfferSuccessResult { offer, .. },
            ))) => match offer {
                ManageOfferSuccessResultOffer::Created(entry) => entry.offer_id,
                _ => panic!("expected created offer"),
            },
            _ => panic!("unexpected result type"),
        };

        let tl = state
            .get_trustline_by_trustline_asset_mut(
                &source_id,
                &TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                    issuer: issuer_id.clone(),
                }),
            )
            .expect("trustline exists");
        tl.flags = AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG;

        let delete = ManageSellOfferOp {
            selling: asset,
            buying: Asset::Native,
            amount: 0,
            price: Price { n: 1, d: 1 },
            offer_id,
        };

        let result = execute_manage_sell_offer(&delete, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(ManageSellOfferResult::Success(
                ManageOfferSuccessResult { offer, .. },
            ))) => assert!(matches!(offer, ManageOfferSuccessResultOffer::Deleted)),
            _ => panic!("Unexpected result type"),
        }
        assert!(state.get_offer(&source_id, offer_id).is_none());
    }

    #[test]
    fn test_manage_sell_offer_cross_self() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let usd = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'X']),
            issuer: issuer_id.clone(),
        });
        let idr = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'I', b'D', b'R', b'X']),
            issuer: issuer_id.clone(),
        });

        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'X']),
                issuer: issuer_id.clone(),
            }),
            1_000,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'I', b'D', b'R', b'X']),
                issuer: issuer_id.clone(),
            }),
            1_000,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        state.create_offer(OfferEntry {
            seller_id: source_id.clone(),
            offer_id: 1,
            selling: idr.clone(),
            buying: usd.clone(),
            amount: 100,
            price: Price { n: 1, d: 1 },
            flags: 0,
            ext: OfferEntryExt::V0,
        });

        let op = ManageSellOfferOp {
            selling: usd,
            buying: idr,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::CrossSelf), "{r:?}");
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_buy_offer_cross_self() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let usd = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'U', b'S', b'D', b'X']),
            issuer: issuer_id.clone(),
        });
        let idr = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'I', b'D', b'R', b'X']),
            issuer: issuer_id.clone(),
        });

        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'X']),
                issuer: issuer_id.clone(),
            }),
            1_000,
            1_000_000,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'I', b'D', b'R', b'X']),
                issuer: issuer_id.clone(),
            }),
            1_000,
            1_000_000,
            AUTHORIZED_FLAG,
        ));

        state.create_offer(OfferEntry {
            seller_id: source_id.clone(),
            offer_id: 1,
            selling: idr.clone(),
            buying: usd.clone(),
            amount: 100,
            price: Price { n: 1, d: 1 },
            flags: 0,
            ext: OfferEntryExt::V0,
        });

        let op = ManageBuyOfferOp {
            selling: usd,
            buying: idr,
            buy_amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_buy_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageBuyOffer(r)) => {
                assert!(matches!(r, ManageBuyOfferResult::CrossSelf));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    fn manage_buy_offer_amount(price: Price, buy_amount: i64) -> i64 {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let selling = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'C', b'U', b'R', b'1']),
            issuer: issuer_id.clone(),
        });
        let buying = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'C', b'U', b'R', b'2']),
            issuer: issuer_id.clone(),
        });

        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'C', b'U', b'R', b'1']),
                issuer: issuer_id.clone(),
            }),
            100,
            100,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'C', b'U', b'R', b'2']),
                issuer: issuer_id.clone(),
            }),
            0,
            100,
            AUTHORIZED_FLAG,
        ));

        let op = ManageBuyOfferOp {
            selling,
            buying,
            buy_amount,
            price,
            offer_id: 0,
        };

        let result = execute_manage_buy_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageBuyOffer(ManageBuyOfferResult::Success(
                ManageOfferSuccessResult { offer, .. },
            ))) => match offer {
                ManageOfferSuccessResultOffer::Created(entry) => entry.amount,
                _ => panic!("expected created offer"),
            },
            other => panic!("unexpected result: {:?}", other),
        }
    }

    fn manage_sell_offer_amount(price: Price, amount: i64, seed: u8) -> i64 {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(seed);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let selling = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'C', b'U', b'R', b'3']),
            issuer: issuer_id.clone(),
        });
        let buying = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([b'C', b'U', b'R', b'4']),
            issuer: issuer_id.clone(),
        });

        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'C', b'U', b'R', b'3']),
                issuer: issuer_id.clone(),
            }),
            100,
            100,
            AUTHORIZED_FLAG,
        ));
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'C', b'U', b'R', b'4']),
                issuer: issuer_id.clone(),
            }),
            0,
            100,
            AUTHORIZED_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling,
            buying,
            amount,
            price,
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(ManageSellOfferResult::Success(
                ManageOfferSuccessResult { offer, .. },
            ))) => match offer {
                ManageOfferSuccessResultOffer::Created(entry) => entry.amount,
                _ => panic!("expected created offer"),
            },
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_manage_buy_offer_amount_matches_sell_offer() {
        let cases = [
            (Price { n: 2, d: 5 }, 20, Price { n: 5, d: 2 }, 8),
            (Price { n: 1, d: 2 }, 20, Price { n: 2, d: 1 }, 10),
            (Price { n: 1, d: 1 }, 20, Price { n: 1, d: 1 }, 20),
            (Price { n: 2, d: 1 }, 20, Price { n: 1, d: 2 }, 40),
            (Price { n: 5, d: 2 }, 20, Price { n: 2, d: 5 }, 50),
            (Price { n: 2, d: 5 }, 21, Price { n: 5, d: 2 }, 8),
            (Price { n: 1, d: 2 }, 21, Price { n: 2, d: 1 }, 10),
            (Price { n: 2, d: 1 }, 21, Price { n: 1, d: 2 }, 42),
            (Price { n: 5, d: 2 }, 21, Price { n: 2, d: 5 }, 53),
        ];

        for (buy_price, buy_amount, sell_price, sell_amount) in cases {
            let buy_offer = manage_buy_offer_amount(buy_price, buy_amount);
            let sell_offer = manage_sell_offer_amount(sell_price, sell_amount, 2);
            assert_eq!(buy_offer, sell_offer);
        }
    }

    #[test]
    fn test_manage_sell_offer_low_reserve() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        let min_balance = state
            .minimum_balance_with_counts(context.protocol_version, 0, 0, 0)
            .unwrap();
        state.create_account(create_test_account(source_id.clone(), min_balance));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let asset = create_asset(&issuer_id);
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

        let op = ManageSellOfferOp {
            selling: asset.clone(),
            buying: Asset::Native,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::LowReserve));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_manage_sell_offer_line_full_buying_limit() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let issuer_id = create_test_account_id(1);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));
        state.create_account(create_test_account(issuer_id.clone(), 100_000_000));

        let buying_asset = create_asset(&issuer_id);
        state.create_trustline(create_test_trustline(
            source_id.clone(),
            TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4([b'U', b'S', b'D', b'C']),
                issuer: issuer_id.clone(),
            }),
            1_000,
            1_000,
            AUTHORIZED_FLAG,
        ));

        let op = ManageSellOfferOp {
            selling: Asset::Native,
            buying: buying_asset,
            amount: 10,
            price: Price { n: 1, d: 1 },
            offer_id: 0,
        };

        let result = execute_manage_sell_offer(&op, &source_id, &mut state, &context).unwrap();
        match result {
            OperationResult::OpInner(OperationResultTr::ManageSellOffer(r)) => {
                assert!(matches!(r, ManageSellOfferResult::LineFull));
            }
            _ => panic!("Unexpected result type"),
        }
    }
}
