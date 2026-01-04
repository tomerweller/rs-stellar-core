//! SetOptions operation execution.
//!
//! This module implements the execution logic for the SetOptions operation,
//! which modifies various account settings.

use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountEntryExtensionV1Ext, AccountEntryExtensionV2, AccountId,
    MASK_ACCOUNT_FLAGS, MASK_ACCOUNT_FLAGS_V17, OperationResult, OperationResultTr, PublicKey,
    SetOptionsOp, SetOptionsResult, SetOptionsResultCode, Signer, SignerKey,
    SignerKeyEd25519SignedPayload, SignerKeyType, SponsorshipDescriptor,
};

use crate::state::{ensure_account_ext_v2, LedgerStateManager};
use crate::validation::LedgerContext;
use crate::{Result, TxError};

/// Maximum number of signers allowed on an account.
const MAX_SIGNERS: usize = 20;

/// Execute a SetOptions operation.
///
/// This operation modifies account settings including:
/// - Inflation destination
/// - Account flags (auth required, revocable, immutable, clawback enabled)
/// - Master key weight
/// - Threshold levels (low, medium, high)
/// - Home domain
/// - Signers
///
/// # Arguments
///
/// * `op` - The SetOptions operation data
/// * `source` - The source account ID
/// * `state` - The ledger state manager
/// * `context` - The ledger context
///
/// # Returns
///
/// Returns the operation result indicating success or a specific failure reason.
pub fn execute_set_options(
    op: &SetOptionsOp,
    source: &AccountId,
    state: &mut LedgerStateManager,
    context: &LedgerContext,
) -> Result<OperationResult> {
    let mask = if context.protocol_version >= 17 {
        MASK_ACCOUNT_FLAGS_V17 as u32
    } else {
        MASK_ACCOUNT_FLAGS as u32
    };

    if let Some(set_flags) = op.set_flags {
        if set_flags & !mask != 0 {
            return Ok(make_result(SetOptionsResultCode::UnknownFlag));
        }
    }
    if let Some(clear_flags) = op.clear_flags {
        if clear_flags & !mask != 0 {
            return Ok(make_result(SetOptionsResultCode::UnknownFlag));
        }
    }

    if let (Some(set_flags), Some(clear_flags)) = (op.set_flags, op.clear_flags) {
        if set_flags & clear_flags != 0 {
            return Ok(make_result(SetOptionsResultCode::BadFlags));
        }
    }

    // Validate operation parameters
    if let Some(weight) = op.master_weight {
        if weight > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    if let Some(t) = op.low_threshold {
        if t > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    if let Some(t) = op.med_threshold {
        if t > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    if let Some(t) = op.high_threshold {
        if t > 255 {
            return Ok(make_result(SetOptionsResultCode::ThresholdOutOfRange));
        }
    }

    // Get source account
    let source_account = match state.get_account(source) {
        Some(account) => account,
        None => return Err(TxError::SourceAccountNotFound),
    };

    // Check flag consistency
    const AUTH_REQUIRED_FLAG: u32 = 0x1;
    const AUTH_REVOCABLE_FLAG: u32 = 0x2;
    const AUTH_IMMUTABLE_FLAG: u32 = 0x4;
    const AUTH_CLAWBACK_FLAG: u32 = 0x8;
    let auth_flags_mask =
        AUTH_REQUIRED_FLAG | AUTH_REVOCABLE_FLAG | AUTH_IMMUTABLE_FLAG | AUTH_CLAWBACK_FLAG;

    let current_flags = source_account.flags;

    // If account is immutable, can only clear flags (not set new ones)
    if current_flags & AUTH_IMMUTABLE_FLAG != 0 {
        let set_flags = op.set_flags.unwrap_or(0);
        let clear_flags = op.clear_flags.unwrap_or(0);
        if (set_flags | clear_flags) & auth_flags_mask != 0 {
            return Ok(make_result(SetOptionsResultCode::CantChange));
        }
    }

    // Clawback requires auth revocable
    if let Some(set_flags) = op.set_flags {
        if set_flags & AUTH_CLAWBACK_FLAG != 0 {
            let new_flags = current_flags | set_flags;
            if new_flags & AUTH_REVOCABLE_FLAG == 0 {
                return Ok(make_result(SetOptionsResultCode::AuthRevocableRequired));
            }
        }
    }

    // Can't clear revocable if clawback is set
    if let Some(clear_flags) = op.clear_flags {
        if clear_flags & AUTH_REVOCABLE_FLAG != 0 {
            if current_flags & AUTH_CLAWBACK_FLAG != 0 {
                return Ok(make_result(SetOptionsResultCode::AuthRevocableRequired));
            }
        }
    }

    // Get current signer count for sub-entry calculations
    let current_signer_count = source_account.signers.len();
    let current_num_sub_entries = source_account.num_sub_entries;
    let base_reserve = state.base_reserve();
    let sponsor_info = if let Some(sponsor_id) = state.active_sponsor_for(source) {
        let sponsor_account = state
            .get_account(&sponsor_id)
            .ok_or(TxError::SourceAccountNotFound)?;
        let min_balance = state.minimum_balance_for_account_with_deltas(
            sponsor_account,
            context.protocol_version,
            0,
            1,
            0,
        )?;
        Some((sponsor_id, sponsor_account.balance, min_balance))
    } else {
        None
    };
    let (current_num_sponsoring, current_num_sponsored) =
        sponsorship_counts_for_account_entry(source_account);

    // Now apply changes to the account
    let source_account_mut = state
        .get_account_mut(source)
        .ok_or(TxError::SourceAccountNotFound)?;

    // Update inflation destination
    if let Some(ref inflation_dest) = op.inflation_dest {
        source_account_mut.inflation_dest = Some(inflation_dest.clone());
    }

    // Update flags
    if let Some(clear_flags) = op.clear_flags {
        source_account_mut.flags &= !clear_flags;
    }
    if let Some(set_flags) = op.set_flags {
        source_account_mut.flags |= set_flags;
    }

    // Update master weight
    if let Some(master_weight) = op.master_weight {
        source_account_mut.thresholds.0[0] = master_weight as u8;
    }

    // Update thresholds
    if let Some(low_threshold) = op.low_threshold {
        source_account_mut.thresholds.0[1] = low_threshold as u8;
    }
    if let Some(med_threshold) = op.med_threshold {
        source_account_mut.thresholds.0[2] = med_threshold as u8;
    }
    if let Some(high_threshold) = op.high_threshold {
        source_account_mut.thresholds.0[3] = high_threshold as u8;
    }

    // Update home domain
    if let Some(ref home_domain) = op.home_domain {
        source_account_mut.home_domain = home_domain.clone();
    }

    let mut sponsor_delta: Option<(AccountId, i64)> = None;

    // Update signers
    if let Some(ref signer) = op.signer {
        let signer_key = &signer.key;
        let weight = signer.weight;
        if weight > u8::MAX as u32 {
            return Ok(make_result(SetOptionsResultCode::BadSigner));
        }

        let is_self = match (signer_key, source) {
            (SignerKey::Ed25519(key), AccountId(PublicKey::PublicKeyTypeEd25519(account_key))) => {
                key == account_key
            }
            _ => false,
        };
        if is_self {
            return Ok(make_result(SetOptionsResultCode::BadSigner));
        }

        if signer_key.discriminant() == SignerKeyType::Ed25519SignedPayload {
            if context.protocol_version < 19 {
                return Ok(make_result(SetOptionsResultCode::BadSigner));
            }
            if let SignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload { payload, .. }) =
                signer_key
            {
                if payload.as_vec().is_empty() {
                    return Ok(make_result(SetOptionsResultCode::BadSigner));
                }
            }
        }

        let sponsor = sponsor_info.as_ref().map(|info| info.0.clone());
        let mut signers_vec: Vec<Signer> = source_account_mut.signers.iter().cloned().collect();
        let mut sponsoring_ids: Vec<SponsorshipDescriptor> = {
            let ext_v2 = ensure_account_ext_v2(source_account_mut);
            ext_v2.signer_sponsoring_i_ds.iter().cloned().collect()
        };
        if sponsoring_ids.len() < signers_vec.len() {
            sponsoring_ids.extend(
                std::iter::repeat(SponsorshipDescriptor(None))
                    .take(signers_vec.len() - sponsoring_ids.len()),
            );
        } else if sponsoring_ids.len() > signers_vec.len() {
            sponsoring_ids.truncate(signers_vec.len());
        }

        let existing_pos = signers_vec.iter().position(|s| &s.key == signer_key);
        let mut num_sponsored_delta: i64 = 0;
        let mut signers_changed = false;

        if weight == 0 {
            if let Some(pos) = existing_pos {
                if let Some(sponsor_id) = sponsoring_ids.get(pos).and_then(|id| id.0.clone()) {
                    num_sponsored_delta -= 1;
                    sponsor_delta = Some((sponsor_id, -1));
                }
                signers_vec.remove(pos);
                sponsoring_ids.remove(pos);
                signers_changed = true;

                if source_account_mut.num_sub_entries > 0 {
                    source_account_mut.num_sub_entries -= 1;
                }
            }
        } else if let Some(pos) = existing_pos {
            signers_vec[pos].weight = weight;
            signers_changed = true;
        } else {
            if current_signer_count >= MAX_SIGNERS {
                return Ok(make_result(SetOptionsResultCode::TooManySigners));
            }

            if let Some((_, sponsor_balance, sponsor_min_balance)) = sponsor_info.as_ref() {
                if *sponsor_balance < *sponsor_min_balance {
                    return Ok(make_result(SetOptionsResultCode::LowReserve));
                }
            } else {
                let num_sub_entries = current_num_sub_entries as i64 + 1;
                let effective_entries = if context.protocol_version < 9 {
                    2 + num_sub_entries
                } else {
                    2 + num_sub_entries + current_num_sponsoring - current_num_sponsored
                };
                if effective_entries < 0 {
                    return Err(TxError::Internal(
                        "unexpected account state while computing minimum balance".to_string(),
                    ));
                }
                let new_min_balance = effective_entries * base_reserve;
                if source_account_mut.balance < new_min_balance {
                    return Ok(make_result(SetOptionsResultCode::LowReserve));
                }
            }

            let new_signer = Signer {
                key: signer_key.clone(),
                weight,
            };
            let new_sponsor_id = sponsor
                .clone()
                .map(|id| SponsorshipDescriptor(Some(id)))
                .unwrap_or(SponsorshipDescriptor(None));

            signers_vec.push(new_signer);
            sponsoring_ids.push(new_sponsor_id);

            let mut combined: Vec<(Signer, SponsorshipDescriptor)> = signers_vec
                .into_iter()
                .zip(sponsoring_ids.into_iter())
                .collect();
            combined.sort_by(|a, b| compare_signer_keys(&a.0.key, &b.0.key));
            let (sorted_signers, sorted_sponsoring): (Vec<Signer>, Vec<SponsorshipDescriptor>) =
                combined.into_iter().unzip();
            signers_vec = sorted_signers;
            sponsoring_ids = sorted_sponsoring;
            signers_changed = true;

            if let Some(sponsor) = sponsor {
                num_sponsored_delta += 1;
                sponsor_delta = Some((sponsor, 1));
            }

            source_account_mut.num_sub_entries += 1;
        }

        if signers_changed {
            source_account_mut.signers = signers_vec.try_into().unwrap_or_default();
            let ext_v2 = ensure_account_ext_v2(source_account_mut);
            let updated = ext_v2.num_sponsored as i64 + num_sponsored_delta;
            if updated < 0 || updated > u32::MAX as i64 {
                return Err(TxError::Internal(
                    "num_sponsored out of range".to_string(),
                ));
            }
            ext_v2.num_sponsored = updated as u32;
            ext_v2.signer_sponsoring_i_ds = sponsoring_ids.try_into().unwrap_or_default();
        }
    }

    let _ = source_account_mut;
    if let Some((sponsor_id, delta)) = sponsor_delta {
        state.update_num_sponsoring(&sponsor_id, delta)?;
    }

    Ok(make_result(SetOptionsResultCode::Success))
}

/// Compare signer keys for sorting.
fn compare_signer_keys(a: &SignerKey, b: &SignerKey) -> std::cmp::Ordering {
    // Compare based on key type first, then content
    match (a, b) {
        (SignerKey::Ed25519(a_key), SignerKey::Ed25519(b_key)) => a_key.0.cmp(&b_key.0),
        (SignerKey::PreAuthTx(a_key), SignerKey::PreAuthTx(b_key)) => a_key.0.cmp(&b_key.0),
        (SignerKey::HashX(a_key), SignerKey::HashX(b_key)) => a_key.0.cmp(&b_key.0),
        (SignerKey::Ed25519SignedPayload(a_key), SignerKey::Ed25519SignedPayload(b_key)) => {
            a_key.ed25519.0.cmp(&b_key.ed25519.0)
        }
        // Different types: order by discriminant
        (a, b) => {
            let a_disc = signer_key_discriminant(a);
            let b_disc = signer_key_discriminant(b);
            a_disc.cmp(&b_disc)
        }
    }
}

/// Get discriminant for signer key type ordering.
fn signer_key_discriminant(key: &SignerKey) -> u8 {
    match key {
        SignerKey::Ed25519(_) => 0,
        SignerKey::PreAuthTx(_) => 1,
        SignerKey::HashX(_) => 2,
        SignerKey::Ed25519SignedPayload(_) => 3,
    }
}

fn sponsorship_counts_for_account_entry(account: &AccountEntry) -> (i64, i64) {
    match &account.ext {
        AccountEntryExt::V0 => (0, 0),
        AccountEntryExt::V1(v1) => match &v1.ext {
            AccountEntryExtensionV1Ext::V0 => (0, 0),
            AccountEntryExtensionV1Ext::V2(AccountEntryExtensionV2 {
                num_sponsoring,
                num_sponsored,
                ..
            }) => (*num_sponsoring as i64, *num_sponsored as i64),
        },
    }
}

/// Create an OperationResult from a SetOptionsResultCode.
fn make_result(code: SetOptionsResultCode) -> OperationResult {
    let result = match code {
        SetOptionsResultCode::Success => SetOptionsResult::Success,
        SetOptionsResultCode::LowReserve => SetOptionsResult::LowReserve,
        SetOptionsResultCode::TooManySigners => SetOptionsResult::TooManySigners,
        SetOptionsResultCode::BadFlags => SetOptionsResult::BadFlags,
        SetOptionsResultCode::InvalidInflation => SetOptionsResult::InvalidInflation,
        SetOptionsResultCode::CantChange => SetOptionsResult::CantChange,
        SetOptionsResultCode::UnknownFlag => SetOptionsResult::UnknownFlag,
        SetOptionsResultCode::ThresholdOutOfRange => SetOptionsResult::ThresholdOutOfRange,
        SetOptionsResultCode::BadSigner => SetOptionsResult::BadSigner,
        SetOptionsResultCode::InvalidHomeDomain => SetOptionsResult::InvalidHomeDomain,
        SetOptionsResultCode::AuthRevocableRequired => SetOptionsResult::AuthRevocableRequired,
    };

    OperationResult::OpInner(OperationResultTr::SetOptions(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::*;

    fn make_string32(s: &str) -> String32 {
        String32::try_from(s.as_bytes().to_vec()).unwrap()
    }

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

    #[test]
    fn test_set_options_update_thresholds() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: Some(10),
            low_threshold: Some(1),
            med_threshold: Some(2),
            high_threshold: Some(3),
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.thresholds.0[0], 10); // master weight
        assert_eq!(account.thresholds.0[1], 1);  // low
        assert_eq!(account.thresholds.0[2], 2);  // med
        assert_eq!(account.thresholds.0[3], 3);  // high
    }

    #[test]
    fn test_set_options_set_flags() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: Some(0x3), // AUTH_REQUIRED | AUTH_REVOCABLE
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.flags, 0x3);
    }

    #[test]
    fn test_set_options_threshold_out_of_range() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: Some(256), // Out of range
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::ThresholdOutOfRange));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_immutable_cant_change() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let mut account = create_test_account(source_id.clone(), 100_000_000);
        account.flags = 0x4; // AUTH_IMMUTABLE
        state.create_account(account);

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: Some(0x1), // Try to set AUTH_REQUIRED
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::CantChange));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_immutable_clear_flags_cant_change() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        let mut account = create_test_account(source_id.clone(), 100_000_000);
        account.flags = 0x4; // AUTH_IMMUTABLE
        state.create_account(account);

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: Some(0x1), // Try to clear AUTH_REQUIRED
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::CantChange));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_unknown_flag() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: Some(0x10), // outside MASK_ACCOUNT_FLAGS_V17
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::UnknownFlag));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_bad_flags_overlap() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: Some(0x1),
            set_flags: Some(0x1), // overlap
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::BadFlags));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_add_signer() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let signer_key = SignerKey::Ed25519(Uint256([1u8; 32]));
        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(Signer {
                key: signer_key.clone(),
                weight: 5,
            }),
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.signers.len(), 1);
        assert_eq!(account.num_sub_entries, 1);
    }

    #[test]
    fn test_set_options_bad_signer_self() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let signer_key = SignerKey::Ed25519(Uint256([0u8; 32]));
        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(Signer {
                key: signer_key,
                weight: 1,
            }),
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::BadSigner));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_bad_signer_weight() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let signer_key = SignerKey::Ed25519(Uint256([1u8; 32]));
        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(Signer {
                key: signer_key,
                weight: 256,
            }),
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::BadSigner));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_bad_signer_signed_payload_empty() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let signer_key = SignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload {
            ed25519: Uint256([2u8; 32]),
            payload: BytesM::default(),
        });
        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: None,
            signer: Some(Signer {
                key: signer_key,
                weight: 1,
            }),
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        match result.unwrap() {
            OperationResult::OpInner(OperationResultTr::SetOptions(r)) => {
                assert!(matches!(r, SetOptionsResult::BadSigner));
            }
            _ => panic!("Unexpected result type"),
        }
    }

    #[test]
    fn test_set_options_home_domain() {
        let mut state = LedgerStateManager::new(5_000_000, 100);
        let context = create_test_context();

        let source_id = create_test_account_id(0);
        state.create_account(create_test_account(source_id.clone(), 100_000_000));

        let op = SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: None,
            low_threshold: None,
            med_threshold: None,
            high_threshold: None,
            home_domain: Some(make_string32("stellar.org")),
            signer: None,
        };

        let result = execute_set_options(&op, &source_id, &mut state, &context);
        assert!(result.is_ok());

        let account = state.get_account(&source_id).unwrap();
        assert_eq!(account.home_domain.to_string(), "stellar.org");
    }
}
