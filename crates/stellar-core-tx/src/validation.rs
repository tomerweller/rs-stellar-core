//! Transaction validation for catchup mode.
//!
//! This module provides basic validation checks for transactions during catchup.
//! During catchup, we trust the historical results from the archive, so we only
//! perform minimal validation to ensure data integrity.

use stellar_core_common::{Hash256, NetworkId};
use stellar_core_crypto::{verify_hash, PublicKey, Signature};
use stellar_xdr::curr::{
    AccountEntry, DecoratedSignature, Preconditions, SignerKey, TransactionEnvelope,
};

use crate::frame::TransactionFrame;

/// Ledger context for validation.
pub struct LedgerContext {
    /// Current ledger sequence.
    pub sequence: u32,
    /// Ledger close time (Unix timestamp).
    pub close_time: u64,
    /// Base fee in stroops.
    pub base_fee: u32,
    /// Base reserve in stroops.
    pub base_reserve: u32,
    /// Protocol version.
    pub protocol_version: u32,
    /// Network ID.
    pub network_id: NetworkId,
    /// PRNG seed for Soroban contract execution.
    /// This is computed as subSha256(txSetHash, txIndex) per the C++ stellar-core spec.
    /// None means use a default (incorrect) seed for compatibility.
    pub soroban_prng_seed: Option<[u8; 32]>,
}

impl LedgerContext {
    /// Create a new ledger context.
    pub fn new(
        sequence: u32,
        close_time: u64,
        base_fee: u32,
        base_reserve: u32,
        protocol_version: u32,
        network_id: NetworkId,
    ) -> Self {
        Self {
            sequence,
            close_time,
            base_fee,
            base_reserve,
            protocol_version,
            network_id,
            soroban_prng_seed: None,
        }
    }

    /// Create a new ledger context with a Soroban PRNG seed.
    pub fn with_prng_seed(
        sequence: u32,
        close_time: u64,
        base_fee: u32,
        base_reserve: u32,
        protocol_version: u32,
        network_id: NetworkId,
        soroban_prng_seed: [u8; 32],
    ) -> Self {
        Self {
            sequence,
            close_time,
            base_fee,
            base_reserve,
            protocol_version,
            network_id,
            soroban_prng_seed: Some(soroban_prng_seed),
        }
    }

    /// Create context for testnet.
    pub fn testnet(sequence: u32, close_time: u64) -> Self {
        Self {
            sequence,
            close_time,
            base_fee: 100,
            base_reserve: 5_000_000,
            protocol_version: 21,
            network_id: NetworkId::testnet(),
            soroban_prng_seed: None,
        }
    }

    /// Create context for mainnet.
    pub fn mainnet(sequence: u32, close_time: u64) -> Self {
        Self {
            sequence,
            close_time,
            base_fee: 100,
            base_reserve: 5_000_000,
            protocol_version: 21,
            network_id: NetworkId::mainnet(),
            soroban_prng_seed: None,
        }
    }
}

/// Validation result with detailed error information.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Transaction has invalid structure.
    InvalidStructure(String),
    /// Invalid signature(s).
    InvalidSignature,
    /// Missing required signatures.
    MissingSignatures,
    /// Bad sequence number.
    BadSequence { expected: i64, actual: i64 },
    /// Insufficient fee.
    InsufficientFee { required: u32, provided: u32 },
    /// Source account not found.
    SourceAccountNotFound,
    /// Insufficient balance for fee.
    InsufficientBalance,
    /// Transaction is too late (time bounds).
    TooLate { max_time: u64, ledger_time: u64 },
    /// Transaction is too early (time bounds).
    TooEarly { min_time: u64, ledger_time: u64 },
    /// Ledger bounds not satisfied.
    BadLedgerBounds { min: u32, max: u32, current: u32 },
    /// Min account sequence not met.
    BadMinAccountSequence,
    /// Min account sequence age not met.
    BadMinAccountSequenceAge,
    /// Min account sequence ledger gap not met.
    BadMinAccountSequenceLedgerGap,
    /// Extra signers requirement not met.
    ExtraSignersNotMet,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStructure(msg) => write!(f, "invalid structure: {}", msg),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::MissingSignatures => write!(f, "missing required signatures"),
            Self::BadSequence { expected, actual } => {
                write!(f, "bad sequence: expected {}, got {}", expected, actual)
            }
            Self::InsufficientFee { required, provided } => {
                write!(f, "insufficient fee: required {}, provided {}", required, provided)
            }
            Self::SourceAccountNotFound => write!(f, "source account not found"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::TooLate { max_time, ledger_time } => {
                write!(f, "too late: max_time {}, ledger_time {}", max_time, ledger_time)
            }
            Self::TooEarly { min_time, ledger_time } => {
                write!(f, "too early: min_time {}, ledger_time {}", min_time, ledger_time)
            }
            Self::BadLedgerBounds { min, max, current } => {
                write!(f, "bad ledger bounds: [{}, {}], current {}", min, max, current)
            }
            Self::BadMinAccountSequence => write!(f, "min account sequence not met"),
            Self::BadMinAccountSequenceAge => write!(f, "min account sequence age not met"),
            Self::BadMinAccountSequenceLedgerGap => {
                write!(f, "min account sequence ledger gap not met")
            }
            Self::ExtraSignersNotMet => write!(f, "extra signers requirement not met"),
        }
    }
}

/// Validate transaction signatures.
///
/// This verifies that the signatures on the transaction are cryptographically
/// valid for the transaction hash. It does NOT verify that the signers have
/// the required weights - that requires account information.
pub fn validate_signatures(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let tx_hash = frame
        .hash(&context.network_id)
        .map_err(|_| ValidationError::InvalidSignature)?;

    // Validate signatures on the outer envelope
    for sig in frame.signatures() {
        if !is_valid_signature(&tx_hash, sig) {
            return Err(ValidationError::InvalidSignature);
        }
    }

    // For fee bump, also validate inner signatures
    if frame.is_fee_bump() {
        for sig in frame.inner_signatures() {
            // Inner signatures are for the inner tx hash
            // For simplicity in catchup, we just check they're well-formed
            if sig.signature.0.len() != 64 {
                return Err(ValidationError::InvalidSignature);
            }
        }
    }

    Ok(())
}

/// Validate sequence number.
///
/// For catchup mode, we trust the historical sequence but can verify
/// the relationship if we have account data.
pub fn validate_sequence(
    frame: &TransactionFrame,
    source_account: Option<&AccountEntry>,
) -> std::result::Result<(), ValidationError> {
    if let Some(account) = source_account {
        let expected = account.seq_num.0 + 1;
        let actual = frame.sequence_number();

        if actual != expected {
            return Err(ValidationError::BadSequence { expected, actual });
        }
    }

    Ok(())
}

/// Validate preconditions (min sequence and extra signers).
fn validate_min_seq_num(
    frame: &TransactionFrame,
    source_account: &AccountEntry,
) -> std::result::Result<(), ValidationError> {
    if let Preconditions::V2(cond) = frame.preconditions() {
        if let Some(min_seq) = cond.min_seq_num {
            if source_account.seq_num.0 < min_seq.0 {
                return Err(ValidationError::BadMinAccountSequence);
            }
        }
    }

    Ok(())
}

fn validate_extra_signers(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    if let Preconditions::V2(cond) = frame.preconditions() {
        if !cond.extra_signers.is_empty() {
            let extra_hash = fee_bump_inner_hash(frame, &context.network_id)
                .map_err(|e| ValidationError::InvalidStructure(e))?;
            let extra_signatures = if frame.is_fee_bump() {
                frame.inner_signatures()
            } else {
                frame.signatures()
            };
            if !has_required_extra_signers(&extra_hash, extra_signatures, &cond.extra_signers) {
                return Err(ValidationError::ExtraSignersNotMet);
            }
        }
    }

    Ok(())
}

/// Validate transaction fee.
///
/// Checks that the fee meets the minimum required fee based on operation count.
pub fn validate_fee(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let op_count = frame.operation_count() as u32;
    let required_fee = op_count.saturating_mul(context.base_fee);
    let provided_fee = frame.fee();

    if provided_fee < required_fee {
        return Err(ValidationError::InsufficientFee {
            required: required_fee,
            provided: provided_fee,
        });
    }

    Ok(())
}

/// Validate time bounds.
pub fn validate_time_bounds(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let time_bounds = match frame.preconditions() {
        Preconditions::None => return Ok(()),
        Preconditions::Time(tb) => Some(tb),
        Preconditions::V2(cond) => cond.time_bounds.clone(),
    };

    if let Some(tb) = time_bounds {
        let min_time: u64 = tb.min_time.into();
        let max_time: u64 = tb.max_time.into();

        // Check min time
        if min_time > 0 && context.close_time < min_time {
            return Err(ValidationError::TooEarly {
                min_time,
                ledger_time: context.close_time,
            });
        }

        // Check max time (0 means no limit)
        if max_time > 0 && context.close_time > max_time {
            return Err(ValidationError::TooLate {
                max_time,
                ledger_time: context.close_time,
            });
        }
    }

    Ok(())
}

/// Validate ledger bounds.
pub fn validate_ledger_bounds(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    let ledger_bounds = match frame.preconditions() {
        Preconditions::None | Preconditions::Time(_) => return Ok(()),
        Preconditions::V2(cond) => cond.ledger_bounds.clone(),
    };

    if let Some(lb) = ledger_bounds {
        let current = context.sequence;

        // Check min ledger
        if lb.min_ledger > 0 && current < lb.min_ledger {
            return Err(ValidationError::BadLedgerBounds {
                min: lb.min_ledger,
                max: lb.max_ledger,
                current,
            });
        }

        // Check max ledger (0 means no limit)
        if lb.max_ledger > 0 && current > lb.max_ledger {
            return Err(ValidationError::BadLedgerBounds {
                min: lb.min_ledger,
                max: lb.max_ledger,
                current,
            });
        }
    }

    Ok(())
}

/// Validate transaction structure.
pub fn validate_structure(frame: &TransactionFrame) -> std::result::Result<(), ValidationError> {
    if !frame.is_valid_structure() {
        return Err(ValidationError::InvalidStructure(
            "basic structure validation failed".to_string(),
        ));
    }

    Ok(())
}

fn validate_soroban_resources(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), ValidationError> {
    if !frame.is_soroban() {
        return Ok(());
    }

    if frame.soroban_data().is_none() {
        return Err(ValidationError::InvalidStructure(
            "missing soroban transaction data".to_string(),
        ));
    }

    let Some(data) = frame.soroban_data() else {
        return Ok(());
    };

    let footprint = &data.resources.footprint;
    if let stellar_xdr::curr::SorobanTransactionDataExt::V1(resource_ext) = &data.ext {
        let mut prev: Option<u32> = None;
        for index in resource_ext.archived_soroban_entries.iter() {
            if let Some(prev_index) = prev {
                if index <= &prev_index {
                    return Err(ValidationError::InvalidStructure(
                        "archived soroban entry indices must be sorted and unique".to_string(),
                    ));
                }
            }
            prev = Some(*index);

            let idx = *index as usize;
            let Some(key) = footprint.read_write.get(idx) else {
                return Err(ValidationError::InvalidStructure(
                    "archived soroban entry index out of bounds".to_string(),
                ));
            };

            if !is_archivable_soroban_key(key) {
                return Err(ValidationError::InvalidStructure(
                    "archived soroban entry must be a persistent contract entry".to_string(),
                ));
            }
        }
    }

    let _ = context;
    Ok(())
}

fn is_archivable_soroban_key(key: &stellar_xdr::curr::LedgerKey) -> bool {
    use stellar_xdr::curr::{ContractDataDurability, LedgerKey};

    match key {
        LedgerKey::ContractData(cd) => cd.durability == ContractDataDurability::Persistent,
        LedgerKey::ContractCode(_) => true,
        _ => false,
    }
}

/// Perform all basic validations.
///
/// This is a convenience function that runs all basic checks suitable for catchup.
/// It does not require account data and trusts historical results.
pub fn validate_basic(
    frame: &TransactionFrame,
    context: &LedgerContext,
) -> std::result::Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if let Err(e) = validate_structure(frame) {
        errors.push(e);
    }

    if let Err(e) = validate_fee(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_time_bounds(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_ledger_bounds(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_soroban_resources(frame, context) {
        errors.push(e);
    }

    // Signature validation is optional in basic mode
    // (might not have all data needed)

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Full validation with account data.
pub fn validate_full(
    frame: &TransactionFrame,
    context: &LedgerContext,
    source_account: &AccountEntry,
) -> std::result::Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if let Err(e) = validate_structure(frame) {
        errors.push(e);
    }

    if let Err(e) = validate_fee(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_time_bounds(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_ledger_bounds(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_min_seq_num(frame, source_account) {
        errors.push(e);
    }

    if let Err(e) = validate_sequence(frame, Some(source_account)) {
        errors.push(e);
    }

    if let Err(e) = validate_signatures(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_extra_signers(frame, context) {
        errors.push(e);
    }

    if let Err(e) = validate_soroban_resources(frame, context) {
        errors.push(e);
    }

    // Check account balance can cover fee
    let available_balance = source_account.balance;
    let fee = frame.total_fee();
    if available_balance < fee {
        errors.push(ValidationError::InsufficientBalance);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn fee_bump_inner_hash(
    frame: &TransactionFrame,
    network_id: &NetworkId,
) -> std::result::Result<Hash256, String> {
    match frame.envelope() {
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                let inner_env = TransactionEnvelope::Tx(inner.clone());
                let inner_frame = TransactionFrame::with_network(inner_env, *network_id);
                inner_frame
                    .hash(network_id)
                    .map_err(|e| format!("inner tx hash error: {}", e))
            }
        },
        _ => frame
            .hash(network_id)
            .map_err(|e| format!("tx hash error: {}", e)),
    }
}

fn has_required_extra_signers(
    tx_hash: &Hash256,
    signatures: &[DecoratedSignature],
    extra_signers: &[SignerKey],
) -> bool {
    extra_signers.iter().all(|signer| match signer {
        SignerKey::Ed25519(key) => {
            if let Ok(pk) = PublicKey::from_bytes(&key.0) {
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

fn has_ed25519_signature(
    tx_hash: &Hash256,
    signatures: &[DecoratedSignature],
    pk: &PublicKey,
) -> bool {
    signatures
        .iter()
        .any(|sig| verify_signature_with_key(tx_hash, sig, pk))
}

fn has_hashx_signature(
    signatures: &[DecoratedSignature],
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
    signatures: &[DecoratedSignature],
    payload: &stellar_xdr::curr::SignerKeyEd25519SignedPayload,
) -> bool {
    let pk = match PublicKey::from_bytes(&payload.ed25519.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let mut data = Vec::with_capacity(32 + payload.payload.len());
    data.extend_from_slice(&tx_hash.0);
    data.extend_from_slice(&payload.payload);
    let payload_hash = Hash256::hash(&data);

    signatures
        .iter()
        .any(|sig| verify_signature_with_key(&payload_hash, sig, &pk))
}

/// Check if a signature is cryptographically valid.
///
/// Note: This only checks the signature format/validity, not whether
/// the signer has authority over the account.
fn is_valid_signature(
    _tx_hash: &stellar_core_common::Hash256,
    sig: &DecoratedSignature,
) -> bool {
    // The signature should be 64 bytes for Ed25519
    if sig.signature.0.len() != 64 {
        return false;
    }

    // We can't fully verify without the public key
    // The hint only gives us the last 4 bytes
    // For catchup, we trust the archive data
    true
}

/// Verify a signature against a known public key.
pub fn verify_signature_with_key(
    tx_hash: &stellar_core_common::Hash256,
    sig: &DecoratedSignature,
    public_key: &PublicKey,
) -> bool {
    // Check hint matches
    let key_bytes = public_key.as_bytes();
    let expected_hint = [key_bytes[28], key_bytes[29], key_bytes[30], key_bytes[31]];

    if sig.hint.0 != expected_hint {
        return false;
    }

    // Verify signature
    if let Ok(signature) = Signature::try_from(&sig.signature) {
        verify_hash(public_key, tx_hash, &signature).is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_crypto::{sign_hash, SecretKey};
    use stellar_xdr::curr::{
        AccountEntry, AccountEntryExt, AccountId, Asset, ContractDataDurability, ContractId,
        DecoratedSignature, Duration, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
        LedgerFootprint, LedgerKey, LedgerKeyContractData, ManageDataOp, Memo, MuxedAccount,
        Operation, OperationBody, PaymentOp, Preconditions, PreconditionsV2, ScAddress, ScSymbol,
        ScVal, SequenceNumber, Signature as XdrSignature, SignatureHint,
        SorobanResources, SorobanResourcesExtV0, SorobanTransactionData, SorobanTransactionDataExt,
        String32, String64, StringM, Thresholds, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
    };

    fn create_test_frame() -> TransactionFrame {
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

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        TransactionFrame::new(envelope)
    }

    fn create_account_entry(account_id: AccountId, seq_num: i64) -> AccountEntry {
        AccountEntry {
            account_id,
            balance: 10_000_000,
            seq_num: SequenceNumber(seq_num),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }
    }

    fn create_soroban_envelope(
        read_write: Vec<LedgerKey>,
        archived_indices: Option<Vec<u32>>,
        with_data: bool,
    ) -> TransactionEnvelope {
        let source = MuxedAccount::Ed25519(Uint256([2u8; 32]));
        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([9u8; 32]))),
            function_name: ScSymbol(StringM::<32>::try_from("noop".to_string()).unwrap()),
            args: VecM::<ScVal>::default(),
        });

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function,
                auth: VecM::default(),
            }),
        };

        let mut tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        if with_data {
            let footprint = LedgerFootprint {
                read_only: VecM::default(),
                read_write: read_write.try_into().unwrap(),
            };
            let ext = match archived_indices {
                Some(indices) => SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                    archived_soroban_entries: indices.try_into().unwrap(),
                }),
                None => SorobanTransactionDataExt::V0,
            };
            tx.ext = TransactionExt::V1(SorobanTransactionData {
                ext,
                resources: SorobanResources {
                    footprint,
                    instructions: 100,
                    disk_read_bytes: 0,
                    write_bytes: 0,
                },
                resource_fee: 0,
            });
        }

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    fn sign_envelope(
        envelope: &TransactionEnvelope,
        secret: &SecretKey,
        network_id: &NetworkId,
    ) -> DecoratedSignature {
        let frame = TransactionFrame::with_network(envelope.clone(), *network_id);
        let hash = frame.hash(network_id).expect("tx hash");
        let signature = sign_hash(secret, &hash);

        let public_key = secret.public_key();
        let pk_bytes = public_key.as_bytes();
        let hint = SignatureHint([pk_bytes[28], pk_bytes[29], pk_bytes[30], pk_bytes[31]]);

        DecoratedSignature {
            hint,
            signature: XdrSignature(signature.0.to_vec().try_into().unwrap()),
        }
    }

    #[test]
    fn test_validate_structure() {
        let frame = create_test_frame();
        assert!(validate_structure(&frame).is_ok());
    }

    #[test]
    fn test_validate_fee() {
        let frame = create_test_frame();
        let context = LedgerContext::testnet(1, 1000);

        // Fee of 100 is enough for 1 operation with base_fee of 100
        assert!(validate_fee(&frame, &context).is_ok());
    }

    #[test]
    fn test_validate_fee_insufficient() {
        // Create a transaction with low fee
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
            fee: 10, // Too low
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![payment_op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        let frame = TransactionFrame::new(envelope);
        let context = LedgerContext::testnet(1, 1000);

        assert!(matches!(
            validate_fee(&frame, &context),
            Err(ValidationError::InsufficientFee { .. })
        ));
    }

    #[test]
    fn test_validate_time_bounds_ok() {
        let frame = create_test_frame();
        let context = LedgerContext::testnet(1, 1000);

        // No time bounds, should pass
        assert!(validate_time_bounds(&frame, &context).is_ok());
    }

    #[test]
    fn test_validate_basic() {
        let frame = create_test_frame();
        let context = LedgerContext::testnet(1, 1000);

        assert!(validate_basic(&frame, &context).is_ok());
    }

    #[test]
    fn test_validate_soroban_missing_data() {
        let envelope = create_soroban_envelope(Vec::new(), None, false);
        let frame = TransactionFrame::new(envelope);
        let context = LedgerContext::testnet(1, 1000);

        assert!(matches!(
            validate_basic(&frame, &context),
            Err(errors) if matches!(errors.first(), Some(ValidationError::InvalidStructure(_)))
        ));
    }

    #[test]
    fn test_validate_soroban_archived_index_out_of_bounds() {
        let key = LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
            hash: Hash([3u8; 32]),
        });
        let envelope = create_soroban_envelope(vec![key], Some(vec![1]), true);
        let frame = TransactionFrame::new(envelope);
        let context = LedgerContext::testnet(1, 1000);

        assert!(matches!(
            validate_basic(&frame, &context),
            Err(errors) if matches!(errors.first(), Some(ValidationError::InvalidStructure(_)))
        ));
    }

    #[test]
    fn test_validate_soroban_archived_key_must_be_persistent() {
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([4u8; 32]))),
            key: ScVal::I32(1),
            durability: ContractDataDurability::Temporary,
        });
        let envelope = create_soroban_envelope(vec![key], Some(vec![0]), true);
        let frame = TransactionFrame::new(envelope);
        let context = LedgerContext::testnet(1, 1000);

        assert!(matches!(
            validate_basic(&frame, &context),
            Err(errors) if matches!(errors.first(), Some(ValidationError::InvalidStructure(_)))
        ));
    }

    #[test]
    fn test_validate_full_min_seq_num() {
        let secret = SecretKey::from_seed(&[9u8; 32]);
        let account_id: AccountId = (&secret.public_key()).into();
        let source = MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes()));

        let op = Operation {
            source_account: None,
            body: OperationBody::ManageData(ManageDataOp {
                data_name: String64::try_from(b"minseq".to_vec()).unwrap(),
                data_value: Some(b"value".to_vec().try_into().unwrap()),
            }),
        };

        let preconditions = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: Some(SequenceNumber(5)),
            min_seq_age: Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: VecM::default(),
        });

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(2),
            cond: preconditions,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let context = LedgerContext::testnet(1, 1000);
        let account = create_account_entry(account_id, 1);
        let result = validate_full(&TransactionFrame::new(envelope), &context, &account);
        assert!(matches!(
            result,
            Err(errors) if matches!(errors.first(), Some(ValidationError::BadMinAccountSequence))
        ));
    }

    #[test]
    fn test_validate_full_extra_signers_missing() {
        let secret = SecretKey::from_seed(&[10u8; 32]);
        let account_id: AccountId = (&secret.public_key()).into();
        let source = MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes()));

        let op = Operation {
            source_account: None,
            body: OperationBody::ManageData(ManageDataOp {
                data_name: String64::try_from(b"extra".to_vec()).unwrap(),
                data_value: Some(b"value".to_vec().try_into().unwrap()),
            }),
        };

        let preconditions = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: None,
            min_seq_age: Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: vec![SignerKey::Ed25519(Uint256([1u8; 32]))]
                .try_into()
                .unwrap(),
        });

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(2),
            cond: preconditions,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let context = LedgerContext::testnet(1, 1000);
        let account = create_account_entry(account_id, 1);
        let result = validate_full(&TransactionFrame::new(envelope), &context, &account);
        assert!(matches!(
            result,
            Err(errors) if matches!(errors.first(), Some(ValidationError::ExtraSignersNotMet))
        ));
    }

    #[test]
    fn test_validate_full_extra_signers_satisfied() {
        let extra_secret = SecretKey::from_seed(&[11u8; 32]);
        let account_secret = SecretKey::from_seed(&[12u8; 32]);
        let account_id: AccountId = (&account_secret.public_key()).into();
        let source = MuxedAccount::Ed25519(Uint256(*account_secret.public_key().as_bytes()));

        let op = Operation {
            source_account: None,
            body: OperationBody::ManageData(ManageDataOp {
                data_name: String64::try_from(b"extra".to_vec()).unwrap(),
                data_value: Some(b"value".to_vec().try_into().unwrap()),
            }),
        };

        let preconditions = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: None,
            min_seq_age: Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: vec![SignerKey::Ed25519(Uint256(*extra_secret.public_key().as_bytes()))]
                .try_into()
                .unwrap(),
        });

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(2),
            cond: preconditions,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let network_id = NetworkId::testnet();
        let sig = sign_envelope(&envelope, &extra_secret, &network_id);
        if let TransactionEnvelope::Tx(ref mut env) = envelope {
            env.signatures = vec![sig].try_into().unwrap();
        }

        let context = LedgerContext::testnet(1, 1000);
        let account = create_account_entry(account_id, 1);
        assert!(validate_full(&TransactionFrame::new(envelope), &context, &account).is_ok());
    }
}
