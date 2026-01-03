use stellar_core_common::NetworkId;
use stellar_core_crypto::{sign_hash, SecretKey};
use stellar_core_ledger::execution::{ExecutionFailure, TransactionExecutor};
use stellar_core_ledger::execution::build_tx_result_pair;
use stellar_core_ledger::{LedgerSnapshot, SnapshotBuilder, SnapshotHandle};
use stellar_core_tx::soroban::SorobanConfig;
use std::sync::Arc;
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, CreateAccountOp, CreateAccountResult,
    DecoratedSignature, Duration, FeeBumpTransaction, FeeBumpTransactionEnvelope,
    FeeBumpTransactionInnerTx, InnerTransactionResultPair, LedgerEntry, LedgerEntryData,
    LedgerEntryExt, LedgerKey, Memo, MuxedAccount, Operation, OperationBody, OperationResult,
    OperationResultTr, Preconditions, PreconditionsV2, PublicKey, SequenceNumber, Signature as XdrSignature,
    SignatureHint, SignerKey, String32, Thresholds, TimeBounds, TimePoint, Transaction,
    TransactionEnvelope, TransactionExt, TransactionResultResult, TransactionV1Envelope, Uint256,
    VecM,
};

fn create_account_entry_with_last_modified(
    account_id: AccountId,
    seq_num: i64,
    balance: i64,
    last_modified_ledger_seq: u32,
) -> (LedgerKey, LedgerEntry) {
    let key = LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
        account_id: account_id.clone(),
    });

    let entry = LedgerEntry {
        last_modified_ledger_seq,
        data: LedgerEntryData::Account(AccountEntry {
            account_id,
            balance,
            seq_num: SequenceNumber(seq_num),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: VecM::default(),
            ext: AccountEntryExt::V0,
        }),
        ext: LedgerEntryExt::V0,
    };

    (key, entry)
}

fn create_account_entry(account_id: AccountId, seq_num: i64, balance: i64) -> (LedgerKey, LedgerEntry) {
    create_account_entry_with_last_modified(account_id, seq_num, balance, 1)
}

fn sign_envelope(envelope: &TransactionEnvelope, secret: &SecretKey, network_id: &NetworkId) -> DecoratedSignature {
    let frame = stellar_core_tx::TransactionFrame::with_network(envelope.clone(), *network_id);
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
fn test_execute_transaction_missing_operation() {
    let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
    let tx = Transaction {
        source_account: source,
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: VecM::default(),
        ext: TransactionExt::V0,
    };
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let snapshot = LedgerSnapshot::empty(1);
    let snapshot = SnapshotHandle::new(snapshot);
    let mut executor =
        TransactionExecutor::new(1, 1000, 100, 5_000_000, 25, NetworkId::testnet(), 0, SorobanConfig::default(), None);

    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");
    assert_eq!(result.failure, Some(ExecutionFailure::MissingOperation));
}

#[test]
fn test_execute_transaction_time_bounds_too_early() {
    let secret = SecretKey::from_seed(&[7u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(2_000),
            max_time: TimePoint(0),
        }),
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut executor =
        TransactionExecutor::new(1, 1_000, 100, 5_000_000, 25, network_id, 0, SorobanConfig::default(), None);
    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::TooEarly));
}

#[test]
fn test_execute_transaction_min_seq_num_precondition() {
    let secret = SecretKey::from_seed(&[9u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
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
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut executor =
        TransactionExecutor::new(1, 1_000, 100, 5_000_000, 25, network_id, 0, SorobanConfig::default(), None);
    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadMinSeqAgeOrGap));
}

#[test]
fn test_execute_transaction_min_seq_age_precondition() {
    let secret = SecretKey::from_seed(&[12u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();
    let last_modified_seq = 5;
    let last_close_time = 900;

    let (key, entry) = create_account_entry_with_last_modified(account_id.clone(), 1, 10_000_000, last_modified_seq);
    let snapshot = SnapshotBuilder::new(10)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let mut snapshot = SnapshotHandle::new(snapshot);

    let mut header = snapshot.header().clone();
    header.ledger_seq = last_modified_seq;
    header.scp_value.close_time = TimePoint(last_close_time);
    let header = Arc::new(header);
    snapshot.set_header_lookup(Arc::new(move |seq| {
        if seq == last_modified_seq {
            Ok(Some((*header).clone()))
        } else {
            Ok(None)
        }
    }));

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: Duration(200),
        min_seq_ledger_gap: 0,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut executor =
        TransactionExecutor::new(10, 1_000, 100, 5_000_000, 25, network_id, 0, SorobanConfig::default(), None);
    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadMinSeqAgeOrGap));
}

#[test]
fn test_execute_transaction_min_seq_ledger_gap_precondition() {
    let secret = SecretKey::from_seed(&[13u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry_with_last_modified(account_id.clone(), 1, 10_000_000, 8);
    let snapshot = SnapshotBuilder::new(10)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 5,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut executor =
        TransactionExecutor::new(10, 1_000, 100, 5_000_000, 25, network_id, 0, SorobanConfig::default(), None);
    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadMinSeqAgeOrGap));
}

#[test]
fn test_execute_transaction_extra_signers_missing() {
    let secret = SecretKey::from_seed(&[10u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([3u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let extra_signer = SignerKey::Ed25519(Uint256([4u8; 32]));
    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: vec![extra_signer].try_into().unwrap(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut executor =
        TransactionExecutor::new(1, 1_000, 100, 5_000_000, 25, network_id, 0, SorobanConfig::default(), None);
    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadAuthExtra));
}

#[test]
fn test_fee_bump_result_encoding() {
    let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32])));

    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let inner_tx = Transaction {
        source_account: source.clone(),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let inner_env = TransactionV1Envelope {
        tx: inner_tx,
        signatures: VecM::default(),
    };

    let fee_bump = FeeBumpTransaction {
        fee_source: source,
        fee: 200,
        inner_tx: FeeBumpTransactionInnerTx::Tx(inner_env),
        ext: stellar_xdr::curr::FeeBumpTransactionExt::V0,
    };

    let envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: fee_bump,
        signatures: VecM::default(),
    });

    let exec = stellar_core_ledger::execution::TransactionExecutionResult {
        success: true,
        fee_charged: 200,
        operation_results: vec![OperationResult::OpInner(OperationResultTr::CreateAccount(
            CreateAccountResult::Success,
        ))],
        error: None,
        failure: None,
        tx_meta: None,
        fee_changes: None,
    };

    let pair = build_tx_result_pair(
        &stellar_core_tx::TransactionFrame::with_network(envelope, NetworkId::testnet()),
        &NetworkId::testnet(),
        &exec,
    )
    .expect("build tx result");

    match pair.result.result {
        TransactionResultResult::TxFeeBumpInnerSuccess(InnerTransactionResultPair { .. }) => {}
        other => panic!("unexpected fee bump result: {:?}", other),
    }
}

#[test]
fn test_operation_failure_rolls_back_changes() {
    let secret = SecretKey::from_seed(&[11u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let op_create = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination: destination.clone(),
            starting_balance: 1_000_000,
        }),
    };

    let op_payment = Operation {
        source_account: None,
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([9u8; 32])),
            asset: stellar_xdr::curr::Asset::Native,
            amount: 10,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 200,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op_create, op_payment].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let mut executor =
        TransactionExecutor::new(1, 1_000, 100, 5_000_000, 25, network_id, 0, SorobanConfig::default(), None);
    let result = executor.execute_transaction(&snapshot, &envelope, 100).expect("execute");

    assert!(!result.success);
    assert_eq!(result.failure, Some(ExecutionFailure::OperationFailed));

    let state = executor.state();
    assert!(state.get_account(&destination).is_none());

    let source = state.get_account(&account_id).expect("source account");
    assert_eq!(source.seq_num.0, 2);
    assert_eq!(source.balance, 10_000_000 - 200);
}
