use stellar_core_common::NetworkId;
use stellar_core_crypto::{sign_hash, SecretKey};
use stellar_core_ledger::execution::{ExecutionFailure, TransactionExecutor};
use stellar_core_ledger::execution::build_tx_result_pair;
use stellar_core_ledger::{LedgerSnapshot, SnapshotBuilder, SnapshotHandle};
use stellar_core_tx::{soroban::SorobanConfig, ClassicEventConfig};
use std::sync::Arc;
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, CreateAccountOp, CreateAccountResult,
    BytesM, ContractCodeEntry, ContractCodeEntryExt, ContractEventBody, ContractId, ContractIdPreimage,
    DecoratedSignature, Duration, ExtendFootprintTtlOp, FeeBumpTransaction, FeeBumpTransactionEnvelope,
    FeeBumpTransactionInnerTx, Hash, HashIdPreimage, HashIdPreimageContractId, InnerTransactionResultPair,
    Int128Parts, LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerFootprint, LedgerKey, MuxedAccountMed25519,
    LedgerKeyContractCode, LedgerKeyTtl, Memo, MuxedAccount, Operation, OperationBody, OperationResult,
    OperationResultTr, Preconditions, PreconditionsV2, PublicKey, ScAddress, ScString, ScSymbol, ScVal,
    SequenceNumber, Signature as XdrSignature, SignatureHint, SignerKey, SorobanResources,
    SorobanTransactionData, SorobanTransactionDataExt, String32, StringM, Thresholds, TimeBounds,
    TimePoint, Transaction, TransactionEnvelope, TransactionEventStage, TransactionExt, TransactionMeta,
    TransactionResultResult, TransactionV1Envelope, TtlEntry, Uint256, VecM,
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

fn i128_parts(value: i128) -> Int128Parts {
    Int128Parts {
        hi: (value >> 64) as i64,
        lo: value as u64,
    }
}

fn scval_symbol(sym: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(StringM::try_from(sym).unwrap()))
}

fn native_asset_contract_id(network_id: &NetworkId) -> ContractId {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash::from(network_id.0),
        contract_id_preimage: ContractIdPreimage::Asset(stellar_xdr::curr::Asset::Native),
    });
    let hash = stellar_core_common::Hash256::hash_xdr(&preimage)
        .unwrap_or_else(|_| stellar_core_common::Hash256::ZERO);
    ContractId(Hash::from(hash))
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
        TransactionExecutor::new(
            1,
            1000,
            100,
            5_000_000,
            25,
            NetworkId::testnet(),
            0,
            SorobanConfig::default(),
            ClassicEventConfig::default(),
            None,
        );

    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor =
        TransactionExecutor::new(
            1,
            1_000,
            100,
            5_000_000,
            25,
            network_id,
            0,
            SorobanConfig::default(),
            classic_events,
            None,
        );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

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
        TransactionExecutor::new(
            10,
            1_000,
            100,
            5_000_000,
            25,
            network_id,
            0,
            SorobanConfig::default(),
            ClassicEventConfig::default(),
            None,
        );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

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
        TransactionExecutor::new(
            10,
            1_000,
            100,
            5_000_000,
            25,
            network_id,
            0,
            SorobanConfig::default(),
            ClassicEventConfig::default(),
            None,
        );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

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
        post_fee_changes: None,
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(!result.success);
    assert_eq!(result.failure, Some(ExecutionFailure::OperationFailed));

    let state = executor.state();
    assert!(state.get_account(&destination).is_none());

    let source = state.get_account(&account_id).expect("source account");
    assert_eq!(source.seq_num.0, 2);
    assert_eq!(source.balance, 10_000_000 - 200);
}

#[test]
fn test_classic_events_emitted_for_payment() {
    let secret = SecretKey::from_seed(&[21u8; 32]);
    let source_id: AccountId = (&secret.public_key()).into();
    let dest_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([4u8; 32])));

    let (source_key, source_entry) = create_account_entry(source_id.clone(), 1, 20_000_000);
    let (dest_key, dest_entry) = create_account_entry(dest_id.clone(), 1, 1_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(source_key, source_entry)
        .expect("add source")
        .add_entry(dest_key, dest_entry)
        .expect("add dest")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let operation = Operation {
        source_account: None,
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([4u8; 32])),
            asset: stellar_xdr::curr::Asset::Native,
            amount: 100,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor =
        TransactionExecutor::new(
            1,
            1_000,
            100,
            5_000_000,
            25,
            network_id,
            0,
            SorobanConfig::default(),
            classic_events,
            None,
        );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(result.success);
    let tx_meta = result.tx_meta.expect("tx meta");
    let TransactionMeta::V4(meta) = tx_meta else {
        panic!("unexpected tx meta");
    };

    let tx_events: &[stellar_xdr::curr::TransactionEvent] = meta.events.as_ref();
    assert_eq!(tx_events.len(), 1);
    let fee_event = &tx_events[0];
    assert_eq!(fee_event.stage, TransactionEventStage::BeforeAllTxs);
    let contract_id = native_asset_contract_id(&network_id);
    assert_eq!(fee_event.event.contract_id, Some(contract_id.clone()));
    let ContractEventBody::V0(fee_body) = &fee_event.event.body;
    let fee_topics: &[ScVal] = fee_body.topics.as_ref();
    assert_eq!(fee_topics.len(), 2);
    assert_eq!(
        fee_topics[0],
        ScVal::Symbol(ScSymbol(StringM::try_from("fee").unwrap()))
    );
    assert_eq!(
        fee_topics[1],
        ScVal::Address(ScAddress::Account(source_id.clone()))
    );
    assert_eq!(
        fee_body.data,
        ScVal::I128(i128_parts(100))
    );

    let op_events: &[stellar_xdr::curr::OperationMetaV2] = meta.operations.as_ref();
    assert_eq!(op_events.len(), 1);
    let op_event_list: &[stellar_xdr::curr::ContractEvent] = op_events[0].events.as_ref();
    assert_eq!(op_event_list.len(), 1);
    let op_event = &op_event_list[0];
    assert_eq!(op_event.contract_id, Some(contract_id));
    let ContractEventBody::V0(op_body) = &op_event.body;
    let op_topics: &[ScVal] = op_body.topics.as_ref();
    assert_eq!(op_topics.len(), 4);
    assert_eq!(
        op_topics[0],
        ScVal::Symbol(ScSymbol(StringM::try_from("transfer").unwrap()))
    );
    assert_eq!(
        op_topics[1],
        ScVal::Address(ScAddress::Account(source_id.clone()))
    );
    assert_eq!(
        op_topics[2],
        ScVal::Address(ScAddress::Account(dest_id.clone()))
    );
    assert_eq!(
        op_topics[3],
        ScVal::String(ScString(StringM::try_from("native").unwrap()))
    );
    assert_eq!(
        op_body.data,
        ScVal::I128(i128_parts(100))
    );
}

#[test]
fn test_classic_events_payment_with_muxed_destination() {
    let secret = SecretKey::from_seed(&[41u8; 32]);
    let source_id: AccountId = (&secret.public_key()).into();
    let dest_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7u8; 32])));

    let (source_key, source_entry) = create_account_entry(source_id.clone(), 1, 20_000_000);
    let (dest_key, dest_entry) = create_account_entry(dest_account_id.clone(), 1, 1_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(source_key, source_entry)
        .expect("add source")
        .add_entry(dest_key, dest_entry)
        .expect("add dest")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let muxed_dest = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: 42,
        ed25519: Uint256([7u8; 32]),
    });
    let operation = Operation {
        source_account: None,
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: muxed_dest,
            asset: stellar_xdr::curr::Asset::Native,
            amount: 200,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(result.success);
    let tx_meta = result.tx_meta.expect("tx meta");
    let TransactionMeta::V4(meta) = tx_meta else {
        panic!("unexpected tx meta");
    };

    let op_events: &[stellar_xdr::curr::OperationMetaV2] = meta.operations.as_ref();
    assert_eq!(op_events.len(), 1);
    let op_event_list: &[stellar_xdr::curr::ContractEvent] = op_events[0].events.as_ref();
    assert_eq!(op_event_list.len(), 1);
    let op_event = &op_event_list[0];
    let ContractEventBody::V0(op_body) = &op_event.body;
    let ScVal::Map(Some(map)) = &op_body.data else {
        panic!("expected map data for muxed destination");
    };
    let entries: &[stellar_xdr::curr::ScMapEntry] = map.0.as_ref();
    assert_eq!(entries.len(), 2);
    let amount_entry = entries
        .iter()
        .find(|entry| entry.key == scval_symbol("amount"))
        .expect("amount entry");
    assert_eq!(amount_entry.val, ScVal::I128(i128_parts(200)));
    let muxed_entry = entries
        .iter()
        .find(|entry| entry.key == scval_symbol("to_muxed_id"))
        .expect("muxed entry");
    assert_eq!(muxed_entry.val, ScVal::U64(42));
}

#[test]
fn test_classic_events_payment_with_memo_data() {
    let secret = SecretKey::from_seed(&[51u8; 32]);
    let source_id: AccountId = (&secret.public_key()).into();
    let dest_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([8u8; 32])));

    let (source_key, source_entry) = create_account_entry(source_id.clone(), 1, 20_000_000);
    let (dest_key, dest_entry) = create_account_entry(dest_id.clone(), 1, 1_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(source_key, source_entry)
        .expect("add source")
        .add_entry(dest_key, dest_entry)
        .expect("add dest")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let operation = Operation {
        source_account: None,
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([8u8; 32])),
            asset: stellar_xdr::curr::Asset::Native,
            amount: 150,
        }),
    };

    let memo_text = StringM::try_from("test memo").unwrap();
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
        memo: Memo::Text(memo_text.clone()),
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(result.success);
    let tx_meta = result.tx_meta.expect("tx meta");
    let TransactionMeta::V4(meta) = tx_meta else {
        panic!("unexpected tx meta");
    };

    let op_events: &[stellar_xdr::curr::OperationMetaV2] = meta.operations.as_ref();
    assert_eq!(op_events.len(), 1);
    let op_event_list: &[stellar_xdr::curr::ContractEvent] = op_events[0].events.as_ref();
    assert_eq!(op_event_list.len(), 1);
    let op_event = &op_event_list[0];
    let ContractEventBody::V0(op_body) = &op_event.body;
    let ScVal::Map(Some(map)) = &op_body.data else {
        panic!("expected map data for memo");
    };
    let entries: &[stellar_xdr::curr::ScMapEntry] = map.0.as_ref();
    assert_eq!(entries.len(), 2);
    let amount_entry = entries
        .iter()
        .find(|entry| entry.key == scval_symbol("amount"))
        .expect("amount entry");
    assert_eq!(amount_entry.val, ScVal::I128(i128_parts(150)));
    let memo_entry = entries
        .iter()
        .find(|entry| entry.key == scval_symbol("to_muxed_id"))
        .expect("memo entry");
    let expected_memo = ScVal::String(ScString(StringM::try_from("test memo").unwrap()));
    assert_eq!(memo_entry.val, expected_memo);
}

#[test]
fn test_classic_events_payment_memo_precedence() {
    let secret = SecretKey::from_seed(&[61u8; 32]);
    let source_id: AccountId = (&secret.public_key()).into();
    let dest_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([9u8; 32])));

    let (source_key, source_entry) = create_account_entry(source_id.clone(), 1, 20_000_000);
    let (dest_key, dest_entry) = create_account_entry(dest_account_id.clone(), 1, 1_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(source_key, source_entry)
        .expect("add source")
        .add_entry(dest_key, dest_entry)
        .expect("add dest")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let muxed_dest = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: 77,
        ed25519: Uint256([9u8; 32]),
    });
    let operation = Operation {
        source_account: None,
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: muxed_dest,
            asset: stellar_xdr::curr::Asset::Native,
            amount: 250,
        }),
    };

    let memo_text = StringM::try_from("memo wins?").unwrap();
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
        memo: Memo::Text(memo_text),
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(result.success);
    let tx_meta = result.tx_meta.expect("tx meta");
    let TransactionMeta::V4(meta) = tx_meta else {
        panic!("unexpected tx meta");
    };

    let op_events: &[stellar_xdr::curr::OperationMetaV2] = meta.operations.as_ref();
    assert_eq!(op_events.len(), 1);
    let op_event_list: &[stellar_xdr::curr::ContractEvent] = op_events[0].events.as_ref();
    assert_eq!(op_event_list.len(), 1);
    let op_event = &op_event_list[0];
    let ContractEventBody::V0(op_body) = &op_event.body;
    let ScVal::Map(Some(map)) = &op_body.data else {
        panic!("expected map data for muxed destination");
    };
    let entries: &[stellar_xdr::curr::ScMapEntry] = map.0.as_ref();
    assert_eq!(entries.len(), 2);
    let muxed_entry = entries
        .iter()
        .find(|entry| entry.key == scval_symbol("to_muxed_id"))
        .expect("muxed entry");
    assert_eq!(muxed_entry.val, ScVal::U64(77));
}

#[test]
fn test_soroban_refund_event_after_all_txs() {
    let secret = SecretKey::from_seed(&[33u8; 32]);
    let source_id: AccountId = (&secret.public_key()).into();

    let (source_key, source_entry) = create_account_entry(source_id.clone(), 1, 20_000_000);

    let code_hash = Hash([9u8; 32]);
    let contract_code = ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash: code_hash.clone(),
        code: BytesM::try_from(vec![1u8, 2u8, 3u8]).unwrap(),
    };
    let contract_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: code_hash.clone(),
    });
    let contract_entry = LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::ContractCode(contract_code),
        ext: LedgerEntryExt::V0,
    };

    let key_hash = {
        use sha2::{Digest, Sha256};
        use stellar_xdr::curr::WriteXdr;

        let mut hasher = Sha256::new();
        let bytes = contract_key.to_xdr(stellar_xdr::curr::Limits::none()).unwrap_or_default();
        hasher.update(&bytes);
        Hash(hasher.finalize().into())
    };
    let ttl_entry = LedgerEntry {
        last_modified_ledger_seq: 1,
        data: LedgerEntryData::Ttl(TtlEntry {
            key_hash: key_hash.clone(),
            live_until_ledger_seq: 10,
        }),
        ext: LedgerEntryExt::V0,
    };
    let ttl_key = LedgerKey::Ttl(LedgerKeyTtl { key_hash });

    let snapshot = SnapshotBuilder::new(1)
        .add_entry(source_key, source_entry)
        .expect("add source")
        .add_entry(contract_key.clone(), contract_entry)
        .expect("add contract")
        .add_entry(ttl_key, ttl_entry)
        .expect("add ttl")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let operation = Operation {
        source_account: None,
        body: OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp {
            ext: stellar_xdr::curr::ExtensionPoint::V0,
            extend_to: 100,
        }),
    };

    let soroban_data = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: vec![contract_key].try_into().unwrap(),
                read_write: VecM::default(),
            },
            instructions: 0,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 900,
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 1000,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V1(soroban_data),
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

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let mut executor = TransactionExecutor::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
        0,
        SorobanConfig::default(),
        classic_events,
        None,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(result.success);
    assert_eq!(result.fee_charged, 100);

    let tx_meta = result.tx_meta.expect("tx meta");
    let TransactionMeta::V4(meta) = tx_meta else {
        panic!("unexpected tx meta");
    };

    let tx_events: &[stellar_xdr::curr::TransactionEvent] = meta.events.as_ref();
    assert_eq!(tx_events.len(), 2);

    let contract_id = native_asset_contract_id(&network_id);
    let fee_event = &tx_events[0];
    assert_eq!(fee_event.stage, TransactionEventStage::BeforeAllTxs);
    let ContractEventBody::V0(fee_body) = &fee_event.event.body;
    assert_eq!(fee_event.event.contract_id, Some(contract_id.clone()));
    assert_eq!(
        fee_body.data,
        ScVal::I128(i128_parts(1000))
    );

    let refund_event = &tx_events[1];
    assert_eq!(refund_event.stage, TransactionEventStage::AfterAllTxs);
    let ContractEventBody::V0(refund_body) = &refund_event.event.body;
    assert_eq!(refund_event.event.contract_id, Some(contract_id));
    assert_eq!(
        refund_body.data,
        ScVal::I128(i128_parts(-900))
    );
}
