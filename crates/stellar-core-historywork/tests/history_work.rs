use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use stellar_core_common::Hash256;
use stellar_core_history::verify;
use stellar_core_ledger::TransactionSetVariant;
use stellar_core_history::{
    archive::HistoryArchive,
    archive_state::{HASBucketLevel, HistoryArchiveState},
    paths::{bucket_path, checkpoint_path},
};
use stellar_core_historywork::{HistoryWorkBuilder, HistoryWorkState, LocalArchiveWriter};
use stellar_core_work::{WorkScheduler, WorkSchedulerConfig};
use stellar_xdr::curr::{
    Hash, LedgerHeader, LedgerHeaderExt, LedgerHeaderHistoryEntry, LedgerHeaderHistoryEntryExt,
    LedgerScpMessages, ScpHistoryEntry, ScpHistoryEntryV0, StellarValue, StellarValueExt, TimePoint,
    TransactionHistoryEntry, TransactionHistoryEntryExt, TransactionHistoryResultEntry,
    TransactionHistoryResultEntryExt, TransactionResultSet, TransactionSet, VecM, WriteXdr,
};
use tokio::net::TcpListener;

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn gunzip_bytes(data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut decoder = GzDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).expect("gunzip read");
    output
}

fn make_header(
    ledger_seq: u32,
    bucket_list_hash: Hash256,
    tx_set_hash: Hash256,
    tx_result_hash: Hash256,
) -> LedgerHeader {
    LedgerHeader {
        ledger_version: 25,
        previous_ledger_hash: Hash([0u8; 32]),
        scp_value: StellarValue {
            tx_set_hash: Hash(*tx_set_hash.as_bytes()),
            close_time: TimePoint(0),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash(*tx_result_hash.as_bytes()),
        bucket_list_hash: Hash(*bucket_list_hash.as_bytes()),
        ledger_seq,
        total_coins: 1_000_000,
        fee_pool: 0,
        inflation_seq: 0,
        id_pool: 0,
        base_fee: 100,
        base_reserve: 100,
        max_tx_set_size: 100,
        skip_list: [
            Hash([0u8; 32]),
            Hash([0u8; 32]),
            Hash([0u8; 32]),
            Hash([0u8; 32]),
        ],
        ext: LedgerHeaderExt::V0,
    }
}

#[tokio::test]
async fn test_history_work_chain() {
    let checkpoint = 63u32;
    let bucket_data: Vec<u8> = Vec::new();
    let bucket_hash = Hash256::hash(&bucket_data);

    let tx_set = TransactionSet {
        previous_ledger_hash: Hash([0u8; 32]),
        txs: VecM::default(),
    };
    let tx_set_hash =
        verify::compute_tx_set_hash(&TransactionSetVariant::Classic(tx_set.clone()))
            .expect("tx set hash");

    let tx_result_set = TransactionResultSet {
        results: VecM::default(),
    };
    let tx_result_xdr = tx_result_set
        .to_xdr(stellar_xdr::curr::Limits::none())
        .expect("tx result xdr");
    let tx_result_hash = Hash256::hash(&tx_result_xdr);

    let header = make_header(checkpoint, Hash256::ZERO, tx_set_hash, tx_result_hash);
    let header_entry = LedgerHeaderHistoryEntry {
        hash: Hash([0u8; 32]),
        header,
        ext: LedgerHeaderHistoryEntryExt::default(),
    };
    let header_xdr = header_entry.to_xdr(stellar_xdr::curr::Limits::none()).expect("xdr");

    let has = HistoryArchiveState {
        version: 2,
        server: Some("rs-stellar-core test".to_string()),
        current_ledger: checkpoint,
        network_passphrase: Some("Test SDF Network ; September 2015".to_string()),
        current_buckets: vec![HASBucketLevel {
            curr: bucket_hash.to_hex(),
            snap: "0".repeat(64),
            next: Default::default(),
        }],
        hot_archive_buckets: None,
    };

    let mut fixtures: HashMap<String, Vec<u8>> = HashMap::new();
    fixtures.insert(
        checkpoint_path("history", checkpoint, "json"),
        has.to_json().unwrap().into_bytes(),
    );
    fixtures.insert(
        checkpoint_path("ledger", checkpoint, "xdr.gz"),
        gzip_bytes(&header_xdr),
    );
    fixtures.insert(bucket_path(&bucket_hash), gzip_bytes(&bucket_data));

    let tx_entry = TransactionHistoryEntry {
        ledger_seq: checkpoint,
        tx_set,
        ext: TransactionHistoryEntryExt::default(),
    };
    let tx_entry_xdr = tx_entry
        .to_xdr(stellar_xdr::curr::Limits::none())
        .expect("tx entry xdr");
    fixtures.insert(
        checkpoint_path("transactions", checkpoint, "xdr.gz"),
        gzip_bytes(&tx_entry_xdr),
    );

    let tx_result_entry = TransactionHistoryResultEntry {
        ledger_seq: checkpoint,
        tx_result_set,
        ext: TransactionHistoryResultEntryExt::default(),
    };
    let tx_result_entry_xdr = tx_result_entry
        .to_xdr(stellar_xdr::curr::Limits::none())
        .expect("tx result entry xdr");
    fixtures.insert(
        checkpoint_path("results", checkpoint, "xdr.gz"),
        gzip_bytes(&tx_result_entry_xdr),
    );

    let scp_entry = ScpHistoryEntry::V0(ScpHistoryEntryV0 {
        quorum_sets: VecM::default(),
        ledger_messages: LedgerScpMessages {
            ledger_seq: checkpoint,
            messages: VecM::default(),
        },
    });
    let scp_entry_xdr = scp_entry
        .to_xdr(stellar_xdr::curr::Limits::none())
        .expect("scp entry xdr");
    fixtures.insert(
        checkpoint_path("scp", checkpoint, "xdr.gz"),
        gzip_bytes(&scp_entry_xdr),
    );

    let fixtures = Arc::new(fixtures);
    let app = Router::new()
        .route("/*path", get(|Path(path): Path<String>, State(state): State<Arc<HashMap<String, Vec<u8>>>>| async move {
            if let Some(body) = state.get(&path) {
                (StatusCode::OK, body.clone())
            } else {
                (StatusCode::NOT_FOUND, Vec::new())
            }
        }))
        .with_state(Arc::clone(&fixtures));

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: tcp bind not permitted in this environment");
            return;
        }
        Err(err) => panic!("bind: {err}"),
    };
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let archive = Arc::new(HistoryArchive::new(&format!("http://{}/", addr)).expect("archive"));
    let state = Arc::new(tokio::sync::Mutex::new(HistoryWorkState::default()));

    let mut scheduler = WorkScheduler::new(WorkSchedulerConfig {
        max_concurrency: 2,
        retry_delay: std::time::Duration::from_millis(10),
        event_tx: None,
    });
    let builder = HistoryWorkBuilder::new(archive, checkpoint, Arc::clone(&state));
    let ids = builder.register(&mut scheduler);

    let publish_dir = tempfile::tempdir().expect("publish dir");
    let writer = Arc::new(LocalArchiveWriter::new(publish_dir.path().to_path_buf()));
    builder.register_publish(&mut scheduler, writer, ids);

    scheduler.run_until_done().await;

    let guard = state.lock().await;
    assert!(guard.has.is_some());
    assert_eq!(guard.buckets.len(), 1);
    assert_eq!(guard.headers.len(), 1);
    assert_eq!(guard.transactions.len(), 1);
    assert_eq!(guard.tx_results.len(), 1);
    assert_eq!(guard.scp_history.len(), 1);
    assert!(guard.progress.stage.is_some());
    assert!(!guard.progress.message.is_empty());

    let has_path = publish_dir.path().join(checkpoint_path("history", checkpoint, "json"));
    let bucket_file = publish_dir.path().join(bucket_path(&bucket_hash));
    let headers_file = publish_dir
        .path()
        .join(checkpoint_path("ledger", checkpoint, "xdr.gz"));
    let transactions_file = publish_dir
        .path()
        .join(checkpoint_path("transactions", checkpoint, "xdr.gz"));
    let results_file = publish_dir
        .path()
        .join(checkpoint_path("results", checkpoint, "xdr.gz"));
    let scp_file = publish_dir
        .path()
        .join(checkpoint_path("scp", checkpoint, "xdr.gz"));
    assert!(has_path.exists());
    assert!(bucket_file.exists());
    assert!(headers_file.exists());
    assert!(transactions_file.exists());
    assert!(results_file.exists());
    assert!(scp_file.exists());

    let has_payload = std::fs::read_to_string(&has_path).expect("read has");
    let parsed_has = HistoryArchiveState::from_json(&has_payload).expect("parse has");
    assert_eq!(parsed_has.current_ledger, checkpoint);
    assert_eq!(parsed_has.current_buckets.len(), 1);

    let bucket_payload = std::fs::read(&bucket_file).expect("read bucket");
    assert_eq!(gunzip_bytes(&bucket_payload), bucket_data);

    let headers_payload = std::fs::read(&headers_file).expect("read ledger headers");
    assert_eq!(gunzip_bytes(&headers_payload), header_xdr);

    let transactions_payload = std::fs::read(&transactions_file).expect("read transactions");
    assert_eq!(gunzip_bytes(&transactions_payload), tx_entry_xdr);

    let results_payload = std::fs::read(&results_file).expect("read results");
    assert_eq!(gunzip_bytes(&results_payload), tx_result_entry_xdr);

    let scp_payload = std::fs::read(&scp_file).expect("read scp");
    assert_eq!(gunzip_bytes(&scp_payload), scp_entry_xdr);
}
