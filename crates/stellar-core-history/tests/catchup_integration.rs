use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use flate2::{write::GzEncoder, Compression};
use stellar_core_bucket::{Bucket, BucketList};
use stellar_core_common::Hash256;
use stellar_core_db::Database;
use stellar_core_history::{
    archive::HistoryArchive,
    archive_state::{HASBucketLevel, HistoryArchiveState},
    catchup::{CatchupManagerBuilder, CatchupOptions},
    paths::{bucket_path, checkpoint_path},
};
use stellar_xdr::curr::{
    Hash, LedgerHeader, LedgerHeaderExt, LedgerHeaderHistoryEntry, LedgerHeaderHistoryEntryExt,
    StellarValue, StellarValueExt, TimePoint, VecM, WriteXdr,
};
use tokio::net::TcpListener;

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn make_test_header(ledger_seq: u32, bucket_list_hash: Hash256) -> LedgerHeader {
    LedgerHeader {
        ledger_version: 25,
        previous_ledger_hash: Hash([0u8; 32]),
        scp_value: StellarValue {
            tx_set_hash: Hash([0u8; 32]),
            close_time: TimePoint(0),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        },
        tx_set_result_hash: Hash([0u8; 32]),
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

fn make_bucket_list_with_hash(bucket_hash: Hash256) -> BucketList {
    let mut hashes = Vec::with_capacity(22);
    for level in 0..11 {
        if level == 0 {
            hashes.push(bucket_hash);
            hashes.push(Hash256::ZERO);
        } else {
            hashes.push(Hash256::ZERO);
            hashes.push(Hash256::ZERO);
        }
    }

    let bucket_data: Vec<u8> = Vec::new();
    let load_bucket = move |hash: &Hash256| -> stellar_core_bucket::Result<Bucket> {
        if hash.is_zero() {
            return Ok(Bucket::empty());
        }
        Bucket::from_xdr_bytes(&bucket_data)
    };

    BucketList::restore_from_hashes(&hashes, load_bucket).expect("restore bucket list")
}

#[tokio::test]
async fn test_catchup_against_local_archive_checkpoint() {
    let checkpoint = 63u32;
    let bucket_data: Vec<u8> = Vec::new();
    let bucket_hash = Hash256::hash(&bucket_data);
    let bucket_list = make_bucket_list_with_hash(bucket_hash);
    let bucket_list_hash = bucket_list.hash();

    let header = make_test_header(checkpoint, bucket_list_hash);
    let header_entry = LedgerHeaderHistoryEntry {
        hash: Hash([0u8; 32]),
        header,
        ext: LedgerHeaderHistoryEntryExt::default(),
    };
    let header_xdr = header_entry
        .to_xdr(stellar_xdr::curr::Limits::none())
        .expect("header xdr");

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
    let has_json = has.to_json().expect("has json");

    let mut fixtures: HashMap<String, Vec<u8>> = HashMap::new();
    fixtures.insert(checkpoint_path("history", checkpoint, "json"), has_json.into_bytes());
    fixtures.insert(
        checkpoint_path("ledger", checkpoint, "xdr.gz"),
        gzip_bytes(&header_xdr),
    );
    fixtures.insert(bucket_path(&bucket_hash), gzip_bytes(&bucket_data));

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

    let base_url = format!("http://{}/", addr);
    let archive = HistoryArchive::new(&base_url).expect("archive");

    let bucket_dir = tempfile::tempdir().expect("bucket dir");
    let bucket_manager = stellar_core_bucket::BucketManager::new(bucket_dir.path().to_path_buf())
        .expect("bucket manager");
    let db = Database::open_in_memory().expect("db");

    let mut manager = CatchupManagerBuilder::new()
        .add_archive(archive)
        .bucket_manager(bucket_manager)
        .database(db)
        .options(CatchupOptions {
            verify_buckets: true,
            verify_headers: true,
            ..CatchupOptions::default()
        })
        .build()
        .expect("catchup manager");

    let output = manager
        .catchup_to_ledger(checkpoint)
        .await
        .expect("catchup");

    assert_eq!(output.result.ledger_seq, checkpoint);
    assert_eq!(output.result.buckets_downloaded, 1);
    assert_eq!(output.result.ledgers_applied, 0);
}
