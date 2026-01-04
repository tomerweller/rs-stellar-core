//! Ledger header queries.

use rusqlite::{Connection, OptionalExtension, params};
use stellar_core_common::Hash256;
use stellar_xdr::curr::{LedgerHeader, ReadXdr, Limits};

use super::super::error::DbError;

/// Trait for querying and storing ledger headers.
pub trait LedgerQueries {
    /// Load a ledger header by sequence number.
    fn load_ledger_header(&self, seq: u32) -> Result<Option<LedgerHeader>, DbError>;

    /// Store a ledger header.
    fn store_ledger_header(&self, header: &LedgerHeader, data: &[u8]) -> Result<(), DbError>;

    /// Get the latest ledger sequence number.
    fn get_latest_ledger_seq(&self) -> Result<Option<u32>, DbError>;

    /// Get the hash of a ledger by sequence number.
    fn get_ledger_hash(&self, seq: u32) -> Result<Option<Hash256>, DbError>;
}

impl LedgerQueries for Connection {
    fn load_ledger_header(&self, seq: u32) -> Result<Option<LedgerHeader>, DbError> {
        let result: Option<Vec<u8>> = self
            .query_row(
                "SELECT data FROM ledgerheaders WHERE ledgerseq = ?1",
                params![seq],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(data) => {
                let header = LedgerHeader::from_xdr(&data, Limits::none())?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    fn store_ledger_header(&self, header: &LedgerHeader, data: &[u8]) -> Result<(), DbError> {
        let ledger_hash = Hash256::hash(data);
        let prev_hash = Hash256::from(header.previous_ledger_hash.clone());
        let bucket_list_hash = Hash256::from(header.bucket_list_hash.clone());

        self.execute(
            r#"
            INSERT OR REPLACE INTO ledgerheaders
            (ledgerhash, prevhash, bucketlisthash, ledgerseq, closetime, data)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                ledger_hash.to_hex(),
                prev_hash.to_hex(),
                bucket_list_hash.to_hex(),
                header.ledger_seq,
                header.scp_value.close_time.0,
                data,
            ],
        )?;
        Ok(())
    }

    fn get_latest_ledger_seq(&self) -> Result<Option<u32>, DbError> {
        // MAX() returns NULL when the table is empty, so we get the value optionally
        let result: Option<Option<u32>> = self
            .query_row(
                "SELECT MAX(ledgerseq) FROM ledgerheaders",
                [],
                |row| row.get::<_, Option<u32>>(0),
            )
            .optional()?;
        Ok(result.flatten())
    }

    fn get_ledger_hash(&self, seq: u32) -> Result<Option<Hash256>, DbError> {
        let result: Option<String> = self
            .query_row(
                "SELECT ledgerhash FROM ledgerheaders WHERE ledgerseq = ?1",
                params![seq],
                |row| row.get(0),
            )
            .optional()?;

        match result {
            Some(hex) => {
                let hash = Hash256::from_hex(&hex).map_err(|e| {
                    DbError::Integrity(format!("Invalid ledger hash: {}", e))
                })?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use stellar_xdr::curr::{
        Hash, LedgerHeader, LedgerHeaderExt, StellarValue, StellarValueExt, TimePoint, WriteXdr,
    };

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE ledgerheaders (
                ledgerhash TEXT PRIMARY KEY,
                prevhash TEXT NOT NULL,
                bucketlisthash TEXT NOT NULL,
                ledgerseq INTEGER UNIQUE NOT NULL,
                closetime INTEGER NOT NULL,
                data BLOB NOT NULL
            );
            CREATE INDEX ledgerheaders_seq ON ledgerheaders(ledgerseq);
            "#,
        )
        .unwrap();
        conn
    }

    fn create_test_header(seq: u32) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 20,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(1234567890),
                upgrades: vec![].try_into().unwrap(),
                ext: StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash([1u8; 32]),
            ledger_seq: seq,
            total_coins: 100_000_000_000_000_000,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 5_000_000,
            max_tx_set_size: 100,
            skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
            ext: LedgerHeaderExt::V0,
        }
    }

    #[test]
    fn test_store_and_load_ledger_header() {
        let conn = setup_db();
        let header = create_test_header(100);
        let data = header.to_xdr(Limits::none()).unwrap();

        conn.store_ledger_header(&header, &data).unwrap();

        let loaded = conn.load_ledger_header(100).unwrap().unwrap();
        assert_eq!(loaded.ledger_seq, 100);
        assert_eq!(loaded.base_fee, 100);
    }

    #[test]
    fn test_get_latest_ledger_seq() {
        let conn = setup_db();

        // Initially no ledgers
        assert!(conn.get_latest_ledger_seq().unwrap().is_none());

        // Add some ledgers
        for seq in [10, 20, 15] {
            let header = create_test_header(seq);
            let data = header.to_xdr(Limits::none()).unwrap();
            conn.store_ledger_header(&header, &data).unwrap();
        }

        assert_eq!(conn.get_latest_ledger_seq().unwrap(), Some(20));
    }

    #[test]
    fn test_get_ledger_hash() {
        let conn = setup_db();
        let header = create_test_header(100);
        let data = header.to_xdr(Limits::none()).unwrap();

        conn.store_ledger_header(&header, &data).unwrap();

        let hash = conn.get_ledger_hash(100).unwrap().unwrap();
        assert!(!hash.is_zero());

        // Non-existent ledger
        assert!(conn.get_ledger_hash(999).unwrap().is_none());
    }
}
