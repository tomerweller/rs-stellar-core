//! Transaction history queries.

use rusqlite::{Connection, OptionalExtension, params};
use stellar_xdr::curr::{
    Limits, ReadXdr, TransactionHistoryEntry, TransactionHistoryResultEntry, WriteXdr,
};

use super::super::error::DbError;

/// A record of a transaction stored in history.
#[derive(Debug, Clone)]
pub struct TxRecord {
    /// The transaction ID (hash).
    pub tx_id: String,
    /// The ledger sequence number where this transaction was included.
    pub ledger_seq: u32,
    /// The index of this transaction within the ledger.
    pub tx_index: u32,
    /// The XDR-encoded transaction body.
    pub body: Vec<u8>,
    /// The XDR-encoded transaction result.
    pub result: Vec<u8>,
    /// The XDR-encoded transaction meta (optional).
    pub meta: Option<Vec<u8>>,
}

/// Trait for querying and storing transaction history.
pub trait HistoryQueries {
    /// Store a transaction in history.
    fn store_transaction(
        &self,
        ledger_seq: u32,
        tx_index: u32,
        tx_id: &str,
        body: &[u8],
        result: &[u8],
        meta: Option<&[u8]>,
    ) -> Result<(), DbError>;

    /// Load a transaction by ID.
    fn load_transaction(&self, tx_id: &str) -> Result<Option<TxRecord>, DbError>;

    /// Store a transaction history entry (tx set).
    fn store_tx_history_entry(
        &self,
        ledger_seq: u32,
        entry: &TransactionHistoryEntry,
    ) -> Result<(), DbError>;

    /// Load a transaction history entry (tx set).
    fn load_tx_history_entry(
        &self,
        ledger_seq: u32,
    ) -> Result<Option<TransactionHistoryEntry>, DbError>;

    /// Store a transaction history result entry (tx results).
    fn store_tx_result_entry(
        &self,
        ledger_seq: u32,
        entry: &TransactionHistoryResultEntry,
    ) -> Result<(), DbError>;

    /// Load a transaction history result entry (tx results).
    fn load_tx_result_entry(
        &self,
        ledger_seq: u32,
    ) -> Result<Option<TransactionHistoryResultEntry>, DbError>;
}

impl HistoryQueries for Connection {
    fn store_transaction(
        &self,
        ledger_seq: u32,
        tx_index: u32,
        tx_id: &str,
        body: &[u8],
        result: &[u8],
        meta: Option<&[u8]>,
    ) -> Result<(), DbError> {
        self.execute(
            r#"
            INSERT OR REPLACE INTO txhistory
            (txid, ledgerseq, txindex, txbody, txresult, txmeta)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                tx_id,
                ledger_seq,
                tx_index,
                body,
                result,
                meta,
            ],
        )?;
        Ok(())
    }

    fn load_transaction(&self, tx_id: &str) -> Result<Option<TxRecord>, DbError> {
        let result: Option<(u32, u32, Vec<u8>, Vec<u8>, Option<Vec<u8>>)> = self
            .query_row(
                r#"
                SELECT ledgerseq, txindex, txbody, txresult, txmeta
                FROM txhistory WHERE txid = ?1
                "#,
                params![tx_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((ledger_seq, tx_index, body, result, meta)) => Ok(Some(TxRecord {
                tx_id: tx_id.to_string(),
                ledger_seq,
                tx_index,
                body,
                result,
                meta,
            })),
            None => Ok(None),
        }
    }

    fn store_tx_history_entry(
        &self,
        ledger_seq: u32,
        entry: &TransactionHistoryEntry,
    ) -> Result<(), DbError> {
        let data = entry.to_xdr(Limits::none())?;
        self.execute(
            "INSERT OR REPLACE INTO txsets (ledgerseq, data) VALUES (?1, ?2)",
            params![ledger_seq, data],
        )?;
        Ok(())
    }

    fn load_tx_history_entry(
        &self,
        ledger_seq: u32,
    ) -> Result<Option<TransactionHistoryEntry>, DbError> {
        let result: Option<Vec<u8>> = self
            .query_row(
                "SELECT data FROM txsets WHERE ledgerseq = ?1",
                params![ledger_seq],
                |row| row.get(0),
            )
            .optional()?;
        match result {
            Some(data) => Ok(Some(TransactionHistoryEntry::from_xdr(
                data.as_slice(),
                Limits::none(),
            )?)),
            None => Ok(None),
        }
    }

    fn store_tx_result_entry(
        &self,
        ledger_seq: u32,
        entry: &TransactionHistoryResultEntry,
    ) -> Result<(), DbError> {
        let data = entry.to_xdr(Limits::none())?;
        self.execute(
            "INSERT OR REPLACE INTO txresults (ledgerseq, data) VALUES (?1, ?2)",
            params![ledger_seq, data],
        )?;
        Ok(())
    }

    fn load_tx_result_entry(
        &self,
        ledger_seq: u32,
    ) -> Result<Option<TransactionHistoryResultEntry>, DbError> {
        let result: Option<Vec<u8>> = self
            .query_row(
                "SELECT data FROM txresults WHERE ledgerseq = ?1",
                params![ledger_seq],
                |row| row.get(0),
            )
            .optional()?;
        match result {
            Some(data) => Ok(Some(TransactionHistoryResultEntry::from_xdr(
                data.as_slice(),
                Limits::none(),
            )?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use stellar_xdr::curr::{
        Hash, TransactionHistoryEntryExt, TransactionHistoryResultEntryExt, TransactionResultSet,
        TransactionSet, VecM,
    };

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE txhistory (
                txid TEXT PRIMARY KEY,
                ledgerseq INTEGER NOT NULL,
                txindex INTEGER NOT NULL,
                txbody BLOB NOT NULL,
                txresult BLOB NOT NULL,
                txmeta BLOB
            );
            CREATE INDEX txhistory_ledger ON txhistory(ledgerseq);
            CREATE TABLE txsets (
                ledgerseq INTEGER PRIMARY KEY,
                data BLOB NOT NULL
            );
            CREATE TABLE txresults (
                ledgerseq INTEGER PRIMARY KEY,
                data BLOB NOT NULL
            );
            "#,
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_store_and_load_transaction() {
        let conn = setup_db();
        let tx_id = "abc123def456";
        let body = b"transaction body";
        let result = b"transaction result";
        let meta = b"transaction meta";

        conn.store_transaction(100, 0, tx_id, body, result, Some(meta))
            .unwrap();

        let loaded = conn.load_transaction(tx_id).unwrap().unwrap();
        assert_eq!(loaded.tx_id, tx_id);
        assert_eq!(loaded.ledger_seq, 100);
        assert_eq!(loaded.tx_index, 0);
        assert_eq!(loaded.body, body.to_vec());
        assert_eq!(loaded.result, result.to_vec());
        assert_eq!(loaded.meta, Some(meta.to_vec()));
    }

    #[test]
    fn test_store_transaction_without_meta() {
        let conn = setup_db();
        let tx_id = "xyz789";
        let body = b"body";
        let result = b"result";

        conn.store_transaction(200, 5, tx_id, body, result, None)
            .unwrap();

        let loaded = conn.load_transaction(tx_id).unwrap().unwrap();
        assert_eq!(loaded.ledger_seq, 200);
        assert_eq!(loaded.tx_index, 5);
        assert!(loaded.meta.is_none());
    }

    #[test]
    fn test_load_nonexistent_transaction() {
        let conn = setup_db();
        assert!(conn.load_transaction("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_update_transaction() {
        let conn = setup_db();
        let tx_id = "update_test";

        // Store initial version
        conn.store_transaction(100, 0, tx_id, b"old_body", b"old_result", None)
            .unwrap();

        // Update with new data
        conn.store_transaction(100, 0, tx_id, b"new_body", b"new_result", Some(b"meta"))
            .unwrap();

        let loaded = conn.load_transaction(tx_id).unwrap().unwrap();
        assert_eq!(loaded.body, b"new_body".to_vec());
        assert_eq!(loaded.result, b"new_result".to_vec());
        assert_eq!(loaded.meta, Some(b"meta".to_vec()));
    }

    #[test]
    fn test_store_and_load_tx_history_entry() {
        let conn = setup_db();
        let entry = TransactionHistoryEntry {
            ledger_seq: 123,
            tx_set: TransactionSet {
                previous_ledger_hash: Hash::default(),
                txs: VecM::default(),
            },
            ext: TransactionHistoryEntryExt::V0,
        };

        conn.store_tx_history_entry(123, &entry).unwrap();
        let loaded = conn.load_tx_history_entry(123).unwrap().unwrap();
        assert_eq!(loaded.ledger_seq, 123);
        assert_eq!(loaded.tx_set, entry.tx_set);
        assert_eq!(loaded.ext, entry.ext);
    }

    #[test]
    fn test_store_and_load_tx_result_entry() {
        let conn = setup_db();
        let entry = TransactionHistoryResultEntry {
            ledger_seq: 456,
            tx_result_set: TransactionResultSet {
                results: VecM::default(),
            },
            ext: TransactionHistoryResultEntryExt::V0,
        };

        conn.store_tx_result_entry(456, &entry).unwrap();
        let loaded = conn.load_tx_result_entry(456).unwrap().unwrap();
        assert_eq!(loaded.ledger_seq, 456);
        assert_eq!(loaded.tx_result_set, entry.tx_result_set);
        assert_eq!(loaded.ext, entry.ext);
    }
}
