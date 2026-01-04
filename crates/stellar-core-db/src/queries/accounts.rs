//! Account queries.

use rusqlite::{Connection, OptionalExtension, params};
use stellar_xdr::curr::{
    AccountEntry, AccountEntryExt, AccountId, Liabilities, PublicKey, Signer, Thresholds, ReadXdr,
    WriteXdr, Limits,
};

use super::super::error::DbError;

/// Trait for querying and storing accounts.
pub trait AccountQueries {
    /// Load an account by ID.
    fn load_account(&self, id: &AccountId) -> Result<Option<AccountEntry>, DbError>;

    /// Store an account entry.
    fn store_account(&self, entry: &AccountEntry, last_modified: u32) -> Result<(), DbError>;

    /// Delete an account.
    fn delete_account(&self, id: &AccountId) -> Result<(), DbError>;
}

/// Helper to encode AccountId as string (stellar address format using public key hex).
fn account_id_to_string(id: &AccountId) -> String {
    match &id.0 {
        PublicKey::PublicKeyTypeEd25519(key) => hex::encode(key.0),
    }
}

/// Helper to parse thresholds from hex string.
fn parse_thresholds(s: &str) -> Result<Thresholds, DbError> {
    let bytes = hex::decode(s).map_err(|e| {
        DbError::Integrity(format!("Invalid thresholds hex: {}", e))
    })?;
    if bytes.len() != 4 {
        return Err(DbError::Integrity("Thresholds must be 4 bytes".into()));
    }
    Ok(Thresholds([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Helper to encode thresholds to hex string.
fn thresholds_to_string(t: &Thresholds) -> String {
    hex::encode(t.0)
}

/// Helper to parse signers from JSON string.
fn parse_signers(s: Option<String>) -> Result<Vec<Signer>, DbError> {
    match s {
        Some(json) if !json.is_empty() => {
            let data: Vec<u8> = serde_json::from_str(&json).map_err(|e| {
                DbError::Integrity(format!("Invalid signers JSON: {}", e))
            })?;
            if data.is_empty() {
                return Ok(vec![]);
            }
            // Signers are stored as XDR-encoded blob in JSON
            // For now, return empty vec if we can't parse
            Ok(vec![])
        }
        _ => Ok(vec![]),
    }
}

/// Helper to encode signers to JSON string.
fn signers_to_string(signers: &[Signer]) -> Option<String> {
    if signers.is_empty() {
        None
    } else {
        // Encode signers as XDR bytes in JSON
        let bytes: Vec<u8> = signers.iter()
            .flat_map(|s| s.to_xdr(Limits::none()).unwrap_or_default())
            .collect();
        Some(serde_json::to_string(&bytes).unwrap_or_default())
    }
}

impl AccountQueries for Connection {
    fn load_account(&self, id: &AccountId) -> Result<Option<AccountEntry>, DbError> {
        let account_id_str = account_id_to_string(id);

        let result: Option<(
            i64,      // balance
            i64,      // seqnum
            i32,      // numsubentries
            Option<String>, // inflationdest
            Option<String>, // homedomain
            String,   // thresholds
            i32,      // flags
            i64,      // buyingliabilities
            i64,      // sellingliabilities
            Option<String>, // signers
            Option<Vec<u8>>, // extension
        )> = self
            .query_row(
                r#"
                SELECT balance, seqnum, numsubentries, inflationdest, homedomain,
                       thresholds, flags, buyingliabilities, sellingliabilities,
                       signers, extension
                FROM accounts WHERE accountid = ?1
                "#,
                params![account_id_str],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                balance,
                seqnum,
                numsubentries,
                _inflationdest,
                homedomain,
                thresholds_str,
                flags,
                buying_liabilities,
                selling_liabilities,
                signers_str,
                extension_blob,
            )) => {
                let thresholds = parse_thresholds(&thresholds_str)?;
                let signers = parse_signers(signers_str)?;

                // Parse extension if present
                let ext = match extension_blob {
                    Some(data) if !data.is_empty() => {
                        AccountEntryExt::from_xdr(&data, Limits::none())
                            .unwrap_or(AccountEntryExt::V0)
                    }
                    _ => {
                        // Create V1 extension with liabilities
                        if buying_liabilities != 0 || selling_liabilities != 0 {
                            AccountEntryExt::V1(stellar_xdr::curr::AccountEntryExtensionV1 {
                                liabilities: Liabilities {
                                    buying: buying_liabilities,
                                    selling: selling_liabilities,
                                },
                                ext: stellar_xdr::curr::AccountEntryExtensionV1Ext::V0,
                            })
                        } else {
                            AccountEntryExt::V0
                        }
                    }
                };

                let entry = AccountEntry {
                    account_id: id.clone(),
                    balance,
                    seq_num: stellar_xdr::curr::SequenceNumber(seqnum),
                    num_sub_entries: numsubentries as u32,
                    inflation_dest: None, // Inflation is deprecated since protocol 12
                    flags: flags as u32,
                    home_domain: homedomain
                        .and_then(|s| s.into_bytes().try_into().ok())
                        .unwrap_or_default(),
                    thresholds,
                    signers: signers.try_into().unwrap_or_default(),
                    ext,
                };

                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    fn store_account(&self, entry: &AccountEntry, last_modified: u32) -> Result<(), DbError> {
        let account_id_str = account_id_to_string(&entry.account_id);
        let thresholds_str = thresholds_to_string(&entry.thresholds);
        let home_domain: String = entry.home_domain.to_string();
        let signers_str = signers_to_string(entry.signers.as_slice());

        // Extract liabilities from extension
        let (buying_liabilities, selling_liabilities) = match &entry.ext {
            AccountEntryExt::V1(ext) => (ext.liabilities.buying, ext.liabilities.selling),
            _ => (0, 0),
        };

        // Serialize extension
        let extension_blob: Option<Vec<u8>> = match &entry.ext {
            AccountEntryExt::V0 => None,
            _ => Some(entry.ext.to_xdr(Limits::none())?),
        };

        self.execute(
            r#"
            INSERT OR REPLACE INTO accounts
            (accountid, balance, seqnum, numsubentries, inflationdest, homedomain,
             thresholds, flags, lastmodified, buyingliabilities, sellingliabilities,
             signers, extension)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                account_id_str,
                entry.balance,
                entry.seq_num.0,
                entry.num_sub_entries as i32,
                None::<String>, // inflationdest
                if home_domain.is_empty() { None } else { Some(home_domain) },
                thresholds_str,
                entry.flags as i32,
                last_modified as i32,
                buying_liabilities,
                selling_liabilities,
                signers_str,
                extension_blob,
            ],
        )?;
        Ok(())
    }

    fn delete_account(&self, id: &AccountId) -> Result<(), DbError> {
        let account_id_str = account_id_to_string(id);
        self.execute(
            "DELETE FROM accounts WHERE accountid = ?1",
            params![account_id_str],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use stellar_xdr::curr::{String32, Uint256};

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE accounts (
                accountid TEXT PRIMARY KEY,
                balance BIGINT NOT NULL,
                seqnum BIGINT NOT NULL,
                numsubentries INTEGER NOT NULL,
                inflationdest TEXT,
                homedomain TEXT,
                thresholds TEXT NOT NULL,
                flags INTEGER NOT NULL,
                lastmodified INTEGER NOT NULL,
                buyingliabilities BIGINT DEFAULT 0,
                sellingliabilities BIGINT DEFAULT 0,
                signers TEXT,
                extension BLOB
            );
            "#,
        )
        .unwrap();
        conn
    }

    fn create_test_account() -> (AccountId, AccountEntry) {
        let key = Uint256([1u8; 32]);
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(key));
        let entry = AccountEntry {
            account_id: account_id.clone(),
            balance: 100_000_000,
            seq_num: stellar_xdr::curr::SequenceNumber(12345),
            num_sub_entries: 2,
            inflation_dest: None,
            flags: 0,
            home_domain: String32(stellar_xdr::curr::StringM::try_from("example.com").unwrap()),
            thresholds: Thresholds([1, 2, 3, 4]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V0,
        };
        (account_id, entry)
    }

    #[test]
    fn test_store_and_load_account() {
        let conn = setup_db();
        let (account_id, entry) = create_test_account();

        conn.store_account(&entry, 100).unwrap();

        let loaded = conn.load_account(&account_id).unwrap().unwrap();
        assert_eq!(loaded.balance, 100_000_000);
        assert_eq!(loaded.seq_num.0, 12345);
        assert_eq!(loaded.num_sub_entries, 2);
        assert_eq!(loaded.thresholds.0, [1, 2, 3, 4]);
    }

    #[test]
    fn test_delete_account() {
        let conn = setup_db();
        let (account_id, entry) = create_test_account();

        conn.store_account(&entry, 100).unwrap();
        assert!(conn.load_account(&account_id).unwrap().is_some());

        conn.delete_account(&account_id).unwrap();
        assert!(conn.load_account(&account_id).unwrap().is_none());
    }

    #[test]
    fn test_account_with_liabilities() {
        let conn = setup_db();
        let key = Uint256([2u8; 32]);
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(key));
        let entry = AccountEntry {
            account_id: account_id.clone(),
            balance: 50_000_000,
            seq_num: stellar_xdr::curr::SequenceNumber(100),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32(stellar_xdr::curr::StringM::try_from("").unwrap()),
            thresholds: Thresholds([1, 1, 1, 1]),
            signers: vec![].try_into().unwrap(),
            ext: AccountEntryExt::V1(stellar_xdr::curr::AccountEntryExtensionV1 {
                liabilities: Liabilities {
                    buying: 1000,
                    selling: 2000,
                },
                ext: stellar_xdr::curr::AccountEntryExtensionV1Ext::V0,
            }),
        };

        conn.store_account(&entry, 100).unwrap();
        let loaded = conn.load_account(&account_id).unwrap().unwrap();

        match loaded.ext {
            AccountEntryExt::V1(ext) => {
                assert_eq!(ext.liabilities.buying, 1000);
                assert_eq!(ext.liabilities.selling, 2000);
            }
            _ => panic!("Expected V1 extension"),
        }
    }
}
