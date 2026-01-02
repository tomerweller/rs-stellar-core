//! Database schema migrations.
//!
//! This module provides a migration system for upgrading the database schema
//! between versions. Each migration is a SQL script that transforms the schema.

use crate::{DbError, Result};
use rusqlite::Connection;
use tracing::{info, warn};

/// Current schema version.
pub const CURRENT_VERSION: i32 = 5;

/// A database migration.
struct Migration {
    /// Version this migration upgrades FROM.
    from_version: i32,
    /// Version this migration upgrades TO.
    to_version: i32,
    /// SQL to execute for the upgrade.
    upgrade_sql: &'static str,
    /// Description of what this migration does.
    description: &'static str,
}

/// All available migrations.
const MIGRATIONS: &[Migration] = &[
    Migration {
        from_version: 1,
        to_version: 2,
        upgrade_sql: r#"
            CREATE TABLE IF NOT EXISTS txsets (
                ledgerseq INTEGER PRIMARY KEY,
                data BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS txresults (
                ledgerseq INTEGER PRIMARY KEY,
                data BLOB NOT NULL
            );
        "#,
        description: "Add txsets and txresults tables for history publishing",
    },
    Migration {
        from_version: 2,
        to_version: 3,
        upgrade_sql: r#"
            CREATE TABLE IF NOT EXISTS bucketlist (
                ledgerseq INTEGER NOT NULL,
                level INTEGER NOT NULL,
                currhash TEXT NOT NULL,
                snaphash TEXT NOT NULL,
                PRIMARY KEY (ledgerseq, level)
            );
            CREATE INDEX IF NOT EXISTS bucketlist_ledger ON bucketlist(ledgerseq);
        "#,
        description: "Add bucket list table for checkpoint snapshots",
    },
    Migration {
        from_version: 3,
        to_version: 4,
        upgrade_sql: r#"
            CREATE TABLE IF NOT EXISTS publishqueue (
                ledgerseq INTEGER PRIMARY KEY,
                state TEXT NOT NULL
            );
        "#,
        description: "Add publish queue table for history publishing",
    },
    Migration {
        from_version: 4,
        to_version: 5,
        upgrade_sql: r#"
            ALTER TABLE scphistory RENAME TO scphistory_old;
            CREATE TABLE IF NOT EXISTS scphistory (
                nodeid TEXT NOT NULL,
                ledgerseq INTEGER NOT NULL,
                envelope BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scphistory_ledger ON scphistory(ledgerseq);
            INSERT INTO scphistory (nodeid, ledgerseq, envelope)
                SELECT nodeid, ledgerseq, envelope FROM scphistory_old;
            DROP TABLE scphistory_old;
        "#,
        description: "Allow multiple SCP envelopes per node and ledger",
    },
];

/// Get the current schema version from the database.
pub fn get_schema_version(conn: &Connection) -> Result<i32> {
    let result: std::result::Result<String, _> = conn.query_row(
        "SELECT state FROM storestate WHERE statename = 'databaseschema'",
        [],
        |row| row.get(0),
    );

    match result {
        Ok(version_str) => {
            version_str.parse().map_err(|_| {
                DbError::Migration(format!("Invalid schema version: {}", version_str))
            })
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // No schema version recorded - assume version 1 (initial)
            Ok(1)
        }
        Err(e) => Err(e.into()),
    }
}

/// Set the schema version in the database.
pub fn set_schema_version(conn: &Connection, version: i32) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO storestate (statename, state) VALUES ('databaseschema', ?)",
        [version.to_string()],
    )?;
    Ok(())
}

/// Check if the database needs migration.
pub fn needs_migration(conn: &Connection) -> Result<bool> {
    let current = get_schema_version(conn)?;
    Ok(current < CURRENT_VERSION)
}

/// Run all necessary migrations to bring the database up to date.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    let mut current_version = get_schema_version(conn)?;

    if current_version == CURRENT_VERSION {
        info!("Database is up to date at version {}", current_version);
        return Ok(());
    }

    if current_version > CURRENT_VERSION {
        return Err(DbError::Migration(format!(
            "Database version {} is newer than supported version {}",
            current_version, CURRENT_VERSION
        )));
    }

    info!(
        "Migrating database from version {} to {}",
        current_version, CURRENT_VERSION
    );

    while current_version < CURRENT_VERSION {
        let migration = MIGRATIONS
            .iter()
            .find(|m| m.from_version == current_version)
            .ok_or_else(|| {
                DbError::Migration(format!(
                    "No migration found from version {}",
                    current_version
                ))
            })?;

        info!(
            "Applying migration {} -> {}: {}",
            migration.from_version, migration.to_version, migration.description
        );

        // Execute the migration in a transaction
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(migration.upgrade_sql)?;
        set_schema_version(&tx, migration.to_version)?;
        tx.commit()?;

        current_version = migration.to_version;
        info!("Migration complete, now at version {}", current_version);
    }

    info!("All migrations complete, database at version {}", CURRENT_VERSION);
    Ok(())
}

/// Verify the database schema is compatible with this version.
pub fn verify_schema(conn: &Connection) -> Result<()> {
    let version = get_schema_version(conn)?;

    if version < CURRENT_VERSION {
        return Err(DbError::Migration(format!(
            "Database schema version {} is too old, run migrations first",
            version
        )));
    }

    if version > CURRENT_VERSION {
        return Err(DbError::Migration(format!(
            "Database schema version {} is newer than this software supports ({})",
            version, CURRENT_VERSION
        )));
    }

    Ok(())
}

/// Initialize a fresh database with the current schema.
pub fn initialize_schema(conn: &Connection) -> Result<()> {
    // Create the schema
    conn.execute_batch(crate::schema::CREATE_SCHEMA)?;

    // Set the schema version
    set_schema_version(conn, CURRENT_VERSION)?;

    info!("Initialized database with schema version {}", CURRENT_VERSION);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::schema::CREATE_SCHEMA).unwrap();
        conn
    }

    #[test]
    fn test_get_schema_version_default() {
        let conn = setup_test_db();
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn test_set_and_get_schema_version() {
        let conn = setup_test_db();
        set_schema_version(&conn, 5).unwrap();
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, 5);
    }

    #[test]
    fn test_needs_migration() {
        let conn = setup_test_db();
        set_schema_version(&conn, CURRENT_VERSION).unwrap();
        assert!(!needs_migration(&conn).unwrap());
    }

    #[test]
    fn test_verify_schema_current() {
        let conn = setup_test_db();
        set_schema_version(&conn, CURRENT_VERSION).unwrap();
        assert!(verify_schema(&conn).is_ok());
    }

    #[test]
    fn test_verify_schema_too_old() {
        let conn = setup_test_db();
        set_schema_version(&conn, CURRENT_VERSION - 1).unwrap();
        // Only fails if CURRENT_VERSION > 1
        if CURRENT_VERSION > 1 {
            assert!(verify_schema(&conn).is_err());
        }
    }
}
