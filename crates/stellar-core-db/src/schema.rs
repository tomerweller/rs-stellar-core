//! Database schema definitions.

/// Schema version.
pub const SCHEMA_VERSION: i32 = 3;

/// SQL to create the database schema.
pub const CREATE_SCHEMA: &str = r#"
-- Schema version tracking
CREATE TABLE IF NOT EXISTS storestate (
    statename TEXT PRIMARY KEY,
    state TEXT NOT NULL
);

-- Ledger headers
CREATE TABLE IF NOT EXISTS ledgerheaders (
    ledgerhash TEXT PRIMARY KEY,
    prevhash TEXT NOT NULL,
    bucketlisthash TEXT NOT NULL,
    ledgerseq INTEGER UNIQUE NOT NULL,
    closetime INTEGER NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS ledgerheaders_seq ON ledgerheaders(ledgerseq);

-- Accounts
CREATE TABLE IF NOT EXISTS accounts (
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

-- Trust lines
CREATE TABLE IF NOT EXISTS trustlines (
    accountid TEXT NOT NULL,
    assettype INTEGER NOT NULL,
    issuer TEXT NOT NULL,
    assetcode TEXT NOT NULL,
    tlimit BIGINT NOT NULL,
    balance BIGINT NOT NULL,
    flags INTEGER NOT NULL,
    lastmodified INTEGER NOT NULL,
    buyingliabilities BIGINT DEFAULT 0,
    sellingliabilities BIGINT DEFAULT 0,
    extension BLOB,
    PRIMARY KEY (accountid, assettype, issuer, assetcode)
);

-- Offers
CREATE TABLE IF NOT EXISTS offers (
    offerid BIGINT PRIMARY KEY,
    sellerid TEXT NOT NULL,
    sellingassettype INTEGER NOT NULL,
    sellingissuer TEXT,
    sellingassetcode TEXT,
    buyingassettype INTEGER NOT NULL,
    buyingissuer TEXT,
    buyingassetcode TEXT,
    amount BIGINT NOT NULL,
    pricen INTEGER NOT NULL,
    priced INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    lastmodified INTEGER NOT NULL,
    extension BLOB
);
CREATE INDEX IF NOT EXISTS offers_seller ON offers(sellerid);

-- Account data entries
CREATE TABLE IF NOT EXISTS accountdata (
    accountid TEXT NOT NULL,
    dataname TEXT NOT NULL,
    datavalue TEXT NOT NULL,
    lastmodified INTEGER NOT NULL,
    extension BLOB,
    PRIMARY KEY (accountid, dataname)
);

-- Claimable balances
CREATE TABLE IF NOT EXISTS claimablebalance (
    balanceid TEXT PRIMARY KEY,
    claimants TEXT NOT NULL,
    asset TEXT NOT NULL,
    amount BIGINT NOT NULL,
    lastmodified INTEGER NOT NULL,
    extension BLOB
);

-- Liquidity pools
CREATE TABLE IF NOT EXISTS liquiditypool (
    poolid TEXT PRIMARY KEY,
    type INTEGER NOT NULL,
    assetA TEXT NOT NULL,
    assetB TEXT NOT NULL,
    fee INTEGER NOT NULL,
    reserveA BIGINT NOT NULL,
    reserveB BIGINT NOT NULL,
    totalshares BIGINT NOT NULL,
    poolshareholders INTEGER NOT NULL,
    lastmodified INTEGER NOT NULL,
    extension BLOB
);

-- Soroban contract data
CREATE TABLE IF NOT EXISTS contractdata (
    contractid TEXT NOT NULL,
    key BLOB NOT NULL,
    keytype INTEGER NOT NULL,
    durability INTEGER NOT NULL,
    val BLOB NOT NULL,
    lastmodified INTEGER NOT NULL,
    PRIMARY KEY (contractid, key)
);

-- Soroban contract code
CREATE TABLE IF NOT EXISTS contractcode (
    hash TEXT PRIMARY KEY,
    code BLOB NOT NULL,
    lastmodified INTEGER NOT NULL
);

-- Soroban TTL entries
CREATE TABLE IF NOT EXISTS ttl (
    keyhash TEXT PRIMARY KEY,
    liveuntilledgerseq INTEGER NOT NULL
);

-- Transaction history
CREATE TABLE IF NOT EXISTS txhistory (
    txid TEXT PRIMARY KEY,
    ledgerseq INTEGER NOT NULL,
    txindex INTEGER NOT NULL,
    txbody BLOB NOT NULL,
    txresult BLOB NOT NULL,
    txmeta BLOB
);
CREATE INDEX IF NOT EXISTS txhistory_ledger ON txhistory(ledgerseq);

-- Transaction history entries (tx sets)
CREATE TABLE IF NOT EXISTS txsets (
    ledgerseq INTEGER PRIMARY KEY,
    data BLOB NOT NULL
);

-- Transaction history result entries (tx results)
CREATE TABLE IF NOT EXISTS txresults (
    ledgerseq INTEGER PRIMARY KEY,
    data BLOB NOT NULL
);

-- Bucket list snapshots (checkpoint ledgers only)
CREATE TABLE IF NOT EXISTS bucketlist (
    ledgerseq INTEGER NOT NULL,
    level INTEGER NOT NULL,
    currhash TEXT NOT NULL,
    snaphash TEXT NOT NULL,
    PRIMARY KEY (ledgerseq, level)
);
CREATE INDEX IF NOT EXISTS bucketlist_ledger ON bucketlist(ledgerseq);

-- Transaction fee history
CREATE TABLE IF NOT EXISTS txfeehistory (
    txid TEXT PRIMARY KEY,
    ledgerseq INTEGER NOT NULL,
    txindex INTEGER NOT NULL,
    txchanges BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS txfeehistory_ledger ON txfeehistory(ledgerseq);

-- SCP state
CREATE TABLE IF NOT EXISTS scphistory (
    nodeid TEXT NOT NULL,
    ledgerseq INTEGER NOT NULL,
    envelope BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS scphistory_ledger ON scphistory(ledgerseq);

-- SCP quorum information
CREATE TABLE IF NOT EXISTS scpquorums (
    qsethash TEXT PRIMARY KEY,
    lastledgerseq INTEGER NOT NULL,
    qset BLOB NOT NULL
);

-- Upgrade history
CREATE TABLE IF NOT EXISTS upgradehistory (
    ledgerseq INTEGER NOT NULL,
    upgradeindex INTEGER NOT NULL,
    upgrade BLOB NOT NULL,
    changes BLOB NOT NULL,
    PRIMARY KEY (ledgerseq, upgradeindex)
);

-- Peers
CREATE TABLE IF NOT EXISTS peers (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    nextattempt INTEGER NOT NULL,
    numfailures INTEGER NOT NULL DEFAULT 0,
    type INTEGER NOT NULL,
    PRIMARY KEY (ip, port)
);

-- Ban list
CREATE TABLE IF NOT EXISTS ban (
    nodeid TEXT PRIMARY KEY
);

-- Publish queue (for history publishing)
CREATE TABLE IF NOT EXISTS publishqueue (
    ledgerseq INTEGER PRIMARY KEY,
    state TEXT NOT NULL
);
"#;

/// State keys for storestate table.
pub mod state_keys {
    pub const LAST_CLOSED_LEDGER: &str = "lastclosedledger";
    pub const HISTORY_ARCHIVE_STATE: &str = "historyarchivestate";
    pub const DATABASE_SCHEMA: &str = "databaseschema";
    pub const NETWORK_PASSPHRASE: &str = "networkpassphrase";
    pub const LEDGER_UPGRADE_VERSION: &str = "ledgerupgradeversion";
    pub const LAST_SCP_DATA: &str = "lastscpdata";
    pub const SCP_STATE: &str = "scpstate";
}
