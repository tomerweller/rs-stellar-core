//! Configuration loading for rs-stellar-core.
//!
//! Supports loading configuration from TOML files with environment variable overrides.
//! Provides sensible defaults for testnet and mainnet configurations.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use stellar_core_crypto;

/// Main application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Node identity and behavior.
    #[serde(default)]
    pub node: NodeConfig,

    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Proposed protocol upgrades.
    #[serde(default)]
    pub upgrades: UpgradeConfig,

    /// Database configuration.
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Bucket storage configuration.
    #[serde(default)]
    pub buckets: BucketConfig,

    /// History archive configuration.
    #[serde(default)]
    pub history: HistoryConfig,

    /// Peer network configuration.
    #[serde(default)]
    pub overlay: OverlayConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// HTTP server configuration.
    #[serde(default)]
    pub http: HttpConfig,

    /// Surge pricing configuration.
    #[serde(default)]
    pub surge_pricing: SurgePricingConfig,

    /// Classic event emission configuration.
    #[serde(default)]
    pub events: EventsConfig,
}

/// Node identity and behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node name for identification in logs.
    #[serde(default = "default_node_name")]
    pub name: String,

    /// Secret seed for this node (S... format).
    /// Required for validators, optional for watchers.
    pub node_seed: Option<String>,

    /// Whether this node participates in consensus.
    #[serde(default)]
    pub is_validator: bool,

    /// Home domain for this node.
    pub home_domain: Option<String>,

    /// Quorum set configuration.
    #[serde(default)]
    pub quorum_set: QuorumSetConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: default_node_name(),
            node_seed: None,
            is_validator: false,
            home_domain: None,
            quorum_set: QuorumSetConfig::default(),
        }
    }
}

/// Quorum set configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuorumSetConfig {
    /// Threshold percentage (0-100).
    #[serde(default = "default_threshold")]
    pub threshold_percent: u32,

    /// Validator public keys (G... format).
    #[serde(default)]
    pub validators: Vec<String>,

    /// Inner quorum sets for hierarchical structures.
    #[serde(default)]
    pub inner_sets: Vec<QuorumSetConfig>,
}

impl QuorumSetConfig {
    /// Convert to XDR ScpQuorumSet.
    ///
    /// Returns None if the quorum set is empty or has invalid validators.
    pub fn to_xdr(&self) -> Option<stellar_xdr::curr::ScpQuorumSet> {
        use stellar_xdr::curr::{ScpQuorumSet, NodeId, PublicKey, Uint256};

        // Parse validator public keys
        let mut validators = Vec::new();
        for v in &self.validators {
            // Parse G... public key to bytes
            let pubkey = stellar_core_crypto::PublicKey::from_strkey(v).ok()?;
            let node_id = NodeId(PublicKey::PublicKeyTypeEd25519(Uint256(*pubkey.as_bytes())));
            validators.push(node_id);
        }

        // Recursively convert inner sets
        let mut inner_sets = Vec::new();
        for inner in &self.inner_sets {
            if let Some(inner_xdr) = inner.to_xdr() {
                inner_sets.push(inner_xdr);
            }
        }

        // If empty, return None
        if validators.is_empty() && inner_sets.is_empty() {
            return None;
        }

        // Calculate threshold from percentage
        let total = validators.len() + inner_sets.len();
        let threshold = ((total as u32 * self.threshold_percent) / 100).max(1);

        Some(ScpQuorumSet {
            threshold,
            validators: validators.try_into().ok()?,
            inner_sets: inner_sets.try_into().ok()?,
        })
    }
}

/// Network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network passphrase (determines which network to connect to).
    pub passphrase: String,

    /// Base fee in stroops.
    #[serde(default = "default_base_fee")]
    pub base_fee: u32,

    /// Base reserve in stroops.
    #[serde(default = "default_base_reserve")]
    pub base_reserve: u32,

    /// Maximum protocol version to support.
    #[serde(default = "default_protocol_version")]
    pub max_protocol_version: u32,
}

/// Surge pricing configuration (lane byte allowances and caps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurgePricingConfig {
    /// Classic tx byte allowance for tx set selection.
    #[serde(default = "default_classic_byte_allowance")]
    pub classic_byte_allowance: u32,

    /// Soroban tx byte allowance for tx set selection.
    #[serde(default = "default_soroban_byte_allowance")]
    pub soroban_byte_allowance: u32,

    /// Optional max DEX operations for classic lane selection.
    #[serde(default)]
    pub max_dex_tx_operations: Option<u32>,
}

impl Default for SurgePricingConfig {
    fn default() -> Self {
        Self {
            classic_byte_allowance: default_classic_byte_allowance(),
            soroban_byte_allowance: default_soroban_byte_allowance(),
            max_dex_tx_operations: None,
        }
    }
}

/// Classic event emission configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsConfig {
    /// Emit classic asset events in transaction metadata.
    #[serde(default)]
    pub emit_classic_events: bool,

    /// Backfill classic asset events to pre-23 format.
    #[serde(default)]
    pub backfill_stellar_asset_events: bool,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            emit_classic_events: false,
            backfill_stellar_asset_events: false,
        }
    }
}

/// Proposed protocol upgrades configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpgradeConfig {
    /// Proposed protocol version upgrade.
    pub protocol_version: Option<u32>,
    /// Proposed base fee upgrade.
    pub base_fee: Option<u32>,
    /// Proposed base reserve upgrade.
    pub base_reserve: Option<u32>,
    /// Proposed max tx set size upgrade.
    pub max_tx_set_size: Option<u32>,
}

impl UpgradeConfig {
    pub fn to_ledger_upgrades(&self) -> Vec<stellar_xdr::curr::LedgerUpgrade> {
        let mut upgrades = Vec::new();
        if let Some(version) = self.protocol_version {
            upgrades.push(stellar_xdr::curr::LedgerUpgrade::Version(version));
        }
        if let Some(fee) = self.base_fee {
            upgrades.push(stellar_xdr::curr::LedgerUpgrade::BaseFee(fee));
        }
        if let Some(reserve) = self.base_reserve {
            upgrades.push(stellar_xdr::curr::LedgerUpgrade::BaseReserve(reserve));
        }
        if let Some(max_tx_set_size) = self.max_tx_set_size {
            upgrades.push(stellar_xdr::curr::LedgerUpgrade::MaxTxSetSize(max_tx_set_size));
        }
        upgrades
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::testnet()
    }
}

impl NetworkConfig {
    /// Create a testnet configuration.
    pub fn testnet() -> Self {
        Self {
            passphrase: "Test SDF Network ; September 2015".to_string(),
            base_fee: default_base_fee(),
            base_reserve: default_base_reserve(),
            max_protocol_version: default_protocol_version(),
        }
    }

    /// Create a mainnet configuration.
    pub fn mainnet() -> Self {
        Self {
            passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            base_fee: default_base_fee(),
            base_reserve: default_base_reserve(),
            max_protocol_version: default_protocol_version(),
        }
    }
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file.
    #[serde(default = "default_db_path")]
    pub path: PathBuf,

    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            pool_size: default_pool_size(),
        }
    }
}

/// Bucket storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketConfig {
    /// Directory for bucket files.
    #[serde(default = "default_bucket_dir")]
    pub directory: PathBuf,

    /// Maximum number of buckets to keep in memory cache.
    #[serde(default = "default_bucket_cache_size")]
    pub cache_size: usize,
}

impl Default for BucketConfig {
    fn default() -> Self {
        Self {
            directory: default_bucket_dir(),
            cache_size: default_bucket_cache_size(),
        }
    }
}

/// History archive configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryConfig {
    /// Archives for reading history.
    #[serde(default)]
    pub archives: Vec<HistoryArchiveEntry>,
}

/// A single history archive entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryArchiveEntry {
    /// Name of this archive.
    pub name: String,

    /// Base URL for the archive.
    pub url: String,

    /// Whether this archive can be used for reading.
    #[serde(default = "default_true")]
    pub get_enabled: bool,

    /// Whether this archive can be used for writing (validators only).
    #[serde(default)]
    pub put_enabled: bool,

    /// Optional command template for publishing files to a remote archive.
    /// Uses {0} = local path, {1} = remote path.
    #[serde(default)]
    pub put: Option<String>,

    /// Optional command template to create remote directories.
    /// Uses {0} = remote directory path.
    #[serde(default)]
    pub mkdir: Option<String>,
}

/// Overlay network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayConfig {
    /// Port to listen on for peer connections.
    #[serde(default = "default_peer_port")]
    pub peer_port: u16,

    /// Maximum number of inbound peer connections.
    #[serde(default = "default_max_inbound")]
    pub max_inbound_peers: usize,

    /// Maximum number of outbound peer connections.
    #[serde(default = "default_max_outbound")]
    pub max_outbound_peers: usize,

    /// Target number of outbound connections to maintain.
    #[serde(default = "default_target_outbound")]
    pub target_outbound_peers: usize,

    /// Known peers to connect to on startup.
    #[serde(default)]
    pub known_peers: Vec<String>,

    /// Preferred peers that should always be connected.
    #[serde(default)]
    pub preferred_peers: Vec<String>,

    /// Allowed surveyor node public keys (G...); empty means follow quorum/defaults.
    #[serde(default)]
    pub surveyor_keys: Vec<String>,

    /// Enable automatic survey scheduling (non-upstream behavior).
    #[serde(default)]
    pub auto_survey: bool,

    /// Target fraction of max ops to flood per ledger for classic transactions.
    #[serde(default = "default_flood_op_rate_per_ledger")]
    pub flood_op_rate_per_ledger: f64,

    /// Target fraction of max ops to flood per ledger for Soroban transactions.
    #[serde(default = "default_flood_soroban_rate_per_ledger")]
    pub flood_soroban_rate_per_ledger: f64,

    /// Period (ms) between tx demand cycles.
    #[serde(default = "default_flood_demand_period_ms")]
    pub flood_demand_period_ms: u64,

    /// Period (ms) between tx advert flushes.
    #[serde(default = "default_flood_advert_period_ms")]
    pub flood_advert_period_ms: u64,

    /// Backoff delay (ms) between repeated demands for the same tx.
    #[serde(default = "default_flood_demand_backoff_delay_ms")]
    pub flood_demand_backoff_delay_ms: u64,

    /// Maximum peer failures allowed before pruning.
    #[serde(default = "default_peer_max_failures")]
    pub peer_max_failures: u32,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            peer_port: default_peer_port(),
            max_inbound_peers: default_max_inbound(),
            max_outbound_peers: default_max_outbound(),
            target_outbound_peers: default_target_outbound(),
            known_peers: Vec::new(),
            preferred_peers: Vec::new(),
            surveyor_keys: Vec::new(),
            auto_survey: false,
            flood_op_rate_per_ledger: default_flood_op_rate_per_ledger(),
            flood_soroban_rate_per_ledger: default_flood_soroban_rate_per_ledger(),
            flood_demand_period_ms: default_flood_demand_period_ms(),
            flood_advert_period_ms: default_flood_advert_period_ms(),
            flood_demand_backoff_delay_ms: default_flood_demand_backoff_delay_ms(),
            peer_max_failures: default_peer_max_failures(),
        }
    }
}

fn default_peer_max_failures() -> u32 {
    120
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (text or json).
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Whether to use ANSI colors.
    #[serde(default = "default_true")]
    pub colors: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            colors: true,
        }
    }
}

/// HTTP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Whether to enable the HTTP server.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Port for the HTTP server.
    #[serde(default = "default_http_port")]
    pub port: u16,

    /// Address to bind the HTTP server to.
    #[serde(default = "default_http_address")]
    pub address: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_http_port(),
            address: default_http_address(),
        }
    }
}

fn default_http_port() -> u16 {
    11626
}

fn default_http_address() -> String {
    "0.0.0.0".to_string()
}

// Default value functions

fn default_node_name() -> String {
    "rs-stellar-core".to_string()
}

fn default_threshold() -> u32 {
    67
}

fn default_base_fee() -> u32 {
    100
}

fn default_base_reserve() -> u32 {
    5_000_000 // 0.5 XLM in stroops
}

fn default_protocol_version() -> u32 {
    22
}

fn default_db_path() -> PathBuf {
    PathBuf::from("stellar.db")
}

fn default_pool_size() -> u32 {
    10
}

fn default_bucket_dir() -> PathBuf {
    PathBuf::from("buckets")
}

fn default_bucket_cache_size() -> usize {
    256
}

fn default_peer_port() -> u16 {
    11625
}

fn default_max_inbound() -> usize {
    64
}

fn default_max_outbound() -> usize {
    8
}

fn default_target_outbound() -> usize {
    8
}

fn default_flood_op_rate_per_ledger() -> f64 {
    1.0
}

fn default_flood_soroban_rate_per_ledger() -> f64 {
    1.0
}

fn default_flood_demand_period_ms() -> u64 {
    200
}

fn default_flood_advert_period_ms() -> u64 {
    100
}

fn default_flood_demand_backoff_delay_ms() -> u64 {
    500
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_true() -> bool {
    true
}

fn default_classic_byte_allowance() -> u32 {
    5 * 1024 * 1024
}

fn default_soroban_byte_allowance() -> u32 {
    5 * 1024 * 1024
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::testnet()
    }
}

impl AppConfig {
    /// Create a default testnet configuration.
    pub fn testnet() -> Self {
        Self {
            node: NodeConfig::default(),
            network: NetworkConfig::testnet(),
            upgrades: UpgradeConfig::default(),
            database: DatabaseConfig::default(),
            buckets: BucketConfig::default(),
            history: HistoryConfig {
                archives: vec![
                    HistoryArchiveEntry {
                        name: "sdf1".to_string(),
                        url: "https://history.stellar.org/prd/core-testnet/core_testnet_001"
                            .to_string(),
                        get_enabled: true,
                        put_enabled: false,
                        put: None,
                        mkdir: None,
                    },
                    HistoryArchiveEntry {
                        name: "sdf2".to_string(),
                        url: "https://history.stellar.org/prd/core-testnet/core_testnet_002"
                            .to_string(),
                        get_enabled: true,
                        put_enabled: false,
                        put: None,
                        mkdir: None,
                    },
                    HistoryArchiveEntry {
                        name: "sdf3".to_string(),
                        url: "https://history.stellar.org/prd/core-testnet/core_testnet_003"
                            .to_string(),
                        get_enabled: true,
                        put_enabled: false,
                        put: None,
                        mkdir: None,
                    },
                ],
            },
            overlay: OverlayConfig {
                known_peers: vec![
                    "core-testnet1.stellar.org:11625".to_string(),
                    "core-testnet2.stellar.org:11625".to_string(),
                    "core-testnet3.stellar.org:11625".to_string(),
                ],
                ..Default::default()
            },
            logging: LoggingConfig::default(),
            http: HttpConfig::default(),
            surge_pricing: SurgePricingConfig::default(),
            events: EventsConfig::default(),
        }
    }

    /// Create a default mainnet configuration.
    pub fn mainnet() -> Self {
        Self {
            node: NodeConfig::default(),
            network: NetworkConfig::mainnet(),
            upgrades: UpgradeConfig::default(),
            database: DatabaseConfig::default(),
            buckets: BucketConfig::default(),
            history: HistoryConfig {
                archives: vec![
                    HistoryArchiveEntry {
                        name: "sdf1".to_string(),
                        url: "https://history.stellar.org/prd/core-live/core_live_001".to_string(),
                        get_enabled: true,
                        put_enabled: false,
                        put: None,
                        mkdir: None,
                    },
                    HistoryArchiveEntry {
                        name: "sdf2".to_string(),
                        url: "https://history.stellar.org/prd/core-live/core_live_002".to_string(),
                        get_enabled: true,
                        put_enabled: false,
                        put: None,
                        mkdir: None,
                    },
                    HistoryArchiveEntry {
                        name: "sdf3".to_string(),
                        url: "https://history.stellar.org/prd/core-live/core_live_003".to_string(),
                        get_enabled: true,
                        put_enabled: false,
                        put: None,
                        mkdir: None,
                    },
                ],
            },
            overlay: OverlayConfig {
                known_peers: vec![
                    "core-live-a.stellar.org:11625".to_string(),
                    "core-live-b.stellar.org:11625".to_string(),
                    "core-live-c.stellar.org:11625".to_string(),
                ],
                ..Default::default()
            },
            logging: LoggingConfig::default(),
            http: HttpConfig::default(),
            surge_pricing: SurgePricingConfig::default(),
            events: EventsConfig::default(),
        }
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration with environment variable overrides.
    ///
    /// Environment variables take precedence over file configuration.
    /// Variables use the pattern: RS_STELLAR_CORE_<SECTION>_<KEY>
    ///
    /// Examples:
    /// - RS_STELLAR_CORE_NODE_NAME
    /// - RS_STELLAR_CORE_NODE_SEED
    /// - RS_STELLAR_CORE_NETWORK_PASSPHRASE
    /// - RS_STELLAR_CORE_DATABASE_PATH
    /// - RS_STELLAR_CORE_OVERLAY_PEER_PORT
    pub fn from_file_with_env(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let mut config = Self::from_file(path)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Apply environment variable overrides.
    pub fn apply_env_overrides(&mut self) {
        // Node overrides
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_NODE_NAME") {
            self.node.name = val;
        }
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_NODE_SEED") {
            self.node.node_seed = Some(val);
        }
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_NODE_VALIDATOR") {
            self.node.is_validator = val.parse().unwrap_or(false);
        }

        // Network overrides
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_NETWORK_PASSPHRASE") {
            self.network.passphrase = val;
        }

        // Database overrides
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_DATABASE_PATH") {
            self.database.path = PathBuf::from(val);
        }

        // Bucket overrides
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_BUCKETS_DIRECTORY") {
            self.buckets.directory = PathBuf::from(val);
        }

        // Overlay overrides
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_OVERLAY_PEER_PORT") {
            if let Ok(port) = val.parse() {
                self.overlay.peer_port = port;
            }
        }

        // Logging overrides
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_LOG_LEVEL") {
            self.logging.level = val;
        }
        if let Ok(val) = std::env::var("RS_STELLAR_CORE_LOG_FORMAT") {
            self.logging.format = val;
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validators must have a node seed
        if self.node.is_validator && self.node.node_seed.is_none() {
            anyhow::bail!("Validators must have a node_seed configured");
        }

        // Validate node seed format if provided
        if let Some(ref seed) = self.node.node_seed {
            if !seed.starts_with('S') || seed.len() != 56 {
                anyhow::bail!("Invalid node_seed format (must be S... format)");
            }
        }

        // Must have at least one history archive for catchup
        if self.history.archives.is_empty() {
            anyhow::bail!("At least one history archive must be configured");
        }

        if self.overlay.flood_op_rate_per_ledger <= 0.0 {
            anyhow::bail!("flood_op_rate_per_ledger must be > 0");
        }
        if self.overlay.flood_soroban_rate_per_ledger <= 0.0 {
            anyhow::bail!("flood_soroban_rate_per_ledger must be > 0");
        }
        if self.overlay.flood_demand_period_ms == 0 {
            anyhow::bail!("flood_demand_period_ms must be > 0");
        }
        if self.overlay.flood_advert_period_ms == 0 {
            anyhow::bail!("flood_advert_period_ms must be > 0");
        }
        if self.overlay.flood_demand_backoff_delay_ms == 0 {
            anyhow::bail!("flood_demand_backoff_delay_ms must be > 0");
        }
        if self.overlay.auto_survey {
            anyhow::bail!("auto_survey is not supported; surveys are manual only");
        }
        for key in &self.overlay.surveyor_keys {
            if stellar_core_crypto::PublicKey::from_strkey(key).is_err() {
                anyhow::bail!("Invalid surveyor key: {}", key);
            }
        }

        let total_bytes = self.surge_pricing.classic_byte_allowance
            .saturating_add(self.surge_pricing.soroban_byte_allowance);
        if total_bytes > 10 * 1024 * 1024 {
            anyhow::bail!("surge_pricing byte allowances exceed 10MB total");
        }

        if self.events.backfill_stellar_asset_events && !self.events.emit_classic_events {
            anyhow::bail!(
                "events.backfill_stellar_asset_events requires events.emit_classic_events"
            );
        }

        // Validate quorum set if validator
        if self.node.is_validator {
            if self.node.quorum_set.validators.is_empty()
                && self.node.quorum_set.inner_sets.is_empty()
            {
                anyhow::bail!("Validators must have a quorum set configured");
            }
        }

        Ok(())
    }

    /// Get the network ID hash.
    pub fn network_id(&self) -> stellar_core_common::Hash256 {
        stellar_core_common::Hash256::hash(self.network.passphrase.as_bytes())
    }

    /// Generate a sample configuration file.
    pub fn sample_config() -> String {
        let config = Self::testnet();
        toml::to_string_pretty(&config).unwrap_or_default()
    }
}

/// Builder for AppConfig.
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: AppConfig,
}

impl ConfigBuilder {
    /// Create a new builder with testnet defaults.
    pub fn new() -> Self {
        Self {
            config: AppConfig::testnet(),
        }
    }

    /// Create a builder for mainnet.
    pub fn mainnet() -> Self {
        Self {
            config: AppConfig::mainnet(),
        }
    }

    /// Set the node name.
    pub fn node_name(mut self, name: impl Into<String>) -> Self {
        self.config.node.name = name.into();
        self
    }

    /// Set the node seed.
    pub fn node_seed(mut self, seed: impl Into<String>) -> Self {
        self.config.node.node_seed = Some(seed.into());
        self
    }

    /// Set validator mode.
    pub fn validator(mut self, is_validator: bool) -> Self {
        self.config.node.is_validator = is_validator;
        self
    }

    /// Set the database path.
    pub fn database_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.database.path = path.into();
        self
    }

    /// Set the bucket directory.
    pub fn bucket_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.buckets.directory = path.into();
        self
    }

    /// Set the peer port.
    pub fn peer_port(mut self, port: u16) -> Self {
        self.config.overlay.peer_port = port;
        self
    }

    /// Add a known peer.
    pub fn add_known_peer(mut self, peer: impl Into<String>) -> Self {
        self.config.overlay.known_peers.push(peer.into());
        self
    }

    /// Add a history archive.
    pub fn add_history_archive(mut self, name: impl Into<String>, url: impl Into<String>) -> Self {
        self.config.history.archives.push(HistoryArchiveEntry {
            name: name.into(),
            url: url.into(),
            get_enabled: true,
            put_enabled: false,
            put: None,
            mkdir: None,
        });
        self
    }

    /// Set the log level.
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.config.logging.level = level.into();
        self
    }

    /// Build the configuration.
    pub fn build(self) -> AppConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(
            config.network.passphrase,
            "Test SDF Network ; September 2015"
        );
        assert!(!config.node.is_validator);
        assert!(config.upgrades.to_ledger_upgrades().is_empty());
    }

    #[test]
    fn test_mainnet_config() {
        let config = AppConfig::mainnet();
        assert_eq!(
            config.network.passphrase,
            "Public Global Stellar Network ; September 2015"
        );
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .node_name("my-node")
            .database_path("/tmp/stellar.db")
            .peer_port(11626)
            .log_level("debug")
            .build();

        assert_eq!(config.node.name, "my-node");
        assert_eq!(config.database.path, PathBuf::from("/tmp/stellar.db"));
        assert_eq!(config.overlay.peer_port, 11626);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_validation_validator_without_seed() {
        let mut config = AppConfig::default();
        config.node.is_validator = true;

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_network_id() {
        let config = AppConfig::testnet();
        let network_id = config.network_id();
        // Testnet network ID is well-known
        assert!(!network_id.is_zero());
    }

    #[test]
    fn test_sample_config() {
        let sample = AppConfig::sample_config();
        assert!(!sample.is_empty());
        assert!(sample.contains("[node]"));
        assert!(sample.contains("[network]"));
    }
}
