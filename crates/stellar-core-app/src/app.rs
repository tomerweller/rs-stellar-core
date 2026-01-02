//! Application struct and component initialization for rs-stellar-core.
//!
//! The App struct is the main entry point that coordinates all subsystems:
//! - Database for persistent storage
//! - BucketManager for ledger state
//! - LedgerManager for ledger operations
//! - HistoryManager for archive access
//! - OverlayManager for P2P networking
//! - Herder for consensus coordination

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rand::{seq::SliceRandom, Rng};
use serde::Serialize;
use tokio::sync::RwLock;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;

use stellar_core_bucket::BucketManager;
use stellar_core_herder::{
    EnvelopeState, Herder, HerderCallback, HerderConfig, HerderStats, TxQueueConfig,
};
use stellar_core_history::{
    is_checkpoint_ledger, latest_checkpoint_before_or_at, CatchupManager, CatchupOutput,
    CheckpointData, HistoryArchive, CHECKPOINT_FREQUENCY,
};
use stellar_core_historywork::{
    build_checkpoint_data, get_progress, HistoryWorkBuilder, HistoryWorkState,
};
use stellar_core_ledger::{
    LedgerCloseData, LedgerManager, LedgerManagerConfig, TransactionSetVariant,
};
use stellar_core_overlay::{
    ConnectionDirection, LocalNode, OverlayConfig as OverlayManagerConfig, OverlayManager,
    OverlayMessage, PeerAddress, PeerEvent, PeerId, PeerSnapshot, PeerType,
};
use stellar_core_work::{WorkScheduler, WorkSchedulerConfig, WorkState};
use stellar_core_common::{Hash256, NetworkId};
use stellar_core_db::{
    BucketListQueries, HistoryQueries, LedgerQueries, PublishQueueQueries, ScpQueries,
};
use stellar_core_scp::hash_quorum_set;
use x25519_dalek::{PublicKey as CurvePublicKey, StaticSecret as CurveSecretKey};
use stellar_xdr::curr::{
    Curve25519Public, DontHave, EncryptedBody, FloodAdvert, FloodDemand, GeneralizedTransactionSet,
    Hash, LedgerCloseMeta, LedgerUpgrade, MessageType, ReadXdr, ScpEnvelope,
    SignedTimeSlicedSurveyResponseMessage, StellarMessage, StellarValue, SurveyMessageCommandType,
    SurveyRequestMessage, SurveyResponseBody, SurveyResponseMessage, TimeSlicedSurveyRequestMessage,
    TimeSlicedSurveyResponseMessage, TimeSlicedSurveyStartCollectingMessage,
    TimeSlicedSurveyStopCollectingMessage, TimeSlicedPeerDataList, TopologyResponseBodyV2,
    TransactionHistoryEntry, TransactionHistoryEntryExt, TransactionHistoryResultEntry,
    TransactionHistoryResultEntryExt, TransactionMeta, TransactionResultPair, TransactionResultSet,
    TransactionSet, TxAdvertVector, TxDemandVector, UpgradeType, VecM, WriteXdr,
};
use stellar_core_tx::TransactionFrame;

use crate::config::AppConfig;
use crate::logging::CatchupProgress;
use crate::survey::{SurveyDataManager, SurveyMessageLimiter, SurveyPhase};
use stellar_core_ledger::{
    close_time as ledger_close_time, compute_header_hash, verify_header_chain, verify_skip_list,
};
use stellar_xdr::curr::TransactionEnvelope;

const TIME_SLICED_PEERS_MAX: usize = 25;
const PEER_TYPE_OUTBOUND: i32 = 1;
const PEER_TYPE_PREFERRED: i32 = 2;
const PEER_TYPE_INBOUND: i32 = 0;
const PEER_MAX_FAILURES_TO_SEND: u32 = 10;
const TX_SET_REQUEST_WINDOW: u64 = 12;
const MAX_TX_SET_REQUESTS_PER_TICK: usize = 32;

fn build_generalized_tx_set(
    tx_set: &stellar_core_herder::TransactionSet,
) -> Option<stellar_xdr::curr::GeneralizedTransactionSet> {
    use stellar_xdr::curr::{
        GeneralizedTransactionSet, TransactionPhase, TransactionSetV1, TxSetComponent,
        TxSetComponentTxsMaybeDiscountedFee,
    };

    let component = TxSetComponent::TxsetCompTxsMaybeDiscountedFee(
        TxSetComponentTxsMaybeDiscountedFee {
            base_fee: None,
            txs: tx_set.transactions.clone().try_into().ok()?,
        },
    );
    let phase = TransactionPhase::V0(vec![component].try_into().ok()?);
    Some(GeneralizedTransactionSet::V1(TransactionSetV1 {
        previous_ledger_hash: Hash(tx_set.previous_ledger_hash.0),
        phases: vec![phase].try_into().ok()?,
    }))
}

fn decode_upgrades(upgrades: Vec<UpgradeType>) -> Vec<LedgerUpgrade> {
    upgrades
        .into_iter()
        .filter_map(|upgrade| {
            let bytes = upgrade.0.as_slice();
            match LedgerUpgrade::from_xdr(bytes, stellar_xdr::curr::Limits::none()) {
                Ok(decoded) => Some(decoded),
                Err(err) => {
                    tracing::warn!(error = %err, "Failed to decode ledger upgrade");
                    None
                }
            }
        })
        .collect()
}

/// Application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Application is initializing.
    Initializing,
    /// Application is catching up from history.
    CatchingUp,
    /// Application is synced and tracking consensus.
    Synced,
    /// Application is running as a validator.
    Validating,
    /// Application is shutting down.
    ShuttingDown,
}

impl std::fmt::Display for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppState::Initializing => write!(f, "Initializing"),
            AppState::CatchingUp => write!(f, "Catching Up"),
            AppState::Synced => write!(f, "Synced"),
            AppState::Validating => write!(f, "Validating"),
            AppState::ShuttingDown => write!(f, "Shutting Down"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SurveyPeerReport {
    pub peer_id: String,
    pub response: TopologyResponseBodyV2,
}

#[derive(Debug, Serialize)]
pub struct SurveyReport {
    pub phase: SurveyPhase,
    pub nonce: Option<u32>,
    pub local_node: Option<stellar_xdr::curr::TimeSlicedNodeData>,
    pub inbound_peers: Vec<stellar_xdr::curr::TimeSlicedPeerData>,
    pub outbound_peers: Vec<stellar_xdr::curr::TimeSlicedPeerData>,
    pub peer_reports: BTreeMap<u32, Vec<SurveyPeerReport>>,
    pub survey_in_progress: bool,
    pub backlog: Vec<String>,
    pub bad_response_nodes: Vec<String>,
}

/// The main application struct.
pub struct App {
    /// Application configuration.
    config: AppConfig,

    /// Current application state.
    state: RwLock<AppState>,

    /// Database connection.
    db: stellar_core_db::Database,
    /// Lock file handle to prevent multiple instances.
    db_lock: Option<File>,

    /// Node keypair.
    keypair: stellar_core_crypto::SecretKey,

    /// Bucket manager for ledger state persistence.
    bucket_manager: Arc<BucketManager>,

    /// Ledger manager for ledger operations.
    ledger_manager: Arc<LedgerManager>,

    /// Overlay network manager.
    overlay: TokioMutex<Option<OverlayManager>>,

    /// Herder for consensus coordination.
    herder: Arc<Herder>,

    /// Current ledger sequence.
    current_ledger: RwLock<u32>,

    /// Whether running as validator.
    is_validator: bool,

    /// Shutdown signal sender.
    shutdown_tx: tokio::sync::broadcast::Sender<()>,

    /// Shutdown signal receiver.
    _shutdown_rx: tokio::sync::broadcast::Receiver<()>,

    /// Channel for outbound SCP envelopes.
    scp_envelope_tx: tokio::sync::mpsc::Sender<ScpEnvelope>,

    /// Receiver for outbound SCP envelopes.
    scp_envelope_rx: TokioMutex<tokio::sync::mpsc::Receiver<ScpEnvelope>>,

    /// Last processed externalized slot (for ledger close triggering).
    last_processed_slot: RwLock<u64>,
    /// Prevent concurrent catchup runs when we fall behind.
    catchup_in_progress: AtomicBool,
    /// Buffered externalized ledgers waiting to apply.
    syncing_ledgers: RwLock<BTreeMap<u32, stellar_core_herder::LedgerCloseInfo>>,
    /// Latest externalized slot we've observed (for liveness checks).
    last_externalized_slot: AtomicU64,
    /// Time when we last observed an externalized slot.
    last_externalized_at: RwLock<Instant>,
    /// Last time we requested SCP state due to stalled externalization.
    last_scp_state_request_at: RwLock<Instant>,

    /// Time-sliced survey data manager.
    survey_data: RwLock<SurveyDataManager>,

    /// Pending transaction hashes to advertise.
    tx_advert_queue: RwLock<Vec<Hash256>>,
    /// Deduplication set for pending tx adverts.
    tx_advert_set: RwLock<HashSet<Hash256>>,

    /// Per-peer advert tracking and queues for demand scheduling.
    tx_adverts_by_peer: RwLock<HashMap<stellar_core_overlay::PeerId, PeerTxAdverts>>,
    /// Demand history for transaction pulls.
    tx_demand_history: RwLock<HashMap<Hash256, TxDemandHistory>>,
    /// Pending demand hashes in FIFO order for retention.
    tx_pending_demands: RwLock<VecDeque<Hash256>>,
    /// Per-txset DontHave tracking to avoid retrying peers that lack the set.
    tx_set_dont_have: RwLock<HashMap<Hash256, HashSet<stellar_core_overlay::PeerId>>>,
    /// Last time we requested a tx set by hash (throttling).
    tx_set_last_request: RwLock<HashMap<Hash256, TxSetRequestState>>,
    /// SCP latency samples for surveys.
    scp_latency: RwLock<ScpLatencyTracker>,

    /// Survey scheduler state for time-sliced surveys.
    survey_scheduler: RwLock<SurveyScheduler>,
    /// Next survey nonce.
    survey_nonce: RwLock<u32>,
    /// Ephemeral survey encryption secrets keyed by nonce.
    survey_secrets: RwLock<HashMap<u32, [u8; 32]>>,
    /// Survey responses keyed by nonce.
    survey_results: RwLock<HashMap<u32, HashMap<stellar_core_overlay::PeerId, TopologyResponseBodyV2>>>,
    /// Survey message limiter for rate limiting and deduplication.
    survey_limiter: RwLock<SurveyMessageLimiter>,
    /// Survey throttle timeout between survey runs.
    survey_throttle: Duration,
    /// Survey reporting backlog state (surveyor-side).
    survey_reporting: RwLock<SurveyReportingState>,
    /// SCP timeout scheduling state.
    scp_timeouts: RwLock<ScpTimeoutState>,

    /// Total number of times the node lost sync.
    lost_sync_count: AtomicU64,
    /// Monotonic counter used for ping IDs.
    ping_counter: AtomicU64,
    /// In-flight ping requests keyed by hash.
    ping_inflight: RwLock<HashMap<Hash256, PingInfo>>,
    /// In-flight ping hash per peer.
    peer_ping_inflight: RwLock<HashMap<stellar_core_overlay::PeerId, Hash256>>,
}

#[derive(Debug)]
struct TxAdvertHistory {
    entries: HashMap<Hash256, u32>,
    order: VecDeque<(Hash256, u32)>,
    capacity: usize,
}

impl TxAdvertHistory {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn seen(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash)
    }

    fn remember(&mut self, hash: Hash256, ledger_seq: u32) {
        self.entries.insert(hash, ledger_seq);
        self.order.push_back((hash, ledger_seq));

        while self.entries.len() > self.capacity {
            if let Some((old_hash, old_seq)) = self.order.pop_front() {
                if self.entries.get(&old_hash) == Some(&old_seq) {
                    self.entries.remove(&old_hash);
                }
            }
        }
    }

    fn clear_below(&mut self, ledger_seq: u32) {
        self.entries.retain(|_, seq| *seq >= ledger_seq);
        self.order.retain(|(hash, seq)| *seq >= ledger_seq && self.entries.get(hash) == Some(seq));
    }
}

#[derive(Debug, Clone)]
struct TxSetRequestState {
    last_request: Instant,
    next_peer_offset: usize,
}

#[derive(Debug)]
struct PeerTxAdverts {
    incoming: VecDeque<Hash256>,
    retry: VecDeque<Hash256>,
    history: TxAdvertHistory,
}

impl PeerTxAdverts {
    fn new() -> Self {
        Self {
            incoming: VecDeque::new(),
            retry: VecDeque::new(),
            history: TxAdvertHistory::new(50_000),
        }
    }

    fn seen_advert(&self, hash: &Hash256) -> bool {
        self.history.seen(hash)
    }

    fn remember(&mut self, hash: Hash256, ledger_seq: u32) {
        self.history.remember(hash, ledger_seq);
    }

    fn queue_incoming(&mut self, hashes: &[Hash], ledger_seq: u32, max_ops: usize) {
        for hash in hashes {
            let hash256 = Hash256::from(hash.clone());
            self.remember(hash256, ledger_seq);
        }

        let start = hashes.len().saturating_sub(max_ops);
        for hash in hashes.iter().skip(start) {
            self.incoming.push_back(Hash256::from(hash.clone()));
        }

        while self.size() > max_ops {
            self.pop_advert();
        }
    }

    fn retry_incoming(&mut self, hashes: Vec<Hash256>, max_ops: usize) {
        self.retry.extend(hashes);
        while self.size() > max_ops {
            self.pop_advert();
        }
    }

    fn pop_advert(&mut self) -> Option<Hash256> {
        if let Some(hash) = self.retry.pop_front() {
            return Some(hash);
        }
        self.incoming.pop_front()
    }

    fn has_advert(&self) -> bool {
        self.size() > 0
    }

    fn size(&self) -> usize {
        self.retry.len() + self.incoming.len()
    }

    fn clear_below(&mut self, ledger_seq: u32) {
        self.history.clear_below(ledger_seq);
    }
}

#[derive(Debug)]
struct TxDemandHistory {
    first_demanded: Instant,
    last_demanded: Instant,
    peers: HashMap<stellar_core_overlay::PeerId, Instant>,
    latency_recorded: bool,
}

#[derive(Debug, Clone, Copy)]
enum DemandStatus {
    Demand,
    RetryLater,
    Discard,
}

#[derive(Debug, Clone)]
struct PingInfo {
    peer_id: stellar_core_overlay::PeerId,
    sent_at: Instant,
}

#[derive(Debug, Default)]
struct ScpLatencyTracker {
    first_seen: HashMap<u64, Instant>,
    self_sent: HashMap<u64, Instant>,
    self_to_other_recorded: HashSet<u64>,
    first_to_self_samples_ms: Vec<u64>,
    self_to_other_samples_ms: Vec<u64>,
}

#[derive(Debug)]
struct SurveyReportingState {
    running: bool,
    peers: HashSet<stellar_core_overlay::PeerId>,
    queue: VecDeque<stellar_core_overlay::PeerId>,
    inbound_indices: HashMap<stellar_core_overlay::PeerId, u32>,
    outbound_indices: HashMap<stellar_core_overlay::PeerId, u32>,
    bad_response_nodes: HashSet<stellar_core_overlay::PeerId>,
    next_topoff: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurveyReportingStart {
    Started,
    AlreadyRunning,
    NotReady,
}

impl SurveyReportingState {
    fn new() -> Self {
        Self {
            running: false,
            peers: HashSet::new(),
            queue: VecDeque::new(),
            inbound_indices: HashMap::new(),
            outbound_indices: HashMap::new(),
            bad_response_nodes: HashSet::new(),
            next_topoff: Instant::now(),
        }
    }
}

impl ScpLatencyTracker {
    const MAX_SAMPLES: usize = 256;

    fn record_first_seen(&mut self, slot: u64) {
        self.first_seen.entry(slot).or_insert_with(Instant::now);
    }

    fn record_self_sent(&mut self, slot: u64) -> Option<u64> {
        let now = Instant::now();
        let mut sample = None;
        if let Some(first) = self.first_seen.get(&slot) {
            let delta = now.duration_since(*first).as_millis() as u64;
            Self::push_sample(&mut self.first_to_self_samples_ms, delta);
            sample = Some(delta);
        }
        self.self_sent.insert(slot, now);
        sample
    }

    fn record_other_after_self(&mut self, slot: u64) -> Option<u64> {
        if self.self_to_other_recorded.contains(&slot) {
            return None;
        }
        if let Some(sent) = self.self_sent.get(&slot) {
            let delta = sent.elapsed().as_millis() as u64;
            Self::push_sample(&mut self.self_to_other_samples_ms, delta);
            self.self_to_other_recorded.insert(slot);
            return Some(delta);
        }
        None
    }

    fn push_sample(samples: &mut Vec<u64>, value: u64) {
        samples.push(value);
        if samples.len() > Self::MAX_SAMPLES {
            let _ = samples.remove(0);
        }
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurveySchedulerPhase {
    Idle,
    StartSent,
    RequestSent,
}

#[derive(Debug)]
struct SurveyScheduler {
    phase: SurveySchedulerPhase,
    next_action: Instant,
    peers: Vec<stellar_core_overlay::PeerId>,
    nonce: u32,
    ledger_num: u32,
    last_started: Option<Instant>,
}

impl SurveyScheduler {
    fn new() -> Self {
        Self {
            phase: SurveySchedulerPhase::Idle,
            next_action: Instant::now() + Duration::from_secs(60),
            peers: Vec::new(),
            nonce: 0,
            ledger_num: 0,
            last_started: None,
        }
    }
}

#[derive(Debug)]
struct ScpTimeoutState {
    slot: u64,
    next_nomination: Option<Instant>,
    next_ballot: Option<Instant>,
}

impl ScpTimeoutState {
    fn new() -> Self {
        Self {
            slot: 0,
            next_nomination: None,
            next_ballot: None,
        }
    }
}

impl App {
    /// Create a new application instance.
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        tracing::info!(
            node_name = %config.node.name,
            network = %config.network.passphrase,
            "Initializing rs-stellar-core"
        );

        // Validate configuration
        config.validate()?;

        let db_lock = Self::acquire_db_lock(&config)?;

        // Initialize database
        let db = Self::init_database(&config)?;

        // Ensure network passphrase matches stored state.
        Self::ensure_network_passphrase(&db, &config.network.passphrase)?;

        // Verify on-disk ledger headers before loading state.
        Self::verify_on_disk_integrity(&db)?;

        // Initialize or generate keypair
        let keypair = Self::init_keypair(&config)?;

        tracing::info!(
            public_key = %keypair.public_key().to_strkey(),
            "Node identity"
        );

        let is_validator = config.node.is_validator;
        let max_inbound_peers = config.overlay.max_inbound_peers as u32;
        let max_outbound_peers = config.overlay.max_outbound_peers as u32;

        // Convert quorum set config to XDR
        let local_quorum_set = config.node.quorum_set.to_xdr();
        if let Some(ref qs) = local_quorum_set {
            tracing::info!(
                threshold = qs.threshold,
                validators = qs.validators.len(),
                inner_sets = qs.inner_sets.len(),
                "Loaded quorum set configuration"
            );
        }

        // Initialize bucket manager for ledger state persistence
        let bucket_dir = config.database.path.parent()
            .unwrap_or(&config.database.path)
            .join("buckets");
        std::fs::create_dir_all(&bucket_dir)?;

        let bucket_manager = Arc::new(BucketManager::new(bucket_dir)?);
        tracing::info!("Bucket manager initialized");

        // Initialize ledger manager
        let ledger_manager = Arc::new(LedgerManager::with_config(
            db.clone(),
            bucket_manager.clone(),
            config.network.passphrase.clone(),
            LedgerManagerConfig {
                max_snapshots: 10,
                validate_bucket_hash: true,
                validate_invariants: true,
                persist_to_db: true,
            },
        ));
        tracing::info!("Ledger manager initialized");

        // Create herder configuration
        let herder_config = HerderConfig {
            max_pending_transactions: 1000,
            is_validator: config.node.is_validator,
            ledger_close_time: 5,
            node_public_key: keypair.public_key(),
            network_id: config.network_id(),
            max_externalized_slots: TX_SET_REQUEST_WINDOW as usize,
            max_tx_set_size: 1000,
            pending_config: Default::default(),
            tx_queue_config: TxQueueConfig {
                max_dex_ops: config.surge_pricing.max_dex_tx_operations,
                max_classic_bytes: Some(config.surge_pricing.classic_byte_allowance),
                max_soroban_bytes: Some(config.surge_pricing.soroban_byte_allowance),
                ..Default::default()
            },
            local_quorum_set,
            proposed_upgrades: config.upgrades.to_ledger_upgrades(),
        };

        // Create herder (with or without secret key for signing)
        let survey_throttle = Duration::from_secs(herder_config.ledger_close_time as u64 * 3);

        let herder = if config.node.is_validator {
            Arc::new(Herder::with_secret_key(herder_config, keypair.clone()))
        } else {
            Arc::new(Herder::new(herder_config))
        };
        herder.set_ledger_manager(ledger_manager.clone());

        if let Some(qs) = herder.local_quorum_set() {
            let hash = hash_quorum_set(&qs);
            if let Err(err) = db.store_scp_quorum_set(&hash, 0, &qs) {
                tracing::warn!(error = %err, "Failed to store local quorum set");
            }
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        // Create channel for outbound SCP envelopes
        let (scp_envelope_tx, scp_envelope_rx) = tokio::sync::mpsc::channel(100);

        // Wire up envelope sender for validators
        if config.node.is_validator {
            let tx = scp_envelope_tx.clone();
            herder.set_envelope_sender(move |envelope| {
                // Non-blocking send - if channel is full, we drop the envelope
                // (This is fine, SCP will retry)
                let _ = tx.try_send(envelope);
            });
            tracing::info!("Envelope sender configured for validator mode");
        }

        Ok(Self {
            is_validator,
            config,
            state: RwLock::new(AppState::Initializing),
            db,
            db_lock: Some(db_lock),
            keypair,
            bucket_manager,
            ledger_manager,
            overlay: TokioMutex::new(None),
            herder,
            current_ledger: RwLock::new(0),
            shutdown_tx,
            _shutdown_rx: shutdown_rx,
            scp_envelope_tx,
            scp_envelope_rx: TokioMutex::new(scp_envelope_rx),
            last_processed_slot: RwLock::new(0),
            catchup_in_progress: AtomicBool::new(false),
            syncing_ledgers: RwLock::new(BTreeMap::new()),
            last_externalized_slot: AtomicU64::new(0),
            last_externalized_at: RwLock::new(Instant::now()),
            last_scp_state_request_at: RwLock::new(Instant::now()),
            survey_data: RwLock::new(SurveyDataManager::new(
                is_validator,
                max_inbound_peers,
                max_outbound_peers,
            )),
            tx_advert_queue: RwLock::new(Vec::new()),
            tx_advert_set: RwLock::new(HashSet::new()),
            tx_adverts_by_peer: RwLock::new(HashMap::new()),
            tx_demand_history: RwLock::new(HashMap::new()),
            tx_pending_demands: RwLock::new(VecDeque::new()),
            tx_set_dont_have: RwLock::new(HashMap::new()),
            tx_set_last_request: RwLock::new(HashMap::new()),
            scp_latency: RwLock::new(ScpLatencyTracker::default()),
            survey_scheduler: RwLock::new(SurveyScheduler::new()),
            survey_nonce: RwLock::new(1),
            survey_secrets: RwLock::new(HashMap::new()),
            survey_results: RwLock::new(HashMap::new()),
            survey_limiter: RwLock::new(SurveyMessageLimiter::new(6, 10)),
            survey_throttle,
            survey_reporting: RwLock::new(SurveyReportingState::new()),
            scp_timeouts: RwLock::new(ScpTimeoutState::new()),
            lost_sync_count: AtomicU64::new(0),
            ping_counter: AtomicU64::new(0),
            ping_inflight: RwLock::new(HashMap::new()),
            peer_ping_inflight: RwLock::new(HashMap::new()),
        })
    }

    fn verify_on_disk_integrity(db: &stellar_core_db::Database) -> anyhow::Result<()> {
        const VERIFY_DEPTH: u32 = 128;

        let Some(latest) = db.get_latest_ledger_seq()? else {
            return Ok(());
        };
        if latest == 0 {
            return Ok(());
        }

        let mut current_seq = latest;
        let mut checked = 0u32;
        while current_seq > 0 && checked < VERIFY_DEPTH {
            let current = db
                .get_ledger_header(current_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", current_seq))?;
            let prev_seq = current_seq - 1;
            let Some(prev) = db.get_ledger_header(prev_seq)? else {
                tracing::warn!(
                    missing_seq = prev_seq,
                    latest_seq = latest,
                    "Ledger header chain has a gap; skipping deeper integrity checks"
                );
                break;
            };
            let prev_hash = compute_header_hash(&prev)?;
            verify_header_chain(&prev, &prev_hash, &current)?;
            current_seq = prev_seq;
            checked += 1;
        }

        let latest_header = db
            .get_ledger_header(latest)?
            .ok_or_else(|| anyhow::anyhow!("Missing latest ledger header at {}", latest))?;
        verify_skip_list(&latest_header, |seq| {
            db.get_ledger_header(seq)
                .ok()
                .flatten()
                .and_then(|header| compute_header_hash(&header).ok())
        })?;

        Ok(())
    }

    fn ensure_network_passphrase(
        db: &stellar_core_db::Database,
        passphrase: &str,
    ) -> anyhow::Result<()> {
        let stored = db.get_network_passphrase()?;
        if let Some(existing) = stored {
            if existing != passphrase {
                anyhow::bail!(
                    "Network passphrase mismatch: db has '{}', config has '{}'",
                    existing,
                    passphrase
                );
            }
            return Ok(());
        }
        db.set_network_passphrase(passphrase)?;
        Ok(())
    }

    /// Initialize the database.
    fn init_database(config: &AppConfig) -> anyhow::Result<stellar_core_db::Database> {
        tracing::info!(path = ?config.database.path, "Opening database");

        // Ensure parent directory exists
        if let Some(parent) = config.database.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let db = stellar_core_db::Database::open(&config.database.path)?;
        tracing::debug!("Database opened successfully");
        Ok(db)
    }

    fn acquire_db_lock(config: &AppConfig) -> anyhow::Result<File> {
        use fs2::FileExt;

        let lock_path = config
            .database
            .path
            .with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lock_path)?;
        file.try_lock_exclusive()
            .map_err(|_| anyhow::anyhow!("database is locked (lockfile: {})", lock_path.display()))?;
        Ok(file)
    }

    /// Initialize the node keypair.
    fn init_keypair(config: &AppConfig) -> anyhow::Result<stellar_core_crypto::SecretKey> {
        if let Some(ref seed) = config.node.node_seed {
            tracing::debug!("Using configured node seed");
            let keypair = stellar_core_crypto::SecretKey::from_strkey(seed)?;
            Ok(keypair)
        } else {
            tracing::info!("Generating ephemeral node keypair");
            Ok(stellar_core_crypto::SecretKey::generate())
        }
    }

    /// Get the application configuration.
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Get the current application state.
    pub async fn state(&self) -> AppState {
        *self.state.read().await
    }

    /// Set the application state.
    async fn set_state(&self, state: AppState) {
        let mut current = self.state.write().await;
        if *current != state {
            if matches!(*current, AppState::Synced | AppState::Validating)
                && state == AppState::CatchingUp
            {
                self.lost_sync_count.fetch_add(1, Ordering::Relaxed);
            }
            tracing::info!(from = %*current, to = %state, "State transition");
            *current = state;
        }
    }

    /// Get the database.
    pub fn database(&self) -> &stellar_core_db::Database {
        &self.db
    }

    /// Get the node's public key.
    pub fn public_key(&self) -> stellar_core_crypto::PublicKey {
        self.keypair.public_key()
    }

    /// Get the network ID.
    pub fn network_id(&self) -> stellar_core_common::Hash256 {
        self.config.network_id()
    }

    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let overlay = self.overlay.lock().await;
        overlay
            .as_ref()
            .map(|overlay| overlay.peer_snapshots())
            .unwrap_or_default()
    }

    pub async fn connect_peer(&self, addr: PeerAddress) -> anyhow::Result<PeerId> {
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        overlay.connect(&addr).await.map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> bool {
        let overlay = self.overlay.lock().await;
        let Some(overlay) = overlay.as_ref() else {
            return false;
        };
        overlay.disconnect(peer_id).await
    }

    pub async fn ban_peer(&self, peer_id: PeerId) -> anyhow::Result<()> {
        let Some(strkey) = Self::peer_id_to_strkey(&peer_id) else {
            anyhow::bail!("Invalid peer id");
        };
        self.db.ban_node(&strkey)?;
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        overlay.ban_peer(peer_id).await;
        Ok(())
    }

    pub async fn unban_peer(&self, peer_id: &PeerId) -> anyhow::Result<bool> {
        let Some(strkey) = Self::peer_id_to_strkey(peer_id) else {
            anyhow::bail!("Invalid peer id");
        };
        self.db.unban_node(&strkey)?;
        let overlay = self.overlay.lock().await;
        let overlay = overlay
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Overlay manager not available"))?;
        Ok(overlay.unban_peer(peer_id))
    }

    pub async fn banned_peers(&self) -> anyhow::Result<Vec<PeerId>> {
        let bans = self.db.load_bans()?;
        let mut peers = Vec::new();
        for ban in bans {
            if let Some(peer_id) = Self::strkey_to_peer_id(&ban) {
                peers.push(peer_id);
            } else {
                tracing::warn!(node = %ban, "Ignoring invalid ban entry");
            }
        }
        Ok(peers)
    }

    pub fn ledger_info(&self) -> (u32, stellar_core_common::Hash256, u64, u32) {
        let header = self.ledger_manager.current_header();
        let hash = self.ledger_manager.current_header_hash();
        let close_time = ledger_close_time(&header);
        (header.ledger_seq, hash, close_time, header.ledger_version)
    }

    pub fn target_ledger_close_time(&self) -> u32 {
        self.herder.ledger_close_time()
    }

    pub fn current_upgrade_state(&self) -> (u32, u32, u32, u32) {
        let header = self.ledger_manager.current_header();
        (
            header.ledger_version,
            header.base_fee,
            header.base_reserve,
            header.max_tx_set_size,
        )
    }

    pub fn proposed_upgrades(&self) -> Vec<LedgerUpgrade> {
        self.config.upgrades.to_ledger_upgrades()
    }

    pub fn self_check(&self, depth: u32) -> anyhow::Result<SelfCheckResult> {
        let Some(latest) = self.db.get_latest_ledger_seq()? else {
            return Ok(SelfCheckResult {
                ok: true,
                checked_ledgers: 0,
                last_checked_ledger: None,
            });
        };
        if latest == 0 {
            return Ok(SelfCheckResult {
                ok: true,
                checked_ledgers: 0,
                last_checked_ledger: None,
            });
        }

        let mut current_seq = latest;
        let mut checked = 0u32;
        let mut last_verified = None;

        while current_seq > 0 && checked < depth {
            let current = self
                .db
                .get_ledger_header(current_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", current_seq))?;
            let prev_seq = current_seq - 1;
            let prev = self
                .db
                .get_ledger_header(prev_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", prev_seq))?;
            let prev_hash = compute_header_hash(&prev)?;
            verify_header_chain(&prev, &prev_hash, &current)?;
            last_verified = Some(current_seq);
            current_seq = prev_seq;
            checked += 1;
        }

        Ok(SelfCheckResult {
            ok: true,
            checked_ledgers: checked,
            last_checked_ledger: last_verified,
        })
    }

    pub fn pending_transaction_count(&self) -> usize {
        self.herder.stats().pending_transactions
    }

    pub fn submit_transaction(
        &self,
        tx: TransactionEnvelope,
    ) -> stellar_core_herder::TxQueueResult {
        self.herder.receive_transaction(tx)
    }

    pub fn herder_stats(&self) -> HerderStats {
        self.herder.stats()
    }

    pub fn scp_slot_snapshots(&self, limit: usize) -> Vec<ScpSlotSnapshot> {
        let Some(scp) = self.herder.scp() else {
            return Vec::new();
        };
        let (ledger_seq, _, _, _) = self.ledger_info();
        let latest_slot = self
            .herder
            .latest_externalized_slot()
            .unwrap_or(ledger_seq as u64);
        let mut slot = latest_slot;
        let mut snapshots = Vec::new();

        while slot > 0 && snapshots.len() < limit {
            if let Some(state) = scp.get_slot_state(slot) {
                let envelopes = self.herder.get_scp_envelopes(slot);
                snapshots.push(ScpSlotSnapshot {
                    slot_index: state.slot_index,
                    is_externalized: state.is_externalized,
                    is_nominating: state.is_nominating,
                    ballot_phase: format!("{:?}", state.ballot_phase),
                    nomination_round: state.nomination_round,
                    ballot_round: state.ballot_round,
                    envelope_count: envelopes.len(),
                });
            }
            slot = slot.saturating_sub(1);
        }

        snapshots
    }

    fn extract_tx_metas(meta: &LedgerCloseMeta) -> Vec<TransactionMeta> {
        match meta {
            LedgerCloseMeta::V0(_) => Vec::new(),
            LedgerCloseMeta::V1(v1) => v1
                .tx_processing
                .iter()
                .map(|processing| processing.tx_apply_processing.clone())
                .collect(),
            LedgerCloseMeta::V2(v2) => v2
                .tx_processing
                .iter()
                .map(|processing| processing.tx_apply_processing.clone())
                .collect(),
        }
    }

    fn persist_ledger_close(
        &self,
        header: &stellar_xdr::curr::LedgerHeader,
        tx_set_variant: &TransactionSetVariant,
        tx_results: &[TransactionResultPair],
        tx_metas: Option<&[TransactionMeta]>,
    ) -> anyhow::Result<()> {
        let header_xdr = header.to_xdr(stellar_xdr::curr::Limits::none())?;
        let network_id = NetworkId::from_passphrase(&self.config.network.passphrase);
        let ordered_txs: Vec<TransactionEnvelope> = tx_set_variant
            .transactions_with_base_fee()
            .into_iter()
            .map(|(tx, _)| tx)
            .collect();
        let tx_count = ordered_txs.len().min(tx_results.len());
        let meta_count = tx_metas.map(|metas| metas.len()).unwrap_or(0);
        let scp_envelopes = self.herder.get_scp_envelopes(header.ledger_seq as u64);
        let mut scp_quorum_sets = Vec::new();
        for envelope in &scp_envelopes {
            if let Some(hash) = Self::scp_quorum_set_hash(&envelope.statement) {
                let hash256 = Hash256::from_bytes(hash.0);
                if let Some(qset) = self.herder.get_quorum_set_by_hash(hash256.as_bytes()) {
                    scp_quorum_sets.push((hash256, qset));
                } else {
                    tracing::warn!(hash = %hash256.to_hex(), "Missing quorum set for SCP history");
                }
            }
        }

        if tx_results.len() != ordered_txs.len() {
            tracing::warn!(
                tx_count = ordered_txs.len(),
                result_count = tx_results.len(),
                "Transaction count mismatch while persisting history"
            );
        }
        if let Some(_) = tx_metas {
            if meta_count < tx_count {
                tracing::warn!(
                    tx_count,
                    meta_count,
                    "Transaction meta count mismatch while persisting history"
                );
            }
        }

        let tx_set_entry = match tx_set_variant {
            TransactionSetVariant::Classic(set) => set.clone(),
            TransactionSetVariant::Generalized(set) => {
                let stellar_xdr::curr::GeneralizedTransactionSet::V1(set_v1) = set;
                TransactionSet {
                    previous_ledger_hash: set_v1.previous_ledger_hash.clone(),
                    txs: VecM::default(),
                }
            }
        };
        let tx_history_entry = TransactionHistoryEntry {
            ledger_seq: header.ledger_seq,
            tx_set: tx_set_entry,
            ext: match tx_set_variant {
                TransactionSetVariant::Classic(_) => TransactionHistoryEntryExt::V0,
                TransactionSetVariant::Generalized(set) => {
                    TransactionHistoryEntryExt::V1(set.clone())
                }
            },
        };
        let tx_result_set = TransactionResultSet {
            results: tx_results.to_vec().try_into().unwrap_or_default(),
        };
        let tx_result_entry = TransactionHistoryResultEntry {
            ledger_seq: header.ledger_seq,
            tx_result_set,
            ext: TransactionHistoryResultEntryExt::default(),
        };

        self.db.transaction(|conn| {
            conn.store_ledger_header(header, &header_xdr)?;
            conn.store_tx_history_entry(header.ledger_seq, &tx_history_entry)?;
            conn.store_tx_result_entry(header.ledger_seq, &tx_result_entry)?;
            if is_checkpoint_ledger(header.ledger_seq) {
                let levels = self.ledger_manager.bucket_list_levels();
                conn.store_bucket_list(header.ledger_seq, &levels)?;
                if self.is_validator {
                    conn.enqueue_publish(header.ledger_seq)?;
                }
            }
            for index in 0..tx_count {
                let tx = &ordered_txs[index];
                let tx_result = &tx_results[index];
                let tx_meta = tx_metas.and_then(|metas| metas.get(index));

                let frame = TransactionFrame::with_network(tx.clone(), network_id);
                let tx_hash = frame
                    .hash(&network_id)
                    .map_err(|e| stellar_core_db::DbError::Integrity(e.to_string()))?;
                let tx_id = tx_hash.to_hex();

                let tx_body = tx.to_xdr(stellar_xdr::curr::Limits::none())?;
                let tx_result_xdr = tx_result.to_xdr(stellar_xdr::curr::Limits::none())?;
                let tx_meta_xdr = match tx_meta {
                    Some(meta) => Some(meta.to_xdr(stellar_xdr::curr::Limits::none())?),
                    None => None,
                };

                conn.store_transaction(
                    header.ledger_seq,
                    index as u32,
                    &tx_id,
                    &tx_body,
                    &tx_result_xdr,
                    tx_meta_xdr.as_deref(),
                )?;
            }

            conn.store_scp_history(header.ledger_seq, &scp_envelopes)?;
            for (hash, qset) in &scp_quorum_sets {
                conn.store_scp_quorum_set(hash, header.ledger_seq, qset)?;
            }
            Ok(())
        })?;

        Ok(())
    }

    pub async fn survey_report(&self) -> SurveyReport {
        let survey_data = self.survey_data.read().await;
        let phase = survey_data.phase();
        let nonce = survey_data.nonce();
        let local_node = survey_data.final_node_data();
        let inbound_peers = survey_data.final_inbound_peers().to_vec();
        let outbound_peers = survey_data.final_outbound_peers().to_vec();
        drop(survey_data);

        let (survey_in_progress, backlog, bad_response_nodes) = {
            let reporting = self.survey_reporting.read().await;
            let backlog = reporting
                .peers
                .iter()
                .map(|peer| peer.to_hex())
                .collect::<Vec<_>>();
            let bad = reporting
                .bad_response_nodes
                .iter()
                .map(|peer| peer.to_hex())
                .collect::<Vec<_>>();
            (reporting.running, backlog, bad)
        };
        let mut backlog = backlog;
        backlog.sort();
        let mut bad_response_nodes = bad_response_nodes;
        bad_response_nodes.sort();

        let peer_reports = {
            let results = self.survey_results.read().await;
            results
                .iter()
                .map(|(nonce, peers)| {
                    let mut reports = peers
                        .iter()
                        .map(|(peer_id, response)| SurveyPeerReport {
                            peer_id: peer_id.to_hex(),
                            response: response.clone(),
                        })
                        .collect::<Vec<_>>();
                    reports.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
                    (*nonce, reports)
                })
                .collect::<BTreeMap<_, _>>()
        };

        SurveyReport {
            phase,
            nonce,
            local_node,
            inbound_peers,
            outbound_peers,
            peer_reports,
            survey_in_progress,
            backlog,
            bad_response_nodes,
        }
    }

    pub async fn start_survey_collecting(&self, nonce: u32) -> bool {
        let ledger_num = self.survey_local_ledger().await;
        self.broadcast_survey_start(nonce, ledger_num).await
    }

    pub async fn stop_survey_collecting(&self) -> bool {
        let ledger_num = self.survey_local_ledger().await;
        let nonce = { self.survey_data.read().await.nonce() };
        let Some(nonce) = nonce else {
            return false;
        };
        self.broadcast_survey_stop(nonce, ledger_num).await;
        true
    }

    pub async fn stop_survey_reporting(&self) {
        let mut reporting = self.survey_reporting.write().await;
        reporting.running = false;
        drop(reporting);

        if let Some(nonce) = self.survey_data.read().await.nonce() {
            self.survey_secrets.write().await.remove(&nonce);
        }
    }

    pub async fn survey_topology_timesliced(
        &self,
        peer_id: stellar_core_overlay::PeerId,
        inbound_index: u32,
        outbound_index: u32,
    ) -> bool {
        let start = self.start_survey_reporting().await;
        if start == SurveyReportingStart::NotReady {
            return false;
        }

        if let Some(nonce) = { self.survey_data.read().await.nonce() } {
            if let Some(peers) = self.survey_results.write().await.get_mut(&nonce) {
                peers.remove(&peer_id);
            }
        }

        let self_peer = stellar_core_overlay::PeerId::from_bytes(
            *self.keypair.public_key().as_bytes(),
        );
        let mut reporting = self.survey_reporting.write().await;
        if reporting.peers.contains(&peer_id) || peer_id == self_peer {
            return false;
        }
        reporting.bad_response_nodes.remove(&peer_id);
        reporting.peers.insert(peer_id.clone());
        reporting.queue.push_back(peer_id.clone());
        reporting.inbound_indices.insert(peer_id.clone(), inbound_index);
        reporting.outbound_indices.insert(peer_id.clone(), outbound_index);
        true
    }

    async fn start_survey_reporting(&self) -> SurveyReportingStart {
        let nonce = { self.survey_data.read().await.nonce() };
        let Some(nonce) = nonce else {
            return SurveyReportingStart::NotReady;
        };
        if self.survey_data.read().await.final_node_data().is_none() {
            return SurveyReportingStart::NotReady;
        }

        let mut reporting = self.survey_reporting.write().await;
        if reporting.running {
            return SurveyReportingStart::AlreadyRunning;
        }
        reporting.running = true;
        reporting.peers.clear();
        reporting.queue.clear();
        reporting.inbound_indices.clear();
        reporting.outbound_indices.clear();
        reporting.bad_response_nodes.clear();
        reporting.next_topoff = Instant::now();

        self.survey_results.write().await.clear();
        self.ensure_survey_secret(nonce).await;
        if let Some(response) = self.local_topology_response().await {
            let self_peer = stellar_core_overlay::PeerId::from_bytes(
                *self.keypair.public_key().as_bytes(),
            );
            self.survey_results
                .write()
                .await
                .entry(nonce)
                .or_insert_with(HashMap::new)
                .insert(self_peer, response);
        }
        SurveyReportingStart::Started
    }

    async fn local_topology_response(&self) -> Option<TopologyResponseBodyV2> {
        const MAX_PEERS: usize = 25;
        let survey_data = self.survey_data.read().await;
        let node_data = survey_data.final_node_data()?;
        let inbound_peers = survey_data
            .final_inbound_peers()
            .iter()
            .take(MAX_PEERS)
            .cloned()
            .collect::<Vec<_>>();
        let outbound_peers = survey_data
            .final_outbound_peers()
            .iter()
            .take(MAX_PEERS)
            .cloned()
            .collect::<Vec<_>>();
        Some(TopologyResponseBodyV2 {
            inbound_peers: TimeSlicedPeerDataList(inbound_peers.try_into().unwrap_or_default()),
            outbound_peers: TimeSlicedPeerDataList(outbound_peers.try_into().unwrap_or_default()),
            node_data,
        })
    }

    async fn top_off_survey_requests(&self) {
        const MAX_REQUEST_LIMIT_PER_LEDGER: usize = 10;

        let (running, next_topoff) = {
            let reporting = self.survey_reporting.read().await;
            (reporting.running, reporting.next_topoff)
        };
        if !running {
            return;
        }
        if Instant::now() < next_topoff {
            return;
        }

        let nonce = { self.survey_data.read().await.nonce() };
        let Some(nonce) = nonce else {
            self.stop_survey_reporting().await;
            return;
        };
        if !self.survey_data.read().await.nonce_is_reporting(nonce) {
            self.stop_survey_reporting().await;
            return;
        }

        let ledger_num = self.survey_local_ledger().await;
        let mut requests_sent = 0usize;
        let mut to_send = Vec::new();

        {
            let mut reporting = self.survey_reporting.write().await;
            while requests_sent < MAX_REQUEST_LIMIT_PER_LEDGER && !reporting.queue.is_empty() {
                let peer_id = reporting.queue.pop_front().unwrap();
                if !reporting.peers.remove(&peer_id) {
                    continue;
                }
                let inbound_index = reporting.inbound_indices.remove(&peer_id).unwrap_or(0);
                let outbound_index = reporting.outbound_indices.remove(&peer_id).unwrap_or(0);
                to_send.push((peer_id, inbound_index, outbound_index));
                requests_sent += 1;
            }
            reporting.next_topoff = Instant::now() + self.survey_throttle;
        }

        for (peer_id, inbound_index, outbound_index) in to_send {
            let ok = self
                .send_survey_request(peer_id.clone(), nonce, ledger_num, inbound_index, outbound_index)
                .await;
            if !ok {
                tracing::debug!(peer = ?peer_id, "Survey request failed to send");
            }
        }
    }

    async fn send_survey_request(
        &self,
        peer_id: stellar_core_overlay::PeerId,
        nonce: u32,
        ledger_num: u32,
        inbound_index: u32,
        outbound_index: u32,
    ) -> bool {
        let local_node_id = self.local_node_id();
        let secret = self.ensure_survey_secret(nonce).await;
        let public = CurvePublicKey::from(&secret);
        let encryption_key = Curve25519Public {
            key: public.to_bytes(),
        };

        let request = SurveyRequestMessage {
            surveyor_peer_id: local_node_id.clone(),
            surveyed_peer_id: stellar_xdr::curr::NodeId(peer_id.0.clone()),
            ledger_num,
            encryption_key,
            command_type: SurveyMessageCommandType::TimeSlicedSurveyTopology,
        };

        let message = TimeSlicedSurveyRequestMessage {
            request,
            nonce,
            inbound_peers_index: inbound_index,
            outbound_peers_index: outbound_index,
        };

        let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey request");
                return false;
            }
        };

        let signature = self.sign_survey_message(&message_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyRequestMessage {
            request_signature: signature,
            request: message,
        };

        let local_ledger = self.survey_local_ledger().await;
        let mut limiter = self.survey_limiter.write().await;
        let ok = limiter.add_and_validate_request(
            &signed.request.request,
            local_ledger,
            &local_node_id,
            || {
                self.verify_survey_signature(
                    &signed.request.request.surveyor_peer_id,
                    &message_bytes,
                    &signed.request_signature,
                )
            },
        );
        if !ok {
            return false;
        }

        self.broadcast_survey_message(StellarMessage::TimeSlicedSurveyRequest(signed))
            .await
    }

    async fn broadcast_survey_start(&self, nonce: u32, ledger_num: u32) -> bool {
        let start = TimeSlicedSurveyStartCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };
        let start_bytes = match start.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey start message");
                return false;
            }
        };
        let signature = self.sign_survey_message(&start_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStartCollectingMessage {
            signature,
            start_collecting: start.clone(),
        };

        let sent = self
            .broadcast_survey_message(StellarMessage::TimeSlicedSurveyStartCollecting(signed))
            .await;
        if sent {
            self.survey_results
                .write()
                .await
                .entry(nonce)
                .or_insert_with(HashMap::new);
            self.start_local_survey_collecting(&start).await;
        }
        sent
    }

    async fn broadcast_survey_stop(&self, nonce: u32, ledger_num: u32) {
        let stop = TimeSlicedSurveyStopCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };

        let stop_bytes = match stop.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey stop message");
                return;
            }
        };

        let signature = self.sign_survey_message(&stop_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStopCollectingMessage {
            signature,
            stop_collecting: stop.clone(),
        };

        let _ = self
            .broadcast_survey_message(StellarMessage::TimeSlicedSurveyStopCollecting(signed))
            .await;
        self.stop_local_survey_collecting(&stop).await;
    }

    async fn broadcast_survey_message(&self, message: StellarMessage) -> bool {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return false,
        };

        match overlay.broadcast(message).await {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to broadcast survey message");
                false
            }
        }
    }

    async fn ensure_survey_secret(&self, nonce: u32) -> CurveSecretKey {
        if let Some(secret) = self.survey_secrets.read().await.get(&nonce).copied() {
            return CurveSecretKey::from(secret);
        }
        let secret = CurveSecretKey::random_from_rng(rand::rngs::OsRng);
        self.survey_secrets
            .write()
            .await
            .insert(nonce, secret.to_bytes());
        secret
    }

    /// Run catchup to a target ledger.
    ///
    /// This downloads history from archives and applies it to bring the
    /// node up to date with the network.
    pub async fn catchup(&self, target: CatchupTarget) -> anyhow::Result<CatchupResult> {
        self.set_state(AppState::CatchingUp).await;

        let progress = Arc::new(CatchupProgress::new());

        tracing::info!(?target, "Starting catchup");

        // Determine target ledger
        let target_ledger = match target {
            CatchupTarget::Current => {
                // Query archive for latest checkpoint
                self.get_latest_checkpoint().await?
            }
            CatchupTarget::Ledger(seq) => seq,
            CatchupTarget::Checkpoint(checkpoint) => checkpoint * 64,
        };

        progress.set_target(target_ledger);

        tracing::info!(target_ledger = target_ledger, "Target ledger determined");

        // Run catchup work
        let output = self.run_catchup_work(target_ledger, progress.clone()).await?;

        // Initialize ledger manager with catchup results.
        // This validates that the bucket list hash matches the ledger header.
        if self.ledger_manager.is_initialized() {
            self.ledger_manager
                .reinitialize_from_buckets(
                    output.bucket_list,
                    output.hot_archive_bucket_list,
                    output.header,
                )
                .map_err(|e| anyhow::anyhow!("Failed to reinitialize ledger manager: {}", e))?;
        } else {
            self.ledger_manager
                .initialize_from_buckets(
                    output.bucket_list,
                    output.hot_archive_bucket_list,
                    output.header,
                )
                .map_err(|e| anyhow::anyhow!("Failed to initialize ledger manager: {}", e))?;
        }

        tracing::info!(
            ledger_seq = output.result.ledger_seq,
            "Ledger manager initialized from catchup"
        );

        progress.set_phase(crate::logging::CatchupPhase::Complete);
        progress.summary();

        Ok(CatchupResult {
            ledger_seq: output.result.ledger_seq,
            ledger_hash: output.result.ledger_hash,
            buckets_applied: output.result.buckets_downloaded,
            ledgers_replayed: output.result.ledgers_applied,
        })
    }

    /// Get the latest checkpoint from history archives.
    async fn get_latest_checkpoint(&self) -> anyhow::Result<u32> {
        tracing::info!("Querying history archives for latest checkpoint");

        // Try each configured archive to get the current ledger
        for archive_config in &self.config.history.archives {
            match HistoryArchive::new(&archive_config.url) {
                Ok(archive) => {
                    match archive.get_current_ledger().await {
                        Ok(ledger) => {
                            tracing::info!(
                                ledger,
                                archive = %archive_config.url,
                                "Got current ledger from archive"
                            );
                            // Round down to the latest completed checkpoint
                            let checkpoint = stellar_core_history::checkpoint::latest_checkpoint_before_or_at(ledger)
                                .ok_or_else(|| anyhow::anyhow!("No checkpoint available for ledger {}", ledger))?;
                            return Ok(checkpoint);
                        }
                        Err(e) => {
                            tracing::warn!(
                                archive = %archive_config.url,
                                error = %e,
                                "Failed to get current ledger from archive"
                            );
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        archive = %archive_config.url,
                        error = %e,
                        "Failed to create archive client"
                    );
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!("Failed to get current ledger from any archive"))
    }

    /// Run the catchup work using the real CatchupManager.
    async fn run_catchup_work(
        &self,
        target_ledger: u32,
        progress: Arc<CatchupProgress>,
    ) -> anyhow::Result<CatchupOutput> {
        use crate::logging::CatchupPhase;

        // Phase 1: Create history archives from config
        progress.set_phase(CatchupPhase::DownloadingState);
        tracing::info!(target_ledger, "Downloading history archive state");

        let archives: Vec<HistoryArchive> = self.config.history.archives
            .iter()
            .filter(|a| a.get_enabled)
            .filter_map(|a| {
                match HistoryArchive::new(&a.url) {
                    Ok(archive) => Some(archive),
                    Err(e) => {
                        tracing::warn!(url = %a.url, error = %e, "Failed to create archive");
                        None
                    }
                }
            })
            .collect();

        if archives.is_empty() {
            return Err(anyhow::anyhow!("No history archives available"));
        }

        tracing::info!(archive_count = archives.len(), "Created history archive clients");

        let checkpoint_seq = latest_checkpoint_before_or_at(target_ledger).ok_or_else(|| {
            anyhow::anyhow!("target ledger {} is before first checkpoint", target_ledger)
        })?;

        let archives_arc: Vec<Arc<HistoryArchive>> = archives.into_iter().map(Arc::new).collect();
        let checkpoint_data = if let Some(primary) = archives_arc.first() {
            match self
                .download_checkpoint_with_historywork(Arc::clone(primary), checkpoint_seq)
                .await
            {
                Ok(data) => {
                    tracing::info!(checkpoint_seq, "Using historywork for checkpoint downloads");
                    Some(data)
                }
                Err(err) => {
                    tracing::warn!(
                        checkpoint_seq,
                        error = %err,
                        "Historywork download failed, falling back to direct catchup"
                    );
                    None
                }
            }
        } else {
            None
        };

        // Create CatchupManager using Arc references
        let mut catchup_manager = CatchupManager::new_with_arcs(
            archives_arc,
            self.bucket_manager.clone(),
            Arc::new(self.db.clone()),
        );

        // Run catchup
        progress.set_phase(CatchupPhase::DownloadingBuckets);
        let output = match checkpoint_data {
            Some(data) => catchup_manager
                .catchup_to_ledger_with_checkpoint_data(target_ledger, data)
                .await,
            None => catchup_manager.catchup_to_ledger(target_ledger).await,
        }
        .map_err(|e| anyhow::anyhow!("Catchup failed: {}", e))?;

        // Update progress with bucket count
        progress.set_total_buckets(output.result.buckets_downloaded);
        for _ in 0..output.result.buckets_downloaded {
            progress.bucket_downloaded();
        }

        // Update ledger progress
        progress.set_phase(CatchupPhase::ReplayingLedgers);
        for _ in 0..output.result.ledgers_applied {
            progress.ledger_applied();
        }

        // Verify
        progress.set_phase(CatchupPhase::Verifying);
        tracing::info!("Verifying catchup state");

        Ok(output)
    }

    async fn download_checkpoint_with_historywork(
        &self,
        archive: Arc<HistoryArchive>,
        checkpoint_seq: u32,
    ) -> anyhow::Result<CheckpointData> {
        let state = Arc::new(tokio::sync::Mutex::new(HistoryWorkState::default()));
        let mut scheduler = WorkScheduler::new(WorkSchedulerConfig {
            max_concurrency: 4,
            retry_delay: Duration::from_millis(200),
            event_tx: None,
        });
        let builder = HistoryWorkBuilder::new(archive, checkpoint_seq, Arc::clone(&state));
        let ids = builder.register(&mut scheduler);

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let state_monitor = Arc::clone(&state);
        let monitor = tokio::spawn(async move {
            let mut last_stage = None;
            let mut last_message = String::new();
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let progress = get_progress(&state_monitor).await;
                        if progress.stage != last_stage || progress.message != last_message {
                            last_stage = progress.stage.clone();
                            last_message = progress.message.clone();
                            if let Some(stage) = progress.stage {
                                tracing::info!(stage = ?stage, message = %progress.message, "Historywork progress");
                            }
                        }
                    }
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        scheduler.run_until_done().await;

        let _ = stop_tx.send(true);
        let _ = monitor.await;

        let work_ids = [
            ids.has,
            ids.buckets,
            ids.headers,
            ids.transactions,
            ids.tx_results,
            ids.scp_history,
        ];
        for id in work_ids {
            match scheduler.state(id) {
                Some(WorkState::Success) => {}
                state => {
                    return Err(anyhow::anyhow!(
                        "historywork failed; work {} ended in {:?}",
                        id,
                        state
                    ));
                }
            }
        }

        Ok(build_checkpoint_data(&state).await?)
    }

    /// Run the main event loop.
    ///
    /// This starts all subsystems and runs until shutdown is signaled.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("Starting main event loop");

        // First, check if we need to catch up
        let current_ledger = self.get_current_ledger().await?;

        if current_ledger == 0 {
            tracing::info!("No ledger state, running catchup first");
            let result = self.catchup(CatchupTarget::Current).await?;
            *self.current_ledger.write().await = result.ledger_seq;
        } else {
            // Ledger manager was already initialized (e.g., catchup ran before run())
            *self.current_ledger.write().await = current_ledger;
        }

        // Bootstrap herder with current ledger
        let ledger_seq = *self.current_ledger.read().await;
        *self.last_processed_slot.write().await = ledger_seq as u64;
        self.herder.start_syncing();
        self.herder.bootstrap(ledger_seq);
        tracing::info!(ledger_seq, "Herder bootstrapped");

        // Start overlay network
        self.start_overlay().await?;

        // Wait a short time for initial peer connections, then request SCP state
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.request_scp_state_from_peers().await;

        // Set state based on validator mode
        if self.is_validator {
            self.set_state(AppState::Validating).await;
        } else {
            self.set_state(AppState::Synced).await;
        }

        // Get message receiver from overlay
        let message_rx = {
            let overlay = self.overlay.lock().await;
            overlay.as_ref().map(|o| o.subscribe())
        };

        let mut message_rx = match message_rx {
            Some(rx) => rx,
            None => {
                tracing::warn!("Overlay not started, running without network");
                // Create a dummy receiver that never receives
                let (tx, rx) = tokio::sync::broadcast::channel::<OverlayMessage>(1);
                drop(tx);
                rx
            }
        };
        let (overlay_tx, mut overlay_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match message_rx.recv().await {
                    Ok(overlay_msg) => {
                        if overlay_tx.send(overlay_msg).is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "Overlay receiver lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        // Main run loop
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut consensus_interval = tokio::time::interval(Duration::from_secs(5));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(30));
        let mut tx_advert_interval = tokio::time::interval(self.flood_advert_period());
        let mut tx_demand_interval = tokio::time::interval(self.flood_demand_period());
        let mut survey_interval = tokio::time::interval(Duration::from_secs(1));
        let mut survey_phase_interval = tokio::time::interval(Duration::from_secs(5));
        let mut survey_request_interval = tokio::time::interval(Duration::from_secs(1));
        let mut scp_timeout_interval = tokio::time::interval(Duration::from_millis(500));
        let mut ping_interval = tokio::time::interval(Duration::from_secs(5));
        let mut peer_maintenance_interval = tokio::time::interval(Duration::from_secs(10));
        let mut peer_refresh_interval = tokio::time::interval(Duration::from_secs(60));

        // Get mutable access to SCP envelope receiver
        let mut scp_rx = self.scp_envelope_rx.lock().await;

        tracing::info!("Entering main event loop");

        // Add a short heartbeat interval for debugging
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                // NOTE: Removed biased; to ensure timers get fair polling

                // Process overlay messages
                msg = overlay_rx.recv() => {
                    match msg {
                        Some(overlay_msg) => {
                            let msg_type = match &overlay_msg.message {
                                StellarMessage::ScpMessage(_) => "SCP",
                                StellarMessage::Transaction(_) => "TX",
                                StellarMessage::TxSet(_) => "TxSet",
                                StellarMessage::GeneralizedTxSet(_) => "GeneralizedTxSet",
                                StellarMessage::GetTxSet(_) => "GetTxSet",
                                StellarMessage::Hello(_) => "Hello",
                                StellarMessage::Peers(_) => "Peers",
                                _ => "Other",
                            };
                            tracing::debug!(msg_type, "Received overlay message");
                            self.handle_overlay_message(overlay_msg).await;
                        }
                        None => {
                            tracing::info!("Overlay message channel closed");
                            break;
                        }
                    }
                }

                // Broadcast outbound SCP envelopes
                envelope = scp_rx.recv() => {
                    if let Some(envelope) = envelope {
                        let slot = envelope.statement.slot_index;
                        let sample = {
                            let mut latency = self.scp_latency.write().await;
                            latency.record_self_sent(slot)
                        };
                        if let Some(ms) = sample {
                            let mut survey_data = self.survey_data.write().await;
                            survey_data.record_scp_first_to_self_latency(ms);
                        }
                        let msg = StellarMessage::ScpMessage(envelope);
                        let overlay = self.overlay.lock().await;
                        if let Some(ref overlay) = *overlay {
                            match overlay.broadcast(msg).await {
                                Ok(count) => {
                                    tracing::debug!(slot, peers = count, "Broadcast SCP envelope");
                                }
                                Err(e) => {
                                    tracing::warn!(slot, error = %e, "Failed to broadcast SCP envelope");
                                }
                            }
                        }
                    }
                }

                // Consensus timer - trigger ledger close for validators and process externalized
                _ = consensus_interval.tick() => {
                    // Check for externalized slots to process
                    self.process_externalized_slots().await;

                    // Request any pending tx sets we need
                    self.request_pending_tx_sets().await;

                    // For validators, try to trigger next round
                    if self.is_validator {
                        self.try_trigger_consensus().await;
                    }
                }

                // Stats logging
                _ = stats_interval.tick() => {
                    self.log_stats().await;
                }

                // Batched tx advert flush
                _ = tx_advert_interval.tick() => {
                    self.flush_tx_adverts().await;
                }

                // Demand missing transactions from peers
                _ = tx_demand_interval.tick() => {
                    self.run_tx_demands().await;
                }

                // Survey scheduler
                _ = survey_interval.tick() => {
                    if self.config.overlay.auto_survey {
                        self.advance_survey_scheduler().await;
                    }
                }

                // Survey reporting request top-off
                _ = survey_request_interval.tick() => {
                    self.top_off_survey_requests().await;
                }

                // Survey phase maintenance
                _ = survey_phase_interval.tick() => {
                    self.update_survey_phase().await;
                }

                // SCP nomination/ballot timeouts
                _ = scp_timeout_interval.tick() => {
                    self.check_scp_timeouts().await;
                }

                // Ping peers for latency measurements
                _ = ping_interval.tick() => {
                    self.send_peer_pings().await;
                }

                // Peer maintenance - reconnect if peer count drops too low
                _ = peer_maintenance_interval.tick() => {
                    self.maintain_peers().await;
                }

                // Refresh known peers from config + SQLite cache
                _ = peer_refresh_interval.tick() => {
                    if let Some(overlay) = self.overlay.lock().await.as_ref() {
                        let _ = self.refresh_known_peers(overlay);
                    }
                }

                // Shutdown signal (lowest priority)
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                // Heartbeat for debugging
                _ = heartbeat_interval.tick() => {
                    let tracking_slot = self.herder.tracking_slot();
                    let ledger = *self.current_ledger.read().await;
                    let latest_ext = self.herder.latest_externalized_slot().unwrap_or(0);
                    let overlay = self.overlay.lock().await;
                    let peers = overlay.as_ref().map(|o| o.peer_count()).unwrap_or(0);
                    drop(overlay);
                    tracing::info!(
                        tracking_slot,
                        ledger,
                        latest_ext,
                        peers,
                        "Heartbeat"
                    );

                    // If externalization stalls, ask peers for fresh SCP state.
                    if peers > 0 && self.herder.state().can_receive_scp() {
                        let now = Instant::now();
                        let last_ext = *self.last_externalized_at.read().await;
                        let last_request = *self.last_scp_state_request_at.read().await;
                        if now.duration_since(last_ext) > Duration::from_secs(20)
                            && now.duration_since(last_request) > Duration::from_secs(10)
                        {
                            tracing::warn!(
                                latest_ext,
                                tracking_slot,
                                "SCP externalization stalled; requesting SCP state"
                            );
                            *self.last_scp_state_request_at.write().await = now;
                            self.request_scp_state_from_peers().await;
                        }
                    }
                }
            }
        }

        self.set_state(AppState::ShuttingDown).await;
        self.shutdown_internal().await?;

        Ok(())
    }

    /// Start the overlay network.
    async fn start_overlay(&self) -> anyhow::Result<()> {
        tracing::info!("Starting overlay network");

        self.store_config_peers();

        // Create local node info
        let local_node = if self.config.network.passphrase.contains("Test") {
            LocalNode::new_testnet(self.keypair.clone())
        } else {
            LocalNode::new_mainnet(self.keypair.clone())
        };

        // Start with testnet or mainnet defaults
        let mut overlay_config = if self.config.network.passphrase.contains("Test") {
            OverlayManagerConfig::testnet()
        } else {
            OverlayManagerConfig::mainnet()
        };

        // Override with app config settings
        overlay_config.max_inbound_peers = self.config.overlay.max_inbound_peers;
        overlay_config.max_outbound_peers = self.config.overlay.max_outbound_peers;
        overlay_config.target_outbound_peers = self.config.overlay.target_outbound_peers;
        overlay_config.listen_port = self.config.overlay.peer_port;
        overlay_config.listen_enabled = self.is_validator; // Validators listen for connections
        overlay_config.network_passphrase = self.config.network.passphrase.clone();

        // Convert known peers from strings to PeerAddress
        if !self.config.overlay.known_peers.is_empty() {
            overlay_config.known_peers = self
                .config
                .overlay
                .known_peers
                .iter()
                .filter_map(|s| Self::parse_peer_address(s))
                .collect();
        }

        if let Ok(persisted) = self.load_persisted_peers() {
            for addr in persisted {
                if !overlay_config.known_peers.contains(&addr) {
                    overlay_config.known_peers.push(addr);
                }
            }
        }

        // Convert preferred peers
        if !self.config.overlay.preferred_peers.is_empty() {
            overlay_config.preferred_peers = self.config.overlay.preferred_peers
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.split(':').collect();
                    match parts.len() {
                        1 => Some(PeerAddress::new(parts[0], 11625)),
                        2 => parts[1].parse().ok().map(|port| PeerAddress::new(parts[0], port)),
                        _ => None,
                    }
                })
                .collect();
        }

        let (peer_event_tx, mut peer_event_rx) = mpsc::channel(1024);
        overlay_config.peer_event_tx = Some(peer_event_tx);

        let db = self.db.clone();
        tokio::spawn(async move {
            while let Some(event) = peer_event_rx.recv().await {
                update_peer_record(&db, event);
            }
        });

        tracing::info!(
            listen_port = overlay_config.listen_port,
            known_peers = overlay_config.known_peers.len(),
            listen_enabled = overlay_config.listen_enabled,
            "Creating overlay with config"
        );

        let mut overlay = OverlayManager::new(overlay_config, local_node)?;
        if let Ok(bans) = self.db.load_bans() {
            for ban in bans {
                if let Some(peer_id) = Self::strkey_to_peer_id(&ban) {
                    overlay.ban_peer(peer_id).await;
                } else {
                    tracing::warn!(node = %ban, "Ignoring invalid ban entry");
                }
            }
        }
        overlay.start().await?;

        let peer_count = overlay.peer_count();
        tracing::info!(peer_count, "Overlay network started");

        *self.overlay.lock().await = Some(overlay);
        Ok(())
    }

    /// Handle a message from the overlay network.
    async fn handle_overlay_message(&self, msg: OverlayMessage) {
        match msg.message {
            StellarMessage::ScpMessage(envelope) => {
                let slot = envelope.statement.slot_index;
                let tracking = self.herder.tracking_slot();

                let sample = {
                    let mut latency = self.scp_latency.write().await;
                    latency.record_first_seen(slot);
                    latency.record_other_after_self(slot)
                };
                if let Some(ms) = sample {
                    let mut survey_data = self.survey_data.write().await;
                    survey_data.record_scp_self_to_other_latency(ms);
                }

                // Check if this is an EXTERNALIZE message so we can request the tx set
                let is_externalize = matches!(
                    &envelope.statement.pledges,
                    stellar_xdr::curr::ScpStatementPledges::Externalize(_)
                );
                let tx_set_hash = match &envelope.statement.pledges {
                    stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
                        match StellarValue::from_xdr(&ext.commit.value.0, stellar_xdr::curr::Limits::none()) {
                            Ok(stellar_value) => Some(Hash256::from_bytes(stellar_value.tx_set_hash.0)),
                            Err(err) => {
                                tracing::warn!(slot, error = %err, "Failed to parse externalized StellarValue");
                                None
                            }
                        }
                    }
                    _ => None,
                };

                if let Some(hash) = Self::scp_quorum_set_hash(&envelope.statement) {
                    let hash256 = stellar_core_common::Hash256::from_bytes(hash.0);
                    if !self.herder.has_quorum_set_hash(&hash256) {
                        if self.herder.request_quorum_set(hash256) {
                            let peer = msg.from_peer.clone();
                            let overlay = self.overlay.lock().await;
                            if let Some(ref overlay) = *overlay {
                                let request = StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(hash.0));
                                if let Err(e) = overlay.send_to(&peer, request).await {
                                    tracing::debug!(peer = ?peer, error = %e, "Failed to request quorum set");
                                }
                            }
                        }
                    }
                }

                match self.herder.receive_scp_envelope(envelope) {
                    EnvelopeState::Valid => {
                        tracing::info!(slot, tracking, "Processed SCP envelope (valid)");

                        // For EXTERNALIZE messages, immediately try to close ledger and request tx set
                        if is_externalize {
                            if let Some(tx_set_hash) = tx_set_hash {
                                self.herder.scp_driver().request_tx_set(tx_set_hash, slot);
                                if self.herder.needs_tx_set(&tx_set_hash) {
                                    let peer = msg.from_peer.clone();
                                    let overlay = self.overlay.lock().await;
                                    if let Some(ref overlay) = *overlay {
                                        let request = StellarMessage::GetTxSet(
                                            stellar_xdr::curr::Uint256(tx_set_hash.0),
                                        );
                                        if let Err(e) = overlay.send_to(&peer, request).await {
                                            tracing::debug!(
                                                peer = ?peer,
                                                error = %e,
                                                "Failed to request tx set from externalize peer"
                                            );
                                        }
                                    }
                                }
                            }
                            // First, process externalized slots to register pending tx set requests
                            self.process_externalized_slots().await;
                            // Then, immediately request any pending tx sets
                            self.request_pending_tx_sets().await;
                        }
                    }
                    EnvelopeState::Pending => {
                        tracing::info!(slot, tracking, "SCP envelope buffered for future slot");
                    }
                    EnvelopeState::Duplicate => {
                        // Expected, ignore silently
                    }
                    EnvelopeState::TooOld => {
                        tracing::info!(slot, tracking, "SCP envelope too old");
                    }
                    EnvelopeState::Invalid => {
                        tracing::warn!(slot, peer = ?msg.from_peer, "Invalid SCP envelope");
                    }
                    EnvelopeState::InvalidSignature => {
                        tracing::warn!(slot, peer = ?msg.from_peer, "SCP envelope with invalid signature");
                    }
                }
            }

            StellarMessage::Transaction(tx_env) => {
                let tx_hash = self.tx_hash(&tx_env);
                match self.herder.receive_transaction(tx_env.clone()) {
                    stellar_core_herder::TxQueueResult::Added => {
                        tracing::debug!(peer = ?msg.from_peer, "Transaction added to queue");
                        if let Some(hash) = tx_hash {
                            self.record_tx_pull_latency(hash, &msg.from_peer).await;
                        }
                        self.enqueue_tx_advert(&tx_env).await;
                    }
                    stellar_core_herder::TxQueueResult::Duplicate => {
                        if let Some(hash) = tx_hash {
                            self.record_tx_pull_latency(hash, &msg.from_peer).await;
                        }
                        // Expected, ignore
                    }
                    stellar_core_herder::TxQueueResult::QueueFull => {
                        tracing::warn!("Transaction queue full, dropping transaction");
                    }
                    stellar_core_herder::TxQueueResult::FeeTooLow => {
                        tracing::debug!("Transaction fee too low, rejected");
                    }
                    stellar_core_herder::TxQueueResult::Invalid => {
                        tracing::debug!("Invalid transaction rejected");
                    }
                }
            }

            StellarMessage::FloodAdvert(advert) => {
                self.handle_flood_advert(&msg.from_peer, advert).await;
            }

            StellarMessage::FloodDemand(demand) => {
                self.handle_flood_demand(&msg.from_peer, demand).await;
            }

            StellarMessage::DontHave(dont_have) => {
                let is_tx_set = matches!(
                    dont_have.type_,
                    stellar_xdr::curr::MessageType::TxSet
                        | stellar_xdr::curr::MessageType::GeneralizedTxSet
                );
                let is_ping = matches!(dont_have.type_, stellar_xdr::curr::MessageType::ScpQuorumset);
                if is_tx_set {
                    tracing::info!(
                        peer = ?msg.from_peer,
                        hash = hex::encode(dont_have.req_hash.0),
                        "Peer reported DontHave for TxSet"
                    );
                    let hash = Hash256::from_bytes(dont_have.req_hash.0);
                    let mut map = self.tx_set_dont_have.write().await;
                    map.entry(hash).or_default().insert(msg.from_peer.clone());
                    if self.herder.needs_tx_set(&hash) {
                        let mut last_request = self.tx_set_last_request.write().await;
                        last_request.remove(&hash);
                        drop(last_request);
                        drop(map);
                        self.request_pending_tx_sets().await;
                    }
                }
                if is_ping {
                    self.process_ping_response(&msg.from_peer, dont_have.req_hash.0)
                        .await;
                }
            }

            StellarMessage::GetScpState(ledger_seq) => {
                tracing::debug!(ledger_seq, peer = ?msg.from_peer, "Peer requested SCP state");
                self.send_scp_state(&msg.from_peer, ledger_seq).await;
            }

            StellarMessage::GetScpQuorumset(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = ?msg.from_peer, "Peer requested quorum set");
                self.send_quorum_set(&msg.from_peer, hash).await;
            }

            StellarMessage::ScpQuorumset(quorum_set) => {
                tracing::debug!(peer = ?msg.from_peer, "Received quorum set");
                let hash = stellar_core_scp::hash_quorum_set(&quorum_set);
                self.process_ping_response(&msg.from_peer, hash.0).await;
                self.handle_quorum_set(&msg.from_peer, quorum_set).await;
            }

            StellarMessage::TimeSlicedSurveyStartCollecting(start) => {
                self.handle_survey_start_collecting(&msg.from_peer, start)
                    .await;
            }

            StellarMessage::TimeSlicedSurveyStopCollecting(stop) => {
                self.handle_survey_stop_collecting(&msg.from_peer, stop)
                    .await;
            }

            StellarMessage::TimeSlicedSurveyRequest(request) => {
                self.handle_survey_request(&msg.from_peer, request).await;
            }

            StellarMessage::TimeSlicedSurveyResponse(response) => {
                self.handle_survey_response(&msg.from_peer, response)
                    .await;
            }

            StellarMessage::Peers(peer_list) => {
                tracing::debug!(count = peer_list.len(), peer = ?msg.from_peer, "Received peer list");
                self.process_peer_list(peer_list).await;
            }

            StellarMessage::TxSet(tx_set) => {
                tracing::info!(peer = ?msg.from_peer, "Received TxSet");
                self.handle_tx_set(tx_set).await;
            }

            StellarMessage::GeneralizedTxSet(gen_tx_set) => {
                tracing::info!(peer = ?msg.from_peer, "Received GeneralizedTxSet");
                self.handle_generalized_tx_set(gen_tx_set).await;
            }

            StellarMessage::GetTxSet(hash) => {
                tracing::debug!(hash = hex::encode(hash.0), peer = ?msg.from_peer, "Peer requested TxSet");
                self.send_tx_set(&msg.from_peer, &hash.0).await;
            }

            _ => {
                // Other message types (Hello, Auth, etc.) are handled by overlay
                tracing::trace!(msg_type = ?std::mem::discriminant(&msg.message), "Ignoring message type");
            }
        }
    }

    /// Try to close a specific slot directly when we receive its tx set.
    /// This feeds the buffered ledger pipeline and attempts sequential apply.
    async fn try_close_slot_directly(&self, slot: u64) {
        tracing::info!(slot, "Attempting to close specific slot directly");
        let close_info = match self.herder.check_ledger_close(slot) {
            Some(info) => info,
            None => {
                tracing::debug!(slot, "No ledger close info for slot");
                return;
            }
        };

        self.update_buffered_tx_set(slot as u32, close_info.tx_set).await;
        self.try_apply_buffered_ledgers().await;
    }

    /// Process any externalized slots that need ledger close.
    async fn process_externalized_slots(&self) {
        // Get the latest externalized slot
        let latest_externalized = match self.herder.latest_externalized_slot() {
            Some(slot) => slot,
            None => {
                tracing::debug!("No externalized slots yet");
                return;
            }
        };

        tracing::debug!(latest_externalized, "Processing externalized slots");

        // Check if we've already processed this slot
        let last_processed = *self.last_processed_slot.read().await;
        if latest_externalized <= last_processed {
            tracing::debug!(latest_externalized, last_processed, "Already processed");
            return;
        }

        tracing::debug!(latest_externalized, last_processed, "Need to process");

        let prev_latest = self
            .last_externalized_slot
            .swap(latest_externalized, Ordering::Relaxed);
        if latest_externalized != prev_latest {
            *self.last_externalized_at.write().await = Instant::now();
        }

        let mut missing_tx_set = false;
        let mut buffered_count = 0usize;
        let mut advance_to = last_processed;
        {
            let mut buffer = self.syncing_ledgers.write().await;
            for slot in (last_processed + 1)..=latest_externalized {
                if let Some(info) = self.herder.check_ledger_close(slot) {
                    if info.tx_set.is_none() {
                        missing_tx_set = true;
                    }
                    buffer.entry(info.slot as u32).or_insert(info);
                    buffered_count += 1;
                    if slot == advance_to + 1 {
                        advance_to = slot;
                    }
                }
            }
        }

        *self.last_processed_slot.write().await = advance_to;

        if missing_tx_set {
            self.request_pending_tx_sets().await;
        }
        self.try_apply_buffered_ledgers().await;
        self.maybe_start_buffered_catchup().await;
        if buffered_count == 0 {
            self.maybe_start_externalized_catchup(latest_externalized)
                .await;
        }
    }

    fn first_ledger_in_checkpoint(ledger: u32) -> u32 {
        (ledger / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY
    }

    fn is_first_ledger_in_checkpoint(ledger: u32) -> bool {
        ledger % CHECKPOINT_FREQUENCY == 0
    }

    fn trim_syncing_ledgers(
        buffer: &mut BTreeMap<u32, stellar_core_herder::LedgerCloseInfo>,
        current_ledger: u32,
    ) {
        let min_keep = current_ledger.saturating_add(1);
        buffer.retain(|seq, _| *seq >= min_keep);
        if buffer.is_empty() {
            return;
        }

        let last_buffered = *buffer.keys().next_back().unwrap();
        let trim_before = if Self::is_first_ledger_in_checkpoint(last_buffered) {
            if last_buffered == 0 {
                return;
            }
            let prev = last_buffered - 1;
            Self::first_ledger_in_checkpoint(prev)
        } else {
            Self::first_ledger_in_checkpoint(last_buffered)
        };

        buffer.retain(|seq, _| *seq >= trim_before);
    }

    async fn update_buffered_tx_set(
        &self,
        slot: u32,
        tx_set: Option<stellar_core_herder::TransactionSet>,
    ) {
        let Some(tx_set) = tx_set else {
            return;
        };
        let mut buffer = self.syncing_ledgers.write().await;
        if let Some(entry) = buffer.get_mut(&slot) {
            if tx_set.hash != entry.tx_set_hash {
                tracing::warn!(
                    slot,
                    expected = %entry.tx_set_hash.to_hex(),
                    found = %tx_set.hash.to_hex(),
                    "Buffered tx set hash mismatch (dropping)"
                );
                return;
            }
            entry.tx_set = Some(tx_set);
            tracing::info!(slot, "Buffered tx set attached");
        } else {
            tracing::debug!(slot, "Received tx set for unbuffered slot");
        }
    }

    async fn attach_tx_set_by_hash(
        &self,
        tx_set: &stellar_core_herder::TransactionSet,
    ) -> bool {
        let mut buffer = self.syncing_ledgers.write().await;
        for (slot, entry) in buffer.iter_mut() {
            if entry.tx_set.is_none() && entry.tx_set_hash == tx_set.hash {
                entry.tx_set = Some(tx_set.clone());
                tracing::info!(slot, hash = %tx_set.hash, "Attached tx set to buffered slot");
                return true;
            }
        }
        false
    }

    async fn buffer_externalized_tx_set(
        &self,
        tx_set: &stellar_core_herder::TransactionSet,
    ) -> bool {
        let Some(slot) = self
            .herder
            .find_externalized_slot_by_tx_set_hash(&tx_set.hash)
        else {
            return false;
        };
        let Some(info) = self.herder.check_ledger_close(slot) else {
            return false;
        };
        {
            let mut buffer = self.syncing_ledgers.write().await;
            buffer.entry(info.slot as u32).or_insert(info);
        }
        self.update_buffered_tx_set(slot as u32, Some(tx_set.clone()))
            .await;
        tracing::info!(
            slot,
            hash = %tx_set.hash,
            "Buffered tx set after externalized lookup"
        );
        true
    }

    async fn try_apply_buffered_ledgers(&self) {
        loop {
            let current_ledger = match self.get_current_ledger().await {
                Ok(seq) => seq,
                Err(_) => return,
            };
            let next_seq = current_ledger.saturating_add(1);

            let close_info = {
                let mut buffer = self.syncing_ledgers.write().await;
                Self::trim_syncing_ledgers(&mut buffer, current_ledger);
                match buffer.get(&next_seq) {
                    Some(info) if info.tx_set.is_some() => info.clone(),
                    Some(_) => return,
                    None => return,
                }
            };

            let tx_set = close_info.tx_set.clone().expect("tx set present");
            if tx_set.hash != close_info.tx_set_hash {
                tracing::error!(
                    ledger_seq = next_seq,
                    expected = %close_info.tx_set_hash.to_hex(),
                    found = %tx_set.hash.to_hex(),
                    "Buffered tx set hash mismatch"
                );
                let mut buffer = self.syncing_ledgers.write().await;
                if let Some(entry) = buffer.get_mut(&next_seq) {
                    entry.tx_set = None;
                }
                return;
            }
            tracing::info!(
                ledger_seq = next_seq,
                tx_count = tx_set.transactions.len(),
                close_time = close_info.close_time,
                "Applying buffered ledger"
            );

            match HerderCallback::close_ledger(
                self,
                next_seq,
                tx_set,
                close_info.close_time,
                close_info.upgrades.clone(),
            )
            .await
            {
                Ok(hash) => {
                    tracing::info!(
                        ledger_seq = next_seq,
                        hash = %hash.to_hex(),
                        "Applied buffered ledger"
                    );
                    {
                        let mut buffer = self.syncing_ledgers.write().await;
                        buffer.remove(&next_seq);
                    }
                    *self.current_ledger.write().await = next_seq;
                    *self.last_processed_slot.write().await = next_seq as u64;
                    self.clear_tx_advert_history(next_seq).await;
                }
                Err(e) => {
                    tracing::error!(
                        ledger_seq = next_seq,
                        error = %e,
                        "Failed to apply buffered ledger"
                    );
                    return;
                }
            }
        }
    }

    async fn maybe_start_buffered_catchup(&self) {
        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return,
        };

        let (first_buffered, last_buffered) = {
            let mut buffer = self.syncing_ledgers.write().await;
            Self::trim_syncing_ledgers(&mut buffer, current_ledger);
            match (buffer.keys().next().copied(), buffer.keys().next_back().copied()) {
                (Some(first), Some(last)) => (first, last),
                _ => return,
            }
        };

        tracing::info!(
            current_ledger,
            first_buffered,
            last_buffered,
            "Evaluating buffered catchup"
        );

        if first_buffered == current_ledger + 1 {
            tracing::info!(
                current_ledger,
                first_buffered,
                "Sequential ledger available; skipping buffered catchup"
            );
            return;
        }

        let gap = first_buffered.saturating_sub(current_ledger);
        let large_gap = gap >= CHECKPOINT_FREQUENCY && first_buffered > current_ledger + 1;
        let (required_first, trigger) = if large_gap {
            (0, 0)
        } else if Self::is_first_ledger_in_checkpoint(first_buffered) {
            let required_first = first_buffered;
            (required_first, required_first.saturating_add(1))
        } else {
            let required_first =
                Self::first_ledger_in_checkpoint(first_buffered).saturating_add(CHECKPOINT_FREQUENCY);
            (required_first, required_first.saturating_add(1))
        };
        let target = Self::buffered_catchup_target(current_ledger, first_buffered, last_buffered);
        if target.is_none() {
            if !large_gap {
                tracing::info!(
                    current_ledger,
                    first_buffered,
                    last_buffered,
                    required_first,
                    trigger,
                    "Waiting for buffered catchup trigger ledger"
                );
            }
            return;
        }
        let target = target.unwrap();
        if large_gap {
            tracing::info!(
                current_ledger,
                first_buffered,
                gap,
                "Buffered gap exceeds checkpoint; starting catchup"
            );
        }

        if self.catchup_in_progress.swap(true, Ordering::SeqCst) {
            tracing::info!("Buffered catchup already in progress");
            return;
        }

        if target == 0 || target <= current_ledger {
            self.catchup_in_progress.store(false, Ordering::SeqCst);
            return;
        }

        tracing::info!(
            current_ledger,
            target,
            first_buffered,
            last_buffered,
            "Starting buffered catchup"
        );

        let catchup_result = self.catchup(CatchupTarget::Ledger(target)).await;
        self.catchup_in_progress.store(false, Ordering::SeqCst);

        match catchup_result {
            Ok(result) => {
                *self.current_ledger.write().await = result.ledger_seq;
                *self.last_processed_slot.write().await = result.ledger_seq as u64;
                self.clear_tx_advert_history(result.ledger_seq).await;
                self.herder.bootstrap(result.ledger_seq);
                let cleaned = self
                    .herder
                    .cleanup_old_pending_tx_sets(result.ledger_seq as u64 + 1);
                if cleaned > 0 {
                    tracing::info!(cleaned, "Dropped stale pending tx set requests after catchup");
                }
                self.prune_tx_set_tracking().await;
                if self.is_validator {
                    self.set_state(AppState::Validating).await;
                } else {
                    self.set_state(AppState::Synced).await;
                }
                tracing::info!(
                    ledger_seq = result.ledger_seq,
                    "Buffered catchup complete"
                );
                self.try_apply_buffered_ledgers().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "Buffered catchup failed");
            }
        }
    }

    async fn maybe_start_externalized_catchup(&self, latest_externalized: u64) {
        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return,
        };
        if latest_externalized <= current_ledger as u64 {
            return;
        }
        let gap = latest_externalized.saturating_sub(current_ledger as u64);
        if gap <= TX_SET_REQUEST_WINDOW {
            return;
        }

        if self.catchup_in_progress.swap(true, Ordering::SeqCst) {
            tracing::info!("Externalized catchup already in progress");
            return;
        }

        let target = latest_externalized.saturating_sub(TX_SET_REQUEST_WINDOW) as u32;
        if target == 0 || target <= current_ledger {
            self.catchup_in_progress.store(false, Ordering::SeqCst);
            return;
        }

        tracing::info!(
            current_ledger,
            latest_externalized,
            target,
            "Starting externalized catchup"
        );

        let catchup_result = self.catchup(CatchupTarget::Ledger(target)).await;
        self.catchup_in_progress.store(false, Ordering::SeqCst);

        match catchup_result {
            Ok(result) => {
                *self.current_ledger.write().await = result.ledger_seq;
                *self.last_processed_slot.write().await = result.ledger_seq as u64;
                self.clear_tx_advert_history(result.ledger_seq).await;
                self.herder.bootstrap(result.ledger_seq);
                let cleaned = self
                    .herder
                    .cleanup_old_pending_tx_sets(result.ledger_seq as u64 + 1);
                if cleaned > 0 {
                    tracing::info!(cleaned, "Dropped stale pending tx set requests after catchup");
                }
                self.prune_tx_set_tracking().await;
                if self.is_validator {
                    self.set_state(AppState::Validating).await;
                } else {
                    self.set_state(AppState::Synced).await;
                }
                tracing::info!(
                    ledger_seq = result.ledger_seq,
                    "Externalized catchup complete"
                );
                self.try_apply_buffered_ledgers().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "Externalized catchup failed");
            }
        }
    }

    fn buffered_catchup_target(
        current_ledger: u32,
        first_buffered: u32,
        last_buffered: u32,
    ) -> Option<u32> {
        if first_buffered <= current_ledger + 1 {
            return None;
        }

        let gap = first_buffered.saturating_sub(current_ledger);
        if gap >= CHECKPOINT_FREQUENCY {
            let target = first_buffered.saturating_sub(1);
            return if target == 0 { None } else { Some(target) };
        }

        let required_first = if Self::is_first_ledger_in_checkpoint(first_buffered) {
            first_buffered
        } else {
            Self::first_ledger_in_checkpoint(first_buffered).saturating_add(CHECKPOINT_FREQUENCY)
        };
        let trigger = required_first.saturating_add(1);
        if last_buffered < trigger {
            return None;
        }
        let target = required_first.saturating_sub(1);
        if target == 0 {
            None
        } else {
            Some(target)
        }
    }

    async fn prune_tx_set_tracking(&self) {
        let pending: HashSet<Hash256> = self
            .herder
            .get_pending_tx_sets()
            .into_iter()
            .map(|(hash, _)| hash)
            .collect();
        let mut dont_have = self.tx_set_dont_have.write().await;
        dont_have.retain(|hash, _| pending.contains(hash));
        let mut last_request = self.tx_set_last_request.write().await;
        last_request.retain(|hash, _| pending.contains(hash));
    }

    fn tx_set_start_index(hash: &Hash256, peers_len: usize, peer_offset: usize) -> usize {
        if peers_len == 0 {
            return 0;
        }
        let start = u64::from_le_bytes(hash.0[0..8].try_into().unwrap_or([0; 8]));
        let base = (start as usize) % peers_len;
        (base + (peer_offset % peers_len)) % peers_len
    }

    /// Try to trigger consensus for the next ledger (validators only).
    async fn try_trigger_consensus(&self) {
        let current_slot = self.herder.tracking_slot();

        // Check if we should start a new round
        if self.herder.is_tracking() {
            let next_slot = (current_slot + 1) as u32;
            tracing::debug!(next_slot, "Checking if we should trigger consensus");

            // In a full implementation, we would:
            // 1. Check if enough time has passed since last close
            // 2. Build a transaction set from queued transactions
            // 3. Create a StellarValue with the tx set hash and close time
            // 4. Start SCP nomination with that value

            // For now, trigger the herder
            if let Err(e) = self.herder.trigger_next_ledger(next_slot).await {
                tracing::error!(error = %e, slot = next_slot, "Failed to trigger ledger");
            }
        }
    }

    /// Maintain peer connections - reconnect if peer count drops too low.
    async fn maintain_peers(&self) {
        let _ = self
            .db
            .remove_peers_with_failures(self.config.overlay.peer_max_failures);
        let overlay_guard = self.overlay.lock().await;
        let overlay = match overlay_guard.as_ref() {
            Some(o) => o,
            None => return,
        };

        let peer_count = overlay.peer_count();
        let min_peers = 3; // Minimum peers we want

        if peer_count < min_peers {
            tracing::info!(
                peer_count,
                min_peers,
                "Peer count below threshold, reconnecting to known peers"
            );

            // Try to reconnect to known peers (dynamic list first, then config).
            let mut candidates = overlay.known_peers();
            for addr_str in &self.config.overlay.known_peers {
                // Parse "host:port" or just "host" (default port 11625)
                let parts: Vec<&str> = addr_str.split(':').collect();
                let peer_addr = match parts.len() {
                    1 => Some(PeerAddress::new(parts[0], 11625)),
                    2 => parts[1].parse().ok().map(|port| PeerAddress::new(parts[0], port)),
                    _ => None,
                };
                if let Some(addr) = peer_addr {
                    if !candidates.contains(&addr) {
                        candidates.push(addr);
                    }
                }
            }

            let mut reconnected = false;
            let candidates = self.refresh_known_peers(overlay);
            for addr in candidates {
                if overlay.peer_count() >= self.config.overlay.target_outbound_peers {
                    break;
                }

                if let Err(e) = overlay.connect(&addr).await {
                    tracing::debug!(addr = %addr, error = %e, "Failed to reconnect to peer");
                } else {
                    reconnected = true;
                }
            }

            // Drop the lock explicitly before requesting SCP state
            // (which needs to acquire the lock again)
            let _ = overlay;
            drop(overlay_guard);

            if reconnected {
                // Give peers time to complete handshake
                tokio::time::sleep(Duration::from_millis(200)).await;
                self.request_scp_state_from_peers().await;
            }
        }
    }

    /// Request SCP state from all connected peers.
    async fn request_scp_state_from_peers(&self) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let peer_count = overlay.peer_count();
        if peer_count == 0 {
            tracing::debug!("No peers connected, cannot request SCP state");
            return;
        }

        // Request SCP state from a low watermark similar to upstream behavior.
        let ledger_seq = self.herder.get_min_ledger_seq_to_ask_peers();
        match overlay.request_scp_state(ledger_seq).await {
            Ok(count) => {
                tracing::info!(
                    ledger_seq,
                    peers_sent = count,
                    "Requested SCP state from peers"
                );
            }
            Err(e) => {
                tracing::warn!(
                    ledger_seq,
                    error = %e,
                    "Failed to request SCP state from peers"
                );
            }
        }
    }

    /// Send SCP state to a peer in response to GetScpState.
    async fn send_scp_state(&self, peer_id: &stellar_core_overlay::PeerId, from_ledger: u32) {
        let from_slot = from_ledger as u64;
        let (envelopes, quorum_set) = self.herder.get_scp_state(from_slot);

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        // Send our quorum set first if we have one configured
        if let Some(qs) = quorum_set {
            let msg = StellarMessage::ScpQuorumset(qs);
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send quorum set");
            }
        }

        // Send SCP envelopes for recent slots
        for envelope in envelopes {
            let msg = StellarMessage::ScpMessage(envelope);
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send SCP envelope");
                break; // Stop if we can't send
            }
        }

        tracing::debug!(peer = ?peer_id, from_ledger, "Sent SCP state response");
    }

    /// Respond to a GetScpQuorumset message.
    async fn send_quorum_set(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        requested_hash: stellar_xdr::curr::Uint256,
    ) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let req = requested_hash.0;
        if let Some(qs) = self.herder.get_quorum_set_by_hash(&req) {
            if let Err(e) = overlay.send_to(peer_id, StellarMessage::ScpQuorumset(qs)).await {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send quorum set");
            }
        } else {
            let msg = StellarMessage::DontHave(stellar_xdr::curr::DontHave {
                type_: stellar_xdr::curr::MessageType::ScpQuorumset,
                req_hash: requested_hash,
            });
            if let Err(e) = overlay.send_to(peer_id, msg).await {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send DontHave for quorum set");
            }
        }
    }

    /// Store a quorum set received from a peer.
    async fn handle_quorum_set(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        quorum_set: stellar_xdr::curr::ScpQuorumSet,
    ) {
        let node_id = stellar_xdr::curr::NodeId(peer_id.0.clone());
        let hash = stellar_core_scp::hash_quorum_set(&quorum_set);
        if let Err(err) = self.db.store_scp_quorum_set(&hash, self.ledger_manager.current_ledger_seq(), &quorum_set) {
            tracing::warn!(error = %err, "Failed to store quorum set");
        }
        self.herder.store_quorum_set(&node_id, quorum_set);
        self.herder.clear_quorum_set_request(&hash);
    }

    async fn handle_survey_start_collecting(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        signed: stellar_xdr::curr::SignedTimeSlicedSurveyStartCollectingMessage,
    ) {
        let message = &signed.start_collecting;
        let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey start message");
                return;
            }
        };
        if !self.surveyor_permitted(&message.surveyor_id) {
            return;
        }
        let local_ledger = self.survey_local_ledger().await;
        let survey_active = { self.survey_data.read().await.survey_is_active() };
        let limiter = self.survey_limiter.read().await;
        let is_valid = limiter.validate_start_collecting(
            message,
            local_ledger,
            survey_active,
            || self.verify_survey_signature(&message.surveyor_id, &message_bytes, &signed.signature),
        );
        if !is_valid {
            tracing::debug!(peer = ?peer_id, "Survey start rejected by limiter");
            return;
        }

        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);
        let state = self.state().await;
        let initially_out_of_sync = matches!(state, AppState::Initializing | AppState::CatchingUp);

        let mut survey_data = self.survey_data.write().await;
        if survey_data.start_collecting(
            message,
            &inbound,
            &outbound,
            lost_sync,
            added,
            dropped,
            initially_out_of_sync,
        ) {
            tracing::debug!(peer = ?peer_id, "Survey collection started");
        } else {
            tracing::debug!(peer = ?peer_id, "Survey collection already active");
        }
    }

    async fn handle_survey_stop_collecting(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        signed: stellar_xdr::curr::SignedTimeSlicedSurveyStopCollectingMessage,
    ) {
        let message = &signed.stop_collecting;
        let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey stop message");
                return;
            }
        };
        if !self.surveyor_permitted(&message.surveyor_id) {
            return;
        }
        let local_ledger = self.survey_local_ledger().await;
        let limiter = self.survey_limiter.read().await;
        let is_valid = limiter.validate_stop_collecting(
            message,
            local_ledger,
            || self.verify_survey_signature(&message.surveyor_id, &message_bytes, &signed.signature),
        );
        if !is_valid {
            tracing::debug!(peer = ?peer_id, "Survey stop rejected by limiter");
            return;
        }

        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);

        let mut survey_data = self.survey_data.write().await;
        if survey_data.stop_collecting(message, &inbound, &outbound, added, dropped, lost_sync) {
            tracing::debug!(peer = ?peer_id, "Survey collection stopped");
        } else {
            tracing::debug!(peer = ?peer_id, "Survey stop ignored (inactive or nonce mismatch)");
        }
    }

    async fn handle_survey_request(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        signed: stellar_xdr::curr::SignedTimeSlicedSurveyRequestMessage,
    ) {
        let request = &signed.request;
        let request_bytes = match request.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey request");
                return;
            }
        };

        if !self.surveyor_permitted(&request.request.surveyor_peer_id) {
            return;
        }

        let local_node_id = self.local_node_id();
        let local_ledger = self.survey_local_ledger().await;
        let nonce_is_reporting = self.survey_data.read().await.nonce_is_reporting(request.nonce);
        let mut limiter = self.survey_limiter.write().await;
        let is_valid = limiter.add_and_validate_request(
            &request.request,
            local_ledger,
            &local_node_id,
            || {
                nonce_is_reporting
                    && self.verify_survey_signature(
                        &request.request.surveyor_peer_id,
                        &request_bytes,
                        &signed.request_signature,
                    )
            },
        );
        if !is_valid {
            tracing::debug!(peer = ?peer_id, "Survey request rejected by limiter");
            return;
        }

        if request.request.surveyed_peer_id != local_node_id {
            let _ = self
                .broadcast_survey_message(StellarMessage::TimeSlicedSurveyRequest(signed))
                .await;
            return;
        }
        let response_body = match request.request.command_type {
            stellar_xdr::curr::SurveyMessageCommandType::TimeSlicedSurveyTopology => {
                let survey_data = self.survey_data.read().await;
                match survey_data.fill_survey_data(request) {
                    Some(body) => body,
                    None => {
                        tracing::debug!(peer = ?peer_id, "Survey request without reporting data");
                        return;
                    }
                }
            }
        };

        let response_body = SurveyResponseBody::SurveyTopologyResponseV2(response_body);
        let response_body_bytes = match response_body.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey response body");
                return;
            }
        };
        let encrypted_body_bytes = match stellar_core_crypto::seal_to_curve25519_public_key(
            &request.request.encryption_key.key,
            &response_body_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encrypt survey response body");
                return;
            }
        };
        let encrypted_body = match encrypted_body_bytes.try_into() {
            Ok(body) => EncryptedBody(body),
            Err(_) => {
                tracing::debug!(peer = ?peer_id, "Survey response body exceeded XDR limits");
                return;
            }
        };

        let response = SurveyResponseMessage {
            surveyor_peer_id: request.request.surveyor_peer_id.clone(),
            surveyed_peer_id: local_node_id,
            ledger_num: request.request.ledger_num,
            command_type: request.request.command_type,
            encrypted_body,
        };

        let response_message = TimeSlicedSurveyResponseMessage {
            response,
            nonce: request.nonce,
        };

        let response_bytes = match response_message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey response");
                return;
            }
        };

        let signature = self.sign_survey_message(&response_bytes);

        let signed_response = stellar_xdr::curr::SignedTimeSlicedSurveyResponseMessage {
            response_signature: signature,
            response: response_message,
        };

        let overlay = self.overlay.lock().await;
        if let Some(ref overlay) = *overlay {
            if let Err(e) = overlay
                .send_to(peer_id, StellarMessage::TimeSlicedSurveyResponse(signed_response))
                .await
            {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send survey response");
            }
        }
    }

    async fn handle_survey_response(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        signed: SignedTimeSlicedSurveyResponseMessage,
    ) {
        let response_message = signed.response.clone();
        let response_bytes = match response_message.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to encode survey response");
                return;
            }
        };

        let local_ledger = self.survey_local_ledger().await;
        let nonce_is_reporting =
            self.survey_data.read().await.nonce_is_reporting(response_message.nonce);
        let mut limiter = self.survey_limiter.write().await;
        let is_valid = limiter.record_and_validate_response(
            &response_message.response,
            local_ledger,
            || {
                nonce_is_reporting
                    && self.verify_survey_signature(
                        &response_message.response.surveyed_peer_id,
                        &response_bytes,
                        &signed.response_signature,
                    )
            },
        );
        if !is_valid {
            tracing::debug!(peer = ?peer_id, "Survey response rejected by limiter");
            return;
        }

        if response_message.response.surveyor_peer_id != self.local_node_id() {
            let _ = self
                .broadcast_survey_message(StellarMessage::TimeSlicedSurveyResponse(signed))
                .await;
            return;
        }

        let secret = { self.survey_secrets.read().await.get(&response_message.nonce).copied() };

        let secret = match secret {
            Some(secret) => secret,
            None => {
                tracing::debug!(peer = ?peer_id, "Survey response without matching secret");
                return;
            }
        };

        let decrypted = match stellar_core_crypto::open_from_curve25519_secret_key(
            &secret,
            response_message.response.encrypted_body.0.as_slice(),
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to decrypt survey response");
                let mut reporting = self.survey_reporting.write().await;
                reporting.bad_response_nodes.insert(peer_id.clone());
                return;
            }
        };

        let response_body = match SurveyResponseBody::from_xdr(
            decrypted.as_slice(),
            stellar_xdr::curr::Limits::none(),
        ) {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to decode survey response body");
                let mut reporting = self.survey_reporting.write().await;
                reporting.bad_response_nodes.insert(peer_id.clone());
                return;
            }
        };

        let body = match response_body {
            SurveyResponseBody::SurveyTopologyResponseV2(body) => body,
        };
        let (inbound_len, outbound_len) = {
            let mut results = self.survey_results.write().await;
            let entry = results
                .entry(response_message.nonce)
                .or_insert_with(HashMap::new)
                .entry(peer_id.clone())
                .or_insert_with(|| body.clone());
            Self::merge_topology_response(entry, &body);
            (entry.inbound_peers.0.len(), entry.outbound_peers.0.len())
        };
        tracing::debug!(
            peer = ?peer_id,
            inbound = body.inbound_peers.0.len(),
            outbound = body.outbound_peers.0.len(),
            "Decrypted survey response"
        );

        let needs_more_inbound = body.inbound_peers.0.len() == TIME_SLICED_PEERS_MAX;
        let needs_more_outbound = body.outbound_peers.0.len() == TIME_SLICED_PEERS_MAX;
        if needs_more_inbound || needs_more_outbound {
            if self.survey_reporting.read().await.running {
                let next_inbound = inbound_len as u32;
                let next_outbound = outbound_len as u32;
                let _ = self
                    .survey_topology_timesliced(peer_id.clone(), next_inbound, next_outbound)
                    .await;
            }
        }
    }

    fn local_node_id(&self) -> stellar_xdr::curr::NodeId {
        stellar_xdr::curr::NodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256(*self.keypair.public_key().as_bytes()),
        ))
    }

    async fn survey_local_ledger(&self) -> u32 {
        let tracking = self.herder.tracking_slot() as u32;
        if tracking == 0 {
            *self.current_ledger.read().await
        } else {
            tracking
        }
    }

    fn partition_peer_snapshots(
        snapshots: Vec<PeerSnapshot>,
    ) -> (Vec<PeerSnapshot>, Vec<PeerSnapshot>) {
        let mut inbound = Vec::new();
        let mut outbound = Vec::new();

        for snapshot in snapshots {
            match snapshot.info.direction {
                stellar_core_overlay::ConnectionDirection::Inbound => inbound.push(snapshot),
                stellar_core_overlay::ConnectionDirection::Outbound => outbound.push(snapshot),
            }
        }

        (inbound, outbound)
    }

    fn select_survey_peers(
        snapshots: Vec<PeerSnapshot>,
        max_peers: usize,
    ) -> Vec<stellar_core_overlay::PeerId> {
        let (mut inbound, mut outbound) = Self::partition_peer_snapshots(snapshots);
        let mut sort_by_activity = |a: &PeerSnapshot, b: &PeerSnapshot| {
            b.stats
                .messages_received
                .cmp(&a.stats.messages_received)
                .then_with(|| b.info.connected_at.cmp(&a.info.connected_at))
                .then_with(|| a.info.peer_id.to_hex().cmp(&b.info.peer_id.to_hex()))
        };
        inbound.sort_by(&mut sort_by_activity);
        outbound.sort_by(&mut sort_by_activity);

        let mut selected = Vec::new();
        let mut inbound_idx = 0usize;
        let mut outbound_idx = 0usize;

        while selected.len() < max_peers
            && (inbound_idx < inbound.len() || outbound_idx < outbound.len())
        {
            if outbound_idx < outbound.len() {
                selected.push(outbound[outbound_idx].info.peer_id.clone());
                outbound_idx += 1;
                if selected.len() == max_peers {
                    break;
                }
            }
            if inbound_idx < inbound.len() {
                selected.push(inbound[inbound_idx].info.peer_id.clone());
                inbound_idx += 1;
            }
        }

        selected
    }

    fn sign_survey_message(&self, message: &[u8]) -> stellar_xdr::curr::Signature {
        let sig = self.keypair.sign(message);
        sig.into()
    }

    fn merge_topology_response(
        existing: &mut TopologyResponseBodyV2,
        incoming: &TopologyResponseBodyV2,
    ) {
        existing.node_data = incoming.node_data.clone();

        let mut inbound = existing
            .inbound_peers
            .0
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        inbound.extend(incoming.inbound_peers.0.iter().cloned());
        existing.inbound_peers.0 = inbound.try_into().unwrap_or_default();

        let mut outbound = existing
            .outbound_peers
            .0
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        outbound.extend(incoming.outbound_peers.0.iter().cloned());
        existing.outbound_peers.0 = outbound.try_into().unwrap_or_default();
    }

    fn verify_survey_signature(
        &self,
        node_id: &stellar_xdr::curr::NodeId,
        message: &[u8],
        signature: &stellar_xdr::curr::Signature,
    ) -> bool {
        let key_bytes = match Self::node_id_bytes(node_id) {
            Some(bytes) => bytes,
            None => return false,
        };
        let public_key = match stellar_core_crypto::PublicKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let sig = match stellar_core_crypto::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        stellar_core_crypto::verify(&public_key, message, &sig).is_ok()
    }

    fn node_id_bytes(node_id: &stellar_xdr::curr::NodeId) -> Option<[u8; 32]> {
        match &node_id.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => Some(key.0),
        }
    }

    fn surveyor_permitted(&self, surveyor_id: &stellar_xdr::curr::NodeId) -> bool {
        let allowed_keys = &self.config.overlay.surveyor_keys;
        if allowed_keys.is_empty() {
            let quorum_nodes = self.herder.local_quorum_nodes();
            if quorum_nodes.is_empty() {
                return false;
            }
            return quorum_nodes.contains(surveyor_id);
        }

        let Some(bytes) = Self::node_id_bytes(surveyor_id) else {
            return false;
        };

        allowed_keys.iter().any(|key| {
            stellar_core_crypto::PublicKey::from_strkey(key)
                .map(|pk| pk.as_bytes() == &bytes)
                .unwrap_or(false)
        })
    }

    fn scp_quorum_set_hash(statement: &stellar_xdr::curr::ScpStatement) -> Option<Hash> {
        match &statement.pledges {
            stellar_xdr::curr::ScpStatementPledges::Nominate(nom) => {
                Some(nom.quorum_set_hash.clone())
            }
            stellar_xdr::curr::ScpStatementPledges::Prepare(prep) => {
                Some(prep.quorum_set_hash.clone())
            }
            stellar_xdr::curr::ScpStatementPledges::Confirm(conf) => {
                Some(conf.quorum_set_hash.clone())
            }
            stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
                Some(ext.commit_quorum_set_hash.clone())
            }
        }
    }

    fn tx_hash(&self, tx_env: &stellar_xdr::curr::TransactionEnvelope) -> Option<Hash256> {
        Hash256::hash_xdr(tx_env).ok()
    }

    async fn enqueue_tx_advert(&self, tx_env: &stellar_xdr::curr::TransactionEnvelope) {
        let Some(hash) = self.tx_hash(tx_env) else {
            tracing::debug!("Failed to hash transaction for advert");
            return;
        };

        let mut set = self.tx_advert_set.write().await;
        if set.contains(&hash) {
            return;
        }
        set.insert(hash);
        drop(set);

        let mut queue = self.tx_advert_queue.write().await;
        queue.push(hash);
    }

    async fn flush_tx_adverts(&self) {
        let hashes = {
            let mut queue = self.tx_advert_queue.write().await;
            if queue.is_empty() {
                return;
            }
            std::mem::take(&mut *queue)
        };

        self.tx_advert_set.write().await.clear();

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return,
        };

        let max_advert_size = self.max_advert_size();
        let snapshots = overlay.peer_snapshots();
        if snapshots.is_empty() {
            return;
        }

        let peer_ids = snapshots
            .iter()
            .map(|snapshot| snapshot.info.peer_id.clone())
            .collect::<Vec<_>>();
        let peer_set: HashSet<_> = peer_ids.iter().cloned().collect();

        let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
        adverts_by_peer.retain(|peer, _| peer_set.contains(peer));

        let mut per_peer = Vec::new();
        for peer_id in peer_ids {
            let adverts = adverts_by_peer
                .entry(peer_id.clone())
                .or_insert_with(PeerTxAdverts::new);
            let mut outgoing = Vec::new();
            for hash in &hashes {
                if adverts.seen_advert(hash) {
                    continue;
                }
                outgoing.push(*hash);
            }
            if !outgoing.is_empty() {
                per_peer.push((peer_id, outgoing));
            }
        }
        drop(adverts_by_peer);

        for (peer_id, hashes) in per_peer {
            for chunk in hashes.chunks(max_advert_size) {
                let tx_hashes = match TxAdvertVector::try_from(
                    chunk.iter().map(|hash| Hash::from(*hash)).collect::<Vec<_>>(),
                ) {
                    Ok(vec) => vec,
                    Err(_) => {
                        tracing::debug!(peer = ?peer_id, "Failed to build tx advert vector");
                        continue;
                    }
                };
                let advert = FloodAdvert { tx_hashes };
                if let Err(e) = overlay
                    .send_to(&peer_id, StellarMessage::FloodAdvert(advert))
                    .await
                {
                    tracing::debug!(peer = ?peer_id, error = %e, "Failed to send tx advert batch");
                }
            }
        }
    }

    fn flood_advert_period(&self) -> Duration {
        Duration::from_millis(self.config.overlay.flood_advert_period_ms.max(1))
    }

    fn flood_demand_period(&self) -> Duration {
        Duration::from_millis(self.config.overlay.flood_demand_period_ms.max(1))
    }

    fn flood_demand_backoff_delay(&self) -> Duration {
        Duration::from_millis(self.config.overlay.flood_demand_backoff_delay_ms.max(1))
    }

    fn max_advert_queue_size(&self) -> usize {
        self.herder.max_tx_set_size().max(1)
    }

    fn max_advert_size(&self) -> usize {
        const TX_ADVERT_VECTOR_MAX_SIZE: usize = 1000;
        let ledger_close_ms = (self.herder.ledger_close_time() as u64).saturating_mul(1000);
        let ledger_close_ms = ledger_close_ms.max(1) as f64;
        let ops_to_flood = self.config.overlay.flood_op_rate_per_ledger
            * self.herder.max_tx_set_size() as f64;
        let per_period = (ops_to_flood
            * self.config.overlay.flood_advert_period_ms as f64
            / ledger_close_ms)
            .ceil()
            .max(1.0);
        per_period.min(TX_ADVERT_VECTOR_MAX_SIZE as f64) as usize
    }

    fn max_demand_size(&self) -> usize {
        const TX_DEMAND_VECTOR_MAX_SIZE: usize = 1000;
        let ledger_close_ms = (self.herder.ledger_close_time() as u64).saturating_mul(1000);
        let ledger_close_ms = ledger_close_ms.max(1) as f64;
        let ops_to_flood = self.config.overlay.flood_op_rate_per_ledger
            * self.herder.max_queue_size_ops() as f64;
        let per_period = (ops_to_flood
            * self.config.overlay.flood_demand_period_ms as f64
            / ledger_close_ms)
            .ceil()
            .max(1.0);
        per_period.min(TX_DEMAND_VECTOR_MAX_SIZE as f64) as usize
    }

    fn retry_delay_demand(&self, attempts: usize) -> Duration {
        let delay_ms = self
            .flood_demand_backoff_delay()
            .as_millis()
            .saturating_mul(attempts as u128);
        Duration::from_millis(delay_ms.min(2000) as u64)
    }

    async fn clear_tx_advert_history(&self, ledger_seq: u32) {
        let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
        for adverts in adverts_by_peer.values_mut() {
            adverts.clear_below(ledger_seq);
        }
    }

    async fn record_tx_pull_latency(
        &self,
        hash: Hash256,
        peer: &stellar_core_overlay::PeerId,
    ) {
        let now = Instant::now();
        let mut history = self.tx_demand_history.write().await;
        let Some(entry) = history.get_mut(&hash) else {
            return;
        };

        if !entry.latency_recorded {
            entry.latency_recorded = true;
            let delta = now.duration_since(entry.first_demanded);
            tracing::debug!(
                hash = %hash.to_hex(),
                latency_ms = delta.as_millis(),
                peers = entry.peers.len(),
                "Pulled transaction after demand"
            );
        }

        if let Some(peer_demanded) = entry.peers.get(peer) {
            let delta = now.duration_since(*peer_demanded);
            tracing::debug!(
                hash = %hash.to_hex(),
                peer = ?peer,
                latency_ms = delta.as_millis(),
                "Pulled transaction from peer"
            );
        }
    }

    fn demand_status(
        &self,
        hash: Hash256,
        peer: &stellar_core_overlay::PeerId,
        now: Instant,
        history: &HashMap<Hash256, TxDemandHistory>,
    ) -> DemandStatus {
        const MAX_RETRY_COUNT: usize = 15;

        if self.herder.tx_queue().contains(&hash) {
            return DemandStatus::Discard;
        }

        let Some(entry) = history.get(&hash) else {
            return DemandStatus::Demand;
        };

        if entry.peers.contains_key(peer) {
            return DemandStatus::Discard;
        }

        let num_demanded = entry.peers.len();
        if num_demanded < MAX_RETRY_COUNT {
            let retry_delay = self.retry_delay_demand(num_demanded);
            if now.duration_since(entry.last_demanded) >= retry_delay {
                DemandStatus::Demand
            } else {
                DemandStatus::RetryLater
            }
        } else {
            DemandStatus::Discard
        }
    }

    fn prune_tx_demands(
        &self,
        now: Instant,
        pending: &mut VecDeque<Hash256>,
        history: &mut HashMap<Hash256, TxDemandHistory>,
    ) {
        const MAX_RETRY_COUNT: u32 = 15;
        let max_retention = Duration::from_secs(2) * MAX_RETRY_COUNT * 2;

        while let Some(hash) = pending.front().copied() {
            let Some(entry) = history.get(&hash) else {
                pending.pop_front();
                continue;
            };
            if now.duration_since(entry.first_demanded) >= max_retention {
                if !entry.latency_recorded {
                    tracing::debug!(hash = %hash.to_hex(), "Abandoned tx demand");
                }
                pending.pop_front();
                history.remove(&hash);
            } else {
                break;
            }
        }
    }

    async fn run_tx_demands(&self) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return,
        };

        let mut peers = overlay.peer_snapshots();
        if peers.is_empty() {
            return;
        }

        peers.shuffle(&mut rand::thread_rng());
        let peer_ids = peers
            .iter()
            .map(|snapshot| snapshot.info.peer_id.clone())
            .collect::<Vec<_>>();
        let peer_set: HashSet<_> = peer_ids.iter().cloned().collect();

        let max_demand_size = self.max_demand_size();
        let max_queue_size = self.max_advert_queue_size();
        let now = Instant::now();
        let mut to_send: Vec<(stellar_core_overlay::PeerId, Vec<Hash256>)> = Vec::new();

        {
            let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
            adverts_by_peer.retain(|peer, _| peer_set.contains(peer));
            for peer_id in &peer_ids {
                adverts_by_peer
                    .entry(peer_id.clone())
                    .or_insert_with(PeerTxAdverts::new);
            }

            let mut history = self.tx_demand_history.write().await;
            let mut pending = self.tx_pending_demands.write().await;
            self.prune_tx_demands(now, &mut pending, &mut history);

            let mut demand_map: HashMap<
                stellar_core_overlay::PeerId,
                (Vec<Hash256>, Vec<Hash256>),
            > = peer_ids
                .iter()
                .map(|peer| (peer.clone(), (Vec::new(), Vec::new())))
                .collect();

            let mut any_new_demand = true;
            while any_new_demand {
                any_new_demand = false;
                for peer_id in &peer_ids {
                    let Some(adverts) = adverts_by_peer.get_mut(peer_id) else {
                        continue;
                    };
                    let Some((demand, retry)) = demand_map.get_mut(peer_id) else {
                        continue;
                    };

                    let mut added_new = false;
                    while demand.len() < max_demand_size && adverts.has_advert() && !added_new {
                        let Some(hash) = adverts.pop_advert() else {
                            break;
                        };
                        match self.demand_status(hash, peer_id, now, &history) {
                            DemandStatus::Demand => {
                                demand.push(hash);
                                let entry = history.entry(hash).or_insert_with(|| {
                                    pending.push_back(hash);
                                    TxDemandHistory {
                                        first_demanded: now,
                                        last_demanded: now,
                                        peers: HashMap::new(),
                                        latency_recorded: false,
                                    }
                                });
                                entry.peers.insert(peer_id.clone(), now);
                                entry.last_demanded = now;
                                added_new = true;
                                any_new_demand = true;
                            }
                            DemandStatus::RetryLater => {
                                retry.push(hash);
                            }
                            DemandStatus::Discard => {}
                        }
                    }
                }
            }

            for peer_id in &peer_ids {
                let Some(adverts) = adverts_by_peer.get_mut(peer_id) else {
                    continue;
                };
                let Some((demand, retry)) = demand_map.remove(peer_id) else {
                    continue;
                };
                adverts.retry_incoming(retry, max_queue_size);
                if !demand.is_empty() {
                    to_send.push((peer_id.clone(), demand));
                }
            }
        }

        for (peer_id, hashes) in to_send {
            let tx_hashes = match TxDemandVector::try_from(
                hashes.into_iter().map(Hash::from).collect::<Vec<_>>(),
            ) {
                Ok(vec) => vec,
                Err(_) => {
                    tracing::debug!(peer = ?peer_id, "Failed to build tx demand vector");
                    continue;
                }
            };
            let demand = FloodDemand { tx_hashes };
            if let Err(e) = overlay
                .send_to(&peer_id, StellarMessage::FloodDemand(demand))
                .await
            {
                tracing::debug!(peer = ?peer_id, error = %e, "Failed to send flood demand");
            }
        }
    }

    async fn advance_survey_scheduler(&self) {
        const SURVEY_INTERVAL: Duration = Duration::from_secs(60);
        const SURVEY_COLLECT_DELAY: Duration = Duration::from_secs(5);
        const SURVEY_RESPONSE_WAIT: Duration = Duration::from_secs(5);
        const SURVEY_MAX_PEERS: usize = 4;

        let now = Instant::now();
        let mut scheduler = self.survey_scheduler.write().await;

        if now < scheduler.next_action {
            return;
        }

        match scheduler.phase {
            SurveySchedulerPhase::Idle => {
                if self.survey_data.read().await.survey_is_active()
                    || self.survey_reporting.read().await.running
                {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }
                let state = *self.state.read().await;
                if !matches!(state, AppState::Synced | AppState::Validating) {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }
                if let Some(last) = scheduler.last_started {
                    if now.duration_since(last) < self.survey_throttle {
                        scheduler.next_action = last + self.survey_throttle;
                        return;
                    }
                }

                let overlay = self.overlay.lock().await;
                let overlay = match overlay.as_ref() {
                    Some(overlay) => overlay,
                    None => {
                        scheduler.next_action = now + SURVEY_INTERVAL;
                        return;
                    }
                };

                let peers = Self::select_survey_peers(overlay.peer_snapshots(), SURVEY_MAX_PEERS);

                if peers.is_empty() {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }

                let ledger_num = *self.current_ledger.read().await;
                let nonce = {
                    let mut nonce = self.survey_nonce.write().await;
                    let current = *nonce;
                    *nonce = nonce.wrapping_add(1);
                    current
                };

                if !self
                    .send_survey_start(&peers, nonce, ledger_num)
                    .await
                {
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }

                scheduler.phase = SurveySchedulerPhase::StartSent;
                scheduler.peers = peers;
                scheduler.nonce = nonce;
                scheduler.ledger_num = ledger_num;
                scheduler.next_action = now + SURVEY_COLLECT_DELAY;
                scheduler.last_started = Some(now);
            }
            SurveySchedulerPhase::StartSent => {
                if !self
                    .send_survey_requests(&scheduler.peers, scheduler.nonce, scheduler.ledger_num)
                    .await
                {
                    self.survey_secrets.write().await.remove(&scheduler.nonce);
                    scheduler.phase = SurveySchedulerPhase::Idle;
                    scheduler.next_action = now + SURVEY_INTERVAL;
                    return;
                }
                scheduler.phase = SurveySchedulerPhase::RequestSent;
                scheduler.next_action = now + SURVEY_RESPONSE_WAIT;
            }
            SurveySchedulerPhase::RequestSent => {
                self.send_survey_stop(&scheduler.peers, scheduler.nonce, scheduler.ledger_num)
                    .await;
                for peer_id in scheduler.peers.clone() {
                    let _ = self.survey_topology_timesliced(peer_id, 0, 0).await;
                }
                scheduler.phase = SurveySchedulerPhase::Idle;
                scheduler.peers.clear();
                scheduler.nonce = 0;
                scheduler.ledger_num = 0;
                scheduler.next_action = now + SURVEY_INTERVAL;
            }
        }
    }

    async fn update_survey_phase(&self) {
        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);

        let mut survey_data = self.survey_data.write().await;
        survey_data.update_phase(&inbound, &outbound, added, dropped, lost_sync);

        let last_closed = *self.current_ledger.read().await;
        let mut limiter = self.survey_limiter.write().await;
        limiter.clear_old_ledgers(last_closed);
    }

    async fn check_scp_timeouts(&self) {
        if !self.is_validator {
            return;
        }
        if !self.herder.state().can_receive_scp() {
            return;
        }
        let slot = self.herder.tracking_slot();
        let now = Instant::now();
        let mut timeouts = self.scp_timeouts.write().await;
        if timeouts.slot != slot {
            timeouts.slot = slot;
            timeouts.next_nomination = None;
            timeouts.next_ballot = None;
        }

        if let Some(next) = timeouts.next_nomination {
            if now >= next {
                self.herder.handle_nomination_timeout(slot);
                timeouts.next_nomination = None;
            }
        }
        if timeouts.next_nomination.is_none() {
            if let Some(timeout) = self.herder.get_nomination_timeout(slot) {
                timeouts.next_nomination = Some(now + timeout);
            }
        }

        if let Some(next) = timeouts.next_ballot {
            if now >= next {
                self.herder.handle_ballot_timeout(slot);
                timeouts.next_ballot = None;
            }
        }
        if timeouts.next_ballot.is_none() {
            if let Some(timeout) = self.herder.get_ballot_timeout(slot) {
                timeouts.next_ballot = Some(now + timeout);
            }
        }
    }

    fn next_ping_hash(&self) -> Hash256 {
        let counter = self.ping_counter.fetch_add(1, Ordering::Relaxed);
        Hash256::hash(&counter.to_be_bytes())
    }

    async fn send_peer_pings(&self) {
        const PING_TIMEOUT: Duration = Duration::from_secs(60);

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        let snapshots = overlay.peer_snapshots();
        if snapshots.is_empty() {
            return;
        }

        let now = Instant::now();
        let mut inflight = self.ping_inflight.write().await;
        let mut peer_inflight = self.peer_ping_inflight.write().await;
        inflight.retain(|hash, info| {
            if now.duration_since(info.sent_at) > PING_TIMEOUT {
                if let Some(existing) = peer_inflight.get(&info.peer_id) {
                    if existing == hash {
                        peer_inflight.remove(&info.peer_id);
                    }
                }
                return false;
            }
            true
        });

        let mut to_ping = Vec::new();
        for snapshot in snapshots {
            if peer_inflight.contains_key(&snapshot.info.peer_id) {
                continue;
            }
            let hash = self.next_ping_hash();
            peer_inflight.insert(snapshot.info.peer_id.clone(), hash);
            inflight.insert(
                hash,
                PingInfo {
                    peer_id: snapshot.info.peer_id.clone(),
                    sent_at: Instant::now(),
                },
            );
            to_ping.push((snapshot.info.peer_id, hash));
        }
        drop(inflight);
        drop(peer_inflight);

        for (peer, hash) in to_ping {
            let msg = StellarMessage::GetScpQuorumset(stellar_xdr::curr::Uint256(hash.0));
            if let Err(e) = overlay.send_to(&peer, msg).await {
                tracing::debug!(peer = ?peer, error = %e, "Failed to send ping");
                let mut inflight = self.ping_inflight.write().await;
                inflight.remove(&hash);
                let mut peer_inflight = self.peer_ping_inflight.write().await;
                if let Some(existing) = peer_inflight.get(&peer) {
                    if *existing == hash {
                        peer_inflight.remove(&peer);
                    }
                }
            }
        }
    }

    async fn process_ping_response(&self, peer_id: &stellar_core_overlay::PeerId, hash: [u8; 32]) {
        let hash = Hash256::from_bytes(hash);
        let info = {
            let mut inflight = self.ping_inflight.write().await;
            inflight.remove(&hash)
        };

        let Some(info) = info else {
            return;
        };

        {
            let mut peer_inflight = self.peer_ping_inflight.write().await;
            if let Some(existing) = peer_inflight.get(&info.peer_id) {
                if *existing == hash {
                    peer_inflight.remove(&info.peer_id);
                }
            }
        }

        if &info.peer_id != peer_id {
            return;
        }

        let latency_ms = info.sent_at.elapsed().as_millis() as u64;
        let mut survey_data = self.survey_data.write().await;
        survey_data.record_peer_latency(peer_id, latency_ms);
    }

    async fn send_survey_start(
        &self,
        peers: &[stellar_core_overlay::PeerId],
        nonce: u32,
        ledger_num: u32,
    ) -> bool {
        let start = TimeSlicedSurveyStartCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };

        let start_bytes = match start.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey start message");
                return false;
            }
        };

        let signature = self.sign_survey_message(&start_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStartCollectingMessage {
            signature,
            start_collecting: start.clone(),
        };

        let sent = self.send_survey_message(
            peers,
            StellarMessage::TimeSlicedSurveyStartCollecting(signed),
        )
        .await;
        if sent {
            self.survey_results
                .write()
                .await
                .entry(nonce)
                .or_insert_with(HashMap::new);
            self.start_local_survey_collecting(&start).await;
        }
        sent
    }

    async fn send_survey_requests(
        &self,
        peers: &[stellar_core_overlay::PeerId],
        nonce: u32,
        ledger_num: u32,
    ) -> bool {
        let local_node_id = self.local_node_id();
        let secret = self.ensure_survey_secret(nonce).await;
        let public = CurvePublicKey::from(&secret);
        let encryption_key = Curve25519Public { key: public.to_bytes() };

        let mut ok = true;
        for peer in peers {
            let request = SurveyRequestMessage {
                surveyor_peer_id: local_node_id.clone(),
                surveyed_peer_id: stellar_xdr::curr::NodeId(peer.0.clone()),
                ledger_num,
                encryption_key: encryption_key.clone(),
                command_type: SurveyMessageCommandType::TimeSlicedSurveyTopology,
            };

            let message = TimeSlicedSurveyRequestMessage {
                request,
                nonce,
                inbound_peers_index: 0,
                outbound_peers_index: 0,
            };

            let message_bytes = match message.to_xdr(stellar_xdr::curr::Limits::none()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::debug!(peer = ?peer, error = %e, "Failed to encode survey request");
                    ok = false;
                    continue;
                }
            };

            let signature = self.sign_survey_message(&message_bytes);
            let signed = stellar_xdr::curr::SignedTimeSlicedSurveyRequestMessage {
                request_signature: signature,
                request: message,
            };

            if !self
                .send_survey_message(
                    std::slice::from_ref(peer),
                    StellarMessage::TimeSlicedSurveyRequest(signed),
                )
                .await
            {
                ok = false;
            }
        }
        ok
    }

    async fn send_survey_stop(
        &self,
        peers: &[stellar_core_overlay::PeerId],
        nonce: u32,
        ledger_num: u32,
    ) {
        let stop = TimeSlicedSurveyStopCollectingMessage {
            surveyor_id: self.local_node_id(),
            nonce,
            ledger_num,
        };

        let stop_bytes = match stop.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to encode survey stop message");
                return;
            }
        };

        let signature = self.sign_survey_message(&stop_bytes);
        let signed = stellar_xdr::curr::SignedTimeSlicedSurveyStopCollectingMessage {
            signature,
            stop_collecting: stop.clone(),
        };

        let _ = self
            .send_survey_message(
                peers,
                StellarMessage::TimeSlicedSurveyStopCollecting(signed),
            )
            .await;
        self.stop_local_survey_collecting(&stop).await;
    }

    async fn send_survey_message(
        &self,
        peers: &[stellar_core_overlay::PeerId],
        message: StellarMessage,
    ) -> bool {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return false,
        };

        let mut ok = true;
        for peer in peers {
            if let Err(e) = overlay.send_to(peer, message.clone()).await {
                tracing::debug!(peer = ?peer, error = %e, "Failed to send survey message");
                ok = false;
            }
        }
        ok
    }

    async fn start_local_survey_collecting(
        &self,
        message: &TimeSlicedSurveyStartCollectingMessage,
    ) {
        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);
        let state = self.state().await;
        let initially_out_of_sync = matches!(state, AppState::Initializing | AppState::CatchingUp);

        let mut survey_data = self.survey_data.write().await;
        let _ = survey_data.start_collecting(
            message,
            &inbound,
            &outbound,
            lost_sync,
            added,
            dropped,
            initially_out_of_sync,
        );
    }

    async fn stop_local_survey_collecting(
        &self,
        message: &TimeSlicedSurveyStopCollectingMessage,
    ) {
        let (snapshots, added, dropped) = {
            let overlay = self.overlay.lock().await;
            let overlay = match overlay.as_ref() {
                Some(o) => o,
                None => return,
            };
            (
                overlay.peer_snapshots(),
                overlay.added_authenticated_peers(),
                overlay.dropped_authenticated_peers(),
            )
        };
        let (inbound, outbound) = Self::partition_peer_snapshots(snapshots);
        let lost_sync = self.lost_sync_count.load(Ordering::Relaxed);

        let mut survey_data = self.survey_data.write().await;
        let _ = survey_data.stop_collecting(message, &inbound, &outbound, added, dropped, lost_sync);
    }

    async fn handle_flood_advert(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        advert: FloodAdvert,
    ) {
        let ledger_seq = self.herder.tracking_slot().min(u32::MAX as u64) as u32;
        let max_ops = self.max_advert_queue_size();
        let mut adverts_by_peer = self.tx_adverts_by_peer.write().await;
        let entry = adverts_by_peer
            .entry(peer_id.clone())
            .or_insert_with(PeerTxAdverts::new);
        entry.queue_incoming(&advert.tx_hashes.0, ledger_seq, max_ops);
    }

    async fn handle_flood_demand(
        &self,
        peer_id: &stellar_core_overlay::PeerId,
        demand: FloodDemand,
    ) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(overlay) => overlay,
            None => return,
        };

        for hash in demand.tx_hashes.0.iter() {
            let hash256 = Hash256::from(hash.clone());
            if let Some(tx) = self.herder.tx_queue().get(&hash256) {
                if let Err(e) = overlay
                    .send_to(peer_id, StellarMessage::Transaction(tx.envelope))
                    .await
                {
                    tracing::debug!(peer = ?peer_id, error = %e, "Failed to send demanded transaction");
                }
            } else {
                let dont_have = DontHave {
                    type_: MessageType::Transaction,
                    req_hash: stellar_xdr::curr::Uint256(hash.0),
                };
                if let Err(e) = overlay
                    .send_to(peer_id, StellarMessage::DontHave(dont_have))
                    .await
                {
                    tracing::debug!(peer = ?peer_id, error = %e, "Failed to send DontHave for transaction");
                }
            }
        }
    }

    /// Process a peer list received from the network.
    async fn process_peer_list(&self, peer_list: stellar_xdr::curr::VecM<stellar_xdr::curr::PeerAddress, 100>) {
        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => return,
        };

        // Convert XDR peer addresses to our PeerAddress format
        let addrs: Vec<PeerAddress> = peer_list
            .iter()
            .filter_map(|xdr_addr| {
                // Extract IP address from the XDR type
                let ip = match &xdr_addr.ip {
                    stellar_xdr::curr::PeerAddressIp::IPv4(bytes) => {
                        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
                    }
                    stellar_xdr::curr::PeerAddressIp::IPv6(_) => {
                        return None;
                    }
                };

                let port = xdr_addr.port;

                // Skip obviously invalid addresses
                if port == 0 {
                    return None;
                }

                Some(PeerAddress::new(ip, port as u16))
            })
            .collect();

        let addrs = self.filter_discovered_peers(addrs);

        if !addrs.is_empty() {
            self.persist_peers(&addrs);
            let count = overlay.add_peers(addrs).await;
            if count > 0 {
                tracing::info!(added = count, "Added peers from discovery");
            }
        }

        let _ = self.refresh_known_peers(overlay);
    }

    fn parse_peer_address(value: &str) -> Option<PeerAddress> {
        let parts: Vec<&str> = value.split(':').collect();
        match parts.len() {
            1 => Some(PeerAddress::new(parts[0], 11625)),
            2 => parts[1].parse().ok().map(|port| PeerAddress::new(parts[0], port)),
            _ => None,
        }
    }

    fn peer_id_to_strkey(peer_id: &PeerId) -> Option<String> {
        stellar_core_crypto::PublicKey::from_bytes(peer_id.as_bytes())
            .ok()
            .map(|pk| pk.to_strkey())
    }

    fn strkey_to_peer_id(value: &str) -> Option<PeerId> {
        stellar_core_crypto::PublicKey::from_strkey(value)
            .ok()
            .map(|pk| PeerId::from_bytes(*pk.as_bytes()))
    }

    fn load_persisted_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let now = current_epoch_seconds();
        let peers = self.db.load_random_peers(
            1000,
            self.config.overlay.peer_max_failures,
            now,
            Some(PEER_TYPE_OUTBOUND),
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn store_config_peers(&self) {
        let now = current_epoch_seconds();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                let record = stellar_core_db::queries::PeerRecord::new(
                    now,
                    0,
                    PEER_TYPE_OUTBOUND,
                );
                let _ = self.db.store_peer(&peer.host, peer.port, record);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                let record = stellar_core_db::queries::PeerRecord::new(
                    now,
                    0,
                    PEER_TYPE_PREFERRED,
                );
                let _ = self.db.store_peer(&peer.host, peer.port, record);
            }
        }
    }

    fn load_advertised_outbound_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let peers = self.db.load_random_peers_any_outbound_max_failures(
            1000,
            PEER_MAX_FAILURES_TO_SEND,
            PEER_TYPE_INBOUND,
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn load_advertised_inbound_peers(&self) -> anyhow::Result<Vec<PeerAddress>> {
        let peers = self.db.load_random_peers_by_type_max_failures(
            1000,
            PEER_MAX_FAILURES_TO_SEND,
            PEER_TYPE_INBOUND,
        )?;
        let mut addrs = Vec::new();
        for (host, port, _) in peers {
            addrs.push(PeerAddress::new(host, port));
        }
        Ok(addrs)
    }

    fn persist_peers(&self, peers: &[PeerAddress]) {
        let now = current_epoch_seconds();
        for peer in peers {
            let existing = self.db.load_peer(&peer.host, peer.port).ok().flatten();
            if existing.is_some() {
                continue;
            }
            let record = stellar_core_db::queries::PeerRecord::new(now, 0, PEER_TYPE_OUTBOUND);
            if let Err(err) = self.db.store_peer(&peer.host, peer.port, record) {
                tracing::debug!(peer = %peer, error = %err, "Failed to persist peer");
            }
        }
    }

    fn filter_discovered_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        let now = current_epoch_seconds();
        let mut filtered = Vec::new();
        for peer in peers {
            if !Self::is_public_peer(&peer) {
                continue;
            }
            let record = self.db.load_peer(&peer.host, peer.port).ok().flatten();
            if let Some(record) = record {
                if record.num_failures >= self.config.overlay.peer_max_failures {
                    continue;
                }
                if record.next_attempt > now {
                    continue;
                }
            }
            filtered.push(peer);
        }
        filtered
    }

    fn filter_advertised_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        peers
            .into_iter()
            .filter(|peer| Self::is_public_peer(peer))
            .collect()
    }

    fn is_public_peer(peer: &PeerAddress) -> bool {
        if peer.port == 0 {
            return false;
        }
        let Ok(ip) = peer.host.parse::<std::net::IpAddr>() else {
            return true;
        };
        match ip {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified())
            }
            std::net::IpAddr::V6(_) => false,
        }
    }

    fn refresh_known_peers(&self, overlay: &OverlayManager) -> Vec<PeerAddress> {
        let mut peers = Vec::new();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                peers.push(peer);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                self.upsert_peer_type(&peer, PEER_TYPE_PREFERRED);
                peers.push(peer);
            }
        }
        if let Ok(persisted) = self.load_persisted_peers() {
            peers.extend(persisted);
        }
        let peers = self.filter_discovered_peers(peers);
        let peers = self.dedupe_peers(peers);
        overlay.set_known_peers(peers.clone());

        let mut advertised_outbound = Vec::new();
        for addr in &self.config.overlay.known_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                advertised_outbound.push(peer);
            }
        }
        for addr in &self.config.overlay.preferred_peers {
            if let Some(peer) = Self::parse_peer_address(addr) {
                advertised_outbound.push(peer);
            }
        }
        if let Ok(persisted) = self.load_advertised_outbound_peers() {
            advertised_outbound.extend(persisted);
        }
        let advertised_outbound = self.filter_advertised_peers(advertised_outbound);
        let advertised_outbound = self.dedupe_peers(advertised_outbound);

        let mut advertised_inbound = Vec::new();
        if let Ok(persisted) = self.load_advertised_inbound_peers() {
            advertised_inbound.extend(persisted);
        }
        let advertised_inbound = self.filter_advertised_peers(advertised_inbound);
        let advertised_inbound = self.dedupe_peers(advertised_inbound);
        overlay.set_advertised_peers(advertised_outbound, advertised_inbound);

        peers
    }

    fn upsert_peer_type(&self, peer: &PeerAddress, peer_type: i32) {
        let now = current_epoch_seconds();
        let existing = self.db.load_peer(&peer.host, peer.port).ok().flatten();
        let record = match existing {
            Some(existing) => stellar_core_db::queries::PeerRecord::new(
                existing.next_attempt,
                existing.num_failures,
                peer_type,
            ),
            None => stellar_core_db::queries::PeerRecord::new(now, 0, peer_type),
        };
        let _ = self.db.store_peer(&peer.host, peer.port, record);
    }
    fn dedupe_peers(&self, peers: Vec<PeerAddress>) -> Vec<PeerAddress> {
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for peer in peers {
            if seen.insert(peer.to_socket_addr()) {
                deduped.push(peer);
            }
        }
        deduped
    }

    /// Handle a TxSet message from the network.
    async fn handle_tx_set(&self, tx_set: stellar_xdr::curr::TransactionSet) {
        use stellar_core_herder::TransactionSet;

        // For legacy TransactionSet, hash is SHA-256 of previous_ledger_hash + tx XDR blobs
        let transactions: Vec<_> = tx_set.txs.to_vec();
        let prev_hash = stellar_core_common::Hash256::from_bytes(tx_set.previous_ledger_hash.0);
        let hash = match TransactionSet::compute_non_generalized_hash(prev_hash, &transactions) {
            Some(hash) => hash,
            None => {
                tracing::error!("Failed to compute legacy TxSet hash");
                return;
            }
        };

        // Create our internal TransactionSet with correct hash
        let internal_tx_set = TransactionSet::with_hash(prev_hash, hash, transactions);
        {
            let mut map = self.tx_set_dont_have.write().await;
            map.remove(&internal_tx_set.hash);
        }
        {
            let mut map = self.tx_set_last_request.write().await;
            map.remove(&internal_tx_set.hash);
        }

        tracing::info!(
            hash = %internal_tx_set.hash,
            tx_count = internal_tx_set.transactions.len(),
            "Processing TxSet"
        );

        if !self.herder.needs_tx_set(&internal_tx_set.hash) {
            tracing::info!(hash = %internal_tx_set.hash, "TxSet not pending");
        }

        let received_slot = self.herder.receive_tx_set(internal_tx_set.clone());
        if let Some(slot) = received_slot {
            tracing::info!(slot, "Received pending TxSet, attempting ledger close");
            self.process_externalized_slots().await;
        } else if self.attach_tx_set_by_hash(&internal_tx_set).await
            || self.buffer_externalized_tx_set(&internal_tx_set).await
        {
            self.try_apply_buffered_ledgers().await;
        }
    }

    /// Handle a GeneralizedTxSet message from the network.
    async fn handle_generalized_tx_set(&self, gen_tx_set: stellar_xdr::curr::GeneralizedTransactionSet) {
        use stellar_xdr::curr::{GeneralizedTransactionSet, TransactionPhase, TxSetComponent, WriteXdr};
        use stellar_core_herder::TransactionSet;

        // Compute hash as SHA-256 of XDR-encoded GeneralizedTransactionSet
        // This matches how stellar-core computes it: xdrSha256(xdrTxSet)
        let xdr_bytes = match gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode GeneralizedTxSet to XDR");
                return;
            }
        };
        let hash = stellar_core_common::Hash256::hash(&xdr_bytes);

        // Extract transactions from GeneralizedTransactionSet
        let prev_hash = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                stellar_core_common::Hash256::from_bytes(v1.previous_ledger_hash.0)
            }
        };
        let transactions: Vec<stellar_xdr::curr::TransactionEnvelope> = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                if v1.phases.len() != 2 {
                    tracing::warn!(
                        hash = %hash,
                        phases = v1.phases.len(),
                        "Invalid GeneralizedTxSet phase count"
                    );
                    return;
                }
                v1.phases
                    .iter()
                    .flat_map(|phase| match phase {
                        TransactionPhase::V0(components) => components
                            .iter()
                            .flat_map(|component| match component {
                                TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                                    comp.txs.to_vec()
                                }
                            })
                            .collect::<Vec<_>>(),
                        TransactionPhase::V1(parallel) => parallel
                            .execution_stages
                            .iter()
                            .flat_map(|stage| stage.0.iter().flat_map(|cluster| cluster.0.to_vec()))
                            .collect(),
                    })
                    .collect()
            }
        };

        tracing::info!(
            hash = %hash,
            tx_count = transactions.len(),
            "Processing GeneralizedTxSet"
        );

        if !self.herder.needs_tx_set(&hash) {
            tracing::info!(hash = %hash, "GeneralizedTxSet not pending");
        }

        let phase_check = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                let classic_ok = matches!(v1.phases[0], TransactionPhase::V0(_));
                let soroban_ok = matches!(
                    v1.phases[1],
                    TransactionPhase::V1(_) | TransactionPhase::V0(_)
                );
                if !classic_ok || !soroban_ok {
                    tracing::warn!(hash = %hash, "Invalid GeneralizedTxSet phase types");
                }
                classic_ok && soroban_ok
            }
        };
        if !phase_check {
            return;
        }

        let base_fee_limit = self.ledger_manager.current_header().base_fee as i64;
        let base_fee_ok = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                let classic_ok = match &v1.phases[0] {
                    TransactionPhase::V0(components) => components.iter().all(|component| {
                        let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = component;
                        comp.base_fee.map_or(true, |fee| fee >= base_fee_limit)
                    }),
                    _ => false,
                };
                let soroban_ok = match &v1.phases[1] {
                    TransactionPhase::V1(parallel) => {
                        parallel.base_fee.map_or(true, |fee| fee >= base_fee_limit)
                    }
                    TransactionPhase::V0(components) => components.iter().all(|component| {
                        let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = component;
                        comp.base_fee.map_or(true, |fee| fee >= base_fee_limit)
                    }),
                };
                classic_ok && soroban_ok
            }
        };
        if !base_fee_ok {
            tracing::warn!(hash = %hash, base_fee = base_fee_limit, "GeneralizedTxSet base fee below ledger base fee");
            return;
        }

        let network_id = NetworkId(self.network_id());
        let mut classic_count = 0usize;
        let mut soroban_count = 0usize;
        for env in &transactions {
            let frame = stellar_core_tx::TransactionFrame::with_network(env.clone(), network_id);
            if frame.is_soroban() {
                soroban_count += 1;
            } else {
                classic_count += 1;
            }
        }
        let phase_sizes = match &gen_tx_set {
            GeneralizedTransactionSet::V1(v1) => {
                let classic_phase_count: usize = match &v1.phases[0] {
                    TransactionPhase::V0(components) => components
                        .iter()
                        .map(|component| match component {
                            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => comp.txs.len(),
                        })
                        .sum(),
                    _ => 0,
                };
                let soroban_phase_count: usize = match &v1.phases[1] {
                    TransactionPhase::V1(parallel) => parallel
                        .execution_stages
                        .iter()
                        .map(|stage| {
                            stage
                                .0
                                .iter()
                                .map(|cluster| cluster.0.len())
                                .sum::<usize>()
                        })
                        .sum(),
                    TransactionPhase::V0(components) => components
                        .iter()
                        .map(|component| match component {
                            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => comp.txs.len(),
                        })
                        .sum(),
                };
                (classic_phase_count, soroban_phase_count)
            }
        };
        if classic_count != phase_sizes.0 || soroban_count != phase_sizes.1 {
            tracing::warn!(
                hash = %hash,
                classic = classic_count,
                soroban = soroban_count,
                classic_phase = phase_sizes.0,
                soroban_phase = phase_sizes.1,
                "GeneralizedTxSet phase tx type mismatch"
            );
            return;
        }

        // Create internal tx set with the correct hash and retain generalized set
        let internal_tx_set =
            TransactionSet::with_generalized(prev_hash, hash, transactions, gen_tx_set);
        {
            let mut map = self.tx_set_dont_have.write().await;
            map.remove(&internal_tx_set.hash);
        }
        {
            let mut map = self.tx_set_last_request.write().await;
            map.remove(&internal_tx_set.hash);
        }

        let received_slot = self.herder.receive_tx_set(internal_tx_set.clone());
        if let Some(slot) = received_slot {
            tracing::info!(slot, "Received pending GeneralizedTxSet, attempting ledger close");
            self.try_close_slot_directly(slot).await;
        } else if self.attach_tx_set_by_hash(&internal_tx_set).await
            || self.buffer_externalized_tx_set(&internal_tx_set).await
        {
            self.try_apply_buffered_ledgers().await;
        }
    }

    /// Send a TxSet to a peer in response to GetTxSet.
    async fn send_tx_set(&self, peer_id: &stellar_core_overlay::PeerId, hash: &[u8; 32]) {
        let hash256 = stellar_core_common::Hash256::from_bytes(*hash);

        // Get the tx set from cache
        let tx_set = match self.herder.get_tx_set(&hash256) {
            Some(ts) => ts,
            None => {
                tracing::debug!(hash = hex::encode(hash), peer = ?peer_id, "TxSet not found in cache");
                let overlay = self.overlay.lock().await;
                if let Some(ref overlay) = *overlay {
                    let ledger_version = self.ledger_manager.current_header().ledger_version;
                    let message_type = if ledger_version >= 20 {
                        stellar_xdr::curr::MessageType::GeneralizedTxSet
                    } else {
                        stellar_xdr::curr::MessageType::TxSet
                    };
                    let msg = StellarMessage::DontHave(stellar_xdr::curr::DontHave {
                        type_: message_type,
                        req_hash: stellar_xdr::curr::Uint256(*hash),
                    });
                    if let Err(e) = overlay.send_to(peer_id, msg).await {
                        tracing::debug!(hash = hex::encode(hash), peer = ?peer_id, error = %e, "Failed to send DontHave for TxSet");
                    }
                }
                return;
            }
        };

        let ledger_version = self.ledger_manager.current_header().ledger_version;
        if ledger_version >= 20 {
            if let Some(gen_tx_set) = tx_set
                .generalized_tx_set
                .clone()
                .or_else(|| build_generalized_tx_set(&tx_set))
            {
                let gen_hash = match gen_tx_set.to_xdr(stellar_xdr::curr::Limits::none()) {
                    Ok(bytes) => stellar_core_common::Hash256::hash(&bytes),
                    Err(e) => {
                        tracing::warn!(hash = %hash256, error = %e, "Failed to encode GeneralizedTxSet");
                        stellar_core_common::Hash256::ZERO
                    }
                };
                if gen_hash == hash256 {
                    let message = StellarMessage::GeneralizedTxSet(gen_tx_set);
                    let overlay = self.overlay.lock().await;
                    if let Some(ref overlay) = *overlay {
                        if let Err(e) = overlay.send_to(peer_id, message).await {
                            tracing::warn!(hash = %hash256, peer = ?peer_id, error = %e, "Failed to send GeneralizedTxSet");
                        } else {
                            tracing::debug!(hash = %hash256, peer = ?peer_id, "Sent GeneralizedTxSet");
                        }
                    }
                    return;
                }
                tracing::warn!(hash = %hash256, computed = %gen_hash, "GeneralizedTxSet hash mismatch; falling back");
            }
        }

        // Convert to legacy XDR TransactionSet
        let prev_hash = tx_set.previous_ledger_hash;
        let xdr_tx_set = stellar_xdr::curr::TransactionSet {
            previous_ledger_hash: Hash::from(prev_hash),
            txs: tx_set.transactions.try_into().unwrap_or_default(),
        };

        let message = StellarMessage::TxSet(xdr_tx_set);

        let overlay = self.overlay.lock().await;
        if let Some(ref overlay) = *overlay {
            if let Err(e) = overlay.send_to(peer_id, message).await {
                tracing::warn!(hash = hex::encode(hash), peer = ?peer_id, error = %e, "Failed to send TxSet");
            } else {
                tracing::debug!(hash = hex::encode(hash), peer = ?peer_id, "Sent TxSet");
            }
        }
    }

    /// Request pending transaction sets from peers.
    async fn request_pending_tx_sets(&self) {
        let current_ledger = match self.get_current_ledger().await {
            Ok(seq) => seq,
            Err(_) => return,
        };
        let min_slot = current_ledger.saturating_add(1) as u64;
        let window_end = current_ledger as u64 + TX_SET_REQUEST_WINDOW;
        let mut pending = self.herder.get_pending_tx_sets();
        pending.sort_by_key(|(_, slot)| *slot);
        let pending_hashes: Vec<Hash256> = pending
            .into_iter()
            .filter(|(_, slot)| *slot >= min_slot && *slot <= window_end)
            .map(|(hash, _)| hash)
            .take(MAX_TX_SET_REQUESTS_PER_TICK)
            .collect();
        if pending_hashes.is_empty() {
            return;
        }

        let overlay = self.overlay.lock().await;
        let overlay = match overlay.as_ref() {
            Some(o) => o,
            None => {
                tracing::warn!("No overlay available to request tx sets");
                return;
            }
        };

        let peer_infos = overlay.peer_infos();
        if peer_infos.is_empty() {
            tracing::warn!("No peers connected, cannot request tx sets");
            return;
        }
        let mut peers = Vec::new();
        let mut fallback = Vec::new();
        for info in peer_infos {
            fallback.push(info.peer_id.clone());
            let is_outbound = matches!(info.direction, ConnectionDirection::Outbound);
            let is_preferred = if is_outbound {
                true
            } else {
                let host = info.address.ip().to_string();
                let port = info.address.port();
                match self.db.load_peer(&host, port) {
                    Ok(Some(record)) => {
                        record.peer_type == PEER_TYPE_PREFERRED
                            || record.peer_type == PEER_TYPE_OUTBOUND
                    }
                    _ => false,
                }
            };
            if is_outbound || is_preferred {
                peers.push(info.peer_id);
            }
        }
        if peers.is_empty() {
            peers = fallback;
        }
        peers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let now = Instant::now();
        let requests: Vec<(Hash256, stellar_core_overlay::PeerId)> = {
            let mut dont_have = self.tx_set_dont_have.write().await;
            let pending_set: HashSet<Hash256> = pending_hashes.iter().copied().collect();
            dont_have.retain(|hash, _| pending_set.contains(hash));
            let mut last_request = self.tx_set_last_request.write().await;
            last_request.retain(|hash, _| pending_set.contains(hash));

            pending_hashes
                .iter()
                .filter_map(|hash| {
                    if !self.herder.needs_tx_set(hash) {
                        return None;
                    }
                    let throttle = std::time::Duration::from_millis(200);
                    let mut request_state = last_request.get(hash).cloned().unwrap_or(
                        TxSetRequestState {
                            last_request: now
                                .checked_sub(throttle)
                                .unwrap_or(now),
                            next_peer_offset: 0,
                        },
                    );
                    if now.duration_since(request_state.last_request) < throttle {
                        return None;
                    }
                    let start_idx = Self::tx_set_start_index(
                        hash,
                        peers.len(),
                        request_state.next_peer_offset,
                    );
                    let eligible_peer = match dont_have.get_mut(hash) {
                        Some(set) => {
                            let mut found = None;
                            for offset in 0..peers.len() {
                                let idx = (start_idx + offset) % peers.len();
                                let peer = &peers[idx];
                                if !set.contains(peer) {
                                    found = Some(peer);
                                    break;
                                }
                            }
                            found.or_else(|| {
                                set.clear();
                                peers.get(start_idx)
                            })
                        }
                        None => peers.get(start_idx),
                    };

                    eligible_peer
                        .cloned()
                        .map(|peer_id| {
                            request_state.last_request = now;
                            request_state.next_peer_offset =
                                request_state.next_peer_offset.saturating_add(1);
                            last_request.insert(*hash, request_state);
                            (*hash, peer_id)
                        })
                })
                .collect()
        };

        for (hash, peer_id) in requests {
            tracing::info!(hash = %hash, peer = ?peer_id, "Requesting tx set");
            let request = StellarMessage::GetTxSet(stellar_xdr::curr::Uint256(hash.0));
            if let Err(e) = overlay.send_to(&peer_id, request).await {
                tracing::warn!(hash = %hash, peer = ?peer_id, error = %e, "Failed to request TxSet");
            }
        }
    }

    /// Log current stats.
    async fn log_stats(&self) {
        let stats = self.herder.stats();
        let ledger = *self.current_ledger.read().await;

        // Get overlay stats if available
        let (peer_count, flood_stats) = {
            let overlay = self.overlay.lock().await;
            match overlay.as_ref() {
                Some(o) => (o.peer_count(), Some(o.flood_stats())),
                None => (0, None),
            }
        };

        tracing::info!(
            state = ?stats.state,
            tracking_slot = stats.tracking_slot,
            pending_txs = stats.pending_transactions,
            ledger,
            peers = peer_count,
            is_validator = self.is_validator,
            "Node status"
        );

        if let Some(fs) = flood_stats {
            tracing::debug!(
                seen_messages = fs.seen_count,
                dropped_messages = fs.dropped_messages,
                "Flood gate stats"
            );
        }
    }

    /// Get the current ledger sequence from the database.
    async fn get_current_ledger(&self) -> anyhow::Result<u32> {
        // Check if ledger manager is initialized
        if self.ledger_manager.is_initialized() {
            return Ok(self.ledger_manager.current_ledger_seq());
        }
        // No state yet
        Ok(0)
    }

    /// Signal the application to shut down.
    pub fn shutdown(&self) {
        tracing::info!("Shutdown requested");
        let _ = self.shutdown_tx.send(());
    }

    /// Subscribe to shutdown notifications.
    pub fn subscribe_shutdown(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Internal shutdown cleanup.
    async fn shutdown_internal(&self) -> anyhow::Result<()> {
        tracing::info!("Performing shutdown cleanup");

        self.set_state(AppState::ShuttingDown).await;
        self.stop_survey_reporting().await;

        let mut overlay = self.overlay.lock().await;
        if let Some(mut overlay) = overlay.take() {
            if let Err(err) = overlay.shutdown().await {
                tracing::warn!(error = %err, "Overlay shutdown reported error");
            }
        }

        Ok(())
    }

    /// Get application info.
    pub fn info(&self) -> AppInfo {
        AppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_name: self.config.node.name.clone(),
            public_key: self.keypair.public_key().to_strkey(),
            network_passphrase: self.config.network.passphrase.clone(),
            is_validator: self.config.node.is_validator,
            database_path: self.config.database.path.clone(),
        }
    }

    /// Return the local quorum set if configured.
    pub fn local_quorum_set(&self) -> Option<stellar_xdr::curr::ScpQuorumSet> {
        self.herder.local_quorum_set()
    }
}

fn update_peer_record(db: &stellar_core_db::Database, event: PeerEvent) {
    let now = current_epoch_seconds();
    match event {
        PeerEvent::Connected(addr, peer_type) => {
            let existing = db.load_peer(&addr.host, addr.port).ok().flatten();
            let existing_type = existing
                .map(|r| r.peer_type)
                .unwrap_or(PEER_TYPE_INBOUND);
            let mapped = match peer_type {
                PeerType::Inbound => match existing_type {
                    PEER_TYPE_PREFERRED => PEER_TYPE_PREFERRED,
                    PEER_TYPE_OUTBOUND => PEER_TYPE_OUTBOUND,
                    _ => PEER_TYPE_INBOUND,
                },
                PeerType::Outbound => {
                    if existing_type == PEER_TYPE_PREFERRED {
                        PEER_TYPE_PREFERRED
                    } else {
                        PEER_TYPE_OUTBOUND
                    }
                }
            };
            let record = stellar_core_db::queries::PeerRecord::new(now, 0, mapped);
            let _ = db.store_peer(&addr.host, addr.port, record);
        }
        PeerEvent::Failed(addr, peer_type) => {
            let existing = db.load_peer(&addr.host, addr.port).ok().flatten();
            let mut failures = existing.map(|r| r.num_failures).unwrap_or(0);
            failures = failures.saturating_add(1);
            let backoff = compute_peer_backoff_secs(failures);
            let next_attempt = now.saturating_add(backoff);
            let existing_type = existing
                .map(|r| r.peer_type)
                .unwrap_or(PEER_TYPE_INBOUND);
            let mapped = match peer_type {
                PeerType::Inbound => match existing_type {
                    PEER_TYPE_PREFERRED => PEER_TYPE_PREFERRED,
                    PEER_TYPE_OUTBOUND => PEER_TYPE_OUTBOUND,
                    _ => PEER_TYPE_INBOUND,
                },
                PeerType::Outbound => {
                    if existing_type == PEER_TYPE_PREFERRED {
                        PEER_TYPE_PREFERRED
                    } else {
                        PEER_TYPE_OUTBOUND
                    }
                }
            };
            let record = stellar_core_db::queries::PeerRecord::new(next_attempt, failures, mapped);
            let _ = db.store_peer(&addr.host, addr.port, record);
        }
    }
}

fn compute_peer_backoff_secs(failures: u32) -> i64 {
    const SECONDS_PER_BACKOFF: u64 = 10;
    const MAX_BACKOFF_EXPONENT: u32 = 10;
    let exp = failures.min(MAX_BACKOFF_EXPONENT);
    let max = SECONDS_PER_BACKOFF.saturating_mul(1u64 << exp);
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(1..=max.max(1));
    jitter as i64
}

fn current_epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Target for catchup operation.
#[derive(Debug, Clone, Copy)]
pub enum CatchupTarget {
    /// Catch up to the current/latest ledger.
    Current,
    /// Catch up to a specific ledger sequence.
    Ledger(u32),
    /// Catch up to a specific checkpoint number.
    Checkpoint(u32),
}

/// Result of a catchup operation.
#[derive(Debug, Clone)]
pub struct CatchupResult {
    /// Final ledger sequence.
    pub ledger_seq: u32,
    /// Hash of the final ledger.
    pub ledger_hash: stellar_core_common::Hash256,
    /// Number of buckets applied.
    pub buckets_applied: u32,
    /// Number of ledgers replayed.
    pub ledgers_replayed: u32,
}

impl std::fmt::Display for CatchupResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Caught up to ledger {} (hash: {}, {} buckets, {} ledgers replayed)",
            self.ledger_seq,
            &self.ledger_hash.to_hex()[..16],
            self.buckets_applied,
            self.ledgers_replayed
        )
    }
}

/// Application info for the info command.
#[derive(Debug, Clone)]
pub struct AppInfo {
    /// Application version.
    pub version: String,
    /// Node name.
    pub node_name: String,
    /// Node public key.
    pub public_key: String,
    /// Network passphrase.
    pub network_passphrase: String,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Database path.
    pub database_path: std::path::PathBuf,
}

#[derive(Debug, Clone)]
pub struct ScpSlotSnapshot {
    pub slot_index: u64,
    pub is_externalized: bool,
    pub is_nominating: bool,
    pub ballot_phase: String,
    pub nomination_round: u32,
    pub ballot_round: Option<u32>,
    pub envelope_count: usize,
}

#[derive(Debug, Clone)]
pub struct SelfCheckResult {
    pub ok: bool,
    pub checked_ledgers: u32,
    pub last_checked_ledger: Option<u32>,
}

impl std::fmt::Display for AppInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "rs-stellar-core {}", self.version)?;
        writeln!(f)?;
        writeln!(f, "Node Information:")?;
        writeln!(f, "  Name:       {}", self.node_name)?;
        writeln!(f, "  Public Key: {}", self.public_key)?;
        writeln!(f, "  Validator:  {}", self.is_validator)?;
        writeln!(f)?;
        writeln!(f, "Network:")?;
        writeln!(f, "  Passphrase: {}", self.network_passphrase)?;
        writeln!(f)?;
        writeln!(f, "Storage:")?;
        writeln!(f, "  Database:   {}", self.database_path.display())?;
        Ok(())
    }
}

/// Application builder for more flexible initialization.
pub struct AppBuilder {
    config: Option<AppConfig>,
    config_path: Option<std::path::PathBuf>,
}

impl AppBuilder {
    /// Create a new application builder.
    pub fn new() -> Self {
        Self {
            config: None,
            config_path: None,
        }
    }

    /// Use the given configuration.
    pub fn with_config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Load configuration from a file.
    pub fn with_config_file(mut self, path: impl AsRef<Path>) -> Self {
        self.config_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build the application.
    pub async fn build(self) -> anyhow::Result<App> {
        let config = if let Some(config) = self.config {
            config
        } else if let Some(path) = self.config_path {
            AppConfig::from_file_with_env(&path)?
        } else {
            AppConfig::default()
        };

        App::new(config).await
    }
}

impl Default for AppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of HerderCallback for App.
///
/// This enables the herder to trigger ledger closes through the app.
#[async_trait::async_trait]
impl HerderCallback for App {
    async fn close_ledger(
        &self,
        ledger_seq: u32,
        tx_set: stellar_core_herder::TransactionSet,
        close_time: u64,
        upgrades: Vec<UpgradeType>,
    ) -> stellar_core_herder::Result<stellar_core_common::Hash256> {
        let tx_summary = tx_set.summary();
        tracing::info!(
            ledger_seq,
            tx_count = tx_set.transactions.len(),
            close_time,
            summary = %tx_summary,
            "Closing ledger"
        );

        // Get the previous ledger hash
        let prev_hash = tx_set.previous_ledger_hash;

        // Create the transaction set
        let tx_set_variant = if let Some(gen_tx_set) = tx_set.generalized_tx_set.clone() {
            TransactionSetVariant::Generalized(gen_tx_set)
        } else {
            TransactionSetVariant::Classic(TransactionSet {
                previous_ledger_hash: Hash::from(prev_hash),
                txs: tx_set.transactions.clone().try_into().map_err(|_| {
                    stellar_core_herder::HerderError::Internal("Failed to create tx set".into())
                })?,
            })
        };

        // Create close data
        let mut close_data = LedgerCloseData::new(
            ledger_seq,
            tx_set_variant.clone(),
            close_time,
            prev_hash,
        );
        let decoded_upgrades = decode_upgrades(upgrades);
        if !decoded_upgrades.is_empty() {
            close_data = close_data.with_upgrades(decoded_upgrades);
        }

        // Begin the ledger close
        let mut close_ctx = self.ledger_manager.begin_close(close_data).map_err(|e| {
            stellar_core_herder::HerderError::Internal(format!("Failed to begin close: {}", e))
        })?;

        // Apply transactions
        let results = close_ctx.apply_transactions().map_err(|e| {
            stellar_core_herder::HerderError::Internal(format!("Failed to apply transactions: {}", e))
        })?;

        let success_count = results.iter().filter(|r| r.success).count();
        let fail_count = results.len() - success_count;
        tracing::info!(
            ledger_seq,
            tx_success = success_count,
            tx_failed = fail_count,
            "Transactions applied"
        );

        // Commit the ledger
        let result = close_ctx.commit().map_err(|e| {
            stellar_core_herder::HerderError::Internal(format!("Failed to commit ledger: {}", e))
        })?;

        let tx_metas = result.meta.as_ref().map(Self::extract_tx_metas);
        if let Err(err) = self.persist_ledger_close(
            &result.header,
            &tx_set_variant,
            &result.tx_results,
            tx_metas.as_deref(),
        ) {
            tracing::warn!(error = %err, "Failed to persist ledger close data");
        }

        let applied_hashes: Vec<stellar_core_common::Hash256> = tx_set
            .transactions
            .iter()
            .filter_map(|tx| self.tx_hash(tx))
            .collect();
        self.herder
            .ledger_closed(ledger_seq as u64, &applied_hashes);
        self.herder.tx_queue().update_validation_context(
            ledger_seq,
            result.header.scp_value.close_time.0,
            result.header.ledger_version,
            result.header.base_fee,
        );

        // Update current ledger tracking
        *self.current_ledger.write().await = ledger_seq;
        self.clear_tx_advert_history(ledger_seq).await;

        tracing::info!(
            ledger_seq = result.ledger_seq(),
            hash = %result.header_hash.to_hex(),
            "Ledger closed successfully"
        );

        Ok(result.header_hash)
    }

    async fn validate_tx_set(&self, _tx_set_hash: &stellar_core_common::Hash256) -> bool {
        // For now, accept all transaction sets
        // In a full implementation, this would:
        // 1. Check we have the tx set locally
        // 2. Validate all transactions are valid
        // 3. Check the tx set hash matches
        true
    }

    async fn broadcast_scp_message(&self, envelope: ScpEnvelope) {
        let slot = envelope.statement.slot_index;
        // Send through the channel to be picked up by the main loop
        if let Err(e) = self.scp_envelope_tx.try_send(envelope) {
            tracing::warn!(slot, error = %e, "Failed to queue SCP envelope for broadcast");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[tokio::test]
    async fn test_app_creation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        assert_eq!(app.state().await, AppState::Initializing);
    }

    #[tokio::test]
    async fn test_app_info() {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("rs-stellar-test.db");
        let config = crate::config::ConfigBuilder::new()
            .node_name("test-node")
            .database_path(db_path)
            .build();

        let app = App::new(config).await.unwrap();
        let info = app.info();

        assert_eq!(info.node_name, "test-node");
        assert!(!info.public_key.is_empty());
        assert!(info.public_key.starts_with('G'));
    }

    #[test]
    fn test_catchup_result_display() {
        let result = CatchupResult {
            ledger_seq: 1000,
            ledger_hash: stellar_core_common::Hash256::ZERO,
            buckets_applied: 22,
            ledgers_replayed: 64,
        };

        let display = format!("{}", result);
        assert!(display.contains("1000"));
        assert!(display.contains("22 buckets"));
    }

    #[test]
    fn test_buffered_catchup_target_large_gap() {
        let current = 100;
        let first_buffered = current + CHECKPOINT_FREQUENCY + 5;
        let target = App::buffered_catchup_target(current, first_buffered, first_buffered);
        assert_eq!(target, Some(first_buffered - 1));
    }

    #[test]
    fn test_buffered_catchup_target_requires_trigger() {
        let current = 100;
        let first_buffered = 120;
        let last_buffered = 120;
        let target = App::buffered_catchup_target(current, first_buffered, last_buffered);
        assert_eq!(target, None);

        let last_buffered = 130;
        let target = App::buffered_catchup_target(current, first_buffered, last_buffered);
        assert_eq!(target, Some(127));
    }

    #[test]
    fn test_tx_set_start_index_rotation() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(App::tx_set_start_index(&hash, 3, 0), 1);
        assert_eq!(App::tx_set_start_index(&hash, 3, 1), 2);
        assert_eq!(App::tx_set_start_index(&hash, 3, 2), 0);
        assert_eq!(App::tx_set_start_index(&hash, 3, 3), 1);
    }
}
