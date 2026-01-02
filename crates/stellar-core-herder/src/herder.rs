//! Main Herder implementation.
//!
//! The Herder is the central coordinator that drives consensus and manages
//! the transition between ledgers. It integrates with:
//!
//! - SCP for consensus
//! - Overlay for network communication
//! - Ledger for state management
//! - Transaction processing

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tracing::{debug, info, warn, error};

use stellar_core_common::Hash256;
use stellar_core_crypto::{PublicKey, SecretKey};
use stellar_core_ledger::LedgerManager;
use stellar_core_scp::{SCP, SlotIndex};
use stellar_xdr::curr::{
    NodeId, ReadXdr, ScpEnvelope, ScpQuorumSet, StellarValue, TimePoint, TransactionEnvelope,
    UpgradeType, Value, WriteXdr, Limits,
};

use crate::error::HerderError;
use crate::pending::{PendingConfig, PendingEnvelopes, PendingResult};
use crate::quorum_tracker::{QuorumTracker, SlotQuorumTracker};
use crate::scp_driver::{HerderScpCallback, ScpDriver, ScpDriverConfig, ValueValidation};
use crate::state::HerderState;
use crate::tx_queue::{
    account_key_from_account_id, TransactionQueue, TransactionSet, TxQueueConfig, TxQueueResult,
};
pub use crate::tx_queue::TransactionSet as TxSet;
use crate::Result;

/// Maximum slot distance for accepting EXTERNALIZE messages.
///
/// EXTERNALIZE messages from future slots can fast-forward our tracking slot,
/// but we need to limit this to prevent malicious nodes from making us catch up
/// to non-existent slots. This limit (1000 ledgers, ~83 minutes at 5s/ledger)
/// is generous enough to handle network partitions while preventing attacks.
const MAX_EXTERNALIZE_SLOT_DISTANCE: u64 = 1000;

/// Result of receiving an SCP envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeState {
    /// Envelope was processed successfully.
    Valid,
    /// Envelope is for a future slot and was buffered.
    Pending,
    /// Envelope is a duplicate.
    Duplicate,
    /// Envelope is for an old slot.
    TooOld,
    /// Envelope has invalid signature.
    InvalidSignature,
    /// Envelope is invalid.
    Invalid,
}

/// Configuration for the Herder.
#[derive(Debug, Clone)]
pub struct HerderConfig {
    /// Maximum number of pending transactions.
    pub max_pending_transactions: usize,
    /// Whether this node should participate in consensus as a validator.
    pub is_validator: bool,
    /// Target ledger close time in seconds.
    pub ledger_close_time: u32,
    /// Our node's public key.
    pub node_public_key: PublicKey,
    /// Network ID hash.
    pub network_id: Hash256,
    /// Maximum number of slots to keep externalized values for.
    pub max_externalized_slots: usize,
    /// Pending envelope configuration.
    pub pending_config: PendingConfig,
    /// Transaction queue configuration.
    pub tx_queue_config: TxQueueConfig,
    /// Local quorum set configuration.
    pub local_quorum_set: Option<ScpQuorumSet>,
    /// Maximum transactions per transaction set.
    pub max_tx_set_size: usize,
    /// Proposed protocol upgrades to include in nominations.
    pub proposed_upgrades: Vec<stellar_xdr::curr::LedgerUpgrade>,
}

const DEFAULT_MAX_EXTERNALIZED_SLOTS: usize = 12;

impl Default for HerderConfig {
    fn default() -> Self {
        Self {
            max_pending_transactions: 1000,
            is_validator: false,
            ledger_close_time: 5,
            node_public_key: PublicKey::from_bytes(&[0u8; 32]).unwrap(),
            network_id: Hash256::ZERO,
            max_externalized_slots: DEFAULT_MAX_EXTERNALIZED_SLOTS,
            pending_config: PendingConfig::default(),
            tx_queue_config: TxQueueConfig::default(),
            local_quorum_set: None,
            max_tx_set_size: 1000,
            proposed_upgrades: Vec::new(),
        }
    }
}

/// The main Herder that coordinates consensus.
///
/// This is the central component that:
/// - Receives transactions from the network
/// - Receives SCP envelopes from the network
/// - Drives consensus for ledger close
/// - Tracks externalized values
pub struct Herder {
    /// Configuration.
    config: HerderConfig,
    /// Current state.
    state: RwLock<HerderState>,
    /// Transaction queue.
    tx_queue: TransactionQueue,
    /// Pending envelopes for future slots.
    pending_envelopes: PendingEnvelopes,
    /// SCP driver for consensus callbacks.
    scp_driver: Arc<ScpDriver>,
    /// SCP consensus protocol instance.
    scp: Option<SCP<HerderScpCallback>>,
    /// Current tracking slot (ledger sequence as u64).
    tracking_slot: RwLock<u64>,
    /// When we started tracking.
    tracking_started_at: RwLock<Option<Instant>>,
    /// Secret key for signing (if validator).
    secret_key: Option<SecretKey>,
    /// Ledger manager reference (optional, for validation).
    ledger_manager: RwLock<Option<Arc<LedgerManager>>>,
    /// Previous externalized value (for priority calculation).
    prev_value: RwLock<Value>,
    /// Slot-level quorum tracker for heard-from quorum/v-blocking checks.
    slot_quorum_tracker: RwLock<SlotQuorumTracker>,
    /// Transitive quorum tracker for the current quorum map.
    quorum_tracker: RwLock<QuorumTracker>,
}

impl Herder {
    /// Create a new Herder.
    pub fn new(config: HerderConfig) -> Self {
        let mut pending_config = config.pending_config.clone();
        let max_slots = config.max_externalized_slots.max(1);
        pending_config.max_slots = pending_config.max_slots.min(max_slots);
        pending_config.max_slot_distance =
            pending_config.max_slot_distance.min(max_slots as u64);

        let max_time_drift = (max_slots as u64).saturating_add(2)
            .saturating_mul(config.ledger_close_time as u64);
        let scp_driver_config = ScpDriverConfig {
            node_id: config.node_public_key.clone(),
            max_tx_set_cache: 100,
            max_time_drift,
            local_quorum_set: config.local_quorum_set.clone(),
        };

        let scp_driver = Arc::new(ScpDriver::new(scp_driver_config, config.network_id));
        let tx_queue = TransactionQueue::new(config.tx_queue_config.clone());
        let pending_envelopes = PendingEnvelopes::new(pending_config);

        // SCP is None for non-validators (they just observe)
        let slot_quorum_tracker =
            SlotQuorumTracker::new(config.local_quorum_set.clone(), max_slots);
        let local_node_id = node_id_from_public_key(&config.node_public_key);
        let mut quorum_tracker = QuorumTracker::new(local_node_id.clone());
        if let Some(ref quorum_set) = config.local_quorum_set {
            let _ = quorum_tracker.expand(&local_node_id, quorum_set.clone());
        }

        Self {
            config,
            state: RwLock::new(HerderState::Booting),
            tx_queue,
            pending_envelopes,
            scp_driver,
            scp: None,
            tracking_slot: RwLock::new(0),
            tracking_started_at: RwLock::new(None),
            secret_key: None,
            ledger_manager: RwLock::new(None),
            prev_value: RwLock::new(Value::default()),
            slot_quorum_tracker: RwLock::new(slot_quorum_tracker),
            quorum_tracker: RwLock::new(quorum_tracker),
        }
    }

    /// Create a new Herder with a secret key for validation.
    pub fn with_secret_key(config: HerderConfig, secret_key: SecretKey) -> Self {
        let mut pending_config = config.pending_config.clone();
        let max_slots = config.max_externalized_slots.max(1);
        pending_config.max_slots = pending_config.max_slots.min(max_slots);
        pending_config.max_slot_distance =
            pending_config.max_slot_distance.min(max_slots as u64);

        let max_time_drift = (max_slots as u64).saturating_add(2)
            .saturating_mul(config.ledger_close_time as u64);
        let scp_driver_config = ScpDriverConfig {
            node_id: config.node_public_key.clone(),
            max_tx_set_cache: 100,
            max_time_drift,
            local_quorum_set: config.local_quorum_set.clone(),
        };

        let scp_driver = Arc::new(ScpDriver::with_secret_key(
            scp_driver_config,
            config.network_id,
            secret_key.clone(),
        ));

        let tx_queue = TransactionQueue::new(config.tx_queue_config.clone());
        let pending_envelopes = PendingEnvelopes::new(pending_config);

        // Create SCP instance for validators
        let node_id = node_id_from_public_key(&config.node_public_key);
        let scp = if config.is_validator {
            if let Some(ref quorum_set) = config.local_quorum_set {
                let callback = HerderScpCallback::new(Arc::clone(&scp_driver));
                Some(SCP::new(
                    node_id.clone(),
                    true, // is_validator
                    quorum_set.clone(),
                    Arc::new(callback),
                ))
            } else {
                warn!("Validator mode requested but no quorum set configured");
                None
            }
        } else {
            None
        };

        let slot_quorum_tracker =
            SlotQuorumTracker::new(config.local_quorum_set.clone(), max_slots);
        let mut quorum_tracker = QuorumTracker::new(node_id.clone());
        if let Some(ref quorum_set) = config.local_quorum_set {
            let _ = quorum_tracker.expand(&node_id, quorum_set.clone());
        }

        Self {
            config,
            state: RwLock::new(HerderState::Booting),
            tx_queue,
            pending_envelopes,
            scp_driver,
            scp,
            tracking_slot: RwLock::new(0),
            tracking_started_at: RwLock::new(None),
            secret_key: Some(secret_key),
            ledger_manager: RwLock::new(None),
            prev_value: RwLock::new(Value::default()),
            slot_quorum_tracker: RwLock::new(slot_quorum_tracker),
            quorum_tracker: RwLock::new(quorum_tracker),
        }
    }

    /// Set the ledger manager reference.
    pub fn set_ledger_manager(&self, manager: Arc<LedgerManager>) {
        self.scp_driver.set_ledger_manager(Arc::clone(&manager));
        *self.ledger_manager.write() = Some(manager);
    }

    /// Get the current state of the Herder.
    pub fn state(&self) -> HerderState {
        *self.state.read()
    }

    /// Get the current tracking slot.
    pub fn tracking_slot(&self) -> u64 {
        *self.tracking_slot.read()
    }

    /// Compute the minimum ledger sequence to ask peers for SCP state.
    pub fn get_min_ledger_seq_to_ask_peers(&self) -> u32 {
        let lcl = self
            .ledger_manager
            .read()
            .as_ref()
            .map(|manager| manager.current_ledger_seq())
            .unwrap_or_else(|| self.tracking_slot().min(u32::MAX as u64) as u32);
        let mut low = lcl.saturating_add(1);
        let max_slots = self.config.max_externalized_slots.max(1) as u32;
        let extra = 3u32;
        let window = max_slots.min(extra);
        if low > window {
            low = low.saturating_sub(window);
        } else {
            low = 1;
        }
        low
    }

    /// Get the configured target ledger close time in seconds.
    pub fn ledger_close_time(&self) -> u32 {
        self.config.ledger_close_time
    }

    /// Get the maximum size of a transaction set (ops).
    pub fn max_tx_set_size(&self) -> usize {
        self.config.max_tx_set_size
    }

    /// Get the maximum queue size in ops for demand sizing.
    pub fn max_queue_size_ops(&self) -> usize {
        self.config.max_pending_transactions
    }

    /// Return the set of node IDs from the local quorum set (if configured).
    pub fn local_quorum_nodes(&self) -> std::collections::HashSet<stellar_xdr::curr::NodeId> {
        fn collect_nodes(
            quorum_set: &stellar_xdr::curr::ScpQuorumSet,
            acc: &mut std::collections::HashSet<stellar_xdr::curr::NodeId>,
        ) {
            for validator in quorum_set.validators.iter() {
                acc.insert(validator.clone());
            }
            for inner in quorum_set.inner_sets.iter() {
                collect_nodes(inner, acc);
            }
        }

        let mut nodes = std::collections::HashSet::new();
        if let Some(qs) = &self.config.local_quorum_set {
            collect_nodes(qs, &mut nodes);
        }
        nodes
    }

    /// Check if the herder is tracking consensus.
    pub fn is_tracking(&self) -> bool {
        self.state().is_tracking()
    }

    /// Check if this node is a validator.
    pub fn is_validator(&self) -> bool {
        self.config.is_validator && self.secret_key.is_some()
    }

    /// Store a quorum set for a peer node.
    pub fn store_quorum_set(&self, node_id: &NodeId, quorum_set: ScpQuorumSet) {
        self.scp_driver
            .store_quorum_set(node_id, quorum_set.clone());
        let mut tracker = self.quorum_tracker.write();
        if !tracker.expand(node_id, quorum_set) {
            if let Err(err) = tracker.rebuild(|id| self.scp_driver.get_quorum_set(id)) {
                warn!(error = %err, "Failed to rebuild quorum tracker");
            }
        }
    }

    /// Get a quorum set by hash if available.
    pub fn get_quorum_set_by_hash(&self, hash: &[u8; 32]) -> Option<ScpQuorumSet> {
        self.scp_driver.get_quorum_set_by_hash(hash)
    }

    /// Whether we already have a quorum set with the given hash.
    pub fn has_quorum_set_hash(&self, hash: &Hash256) -> bool {
        self.scp_driver.has_quorum_set_hash(hash)
    }

    /// Register a quorum set request if needed.
    pub fn request_quorum_set(&self, hash: Hash256) -> bool {
        self.scp_driver.request_quorum_set(hash)
    }

    /// Clear a quorum set request.
    pub fn clear_quorum_set_request(&self, hash: &Hash256) {
        self.scp_driver.clear_quorum_set_request(hash);
    }

    /// Check whether we've heard from quorum for a slot.
    pub fn heard_from_quorum(&self, slot: SlotIndex) -> bool {
        self.slot_quorum_tracker.read().has_quorum(slot, |node_id| {
            self.scp_driver.get_quorum_set(node_id)
        })
    }

    /// Check whether we have a v-blocking set for a slot.
    pub fn is_v_blocking(&self, slot: SlotIndex) -> bool {
        self.slot_quorum_tracker.read().is_v_blocking(slot)
    }

    /// Bootstrap the Herder after catchup.
    ///
    /// This transitions the Herder from Syncing to Tracking state,
    /// setting the current ledger sequence as the tracking slot.
    pub fn bootstrap(&self, ledger_seq: u32) {
        let slot = ledger_seq as u64;

        info!("Bootstrapping Herder at ledger {}", ledger_seq);

        // Update tracking slot
        *self.tracking_slot.write() = slot;
        *self.tracking_started_at.write() = Some(Instant::now());

        // Update pending envelopes current slot
        self.pending_envelopes.set_current_slot(slot);

        // Transition to tracking state
        *self.state.write() = HerderState::Tracking;

        // Release any pending envelopes for this slot and previous
        let pending = self.pending_envelopes.release_up_to(slot);
        for (pending_slot, envelopes) in pending {
            debug!(
                "Released {} pending envelopes for slot {}",
                envelopes.len(),
                pending_slot
            );
            for envelope in envelopes {
                // Process released envelopes (ignore result as they may be old)
                let _ = self.process_scp_envelope(envelope);
            }
        }

        info!("Herder now tracking at slot {}", slot);
    }

    /// Start syncing (called when catchup begins).
    pub fn start_syncing(&self) {
        info!("Herder entering syncing state");
        *self.state.write() = HerderState::Syncing;
    }

    /// Receive an SCP envelope from the network.
    pub fn receive_scp_envelope(&self, envelope: ScpEnvelope) -> EnvelopeState {
        let state = self.state();
        let slot = envelope.statement.slot_index;
        let current_slot = self.tracking_slot();
        let pending_slot = self.pending_envelopes.current_slot();

        // Check if we can receive SCP messages
        if !state.can_receive_scp() {
            debug!("Ignoring SCP envelope in {:?} state", state);
            return EnvelopeState::Invalid;
        }

        // Verify envelope signature
        if let Err(e) = self.scp_driver.verify_envelope(&envelope) {
            debug!(slot, error = %e, "Invalid SCP envelope signature");
            return EnvelopeState::InvalidSignature;
        }

        self.slot_quorum_tracker
            .write()
            .record_envelope(slot, envelope.statement.node_id.clone());

        // Special handling for EXTERNALIZE messages - they can fast-forward our state
        // even if from future slots, as they represent network consensus
        if let stellar_xdr::curr::ScpStatementPledges::Externalize(ext) = &envelope.statement.pledges {
            // Extract tx set hash from the externalized value and request it immediately
            // This ensures we request tx sets as soon as we learn about them, not after externalization
            if let Ok(sv) = StellarValue::from_xdr(&ext.commit.value.0, Limits::none()) {
                let tx_set_hash = Hash256::from_bytes(sv.tx_set_hash.0);
                // Request this tx set immediately - don't wait for ledger close
                if self.scp_driver.request_tx_set(tx_set_hash, slot) {
                    info!(slot, hash = %tx_set_hash, "Immediately requesting tx set from EXTERNALIZE");
                }
            }

            if slot > current_slot {
                // Security check 1: Validate sender is in our transitive quorum
                // This prevents accepting EXTERNALIZE messages from nodes we don't trust
                let sender = &envelope.statement.node_id;
                let in_quorum = self.quorum_tracker.read().is_node_definitely_in_quorum(sender);
                if !in_quorum {
                    warn!(
                        slot,
                        current_slot,
                        sender = ?sender,
                        "Rejecting EXTERNALIZE from node not in quorum"
                    );
                    return EnvelopeState::Invalid;
                }

                // Security check 2: Reject slots that are unreasonably far in the future
                // This prevents malicious nodes from making us catch up to non-existent slots.
                let slot_distance = slot.saturating_sub(current_slot);
                if slot_distance > MAX_EXTERNALIZE_SLOT_DISTANCE {
                    warn!(
                        slot,
                        current_slot,
                        slot_distance,
                        max_distance = MAX_EXTERNALIZE_SLOT_DISTANCE,
                        "Rejecting EXTERNALIZE for slot too far in future"
                    );
                    return EnvelopeState::Invalid;
                }

                // Fast-forward to this slot using the externalized value
                info!(
                    slot,
                    current_slot,
                    "Fast-forwarding using EXTERNALIZE from network"
                );

                let value = ext.commit.value.clone();
                self.scp_driver.record_externalized(slot, value.clone());
                self.scp_driver
                    .cleanup_externalized(self.config.max_externalized_slots);

                // Store for reference
                *self.prev_value.write() = value;

                // Advance tracking slot
                self.advance_tracking_slot(slot);

                return EnvelopeState::Valid;
            }
        }

        // Check if this is for a future slot
        if slot > current_slot {
            // Buffer for later
            match self.pending_envelopes.add(slot, envelope) {
                PendingResult::Added => {
                    debug!("Buffered envelope for future slot {}", slot);
                    return EnvelopeState::Pending;
                }
                PendingResult::Duplicate => {
                    return EnvelopeState::Duplicate;
                }
                PendingResult::SlotTooFar => {
                    debug!(
                        slot,
                        current_slot,
                        pending_slot,
                        "Envelope rejected: slot too far ahead"
                    );
                    return EnvelopeState::Invalid;
                }
                PendingResult::SlotTooOld => {
                    return EnvelopeState::TooOld;
                }
                PendingResult::BufferFull => {
                    warn!("Pending envelope buffer full");
                    return EnvelopeState::Invalid;
                }
            }
        }

        // Process the envelope
        self.process_scp_envelope(envelope)
    }

    /// Process an SCP envelope (internal).
    fn process_scp_envelope(&self, envelope: ScpEnvelope) -> EnvelopeState {
        let slot = envelope.statement.slot_index;

        debug!(
            "Processing SCP envelope for slot {} from {:?}",
            slot, envelope.statement.node_id
        );

        // If we have SCP (validator mode), process through consensus
        if let Some(ref scp) = self.scp {
            let result = scp.receive_envelope(envelope.clone());

            match result {
                stellar_core_scp::EnvelopeState::Invalid => {
                    return EnvelopeState::Invalid;
                }
                stellar_core_scp::EnvelopeState::Valid => {
                    // Valid but not new
                    return EnvelopeState::Duplicate;
                }
                stellar_core_scp::EnvelopeState::ValidNew => {
                    if self.heard_from_quorum(slot) {
                        debug!(slot, "Heard from quorum");
                    }
                    // Check if this slot is now externalized
                    if scp.is_slot_externalized(slot) {
                        if let Some(value) = scp.get_externalized_value(slot) {
                            info!(slot, "Slot externalized via SCP consensus");
                            self.scp_driver.record_externalized(slot, value.clone());
                            self.scp_driver
                                .cleanup_externalized(self.config.max_externalized_slots);

                            // Store for next round's priority calculation
                            *self.prev_value.write() = value;

                            // Advance tracking slot
                            self.advance_tracking_slot(slot);
                        }
                    }
                    return EnvelopeState::Valid;
                }
            }
        }

        // Non-validator mode: just track externalized values from network
        if let stellar_xdr::curr::ScpStatementPledges::Externalize(ext) =
            &envelope.statement.pledges
        {
            if self.heard_from_quorum(slot) {
                debug!(slot, "Heard from quorum (observer)");
            }
            let value = ext.commit.value.clone();
            self.scp_driver.record_externalized(slot, value.clone());
            self.scp_driver
                .cleanup_externalized(self.config.max_externalized_slots);

            // Store for reference
            *self.prev_value.write() = value;

            // Advance tracking slot
            self.advance_tracking_slot(slot);
        }

        EnvelopeState::Valid
    }

    /// Advance tracking slot after externalization.
    fn advance_tracking_slot(&self, externalized_slot: u64) {
        let mut tracking = self.tracking_slot.write();
        if externalized_slot >= *tracking {
            *tracking = externalized_slot + 1;
            self.pending_envelopes.set_current_slot(externalized_slot + 1);

            // Release any pending envelopes for the new slot
            drop(tracking);
            let pending = self.pending_envelopes.release(externalized_slot + 1);
            for env in pending {
                let _ = self.process_scp_envelope(env);
            }
        }
    }

    /// Receive a transaction from the network.
    pub fn receive_transaction(&self, tx: TransactionEnvelope) -> TxQueueResult {
        let state = self.state();

        if !state.can_receive_transactions() {
            debug!("Ignoring transaction in {:?} state", state);
            return TxQueueResult::Invalid;
        }

        // Add to transaction queue
        let result = self.tx_queue.try_add(tx);

        match result {
            TxQueueResult::Added => {
                debug!(
                    "Added transaction to queue, size: {}",
                    self.tx_queue.len()
                );
            }
            TxQueueResult::Duplicate => {
                debug!("Duplicate transaction ignored");
            }
            TxQueueResult::QueueFull => {
                warn!("Transaction queue full");
            }
            TxQueueResult::FeeTooLow => {
                debug!("Transaction fee too low");
            }
            TxQueueResult::Invalid => {
                debug!("Invalid transaction rejected");
            }
        }

        result
    }

    /// Trigger consensus for the next ledger (for validators).
    ///
    /// This is called periodically by the consensus timer.
    pub async fn trigger_next_ledger(&self, ledger_seq: u32) -> Result<()> {
        if !self.is_validator() {
            return Err(HerderError::NotValidating);
        }

        if !self.is_tracking() {
            return Err(HerderError::NotValidating);
        }

        let scp = match &self.scp {
            Some(scp) => scp,
            None => return Err(HerderError::NotValidating),
        };

        let slot = ledger_seq as u64;
        info!("Triggering consensus for ledger {}", ledger_seq);

        // Get the previous ledger hash
        let previous_hash = if let Some(manager) = self.ledger_manager.read().as_ref() {
            manager.current_header_hash()
        } else {
            Hash256::ZERO
        };
        let starting_seq = self
            .ledger_manager
            .read()
            .as_ref()
            .and_then(|manager| self.build_starting_seq_map(manager));

        // Create transaction set from queue using the current ledger limit when available.
        let max_txs = self
            .ledger_manager
            .read()
            .as_ref()
            .map(|manager| manager.current_header().max_tx_set_size as usize)
            .unwrap_or(self.config.max_tx_set_size);
        let tx_set = self.tx_queue.get_transaction_set_with_starting_seq(
            previous_hash,
            max_txs,
            starting_seq.as_ref(),
        );

        info!(
            "Proposing transaction set with {} transactions, hash: {}",
            tx_set.len(),
            tx_set.hash
        );

        // Cache the transaction set
        self.scp_driver.cache_tx_set(tx_set.clone());

        // Create StellarValue for nomination
        let close_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let upgrades: Vec<UpgradeType> = self
            .config
            .proposed_upgrades
            .iter()
            .filter_map(|upgrade| upgrade.to_xdr(Limits::none()).ok())
            .filter_map(|bytes| bytes.try_into().ok().map(UpgradeType))
            .collect();

        let stellar_value = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set.hash.0),
            close_time: TimePoint(close_time),
            upgrades: upgrades.try_into().unwrap_or_default(),
            ext: stellar_xdr::curr::StellarValueExt::Basic,
        };

        // Encode to Value
        let value_bytes = stellar_value
            .to_xdr(Limits::none())
            .map_err(|e| HerderError::Internal(format!("Failed to encode value: {}", e)))?;
        let value = Value(value_bytes.try_into().map_err(|_| {
            HerderError::Internal("Value too large".to_string())
        })?);

        // Get previous value for priority calculation
        let prev_value = self.prev_value.read().clone();

        // Start SCP nomination
        if scp.nominate(slot, value, &prev_value) {
            info!(slot, "Started SCP nomination for ledger");
        } else {
            debug!(slot, "Nomination already in progress or slot already externalized");
        }

        Ok(())
    }

    /// Get the SCP driver.
    pub fn scp_driver(&self) -> &Arc<ScpDriver> {
        &self.scp_driver
    }

    /// Set the envelope broadcast callback.
    ///
    /// This is called when SCP needs to send an envelope to the network.
    pub fn set_envelope_sender<F>(&self, sender: F)
    where
        F: Fn(ScpEnvelope) + Send + Sync + 'static,
    {
        self.scp_driver.set_envelope_sender(sender);
    }

    /// Get the SCP instance (if validator).
    pub fn scp(&self) -> Option<&SCP<HerderScpCallback>> {
        self.scp.as_ref()
    }

    /// Check if a ledger close is ready and return the close info.
    ///
    /// This is called by the application to check if consensus has been
    /// reached and the ledger should be closed.
    pub fn check_ledger_close(&self, slot: SlotIndex) -> Option<LedgerCloseInfo> {
        // Check if we have externalized this slot
        let externalized = self.scp_driver.get_externalized(slot)?;

        // Parse the StellarValue
        let stellar_value = match StellarValue::from_xdr(&externalized.value, Limits::none()) {
            Ok(v) => v,
            Err(e) => {
                error!(slot, error = %e, "Failed to parse externalized StellarValue");
                return None;
            }
        };

        // Get the transaction set
        let tx_set_hash = Hash256::from_bytes(stellar_value.tx_set_hash.0);
        let tx_set = self.scp_driver.get_tx_set(&tx_set_hash);

        if tx_set.is_none() {
            // Register this as a pending tx set request
            self.scp_driver.request_tx_set(tx_set_hash, slot);
        }

        Some(LedgerCloseInfo {
            slot,
            close_time: stellar_value.close_time.0,
            tx_set_hash,
            tx_set,
            upgrades: stellar_value.upgrades.to_vec(),
        })
    }

    /// Mark a ledger as closed and clean up.
    ///
    /// Called after the application has applied the ledger.
    pub fn ledger_closed(&self, slot: SlotIndex, applied_tx_hashes: &[Hash256]) {
        info!(slot, txs = applied_tx_hashes.len(), "Ledger closed");

        // Remove applied transactions from queue
        self.tx_queue.remove_applied(applied_tx_hashes);

        // Drop pending tx set requests for slots older than the next slot.
        let _ = self.scp_driver.cleanup_old_pending_slots(slot.saturating_add(1));

        // Clean up old SCP state
        if let Some(ref scp) = self.scp {
            scp.purge_slots(slot.saturating_sub(10));
        }

        // Clean up old data
        self.cleanup();
    }

    /// Handle nomination timeout.
    ///
    /// Called when the nomination timer expires. Re-nominates with the same
    /// value to try to make progress.
    pub fn handle_nomination_timeout(&self, slot: SlotIndex) {
        if let Some(ref scp) = self.scp {
            let prev_value = self.prev_value.read().clone();
            let value = self.create_nomination_value(slot);

            if let Some(value) = value {
                if scp.nominate_timeout(slot, value, &prev_value) {
                    debug!(slot, "Re-nominated after timeout");
                }
            }
        }
    }

    /// Handle ballot timeout.
    ///
    /// Called when the ballot timer expires. Bumps the ballot counter to
    /// try to make progress.
    pub fn handle_ballot_timeout(&self, slot: SlotIndex) {
        if let Some(ref scp) = self.scp {
            if scp.bump_ballot(slot) {
                debug!(slot, "Bumped ballot after timeout");
            }
        }
    }

    /// Get the current nomination timeout.
    pub fn get_nomination_timeout(&self, slot: SlotIndex) -> Option<std::time::Duration> {
        if let Some(ref scp) = self.scp {
            if let Some(state) = scp.get_slot_state(slot) {
                return Some(scp.get_nomination_timeout(state.nomination_round));
            }
        }
        None
    }

    /// Get the current ballot timeout.
    pub fn get_ballot_timeout(&self, slot: SlotIndex) -> Option<std::time::Duration> {
        if let Some(ref scp) = self.scp {
            if let Some(state) = scp.get_slot_state(slot) {
                if let Some(round) = state.ballot_round {
                    return Some(scp.get_ballot_timeout(round));
                }
            }
        }
        None
    }

    /// Create a nomination value for a slot.
    fn create_nomination_value(&self, _slot: SlotIndex) -> Option<Value> {
        // Get the previous ledger hash from our current ledger state
        let (previous_hash, max_txs, starting_seq) =
            if let Some(manager) = self.ledger_manager.read().as_ref() {
            let header = manager.current_header();
            let max = header.max_tx_set_size as usize;
            let starting_seq = self.build_starting_seq_map(manager);
            (manager.current_header_hash(), max, starting_seq)
        } else {
            (Hash256::ZERO, self.config.max_tx_set_size, None)
        };

        // Build GeneralizedTransactionSet with proper hash computation
        let (tx_set, _gen_tx_set) = self
            .tx_queue
            .build_generalized_tx_set_with_starting_seq(
                previous_hash,
                max_txs,
                starting_seq.as_ref(),
            );

        info!(
            hash = %tx_set.hash,
            tx_count = tx_set.transactions.len(),
            "Proposing transaction set"
        );

        // Cache the tx set so we can respond to GetTxSet requests
        self.scp_driver.cache_tx_set(tx_set.clone());

        // Create StellarValue with the GeneralizedTransactionSet hash
        let close_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let upgrades: Vec<UpgradeType> = self
            .config
            .proposed_upgrades
            .iter()
            .filter_map(|upgrade| upgrade.to_xdr(Limits::none()).ok())
            .filter_map(|bytes| bytes.try_into().ok().map(UpgradeType))
            .collect();

        let stellar_value = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set.hash.0),
            close_time: TimePoint(close_time),
            upgrades: upgrades.try_into().unwrap_or_default(),
            ext: stellar_xdr::curr::StellarValueExt::Basic,
        };

        // Encode to Value
        let value_bytes = stellar_value.to_xdr(Limits::none()).ok()?;
        let value = Value(value_bytes.try_into().ok()?);
        Some(value)
    }

    fn build_starting_seq_map(
        &self,
        manager: &Arc<LedgerManager>,
    ) -> Option<HashMap<Vec<u8>, i64>> {
        let snapshot = manager.create_snapshot().ok()?;
        let ledger_seq = manager.current_ledger_seq();
        if ledger_seq > i32::MAX as u32 {
            return None;
        }
        let starting_seq = (ledger_seq as i64) << 32;
        let mut map: HashMap<Vec<u8>, i64> = HashMap::new();
        for account in self.tx_queue.pending_accounts() {
            let key = account_key_from_account_id(&account);
            match snapshot.get_account(&account) {
                Ok(Some(entry)) => {
                    map.insert(key, entry.seq_num.0);
                }
                Ok(None) => {
                    map.insert(key, starting_seq);
                }
                Err(_) => {}
            }
        }
        Some(map)
    }

    /// Get the transaction queue.
    pub fn tx_queue(&self) -> &TransactionQueue {
        &self.tx_queue
    }

    /// Get the pending envelope manager.
    pub fn pending_envelopes(&self) -> &PendingEnvelopes {
        &self.pending_envelopes
    }

    /// Get the latest externalized slot.
    pub fn latest_externalized_slot(&self) -> Option<u64> {
        self.scp_driver.latest_externalized_slot()
    }

    /// Get an externalized value.
    pub fn get_externalized(&self, slot: u64) -> Option<crate::scp_driver::ExternalizedSlot> {
        self.scp_driver.get_externalized(slot)
    }

    /// Find an externalized slot for a given tx set hash.
    pub fn find_externalized_slot_by_tx_set_hash(&self, hash: &Hash256) -> Option<SlotIndex> {
        self.scp_driver.find_externalized_slot_by_tx_set_hash(hash)
    }

    /// Get SCP state envelopes for responding to peers.
    ///
    /// Returns SCP envelopes for slots starting from `from_slot`, along with
    /// our local quorum set if configured.
    pub fn get_scp_state(&self, from_slot: u64) -> (Vec<ScpEnvelope>, Option<ScpQuorumSet>) {
        let envelopes = if let Some(ref scp) = self.scp {
            scp.get_scp_state(from_slot)
        } else {
            vec![]
        };

        let quorum_set = self.scp_driver.get_local_quorum_set();

        (envelopes, quorum_set)
    }

    /// Get all SCP envelopes recorded for a slot.
    pub fn get_scp_envelopes(&self, slot: u64) -> Vec<ScpEnvelope> {
        if let Some(ref scp) = self.scp {
            scp.get_slot_envelopes(slot)
        } else {
            Vec::new()
        }
    }

    /// Get the local quorum set if configured.
    pub fn local_quorum_set(&self) -> Option<ScpQuorumSet> {
        self.scp_driver.get_local_quorum_set()
    }

    /// Remove applied transactions from the queue.
    pub fn remove_applied_transactions(&self, tx_hashes: &[Hash256]) {
        self.tx_queue.remove_applied(tx_hashes);
    }

    /// Clean up old data.
    pub fn cleanup(&self) {
        // Clean up old externalized slots
        self.scp_driver
            .cleanup_externalized(self.config.max_externalized_slots);

        // Clean up expired pending envelopes
        self.pending_envelopes.evict_expired();

        // Clean up expired transactions
        self.tx_queue.evict_expired();

        // Clean up old pending tx set requests (by time).
        // Keep them longer to allow lagging nodes to fetch historical sets.
        self.scp_driver.cleanup_pending_tx_sets(120);
    }

    /// Get pending transaction set hashes that need to be fetched from peers.
    pub fn get_pending_tx_set_hashes(&self) -> Vec<Hash256> {
        self.scp_driver.get_pending_tx_set_hashes()
    }

    /// Get pending transaction sets with their slots.
    pub fn get_pending_tx_sets(&self) -> Vec<(Hash256, SlotIndex)> {
        self.scp_driver.get_pending_tx_sets()
    }

    /// Drop pending tx set requests for slots older than the given slot.
    pub fn cleanup_old_pending_tx_sets(&self, current_slot: SlotIndex) -> usize {
        self.scp_driver.cleanup_old_pending_slots(current_slot)
    }

    /// Check if we need a transaction set.
    pub fn needs_tx_set(&self, hash: &Hash256) -> bool {
        self.scp_driver.needs_tx_set(hash)
    }

    /// Receive a transaction set from the network.
    /// Returns the slot it was needed for, if any.
    pub fn receive_tx_set(&self, tx_set: TransactionSet) -> Option<SlotIndex> {
        self.scp_driver.receive_tx_set(tx_set)
    }

    /// Cache a transaction set directly.
    pub fn cache_tx_set(&self, tx_set: TransactionSet) {
        self.scp_driver.cache_tx_set(tx_set);
    }

    /// Check if a transaction set is cached.
    pub fn has_tx_set(&self, hash: &Hash256) -> bool {
        self.scp_driver.has_tx_set(hash)
    }

    /// Get a cached transaction set by hash.
    pub fn get_tx_set(&self, hash: &Hash256) -> Option<TransactionSet> {
        self.scp_driver.get_tx_set(hash)
    }

    /// Get statistics about the Herder.
    pub fn stats(&self) -> HerderStats {
        HerderStats {
            state: self.state(),
            tracking_slot: self.tracking_slot(),
            pending_transactions: self.tx_queue.len(),
            pending_envelopes: self.pending_envelopes.len(),
            pending_envelope_slots: self.pending_envelopes.slot_count(),
            cached_tx_sets: self.scp_driver.tx_set_cache_size(),
            is_validator: self.is_validator(),
        }
    }
}

/// Information about a ledger ready to close.
#[derive(Debug, Clone)]
pub struct LedgerCloseInfo {
    /// The slot/ledger sequence.
    pub slot: SlotIndex,
    /// Close time from consensus.
    pub close_time: u64,
    /// Transaction set hash.
    pub tx_set_hash: Hash256,
    /// Transaction set (if available in cache).
    pub tx_set: Option<TransactionSet>,
    /// Protocol upgrades.
    pub upgrades: Vec<UpgradeType>,
}

/// Statistics about the Herder.
#[derive(Debug, Clone)]
pub struct HerderStats {
    /// Current state.
    pub state: HerderState,
    /// Current tracking slot.
    pub tracking_slot: u64,
    /// Number of pending transactions.
    pub pending_transactions: usize,
    /// Number of pending SCP envelopes.
    pub pending_envelopes: usize,
    /// Number of slots with pending envelopes.
    pub pending_envelope_slots: usize,
    /// Number of cached transaction sets.
    pub cached_tx_sets: usize,
    /// Whether this node is a validator.
    pub is_validator: bool,
}

fn node_id_from_public_key(pk: &PublicKey) -> NodeId {
    NodeId(pk.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScpStatement, ScpStatementPledges, ScpNomination, ScpBallot,
        ScpStatementExternalize, NodeId as XdrNodeId, Value,
        Signature as XdrSignature, WriteXdr, Limits,
    };
    use stellar_core_crypto::SecretKey;

    fn make_test_herder() -> Herder {
        let config = HerderConfig::default();
        Herder::new(config)
    }

    /// Creates a test envelope with a valid signature for the given herder's network.
    fn make_signed_test_envelope(slot: u64, herder: &Herder) -> ScpEnvelope {
        // Generate a test keypair
        let secret = SecretKey::from_seed(&[1u8; 32]);
        let public = secret.public_key();

        let node_id = XdrNodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256(*public.as_bytes()),
        ));

        let statement = ScpStatement {
            node_id: node_id.clone(),
            slot_index: slot,
            pledges: ScpStatementPledges::Nominate(ScpNomination {
                quorum_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
                votes: vec![].try_into().unwrap(),
                accepted: vec![].try_into().unwrap(),
            }),
        };

        // Sign the statement with network ID + ENVELOPE_TYPE_SCP prefix
        // (same format as verify_envelope expects)
        let statement_bytes = statement.to_xdr(Limits::none()).unwrap();
        let mut data = herder.scp_driver.network_id().0.to_vec();
        data.extend_from_slice(&1i32.to_be_bytes()); // ENVELOPE_TYPE_SCP = 1
        data.extend_from_slice(&statement_bytes);

        let signature = secret.sign(&data);
        let sig_bytes: Vec<u8> = signature.as_bytes().to_vec();

        ScpEnvelope {
            statement,
            signature: XdrSignature(sig_bytes.try_into().unwrap()),
        }
    }

    fn make_test_envelope(slot: u64) -> ScpEnvelope {
        let node_id = XdrNodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256([0u8; 32]),
        ));

        ScpEnvelope {
            statement: ScpStatement {
                node_id,
                slot_index: slot,
                pledges: ScpStatementPledges::Nominate(ScpNomination {
                    quorum_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
                    votes: vec![].try_into().unwrap(),
                    accepted: vec![].try_into().unwrap(),
                }),
            },
            signature: XdrSignature(vec![0u8; 64].try_into().unwrap()),
        }
    }

    #[test]
    fn test_initial_state() {
        let herder = make_test_herder();
        assert_eq!(herder.state(), HerderState::Booting);
        assert!(!herder.is_tracking());
    }

    #[test]
    fn test_bootstrap() {
        let herder = make_test_herder();

        herder.start_syncing();
        assert_eq!(herder.state(), HerderState::Syncing);

        herder.bootstrap(100);
        assert_eq!(herder.state(), HerderState::Tracking);
        assert_eq!(herder.tracking_slot(), 100);
        assert!(herder.is_tracking());
    }

    #[test]
    fn test_receive_envelope_before_tracking() {
        let herder = make_test_herder();

        let envelope = make_test_envelope(100);
        let result = herder.receive_scp_envelope(envelope);

        // Should be invalid because we're not syncing or tracking
        assert_eq!(result, EnvelopeState::Invalid);
    }

    #[test]
    fn test_receive_envelope_while_syncing() {
        let herder = make_test_herder();
        herder.start_syncing();

        // Syncing but not yet tracking, envelopes go to pending
        // Use signed envelope to pass signature verification
        let envelope = make_signed_test_envelope(100, &herder);

        // We need to set a current slot first
        herder.pending_envelopes.set_current_slot(95);

        let result = herder.receive_scp_envelope(envelope);
        assert_eq!(result, EnvelopeState::Pending);
    }

    #[test]
    fn test_stats() {
        let herder = make_test_herder();
        herder.bootstrap(50);

        let stats = herder.stats();
        assert_eq!(stats.state, HerderState::Tracking);
        assert_eq!(stats.tracking_slot, 50);
        assert_eq!(stats.pending_transactions, 0);
        assert!(!stats.is_validator);
    }

    #[test]
    fn test_max_externalize_slot_distance_constant() {
        // Verify the constant is set to a reasonable value (1000 ledgers)
        // This prevents accepting EXTERNALIZE messages for slots millions of ledgers ahead
        assert_eq!(MAX_EXTERNALIZE_SLOT_DISTANCE, 1000);
    }

    /// Creates a signed EXTERNALIZE envelope for testing.
    fn make_signed_externalize_envelope(slot: u64, herder: &Herder) -> ScpEnvelope {
        let secret = SecretKey::from_seed(&[1u8; 32]);
        let public = secret.public_key();

        let node_id = XdrNodeId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::curr::Uint256(*public.as_bytes()),
        ));

        // Create a minimal valid StellarValue for the externalized value
        let stellar_value = stellar_xdr::curr::StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
            close_time: stellar_xdr::curr::TimePoint(1234567890),
            upgrades: vec![].try_into().unwrap(),
            ext: stellar_xdr::curr::StellarValueExt::Basic,
        };
        let value_bytes = stellar_value.to_xdr(Limits::none()).unwrap();

        let statement = ScpStatement {
            node_id: node_id.clone(),
            slot_index: slot,
            pledges: ScpStatementPledges::Externalize(ScpStatementExternalize {
                commit: ScpBallot {
                    counter: 1,
                    value: Value(value_bytes.try_into().unwrap()),
                },
                n_h: 1,
                commit_quorum_set_hash: stellar_xdr::curr::Hash([0u8; 32]),
            }),
        };

        // Sign the statement
        let statement_bytes = statement.to_xdr(Limits::none()).unwrap();
        let mut data = herder.scp_driver.network_id().0.to_vec();
        data.extend_from_slice(&1i32.to_be_bytes()); // ENVELOPE_TYPE_SCP = 1
        data.extend_from_slice(&statement_bytes);

        let signature = secret.sign(&data);
        let sig_bytes: Vec<u8> = signature.as_bytes().to_vec();

        ScpEnvelope {
            statement,
            signature: XdrSignature(sig_bytes.try_into().unwrap()),
        }
    }

    #[test]
    fn test_externalize_rejected_when_node_not_in_quorum() {
        let herder = make_test_herder();
        herder.start_syncing();
        herder.bootstrap(100);

        // Create an EXTERNALIZE envelope from a node that is NOT in our quorum
        // (the test herder has no quorum set configured, so no nodes are in quorum)
        let envelope = make_signed_externalize_envelope(105, &herder);

        let result = herder.receive_scp_envelope(envelope);

        // Should be rejected because sender is not in our transitive quorum
        assert_eq!(result, EnvelopeState::Invalid);
    }

    #[test]
    fn test_externalize_rejected_when_slot_too_far_in_future() {
        // Create a herder with a quorum set that includes our test node
        let secret = SecretKey::from_seed(&[1u8; 32]);
        let public = secret.public_key();
        let test_node_id = node_id_from_public_key(&public);

        let quorum_set = ScpQuorumSet {
            threshold: 1,
            validators: vec![test_node_id.clone()].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };

        let config = HerderConfig {
            local_quorum_set: Some(quorum_set),
            ..HerderConfig::default()
        };
        let herder = Herder::new(config);
        herder.start_syncing();
        herder.bootstrap(100);

        // Add the test node to the quorum tracker
        let test_qs = ScpQuorumSet {
            threshold: 1,
            validators: vec![test_node_id.clone()].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };
        herder.quorum_tracker.write().expand(&test_node_id, test_qs);

        // Create an EXTERNALIZE envelope for a slot WAY in the future (beyond MAX_EXTERNALIZE_SLOT_DISTANCE)
        let far_future_slot = 100 + MAX_EXTERNALIZE_SLOT_DISTANCE + 100; // 1200
        let envelope = make_signed_externalize_envelope(far_future_slot, &herder);

        let result = herder.receive_scp_envelope(envelope);

        // Should be rejected because slot is too far in the future
        assert_eq!(result, EnvelopeState::Invalid);
    }

    #[test]
    fn test_externalize_accepted_when_within_distance_and_in_quorum() {
        // Create a herder with a quorum set that includes our test node
        let secret = SecretKey::from_seed(&[1u8; 32]);
        let public = secret.public_key();
        let test_node_id = node_id_from_public_key(&public);

        let quorum_set = ScpQuorumSet {
            threshold: 1,
            validators: vec![test_node_id.clone()].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };

        let config = HerderConfig {
            local_quorum_set: Some(quorum_set),
            ..HerderConfig::default()
        };
        let herder = Herder::new(config);
        herder.start_syncing();
        herder.bootstrap(100);

        // Add the test node to the quorum tracker
        let test_qs = ScpQuorumSet {
            threshold: 1,
            validators: vec![test_node_id.clone()].try_into().unwrap(),
            inner_sets: vec![].try_into().unwrap(),
        };
        herder.quorum_tracker.write().expand(&test_node_id, test_qs);

        // Create an EXTERNALIZE envelope for a slot within acceptable distance
        let acceptable_slot = 100 + 50; // 150, well within MAX_EXTERNALIZE_SLOT_DISTANCE
        let envelope = make_signed_externalize_envelope(acceptable_slot, &herder);

        let result = herder.receive_scp_envelope(envelope);

        // Should be accepted and cause fast-forward
        assert_eq!(result, EnvelopeState::Valid);
        // Tracking slot should have advanced (to slot + 1, since EXTERNALIZE completes that slot)
        assert_eq!(herder.tracking_slot(), acceptable_slot + 1);
    }
}
