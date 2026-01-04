//! SCP driver integration for the Herder.
//!
//! This module implements the SCPDriver trait callbacks that integrate
//! the SCP consensus protocol with the Herder's transaction processing
//! and ledger management.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use stellar_core_common::Hash256;
use stellar_core_crypto::{PublicKey, SecretKey, Signature};
use stellar_core_ledger::LedgerManager;
use stellar_core_scp::{hash_quorum_set, SCPDriver, SlotIndex, ValidationLevel};
use stellar_xdr::curr::{
    LedgerUpgrade, ReadXdr, ScpEnvelope, ScpQuorumSet, ScpStatement, StellarValue, Value, WriteXdr,
};

use crate::error::HerderError;
use crate::tx_queue::TransactionSet;
use crate::Result;

/// Result of validating an SCP value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueValidation {
    /// Value is fully valid.
    Valid,
    /// Value might be valid but we're missing data.
    MaybeValid,
    /// Value is invalid.
    Invalid,
}

/// Configuration for the SCP driver.
#[derive(Debug, Clone)]
pub struct ScpDriverConfig {
    /// Our node's public key.
    pub node_id: PublicKey,
    /// Maximum transaction sets to cache.
    pub max_tx_set_cache: usize,
    /// Maximum time drift allowed (in seconds).
    pub max_time_drift: u64,
    /// Local quorum set.
    pub local_quorum_set: Option<ScpQuorumSet>,
}

impl Default for ScpDriverConfig {
    fn default() -> Self {
        Self {
            node_id: PublicKey::from_bytes(&[0u8; 32]).unwrap(),
            max_tx_set_cache: 100,
            max_time_drift: 60,
            local_quorum_set: None,
        }
    }
}

/// Cached transaction set with metadata.
#[derive(Debug, Clone)]
pub struct CachedTxSet {
    /// The transaction set.
    pub tx_set: TransactionSet,
    /// When this was cached.
    pub cached_at: std::time::Instant,
    /// Number of times this was requested.
    pub request_count: u64,
}

impl CachedTxSet {
    fn new(tx_set: TransactionSet) -> Self {
        Self {
            tx_set,
            cached_at: std::time::Instant::now(),
            request_count: 0,
        }
    }
}

/// Externalized value with metadata.
#[derive(Debug, Clone)]
pub struct ExternalizedSlot {
    /// The slot index.
    pub slot: SlotIndex,
    /// The externalized SCP value.
    pub value: Value,
    /// The transaction set hash (if resolved).
    pub tx_set_hash: Option<Hash256>,
    /// Close time from the value.
    pub close_time: u64,
    /// When this was externalized.
    pub externalized_at: std::time::Instant,
}

/// Pending transaction set request.
#[derive(Debug, Clone)]
pub struct PendingTxSet {
    /// The hash of the tx set we need.
    pub hash: Hash256,
    /// The slot this tx set is needed for.
    pub slot: SlotIndex,
    /// When we first requested this.
    pub requested_at: std::time::Instant,
    /// Number of times we've requested this.
    pub request_count: u32,
}

/// Pending quorum set request.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PendingQuorumSet {
    /// The hash of the quorum set.
    pub hash: Hash256,
    /// When we first requested this quorum set.
    pub requested_at: std::time::Instant,
    /// Number of times we've requested this.
    pub request_count: u32,
}

/// SCP driver that integrates consensus with the Herder.
///
/// This manages:
/// - Transaction set caching by hash
/// - Value validation callbacks
/// - Envelope signing and verification
/// - Externalized value tracking
/// - Quorum set storage and lookup
pub struct ScpDriver {
    /// Configuration.
    config: ScpDriverConfig,
    /// Secret key for signing (None if not a validator).
    secret_key: Option<SecretKey>,
    /// Cached transaction sets by hash.
    tx_set_cache: DashMap<Hash256, CachedTxSet>,
    /// Pending transaction set requests (hashes we need but don't have).
    pending_tx_sets: DashMap<Hash256, PendingTxSet>,
    /// Pending quorum set requests (hashes we need but don't have).
    pending_quorum_sets: DashMap<Hash256, PendingQuorumSet>,
    /// Externalized slots.
    externalized: RwLock<HashMap<SlotIndex, ExternalizedSlot>>,
    /// Latest externalized slot.
    latest_externalized: RwLock<Option<SlotIndex>>,
    /// Envelope broadcast callback.
    envelope_sender: RwLock<Option<Box<dyn Fn(ScpEnvelope) + Send + Sync>>>,
    /// Network ID for signing.
    network_id: Hash256,
    /// Quorum sets by node ID (key is 32-byte public key).
    quorum_sets: DashMap<[u8; 32], ScpQuorumSet>,
    /// Quorum sets by quorum set hash.
    quorum_sets_by_hash: DashMap<[u8; 32], ScpQuorumSet>,
    /// Our local quorum set.
    local_quorum_set: RwLock<Option<ScpQuorumSet>>,
    /// Ledger manager for network configuration lookups.
    ledger_manager: RwLock<Option<Arc<LedgerManager>>>,
}

impl ScpDriver {
    /// Create a new SCP driver.
    pub fn new(config: ScpDriverConfig, network_id: Hash256) -> Self {
        let local_quorum_set = config.local_quorum_set.clone();
        let quorum_sets = DashMap::new();
        let quorum_sets_by_hash = DashMap::new();

        if let Some(ref quorum_set) = local_quorum_set {
            let hash = hash_quorum_set(quorum_set);
            quorum_sets_by_hash.insert(hash.0, quorum_set.clone());
            quorum_sets.insert(*config.node_id.as_bytes(), quorum_set.clone());
        }
        Self {
            config,
            secret_key: None,
            tx_set_cache: DashMap::new(),
            pending_tx_sets: DashMap::new(),
            pending_quorum_sets: DashMap::new(),
            externalized: RwLock::new(HashMap::new()),
            latest_externalized: RwLock::new(None),
            envelope_sender: RwLock::new(None),
            network_id,
            quorum_sets,
            quorum_sets_by_hash,
            local_quorum_set: RwLock::new(local_quorum_set),
            ledger_manager: RwLock::new(None),
        }
    }

    /// Create a new SCP driver with a secret key for signing.
    pub fn with_secret_key(
        config: ScpDriverConfig,
        network_id: Hash256,
        secret_key: SecretKey,
    ) -> Self {
        let mut driver = Self::new(config, network_id);
        driver.secret_key = Some(secret_key);
        driver
    }

    /// Set the envelope broadcast callback.
    pub fn set_envelope_sender<F>(&self, sender: F)
    where
        F: Fn(ScpEnvelope) + Send + Sync + 'static,
    {
        *self.envelope_sender.write() = Some(Box::new(sender));
    }

    /// Provide ledger manager access for network configuration lookups.
    pub fn set_ledger_manager(&self, manager: Arc<LedgerManager>) {
        *self.ledger_manager.write() = Some(manager);
    }

    /// Cache a transaction set.
    pub fn cache_tx_set(&self, tx_set: TransactionSet) {
        let hash = tx_set.hash;

        // Check cache size limit
        if self.tx_set_cache.len() >= self.config.max_tx_set_cache {
            // Evict oldest entry
            if let Some(oldest) = self
                .tx_set_cache
                .iter()
                .min_by_key(|e| e.cached_at)
                .map(|e| *e.key())
            {
                self.tx_set_cache.remove(&oldest);
            }
        }

        self.tx_set_cache.insert(hash, CachedTxSet::new(tx_set));
    }

    /// Get a cached transaction set by hash.
    pub fn get_tx_set(&self, hash: &Hash256) -> Option<TransactionSet> {
        self.tx_set_cache.get_mut(hash).map(|mut entry| {
            entry.request_count += 1;
            entry.tx_set.clone()
        })
    }

    /// Check if a transaction set is cached.
    pub fn has_tx_set(&self, hash: &Hash256) -> bool {
        self.tx_set_cache.contains_key(hash)
    }

    /// Register a pending tx set request.
    /// Returns true if this is a new request, false if already pending.
    pub fn request_tx_set(&self, hash: Hash256, slot: SlotIndex) -> bool {
        if self.tx_set_cache.contains_key(&hash) {
            // Already have it
            return false;
        }

        if self.pending_tx_sets.contains_key(&hash) {
            // Already requested, increment count
            if let Some(mut entry) = self.pending_tx_sets.get_mut(&hash) {
                entry.request_count += 1;
            }
            return false;
        }

        // New request
        self.pending_tx_sets.insert(
            hash,
            PendingTxSet {
                hash,
                slot,
                requested_at: std::time::Instant::now(),
                request_count: 1,
            },
        );
        info!(%hash, slot, "Registered pending tx set request");
        true
    }

    /// Register a pending quorum set request.
    /// Returns true if this is a new request, false if already pending or known.
    pub fn request_quorum_set(&self, hash: Hash256) -> bool {
        if self.quorum_sets_by_hash.contains_key(&hash.0) {
            return false;
        }

        if self.pending_quorum_sets.contains_key(&hash) {
            if let Some(mut entry) = self.pending_quorum_sets.get_mut(&hash) {
                entry.request_count += 1;
            }
            return false;
        }

        self.pending_quorum_sets.insert(
            hash,
            PendingQuorumSet {
                hash,
                requested_at: std::time::Instant::now(),
                request_count: 1,
            },
        );
        info!(%hash, "Registered pending quorum set request");
        true
    }

    /// Clear a quorum set request once it has been satisfied.
    pub fn clear_quorum_set_request(&self, hash: &Hash256) {
        self.pending_quorum_sets.remove(hash);
    }

    /// Get all pending tx set hashes that need to be fetched.
    pub fn get_pending_tx_set_hashes(&self) -> Vec<Hash256> {
        self.pending_tx_sets
            .iter()
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get all pending tx sets with their slots.
    pub fn get_pending_tx_sets(&self) -> Vec<(Hash256, SlotIndex)> {
        self.pending_tx_sets
            .iter()
            .map(|entry| {
                let pending = entry.value();
                (pending.hash, pending.slot)
            })
            .collect()
    }

    /// Check if we need a tx set.
    pub fn needs_tx_set(&self, hash: &Hash256) -> bool {
        self.pending_tx_sets.contains_key(hash) && !self.tx_set_cache.contains_key(hash)
    }

    /// Receive a tx set from the network.
    /// Returns the slot it was needed for, if any.
    pub fn receive_tx_set(&self, tx_set: TransactionSet) -> Option<SlotIndex> {
        let hash = tx_set.hash;
        if let Some(recomputed) = tx_set.recompute_hash() {
            if recomputed != hash {
                warn!(
                    expected = %hash,
                    computed = %recomputed,
                    "Rejecting tx set with mismatched hash"
                );
                return None;
            }
        } else {
            warn!(%hash, "Rejecting tx set without recomputable hash");
            return None;
        }

        // Remove from pending
        let pending = self.pending_tx_sets.remove(&hash);
        let slot = pending.map(|(_, p)| p.slot);

        // Cache it
        self.cache_tx_set(tx_set);

        if let Some(s) = slot {
            info!(%hash, slot = s, "Received pending tx set");
        } else {
            debug!(%hash, "Received tx set (not pending)");
        }

        slot
    }

    /// Clean up old pending requests.
    pub fn cleanup_pending_tx_sets(&self, max_age_secs: u64) {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(max_age_secs);
        self.pending_tx_sets.retain(|_, v| v.requested_at > cutoff);
    }

    /// Clean up pending requests for slots older than the given slot.
    /// Returns the number of requests removed.
    pub fn cleanup_old_pending_slots(&self, current_slot: SlotIndex) -> usize {
        let old_count = self.pending_tx_sets.len();
        // Only keep requests for the current slot - peers don't cache old tx sets long
        // We use >= current_slot to keep current and future (shouldn't happen but be safe)
        self.pending_tx_sets.retain(|_, v| v.slot >= current_slot);
        let new_count = self.pending_tx_sets.len();
        old_count - new_count
    }

    /// Get the network ID.
    pub fn network_id(&self) -> Hash256 {
        self.network_id
    }

    /// Get the latest externalized slot.
    pub fn latest_externalized_slot(&self) -> Option<SlotIndex> {
        *self.latest_externalized.read()
    }

    /// Get an externalized slot.
    pub fn get_externalized(&self, slot: SlotIndex) -> Option<ExternalizedSlot> {
        self.externalized.read().get(&slot).cloned()
    }

    /// Find the slot for a given tx set hash in recent externalized values.
    pub fn find_externalized_slot_by_tx_set_hash(&self, hash: &Hash256) -> Option<SlotIndex> {
        self.externalized
            .read()
            .iter()
            .find_map(|(slot, ext)| {
                ext.tx_set_hash
                    .as_ref()
                    .filter(|tx_hash| *tx_hash == hash)
                    .map(|_| *slot)
            })
    }

    /// Validate an SCP value.
    ///
    /// The value is the XDR-encoded StellarValue.
    pub fn validate_value_impl(&self, _slot: SlotIndex, value: &Value) -> ValueValidation {
        // Decode the StellarValue
        let stellar_value = match StellarValue::from_xdr(value, stellar_xdr::curr::Limits::none()) {
            Ok(v) => v,
            Err(e) => {
                debug!("Failed to decode StellarValue: {}", e);
                return ValueValidation::Invalid;
            }
        };

        // Check close time is reasonable
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let close_time = stellar_value.close_time.0;
        if close_time > now + self.config.max_time_drift {
            debug!(
                "Close time {} too far in future (now: {})",
                close_time, now
            );
            return ValueValidation::Invalid;
        }
        if let Some(latest) = *self.latest_externalized.read() {
            if let Some(externalized) = self.externalized.read().get(&latest) {
                if close_time <= externalized.close_time {
                    debug!(
                        "Close time {} not after last externalized {}",
                        close_time, externalized.close_time
                    );
                    return ValueValidation::Invalid;
                }
            }
        }

        // Check if we have the transaction set
        let tx_set_hash = Hash256::from_bytes(stellar_value.tx_set_hash.0);
        if !self.has_tx_set(&tx_set_hash) {
            debug!("Missing transaction set: {}", tx_set_hash);
            return ValueValidation::MaybeValid;
        }
        if let Some(tx_set) = self.tx_set_cache.get(&tx_set_hash) {
            match tx_set.tx_set.recompute_hash() {
                Some(computed) if computed == tx_set_hash => {}
                Some(computed) => {
                    debug!(
                        "Tx set hash mismatch: expected {}, computed {}",
                        tx_set_hash, computed
                    );
                    return ValueValidation::Invalid;
                }
                None => {
                    debug!("Failed to recompute tx set hash");
                    return ValueValidation::Invalid;
                }
            }
        }

        let mut last_upgrade_order = None;
        for upgrade in stellar_value.upgrades.iter() {
            let upgrade = match LedgerUpgrade::from_xdr(
                upgrade.0.as_slice(),
                stellar_xdr::curr::Limits::none(),
            ) {
                Ok(upgrade) => upgrade,
                Err(_) => {
                    debug!("Invalid ledger upgrade encountered");
                    return ValueValidation::Invalid;
                }
            };
            let order = match upgrade {
                LedgerUpgrade::Version(_) => 0,
                LedgerUpgrade::BaseFee(_) => 1,
                LedgerUpgrade::MaxTxSetSize(_) => 2,
                LedgerUpgrade::BaseReserve(_) => 3,
                LedgerUpgrade::Flags(_) => 4,
                LedgerUpgrade::Config(_) => 5,
                LedgerUpgrade::MaxSorobanTxSetSize(_) => 6,
            };
            if last_upgrade_order.map_or(false, |prev| order <= prev) {
                debug!("Invalid ledger upgrade encountered");
                return ValueValidation::Invalid;
            }
            last_upgrade_order = Some(order);
        }

        ValueValidation::Valid
    }

    /// Combine multiple candidate values into one.
    ///
    /// This picks the value with the latest close time and highest tx set hash.
    pub fn combine_candidates_impl(&self, _slot: SlotIndex, values: &[Value]) -> Value {
        if values.is_empty() {
            return Value::default();
        }

        if values.len() == 1 {
            return values[0].clone();
        }

        // Decode all values
        let mut decoded: Vec<(usize, StellarValue)> = values
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                StellarValue::from_xdr(v, stellar_xdr::curr::Limits::none())
                    .ok()
                    .map(|sv| (i, sv))
            })
            .collect();

        if decoded.is_empty() {
            return values[0].clone();
        }

        // Sort by close time (desc) then by tx set hash (desc)
        decoded.sort_by(|a, b| {
            b.1.close_time
                .0
                .cmp(&a.1.close_time.0)
                .then_with(|| b.1.tx_set_hash.0.cmp(&a.1.tx_set_hash.0))
        });

        // Return the best value (original bytes)
        values[decoded[0].0].clone()
    }

    /// Sign an SCP envelope.
    pub fn sign_envelope(&self, statement: &ScpStatement) -> Option<Signature> {
        let secret_key = self.secret_key.as_ref()?;

        // Create the data to sign: network ID + ENVELOPE_TYPE_SCP + statement XDR
        // ENVELOPE_TYPE_SCP = 1 (as i32 big-endian)
        let statement_bytes = statement.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
        let mut data = self.network_id.0.to_vec();
        data.extend_from_slice(&1i32.to_be_bytes()); // ENVELOPE_TYPE_SCP
        data.extend_from_slice(&statement_bytes);

        Some(secret_key.sign(&data))
    }

    /// Verify an SCP envelope signature.
    pub fn verify_envelope(&self, envelope: &ScpEnvelope) -> Result<()> {
        // Extract the public key from the node ID
        let node_id = &envelope.statement.node_id;
        let public_key = PublicKey::try_from(&node_id.0)
            .map_err(|_| HerderError::Internal("Invalid node ID".to_string()))?;

        // Create the data that was signed: network ID + ENVELOPE_TYPE_SCP + statement XDR
        // ENVELOPE_TYPE_SCP = 1 (as i32 big-endian)
        let statement_bytes = envelope
            .statement
            .to_xdr(stellar_xdr::curr::Limits::none())
            .map_err(|e| HerderError::Internal(format!("Failed to encode statement: {}", e)))?;

        let mut data = self.network_id.0.to_vec();
        data.extend_from_slice(&1i32.to_be_bytes()); // ENVELOPE_TYPE_SCP
        data.extend_from_slice(&statement_bytes);

        // Verify signature
        let sig_bytes: [u8; 64] = envelope
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| HerderError::Internal("Invalid signature length".to_string()))?;

        let signature = stellar_core_crypto::Signature::from_bytes(sig_bytes);

        public_key
            .verify(&data, &signature)
            .map_err(|_| HerderError::Scp(stellar_core_scp::ScpError::SignatureVerificationFailed))
    }

    /// Record an externalized value.
    pub fn record_externalized(&self, slot: SlotIndex, value: Value) {
        // Parse the StellarValue
        let (tx_set_hash, close_time) =
            if let Ok(sv) = StellarValue::from_xdr(&value, stellar_xdr::curr::Limits::none()) {
                (Some(Hash256::from_bytes(sv.tx_set_hash.0)), sv.close_time.0)
            } else {
                (None, 0)
            };

        let externalized = ExternalizedSlot {
            slot,
            value,
            tx_set_hash,
            close_time,
            externalized_at: std::time::Instant::now(),
        };

        self.externalized.write().insert(slot, externalized);

        // Update latest
        let mut latest = self.latest_externalized.write();
        if latest.map(|l| slot > l).unwrap_or(true) {
            *latest = Some(slot);
        }

        info!("Externalized slot {} with close time {}", slot, close_time);
    }

    /// Emit an envelope to the network.
    fn emit(&self, envelope: ScpEnvelope) {
        if let Some(sender) = self.envelope_sender.read().as_ref() {
            sender(envelope);
        }
    }

    /// Get the cache size.
    pub fn tx_set_cache_size(&self) -> usize {
        self.tx_set_cache.len()
    }

    /// Clear old externalized slots.
    pub fn cleanup_externalized(&self, keep_count: usize) {
        let mut externalized = self.externalized.write();
        if externalized.len() <= keep_count {
            return;
        }

        // Get slots sorted by slot index
        let mut slots: Vec<SlotIndex> = externalized.keys().copied().collect();
        slots.sort();

        // Remove oldest
        let to_remove = externalized.len() - keep_count;
        for slot in slots.into_iter().take(to_remove) {
            externalized.remove(&slot);
        }
    }

    /// Clear the transaction set cache.
    pub fn clear_tx_set_cache(&self) {
        self.tx_set_cache.clear();
    }

    /// Get our local quorum set.
    pub fn get_local_quorum_set(&self) -> Option<ScpQuorumSet> {
        self.local_quorum_set.read().clone()
    }

    /// Set our local quorum set.
    pub fn set_local_quorum_set(&self, quorum_set: ScpQuorumSet) {
        *self.local_quorum_set.write() = Some(quorum_set);
        if let Some(local) = self.local_quorum_set.read().clone() {
            let hash = hash_quorum_set(&local);
            self.quorum_sets_by_hash.insert(hash.0, local.clone());
            self.quorum_sets
                .insert(*self.config.node_id.as_bytes(), local);
            self.pending_quorum_sets.remove(&Hash256::from_bytes(hash.0));
        }
    }

    /// Store a quorum set for a node.
    pub fn store_quorum_set(&self, node_id: &stellar_xdr::curr::NodeId, quorum_set: ScpQuorumSet) {
        let key: [u8; 32] = match &node_id.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
        };
        let hash = hash_quorum_set(&quorum_set);
        self.quorum_sets.insert(key, quorum_set.clone());
        self.quorum_sets_by_hash.insert(hash.0, quorum_set);
        self.pending_quorum_sets.remove(&Hash256::from_bytes(hash.0));
    }

    /// Get a quorum set for a node.
    pub fn get_quorum_set(&self, node_id: &stellar_xdr::curr::NodeId) -> Option<ScpQuorumSet> {
        let key: [u8; 32] = match &node_id.0 {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(key) => key.0,
        };

        // Check if this is our own node
        let our_key: [u8; 32] = *self.config.node_id.as_bytes();
        if key == our_key {
            return self.local_quorum_set.read().clone();
        }

        self.quorum_sets.get(&key).map(|v| v.clone())
    }

    /// Get a quorum set by its hash.
    pub fn get_quorum_set_by_hash(&self, hash: &[u8; 32]) -> Option<ScpQuorumSet> {
        self.quorum_sets_by_hash.get(hash).map(|v| v.clone())
    }

    /// Whether we already have a quorum set with the given hash.
    pub fn has_quorum_set_hash(&self, hash: &Hash256) -> bool {
        self.quorum_sets_by_hash.contains_key(&hash.0)
    }

    /// Get our node ID.
    pub fn node_id(&self) -> &PublicKey {
        &self.config.node_id
    }
}

/// SCP callback implementation wrapper.
///
/// This wraps the ScpDriver to implement the SCPDriver trait.
pub struct HerderScpCallback {
    driver: Arc<ScpDriver>,
}

impl HerderScpCallback {
    /// Create a new callback wrapper.
    pub fn new(driver: Arc<ScpDriver>) -> Self {
        Self { driver }
    }

    fn hash_helper<F>(&self, slot_index: u64, prev_value: &Value, extra: F) -> u64
    where
        F: FnOnce(&mut Vec<Vec<u8>>),
    {
        let mut values = Vec::new();
        values.push(Self::xdr_bytes(&slot_index));
        values.push(Self::xdr_bytes(prev_value));
        extra(&mut values);

        let mut data = Vec::new();
        for value in values {
            data.extend_from_slice(&value);
        }
        let hash = Hash256::hash(&data);
        let mut result = 0u64;
        for byte in &hash.as_bytes()[0..8] {
            result = (result << 8) | (*byte as u64);
        }
        result
    }

    fn xdr_bytes<T: stellar_xdr::curr::WriteXdr>(value: &T) -> Vec<u8> {
        value.to_xdr(stellar_xdr::curr::Limits::none()).unwrap_or_default()
    }
}

impl SCPDriver for HerderScpCallback {
    fn validate_value(
        &self,
        slot_index: u64,
        value: &Value,
        _nomination: bool,
    ) -> ValidationLevel {
        match self.driver.validate_value_impl(slot_index, value) {
            ValueValidation::Valid => ValidationLevel::FullyValidated,
            ValueValidation::MaybeValid => ValidationLevel::MaybeValid,
            ValueValidation::Invalid => ValidationLevel::Invalid,
        }
    }

    fn combine_candidates(
        &self,
        slot_index: u64,
        candidates: &[Value],
    ) -> Option<Value> {
        let result = self.driver.combine_candidates_impl(slot_index, candidates);
        if result.0.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn extract_valid_value(
        &self,
        slot_index: u64,
        value: &Value,
    ) -> Option<Value> {
        if value.0.is_empty() {
            return None;
        }

        match self.driver.validate_value_impl(slot_index, value) {
            ValueValidation::Invalid => None,
            ValueValidation::MaybeValid | ValueValidation::Valid => Some(value.clone()),
        }
    }

    fn emit_envelope(&self, envelope: &ScpEnvelope) {
        self.driver.emit(envelope.clone());
    }

    fn get_quorum_set(&self, node_id: &stellar_xdr::curr::NodeId) -> Option<ScpQuorumSet> {
        self.driver.get_quorum_set(node_id)
    }

    fn nominating_value(&self, _slot_index: u64, _value: &Value) {
        // Logging only
    }

    fn value_externalized(&self, slot_index: u64, value: &Value) {
        self.driver.record_externalized(slot_index, value.clone());
    }

    fn ballot_did_prepare(&self, _slot_index: u64, _ballot: &stellar_xdr::curr::ScpBallot) {
        // Logging only
    }

    fn ballot_did_confirm(&self, _slot_index: u64, _ballot: &stellar_xdr::curr::ScpBallot) {
        // Logging only
    }

    fn compute_hash_node(
        &self,
        slot_index: u64,
        prev_value: &Value,
        is_priority: bool,
        round: u32,
        node_id: &stellar_xdr::curr::NodeId,
    ) -> u64 {
        const HASH_N: u32 = 1;
        const HASH_P: u32 = 2;
        self.hash_helper(slot_index, prev_value, |values| {
            let tag = if is_priority { HASH_P } else { HASH_N };
            values.push(Self::xdr_bytes(&tag));
            values.push(Self::xdr_bytes(&round));
            values.push(Self::xdr_bytes(node_id));
        })
    }

    fn compute_value_hash(
        &self,
        slot_index: u64,
        prev_value: &Value,
        round: u32,
        value: &Value,
    ) -> u64 {
        const HASH_K: u32 = 3;
        self.hash_helper(slot_index, prev_value, |values| {
            values.push(Self::xdr_bytes(&HASH_K));
            values.push(Self::xdr_bytes(&round));
            values.push(Self::xdr_bytes(value));
        })
    }

    fn compute_timeout(&self, round: u32, is_nomination: bool) -> std::time::Duration {
        const MAX_TIMEOUT_MS: u64 = 30 * 60 * 1000;
        let mut initial_ms: u64 = 1000;
        let mut increment_ms: u64 = 1000;
        if let Some(manager) = self.driver.ledger_manager.read().as_ref() {
            let header = manager.current_header();
            if header.ledger_version >= 23 {
                if let Some(timing) = manager.scp_timing() {
                    if is_nomination {
                        initial_ms = timing.nomination_timeout_initial_milliseconds as u64;
                        increment_ms = timing.nomination_timeout_increment_milliseconds as u64;
                    } else {
                        initial_ms = timing.ballot_timeout_initial_milliseconds as u64;
                        increment_ms = timing.ballot_timeout_increment_milliseconds as u64;
                    }
                }
            }
        }
        let round = round.max(1) as u64;
        let timeout_ms = initial_ms.saturating_add((round - 1).saturating_mul(increment_ms));
        std::time::Duration::from_millis(timeout_ms.min(MAX_TIMEOUT_MS))
    }

    fn sign_envelope(&self, envelope: &mut ScpEnvelope) {
        if let Some(sig) = self.driver.sign_envelope(&envelope.statement) {
            envelope.signature = stellar_xdr::curr::Signature(sig.0.to_vec().try_into().unwrap_or_default());
        }
    }

    fn verify_envelope(&self, envelope: &ScpEnvelope) -> bool {
        self.driver.verify_envelope(envelope).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{Limits, StellarValue, StellarValueExt, TimePoint, UpgradeType, VecM};

    fn make_test_driver() -> ScpDriver {
        let config = ScpDriverConfig::default();
        ScpDriver::new(config, Hash256::ZERO)
    }

    #[test]
    fn test_tx_set_caching() {
        let driver = make_test_driver();

        let tx_set = TransactionSet::new(Hash256::ZERO, vec![]);
        let hash = tx_set.hash;

        driver.cache_tx_set(tx_set);
        assert!(driver.has_tx_set(&hash));

        let cached = driver.get_tx_set(&hash);
        assert!(cached.is_some());
    }

    #[test]
    fn test_externalized_recording() {
        let driver = make_test_driver();

        assert!(driver.latest_externalized_slot().is_none());

        driver.record_externalized(100, Value::default());
        assert_eq!(driver.latest_externalized_slot(), Some(100));

        driver.record_externalized(99, Value::default()); // older slot
        assert_eq!(driver.latest_externalized_slot(), Some(100)); // still 100

        driver.record_externalized(101, Value::default());
        assert_eq!(driver.latest_externalized_slot(), Some(101));
    }

    #[test]
    fn test_cleanup_externalized() {
        let driver = make_test_driver();

        for slot in 1..=10 {
            driver.record_externalized(slot, Value::default());
        }

        assert_eq!(driver.externalized.read().len(), 10);

        driver.cleanup_externalized(5);
        assert_eq!(driver.externalized.read().len(), 5);

        // Should keep slots 6-10
        let externalized = driver.externalized.read();
        assert!(!externalized.contains_key(&1));
        assert!(!externalized.contains_key(&5));
        assert!(externalized.contains_key(&6));
        assert!(externalized.contains_key(&10));
    }

    #[test]
    fn test_combine_single_value() {
        let driver = make_test_driver();

        let value = Value(vec![1, 2, 3].try_into().unwrap());
        let result = driver.combine_candidates_impl(1, &[value.clone()]);
        assert_eq!(result, value);
    }

    #[test]
    fn test_combine_empty() {
        let driver = make_test_driver();

        let result = driver.combine_candidates_impl(1, &[]);
        assert_eq!(result, Value::default());
    }

    #[test]
    fn test_invalid_upgrade_rejected() {
        let driver = make_test_driver();

        let tx_set = TransactionSet::new(Hash256::ZERO, vec![]);
        let tx_set_hash = tx_set.hash;
        driver.cache_tx_set(tx_set);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let invalid_upgrade = UpgradeType(vec![0u8; 1].try_into().unwrap());
        let stellar_value = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set_hash.0),
            close_time: TimePoint(now),
            upgrades: vec![invalid_upgrade].try_into().unwrap(),
            ext: StellarValueExt::Basic,
        };

        let value = Value(
            stellar_value
                .to_xdr(Limits::none())
                .expect("xdr")
                .try_into()
                .unwrap(),
        );

        assert_eq!(driver.validate_value_impl(1, &value), ValueValidation::Invalid);
    }

    #[test]
    fn test_tx_set_hash_mismatch_rejected() {
        let driver = make_test_driver();

        let tx_set = TransactionSet::with_hash(Hash256::ZERO, Hash256::ZERO, vec![]);
        let tx_set_hash = tx_set.hash;
        driver.cache_tx_set(tx_set);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stellar_value = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set_hash.0),
            close_time: TimePoint(now),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        };

        let value = Value(
            stellar_value
                .to_xdr(Limits::none())
                .expect("xdr")
                .try_into()
                .unwrap(),
        );

        assert_eq!(driver.validate_value_impl(1, &value), ValueValidation::Invalid);
    }

    #[test]
    fn test_close_time_must_increase() {
        let driver = make_test_driver();

        let tx_set = TransactionSet::new(Hash256::ZERO, vec![]);
        let tx_set_hash = tx_set.hash;
        driver.cache_tx_set(tx_set);

        let base_close_time = 100;
        let ext_value = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set_hash.0),
            close_time: TimePoint(base_close_time),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        };
        let ext = Value(
            ext_value
                .to_xdr(Limits::none())
                .expect("xdr")
                .try_into()
                .unwrap(),
        );
        driver.record_externalized(1, ext);

        let candidate = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set_hash.0),
            close_time: TimePoint(base_close_time),
            upgrades: VecM::default(),
            ext: StellarValueExt::Basic,
        };
        let value = Value(
            candidate
                .to_xdr(Limits::none())
                .expect("xdr")
                .try_into()
                .unwrap(),
        );

        assert_eq!(driver.validate_value_impl(2, &value), ValueValidation::Invalid);
    }

    #[test]
    fn test_invalid_upgrade_order_rejected() {
        let driver = make_test_driver();

        let tx_set = TransactionSet::new(Hash256::ZERO, vec![]);
        let tx_set_hash = tx_set.hash;
        driver.cache_tx_set(tx_set);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let base_fee = LedgerUpgrade::BaseFee(200)
            .to_xdr(Limits::none())
            .expect("xdr");
        let version = LedgerUpgrade::Version(25)
            .to_xdr(Limits::none())
            .expect("xdr");
        let upgrades = vec![
            UpgradeType(base_fee.try_into().unwrap()),
            UpgradeType(version.try_into().unwrap()),
        ];

        let stellar_value = StellarValue {
            tx_set_hash: stellar_xdr::curr::Hash(tx_set_hash.0),
            close_time: TimePoint(now),
            upgrades: upgrades.try_into().unwrap(),
            ext: StellarValueExt::Basic,
        };

        let value = Value(
            stellar_value
                .to_xdr(Limits::none())
                .expect("xdr")
                .try_into()
                .unwrap(),
        );

        assert_eq!(driver.validate_value_impl(1, &value), ValueValidation::Invalid);
    }
}
