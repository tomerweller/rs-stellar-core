//! Pending SCP envelope management.
//!
//! This module handles buffering and releasing SCP envelopes that arrive
//! for slots that are not yet active. Once a slot becomes active (the node
//! has caught up to that point), the pending envelopes are released for
//! processing.

use dashmap::DashMap;
use parking_lot::RwLock;
use stellar_core_common::Hash256;
use stellar_core_scp::SlotIndex;
use stellar_xdr::curr::ScpEnvelope;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Configuration for pending envelope management.
#[derive(Debug, Clone)]
pub struct PendingConfig {
    /// Maximum number of pending envelopes per slot.
    pub max_per_slot: usize,
    /// Maximum number of slots to buffer.
    pub max_slots: usize,
    /// Maximum age of pending envelopes before eviction.
    pub max_age: Duration,
    /// How far ahead of the current slot to accept envelopes.
    pub max_slot_distance: u64,
}

impl Default for PendingConfig {
    fn default() -> Self {
        Self {
            max_per_slot: 100,
            max_slots: 12,
            max_age: Duration::from_secs(300),
            max_slot_distance: 12,
        }
    }
}

/// A pending SCP envelope with metadata.
#[derive(Debug, Clone)]
pub struct PendingEnvelope {
    /// The SCP envelope.
    pub envelope: ScpEnvelope,
    /// When this envelope was received.
    pub received_at: Instant,
    /// Hash of the envelope for deduplication.
    pub hash: Hash256,
}

impl PendingEnvelope {
    /// Create a new pending envelope.
    pub fn new(envelope: ScpEnvelope) -> Self {
        // Compute envelope hash for deduplication
        let hash = Hash256::hash_xdr(&envelope).unwrap_or(Hash256::ZERO);
        Self {
            envelope,
            received_at: Instant::now(),
            hash,
        }
    }

    /// Check if this envelope has expired.
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.received_at.elapsed() > max_age
    }
}

/// Result of adding an envelope to pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingResult {
    /// Envelope was added successfully.
    Added,
    /// Envelope is a duplicate.
    Duplicate,
    /// Slot is too far ahead.
    SlotTooFar,
    /// Slot is too old.
    SlotTooOld,
    /// Buffer is full.
    BufferFull,
}

/// Manages pending SCP envelopes for future slots.
///
/// When the node is catching up or when envelopes arrive for future slots,
/// they are buffered here until the slot becomes active.
pub struct PendingEnvelopes {
    /// Configuration.
    config: PendingConfig,
    /// Pending envelopes organized by slot.
    slots: DashMap<SlotIndex, Vec<PendingEnvelope>>,
    /// Seen envelope hashes for deduplication.
    seen_hashes: DashMap<Hash256, ()>,
    /// Current active slot.
    current_slot: RwLock<SlotIndex>,
    /// Statistics.
    stats: RwLock<PendingStats>,
}

/// Statistics about pending envelope management.
#[derive(Debug, Clone, Default)]
pub struct PendingStats {
    /// Total envelopes received.
    pub received: u64,
    /// Envelopes added to pending.
    pub added: u64,
    /// Duplicate envelopes rejected.
    pub duplicates: u64,
    /// Envelopes rejected for being too old.
    pub too_old: u64,
    /// Envelopes rejected for being too far ahead.
    pub too_far: u64,
    /// Envelopes released for processing.
    pub released: u64,
    /// Envelopes evicted due to expiration.
    pub evicted: u64,
}

impl PendingEnvelopes {
    /// Create a new pending envelope manager.
    pub fn new(config: PendingConfig) -> Self {
        Self {
            config,
            slots: DashMap::new(),
            seen_hashes: DashMap::new(),
            current_slot: RwLock::new(0),
            stats: RwLock::new(PendingStats::default()),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(PendingConfig::default())
    }

    /// Set the current active slot.
    pub fn set_current_slot(&self, slot: SlotIndex) {
        let mut current = self.current_slot.write();
        *current = slot;
    }

    /// Get the current active slot.
    pub fn current_slot(&self) -> SlotIndex {
        *self.current_slot.read()
    }

    /// Add an envelope for a future slot.
    pub fn add(&self, slot: SlotIndex, envelope: ScpEnvelope) -> PendingResult {
        self.stats.write().received += 1;

        let current = self.current_slot();

        // Check if slot is too old
        if slot < current {
            self.stats.write().too_old += 1;
            return PendingResult::SlotTooOld;
        }

        // Check if slot is too far ahead
        if slot > current + self.config.max_slot_distance {
            self.stats.write().too_far += 1;
            return PendingResult::SlotTooFar;
        }

        let pending = PendingEnvelope::new(envelope);

        // Check for duplicate
        if self.seen_hashes.contains_key(&pending.hash) {
            self.stats.write().duplicates += 1;
            return PendingResult::Duplicate;
        }

        // Check buffer limits
        if self.slots.len() >= self.config.max_slots {
            // Try to evict old slots first
            self.evict_old_slots(current);
            if self.slots.len() >= self.config.max_slots {
                return PendingResult::BufferFull;
            }
        }

        // Add to pending
        self.seen_hashes.insert(pending.hash, ());

        let mut entry = self.slots.entry(slot).or_insert_with(Vec::new);
        if entry.len() >= self.config.max_per_slot {
            return PendingResult::BufferFull;
        }
        entry.push(pending);

        self.stats.write().added += 1;
        PendingResult::Added
    }

    /// Release all envelopes for a slot that has become active.
    pub fn release(&self, slot: SlotIndex) -> Vec<ScpEnvelope> {
        if let Some((_, envelopes)) = self.slots.remove(&slot) {
            let count = envelopes.len() as u64;
            self.stats.write().released += count;

            // Remove from seen hashes
            for env in &envelopes {
                self.seen_hashes.remove(&env.hash);
            }

            envelopes
                .into_iter()
                .filter(|e| !e.is_expired(self.config.max_age))
                .map(|e| e.envelope)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Release all envelopes up to and including the given slot.
    pub fn release_up_to(&self, slot: SlotIndex) -> BTreeMap<SlotIndex, Vec<ScpEnvelope>> {
        let mut result = BTreeMap::new();
        let slots_to_release: Vec<SlotIndex> = self
            .slots
            .iter()
            .filter(|e| *e.key() <= slot)
            .map(|e| *e.key())
            .collect();

        for s in slots_to_release {
            let envelopes = self.release(s);
            if !envelopes.is_empty() {
                result.insert(s, envelopes);
            }
        }

        result
    }

    /// Evict old slots that are behind the current slot.
    fn evict_old_slots(&self, current: SlotIndex) {
        let old_slots: Vec<SlotIndex> = self
            .slots
            .iter()
            .filter(|e| *e.key() < current)
            .map(|e| *e.key())
            .collect();

        for slot in old_slots {
            if let Some((_, envelopes)) = self.slots.remove(&slot) {
                let count = envelopes.len() as u64;
                self.stats.write().evicted += count;

                for env in envelopes {
                    self.seen_hashes.remove(&env.hash);
                }
            }
        }
    }

    /// Evict expired envelopes from all slots.
    pub fn evict_expired(&self) {
        let max_age = self.config.max_age;

        for mut entry in self.slots.iter_mut() {
            let initial_len = entry.len();

            // Collect hashes of expired envelopes
            let expired_hashes: Vec<Hash256> = entry
                .iter()
                .filter(|e| e.is_expired(max_age))
                .map(|e| e.hash)
                .collect();

            // Remove expired envelopes
            entry.retain(|e| !e.is_expired(max_age));

            let removed = initial_len - entry.len();
            if removed > 0 {
                self.stats.write().evicted += removed as u64;

                // Remove from seen hashes
                for hash in expired_hashes {
                    self.seen_hashes.remove(&hash);
                }
            }
        }

        // Remove empty slots
        self.slots.retain(|_, v| !v.is_empty());
    }

    /// Get the number of pending envelopes.
    pub fn len(&self) -> usize {
        self.slots.iter().map(|e| e.len()).sum()
    }

    /// Check if there are no pending envelopes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of slots with pending envelopes.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Get statistics.
    pub fn stats(&self) -> PendingStats {
        self.stats.read().clone()
    }

    /// Check if there are pending envelopes for a slot.
    pub fn has_pending(&self, slot: SlotIndex) -> bool {
        self.slots.get(&slot).map(|e| !e.is_empty()).unwrap_or(false)
    }

    /// Get the count of pending envelopes for a slot.
    pub fn pending_count(&self, slot: SlotIndex) -> usize {
        self.slots.get(&slot).map(|e| e.len()).unwrap_or(0)
    }

    /// Clear all pending envelopes.
    pub fn clear(&self) {
        self.slots.clear();
        self.seen_hashes.clear();
    }
}

impl Default for PendingEnvelopes {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScpEnvelope, ScpStatement, ScpNomination, ScpStatementPledges, NodeId as XdrNodeId,
        PublicKey, Uint256, Hash,
    };

    fn make_test_envelope(slot: SlotIndex) -> ScpEnvelope {
        // Create a minimal SCP envelope for testing
        let node_id = XdrNodeId(PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])));

        ScpEnvelope {
            statement: ScpStatement {
                node_id,
                slot_index: slot,
                pledges: ScpStatementPledges::Nominate(ScpNomination {
                    quorum_set_hash: Hash([0u8; 32]),
                    votes: vec![].try_into().unwrap(),
                    accepted: vec![].try_into().unwrap(),
                }),
            },
            signature: stellar_xdr::curr::Signature(vec![0u8; 64].try_into().unwrap()),
        }
    }

    #[test]
    fn test_add_and_release() {
        let pending = PendingEnvelopes::with_defaults();
        pending.set_current_slot(100);

        // Add envelope for slot 101
        let envelope = make_test_envelope(101);
        let result = pending.add(101, envelope.clone());
        assert_eq!(result, PendingResult::Added);
        assert_eq!(pending.len(), 1);

        // Release slot 101
        let released = pending.release(101);
        assert_eq!(released.len(), 1);
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_duplicate_detection() {
        let pending = PendingEnvelopes::with_defaults();
        pending.set_current_slot(100);

        let envelope = make_test_envelope(101);

        let result1 = pending.add(101, envelope.clone());
        assert_eq!(result1, PendingResult::Added);

        let result2 = pending.add(101, envelope);
        assert_eq!(result2, PendingResult::Duplicate);

        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_slot_too_old() {
        let pending = PendingEnvelopes::with_defaults();
        pending.set_current_slot(100);

        let envelope = make_test_envelope(99);
        let result = pending.add(99, envelope);
        assert_eq!(result, PendingResult::SlotTooOld);
    }

    #[test]
    fn test_slot_too_far() {
        let config = PendingConfig {
            max_slot_distance: 5,
            ..Default::default()
        };
        let pending = PendingEnvelopes::new(config);
        pending.set_current_slot(100);

        let envelope = make_test_envelope(106);
        let result = pending.add(106, envelope);
        assert_eq!(result, PendingResult::SlotTooFar);
    }

    #[test]
    fn test_release_up_to() {
        let pending = PendingEnvelopes::with_defaults();
        pending.set_current_slot(100);

        pending.add(101, make_test_envelope(101));
        pending.add(102, make_test_envelope(102));
        pending.add(103, make_test_envelope(103));

        assert_eq!(pending.slot_count(), 3);

        let released = pending.release_up_to(102);
        assert_eq!(released.len(), 2);
        assert!(released.contains_key(&101));
        assert!(released.contains_key(&102));
        assert_eq!(pending.slot_count(), 1);
    }
}
