//! FloodGate for managing message propagation.
//!
//! Tracks seen messages by hash to prevent duplicate flooding.
//! Uses TTL-based expiry to clean up old entries.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use stellar_core_common::Hash256;
use stellar_xdr::curr::StellarMessage;
use tracing::{debug, trace};

use crate::PeerId;

/// Default TTL for seen messages (5 minutes).
const DEFAULT_TTL_SECS: u64 = 300;

/// Maximum number of entries before cleanup is forced.
const MAX_ENTRIES: usize = 100_000;

/// Cleanup interval in seconds.
const CLEANUP_INTERVAL_SECS: u64 = 60;
/// Default max messages per second (soft rate limit).
const DEFAULT_RATE_LIMIT_PER_SEC: u64 = 1000;

/// Entry for a seen message.
struct SeenEntry {
    /// When the message was first seen.
    first_seen: Instant,
    /// Peers that have sent us this message.
    peers: HashSet<PeerId>,
}

impl SeenEntry {
    fn new() -> Self {
        Self {
            first_seen: Instant::now(),
            peers: HashSet::new(),
        }
    }

    fn add_peer(&mut self, peer: PeerId) {
        self.peers.insert(peer);
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.first_seen.elapsed() > ttl
    }
}

/// FloodGate manages message propagation in the overlay network.
///
/// It tracks which messages have been seen to prevent duplicate flooding
/// and manages which peers should receive forwarded messages.
pub struct FloodGate {
    /// Map of message hash -> seen entry.
    seen: DashMap<Hash256, SeenEntry>,
    /// TTL for message expiry.
    ttl: Duration,
    /// Last cleanup time.
    last_cleanup: RwLock<Instant>,
    /// Total messages seen.
    messages_seen: AtomicU64,
    /// Total messages dropped (duplicates).
    messages_dropped: AtomicU64,
    /// Max messages allowed per second.
    rate_limit: u64,
    /// Start time for the current rate window.
    rate_window_start: RwLock<Instant>,
    /// Count of messages seen in the current window.
    rate_window_count: AtomicU64,
}

impl FloodGate {
    /// Create a new FloodGate with default TTL.
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(DEFAULT_TTL_SECS))
    }

    /// Create a new FloodGate with custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            seen: DashMap::new(),
            ttl,
            last_cleanup: RwLock::new(Instant::now()),
            messages_seen: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            rate_limit: DEFAULT_RATE_LIMIT_PER_SEC,
            rate_window_start: RwLock::new(Instant::now()),
            rate_window_count: AtomicU64::new(0),
        }
    }

    /// Check if a message should be flooded (not seen before).
    pub fn should_flood(&self, message_hash: &Hash256) -> bool {
        !self.seen.contains_key(message_hash)
    }

    /// Record that a message has been seen from a peer.
    ///
    /// Returns true if this is the first time seeing this message.
    pub fn record_seen(&self, message_hash: Hash256, from_peer: Option<PeerId>) -> bool {
        self.messages_seen.fetch_add(1, Ordering::Relaxed);

        // Try cleanup if needed
        self.maybe_cleanup();

        // Check if we've seen this message
        if let Some(mut entry) = self.seen.get_mut(&message_hash) {
            // Already seen, record the peer
            if let Some(peer) = from_peer {
                entry.add_peer(peer);
            }
            self.messages_dropped.fetch_add(1, Ordering::Relaxed);
            trace!("Duplicate message: {}", message_hash);
            return false;
        }

        // New message
        let mut entry = SeenEntry::new();
        if let Some(peer) = from_peer {
            entry.add_peer(peer);
        }
        self.seen.insert(message_hash, entry);
        trace!("New message: {}", message_hash);
        true
    }

    /// Check if the current message rate is within limits.
    pub fn allow_message(&self) -> bool {
        let now = Instant::now();
        {
            let mut start = self.rate_window_start.write();
            if now.duration_since(*start) >= Duration::from_secs(1) {
                *start = now;
                self.rate_window_count.store(0, Ordering::Relaxed);
            }
        }

        let count = self.rate_window_count.fetch_add(1, Ordering::Relaxed) + 1;
        count <= self.rate_limit
    }

    /// Get peers to forward a message to (excluding peers that sent it to us).
    pub fn get_forward_peers(
        &self,
        message_hash: &Hash256,
        all_peers: &[PeerId],
    ) -> Vec<PeerId> {
        let exclude: HashSet<PeerId> = self
            .seen
            .get(message_hash)
            .map(|entry| entry.peers.iter().cloned().collect())
            .unwrap_or_default();

        all_peers
            .iter()
            .filter(|p| !exclude.contains(*p))
            .cloned()
            .collect()
    }

    /// Check if a message has been seen.
    pub fn has_seen(&self, message_hash: &Hash256) -> bool {
        self.seen.contains_key(message_hash)
    }

    /// Force cleanup of expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let ttl = self.ttl;

        let before_count = self.seen.len();
        self.seen.retain(|_, entry| !entry.is_expired(ttl));
        let removed = before_count - self.seen.len();

        if removed > 0 {
            debug!("FloodGate cleanup: removed {} expired entries", removed);
        }

        *self.last_cleanup.write() = now;
    }

    /// Maybe run cleanup if interval has passed or too many entries.
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = *self.last_cleanup.read();
            last.elapsed() > Duration::from_secs(CLEANUP_INTERVAL_SECS)
                || self.seen.len() > MAX_ENTRIES
        };

        if should_cleanup {
            self.cleanup();
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> FloodGateStats {
        FloodGateStats {
            seen_count: self.seen.len(),
            total_messages: self.messages_seen.load(Ordering::Relaxed),
            dropped_messages: self.messages_dropped.load(Ordering::Relaxed),
        }
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.seen.clear();
        *self.last_cleanup.write() = Instant::now();
    }
}

impl Default for FloodGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for FloodGate.
#[derive(Debug, Clone)]
pub struct FloodGateStats {
    /// Number of messages currently tracked.
    pub seen_count: usize,
    /// Total messages processed.
    pub total_messages: u64,
    /// Messages dropped as duplicates.
    pub dropped_messages: u64,
}

impl FloodGateStats {
    /// Get the duplicate rate as a percentage.
    pub fn duplicate_rate(&self) -> f64 {
        if self.total_messages == 0 {
            0.0
        } else {
            (self.dropped_messages as f64 / self.total_messages as f64) * 100.0
        }
    }
}

/// Helper to compute message hash.
pub fn compute_message_hash(message: &StellarMessage) -> Hash256 {
    use stellar_xdr::curr::{Limits, WriteXdr};
    let bytes = message.to_xdr(Limits::none()).unwrap_or_default();
    Hash256::hash(&bytes)
}

/// Message flood record for tracking which peers need a message.
pub struct FloodRecord {
    /// Message hash.
    pub hash: Hash256,
    /// The message.
    pub message: StellarMessage,
    /// When it was received.
    pub received: Instant,
    /// Peer that sent it.
    pub from_peer: Option<PeerId>,
}

impl FloodRecord {
    /// Create a new flood record.
    pub fn new(message: StellarMessage, from_peer: Option<PeerId>) -> Self {
        let hash = compute_message_hash(&message);
        Self {
            hash,
            message,
            received: Instant::now(),
            from_peer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(v: u8) -> Hash256 {
        Hash256([v; 32])
    }

    fn make_peer_id(v: u8) -> PeerId {
        PeerId::from_bytes([v; 32])
    }

    #[test]
    fn test_flood_gate_basic() {
        let gate = FloodGate::new();

        let hash = make_hash(1);
        assert!(gate.should_flood(&hash));

        // Record as seen
        assert!(gate.record_seen(hash, None));

        // Should not flood again
        assert!(!gate.should_flood(&hash));

        // Record again should return false
        assert!(!gate.record_seen(hash, None));
    }

    #[test]
    fn test_flood_gate_with_peers() {
        let gate = FloodGate::new();

        let hash = make_hash(1);
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);
        let peer3 = make_peer_id(3);

        // First seen from peer1
        assert!(gate.record_seen(hash, Some(peer1.clone())));

        // Also seen from peer2
        assert!(!gate.record_seen(hash, Some(peer2.clone())));

        // Get forward peers - should exclude peer1 and peer2
        let all_peers = vec![peer1.clone(), peer2.clone(), peer3.clone()];
        let forward = gate.get_forward_peers(&hash, &all_peers);

        assert_eq!(forward.len(), 1);
        assert_eq!(forward[0], peer3);
    }

    #[test]
    fn test_flood_gate_stats() {
        let gate = FloodGate::new();

        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        gate.record_seen(hash1, None);
        gate.record_seen(hash1, None); // duplicate
        gate.record_seen(hash2, None);

        let stats = gate.stats();
        assert_eq!(stats.seen_count, 2);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.dropped_messages, 1);
    }

    #[test]
    fn test_flood_gate_expiry() {
        let gate = FloodGate::with_ttl(Duration::from_millis(10));

        let hash = make_hash(1);
        gate.record_seen(hash, None);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        // Force cleanup
        gate.cleanup();

        // Should be able to flood again
        assert!(gate.should_flood(&hash));
    }

    #[test]
    fn test_flood_record() {
        let message = StellarMessage::Peers(stellar_xdr::curr::VecM::default());
        let record = FloodRecord::new(message, None);

        assert!(!record.hash.is_zero());
        assert!(record.from_peer.is_none());
    }
}
