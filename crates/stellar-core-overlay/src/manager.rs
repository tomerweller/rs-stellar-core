//! OverlayManager for managing all peer connections.
//!
//! Handles:
//! - Accepting incoming connections
//! - Connecting to outbound peers
//! - Broadcasting messages
//! - Message routing

use crate::{
    codec::helpers,
    connection::{ConnectionPool, Listener},
    flood::{compute_message_hash, FloodGate, FloodGateStats},
    peer::{Peer, PeerInfo, PeerStatsSnapshot},
    LocalNode, OverlayConfig, OverlayError, PeerAddress, PeerEvent, PeerId, PeerType, Result,
};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stellar_xdr::curr::{PeerAddress as XdrPeerAddress, PeerAddressIp, StellarMessage, VecM};
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tokio::task::JoinHandle;
use parking_lot::RwLock;
use tracing::{debug, error, info, trace, warn};
use rand::seq::SliceRandom;

fn message_len(message: &StellarMessage) -> u64 {
    stellar_xdr::curr::WriteXdr::to_xdr(message, stellar_xdr::curr::Limits::none())
        .map(|bytes| bytes.len() as u64)
        .unwrap_or(0)
}

fn is_fetch_message(message: &StellarMessage) -> bool {
    matches!(
        message,
        StellarMessage::GetTxSet(_)
            | StellarMessage::TxSet(_)
            | StellarMessage::GeneralizedTxSet(_)
            | StellarMessage::GetScpState(_)
            | StellarMessage::ScpQuorumset(_)
            | StellarMessage::GetScpQuorumset(_)
            | StellarMessage::DontHave(_)
    )
}

/// Message received from the overlay.
#[derive(Debug, Clone)]
pub struct OverlayMessage {
    /// The peer that sent the message.
    pub from_peer: PeerId,
    /// The message.
    pub message: StellarMessage,
}

/// Snapshot of a connected peer.
#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub info: PeerInfo,
    pub stats: PeerStatsSnapshot,
}

/// Manager for all peer connections.
pub struct OverlayManager {
    /// Configuration.
    config: OverlayConfig,
    /// Local node info.
    local_node: LocalNode,
    /// Connected peers (using TokioMutex so guards can be held across await).
    peers: Arc<DashMap<PeerId, Arc<TokioMutex<Peer>>>>,
    /// Flood gate.
    flood_gate: Arc<FloodGate>,
    /// Connection pool for inbound connections.
    inbound_pool: Arc<ConnectionPool>,
    /// Connection pool for outbound connections.
    outbound_pool: Arc<ConnectionPool>,
    /// Whether the manager is running.
    running: Arc<AtomicBool>,
    /// Channel for incoming messages.
    message_tx: broadcast::Sender<OverlayMessage>,
    /// Handle to listener task.
    listener_handle: Option<JoinHandle<()>>,
    /// Handle to connector task.
    connector_handle: Option<JoinHandle<()>>,
    /// Handle to peer tasks.
    peer_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    /// Known peers learned from discovery.
    known_peers: Arc<RwLock<Vec<PeerAddress>>>,
    /// Outbound peers to advertise in Peers messages.
    advertised_outbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
    /// Inbound peers to advertise in Peers messages.
    advertised_inbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
    /// Handle to periodic peer advertiser task.
    peer_advertiser_handle: Option<JoinHandle<()>>,
    /// Total authenticated peers added.
    added_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
    /// Total authenticated peers dropped.
    dropped_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
    /// Banned peers by node ID.
    banned_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Shutdown signal.
    shutdown_tx: Option<broadcast::Sender<()>>,
    /// Cache of peer info for connected peers (lock-free access).
    peer_info_cache: Arc<DashMap<PeerId, PeerInfo>>,
}

impl OverlayManager {
    /// Create a new overlay manager with the given configuration.
    pub fn new(config: OverlayConfig, local_node: LocalNode) -> Result<Self> {
        let (message_tx, _) = broadcast::channel(65536);
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config: config.clone(),
            local_node,
            peers: Arc::new(DashMap::new()),
            flood_gate: Arc::new(FloodGate::with_ttl(Duration::from_secs(config.flood_ttl_secs))),
            inbound_pool: Arc::new(ConnectionPool::new(config.max_inbound_peers)),
            outbound_pool: Arc::new(ConnectionPool::new(config.max_outbound_peers)),
            running: Arc::new(AtomicBool::new(false)),
            message_tx,
            listener_handle: None,
            connector_handle: None,
            peer_handles: Arc::new(RwLock::new(Vec::new())),
            known_peers: Arc::new(RwLock::new(config.known_peers.clone())),
            advertised_outbound_peers: Arc::new(RwLock::new(config.known_peers.clone())),
            advertised_inbound_peers: Arc::new(RwLock::new(Vec::new())),
            peer_advertiser_handle: None,
            added_authenticated_peers: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            dropped_authenticated_peers: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            banned_peers: Arc::new(RwLock::new(HashSet::new())),
            shutdown_tx: Some(shutdown_tx),
            peer_info_cache: Arc::new(DashMap::new()),
        })
    }

    /// Start the overlay network (listening and connecting to peers).
    pub async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::AlreadyStarted);
        }

        info!("Starting overlay manager");
        self.running.store(true, Ordering::Relaxed);

        // Start listener if enabled
        if self.config.listen_enabled {
            self.start_listener().await?;
        }

        // Start connector for known peers
        self.start_connector();
        self.start_peer_advertiser();

        Ok(())
    }

    /// Start the connection listener.
    async fn start_listener(&mut self) -> Result<()> {
        let listener = Listener::bind(self.config.listen_port).await?;
        info!("Listening on port {}", self.config.listen_port);

        let peers = Arc::clone(&self.peers);
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.inbound_pool);
        let running = Arc::clone(&self.running);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
        let peer_handles = Arc::clone(&self.peer_handles);
        let advertised_outbound_peers = Arc::clone(&self.advertised_outbound_peers);
        let advertised_inbound_peers = Arc::clone(&self.advertised_inbound_peers);
        let added_authenticated_peers = Arc::clone(&self.added_authenticated_peers);
        let dropped_authenticated_peers = Arc::clone(&self.dropped_authenticated_peers);
        let banned_peers = Arc::clone(&self.banned_peers);
        let peer_info_cache = Arc::clone(&self.peer_info_cache);
        let auth_timeout = self.config.auth_timeout_secs;
        let peer_event_tx = self.config.peer_event_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok(connection) => {
                                if !pool.try_reserve() {
                                    warn!("Inbound peer limit reached, rejecting connection");
                                    continue;
                                }

                                let peers = Arc::clone(&peers);
                                let local_node = local_node.clone();
                                let pool = Arc::clone(&pool);
                                let message_tx = message_tx.clone();
                                let flood_gate = Arc::clone(&flood_gate);
                                let running = Arc::clone(&running);
                                let advertised_outbound_peers =
                                    Arc::clone(&advertised_outbound_peers);
                                let advertised_inbound_peers =
                                    Arc::clone(&advertised_inbound_peers);
                                let peer_event_tx = peer_event_tx.clone();
                                let added_authenticated_peers = Arc::clone(&added_authenticated_peers);
                                let dropped_authenticated_peers = Arc::clone(&dropped_authenticated_peers);
                                let banned_peers = Arc::clone(&banned_peers);
                                let peer_info_cache = Arc::clone(&peer_info_cache);

                                let peer_handle = tokio::spawn(async move {
                                    let remote_addr = connection.remote_addr();
                                    match Peer::accept(connection, local_node, auth_timeout).await {
                                        Ok(mut peer) => {
                                            let peer_id = peer.id().clone();
                                            if banned_peers.read().contains(&peer_id) {
                                                warn!("Rejected banned peer {}", peer_id);
                                                peer.close().await;
                                                pool.release();
                                                return;
                                            }
                                            info!("Accepted peer: {}", peer_id);

                                            let peer_info = peer.info().clone();
                                            if let Some(tx) = peer_event_tx.clone() {
                                                let addr = peer_info.address;
                                                let peer_addr = PeerAddress::new(
                                                    addr.ip().to_string(),
                                                    addr.port(),
                                                );
                                                let _ = tx
                                                    .send(PeerEvent::Connected(
                                                        peer_addr,
                                                        PeerType::Inbound,
                                                    ))
                                                    .await;
                                            }

                                            let peer = Arc::new(TokioMutex::new(peer));
                                            peers.insert(peer_id.clone(), Arc::clone(&peer));
                                            peer_info_cache.insert(peer_id.clone(), peer_info.clone());
                                            added_authenticated_peers.fetch_add(1, Ordering::Relaxed);

                                            let outbound_snapshot =
                                                advertised_outbound_peers.read().clone();
                                            let inbound_snapshot =
                                                advertised_inbound_peers.read().clone();
                                            let exclude = PeerAddress::new(
                                                peer_info.address.ip().to_string(),
                                                peer_info.address.port(),
                                            );
                                            if let Some(message) =
                                                OverlayManager::build_peers_message(
                                                    &outbound_snapshot,
                                                    &inbound_snapshot,
                                                    Some(&exclude),
                                                )
                                            {
                                                let mut peer_lock = peer.lock().await;
                                                if peer_lock.is_ready() {
                                                    if let Err(e) = peer_lock.send(message).await {
                                                        debug!(
                                                            "Failed to send peers to {}: {}",
                                                            peer_id, e
                                                        );
                                                    }
                                                }
                                            }

                                            // Run peer loop
                                            Self::run_peer_loop(
                                                peer_id.clone(),
                                                peer,
                                                message_tx,
                                                flood_gate,
                                                running,
                                            ).await;

                                            // Cleanup
                                            peers.remove(&peer_id);
                                            peer_info_cache.remove(&peer_id);
                                            dropped_authenticated_peers.fetch_add(1, Ordering::Relaxed);
                                            pool.release();
                                        }
                                        Err(e) => {
                                            warn!("Failed to accept peer: {}", e);
                                            if let Some(tx) = peer_event_tx.clone() {
                                                let addr = remote_addr;
                                                let peer_addr = PeerAddress::new(
                                                    addr.ip().to_string(),
                                                    addr.port(),
                                                );
                                                let _ = tx
                                                    .send(PeerEvent::Failed(
                                                        peer_addr,
                                                        PeerType::Inbound,
                                                    ))
                                                    .await;
                                            }
                                            pool.release();
                                        }
                                    }
                                });

                                peer_handles.write().push(peer_handle);
                            }
                            Err(e) => {
                                error!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Listener shutting down");
                        break;
                    }
                }

                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        self.listener_handle = Some(handle);
        Ok(())
    }

    /// Start the outbound connector.
    fn start_connector(&mut self) {
        let peers = Arc::clone(&self.peers);
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.outbound_pool);
        let running = Arc::clone(&self.running);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
        let peer_handles = Arc::clone(&self.peer_handles);
        let known_peers = Arc::clone(&self.known_peers);
        let advertised_outbound_peers = Arc::clone(&self.advertised_outbound_peers);
        let advertised_inbound_peers = Arc::clone(&self.advertised_inbound_peers);
        let added_authenticated_peers = Arc::clone(&self.added_authenticated_peers);
        let dropped_authenticated_peers = Arc::clone(&self.dropped_authenticated_peers);
        let banned_peers = Arc::clone(&self.banned_peers);
        let peer_info_cache = Arc::clone(&self.peer_info_cache);
        let preferred_peers = self.config.preferred_peers.clone();
        let target_outbound = self.config.target_outbound_peers;
        let max_outbound = self.config.max_outbound_peers;
        let connect_timeout = self.config.connect_timeout_secs;
        let auth_timeout = self.config.auth_timeout_secs;
        let peer_event_tx = self.config.peer_event_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            let mut retry_after: HashMap<PeerAddress, Instant> = HashMap::new();
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Connector shutting down");
                        break;
                    }
                    _ = interval.tick() => {}
                }

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let now = Instant::now();
                let outbound_count = Self::count_outbound_peers(&peers);
                let available = max_outbound.saturating_sub(outbound_count);
                if available == 0 {
                    continue;
                }

                let mut remaining = available;

                // Preferred peers first
                for addr in &preferred_peers {
                    if remaining == 0 {
                        break;
                    }

                    if let Some(next) = retry_after.get(addr) {
                        if *next > now {
                            continue;
                        }
                    }

                    if Self::has_outbound_connection_to(&peers, addr) {
                        continue;
                    }

                    if !pool.try_reserve() {
                        debug!("Outbound peer limit reached");
                        remaining = 0;
                        break;
                    }

                    let addr = addr.clone();
                    let local_node = local_node.clone();
                    let peers = Arc::clone(&peers);
                    let pool = Arc::clone(&pool);
                    let message_tx = message_tx.clone();
                    let flood_gate = Arc::clone(&flood_gate);
                    let running = Arc::clone(&running);
                    let peer_handles = Arc::clone(&peer_handles);
                    let timeout = connect_timeout.max(auth_timeout);

                    match Self::connect_outbound_inner(
                        &addr,
                        local_node,
                        timeout,
                        peers,
                        pool,
                        message_tx,
                        flood_gate,
                        running,
                        peer_handles,
                        Arc::clone(&advertised_outbound_peers),
                        Arc::clone(&advertised_inbound_peers),
                        Arc::clone(&added_authenticated_peers),
                        Arc::clone(&dropped_authenticated_peers),
                        Arc::clone(&banned_peers),
                        peer_event_tx.clone(),
                        Arc::clone(&peer_info_cache),
                    )
                    .await
                    {
                        Ok(_) => {
                            retry_after.remove(&addr);
                            remaining = remaining.saturating_sub(1);
                        }
                        Err(e) => {
                            warn!("Failed to connect to preferred peer {}: {}", addr, e);
                            retry_after.insert(addr, now + Duration::from_secs(10));
                        }
                    }
                }

                let outbound_count = Self::count_outbound_peers(&peers);
                if remaining == 0 || outbound_count >= target_outbound {
                    continue;
                }

                let mut known_snapshot = known_peers.read().clone();
                known_snapshot.shuffle(&mut rand::thread_rng());

                // Fill remaining outbound slots with known peers up to target_outbound.
                for addr in &known_snapshot {
                    if remaining == 0 {
                        break;
                    }

                    let outbound_now = Self::count_outbound_peers(&peers);
                    if outbound_now >= target_outbound {
                        break;
                    }

                    if let Some(next) = retry_after.get(addr) {
                        if *next > now {
                            continue;
                        }
                    }

                    if Self::has_outbound_connection_to(&peers, addr) {
                        continue;
                    }

                    if !pool.try_reserve() {
                        debug!("Outbound peer limit reached");
                        break;
                    }

                    let addr = addr.clone();
                    let local_node = local_node.clone();
                    let peers = Arc::clone(&peers);
                    let pool = Arc::clone(&pool);
                    let message_tx = message_tx.clone();
                    let flood_gate = Arc::clone(&flood_gate);
                    let running = Arc::clone(&running);
                    let peer_handles = Arc::clone(&peer_handles);
                    let timeout = connect_timeout.max(auth_timeout);

                    match Self::connect_outbound_inner(
                        &addr,
                        local_node,
                        timeout,
                        peers,
                        pool,
                        message_tx,
                        flood_gate,
                        running,
                        peer_handles,
                        Arc::clone(&advertised_outbound_peers),
                        Arc::clone(&advertised_inbound_peers),
                        Arc::clone(&added_authenticated_peers),
                        Arc::clone(&dropped_authenticated_peers),
                        Arc::clone(&banned_peers),
                        peer_event_tx.clone(),
                        Arc::clone(&peer_info_cache),
                    )
                    .await
                    {
                        Ok(_) => {
                            retry_after.remove(&addr);
                            remaining = remaining.saturating_sub(1);
                        }
                        Err(e) => {
                            warn!("Failed to connect to peer {}: {}", addr, e);
                            retry_after.insert(addr, now + Duration::from_secs(10));
                        }
                    }
                }
            }
        });

        self.connector_handle = Some(handle);
    }

    /// Run the peer message loop.
    async fn run_peer_loop(
        peer_id: PeerId,
        peer: Arc<TokioMutex<Peer>>,
        message_tx: broadcast::Sender<OverlayMessage>,
        flood_gate: Arc<FloodGate>,
        running: Arc<AtomicBool>,
    ) {
        // Flow control: track messages received and send SendMoreExtended frequently
        // Peers disconnect if we don't send enough flow control messages
        // CRITICAL: Must use SendMoreExtended since we initialized with it in handshake
        const SEND_MORE_THRESHOLD: u32 = 5; // Send flow control after just 5 messages
        let mut messages_since_send_more = 0u32;
        let mut last_send_more = std::time::Instant::now();
        const SEND_MORE_INTERVAL: Duration = Duration::from_secs(1); // Send every second

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Check if we should send a flow control message proactively
            if last_send_more.elapsed() >= SEND_MORE_INTERVAL {
                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Send generous flow control matching our handshake values
                    // Use SendMoreExtended to match the handshake (not SendMore)
                    if let Err(e) = peer_lock.send_more_extended(500, 50_000_000).await {
                        debug!("Failed to send periodic flow control to {}: {}", peer_id, e);
                    } else {
                        trace!("Sent periodic flow control (SendMoreExtended 500/50MB) to {}", peer_id);
                    }
                }
                last_send_more = std::time::Instant::now();
            }

            // Receive message with timeout to allow periodic flow control
            let message = {
                let mut peer_lock = peer.lock().await;
                if !peer_lock.is_connected() {
                    break;
                }

                // Use a short timeout so we can send periodic flow control messages
                match tokio::time::timeout(Duration::from_secs(2), peer_lock.recv()).await {
                    Ok(Ok(Some(msg))) => msg,
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => {
                        debug!("Peer {} error: {}", peer_id, e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue to check flow control
                        continue;
                    }
                }
            };

            // Process message
            let msg_type = helpers::message_type_name(&message);
            trace!("Processing {} from {}", msg_type, peer_id);

            // Log ERROR messages
            if let stellar_xdr::curr::StellarMessage::ErrorMsg(ref err) = message {
                warn!(
                    "Peer {} sent ERROR: code={:?}, msg={}",
                    peer_id,
                    err.code,
                    err.msg.to_string()
                );
            }

            // Log and handle flow control messages
            match &message {
                stellar_xdr::curr::StellarMessage::SendMore(sm) => {
                    debug!(
                        "Peer {} sent SEND_MORE: num_messages={}",
                        peer_id, sm.num_messages
                    );
                }
                stellar_xdr::curr::StellarMessage::SendMoreExtended(sme) => {
                    debug!(
                        "Peer {} sent SEND_MORE_EXTENDED: num_messages={}, num_bytes={}",
                        peer_id, sme.num_messages, sme.num_bytes
                    );
                }
                _ => {}
            }

            if helpers::is_handshake_message(&message) {
                debug!("Ignoring handshake message from authenticated peer {}", peer_id);
                continue;
            }

            if !flood_gate.allow_message() {
                debug!("Dropping message due to rate limit");
                continue;
            }

            let message_size = message_len(&message);
            if helpers::is_flood_message(&message) {
                let hash = compute_message_hash(&message);
                let unique = flood_gate.record_seen(hash, Some(peer_id.clone()));
                if let Ok(peer_lock) = peer.try_lock() {
                    peer_lock.record_flood_stats(unique, message_size);
                }
                if !unique {
                    continue;
                }
            } else if is_fetch_message(&message) {
                if let Ok(peer_lock) = peer.try_lock() {
                    peer_lock.record_fetch_stats(true, message_size);
                }
            }

            // Forward to subscribers
            let overlay_msg = OverlayMessage {
                from_peer: peer_id.clone(),
                message,
            };

            let _ = message_tx.send(overlay_msg);

            // Flow control: send SendMoreExtended after receiving a batch of messages
            messages_since_send_more += 1;
            if messages_since_send_more >= SEND_MORE_THRESHOLD {
                let mut peer_lock = peer.lock().await;
                if peer_lock.is_connected() {
                    // Send generous capacity matching handshake values
                    if let Err(e) = peer_lock.send_more_extended(500, 50_000_000).await {
                        debug!("Failed to send flow control to {}: {}", peer_id, e);
                    } else {
                        trace!("Sent batch flow control (SendMoreExtended 500/50MB) to {}", peer_id);
                    }
                }
                messages_since_send_more = 0;
                last_send_more = std::time::Instant::now();
            }
        }

        // Close peer
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
        info!("Peer {} disconnected", peer_id);
    }

    /// Connect to a specific peer.
    pub async fn connect(&self, addr: &PeerAddress) -> Result<PeerId> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        if !self.outbound_pool.try_reserve() {
            return Err(OverlayError::PeerLimitReached);
        }

        let timeout = self.config.connect_timeout_secs.max(self.config.auth_timeout_secs);
        Self::connect_outbound_inner(
            addr,
            self.local_node.clone(),
            timeout,
            Arc::clone(&self.peers),
            Arc::clone(&self.outbound_pool),
            self.message_tx.clone(),
            Arc::clone(&self.flood_gate),
            Arc::clone(&self.running),
            Arc::clone(&self.peer_handles),
            Arc::clone(&self.advertised_outbound_peers),
            Arc::clone(&self.advertised_inbound_peers),
            Arc::clone(&self.added_authenticated_peers),
            Arc::clone(&self.dropped_authenticated_peers),
            Arc::clone(&self.banned_peers),
            self.config.peer_event_tx.clone(),
            Arc::clone(&self.peer_info_cache),
        )
        .await
    }

    /// Broadcast a message to all connected peers.
    pub async fn broadcast(&self, message: StellarMessage) -> Result<usize> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        let msg_type = helpers::message_type_name(&message);
        debug!("Broadcasting {} to {} peers", msg_type, self.peers.len());

        // Record in flood gate if this is a flood message
        if helpers::is_flood_message(&message) {
            let hash = compute_message_hash(&message);
            self.flood_gate.record_seen(hash, None);
        }

        // Collect peers to send to
        let peers: Vec<_> = self.peers.iter().map(|e| (e.key().clone(), Arc::clone(e.value()))).collect();

        let mut sent = 0;
        for (peer_id, peer) in peers {
            let mut peer_lock = peer.lock().await;
            if peer_lock.is_ready() {
                if let Err(e) = peer_lock.send(message.clone()).await {
                    debug!("Failed to send to {}: {}", peer_id, e);
                } else {
                    sent += 1;
                }
            }
        }

        debug!("Broadcast {} to {} peers", msg_type, sent);
        Ok(sent)
    }

    /// Disconnect a specific peer by ID.
    pub async fn disconnect(&self, peer_id: &PeerId) -> bool {
        let Some(entry) = self.peers.get(peer_id) else {
            return false;
        };
        let peer = Arc::clone(entry.value());
        drop(entry);
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
        true
    }

    /// Ban a peer by node ID and disconnect if connected.
    pub async fn ban_peer(&self, peer_id: PeerId) {
        self.banned_peers.write().insert(peer_id.clone());
        let Some(entry) = self.peers.get(&peer_id) else {
            return;
        };
        let peer = Arc::clone(entry.value());
        drop(entry);
        let mut peer_lock = peer.lock().await;
        peer_lock.close().await;
    }

    /// Remove a peer from the ban list.
    pub fn unban_peer(&self, peer_id: &PeerId) -> bool {
        self.banned_peers.write().remove(peer_id)
    }

    /// Return the list of banned peers.
    pub fn banned_peers(&self) -> Vec<PeerId> {
        self.banned_peers.read().iter().cloned().collect()
    }

    /// Send a message to a specific peer.
    pub async fn send_to(&self, peer_id: &PeerId, message: StellarMessage) -> Result<()> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| OverlayError::PeerNotFound(peer_id.to_string()))?;

        let mut peer_lock = peer.value().lock().await;
        peer_lock.send(message).await
    }

    /// Get the number of connected peers.
    /// Uses the peer info cache for lock-free access.
    pub fn peer_count(&self) -> usize {
        self.peer_info_cache.len()
    }

    /// Get a list of connected peer IDs.
    /// Uses the peer info cache for lock-free access.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peer_info_cache.iter().map(|entry| entry.key().clone()).collect()
    }

    fn count_outbound_peers(peers: &DashMap<PeerId, Arc<TokioMutex<Peer>>>) -> usize {
        peers
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .try_lock()
                    .map(|p| p.is_connected() && p.direction().we_called_remote())
                    .unwrap_or(true)
            })
            .count()
    }

    fn has_outbound_connection_to(
        peers: &DashMap<PeerId, Arc<TokioMutex<Peer>>>,
        addr: &PeerAddress,
    ) -> bool {
        let ip = addr.host.parse::<IpAddr>().ok();
        peers.iter().any(|entry| {
            entry
                .value()
                .try_lock()
                .map(|p| {
                    if !p.is_connected() || !p.direction().we_called_remote() {
                        return false;
                    }
                    if p.remote_addr().port() != addr.port {
                        return false;
                    }
                    match ip {
                        Some(ip) => p.remote_addr().ip() == ip,
                        None => false,
                    }
                })
                .unwrap_or(false)
        })
    }

    async fn connect_outbound_inner(
        addr: &PeerAddress,
        local_node: LocalNode,
        timeout_secs: u64,
        peers: Arc<DashMap<PeerId, Arc<TokioMutex<Peer>>>>,
        pool: Arc<ConnectionPool>,
        message_tx: broadcast::Sender<OverlayMessage>,
        flood_gate: Arc<FloodGate>,
        running: Arc<AtomicBool>,
        peer_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
        advertised_outbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
        advertised_inbound_peers: Arc<RwLock<Vec<PeerAddress>>>,
        added_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
        dropped_authenticated_peers: Arc<std::sync::atomic::AtomicU64>,
        banned_peers: Arc<RwLock<HashSet<PeerId>>>,
        peer_event_tx: Option<mpsc::Sender<PeerEvent>>,
        peer_info_cache: Arc<DashMap<PeerId, PeerInfo>>,
    ) -> Result<PeerId> {
        let peer = match Peer::connect(addr, local_node, timeout_secs).await {
            Ok(peer) => peer,
            Err(e) => {
                pool.release();
                if let Some(tx) = peer_event_tx {
                    let _ = tx.send(PeerEvent::Failed(addr.clone(), PeerType::Outbound)).await;
                }
                return Err(e);
            }
        };

        let peer_id = peer.id().clone();
        if banned_peers.read().contains(&peer_id) {
            pool.release();
            return Err(OverlayError::PeerBanned(peer_id.to_string()));
        }

        if peers.contains_key(&peer_id) {
            pool.release();
            return Err(OverlayError::AlreadyConnected);
        }

        info!("Connected to peer: {} at {}", peer_id, addr);

        let peer_info = peer.info().clone();
        let peer = Arc::new(TokioMutex::new(peer));
        peers.insert(peer_id.clone(), Arc::clone(&peer));
        peer_info_cache.insert(peer_id.clone(), peer_info);
        added_authenticated_peers.fetch_add(1, Ordering::Relaxed);
        if let Some(tx) = peer_event_tx {
            let _ = tx.send(PeerEvent::Connected(addr.clone(), PeerType::Outbound)).await;
        }

        let outbound_snapshot = advertised_outbound_peers.read().clone();
        let inbound_snapshot = advertised_inbound_peers.read().clone();
        if let Some(message) =
            Self::build_peers_message(&outbound_snapshot, &inbound_snapshot, Some(addr))
        {
            let mut peer_lock = peer.lock().await;
            if peer_lock.is_ready() {
                if let Err(e) = peer_lock.send(message).await {
                    debug!("Failed to send peers to {}: {}", peer_id, e);
                }
            }
        }

        let peer_id_clone = peer_id.clone();
        let peers_clone = Arc::clone(&peers);
        let pool_clone = Arc::clone(&pool);
        let message_tx = message_tx.clone();
        let flood_gate = Arc::clone(&flood_gate);
        let running = Arc::clone(&running);
        let peer_info_cache_clone = Arc::clone(&peer_info_cache);

        let handle = tokio::spawn(async move {
            Self::run_peer_loop(peer_id_clone.clone(), peer, message_tx, flood_gate, running).await;
            peers_clone.remove(&peer_id_clone);
            peer_info_cache_clone.remove(&peer_id_clone);
            dropped_authenticated_peers.fetch_add(1, Ordering::Relaxed);
            pool_clone.release();
        });

        peer_handles.write().push(handle);

        Ok(peer_id)
    }

    fn start_peer_advertiser(&mut self) {
        let peers = Arc::clone(&self.peers);
        let advertised_outbound_peers = Arc::clone(&self.advertised_outbound_peers);
        let advertised_inbound_peers = Arc::clone(&self.advertised_inbound_peers);
        let running = Arc::clone(&self.running);
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Peer advertiser shutting down");
                        break;
                    }
                    _ = interval.tick() => {}
                }

                if !running.load(Ordering::Relaxed) {
                    break;
                }

                let outbound_snapshot = advertised_outbound_peers.read().clone();
                let inbound_snapshot = advertised_inbound_peers.read().clone();
                let message = match OverlayManager::build_peers_message(
                    &outbound_snapshot,
                    &inbound_snapshot,
                    None,
                ) {
                    Some(message) => message,
                    None => continue,
                };

                for entry in peers.iter() {
                    if let Ok(mut peer) = entry.value().try_lock() {
                        if peer.is_ready() {
                            if let Err(e) = peer.send(message.clone()).await {
                                debug!("Failed to send peers to {}: {}", entry.key(), e);
                            }
                        }
                    }
                }
            }
        });

        self.peer_advertiser_handle = Some(handle);
    }

    fn build_peers_message(
        outbound: &[PeerAddress],
        inbound: &[PeerAddress],
        exclude: Option<&PeerAddress>,
    ) -> Option<StellarMessage> {
        let mut peers = Vec::new();
        let mut unique = HashSet::new();
        const MAX_PEERS_PER_MESSAGE: usize = 50;
        let mut ordered_outbound: Vec<&PeerAddress> = outbound.iter().collect();
        let mut ordered_inbound: Vec<&PeerAddress> = inbound.iter().collect();
        ordered_outbound.shuffle(&mut rand::thread_rng());
        ordered_inbound.shuffle(&mut rand::thread_rng());

        for addr in ordered_outbound.iter().chain(ordered_inbound.iter()) {
            if peers.len() >= MAX_PEERS_PER_MESSAGE {
                break;
            }
            if !Self::is_public_peer(addr) {
                continue;
            }
            if let Some(exclude) = exclude {
                if exclude == *addr {
                    continue;
                }
            }
            if !unique.insert(addr.to_socket_addr()) {
                continue;
            }
            if let Some(xdr) = Self::peer_address_to_xdr(addr) {
                peers.push(xdr);
            }
        }

        if peers.is_empty() {
            return None;
        }

        let vecm: VecM<XdrPeerAddress, 100> = peers.try_into().ok()?;
        Some(StellarMessage::Peers(vecm))
    }

    fn peer_address_to_xdr(addr: &PeerAddress) -> Option<XdrPeerAddress> {
        let ip: IpAddr = addr.host.parse().ok()?;
        let ip = match ip {
            IpAddr::V4(v4) => PeerAddressIp::IPv4(v4.octets()),
            IpAddr::V6(v6) => PeerAddressIp::IPv6(v6.octets()),
        };

        Some(XdrPeerAddress {
            ip,
            port: addr.port as u32,
            num_failures: 0,
        })
    }

    fn is_public_peer(addr: &PeerAddress) -> bool {
        if addr.port == 0 {
            return false;
        }
        let Ok(ip) = addr.host.parse::<IpAddr>() else {
            return true;
        };
        match ip {
            IpAddr::V4(v4) => {
                !(v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_multicast()
                    || v4.is_unspecified())
            }
            IpAddr::V6(v6) => {
                !(v6.is_loopback()
                    || v6.is_multicast()
                    || v6.is_unspecified()
                    || v6.is_unicast_link_local()
                    || v6.is_unique_local())
            }
        }
    }

    /// Get info for all connected peers.
    /// Uses the peer info cache for lock-free access.
    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peer_info_cache.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Get snapshots for all connected peers.
    /// Uses the peer info cache for info, falls back to try_lock for stats.
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peer_info_cache
            .iter()
            .filter_map(|entry| {
                let peer_id = entry.key();
                let info = entry.value().clone();
                // Try to get stats from the locked peer
                self.peers.get(peer_id).and_then(|peer_entry| {
                    peer_entry.value().try_lock().ok().map(|p| {
                        PeerSnapshot {
                            info,
                            stats: p.stats().snapshot(),
                        }
                    })
                })
            })
            .collect()
    }

    /// Subscribe to incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<OverlayMessage> {
        self.message_tx.subscribe()
    }

    /// Get flood gate statistics.
    pub fn flood_stats(&self) -> FloodGateStats {
        self.flood_gate.stats()
    }

    /// Check if the overlay is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get overlay statistics.
    pub fn stats(&self) -> OverlayStats {
        OverlayStats {
            connected_peers: self.peer_count(),
            inbound_peers: self.inbound_pool.count(),
            outbound_peers: self.outbound_pool.count(),
            flood_stats: self.flood_stats(),
        }
    }

    /// Total count of authenticated peers added.
    pub fn added_authenticated_peers(&self) -> u64 {
        self.added_authenticated_peers.load(Ordering::Relaxed)
    }

    /// Total count of authenticated peers dropped.
    pub fn dropped_authenticated_peers(&self) -> u64 {
        self.dropped_authenticated_peers.load(Ordering::Relaxed)
    }

    /// Return the current known peer list.
    pub fn known_peers(&self) -> Vec<PeerAddress> {
        self.known_peers.read().clone()
    }

    /// Replace the known peer list.
    pub fn set_known_peers(&self, peers: Vec<PeerAddress>) {
        let mut known = self.known_peers.write();
        *known = peers;
    }

    /// Replace the peers used for Peers advertisements.
    pub fn set_advertised_peers(
        &self,
        outbound_peers: Vec<PeerAddress>,
        inbound_peers: Vec<PeerAddress>,
    ) {
        let mut advertised_outbound = self.advertised_outbound_peers.write();
        let mut advertised_inbound = self.advertised_inbound_peers.write();
        *advertised_outbound = outbound_peers;
        *advertised_inbound = inbound_peers;
    }

    /// Request SCP state from all peers.
    pub async fn request_scp_state(&self, ledger_seq: u32) -> Result<usize> {
        let message = StellarMessage::GetScpState(ledger_seq);
        self.broadcast(message).await
    }

    /// Request a transaction set by hash from all peers.
    pub async fn request_tx_set(&self, hash: &[u8; 32]) -> Result<usize> {
        let message = StellarMessage::GetTxSet(stellar_xdr::curr::Uint256(*hash));
        tracing::info!(hash = hex::encode(hash), "Requesting transaction set from peers");
        self.broadcast(message).await
    }

    /// Request peers from all connected peers.
    /// Note: GetPeers was removed in Protocol 24. Peers are now pushed via the Peers message.
    pub async fn request_peers(&self) -> Result<usize> {
        // In the current protocol, peers are advertised via Peers messages
        // There is no explicit request mechanism
        warn!("request_peers called but GetPeers is no longer supported");
        Ok(0)
    }

    /// Add a peer to connect to.
    ///
    /// This is used for peer discovery when we receive a Peers message.
    /// Returns true if a connection attempt was initiated.
    pub async fn add_peer(&self, addr: PeerAddress) -> Result<bool> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(OverlayError::NotStarted);
        }

        // Check if we're at the connection limit
        if !self.outbound_pool.try_reserve() {
            debug!("Outbound peer limit reached, not adding peer {}", addr);
            return Ok(false);
        }

        // Check if we're already connected to this address
        // (We check by address, not by peer ID since we don't know it yet)
        let target_addr = addr.to_socket_addr();
        for entry in self.peers.iter() {
            if let Ok(peer) = entry.value().try_lock() {
                if peer.remote_addr().to_string() == target_addr {
                    self.outbound_pool.release();
                    debug!("Already connected to {}", addr);
                    return Ok(false);
                }
            }
        }

        // Spawn connection task
        let peers = Arc::clone(&self.peers);
        let local_node = self.local_node.clone();
        let pool = Arc::clone(&self.outbound_pool);
        let message_tx = self.message_tx.clone();
        let flood_gate = Arc::clone(&self.flood_gate);
        let running = Arc::clone(&self.running);
        let connect_timeout = self.config.connect_timeout_secs.max(self.config.auth_timeout_secs);
        let peer_handles = Arc::clone(&self.peer_handles);
        let advertised_outbound_peers = Arc::clone(&self.advertised_outbound_peers);
        let advertised_inbound_peers = Arc::clone(&self.advertised_inbound_peers);
        let peer_event_tx = self.config.peer_event_tx.clone();
        let peer_info_cache = Arc::clone(&self.peer_info_cache);

        let peer_handle = tokio::spawn(async move {
            match Peer::connect(&addr, local_node, connect_timeout).await {
                Ok(peer) => {
                    let peer_id = peer.id().clone();
                    info!("Connected to discovered peer: {} at {}", peer_id, addr);

                    if let Some(tx) = peer_event_tx.clone() {
                        let _ = tx
                            .send(PeerEvent::Connected(addr.clone(), PeerType::Outbound))
                            .await;
                    }

                    let peer_info = peer.info().clone();
                    let peer = Arc::new(TokioMutex::new(peer));
                    peers.insert(peer_id.clone(), Arc::clone(&peer));
                    peer_info_cache.insert(peer_id.clone(), peer_info);

                    let outbound_snapshot = advertised_outbound_peers.read().clone();
                    let inbound_snapshot = advertised_inbound_peers.read().clone();
                    if let Some(message) =
                        OverlayManager::build_peers_message(
                            &outbound_snapshot,
                            &inbound_snapshot,
                            Some(&addr),
                        )
                    {
                        let mut peer_lock = peer.lock().await;
                        if peer_lock.is_ready() {
                            if let Err(e) = peer_lock.send(message).await {
                                debug!(
                                    "Failed to send peers to {}: {}",
                                    peer_id, e
                                );
                            }
                        }
                    }

                    // Run peer loop
                    Self::run_peer_loop(
                        peer_id.clone(),
                        peer,
                        message_tx,
                        flood_gate,
                        running,
                    ).await;

                    // Cleanup
                    peers.remove(&peer_id);
                    peer_info_cache.remove(&peer_id);
                    pool.release();
                }
                Err(e) => {
                    debug!("Failed to connect to discovered peer {}: {}", addr, e);
                    if let Some(tx) = peer_event_tx.clone() {
                        let _ = tx
                            .send(PeerEvent::Failed(addr.clone(), PeerType::Outbound))
                            .await;
                    }
                    pool.release();
                }
            }
        });

        peer_handles.write().push(peer_handle);

        Ok(true)
    }

    /// Add multiple peers to connect to.
    ///
    /// This is used for peer discovery when we receive a Peers message.
    /// Returns the number of connection attempts initiated.
    pub async fn add_peers(&self, addrs: Vec<PeerAddress>) -> usize {
        let mut added = 0;
        let target_outbound = self.config.target_outbound_peers;
        let mut remaining = target_outbound.saturating_sub(self.outbound_pool.count());
        for addr in addrs {
            if remaining == 0 || !self.outbound_pool.can_accept() {
                break;
            }
            self.add_known_peer(addr.clone());
            match self.add_peer(addr).await {
                Ok(true) => {
                    added += 1;
                    remaining = remaining.saturating_sub(1);
                }
                Ok(false) => {}
                Err(e) => {
                    debug!("Error adding peer: {}", e);
                }
            }
            // Small delay between connection attempts
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        added
    }

    fn add_known_peer(&self, addr: PeerAddress) -> bool {
        let mut known = self.known_peers.write();
        if known.contains(&addr) {
            return false;
        }
        known.push(addr);
        true
    }

    /// Stop the overlay network.
    pub async fn shutdown(&mut self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        info!("Shutting down overlay manager");
        self.running.store(false, Ordering::Relaxed);

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Close all peers
        let peers: Vec<_> = self.peers.iter().map(|e| Arc::clone(e.value())).collect();
        for peer in peers {
            let mut peer_lock = peer.lock().await;
            peer_lock.close().await;
        }
        self.peers.clear();

        // Wait for tasks to complete
        if let Some(handle) = self.listener_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.connector_handle.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.peer_advertiser_handle.take() {
            let _ = handle.await;
        }

        // Wait for peer handles
        let handles: Vec<_> = std::mem::take(&mut *self.peer_handles.write());
        for handle in handles {
            let _ = handle.await;
        }

        info!("Overlay manager shutdown complete");
        Ok(())
    }
}

impl Drop for OverlayManager {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Overlay statistics.
#[derive(Debug, Clone)]
pub struct OverlayStats {
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Number of inbound connections.
    pub inbound_peers: usize,
    /// Number of outbound connections.
    pub outbound_peers: usize,
    /// Flood gate statistics.
    pub flood_stats: FloodGateStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_crypto::SecretKey;

    #[test]
    fn test_overlay_manager_creation() {
        let config = OverlayConfig::testnet();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_overlay_stats() {
        let config = OverlayConfig::default();
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);

        let manager = OverlayManager::new(config, local_node).unwrap();
        let stats = manager.stats();

        assert_eq!(stats.connected_peers, 0);
        assert_eq!(stats.inbound_peers, 0);
        assert_eq!(stats.outbound_peers, 0);
    }
}
