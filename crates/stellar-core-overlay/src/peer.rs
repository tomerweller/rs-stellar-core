//! Peer connection handling for Stellar overlay.
//!
//! Represents a connected and authenticated peer with message send/receive.

use crate::{
    auth::AuthContext,
    codec::helpers,
    connection::{Connection, ConnectionDirection},
    LocalNode, OverlayError, PeerAddress, PeerId, Result,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use stellar_xdr::curr::{Auth, Hello, StellarMessage};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

fn message_len(message: &StellarMessage) -> usize {
    stellar_xdr::curr::WriteXdr::to_xdr(message, stellar_xdr::curr::Limits::none())
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Connecting to peer.
    Connecting,
    /// Connected, handshake in progress.
    Handshaking,
    /// Fully authenticated and ready.
    Authenticated,
    /// Closing connection.
    Closing,
    /// Disconnected.
    Disconnected,
}

impl PeerState {
    /// Check if the peer is connected.
    pub fn is_connected(&self) -> bool {
        matches!(self, PeerState::Handshaking | PeerState::Authenticated)
    }

    /// Check if the peer is ready to send/receive messages.
    pub fn is_ready(&self) -> bool {
        matches!(self, PeerState::Authenticated)
    }
}

/// Statistics for a peer connection.
#[derive(Debug, Default)]
pub struct PeerStats {
    /// Messages sent.
    pub messages_sent: AtomicU64,
    /// Messages received.
    pub messages_received: AtomicU64,
    /// Bytes sent.
    pub bytes_sent: AtomicU64,
    /// Bytes received.
    pub bytes_received: AtomicU64,
    /// Unique flood messages received.
    pub unique_flood_messages_recv: AtomicU64,
    /// Duplicate flood messages received.
    pub duplicate_flood_messages_recv: AtomicU64,
    /// Unique flood bytes received.
    pub unique_flood_bytes_recv: AtomicU64,
    /// Duplicate flood bytes received.
    pub duplicate_flood_bytes_recv: AtomicU64,
    /// Unique fetch messages received.
    pub unique_fetch_messages_recv: AtomicU64,
    /// Duplicate fetch messages received.
    pub duplicate_fetch_messages_recv: AtomicU64,
    /// Unique fetch bytes received.
    pub unique_fetch_bytes_recv: AtomicU64,
    /// Duplicate fetch bytes received.
    pub duplicate_fetch_bytes_recv: AtomicU64,
}

impl PeerStats {
    /// Get a snapshot of the stats.
    pub fn snapshot(&self) -> PeerStatsSnapshot {
        PeerStatsSnapshot {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            unique_flood_messages_recv: self.unique_flood_messages_recv.load(Ordering::Relaxed),
            duplicate_flood_messages_recv: self
                .duplicate_flood_messages_recv
                .load(Ordering::Relaxed),
            unique_flood_bytes_recv: self.unique_flood_bytes_recv.load(Ordering::Relaxed),
            duplicate_flood_bytes_recv: self.duplicate_flood_bytes_recv.load(Ordering::Relaxed),
            unique_fetch_messages_recv: self.unique_fetch_messages_recv.load(Ordering::Relaxed),
            duplicate_fetch_messages_recv: self
                .duplicate_fetch_messages_recv
                .load(Ordering::Relaxed),
            unique_fetch_bytes_recv: self.unique_fetch_bytes_recv.load(Ordering::Relaxed),
            duplicate_fetch_bytes_recv: self.duplicate_fetch_bytes_recv.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of peer statistics.
#[derive(Debug, Clone)]
pub struct PeerStatsSnapshot {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub unique_flood_messages_recv: u64,
    pub duplicate_flood_messages_recv: u64,
    pub unique_flood_bytes_recv: u64,
    pub duplicate_flood_bytes_recv: u64,
    pub unique_fetch_messages_recv: u64,
    pub duplicate_fetch_messages_recv: u64,
    pub unique_fetch_bytes_recv: u64,
    pub duplicate_fetch_bytes_recv: u64,
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's node ID.
    pub peer_id: PeerId,
    /// Remote address.
    pub address: SocketAddr,
    /// Connection direction.
    pub direction: ConnectionDirection,
    /// Peer's version string.
    pub version_string: String,
    /// Peer's overlay version.
    pub overlay_version: u32,
    /// Peer's ledger version.
    pub ledger_version: u32,
    /// When connection was established.
    pub connected_at: Instant,
}

/// An authenticated connection to a peer.
pub struct Peer {
    /// Peer info.
    info: PeerInfo,
    /// Current state.
    state: PeerState,
    /// TCP connection.
    connection: Connection,
    /// Authentication context.
    auth: AuthContext,
    /// Statistics.
    stats: Arc<PeerStats>,
    /// Channel for sending messages (used by split peer).
    #[allow(dead_code)]
    send_tx: Option<mpsc::Sender<StellarMessage>>,
}

impl Peer {
    /// Connect to a peer and perform handshake.
    pub async fn connect(
        addr: &PeerAddress,
        local_node: LocalNode,
        timeout_secs: u64,
    ) -> Result<Self> {
        debug!("Connecting to peer: {}", addr);

        // Establish TCP connection
        let connection = Connection::connect(addr, timeout_secs).await?;

        // Create auth context (we called them)
        let auth = AuthContext::new(local_node, true);

        let mut peer = Self {
            info: PeerInfo {
                peer_id: PeerId::from_bytes([0u8; 32]), // Will be set after handshake
                address: connection.remote_addr(),
                direction: ConnectionDirection::Outbound,
                version_string: String::new(),
                overlay_version: 0,
                ledger_version: 0,
                connected_at: Instant::now(),
            },
            state: PeerState::Connecting,
            connection,
            auth,
            stats: Arc::new(PeerStats::default()),
            send_tx: None,
        };

        // Perform handshake
        peer.handshake(timeout_secs).await?;

        Ok(peer)
    }

    /// Create a peer from an accepted connection.
    pub async fn accept(
        connection: Connection,
        local_node: LocalNode,
        timeout_secs: u64,
    ) -> Result<Self> {
        debug!("Accepting peer from: {}", connection.remote_addr());

        // Create auth context (they called us)
        let auth = AuthContext::new(local_node, false);

        let mut peer = Self {
            info: PeerInfo {
                peer_id: PeerId::from_bytes([0u8; 32]),
                address: connection.remote_addr(),
                direction: ConnectionDirection::Inbound,
                version_string: String::new(),
                overlay_version: 0,
                ledger_version: 0,
                connected_at: Instant::now(),
            },
            state: PeerState::Connecting,
            connection,
            auth,
            stats: Arc::new(PeerStats::default()),
            send_tx: None,
        };

        // Perform handshake
        peer.handshake(timeout_secs).await?;

        Ok(peer)
    }

    /// Perform the authentication handshake.
    async fn handshake(&mut self, timeout_secs: u64) -> Result<()> {
        self.state = PeerState::Handshaking;
        debug!("Starting handshake with {}", self.connection.remote_addr());

        // Send Hello
        let hello = self.auth.create_hello();
        debug!(
            "Sending Hello: overlay_version={}, ledger_version={}, version_str={}, listening_port={}",
            hello.overlay_version,
            hello.ledger_version,
            hello.version_str.to_string(),
            hello.listening_port
        );
        let hello_msg = StellarMessage::Hello(hello);
        self.send_raw(hello_msg).await?;
        self.auth.hello_sent();
        debug!("Hello sent, waiting for peer Hello...");

        // Receive Hello
        let frame = self
            .connection
            .recv_timeout(timeout_secs)
            .await?
            .ok_or_else(|| OverlayError::PeerDisconnected("no Hello received".to_string()))?;
        debug!("Received frame with {} bytes", frame.raw_len);

        let message = self.auth.unwrap_message(frame.message, frame.is_authenticated)?;

        match message {
            StellarMessage::Hello(peer_hello) => {
                self.process_hello(peer_hello)?;
            }
            other => {
                return Err(OverlayError::InvalidMessage(format!(
                    "expected Hello, got {}",
                    helpers::message_type_name(&other)
                )));
            }
        }

        // Send Auth - with MAC (we have keys now from processing Hello)
        // Set AUTH_MSG_FLAG_FLOW_CONTROL_BYTES_REQUESTED = 200 to enable flow control
        let auth_msg = StellarMessage::Auth(Auth { flags: 200 });
        self.send_auth(auth_msg).await?;
        self.auth.auth_sent();

        // Receive Auth
        let frame = self
            .connection
            .recv_timeout(timeout_secs)
            .await?
            .ok_or_else(|| OverlayError::PeerDisconnected("no Auth received".to_string()))?;

        let message = self.auth.unwrap_message(frame.message, frame.is_authenticated)?;

        match message {
            StellarMessage::Auth(_) => {
                self.auth.process_auth()?;
            }
            StellarMessage::ErrorMsg(err) => {
                let err_msg: String = err.msg.to_string();
                warn!("Peer sent error: code={:?}, msg={}", err.code, err_msg);
                return Err(OverlayError::InvalidMessage(format!(
                    "peer sent ERROR: code={:?}, msg={}",
                    err.code, err_msg
                )));
            }
            other => {
                return Err(OverlayError::InvalidMessage(format!(
                    "expected Auth, got {}",
                    helpers::message_type_name(&other)
                )));
            }
        }

        self.state = PeerState::Authenticated;
        info!(
            "Authenticated with peer {} ({})",
            self.info.peer_id, self.info.address
        );

        // Send SEND_MORE_EXTENDED to enable flow control
        // num_messages: how many messages we can buffer
        // num_bytes: how many bytes we can buffer (0 to disable bytes-based flow control)
        // Use generous capacity to avoid early disconnects
        let send_more = StellarMessage::SendMoreExtended(stellar_xdr::curr::SendMoreExtended {
            num_messages: 500,       // We can handle many messages
            num_bytes: 50_000_000,   // 50 MB of data
        });
        self.send(send_more).await?;
        debug!("Sent SEND_MORE_EXTENDED to {}", self.info.peer_id);

        Ok(())
    }

    /// Process a received Hello message.
    fn process_hello(&mut self, hello: Hello) -> Result<()> {
        // Let auth context process it
        self.auth.process_hello(&hello)?;

        // Extract peer info
        let peer_id = self
            .auth
            .peer_id()
            .cloned()
            .ok_or_else(|| OverlayError::AuthenticationFailed("no peer ID".to_string()))?;

        let version_string: String = hello.version_str.to_string();

        self.info.peer_id = peer_id;
        self.info.version_string = version_string;
        self.info.overlay_version = hello.overlay_version;
        self.info.ledger_version = hello.ledger_version;
        if hello.listening_port > 0 {
            let port = hello.listening_port as u16;
            let ip = self.info.address.ip();
            self.info.address = SocketAddr::new(ip, port);
        }

        debug!(
            "Received Hello from {} (version: {}, overlay: {})",
            self.info.peer_id, self.info.version_string, self.info.overlay_version
        );

        Ok(())
    }

    /// Send a raw message (before authentication, e.g., Hello).
    async fn send_raw(&mut self, message: StellarMessage) -> Result<()> {
        let size = message_len(&message);
        let auth_msg = self.auth.wrap_unauthenticated(message);
        self.connection.send(auth_msg).await?;
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Send an Auth message (with MAC but sequence 0).
    async fn send_auth(&mut self, message: StellarMessage) -> Result<()> {
        let size = message_len(&message);
        let auth_msg = self.auth.wrap_auth_message(message)?;
        self.connection.send(auth_msg).await?;
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Send a message to this peer.
    pub async fn send(&mut self, message: StellarMessage) -> Result<()> {
        if self.state != PeerState::Authenticated {
            return Err(OverlayError::PeerDisconnected("not authenticated".to_string()));
        }

        let msg_type = helpers::message_type_name(&message);
        trace!("Sending {} to {}", msg_type, self.info.peer_id);

        let size = message_len(&message);
        let auth_msg = self.auth.wrap_message(message)?;
        self.connection.send(auth_msg).await?;
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Receive a message from this peer.
    pub async fn recv(&mut self) -> Result<Option<StellarMessage>> {
        if self.state != PeerState::Authenticated {
            return Ok(None);
        }

        let frame = match self.connection.recv().await? {
            Some(f) => f,
            None => {
                self.state = PeerState::Disconnected;
                return Ok(None);
            }
        };

        self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(frame.raw_len as u64, Ordering::Relaxed);

        let message = self.auth.unwrap_message(frame.message, frame.is_authenticated)?;
        let msg_type = helpers::message_type_name(&message);
        trace!("Received {} from {}", msg_type, self.info.peer_id);

        Ok(Some(message))
    }

    /// Receive a message with timeout.
    pub async fn recv_timeout(&mut self, timeout_secs: u64) -> Result<Option<StellarMessage>> {
        if self.state != PeerState::Authenticated {
            return Ok(None);
        }

        let frame = match self.connection.recv_timeout(timeout_secs).await? {
            Some(f) => f,
            None => {
                self.state = PeerState::Disconnected;
                return Ok(None);
            }
        };

        self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(frame.raw_len as u64, Ordering::Relaxed);

        let message = self.auth.unwrap_message(frame.message, frame.is_authenticated)?;

        Ok(Some(message))
    }

    /// Get this peer's ID.
    pub fn id(&self) -> &PeerId {
        &self.info.peer_id
    }

    /// Get peer info.
    pub fn info(&self) -> &PeerInfo {
        &self.info
    }

    /// Get current state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Check if this peer is still connected.
    pub fn is_connected(&self) -> bool {
        self.state.is_connected()
    }

    /// Check if this peer is ready for messages.
    pub fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// Get statistics.
    pub fn stats(&self) -> Arc<PeerStats> {
        Arc::clone(&self.stats)
    }

    pub fn record_flood_stats(&self, unique: bool, bytes: u64) {
        if unique {
            self.stats
                .unique_flood_messages_recv
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .unique_flood_bytes_recv
                .fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.stats
                .duplicate_flood_messages_recv
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .duplicate_flood_bytes_recv
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn record_fetch_stats(&self, unique: bool, bytes: u64) {
        if unique {
            self.stats
                .unique_fetch_messages_recv
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .unique_fetch_bytes_recv
                .fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.stats
                .duplicate_fetch_messages_recv
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .duplicate_fetch_bytes_recv
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Get remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.info.address
    }

    /// Get connection direction.
    pub fn direction(&self) -> ConnectionDirection {
        self.info.direction
    }

    /// Request SCP state from peer.
    pub async fn request_scp_state(&mut self, ledger_seq: u32) -> Result<()> {
        let message = StellarMessage::GetScpState(ledger_seq);
        self.send(message).await
    }

    /// Request peers from this peer.
    /// Note: GetPeers was removed in Protocol 24. This is a no-op.
    pub async fn request_peers(&mut self) -> Result<()> {
        // GetPeers is no longer supported - peers are pushed via Peers messages
        Ok(())
    }

    /// Send flow control message.
    pub async fn send_more(&mut self, num_messages: u32) -> Result<()> {
        let message = StellarMessage::SendMore(stellar_xdr::curr::SendMore {
            num_messages,
        });
        self.send(message).await
    }

    /// Send extended flow control message with byte limit.
    pub async fn send_more_extended(&mut self, num_messages: u32, num_bytes: u32) -> Result<()> {
        let message = StellarMessage::SendMoreExtended(stellar_xdr::curr::SendMoreExtended {
            num_messages,
            num_bytes,
        });
        self.send(message).await
    }

    /// Close the connection.
    pub async fn close(&mut self) {
        if self.state != PeerState::Disconnected {
            self.state = PeerState::Closing;
            self.connection.close().await;
            self.state = PeerState::Disconnected;
            debug!("Closed connection to {}", self.info.peer_id);
        }
    }
}

/// Handle for sending messages to a peer (used with split connections).
#[derive(Clone)]
pub struct PeerSender {
    peer_id: PeerId,
    tx: mpsc::Sender<StellarMessage>,
}

impl PeerSender {
    /// Create a new peer sender.
    pub fn new(peer_id: PeerId, tx: mpsc::Sender<StellarMessage>) -> Self {
        Self { peer_id, tx }
    }

    /// Send a message.
    pub async fn send(&self, message: StellarMessage) -> Result<()> {
        self.tx
            .send(message)
            .await
            .map_err(|_| OverlayError::ChannelSend)
    }

    /// Get the peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_state() {
        assert!(!PeerState::Connecting.is_connected());
        assert!(PeerState::Handshaking.is_connected());
        assert!(PeerState::Authenticated.is_connected());
        assert!(PeerState::Authenticated.is_ready());
        assert!(!PeerState::Handshaking.is_ready());
        assert!(!PeerState::Disconnected.is_connected());
    }

    #[test]
    fn test_peer_stats() {
        let stats = PeerStats::default();
        stats.messages_sent.fetch_add(10, Ordering::Relaxed);
        stats.messages_received.fetch_add(5, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.messages_sent, 10);
        assert_eq!(snapshot.messages_received, 5);
    }
}
