//! Authentication for Stellar overlay connections.
//!
//! Implements X25519 key exchange with HMAC-SHA256 message authentication.
//! The handshake follows the Stellar overlay protocol:
//!
//! 1. Both peers exchange Hello messages with their public key and auth cert
//! 2. Both peers derive shared secrets from X25519 key exchange
//! 3. Both peers send Auth messages to complete handshake
//! 4. All subsequent messages are authenticated with HMAC-SHA256

use crate::{LocalNode, OverlayError, PeerId, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use stellar_core_common::Hash256;
use stellar_core_crypto::PublicKey;
use stellar_xdr::curr::{
    self as xdr, AuthCert as XdrAuthCert, AuthenticatedMessage, AuthenticatedMessageV0, Curve25519Public,
    EnvelopeType, Hello, HmacSha256Key, HmacSha256Mac, StellarMessage,
    Uint256, WriteXdr,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};

type HmacSha256 = Hmac<Sha256>;

/// Authentication certificate containing ephemeral key and signature.
#[derive(Debug, Clone)]
pub struct AuthCert {
    /// Ephemeral X25519 public key.
    pub pubkey: [u8; 32],
    /// Expiration time (Unix timestamp).
    pub expiration: u64,
    /// Signature over (network_id || ENVELOPE_TYPE_AUTH || expiration || pubkey).
    pub sig: [u8; 64],
}

impl AuthCert {
    /// Create a new auth cert with an ephemeral key.
    pub fn new(
        local_node: &LocalNode,
        ephemeral_secret: &EphemeralSecret,
    ) -> Self {
        let ephemeral_public = X25519PublicKey::from(ephemeral_secret);
        let pubkey = *ephemeral_public.as_bytes();

        // Expiration: 1 hour from now
        let expiration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        // Sign: network_id || ENVELOPE_TYPE_AUTH || expiration || pubkey
        let sig = Self::sign_cert(local_node, expiration, &pubkey);

        Self {
            pubkey,
            expiration,
            sig,
        }
    }

    /// Sign the auth cert data.
    /// stellar-core signs the SHA-256 hash of the XDR-serialized data.
    fn sign_cert(local_node: &LocalNode, expiration: u64, pubkey: &[u8; 32]) -> [u8; 64] {
        let mut data = Vec::with_capacity(32 + 4 + 8 + 32);
        data.extend_from_slice(local_node.network_id.as_bytes());
        data.extend_from_slice(&(EnvelopeType::Auth as i32).to_be_bytes());
        data.extend_from_slice(&expiration.to_be_bytes());
        data.extend_from_slice(pubkey);

        // stellar-core signs the SHA-256 hash of the data, not the raw data
        let hash = Hash256::hash(&data);
        let signature = local_node.secret_key.sign(hash.as_bytes());
        *signature.as_bytes()
    }

    /// Verify an auth cert from a peer.
    pub fn verify(&self, network_id: &stellar_core_common::NetworkId, peer_public_key: &PublicKey) -> Result<()> {
        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.expiration <= now {
            return Err(OverlayError::AuthenticationFailed(
                "auth cert expired".to_string(),
            ));
        }

        // Verify signature - stellar-core signs the SHA-256 hash of the data
        let mut data = Vec::with_capacity(32 + 4 + 8 + 32);
        data.extend_from_slice(network_id.as_bytes());
        data.extend_from_slice(&(EnvelopeType::Auth as i32).to_be_bytes());
        data.extend_from_slice(&self.expiration.to_be_bytes());
        data.extend_from_slice(&self.pubkey);

        let hash = Hash256::hash(&data);
        let sig = stellar_core_crypto::Signature::from_bytes(self.sig);
        peer_public_key
            .verify(hash.as_bytes(), &sig)
            .map_err(|_| OverlayError::AuthenticationFailed("invalid auth cert signature".to_string()))
    }

    /// Convert to XDR.
    pub fn to_xdr(&self) -> XdrAuthCert {
        XdrAuthCert {
            pubkey: Curve25519Public {
                key: self.pubkey,
            },
            expiration: self.expiration,
            sig: xdr::Signature(self.sig.to_vec().try_into().unwrap()),
        }
    }

    /// Parse from XDR.
    pub fn from_xdr(xdr: &XdrAuthCert) -> Self {
        let mut sig = [0u8; 64];
        let sig_len = xdr.sig.0.len().min(64);
        sig[..sig_len].copy_from_slice(&xdr.sig.0[..sig_len]);

        Self {
            pubkey: xdr.pubkey.key,
            expiration: xdr.expiration,
            sig,
        }
    }
}

/// Authentication state for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Initial state, no Hello received.
    Initial,
    /// Hello sent, waiting for peer's Hello.
    HelloSent,
    /// Hello received, need to send Auth.
    HelloReceived,
    /// Auth sent, waiting for peer's Auth.
    AuthSent,
    /// Fully authenticated.
    Authenticated,
    /// Authentication failed.
    Failed,
}

/// Authentication context for a connection.
///
/// Manages the handshake state and derives keys for message authentication.
pub struct AuthContext {
    /// Local node info.
    local_node: LocalNode,
    /// Our ephemeral secret key.
    our_ephemeral_secret: Option<EphemeralSecret>,
    /// Our ephemeral public key.
    our_ephemeral_public: Option<X25519PublicKey>,
    /// Our auth cert.
    our_auth_cert: Option<AuthCert>,
    /// Our nonce from Hello.
    our_nonce: [u8; 32],
    /// Peer's nonce from Hello.
    peer_nonce: Option<[u8; 32]>,
    /// Peer's auth cert.
    peer_auth_cert: Option<AuthCert>,
    /// Peer's public key.
    peer_public_key: Option<PublicKey>,
    /// Peer's node ID.
    peer_id: Option<PeerId>,
    /// Shared secret from X25519.
    shared_secret: Option<SharedSecret>,
    /// Sending MAC key.
    send_mac_key: Option<HmacSha256Key>,
    /// Receiving MAC key.
    recv_mac_key: Option<HmacSha256Key>,
    /// Sending sequence number.
    send_sequence: u64,
    /// Receiving sequence number.
    recv_sequence: u64,
    /// Current auth state.
    state: AuthState,
    /// Whether we initiated the connection.
    we_called_remote: bool,
}

impl AuthContext {
    /// Create a new auth context.
    pub fn new(local_node: LocalNode, we_called_remote: bool) -> Self {
        // Generate ephemeral key pair
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let auth_cert = AuthCert::new(&local_node, &ephemeral_secret);

        // Generate our nonce for Hello message
        let our_nonce = rand::random::<[u8; 32]>();

        Self {
            local_node,
            our_ephemeral_secret: Some(ephemeral_secret),
            our_ephemeral_public: Some(ephemeral_public),
            our_auth_cert: Some(auth_cert),
            our_nonce,
            peer_nonce: None,
            peer_auth_cert: None,
            peer_public_key: None,
            peer_id: None,
            shared_secret: None,
            send_mac_key: None,
            recv_mac_key: None,
            send_sequence: 0,
            recv_sequence: 0,
            state: AuthState::Initial,
            we_called_remote,
        }
    }

    /// Get current auth state.
    pub fn state(&self) -> AuthState {
        self.state
    }

    /// Check if fully authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.state == AuthState::Authenticated
    }

    /// Get the peer's ID if available.
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }

    /// Create a Hello message for sending.
    pub fn create_hello(&self) -> Hello {
        let public_key = self.local_node.xdr_public_key();

        Hello {
            ledger_version: self.local_node.ledger_version,
            overlay_version: self.local_node.overlay_version,
            overlay_min_version: self.local_node.overlay_min_version,
            network_id: self.local_node.network_id.into(),
            version_str: self.local_node.version_string.clone().try_into().unwrap_or_default(),
            listening_port: self.local_node.listening_port as i32,
            peer_id: xdr::NodeId(public_key),
            cert: self.our_auth_cert.as_ref().unwrap().to_xdr(),
            nonce: Uint256(self.our_nonce),
        }
    }

    /// Process a received Hello message.
    pub fn process_hello(&mut self, hello: &Hello) -> Result<()> {
        // Check network ID
        let network_id_bytes = hello.network_id.0;
        if network_id_bytes != *self.local_node.network_id.as_bytes() {
            return Err(OverlayError::NetworkMismatch);
        }

        // Check overlay version
        if hello.overlay_version < self.local_node.overlay_min_version {
            return Err(OverlayError::VersionMismatch(format!(
                "peer overlay version {} below minimum {}",
                hello.overlay_version, self.local_node.overlay_min_version
            )));
        }

        // Extract peer public key
        let peer_pk_bytes = match &hello.peer_id.0 {
            xdr::PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => *bytes,
        };
        let peer_public_key = PublicKey::from_bytes(&peer_pk_bytes)
            .map_err(|e| OverlayError::AuthenticationFailed(format!("invalid peer public key: {}", e)))?;

        // Verify auth cert
        let peer_auth_cert = AuthCert::from_xdr(&hello.cert);
        peer_auth_cert.verify(&self.local_node.network_id, &peer_public_key)?;

        // Store peer's nonce
        self.peer_nonce = Some(hello.nonce.0);

        // Perform X25519 key exchange
        let our_secret = self.our_ephemeral_secret.take()
            .ok_or_else(|| OverlayError::AuthenticationFailed("ephemeral secret already used".to_string()))?;
        let peer_ephemeral_public = X25519PublicKey::from(peer_auth_cert.pubkey);
        let shared_secret = our_secret.diffie_hellman(&peer_ephemeral_public);

        // Derive MAC keys using nonces from Hello messages
        let (send_key, recv_key) = self.derive_mac_keys(&shared_secret, &peer_auth_cert)?;

        // Store peer info
        self.peer_public_key = Some(peer_public_key);
        self.peer_id = Some(PeerId::from_bytes(peer_pk_bytes));
        self.peer_auth_cert = Some(peer_auth_cert);
        self.shared_secret = Some(shared_secret);
        self.send_mac_key = Some(send_key);
        self.recv_mac_key = Some(recv_key);
        self.state = AuthState::HelloReceived;

        Ok(())
    }

    /// Derive MAC keys from shared secret using HKDF.
    ///
    /// stellar-core derives MAC keys as follows:
    /// 1. K = HKDF_extract(ECDH(A_sec,B_pub) || A_pub || B_pub)
    /// 2. SendKey = HKDF_expand(K, send_prefix || local_nonce || remote_nonce)
    /// 3. RecvKey = HKDF_expand(K, recv_prefix || remote_nonce || local_nonce)
    ///
    /// Where prefix is 0 for A→B messages and 1 for B→A messages.
    fn derive_mac_keys(
        &self,
        shared_secret: &SharedSecret,
        peer_auth_cert: &AuthCert,
    ) -> Result<(HmacSha256Key, HmacSha256Key)> {
        let our_public = self.our_ephemeral_public.as_ref()
            .ok_or_else(|| OverlayError::AuthenticationFailed("ephemeral public key missing".to_string()))?;
        let peer_nonce = self.peer_nonce.as_ref()
            .ok_or_else(|| OverlayError::AuthenticationFailed("peer nonce missing".to_string()))?;

        // Step 1: HKDF-Extract to create shared key K
        // IKM = ECDH_result || A_pub || B_pub (where A is initiator, B is acceptor)
        let (a_pub, b_pub) = if self.we_called_remote {
            (our_public.as_bytes(), &peer_auth_cert.pubkey)
        } else {
            (&peer_auth_cert.pubkey, our_public.as_bytes())
        };

        let mut ikm = Vec::with_capacity(32 + 32 + 32);
        ikm.extend_from_slice(shared_secret.as_bytes());
        ikm.extend_from_slice(a_pub);
        ikm.extend_from_slice(b_pub);

        // HKDF-Extract: PRK = HMAC-SHA256(salt="", IKM)
        // With empty salt, HMAC uses a key of all zeros
        let zero_salt = [0u8; 32];
        let mut extract_mac = HmacSha256::new_from_slice(&zero_salt)
            .map_err(|_| OverlayError::AuthenticationFailed("HMAC init failed".to_string()))?;
        extract_mac.update(&ikm);
        let prk: [u8; 32] = extract_mac.finalize().into_bytes().into();

        // Step 2: Determine prefixes based on role
        // Prefix 0 is for A's messages (A→B direction)
        // Prefix 1 is for B's messages (B→A direction)
        let (send_prefix, recv_prefix): (u8, u8) = if self.we_called_remote {
            // We are A: we send A→B (prefix 0), receive B→A (prefix 1)
            (0, 1)
        } else {
            // We are B: we send B→A (prefix 1), receive A→B (prefix 0)
            (1, 0)
        };

        // Step 3: HKDF-Expand for each direction
        // Send: prefix || local_nonce || remote_nonce
        // Recv: prefix || remote_nonce || local_nonce
        let send_key = self.hkdf_expand(&prk, send_prefix, &self.our_nonce, peer_nonce);
        let recv_key = self.hkdf_expand(&prk, recv_prefix, peer_nonce, &self.our_nonce);

        Ok((send_key, recv_key))
    }

    /// HKDF-Expand: derive a key from PRK using prefix and nonces.
    fn hkdf_expand(&self, prk: &[u8; 32], prefix: u8, nonce1: &[u8; 32], nonce2: &[u8; 32]) -> HmacSha256Key {
        // info = prefix || nonce1 || nonce2
        let mut info = Vec::with_capacity(1 + 32 + 32);
        info.push(prefix);
        info.extend_from_slice(nonce1);
        info.extend_from_slice(nonce2);

        // HKDF-Expand: T(1) = HMAC-Hash(PRK, info || 0x01)
        let mut expand_mac = HmacSha256::new_from_slice(prk).unwrap();
        expand_mac.update(&info);
        expand_mac.update(&[0x01]);
        let key: [u8; 32] = expand_mac.finalize().into_bytes().into();

        HmacSha256Key { key }
    }

    /// Mark that we sent Hello.
    pub fn hello_sent(&mut self) {
        if self.state == AuthState::Initial {
            self.state = AuthState::HelloSent;
        }
    }

    /// Mark that we sent Auth.
    pub fn auth_sent(&mut self) {
        if self.state == AuthState::HelloReceived {
            self.state = AuthState::AuthSent;
        }
    }

    /// Process received Auth message.
    pub fn process_auth(&mut self) -> Result<()> {
        // AUTH messages consume sequence 0 on both sides
        // So first post-auth messages use sequence 1
        self.recv_sequence = 1;
        self.send_sequence = 1;

        // Mark as authenticated
        self.state = AuthState::Authenticated;
        Ok(())
    }

    /// Wrap a message with MAC authentication.
    pub fn wrap_message(&mut self, message: StellarMessage) -> Result<AuthenticatedMessage> {
        let send_key = self.send_mac_key.as_ref()
            .ok_or_else(|| OverlayError::AuthenticationFailed("send key not established".to_string()))?;

        let sequence = self.send_sequence;
        self.send_sequence += 1;

        // Compute MAC
        let mac = self.compute_mac(send_key, sequence, &message)?;

        Ok(AuthenticatedMessage::V0(AuthenticatedMessageV0 {
            sequence,
            message,
            mac,
        }))
    }

    /// Unwrap and verify a message MAC.
    ///
    /// The `message_is_authenticated` flag indicates whether bit 31 was set in the message length
    /// prefix. When set, the message has a valid MAC that should be verified. When clear (e.g.,
    /// during handshake or for certain message types), the MAC is all zeros and should not be verified.
    pub fn unwrap_message(&mut self, auth_msg: AuthenticatedMessage, message_is_authenticated: bool) -> Result<StellarMessage> {
        match auth_msg {
            AuthenticatedMessage::V0(v0) => {
                let msg_type = match &v0.message {
                    StellarMessage::Hello(_) => "HELLO",
                    StellarMessage::Auth(_) => "AUTH",
                    StellarMessage::ErrorMsg(_) => "ERROR",
                    StellarMessage::Peers(_) => "PEERS",
                    StellarMessage::SendMore(_) => "SEND_MORE",
                    StellarMessage::SendMoreExtended(_) => "SEND_MORE_EXT",
                    StellarMessage::ScpMessage(_) => "SCP",
                    StellarMessage::FloodAdvert(_) => "FLOOD_ADVERT",
                    StellarMessage::FloodDemand(_) => "FLOOD_DEMAND",
                    StellarMessage::Transaction(_) => "TX",
                    _ => "OTHER",
                };
                tracing::debug!(
                    "unwrap_message: seq={}, is_auth={}, msg_is_auth={}, expected_seq={}, type={}",
                    v0.sequence,
                    self.is_authenticated(),
                    message_is_authenticated,
                    self.recv_sequence,
                    msg_type
                );

                // Only verify sequence and MAC when:
                // 1. We're past the handshake phase (self.is_authenticated())
                // 2. The message actually has a MAC (bit 31 set in length prefix)
                // 3. Not an ERROR message (errors can use sequence 0 and skip MAC)
                let is_error = matches!(v0.message, StellarMessage::ErrorMsg(_));
                if self.is_authenticated() && message_is_authenticated && !is_error {
                    // Verify sequence number
                    if v0.sequence != self.recv_sequence {
                        return Err(OverlayError::AuthenticationFailed(format!(
                            "sequence mismatch: expected {}, got {}",
                            self.recv_sequence, v0.sequence
                        )));
                    }
                    self.recv_sequence += 1;

                    // Verify MAC
                    let recv_key = self.recv_mac_key.as_ref()
                        .ok_or_else(|| OverlayError::AuthenticationFailed("recv key not established".to_string()))?;

                    let expected_mac = self.compute_mac(recv_key, v0.sequence, &v0.message)?;
                    tracing::debug!(
                        "MAC verification: seq={}, expected={:02x?}, got={:02x?}, key={:02x?}",
                        v0.sequence,
                        &expected_mac.mac[..8],
                        &v0.mac.mac[..8],
                        &recv_key.key[..8]
                    );
                    if expected_mac.mac != v0.mac.mac {
                        return Err(OverlayError::MacVerificationFailed);
                    }
                }

                Ok(v0.message)
            }
        }
    }

    /// Compute HMAC-SHA256 for a message.
    fn compute_mac(
        &self,
        key: &HmacSha256Key,
        sequence: u64,
        message: &StellarMessage,
    ) -> Result<HmacSha256Mac> {
        let message_bytes = message.to_xdr(xdr::Limits::none())?;

        let mut mac = HmacSha256::new_from_slice(&key.key)
            .map_err(|_| OverlayError::AuthenticationFailed("invalid MAC key".to_string()))?;

        mac.update(&sequence.to_be_bytes());
        mac.update(&message_bytes);

        let result = mac.finalize().into_bytes();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&result);

        Ok(HmacSha256Mac { mac: mac_bytes })
    }

    /// Create an unauthenticated message for Hello.
    /// Hello messages have sequence 0 and zero MAC.
    pub fn wrap_unauthenticated(&self, message: StellarMessage) -> AuthenticatedMessage {
        // Hello message uses sequence 0 and zero MAC
        AuthenticatedMessage::V0(AuthenticatedMessageV0 {
            sequence: 0,
            message,
            mac: HmacSha256Mac { mac: [0u8; 32] },
        })
    }

    /// Create an Auth message with proper MAC but sequence 0.
    /// Auth messages have sequence 0 but a real MAC.
    pub fn wrap_auth_message(&self, message: StellarMessage) -> Result<AuthenticatedMessage> {
        let send_key = self.send_mac_key.as_ref()
            .ok_or_else(|| OverlayError::AuthenticationFailed("send key not established".to_string()))?;

        // Auth message uses sequence 0
        let sequence = 0u64;

        // Compute MAC
        let mac = self.compute_mac(send_key, sequence, &message)?;

        Ok(AuthenticatedMessage::V0(AuthenticatedMessageV0 {
            sequence,
            message,
            mac,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_core_crypto::SecretKey;

    #[test]
    fn test_auth_cert_creation() {
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);
        let ephemeral = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let cert = AuthCert::new(&local_node, &ephemeral);

        // Verify it with our own public key
        let result = cert.verify(&local_node.network_id, &local_node.public_key());
        assert!(result.is_ok(), "Self-verification should pass");
    }

    #[test]
    fn test_auth_context_creation() {
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);
        let ctx = AuthContext::new(local_node, true);

        assert_eq!(ctx.state(), AuthState::Initial);
        assert!(!ctx.is_authenticated());
    }

    #[test]
    fn test_hello_creation() {
        let secret = SecretKey::generate();
        let local_node = LocalNode::new_testnet(secret);
        let ctx = AuthContext::new(local_node, true);

        let hello = ctx.create_hello();
        assert_eq!(hello.overlay_version, 38);
        assert_eq!(hello.overlay_min_version, 35);
        assert_eq!(hello.ledger_version, 24);
    }
}
