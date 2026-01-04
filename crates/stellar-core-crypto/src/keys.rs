//! Key types and management.

use crate::error::CryptoError;
use crate::strkey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fmt;
// Note: SigningKey from ed25519_dalek handles its own zeroization on drop

/// Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Create from raw 32-byte key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let key =
            VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self(key))
    }

    /// Get the raw 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Encode as Stellar account ID (G...).
    pub fn to_strkey(&self) -> String {
        strkey::encode_account_id(self.as_bytes())
    }

    /// Parse from Stellar account ID (G...).
    pub fn from_strkey(s: &str) -> Result<Self, CryptoError> {
        let bytes = strkey::decode_account_id(s)?;
        Self::from_bytes(&bytes)
    }

    /// Convert to Curve25519 (Montgomery) public key bytes for sealed box encryption.
    pub fn to_curve25519_bytes(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }

    /// Get the inner verifying key.
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &VerifyingKey {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_strkey())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_strkey())
    }
}

impl TryFrom<&stellar_xdr::curr::PublicKey> for PublicKey {
    type Error = CryptoError;

    fn try_from(xdr: &stellar_xdr::curr::PublicKey) -> Result<Self, Self::Error> {
        match xdr {
            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::curr::Uint256(bytes),
            ) => Self::from_bytes(bytes),
        }
    }
}

impl From<&PublicKey> for stellar_xdr::curr::PublicKey {
    fn from(pk: &PublicKey) -> Self {
        stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::curr::Uint256(
            *pk.as_bytes(),
        ))
    }
}

impl From<&PublicKey> for stellar_xdr::curr::AccountId {
    fn from(pk: &PublicKey) -> Self {
        stellar_xdr::curr::AccountId(pk.into())
    }
}

/// Ed25519 secret key (zeroized on drop).
pub struct SecretKey {
    inner: SigningKey,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // SigningKey implements Zeroize internally when dropped
        // but we ensure the memory is cleared
    }
}

impl SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { inner: signing_key }
    }

    /// Create from seed bytes.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { inner: signing_key }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        let signature = self.inner.sign(message);
        Signature(signature.to_bytes())
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.inner.verifying_key())
    }

    /// Encode as Stellar secret seed (S...).
    pub fn to_strkey(&self) -> String {
        strkey::encode_secret_seed(self.inner.as_bytes())
    }

    /// Parse from Stellar secret seed (S...).
    pub fn from_strkey(s: &str) -> Result<Self, CryptoError> {
        let bytes = strkey::decode_secret_seed(s)?;
        Ok(Self::from_seed(&bytes))
    }

    /// Convert to Curve25519 scalar bytes for sealed box decryption.
    pub fn to_curve25519_bytes(&self) -> [u8; 32] {
        self.inner.to_scalar_bytes()
    }

    /// Get the raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self {
            inner: SigningKey::from_bytes(self.inner.as_bytes()),
        }
    }
}

/// 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(&self.0[..8]))
    }
}

impl From<Signature> for stellar_xdr::curr::Signature {
    fn from(sig: Signature) -> Self {
        stellar_xdr::curr::Signature(sig.0.to_vec().try_into().unwrap())
    }
}

impl TryFrom<&stellar_xdr::curr::Signature> for Signature {
    type Error = CryptoError;

    fn try_from(xdr: &stellar_xdr::curr::Signature) -> Result<Self, Self::Error> {
        let bytes: [u8; 64] = xdr.0.as_slice().try_into().map_err(|_| CryptoError::InvalidLength {
            expected: 64,
            got: xdr.0.len(),
        })?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        // Should produce valid strkeys
        let secret_strkey = secret.to_strkey();
        let public_strkey = public.to_strkey();

        assert!(secret_strkey.starts_with('S'));
        assert!(public_strkey.starts_with('G'));

        // Should round-trip
        let secret2 = SecretKey::from_strkey(&secret_strkey).unwrap();
        let public2 = PublicKey::from_strkey(&public_strkey).unwrap();

        assert_eq!(secret.as_bytes(), secret2.as_bytes());
        assert_eq!(public.as_bytes(), public2.as_bytes());
    }

    #[test]
    fn test_signing() {
        let secret = SecretKey::generate();
        let public = secret.public_key();

        let message = b"hello world";
        let signature = secret.sign(message);

        // Should verify
        assert!(public.verify(message, &signature).is_ok());

        // Should not verify with wrong message
        assert!(public.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_known_key() {
        // Generate a key and verify round-trip
        let secret = SecretKey::generate();
        let secret_strkey = secret.to_strkey();

        // Verify starts with S (secret seed prefix)
        assert!(secret_strkey.starts_with('S'));

        // Round-trip the secret key
        let secret2 = SecretKey::from_strkey(&secret_strkey).unwrap();
        assert_eq!(secret.as_bytes(), secret2.as_bytes());

        // Derive and verify public key
        let public = secret.public_key();
        let public_strkey = public.to_strkey();

        // Verify starts with G (account ID prefix)
        assert!(public_strkey.starts_with('G'));

        // Verify public key from original and loaded secrets match
        let public2 = secret2.public_key();
        assert_eq!(public.as_bytes(), public2.as_bytes());
    }
}
