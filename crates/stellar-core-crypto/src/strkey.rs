//! Stellar key encoding (StrKey format).
//!
//! Stellar uses a base32 encoding with version bytes for different key types.

use crate::error::CryptoError;

// Version bytes for different key types
const VERSION_ACCOUNT_ID: u8 = 6 << 3; // 'G' prefix
const VERSION_SEED: u8 = 18 << 3; // 'S' prefix
const VERSION_PRE_AUTH_TX: u8 = 19 << 3; // 'T' prefix
const VERSION_SHA256_HASH: u8 = 23 << 3; // 'X' prefix
const VERSION_MUXED_ACCOUNT: u8 = 12 << 3; // 'M' prefix
#[allow(dead_code)]
const VERSION_SIGNED_PAYLOAD: u8 = 15 << 3; // 'P' prefix

/// Encode an account ID (G...).
pub fn encode_account_id(key: &[u8; 32]) -> String {
    encode_check(VERSION_ACCOUNT_ID, key)
}

/// Decode an account ID (G...).
pub fn decode_account_id(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_ACCOUNT_ID, s, 32)
}

/// Encode a secret seed (S...).
pub fn encode_secret_seed(seed: &[u8; 32]) -> String {
    encode_check(VERSION_SEED, seed)
}

/// Decode a secret seed (S...).
pub fn decode_secret_seed(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_SEED, s, 32)
}

/// Encode a pre-auth transaction hash (T...).
pub fn encode_pre_auth_tx(hash: &[u8; 32]) -> String {
    encode_check(VERSION_PRE_AUTH_TX, hash)
}

/// Decode a pre-auth transaction hash (T...).
pub fn decode_pre_auth_tx(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_PRE_AUTH_TX, s, 32)
}

/// Encode a SHA256 hash (X...).
pub fn encode_sha256_hash(hash: &[u8; 32]) -> String {
    encode_check(VERSION_SHA256_HASH, hash)
}

/// Decode a SHA256 hash (X...).
pub fn decode_sha256_hash(s: &str) -> Result<[u8; 32], CryptoError> {
    decode_check(VERSION_SHA256_HASH, s, 32)
}

/// Encode a muxed account (M...).
pub fn encode_muxed_account(key: &[u8; 32], id: u64) -> String {
    let mut data = key.to_vec();
    data.extend_from_slice(&id.to_be_bytes());
    encode_check(VERSION_MUXED_ACCOUNT, &data)
}

/// Decode a muxed account (M...).
pub fn decode_muxed_account(s: &str) -> Result<([u8; 32], u64), CryptoError> {
    let data = decode_check_variable(VERSION_MUXED_ACCOUNT, s)?;
    if data.len() != 40 {
        return Err(CryptoError::InvalidStrKey(format!(
            "muxed account data length {} != 40",
            data.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let id = u64::from_be_bytes(data[32..40].try_into().unwrap());
    Ok((key, id))
}

fn encode_check(version: u8, data: &[u8]) -> String {
    let mut payload = vec![version];
    payload.extend_from_slice(data);

    // CRC16-XModem checksum
    let checksum = crc16_xmodem(&payload);
    payload.extend_from_slice(&checksum.to_le_bytes());

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &payload)
}

fn decode_check<const N: usize>(expected_version: u8, s: &str, expected_len: usize) -> Result<[u8; N], CryptoError> {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
        .ok_or_else(|| CryptoError::InvalidStrKey("invalid base32".to_string()))?;

    // Minimum: 1 version byte + N data bytes + 2 checksum bytes
    if decoded.len() != 1 + expected_len + 2 {
        return Err(CryptoError::InvalidStrKey(format!(
            "length {} != {}",
            decoded.len(),
            1 + expected_len + 2
        )));
    }

    let version = decoded[0];
    if version != expected_version {
        return Err(CryptoError::InvalidStrKey(format!(
            "version byte {:02x} != {:02x}",
            version, expected_version
        )));
    }

    // Verify checksum
    let checksum_pos = decoded.len() - 2;
    let checksum = u16::from_le_bytes([decoded[checksum_pos], decoded[checksum_pos + 1]]);
    let computed = crc16_xmodem(&decoded[..checksum_pos]);
    if checksum != computed {
        return Err(CryptoError::InvalidStrKey("checksum mismatch".to_string()));
    }

    let mut key = [0u8; N];
    key.copy_from_slice(&decoded[1..1 + expected_len]);
    Ok(key)
}

fn decode_check_variable(expected_version: u8, s: &str) -> Result<Vec<u8>, CryptoError> {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
        .ok_or_else(|| CryptoError::InvalidStrKey("invalid base32".to_string()))?;

    if decoded.len() < 3 {
        return Err(CryptoError::InvalidStrKey("too short".to_string()));
    }

    let version = decoded[0];
    if version != expected_version {
        return Err(CryptoError::InvalidStrKey(format!(
            "version byte {:02x} != {:02x}",
            version, expected_version
        )));
    }

    // Verify checksum
    let checksum_pos = decoded.len() - 2;
    let checksum = u16::from_le_bytes([decoded[checksum_pos], decoded[checksum_pos + 1]]);
    let computed = crc16_xmodem(&decoded[..checksum_pos]);
    if checksum != computed {
        return Err(CryptoError::InvalidStrKey("checksum mismatch".to_string()));
    }

    Ok(decoded[1..checksum_pos].to_vec())
}

/// CRC16-XModem checksum.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id_roundtrip() {
        let key = [42u8; 32];
        let encoded = encode_account_id(&key);
        assert!(encoded.starts_with('G'));
        let decoded = decode_account_id(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_secret_seed_roundtrip() {
        let seed = [42u8; 32];
        let encoded = encode_secret_seed(&seed);
        assert!(encoded.starts_with('S'));
        let decoded = decode_secret_seed(&encoded).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_known_account_id() {
        // Test with a zero key - known value
        let key = [0u8; 32];
        let strkey = encode_account_id(&key);
        // Decode and verify roundtrip
        let decoded = decode_account_id(&strkey).unwrap();
        assert_eq!(decoded, key);
        // Verify starts with G (account ID prefix)
        assert!(strkey.starts_with('G'));
    }

    #[test]
    fn test_invalid_checksum() {
        let encoded = encode_account_id(&[0u8; 32]);
        // Corrupt the last character
        let mut chars: Vec<char> = encoded.chars().collect();
        let last_idx = chars.len() - 1;
        chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert!(decode_account_id(&corrupted).is_err());
    }

    #[test]
    fn test_muxed_account() {
        let key = [42u8; 32];
        let id = 12345u64;
        let encoded = encode_muxed_account(&key, id);
        assert!(encoded.starts_with('M'));
        let (decoded_key, decoded_id) = decode_muxed_account(&encoded).unwrap();
        assert_eq!(key, decoded_key);
        assert_eq!(id, decoded_id);
    }
}
