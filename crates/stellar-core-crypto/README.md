# stellar-core-crypto

Pure Rust cryptographic primitives used across rs-stellar-core.

## Overview

This crate provides hashing, signatures, key encoding, and sealed-box support used by overlay, SCP, history, and transaction validation. The implementation is pure Rust (no libsodium) and targets deterministic behavior compatible with stellar-core v25.

## Upstream Mapping

- `src/crypto/*` in stellar-core
- StrKey and key utilities
- Short-hash utilities

## Key Capabilities

- Ed25519 key generation, signing, verification
- SHA-256 hashing and XDR hashing helpers
- SipHash-2-4 short hashes for deterministic ordering
- StrKey encode/decode for Stellar key formats
- Curve25519 sealed boxes for survey payloads

## Layout

```
crates/stellar-core-crypto/
├── src/
│   ├── lib.rs
│   ├── hash.rs
│   ├── short_hash.rs
│   ├── strkey.rs
│   ├── xdr.rs
│   └── error.rs
└── tests/
```

## Dependencies (Core)

- `ed25519-dalek`
- `sha2`
- `rand`
- `siphasher`

## Tests To Port

- `crypto/test/*` from stellar-core (key encoding, signature vectors, short-hash ordering)

## Security Notes

- Keys are zeroized on drop where possible.
- Avoid non-deterministic ordering by always hashing XDR bytes directly.

