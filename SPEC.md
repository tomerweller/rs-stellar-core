# rs-stellar-core Specification

**Version:** 0.1.0
**Target Protocol:** v25.x (Protocol 23+ behavior)
**Network:** Testnet primary; mainnet readiness is a later milestone

## 1. Overview

rs-stellar-core is a Rust implementation of Stellar Core intended for research and education. It targets deterministic, observable behavior compatible with stellar-core v25.x, with SQLite-only persistence and no production hardening.

This project is **not** production-grade.

### 1.1 Goals

1. Deterministic parity with stellar-core v25.x for observable behavior.
2. Modular 1:1 mapping between upstream subsystems and crates.
3. Protocol 23+ only to reduce legacy complexity.
4. Educational, auditable Rust implementation.

### 1.2 Non-Goals

- Legacy protocol support (1–22).
- PostgreSQL support (SQLite only).
- Full metrics parity with stellar-core.
- Production deployment or operational hardening.

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           rs-stellar-core                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────┐             │
│  │   CLI   │  │  Config │  │ Logging  │  │  Admin   │             │
│  └────┬────┘  └────┬────┘  └────┬─────┘  └────┬─────┘             │
│       │            │            │             │                   │
│  ┌────┴────────────┴────────────┴─────────────┴───────┐           │
│  │                      Application                   │           │
│  └──────────────────────────┬─────────────────────────┘           │
│                             │                                     │
│  ┌──────────────────────────┴───────────────────────────┐         │
│  │                         Herder                        │         │
│  └──────┬─────────────────┬─────────────────────┬───────┘         │
│         │                 │                     │                 │
│  ┌──────┴──────┐   ┌──────┴──────┐      ┌──────┴──────┐           │
│  │     SCP     │   │   Ledger    │      │  Overlay    │           │
│  └─────────────┘   └──────┬──────┘      └──────┬──────┘           │
│                           │                    │                  │
│  ┌────────────────────────┴────────────────────┴───────────────┐  │
│  │                    Transaction Processing                  │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                     │
│  ┌──────────────────────────┴───────────────────────────────┐    │
│  │                      Storage Layer                       │    │
│  │  BucketList  |  Database (SQLite)  |  History Archives    │    │
│  └───────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      Foundation Layer                       │  │
│  │  Crypto  |  XDR (stellar-xdr)  |  Utils                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## 3. Workspace Layout

```
rs-stellar-core/
├── Cargo.toml                 # Workspace root
├── README.md                  # Project overview
├── PARITY_GAPS.md             # Master parity gap list
├── SPEC.md                    # This document
├── DOCUMENTATION_ISSUES.md    # Upstream doc issues found
├── configs/                   # Example configs
├── crates/                    # Subsystem crates
└── tests/                     # Integration tests
```

Each crate contains a README with subsystem documentation and upstream mapping.

### 3.1 Module Mapping to stellar-core

| rs-stellar-core crate | stellar-core directory | Description |
|-----------------------|------------------------|-------------|
| `stellar-core-app` | `src/main/` | Application orchestration and lifecycle |
| `stellar-core-scp` | `src/scp/` | Stellar Consensus Protocol |
| `stellar-core-herder` | `src/herder/` | SCP coordination, slot management |
| `stellar-core-overlay` | `src/overlay/` | P2P networking |
| `stellar-core-ledger` | `src/ledger/` | Ledger state, closing |
| `stellar-core-bucket` | `src/bucket/` | BucketList storage |
| `stellar-core-history` | `src/history/` | Archive publish/catchup |
| `stellar-core-tx` | `src/transactions/` | Transaction validation/execution |
| `stellar-core-crypto` | `src/crypto/` | Hashing, signatures, keys |
| `stellar-core-db` | `src/database/` | SQLite persistence |
| `stellar-core-common` | `src/util/` | Shared utilities |

## 4. Dependencies

### 4.1 Stellar Rust Crates

- `stellar-xdr` (v25)
- `soroban-env-host` (Protocol 23+ compatible)
- `soroban-env-common`

### 4.2 Third-Party Crates (selected)

- `tokio` (async runtime)
- `rusqlite` (SQLite)
- `ed25519-dalek`, `sha2`, `siphasher` (crypto)
- `tracing` (logging)
- `clap` (CLI)
- `reqwest` (history archive HTTP)
- `serde` / `serde_json` (serialization)

## 5. Protocol Support

- Protocol 23+ behavior only (targeting v25.x).
- Soroban operations supported via host integration.

## 6. Testing Strategy

- Unit and integration tests live within each crate and under `tests/`.
- Upstream test vectors should be ported where possible.
- Parity and regression gaps are tracked in `PARITY_GAPS.md`.

## 7. Configuration

TOML configs under `configs/` mirror the runtime structure. Example:

```toml
[network]
passphrase = "Test SDF Network ; September 2015"
peer_port = 11625
http_port = 11626

[database]
path = "stellar.db"

[history]
archives = [
    "https://history.stellar.org/prd/core-testnet/core_testnet_001",
    "https://history.stellar.org/prd/core-testnet/core_testnet_002",
    "https://history.stellar.org/prd/core-testnet/core_testnet_003"
]
```

## 8. Known Limitations

- SQLite-only persistence.
- Metrics parity is intentionally out of scope.
- Not production-hardened; use for education and research only.

## 9. References

- stellar-core (upstream): https://github.com/stellar/stellar-core
- CAPs: https://github.com/stellar/stellar-protocol/tree/master/core
- stellar-xdr: https://github.com/stellar/rs-stellar-xdr
- soroban-env-host: https://github.com/stellar/rs-soroban-env
