# stellar-core-herder

SCP coordination and ledger-close orchestration for rs-stellar-core.

## Overview

The herder bridges SCP consensus with ledger close. It tracks externalized slots, requests transaction sets, manages the transaction queue, and produces `LedgerCloseInfo` used by the ledger manager.

## Upstream Mapping

- `src/herder/*` (Herder, HerderSCPDriver, TxQueue)
- `src/herder/PendingEnvelopes.*`
- `src/herder/Upgrades.*`

## Key Responsibilities

- Track externalized SCP values and trigger ledger close.
- Manage pending tx set requests and caching.
- Apply surge-pricing ordering and lane limits.
- Maintain quorum tracking and SCP timing.

## Layout

```
crates/stellar-core-herder/
├── src/
│   ├── herder.rs
│   ├── scp_driver.rs
│   ├── tx_queue.rs
│   ├── surge_pricing.rs
│   ├── pending.rs
│   ├── upgrades.rs
│   └── error.rs
└── tests/
```

## Ledger Close Timing

- Uses protocol 23+ SCP timing config.
- Linear backoff with 30m cap for nomination/ballot timeouts.

## Tests To Port

From `src/herder/test/`:
- Tx set builder ordering and surge pricing.
- Quorum tracking edge cases.
- Externalization and catchup boundary behavior.

