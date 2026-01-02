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

## Security: EXTERNALIZE Message Validation

EXTERNALIZE messages from SCP can fast-forward a node's tracking slot, which is
necessary for catching up to the network. However, this capability must be
protected against malicious actors who could send fake EXTERNALIZE messages.

Two security checks are applied before accepting an EXTERNALIZE fast-forward:

1. **Quorum Membership**: The sender must be in our transitive quorum set.
   This ensures we only trust nodes that are part of our configured quorum.

2. **Slot Distance Limit**: The slot must be within `MAX_EXTERNALIZE_SLOT_DISTANCE`
   (1000 ledgers, ~83 minutes) of our current tracking slot. This prevents
   malicious nodes from making us attempt catchup to non-existent slots.

These checks are implemented in `receive_scp_envelope()` in `herder.rs`.

## Tests To Port

From `src/herder/test/`:
- Tx set builder ordering and surge pricing.
- Quorum tracking edge cases.
- Externalization and catchup boundary behavior.

