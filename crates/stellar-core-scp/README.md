# stellar-core-scp

Stellar Consensus Protocol (SCP) implementation.

## Overview

Implements nomination and ballot protocols, slot state tracking, and deterministic value hashing used for consensus. The module is designed to be deterministic and stable under replay.

## Upstream Mapping

- `src/scp/*` (SCP, Slot, BallotProtocol, NominationProtocol)

## Layout

```
crates/stellar-core-scp/
├── src/
│   ├── scp.rs
│   ├── slot.rs
│   ├── nomination.rs
│   ├── ballot.rs
│   └── error.rs
└── tests/
```

## Determinism Notes

- Hashes are computed over XDR bytes.
- Ordering of candidate values is deterministic.
- Timeout backoff is deterministic given config.

## Tests To Port

From `src/scp/test/`:
- Nomination/ballot edge cases.
- Slot recovery and externalization ordering.

