# stellar-core-overlay

P2P overlay networking layer for rs-stellar-core.

## Overview

Handles peer connections, authentication, message routing, flood control, surveys, and transaction advert/demand. Implements Stellar overlay protocol behavior for v25.

## Upstream Mapping

- `src/overlay/*` (OverlayManager, Peer, FlowControl, Survey)

## Layout

```
crates/stellar-core-overlay/
├── src/
│   ├── manager.rs
│   ├── peer.rs
│   ├── flow_control.rs
│   ├── survey.rs
│   ├── flood_gate.rs
│   ├── codec.rs
│   └── error.rs
└── tests/
```

## Key Concepts

- Authenticated handshake (Curve25519).
- Flood gate + rate limiting for inbound/outbound traffic.
- Peer discovery persistence and backoff.
- Tx advert/fetch queues with retry scheduling.

## Tests To Port

From `src/overlay/test/`:
- Peer handshake and auth flows.
- Flood gate and rate-limiting behaviors.
- Survey encryption and paging.

