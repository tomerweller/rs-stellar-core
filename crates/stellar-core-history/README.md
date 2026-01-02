# stellar-core-history

History archive access, catchup, replay, and publish support.

## Overview

This crate reads and writes history archives (HAS, buckets, ledger headers, transaction sets/results, and SCP history). It powers catchup and replay verification for validators.

## Upstream Mapping

- `src/history/*`
- `src/catchup/*`

## Layout

```
crates/stellar-core-history/
├── src/
│   ├── archive.rs
│   ├── catchup.rs
│   ├── checkpoint.rs
│   ├── publish.rs
│   ├── replay.rs
│   ├── verify.rs
│   └── error.rs
└── tests/
```

## Archive Structure

History archives are organized by checkpoint (64-ledger cadence), with buckets stored under `bucket/` and ledger/tx/SCP files stored under `ledger/`, `transactions/`, `results/`, and `scp/`.

## Tests To Port

From `src/history/test/`:
- HAS parsing and integrity checks.
- Replay verification of tx set/result hashes.
- Publish validation for archive layout.

