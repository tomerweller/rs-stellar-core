# stellar-core-ledger

Ledger state management and ledger close pipeline for rs-stellar-core.

## Overview

This crate owns ledger close execution, bucket list updates, and ledger header/close metadata generation. It integrates transaction execution, invariants, and bucket list hashing.

## Upstream Mapping

- `src/ledger/*` (LedgerManager, LedgerTxn, LedgerCloseMeta)
- `src/ledger/LedgerHeaderUtils.*`

## Layout

```
crates/stellar-core-ledger/
├── src/
│   ├── manager.rs
│   ├── close.rs
│   ├── execution.rs
│   ├── delta.rs
│   ├── header.rs
│   ├── snapshot.rs
│   └── error.rs
└── tests/
```

## Key Concepts

- **LedgerCloseData**: externalized tx set + close time + upgrades.
- **LedgerManager**: coordinates close, applies txs, updates bucket list.
- **LedgerCloseMeta**: persisted per-ledger metadata for history.

## Tests To Port

From `src/ledger/test/`:
- Ledger close meta vectors
- LedgerTxn consistency checks
- Bucket hash consistency

