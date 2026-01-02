# stellar-core-bucket

BucketList implementation for rs-stellar-core.

## Overview

The BucketList is the canonical on-disk state for Stellar. It stores ordered ledger entries in immutable bucket files organized by level, supporting efficient replay, hash verification, and incremental state updates.

## Upstream Mapping

- `src/bucket/*` (Bucket, BucketList, BucketManager, BucketIndex, BucketMerger)
- `LiveBucket` and hot archive buckets

## Key Concepts

- **BucketList**: 11 levels (0-10), each with `curr`, `snap`, and optional `next`.
- **BucketEntry**: `LiveEntry`, `DeadEntry`, `InitEntry`, `Metadata`.
- **Spill schedule**: Level N spills every 2^(2N) ledgers.
- **Hot archive**: Separate bucket list for archived Soroban entries.

## Layout

```
crates/stellar-core-bucket/
├── src/
│   ├── bucket.rs
│   ├── bucket_list.rs
│   ├── bucket_index.rs
│   ├── entry.rs
│   ├── live_bucket.rs
│   ├── manager.rs
│   ├── merger.rs
│   ├── snapshot.rs
│   └── error.rs
└── tests/
```

## Protocol 23+ Notes

- Soroban live entries are kept in memory (CAP-0062).
- Hot archive buckets support automatic restoration (CAP-0066).

## Tests To Port

From `src/bucket/test/`:
- `BucketListTests.cpp`
- `BucketMergeTest.cpp`
- `BucketIndexTests.cpp`
- `BucketManagerTests.cpp`

## Performance Notes

- Prefer memory-mapped reads for large buckets.
- Cache bucket indexes for hot buckets.
- Parallelize merges when safe.

