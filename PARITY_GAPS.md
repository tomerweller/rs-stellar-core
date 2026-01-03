# Parity Gaps (stellar-core v25.x)

Scope: Protocol 23+ only, SQLite only, no production hardening. Metrics parity is explicitly out of scope. Observable behavior must remain deterministic and match stellar-core v25.x.

## Application / Ops

### Functional Gaps
- End-to-end validator readiness run: catchup to recent ledger, run close loop continuously, invariants enabled.
- Mainnet readiness checklist: config validation, sustained testnet soak, runbooks, and performance/soak validation.
- Process manager utilities parity (upstream process helpers not yet mirrored).

### Testing Gaps
- Long-running validator soak tests (testnet) to detect divergence or catchup failures.
- Operational readiness tests (restart/recovery, backup/restore, upgrade/rollback).

## Work Scheduler

### Functional Gaps
- App-level metrics export wiring (intentionally out of scope for parity, but still missing).

### Testing Gaps
- Scheduler stress tests and cancellation edge-case coverage.

## Overlay / Network

### Functional Gaps
- None known at v25 parity baseline.

### Testing Gaps
- Integration tests for peer discovery persistence/backoff over restarts.
- Survey/reporting end-to-end tests with encrypted payloads and paging.

## SCP

### Functional Gaps
- Edge-case SCP semantics still pending (slot/ballot corner cases not yet fully validated against upstream).

### Testing Gaps
- Additional upstream-aligned golden vectors for nomination/ballot edge cases.

## Herder

### Functional Gaps
- None known at v25 parity baseline.

### Testing Gaps
- Broader quorum tracker regression coverage (basic expansion/rebuild edge cases covered; broader graph scenarios still missing).
- Tx set builder parity tests against upstream fixtures.

## Ledger / Close

### Functional Gaps
- None known at v25 parity baseline.

### Testing Gaps
- Upstream ledger-close meta golden vectors beyond synthetic fixtures.
- Replay failure handling parity tests for invariants.

## Transactions / Tx Execution

### Functional Gaps
- None known at v25 parity baseline.

### Testing Gaps
- Upstream tx meta hash vector coverage (synthetic vectors exist; upstream fixtures pending).
- Classic event emission golden vectors (ledger-close-meta fixtures with EMIT_CLASSIC_EVENTS enabled).
- Expanded per-operation regression suite for classic + Soroban edge cases.

## History / Catchup

### Functional Gaps
- None known at v25 parity baseline.

### Testing Gaps
- More end-to-end replay tests across multiple checkpoints and archives.

## Historywork

### Functional Gaps
- Metrics export wiring (intentionally out of scope for parity, but still missing).

### Testing Gaps
- Work sequencing tests for partial downloads and retry behavior.

## Bucket / BucketList

### Functional Gaps
- None known at v25 parity baseline.

### Testing Gaps
- Upstream bucket merge/index regression suites and large-scale replay tests.

## Invariants

### Functional Gaps
- Partial parity: added ledger seq bounds, account sequence/signers/flags/home_domain/ext/num_sub_entries checks; trustline asset/limit/flags/extensions; offer assets/validity/flags; claimable balance sponsorship/asset/predicate/flag checks; data name validation; liquidity pool parameter/sponsorship checks; contract code hash validation; sponsorship count checks; account subentries count checks; liabilities/order-book/constant-product checks at operation + ledger close; and ledger-close constant product check with pool-share decrease exemption. Added op-level EventsAreConsistentWithEntryDiffs for classic + Soroban contract events. Full invariant set parity still missing (bucket/ledger/db invariants, etc.).

### Testing Gaps
- Full invariant coverage tests and replay failure regression tests.

## Simulation

### Functional Gaps
- Deterministic multi-node simulation runs (deterministic node keys supported; deterministic scheduling and full scenario scripts still missing).
- Load/tx generators and scripted scenarios.

### Testing Gaps
- Simulation-based regression suite that mirrors upstream scenarios.
