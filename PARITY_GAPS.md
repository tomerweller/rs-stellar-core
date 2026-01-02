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
- Quorum tracking parity beyond slot-level quorum/v-blocking (upstream fidelity incomplete).

### Testing Gaps
- Broader quorum tracker regression coverage.
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
- Full invariant set parity (bucket/ledger/db, sponsorship, order book, liabilities, events, constant product, etc.).
- Replay invariant failure handling parity (strict vs non-strict, reporting behavior).

### Testing Gaps
- Full invariant coverage tests and replay failure regression tests.

## Simulation

### Functional Gaps
- Deterministic multi-node simulation runs.
- Load/tx generators and scripted scenarios.

### Testing Gaps
- Simulation-based regression suite that mirrors upstream scenarios.
