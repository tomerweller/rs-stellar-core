# stellar-core-invariant

Invariant framework for validating ledger transitions.

## Scope

- Invariant trait + registry (`InvariantManager`).
- Basic invariants: ledger sequence increment, bucket list hash match,
  conservation of lumens, and entry validity checks (ledger seq bounds,
  account flags/signers/home domain/ext checks, trustline asset/limits/flags/
  extensions, offer fields/assets, claimable balance sponsorship/assets/predicates,
  data names, liquidity pool parameters/sponsorship, contract code hash),
  sponsorship count, account subentry count, constant product checks, order book
  crossed checks, and liabilities vs offer deltas.
- Hooked into ledger close when enabled.
- Operation-level checks for liabilities/order book/constant product are run during
  transaction execution when invariants are enabled.
- Operation-level event consistency checks for Soroban contract events are run
  alongside other op-level invariants.

## Status

Partial parity with upstream `src/invariant/*`. Additional core invariants,
replay hooks, and metrics are still missing.

## Usage

Register invariants via `LedgerManager::add_invariant()` or add to the
`InvariantManager` directly in tests. The `InvariantContext` includes
header transitions, deltas, and entry changes (with previous/current data
when available). For operation-level checks, it can also carry the contract
events emitted by the operation.
