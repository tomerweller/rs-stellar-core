# rs-stellar-core

A Rust reimplementation of Stellar Core focused on protocol v25 behavior and testnet sync. This is an educational experiment and **not** production-grade software.

## Overview

rs-stellar-core aims to mirror stellar-core v25.x behavior for ledger close, SCP, overlay, history/catchup, and transaction execution. The codebase is organized as a Rust workspace with focused crates for each subsystem.

Key constraints:
- Protocol 23+ only
- SQLite-only persistence
- Metrics parity is out of scope
- Deterministic, observable behavior should match upstream v25

## Status

Work in progress. See `PARITY_GAPS.md` for the current, module-by-module gap list.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test --all
```

## Run (Testnet)

```bash
# Use the packaged config
./target/release/rs-stellar-core --config configs/testnet.toml run

# Catch up first if needed
./target/release/rs-stellar-core --config configs/testnet.toml catchup current
```

## Configuration

Generate and edit a sample config:

```bash
./target/release/rs-stellar-core sample-config > my-config.toml
./target/release/rs-stellar-core --config my-config.toml run
```

Classic event emission (off by default) can be enabled in the config:

```toml
[events]
emit_classic_events = true
backfill_stellar_asset_events = false
```

## Repository Layout

- `crates/rs-stellar-core/` — main binary
- `crates/stellar-core-*/` — subsystem crates (ledger, herder, overlay, scp, history, tx, etc.)
- `configs/` — example configs
- `PARITY_GAPS.md` — master parity gap list

## Contributing

- Keep behavior deterministic and aligned with stellar-core v25.x.
- Add or update tests when behavior changes.
- Update crate READMEs when modifying subsystem behavior.

## License

Apache 2.0
