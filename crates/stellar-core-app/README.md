# stellar-core-app

Application orchestration layer for rs-stellar-core.

## Overview

This crate wires together overlay, herder, ledger, history, and configuration. It hosts the main application state machine, CLI-facing operations (run/catchup), logging setup, and HTTP status endpoints.

## Upstream Mapping

- `src/main/`, `src/ledger/` orchestration logic
- Command handling and node lifecycle in stellar-core

## Layout

```
crates/stellar-core-app/
├── src/
│   ├── app.rs
│   ├── catchup_cmd.rs
│   ├── config.rs
│   ├── logging.rs
│   ├── run_cmd.rs
│   └── survey.rs
└── tests/
```

## Tests To Port

- Application lifecycle tests
- End-to-end validator readiness runs

