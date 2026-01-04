# Repository Guidelines

## Project Structure & Module Organization

- `crates/` contains the Rust workspace crates. Each module is a crate (e.g., `crates/stellar-core-ledger`, `crates/stellar-core-tx`, `crates/stellar-core-history`).
- `crates/rs-stellar-core/` is the main binary crate; other crates are libraries.
- Tests live alongside code in `crates/*/src` and in `crates/*/tests` for integration tests.
- Docs live in crate `README.md` files plus top-level `README.md`, `SPEC.md`, and `DOCUMENTATION_ISSUES.md`.
- Config examples are in `configs/` and `*.toml` at the repo root.

## Build, Test, and Development Commands

- `cargo build --all` — build the entire workspace.
- `cargo test --all` — run all unit and integration tests.
- `cargo test -p stellar-core-ledger --tests` — run a focused crate’s integration tests.
- `cargo clippy --all` — run lint checks (recommended before PRs).

## Coding Style & Naming Conventions

- Follow standard Rust style (4-space indentation, snake_case for functions and modules, CamelCase for types).
- Keep modules small and focused; prefer adding logic inside the relevant crate instead of cross-crate helpers.
- Use descriptive error messages and map to XDR result codes where applicable.
- Fix cargo compiler warnings before submitting changes; keep the workspace warning-free where practical.

## Determinism & Parity

- Any observable behavior must be deterministic and identical to stellar-core (v25.x / p25).
- Align behavior by comparing against upstream test vectors and edge cases; do not introduce new semantics.
- For protocol or consensus behavior, consult `.upstream-v25/` to mirror upstream decisions and sequencing.

## Testing Guidelines

- Use Rust’s built-in test framework (`#[test]`).
- Unit tests go in the same module; integration tests go in `crates/<crate>/tests/`.
- Name tests by behavior, e.g., `test_execute_transaction_min_seq_num_precondition`.
- Run focused tests when possible to speed iteration, then run `cargo test --all` before submitting.

## Commit & Pull Request Guidelines

- Commit messages are short, imperative, and sentence case (examples: “Implement disk-backed bucket storage”, “Optimize memory usage”).
- PRs should include: a clear description, the tests run, and documentation updates when behavior changes.
- Link related issues or upstream references (e.g., stellar-core v25) where relevant.

## Configuration & Operational Notes

- SQLite is the only supported database backend.
- Protocol support is 23+ only; do not add legacy protocol behavior.
- The Stellar Core v25 C++ upstream is available locally under `.upstream-v25/` for parity checks.
