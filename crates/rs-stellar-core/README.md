# rs-stellar-core

Main binary for rs-stellar-core - a pure Rust implementation of Stellar Core.

## Overview

This crate provides:

- Command-line interface (CLI) for all node operations
- Thin wrapper around `stellar-core-app` for runtime orchestration

## CLI Usage

```bash
rs-stellar-core [OPTIONS] <COMMAND>
```

### Global Options

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to configuration file |
| `-v, --verbose` | Enable verbose logging |
| `--trace` | Enable trace logging |
| `--log-format <FORMAT>` | Log format: text or json |
| `--testnet` | Use testnet configuration |
| `--mainnet` | Use mainnet configuration |

### Commands

#### run

Start the node:

```bash
# Run with testnet defaults
rs-stellar-core --testnet run

# Run as validator
rs-stellar-core --testnet run --validator

# Run with HTTP server on custom port
rs-stellar-core --testnet run --http-port 8080
```

#### catchup

Catch up from history archives:

```bash
# Catch up to current ledger
rs-stellar-core --testnet catchup current

# Catch up to specific ledger
rs-stellar-core --testnet catchup 1000000

# Minimal mode (fastest)
rs-stellar-core --testnet catchup current --mode minimal

# With parallel downloads
rs-stellar-core --testnet catchup current --parallelism 16
```

The catchup command uses the historywork pipeline for checkpoint downloads
when available, falling back to direct archive fetches on failure.

#### new-db

Create a new database:

```bash
rs-stellar-core --testnet new-db
```

#### upgrade-db

Upgrade database schema:

```bash
rs-stellar-core --config config.toml upgrade-db
```

#### new-keypair

Generate a new node keypair:

```bash
rs-stellar-core new-keypair
```

#### info

Print node information:

```bash
rs-stellar-core --config config.toml info
```

#### verify-history

Verify history archives:

```bash
rs-stellar-core --testnet verify-history
rs-stellar-core --testnet verify-history --from 1000 --to 2000
```

#### publish-history

Publish history to archives (validators only):

```bash
rs-stellar-core --config config.toml publish-history
rs-stellar-core --config config.toml publish-history --force
```

#### sample-config

Print sample configuration:

```bash
rs-stellar-core sample-config > config.toml
```

#### offline

Offline utilities:

```bash
# Convert key formats
rs-stellar-core offline convert-key GDKXE2OZM...

# Decode XDR
rs-stellar-core offline decode-xdr --type LedgerHeader <base64>

# Encode to XDR
rs-stellar-core offline encode-xdr --type AccountId GDKXE2OZM...
rs-stellar-core offline encode-xdr --type Asset "USD:GDKXE2OZM..."
rs-stellar-core offline encode-xdr --type Hash <64-char-hex>

# Bucket info
rs-stellar-core offline bucket-info /path/to/buckets
```

## HTTP API

When running, the node exposes an HTTP API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API overview |
| `/info` | GET | Node information |
| `/status` | GET | Node status summary |
| `/metrics` | GET | Prometheus metrics |
| `/peers` | GET | Connected peers |
| `/connect` | POST | Connect to peer (query: `addr` or `peer`+`port`) |
| `/droppeer` | POST | Disconnect peer (query: `peer_id` or `node`, optional `ban=1`) |
| `/bans` | GET | List banned peers |
| `/unban` | POST | Remove peer from ban list (query: `peer_id` or `node`) |
| `/ledger` | GET | Current ledger |
| `/upgrades` | GET | Current + proposed upgrade settings |
| `/self-check` | POST | Run ledger self-check |
| `/quorum` | GET | Local quorum set summary |
| `/survey` | GET | Survey report |
| `/scp` | GET | SCP slot summary (query: `limit`) |
| `/survey/start` | POST | Start survey collecting (query: `nonce`) |
| `/survey/stop` | POST | Stop survey collecting |
| `/survey/topology` | POST | Queue survey topology request |
| `/survey/reporting/stop` | POST | Stop survey reporting |
| `/tx` | POST | Submit transaction |
| `/shutdown` | POST | Request graceful shutdown |
| `/health` | GET | Health check |

### Submit Transaction

```bash
curl -X POST http://localhost:11626/tx \
  -H "Content-Type: application/json" \
  -d '{"tx": "<base64-xdr>"}'
```

### Check Health

```bash
curl http://localhost:11626/health
```

## Application Architecture

```
+------------------+
|       App        |
|------------------|
| - config         |
| - database       |
| - bucket_manager |
| - overlay        |
| - herder         |
| - ledger_manager |
+------------------+
        |
        v
+------------------+     +------------------+
|  Status Server   |     |  Overlay Network |
+------------------+     +------------------+
```

## Configuration

### Example Configuration

```toml
[node]
name = "my-node"
is_validator = false

[network]
passphrase = "Test SDF Network ; September 2015"

[database]
path = "stellar.db"

[http]
port = 11626
enabled = true

[history]
[[history.archives]]
url = "https://history.stellar.org/prd/core-testnet/core_testnet_001"
get = true
put = false

[peers]
known = [
    "core-testnet1.stellar.org:11625",
    "core-testnet2.stellar.org:11625",
]

[quorum]
threshold = 2
validators = [
    "GDKXE2OZM...",
    "GCEZWKCA5...",
    "GBLJNN7HG...",
]
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Database error |
| 4 | Network error |

## Logging

Logs use the `tracing` framework:

```bash
# Verbose output
rs-stellar-core --verbose run

# Trace output
rs-stellar-core --trace run

# JSON format
rs-stellar-core --log-format json run

# Filter by module
RUST_LOG=stellar_core_overlay=debug rs-stellar-core run
```

## Dependencies

- `clap` - CLI parsing
- `axum` - HTTP server
- `tokio` - Async runtime
- `tracing` - Logging
- `serde` - Configuration
- All stellar-core-* crates

## License

Apache 2.0
