# stellar-core Documentation Issues

This file tracks documentation issues, inconsistencies, or outdated information discovered in stellar-core documentation during the development of rs-stellar-core. These should be shared with the Stellar Core team.

## Format

Each entry includes:
- **Location**: File path or URL
- **Issue**: Description of the problem
- **Discovered**: Date and context
- **Status**: Open / Reported / Fixed

---

## Issues

### 1. History Archive Structure Documentation

**Location**: `docs/history.md`
**Issue**: The documentation describes the history archive file structure but doesn't clearly document:
- The exact XDR types used in each file (e.g., `LedgerHeaderHistoryEntry` vs `LedgerHeader`)
- The gzip compression applied to XDR files
- The fact that bucket files use raw XDR stream (not length-prefixed)
- The checkpoint frequency (64 ledgers) is mentioned but formula for checkpoint ledger numbers isn't explicit

**Discovered**: 2025-12-30, during history module implementation
**Status**: Open
**Suggested Fix**: Add a section explicitly listing:
```
Checkpoint ledger = (ledger_seq / 64) * 64 + 63
Files contain gzipped XDR streams
Bucket files: concatenated BucketEntry XDR
Header files: concatenated LedgerHeaderHistoryEntry XDR
```

---

### 2. BucketList Merge Semantics

**Location**: `src/bucket/` (code comments)
**Issue**: The documentation for INIT vs LIVE entry semantics during merges is scattered across multiple source files. The key insight that:
- INIT entries "win" over LIVE entries from the same ledger
- Dead entries must be kept until they propagate to higher levels
- The protocol version in BucketMetadata affects merge behavior

Could benefit from a consolidated document.

**Discovered**: 2025-12-30, during bucket module implementation
**Status**: Open
**Suggested Fix**: Add a merge-semantics section with pseudocode to `crates/stellar-core-bucket/README.md`

---

### 3. SCP Driver Interface

**Location**: `src/scp/SCPDriver.h`
**Issue**: The `SCPDriver` callback interface documentation doesn't clearly specify:
- When `validateValue` vs `validateBallot` should be called
- The expected behavior for `combineCandidates`
- Timing requirements for `signEnvelope` vs async signing
- Error handling expectations (what happens if a callback throws)

**Discovered**: 2025-12-30, during SCP module implementation
**Status**: Open
**Suggested Fix**: Add detailed callback contract documentation

---

### 4. Overlay Authentication Protocol

**Location**: `src/overlay/` (scattered across files)
**Issue**: The authentication handshake sequence isn't documented in one place:
1. Hello message exchange
2. Auth certificate validation
3. HMAC key derivation
4. Message authentication

The code implements this but no unified protocol document exists.

**Discovered**: 2025-12-30, during overlay module implementation
**Status**: Open
**Suggested Fix**: Add an authentication protocol section to `crates/stellar-core-overlay/README.md`

---

### 5. Transaction Application Order

**Location**: `src/transactions/TransactionFrame.cpp`
**Issue**: The order of transaction validation checks isn't documented. The actual order matters for error reporting:
1. Structural validation
2. Signature verification
3. Sequence number check
4. Fee check
5. Time bounds
6. Ledger bounds
7. Operation-specific checks

**Discovered**: 2025-12-30, during tx module implementation
**Status**: Open
**Suggested Fix**: Document validation pipeline order in `crates/stellar-core-tx/README.md`

---

### 6. LedgerTxn vs LedgerTxnEntry

**Location**: `src/ledger/LedgerTxn*.h`
**Issue**: The relationship between `LedgerTxn`, `LedgerTxnEntry`, and `LedgerTxnRoot` is complex and not well documented. Key concepts:
- Copy-on-write semantics
- Entry borrowing rules
- When entries are committed vs rolled back

**Discovered**: 2025-12-30, during ledger module implementation
**Status**: Open
**Suggested Fix**: Add a LedgerTxn overview section to `crates/stellar-core-ledger/README.md`

---

### 7. Protocol Version Upgrade Mechanics

**Location**: `src/herder/Upgrades.cpp`
**Issue**: How protocol upgrades propagate through the network isn't clearly documented:
- When upgrades take effect (close of ledger N or N+1?)
- How validators signal upgrade readiness
- Coordination requirements for network-wide upgrades

**Discovered**: 2025-12-30, during herder module implementation
**Status**: Open
**Suggested Fix**: Add a protocol upgrades section to `crates/stellar-core-herder/README.md`

---

### 8. Soroban Integration Points

**Location**: Various
**Issue**: The integration between classic stellar-core and Soroban host is documented in CAPs but practical integration details are missing:
- How Soroban footprint is validated before execution
- Resource metering integration points
- State archival interaction with BucketList

**Discovered**: 2025-12-30, during tx module implementation
**Status**: Open
**Suggested Fix**: Add Soroban integration notes to `crates/stellar-core-tx/README.md`

---

## Notes for Contributors

When you discover a documentation issue:

1. Add an entry to this file with all relevant details
2. Include the exact location (file path, line number, or URL)
3. Describe what's wrong and what the correct information should be
4. Note how you discovered the issue (which module you were implementing)
5. If possible, suggest a fix

## Reporting Process

Once this file has accumulated significant issues, we will:

1. Create GitHub issues on the stellar/stellar-core repository
2. Link to the relevant issues in the Status field
3. Update Status to "Reported" with issue numbers
4. Track resolution and update to "Fixed" when merged

---

*Last updated: 2025-12-30*
