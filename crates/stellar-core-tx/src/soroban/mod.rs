//! Soroban smart contract integration.
//!
//! This module provides the integration layer between the transaction processor
//! and Soroban smart contract execution. It handles:
//!
//! - Budget tracking for CPU and memory
//! - Storage interface for contract state
//! - Event recording
//! - Host function execution via soroban-env-host
//!
//! ## Architecture
//!
//! For full Soroban execution:
//! 1. Create a `Host` with storage adapter connected to our bucket list
//! 2. Load the contract WASM and invoke functions via soroban-env-host
//! 3. Capture state changes and events
//! 4. Apply changes back to our ledger state
//!
//! ## Protocol Versioning
//!
//! The `protocol` submodule provides protocol-versioned host implementations.
//! Each protocol version uses the exact same soroban-env-host version as
//! C++ stellar-core to ensure deterministic replay.

mod budget;
mod events;
mod host;
pub mod protocol;
mod storage;

pub use budget::{SorobanBudget, SorobanConfig, ResourceLimits, FeeConfiguration, RentFeeConfiguration};
pub use events::{ContractEvent, ContractEvents, EventType};
pub use host::{execute_host_function, SorobanExecutionResult, StorageChange};
pub use storage::{SorobanStorage, StorageEntry, StorageKey};
