//! Soroban resource budget tracking.
//!
//! Tracks CPU instructions and memory usage for contract execution.

use soroban_env_host::fees::{FeeConfiguration, RentFeeConfiguration};
use stellar_xdr::curr::ContractCostParams;

/// Soroban network configuration for contract execution.
///
/// This contains the cost parameters and limits loaded from the network's
/// ConfigSettingEntry entries. These must match the network to produce
/// correct transaction results and ledger hashes.
#[derive(Debug)]
pub struct SorobanConfig {
    /// CPU cost model parameters from ConfigSettingId::ContractCostParamsCpuInstructions.
    pub cpu_cost_params: ContractCostParams,
    /// Memory cost model parameters from ConfigSettingId::ContractCostParamsMemoryBytes.
    pub mem_cost_params: ContractCostParams,
    /// Maximum CPU instructions per transaction from ConfigSettingId::ContractComputeV0.
    pub tx_max_instructions: u64,
    /// Maximum memory bytes per transaction.
    pub tx_max_memory_bytes: u64,
    /// Minimum TTL for temporary entries.
    pub min_temp_entry_ttl: u32,
    /// Minimum TTL for persistent entries.
    pub min_persistent_entry_ttl: u32,
    /// Maximum TTL for any entry.
    pub max_entry_ttl: u32,
    /// Fee configuration for Soroban resource fees.
    pub fee_config: FeeConfiguration,
    /// Rent fee configuration for Soroban storage.
    pub rent_fee_config: RentFeeConfiguration,
    /// Maximum size of contract events + return value per tx.
    pub tx_max_contract_events_size_bytes: u32,
}

impl Default for SorobanConfig {
    fn default() -> Self {
        // Default values matching protocol 21 testnet/mainnet
        // These are placeholders - real values should be loaded from ConfigSettingEntry
        Self {
            cpu_cost_params: ContractCostParams(vec![].try_into().unwrap_or_default()),
            mem_cost_params: ContractCostParams(vec![].try_into().unwrap_or_default()),
            tx_max_instructions: 100_000_000,       // 100M instructions
            tx_max_memory_bytes: 40 * 1024 * 1024,  // 40 MB
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 120960,       // ~7 days at 5s ledger close
            max_entry_ttl: 6312000,                 // ~1 year
            fee_config: FeeConfiguration::default(),
            rent_fee_config: RentFeeConfiguration::default(),
            tx_max_contract_events_size_bytes: 0,
        }
    }
}

impl SorobanConfig {
    /// Check if this config has valid cost parameters.
    ///
    /// Returns false if the cost params are empty (default/placeholder values).
    pub fn has_valid_cost_params(&self) -> bool {
        !self.cpu_cost_params.0.is_empty() && !self.mem_cost_params.0.is_empty()
    }
}

/// Resource limits for Soroban execution.
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    /// Maximum CPU instructions allowed.
    pub cpu_instructions: u64,
    /// Maximum memory bytes allowed.
    pub memory_bytes: u64,
    /// Maximum read bytes allowed.
    pub read_bytes: u64,
    /// Maximum write bytes allowed.
    pub write_bytes: u64,
    /// Maximum read entries allowed.
    pub read_entries: u32,
    /// Maximum write entries allowed.
    pub write_entries: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_instructions: 100_000_000, // 100M instructions
            memory_bytes: 64 * 1024 * 1024, // 64 MB
            read_bytes: 200 * 1024,         // 200 KB
            write_bytes: 65 * 1024,         // 65 KB
            read_entries: 40,
            write_entries: 25,
        }
    }
}

impl ResourceLimits {
    /// Create limits from SorobanResources XDR.
    pub fn from_soroban_resources(resources: &stellar_xdr::curr::SorobanResources) -> Self {
        Self {
            cpu_instructions: resources.instructions as u64,
            memory_bytes: 64 * 1024 * 1024, // Fixed memory limit
            read_bytes: resources.disk_read_bytes as u64,
            write_bytes: resources.write_bytes as u64,
            read_entries: resources.footprint.read_only.len() as u32,
            write_entries: resources.footprint.read_write.len() as u32,
        }
    }
}

/// Budget tracker for Soroban execution.
#[derive(Debug, Clone)]
pub struct SorobanBudget {
    /// Current CPU instructions used.
    pub cpu_used: u64,
    /// Current memory bytes used.
    pub mem_used: u64,
    /// Current read bytes used.
    pub read_bytes_used: u64,
    /// Current write bytes used.
    pub write_bytes_used: u64,
    /// Resource limits.
    pub limits: ResourceLimits,
}

impl SorobanBudget {
    /// Create a new budget with the given limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            cpu_used: 0,
            mem_used: 0,
            read_bytes_used: 0,
            write_bytes_used: 0,
            limits,
        }
    }

    /// Charge CPU instructions.
    pub fn charge_cpu(&mut self, instructions: u64) -> Result<(), BudgetError> {
        self.cpu_used = self.cpu_used.saturating_add(instructions);
        if self.cpu_used > self.limits.cpu_instructions {
            Err(BudgetError::CpuLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Charge memory allocation.
    pub fn charge_mem(&mut self, bytes: u64) -> Result<(), BudgetError> {
        self.mem_used = self.mem_used.saturating_add(bytes);
        if self.mem_used > self.limits.memory_bytes {
            Err(BudgetError::MemoryLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Charge read bytes.
    pub fn charge_read(&mut self, bytes: u64) -> Result<(), BudgetError> {
        self.read_bytes_used = self.read_bytes_used.saturating_add(bytes);
        if self.read_bytes_used > self.limits.read_bytes {
            Err(BudgetError::ReadLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Charge write bytes.
    pub fn charge_write(&mut self, bytes: u64) -> Result<(), BudgetError> {
        self.write_bytes_used = self.write_bytes_used.saturating_add(bytes);
        if self.write_bytes_used > self.limits.write_bytes {
            Err(BudgetError::WriteLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Check if the budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.cpu_used > self.limits.cpu_instructions
            || self.mem_used > self.limits.memory_bytes
            || self.read_bytes_used > self.limits.read_bytes
            || self.write_bytes_used > self.limits.write_bytes
    }

    /// Get remaining CPU instructions.
    pub fn remaining_cpu(&self) -> u64 {
        self.limits.cpu_instructions.saturating_sub(self.cpu_used)
    }

    /// Get remaining memory bytes.
    pub fn remaining_mem(&self) -> u64 {
        self.limits.memory_bytes.saturating_sub(self.mem_used)
    }

    /// Reset the budget.
    pub fn reset(&mut self) {
        self.cpu_used = 0;
        self.mem_used = 0;
        self.read_bytes_used = 0;
        self.write_bytes_used = 0;
    }
}

/// Budget tracking error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    /// CPU instruction limit exceeded.
    CpuLimitExceeded,
    /// Memory limit exceeded.
    MemoryLimitExceeded,
    /// Read bytes limit exceeded.
    ReadLimitExceeded,
    /// Write bytes limit exceeded.
    WriteLimitExceeded,
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CpuLimitExceeded => write!(f, "CPU instruction limit exceeded"),
            Self::MemoryLimitExceeded => write!(f, "memory limit exceeded"),
            Self::ReadLimitExceeded => write!(f, "read bytes limit exceeded"),
            Self::WriteLimitExceeded => write!(f, "write bytes limit exceeded"),
        }
    }
}

impl std::error::Error for BudgetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_cpu_tracking() {
        let mut budget = SorobanBudget::new(ResourceLimits {
            cpu_instructions: 1000,
            ..Default::default()
        });

        assert!(budget.charge_cpu(500).is_ok());
        assert_eq!(budget.cpu_used, 500);
        assert_eq!(budget.remaining_cpu(), 500);

        assert!(budget.charge_cpu(500).is_ok());
        assert_eq!(budget.cpu_used, 1000);

        assert!(budget.charge_cpu(1).is_err());
    }

    #[test]
    fn test_budget_exhausted() {
        let mut budget = SorobanBudget::new(ResourceLimits {
            cpu_instructions: 100,
            ..Default::default()
        });

        assert!(!budget.is_exhausted());
        let _ = budget.charge_cpu(200);
        assert!(budget.is_exhausted());
    }
}
