//! Soroban resource budget tracking.
//!
//! Tracks CPU instructions and memory usage for contract execution.

use stellar_xdr::curr::ContractCostParams;

/// Soroban network configuration for contract execution.
///
/// This contains the cost parameters and limits loaded from the network's
/// ConfigSettingEntry entries. These must match the network to produce
/// correct transaction results and ledger hashes.
#[derive(Debug, Clone)]
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
    /// Fee configuration for resource fee computation.
    pub fee_config: FeeConfiguration,
    /// Rent fee configuration for TTL extension fees.
    pub rent_fee_config: RentFeeConfiguration,
}

/// Fee configuration for Soroban resource fee computation.
///
/// These values come from ConfigSettingEntry settings in the ledger.
#[derive(Debug, Clone, Default)]
pub struct FeeConfiguration {
    /// Fee per 10,000 instructions.
    pub fee_per_instruction_increment: i64,
    /// Fee per ledger entry read.
    pub fee_per_read_entry: i64,
    /// Fee per ledger entry written.
    pub fee_per_write_entry: i64,
    /// Fee per 1KB read from ledger.
    pub fee_per_read_1kb: i64,
    /// Fee per 1KB written to ledger.
    pub fee_per_write_1kb: i64,
    /// Fee per 1KB of historical storage.
    pub fee_per_historical_1kb: i64,
    /// Fee per 1KB of contract events.
    pub fee_per_contract_event_1kb: i64,
    /// Fee per 1KB of transaction size (bandwidth).
    pub fee_per_tx_size_1kb: i64,
}

/// Rent fee configuration for TTL extension fees.
#[derive(Debug, Clone)]
pub struct RentFeeConfiguration {
    /// Fee per 1KB written to ledger (same as write fee).
    pub fee_per_write_1kb: i64,
    /// Fee per 1KB of rented ledger space (computed from state size).
    pub fee_per_rent_1kb: i64,
    /// Fee per entry written.
    pub fee_per_write_entry: i64,
    /// Rent rate denominator for persistent storage.
    pub persistent_rent_rate_denominator: i64,
    /// Rent rate denominator for temporary storage.
    pub temporary_rent_rate_denominator: i64,
}

impl Default for RentFeeConfiguration {
    fn default() -> Self {
        Self {
            fee_per_write_1kb: 10000,
            fee_per_rent_1kb: 1000,
            fee_per_write_entry: 10000,
            persistent_rent_rate_denominator: 2103840,  // ~1 year in ledgers
            temporary_rent_rate_denominator: 4607,      // ~6.4 hours in ledgers
        }
    }
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
        }
    }
}

/// Constants for fee computation.
const INSTRUCTIONS_INCREMENT: i64 = 10000;
const DATA_SIZE_1KB_INCREMENT: i64 = 1024;
const TX_BASE_RESULT_SIZE: u32 = 300;

impl SorobanConfig {
    /// Check if this config has valid cost parameters.
    ///
    /// Returns false if the cost params are empty (default/placeholder values).
    pub fn has_valid_cost_params(&self) -> bool {
        !self.cpu_cost_params.0.is_empty() && !self.mem_cost_params.0.is_empty()
    }

    /// Compute the resource fee for a Soroban transaction.
    ///
    /// Returns `(non_refundable_fee, refundable_fee)`.
    /// - non_refundable_fee: instruction, entry, byte, historical, bandwidth fees
    /// - refundable_fee: event fees only (rent is computed separately)
    pub fn compute_resource_fee(
        &self,
        instructions: u32,
        read_entries: u32,
        write_entries: u32,
        read_bytes: u32,
        write_bytes: u32,
        tx_size: u32,
        events_size: u32,
    ) -> (i64, i64) {
        // Instruction fee
        let compute_fee = compute_fee_per_increment(
            instructions,
            self.fee_config.fee_per_instruction_increment,
            INSTRUCTIONS_INCREMENT,
        );

        // Entry fees
        let read_entry_fee = self.fee_config.fee_per_read_entry
            .saturating_mul(read_entries as i64);
        let write_entry_fee = self.fee_config.fee_per_write_entry
            .saturating_mul(write_entries as i64);

        // Byte fees
        let read_bytes_fee = compute_fee_per_increment(
            read_bytes,
            self.fee_config.fee_per_read_1kb,
            DATA_SIZE_1KB_INCREMENT,
        );
        let write_bytes_fee = compute_fee_per_increment(
            write_bytes,
            self.fee_config.fee_per_write_1kb,
            DATA_SIZE_1KB_INCREMENT,
        );

        // Historical fee
        let historical_fee = compute_fee_per_increment(
            tx_size.saturating_add(TX_BASE_RESULT_SIZE),
            self.fee_config.fee_per_historical_1kb,
            DATA_SIZE_1KB_INCREMENT,
        );

        // Bandwidth fee
        let bandwidth_fee = compute_fee_per_increment(
            tx_size,
            self.fee_config.fee_per_tx_size_1kb,
            DATA_SIZE_1KB_INCREMENT,
        );

        // Events fee (refundable)
        let events_fee = compute_fee_per_increment(
            events_size,
            self.fee_config.fee_per_contract_event_1kb,
            DATA_SIZE_1KB_INCREMENT,
        );

        let non_refundable = compute_fee
            .saturating_add(read_entry_fee)
            .saturating_add(write_entry_fee)
            .saturating_add(read_bytes_fee)
            .saturating_add(write_bytes_fee)
            .saturating_add(historical_fee)
            .saturating_add(bandwidth_fee);

        (non_refundable, events_fee)
    }

    /// Compute the fee charged for a Soroban transaction after execution.
    ///
    /// This computes the actual fee based on:
    /// - Declared resource fee
    /// - Non-refundable portion (from declared resources)
    /// - Actual event size (for refundable fees)
    /// - Inclusion fee
    ///
    /// The approach is:
    /// 1. Compute non_refundable_fee from declared resources
    /// 2. max_refundable = declared_resource_fee - non_refundable_fee
    /// 3. Compute actual_refundable from actual events size
    /// 4. refund = max_refundable - actual_refundable
    /// 5. fee_charged = declared_resource_fee - refund + inclusion_fee
    ///
    /// Returns the total fee to be charged.
    pub fn compute_fee_charged(
        &self,
        declared_resource_fee: i64,
        inclusion_fee: i64,
        instructions: u32,
        read_entries: u32,
        write_entries: u32,
        read_bytes: u32,
        write_bytes: u32,
        tx_size: u32,
        actual_events_size: u32,
    ) -> i64 {
        // Compute non-refundable fee from declared resources (events_size = 0 to get just non-refundable)
        let (non_refundable, _) = self.compute_resource_fee(
            instructions,
            read_entries,
            write_entries,
            read_bytes,
            write_bytes,
            tx_size,
            0, // We don't use declared events here
        );

        // The max refundable is what's left after non-refundable from declared
        let max_refundable = declared_resource_fee.saturating_sub(non_refundable).max(0);

        // Compute actual refundable fee (events)
        let actual_events_fee = compute_fee_per_increment(
            actual_events_size,
            self.fee_config.fee_per_contract_event_1kb,
            DATA_SIZE_1KB_INCREMENT,
        );

        // Actual consumed refundable (events fee only for now, rent TBD)
        let actual_consumed_refundable = actual_events_fee;

        // Refund is unused refundable (capped at max)
        let refund = max_refundable.saturating_sub(actual_consumed_refundable).max(0);

        // Fee charged = declared - refund + inclusion
        // But we need to cap the fee at the originally charged amount
        let fee = declared_resource_fee
            .saturating_sub(refund)
            .saturating_add(inclusion_fee);

        fee
    }
}

/// Compute fee for a resource using the increment-based formula.
fn compute_fee_per_increment(resource: u32, fee_per_increment: i64, increment: i64) -> i64 {
    // Round up: (resource + increment - 1) / increment * fee
    let increments = (resource as i64).saturating_add(increment - 1) / increment;
    increments.saturating_mul(fee_per_increment)
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
