//! Surge pricing lane configuration and priority queue helpers.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use stellar_core_common::{
    any_greater, subtract_non_negative, Resource, NUM_CLASSIC_TX_BYTES_RESOURCES,
};
use stellar_core_common::NUM_CLASSIC_TX_RESOURCES;
use stellar_core_tx::TransactionFrame;

use crate::tx_queue::{fee_rate_cmp, QueuedTransaction};

pub(crate) const GENERIC_LANE: usize = 0;
pub(crate) const DEX_LANE: usize = 1;

pub(crate) trait SurgePricingLaneConfig {
    fn get_lane(&self, frame: &TransactionFrame) -> usize;
    fn lane_limits(&self) -> &[Resource];
    #[allow(dead_code)]
    fn update_generic_lane_limit(&mut self, limit: Resource);
    fn tx_resources(&self, frame: &TransactionFrame, ledger_version: u32) -> Resource;
}

pub(crate) struct DexLimitingLaneConfig {
    lane_limits: Vec<Resource>,
    use_byte_limit: bool,
}

impl DexLimitingLaneConfig {
    pub(crate) fn new(limit: Resource, dex_limit: Option<Resource>) -> Self {
        let use_byte_limit = limit.size() == NUM_CLASSIC_TX_BYTES_RESOURCES;
        let mut lane_limits = vec![limit];
        if let Some(limit) = dex_limit {
            lane_limits.push(limit);
        }
        Self {
            lane_limits,
            use_byte_limit,
        }
    }
}

impl SurgePricingLaneConfig for DexLimitingLaneConfig {
    fn get_lane(&self, frame: &TransactionFrame) -> usize {
        if self.lane_limits.len() > DEX_LANE && frame.has_dex_operations() {
            DEX_LANE
        } else {
            GENERIC_LANE
        }
    }

    fn lane_limits(&self) -> &[Resource] {
        &self.lane_limits
    }

    fn update_generic_lane_limit(&mut self, limit: Resource) {
        self.lane_limits[GENERIC_LANE] = limit;
    }

    fn tx_resources(&self, frame: &TransactionFrame, ledger_version: u32) -> Resource {
        frame.resources(self.use_byte_limit, ledger_version)
    }
}

pub(crate) struct SorobanGenericLaneConfig {
    lane_limits: Vec<Resource>,
}

impl SorobanGenericLaneConfig {
    pub(crate) fn new(limit: Resource) -> Self {
        Self {
            lane_limits: vec![limit],
        }
    }
}

impl SurgePricingLaneConfig for SorobanGenericLaneConfig {
    fn get_lane(&self, frame: &TransactionFrame) -> usize {
        if !frame.is_soroban() {
            panic!("non-soroban tx in soroban lane config");
        }
        GENERIC_LANE
    }

    fn lane_limits(&self) -> &[Resource] {
        &self.lane_limits
    }

    fn update_generic_lane_limit(&mut self, limit: Resource) {
        self.lane_limits[GENERIC_LANE] = limit;
    }

    fn tx_resources(&self, frame: &TransactionFrame, ledger_version: u32) -> Resource {
        frame.resources(false, ledger_version)
    }
}

pub(crate) struct OpsOnlyLaneConfig {
    lane_limits: Vec<Resource>,
}

impl OpsOnlyLaneConfig {
    pub(crate) fn new(limit: Resource) -> Self {
        Self {
            lane_limits: vec![limit],
        }
    }
}

impl SurgePricingLaneConfig for OpsOnlyLaneConfig {
    fn get_lane(&self, _frame: &TransactionFrame) -> usize {
        GENERIC_LANE
    }

    fn lane_limits(&self) -> &[Resource] {
        &self.lane_limits
    }

    fn update_generic_lane_limit(&mut self, limit: Resource) {
        self.lane_limits[GENERIC_LANE] = limit;
    }

    fn tx_resources(&self, frame: &TransactionFrame, _ledger_version: u32) -> Resource {
        let ops = i64::try_from(frame.operation_count()).unwrap_or(i64::MAX);
        Resource::new(vec![ops])
    }
}

#[derive(Clone)]
pub(crate) struct QueueEntry {
    total_fee: u64,
    op_count: u32,
    tie_breaker: [u8; 32],
    hash: [u8; 32],
    pub(crate) tx: QueuedTransaction,
}

impl QueueEntry {
    fn new(tx: QueuedTransaction, seed: u64) -> Self {
        let mut tie_breaker = tx.hash.0;
        if seed != 0 {
            let mut seed_bytes = seed.to_be_bytes();
            for (idx, byte) in seed_bytes.iter_mut().enumerate() {
                tie_breaker[idx] ^= *byte;
            }
        }
        Self {
            total_fee: tx.total_fee,
            op_count: tx.op_count,
            tie_breaker,
            hash: tx.hash.0,
            tx,
        }
    }
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for QueueEntry {}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let ord = fee_rate_cmp(self.total_fee, self.op_count, other.total_fee, other.op_count);
        if ord != Ordering::Equal {
            return ord;
        }
        other
            .tie_breaker
            .cmp(&self.tie_breaker)
            .then_with(|| other.hash.cmp(&self.hash))
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VisitTxResult {
    Skipped,
    Rejected,
    Processed,
}

pub(crate) struct SurgePricingPriorityQueue {
    lane_config: Box<dyn SurgePricingLaneConfig>,
    lane_limits: Vec<Resource>,
    lane_current_count: Vec<Resource>,
    lanes: Vec<BTreeSet<QueueEntry>>,
    seed: u64,
}

#[allow(dead_code)]
impl SurgePricingPriorityQueue {
    pub(crate) fn new(
        lane_config: Box<dyn SurgePricingLaneConfig>,
        seed: u64,
    ) -> Self {
        let lane_limits = lane_config.lane_limits().to_vec();
        let resource_len = lane_limits
            .get(0)
            .map(|limit| limit.size())
            .unwrap_or(NUM_CLASSIC_TX_RESOURCES);
        let lane_current_count = lane_limits
            .iter()
            .map(|_| Resource::make_empty(resource_len))
            .collect();
        let lanes = lane_limits.iter().map(|_| BTreeSet::new()).collect();
        Self {
            lane_config,
            lane_limits,
            lane_current_count,
            lanes,
            seed,
        }
    }

    pub(crate) fn get_num_lanes(&self) -> usize {
        self.lane_limits.len()
    }

    pub(crate) fn lane_limits(&self, lane: usize) -> Resource {
        self.lane_limits[lane].clone()
    }

    pub(crate) fn total_resources(&self) -> Resource {
        self.lane_current_count
            .iter()
            .fold(Resource::make_empty(self.lane_limits[0].size()), |acc, r| acc + r.clone())
    }

    pub(crate) fn lane_resources(&self, lane: usize) -> Resource {
        self.lane_current_count[lane].clone()
    }

    pub(crate) fn count_txs_resources(
        &self,
        txs: &[QueuedTransaction],
        network_id: &stellar_core_common::NetworkId,
        ledger_version: u32,
    ) -> Vec<Resource> {
        let mut lane_resources = vec![
            Resource::make_empty(self.lane_limits[0].size());
            self.lane_limits.len()
        ];
        for tx in txs {
            let frame = TransactionFrame::with_network(tx.envelope.clone(), *network_id);
            let lane = self.lane_config.get_lane(&frame);
            lane_resources[lane] += self.lane_config.tx_resources(&frame, ledger_version);
        }
        lane_resources
    }

    pub(crate) fn add(
        &mut self,
        tx: QueuedTransaction,
        network_id: &stellar_core_common::NetworkId,
        ledger_version: u32,
    ) {
        let frame = TransactionFrame::with_network(tx.envelope.clone(), *network_id);
        let lane = self.lane_config.get_lane(&frame);
        let inserted = self
            .lanes
            .get_mut(lane)
            .expect("lane")
            .insert(QueueEntry::new(tx.clone(), self.seed));
        if inserted {
            let resources = self.lane_config.tx_resources(&frame, ledger_version);
            self.lane_current_count[lane] += resources;
        }
    }

    pub(crate) fn lane_for_tx(
        &self,
        frame: &TransactionFrame,
    ) -> usize {
        self.lane_config.get_lane(frame)
    }

    pub(crate) fn tx_resources(
        &self,
        frame: &TransactionFrame,
        ledger_version: u32,
    ) -> Resource {
        self.lane_config.tx_resources(frame, ledger_version)
    }

    fn erase(&mut self, lane: usize, entry: &QueueEntry, ledger_version: u32, network_id: &stellar_core_common::NetworkId) {
        if self.lanes[lane].remove(entry) {
            let frame = TransactionFrame::with_network(entry.tx.envelope.clone(), *network_id);
            let resources = self.lane_config.tx_resources(&frame, ledger_version);
            self.lane_current_count[lane] -= resources;
        }
    }

    fn top_entry(&self, lane: usize) -> Option<QueueEntry> {
        self.lanes[lane].iter().next_back().cloned()
    }

    pub(crate) fn peek_top(&self) -> Option<(usize, QueueEntry)> {
        let mut best: Option<(usize, QueueEntry)> = None;
        for lane in 0..self.lane_limits.len() {
            let Some(entry) = self.top_entry(lane) else {
                continue;
            };
            match &best {
                None => best = Some((lane, entry)),
                Some((_, best_entry)) => {
                    if entry > *best_entry {
                        best = Some((lane, entry));
                    }
                }
            }
        }
        best
    }

    pub(crate) fn remove_entry(
        &mut self,
        lane: usize,
        entry: &QueueEntry,
        ledger_version: u32,
        network_id: &stellar_core_common::NetworkId,
    ) {
        self.erase(lane, entry, ledger_version, network_id);
    }

    pub(crate) fn pop_top_txs(
        &mut self,
        allow_gaps: bool,
        network_id: &stellar_core_common::NetworkId,
        ledger_version: u32,
        mut visitor: impl FnMut(&QueuedTransaction) -> VisitTxResult,
        lane_left_until_limit: &mut Vec<Resource>,
        had_tx_not_fitting_lane: &mut Vec<bool>,
    ) {
        let limits = self.lane_limits.clone();
        *lane_left_until_limit = limits;
        had_tx_not_fitting_lane.clear();
        had_tx_not_fitting_lane.resize(self.lane_limits.len(), false);
        let mut lane_active = vec![true; self.lane_limits.len()];

        loop {
            let mut best: Option<(usize, QueueEntry)> = None;
            for lane in 0..self.lane_limits.len() {
                if !lane_active[lane] {
                    continue;
                }
                let Some(entry) = self.top_entry(lane) else {
                    continue;
                };
                match &best {
                    None => best = Some((lane, entry)),
                    Some((_, best_entry)) => {
                        if entry > *best_entry {
                            best = Some((lane, entry));
                        }
                    }
                }
            }

            let Some((lane, entry)) = best else {
                break;
            };

            let frame = TransactionFrame::with_network(entry.tx.envelope.clone(), *network_id);
            let resources = self.lane_config.tx_resources(&frame, ledger_version);
            let exceeds_lane = any_greater(&resources, &lane_left_until_limit[lane]);
            let exceeds_generic = any_greater(&resources, &lane_left_until_limit[GENERIC_LANE]);

            if exceeds_lane || exceeds_generic {
                if allow_gaps {
                    if exceeds_lane {
                        had_tx_not_fitting_lane[lane] = true;
                    } else {
                        had_tx_not_fitting_lane[GENERIC_LANE] = true;
                    }
                    self.erase(lane, &entry, ledger_version, network_id);
                    continue;
                } else if lane != GENERIC_LANE && exceeds_lane {
                    lane_active[lane] = false;
                    continue;
                } else {
                    break;
                }
            }

            let visit_res = visitor(&entry.tx);
            if visit_res == VisitTxResult::Processed {
                lane_left_until_limit[GENERIC_LANE] -= resources.clone();
                if lane != GENERIC_LANE {
                    lane_left_until_limit[lane] -= resources;
                }
            } else if visit_res == VisitTxResult::Rejected {
                had_tx_not_fitting_lane[GENERIC_LANE] = true;
                had_tx_not_fitting_lane[lane] = true;
            }
            self.erase(lane, &entry, ledger_version, network_id);
        }
    }

    pub(crate) fn get_most_top_txs_within_limits(
        mut self,
        txs: Vec<QueuedTransaction>,
        network_id: &stellar_core_common::NetworkId,
        ledger_version: u32,
        had_tx_not_fitting_lane: &mut Vec<bool>,
    ) -> Vec<QueuedTransaction> {
        let lane_resources = self.count_txs_resources(&txs, network_id, ledger_version);
        let mut total_resources = Resource::make_empty(self.lane_limits[0].size());
        let mut all_fit = true;
        for (lane, res) in lane_resources.iter().enumerate() {
            if any_greater(res, &self.lane_limits[lane]) {
                all_fit = false;
                break;
            }
            total_resources += res.clone();
            if any_greater(&total_resources, &self.lane_limits[GENERIC_LANE]) {
                all_fit = false;
                break;
            }
        }

        if all_fit {
            had_tx_not_fitting_lane.clear();
            had_tx_not_fitting_lane.resize(self.lane_limits.len(), false);
        }

        for tx in txs {
            self.add(tx, network_id, ledger_version);
        }
        let mut out = Vec::new();
        let mut lane_left = Vec::new();
        self.pop_top_txs(
            true,
            network_id,
            ledger_version,
            |tx| {
                out.push(tx.clone());
                VisitTxResult::Processed
            },
            &mut lane_left,
            had_tx_not_fitting_lane,
        );
        out
    }

    pub(crate) fn can_fit_with_eviction(
        &self,
        tx: &QueuedTransaction,
        tx_discount: Option<Resource>,
        network_id: &stellar_core_common::NetworkId,
        ledger_version: u32,
    ) -> Option<Vec<(QueuedTransaction, bool)>> {
        let frame = TransactionFrame::with_network(tx.envelope.clone(), *network_id);
        let lane = self.lane_config.get_lane(&frame);
        let mut tx_resources = self.lane_config.tx_resources(&frame, ledger_version);
        if let Some(discount) = tx_discount {
            tx_resources = subtract_non_negative(&tx_resources, &discount);
        }

        if any_greater(&tx_resources, &self.lane_limits[GENERIC_LANE])
            || any_greater(&tx_resources, &self.lane_limits[lane])
        {
            return None;
        }

        if !self.total_resources().can_add(&tx_resources)
            || !self.lane_current_count[lane].can_add(&tx_resources)
        {
            return None;
        }

        let new_total = self.total_resources() + tx_resources.clone();
        let new_lane = self.lane_current_count[lane].clone() + tx_resources.clone();
        if new_total.leq(&self.lane_limits[GENERIC_LANE]) && new_lane.leq(&self.lane_limits[lane]) {
            return Some(Vec::new());
        }

        let mut needed_total =
            subtract_non_negative(&new_total, &self.lane_limits[GENERIC_LANE]);
        let mut needed_lane = subtract_non_negative(&new_lane, &self.lane_limits[lane]);

        #[derive(Clone)]
        struct LaneCursor {
            lane: usize,
            entries: Vec<QueueEntry>,
            index: usize,
            active: bool,
        }

        impl LaneCursor {
            fn current(&self) -> Option<&QueueEntry> {
                if !self.active {
                    return None;
                }
                self.entries.get(self.index)
            }

            fn advance(&mut self) {
                self.index = self.index.saturating_add(1);
                if self.index >= self.entries.len() {
                    self.active = false;
                }
            }

            fn drop_lane(&mut self) {
                self.active = false;
            }
        }

        let mut cursors: Vec<LaneCursor> = self
            .lanes
            .iter()
            .enumerate()
            .map(|(lane, set)| LaneCursor {
                lane,
                entries: set.iter().cloned().collect(),
                index: 0,
                active: !set.is_empty(),
            })
            .collect();

        let mut evictions: Vec<(QueuedTransaction, bool)> = Vec::new();
        let tx_account = tx.account_key();

        while needed_total.any_positive() || needed_lane.any_positive() {
            let mut evicted_due_to_lane_limit = false;
            let (evict_lane, entry) = loop {
                let mut best: Option<(usize, QueueEntry)> = None;
                for cursor in cursors.iter() {
                    if let Some(entry) = cursor.current() {
                        match &best {
                            None => best = Some((cursor.lane, entry.clone())),
                            Some((_, best_entry)) => {
                                if entry < best_entry {
                                    best = Some((cursor.lane, entry.clone()));
                                }
                            }
                        }
                    }
                }

                let Some((evict_lane, entry)) = best else {
                    return None;
                };

                let can_evict = lane == GENERIC_LANE
                    || lane == evict_lane
                    || any_greater(&needed_total, &needed_lane);
                if !can_evict {
                    evicted_due_to_lane_limit = true;
                    if let Some(cursor) = cursors.get_mut(evict_lane) {
                        cursor.drop_lane();
                    }
                    continue;
                }
                break (evict_lane, entry);
            };

            if fee_rate_cmp(
                entry.total_fee,
                entry.op_count,
                tx.total_fee,
                tx.op_count,
            ) != Ordering::Less
            {
                return None;
            }

            if entry.tx.account_key() == tx_account {
                return None;
            }

            let evict_frame =
                TransactionFrame::with_network(entry.tx.envelope.clone(), *network_id);
            let evict_resources = self.lane_config.tx_resources(&evict_frame, ledger_version);
            evictions.push((entry.tx.clone(), evicted_due_to_lane_limit));

            needed_total = subtract_non_negative(&needed_total, &evict_resources);
            if lane == GENERIC_LANE || lane == evict_lane {
                needed_lane = subtract_non_negative(&needed_lane, &evict_resources);
            }

            if let Some(cursor) = cursors.get_mut(evict_lane) {
                cursor.advance();
            }
        }

        Some(evictions)
    }
}
