//! Coverage and comparison feedback.
//!
//! [`CoverageTracer`] plugs into the interpreter's [`Tracer`] hooks:
//!
//! * every `JUMPI` direction `(code, pc, taken)` is hashed into a 64 KiB
//!   AFL-style map; per-transaction hit counts are bucketed (1, 2, 3, 4-7,
//!   8-15, 16-31, 32-127, 128+) and a transaction is *interesting* when it
//!   sets a bucket bit never seen before (so loops that run more often count
//!   as progress too);
//! * operands of `EQ`/`LT`/`GT`/`SLT`/`SGT` are logged so the fuzzer can add
//!   them to its value dictionary (comparison feedback, as in AFL++ cmplog).
//!
//! Per-transaction cost is O(distinct edges touched): only touched map slots
//! are visited when committing, never the whole map.

use crate::evm::Tracer;
use crate::fxhash::FxHashSet;
use crate::u256::U256;

/// Number of slots in the coverage map.
pub const MAP_SIZE: usize = 1 << 16;

/// Maximum comparison operands logged per transaction.
const CMP_LOG_CAP: usize = 256;

/// A `JUMPI` direction: `(code id, pc, taken)`.
pub type Edge = (u64, u32, bool);

/// Coverage and comparison-logging tracer.
#[derive(Debug, Clone)]
pub struct CoverageTracer {
    /// When false, hooks do nothing (deployment, invariant evaluation, shrinking).
    pub enabled: bool,
    hits: Vec<u8>,
    touched: Vec<(u32, Edge)>,
    virgin: Vec<u8>,
    edges: FxHashSet<Edge>,
    cmp_log: Vec<U256>,
}

impl Default for CoverageTracer {
    fn default() -> Self {
        CoverageTracer {
            enabled: true,
            hits: vec![0; MAP_SIZE],
            touched: Vec::new(),
            virgin: vec![0; MAP_SIZE],
            edges: FxHashSet::default(),
            cmp_log: Vec::new(),
        }
    }
}

#[inline]
fn slot(code_id: u64, pc: usize, taken: bool) -> u32 {
    let h = (code_id ^ (pc as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ u64::from(taken))
        .wrapping_mul(0xff51_afd7_ed55_8ccd);
    (h >> 48) as u32
}

/// AFL hit-count bucket as a single bit.
#[inline]
fn bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

impl CoverageTracer {
    /// Folds the current transaction's hits into the global map. Returns true
    /// if a new edge or hit-count bucket was seen.
    pub fn commit(&mut self) -> bool {
        let mut new = false;
        for (idx, edge) in self.touched.drain(..) {
            let i = idx as usize;
            let b = bucket(self.hits[i]);
            self.hits[i] = 0;
            if self.virgin[i] & b == 0 {
                self.virgin[i] |= b;
                new = true;
            }
            self.edges.insert(edge);
        }
        new
    }

    /// Discards uncommitted hits (used when feedback is disabled mid-transaction).
    pub fn discard(&mut self) {
        for (idx, _) in self.touched.drain(..) {
            self.hits[idx as usize] = 0;
        }
        self.cmp_log.clear();
    }

    /// Takes the comparison operands logged since the last call.
    pub fn take_cmp_log(&mut self) -> Vec<U256> {
        std::mem::take(&mut self.cmp_log)
    }

    /// Distinct `JUMPI` directions observed so far.
    pub fn edges(&self) -> &FxHashSet<Edge> {
        &self.edges
    }

    /// Number of map slots with at least one bucket bit set.
    pub fn map_density(&self) -> usize {
        self.virgin.iter().filter(|&&b| b != 0).count()
    }
}

impl Tracer for CoverageTracer {
    #[inline]
    fn branch(&mut self, code_id: u64, pc: usize, _dest: usize, taken: bool) {
        if !self.enabled {
            return;
        }
        let idx = slot(code_id, pc, taken);
        let h = &mut self.hits[idx as usize];
        if *h == 0 {
            self.touched.push((idx, (code_id, pc as u32, taken)));
        }
        *h = h.saturating_add(1);
    }

    #[inline]
    fn compare(&mut self, a: U256, b: U256) {
        if self.enabled && self.cmp_log.len() < CMP_LOG_CAP {
            self.cmp_log.push(a);
            self.cmp_log.push(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buckets_are_reported_once() {
        let mut t = CoverageTracer::default();
        t.branch(1, 10, 0, true);
        assert!(t.commit());
        t.branch(1, 10, 0, true);
        assert!(!t.commit(), "same edge, same bucket");
        for _ in 0..5 {
            t.branch(1, 10, 0, true);
        }
        assert!(t.commit(), "hit count moved to the 4-7 bucket");
        t.branch(1, 10, 0, false);
        assert!(t.commit(), "other direction is a new edge");
        assert_eq!(t.edges().len(), 2);
        assert_eq!(t.map_density(), 2);
    }

    #[test]
    fn disabled_tracer_records_nothing_and_cmp_log_is_capped() {
        let mut t = CoverageTracer { enabled: false, ..CoverageTracer::default() };
        t.branch(1, 1, 0, true);
        t.compare(U256::ONE, U256::ZERO);
        assert!(!t.commit());
        assert!(t.take_cmp_log().is_empty());
        t.enabled = true;
        for i in 0..1000 {
            t.compare(U256::from_u64(i), U256::ZERO);
        }
        assert_eq!(t.take_cmp_log().len(), CMP_LOG_CAP);
        t.branch(2, 2, 0, true);
        t.compare(U256::ONE, U256::ONE);
        t.discard();
        assert!(!t.commit());
        assert!(t.take_cmp_log().is_empty());
    }

    #[test]
    fn bucket_boundaries() {
        let got: Vec<u8> = [0u8, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 127, 128, 255].iter().map(|&c| bucket(c)).collect();
        assert_eq!(got, vec![0, 1, 2, 4, 8, 8, 16, 16, 32, 32, 64, 64, 128, 128]);
    }
}
