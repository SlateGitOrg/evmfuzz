//! Shrinking of failing call sequences.
//!
//! A candidate is accepted when replaying it from genesis still violates the
//! *same* oracle. Passes, repeated until a fixpoint or the execution budget
//! runs out:
//!
//! 1. **Truncate** after the violating call.
//! 2. **Delta debugging** over calls: try deleting chunks of size n/2, n/4,
//!    ..., 1 (ddmin's complement step), keeping every deletion that still fails.
//! 3. **Simplify each call**: lowest sender index, zero value, default warp,
//!    then each argument towards its simplest form — integers by trying 0, 1
//!    and a binary search for the smallest failing magnitude, addresses by
//!    earlier pool entries, booleans to false, byte strings and arrays by
//!    dropping elements.
//!
//! Each accepted candidate is re-truncated at its new violation step, so the
//! result is always a sequence whose *last* call triggers the violation.

use super::exec::{Checks, Executor, Oracle};
use super::sequence::{Call, Sequence, DEFAULT_WARP};
use crate::abi::{AbiType, AbiValue};
use crate::types::Address;
use crate::u256::U256;

/// Shrinking statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShrinkStats {
    /// Sequence executions spent.
    pub executions: usize,
    /// Length before shrinking (after truncation to the failing step).
    pub original_len: usize,
    /// Final length.
    pub final_len: usize,
}

struct Shrinker<'e, 'c> {
    exec: &'e mut Executor<'c>,
    oracle: Oracle,
    budget: usize,
    stats: ShrinkStats,
    pool: Vec<Address>,
}

impl Shrinker<'_, '_> {
    /// Returns the candidate truncated at its violation step if it still fails.
    fn fails(&mut self, cand: &[Call]) -> Option<Sequence> {
        if self.stats.executions >= self.budget || cand.is_empty() {
            return None;
        }
        self.stats.executions += 1;
        let out = self.exec.run(cand, Checks::Only(self.oracle), false, false);
        out.violation.filter(|v| v.oracle == self.oracle).map(|v| cand[..=v.step].to_vec())
    }

    fn remove_chunks(&mut self, seq: &mut Sequence) -> bool {
        let mut changed = false;
        let mut chunk = (seq.len() / 2).max(1);
        loop {
            let mut start = 0;
            while start < seq.len() {
                let end = (start + chunk).min(seq.len());
                let mut cand = seq.clone();
                cand.drain(start..end);
                if let Some(s) = self.fails(&cand) {
                    *seq = s;
                    changed = true;
                } else {
                    start += chunk;
                }
            }
            if chunk == 1 {
                return changed;
            }
            chunk /= 2;
        }
    }

    /// Tries `seq` with call `i` replaced; adopts it if it still fails.
    fn try_call(&mut self, seq: &mut Sequence, i: usize, call: Call) -> bool {
        if seq[i] == call {
            return false;
        }
        let mut cand = seq.clone();
        cand[i] = call;
        self.try_seq(seq, &cand)
    }

    /// Adopts `cand` if it still fails.
    fn try_seq(&mut self, seq: &mut Sequence, cand: &[Call]) -> bool {
        match self.fails(cand) {
            Some(s) => {
                *seq = s;
                true
            }
            None => false,
        }
    }

    /// Finds a small failing value for a quantity currently equal to `cur`:
    /// tries 0 and 1, then binary-searches `[1, cur]` assuming monotonicity
    /// (a non-monotone property just ends the search at `cur`).
    /// `build(seq, x)` returns `seq` with the quantity set to `x`, or `None`
    /// if the quantity does not occur in `seq`. Candidates are always built
    /// from the sequence as it was on entry; the best failing one is adopted.
    fn min_value(&mut self, seq: &mut Sequence, build: &dyn Fn(&Sequence, U256) -> Option<Sequence>, cur: U256) -> bool {
        let original = seq.clone();
        for small in [U256::ZERO, U256::ONE] {
            if small < cur {
                if let Some(s) = build(&original, small).and_then(|c| self.fails(&c)) {
                    *seq = s;
                    return true;
                }
            }
        }
        let mut best = None;
        let (mut lo, mut hi) = (U256::ONE, cur); // 1 is known not to fail, `cur` fails
        while hi > lo && hi.wrapping_sub(lo) > U256::ONE && self.stats.executions < self.budget {
            let mid = lo.wrapping_add(hi.wrapping_sub(lo).shr_bits(1));
            let Some(cand) = build(&original, mid) else { break };
            match self.fails(&cand) {
                Some(s) => {
                    hi = mid;
                    best = Some(s);
                }
                None => lo = mid,
            }
        }
        match best {
            Some(s) => {
                *seq = s;
                true
            }
            None => false,
        }
    }

    /// [`Self::min_value`] for a field of call `i`.
    fn min_uint(&mut self, seq: &mut Sequence, i: usize, set: &dyn Fn(&mut Call, U256), cur: U256) -> bool {
        let build = |s: &Sequence, x: U256| {
            let mut cand = s.clone();
            set(cand.get_mut(i)?, x);
            Some(cand)
        };
        self.min_value(seq, &build, cur)
    }

    /// Shrinks integer values that occur in several arguments *together*,
    /// e.g. an id passed to `configure(id)` and later to `store(id, ...)`,
    /// which per-argument shrinking cannot change one at a time.
    fn shrink_linked(&mut self, seq: &mut Sequence) -> bool {
        let mut counts: Vec<(U256, usize)> = Vec::new();
        for call in seq.iter() {
            for a in &call.args {
                if let AbiValue::Uint(v) = a {
                    match counts.iter_mut().find(|(x, _)| x == v) {
                        Some((_, n)) => *n += 1,
                        None => counts.push((*v, 1)),
                    }
                }
            }
        }
        let mut changed = false;
        for (v, n) in counts {
            if n < 2 || v <= U256::ONE {
                continue;
            }
            let build = |s: &Sequence, x: U256| {
                let mut cand = s.clone();
                let mut hit = false;
                for call in &mut cand {
                    for a in &mut call.args {
                        if *a == AbiValue::Uint(v) {
                            *a = AbiValue::Uint(x);
                            hit = true;
                        }
                    }
                }
                hit.then_some(cand)
            };
            changed |= self.min_value(seq, &build, v);
        }
        changed
    }

    fn simplify_arg(&mut self, seq: &mut Sequence, i: usize, a: usize, ty: &AbiType) -> bool {
        let cur = seq[i].args[a].clone();
        match (ty, cur) {
            (AbiType::Uint(_), AbiValue::Uint(v)) => {
                let set = move |c: &mut Call, x: U256| c.args[a] = AbiValue::Uint(x);
                self.min_uint(seq, i, &set, v)
            }
            (AbiType::Int(_), AbiValue::Int(v)) => {
                let neg = v.is_negative();
                let mag = if neg { v.wrapping_neg() } else { v };
                let set = move |c: &mut Call, x: U256| {
                    c.args[a] = AbiValue::Int(if neg { x.wrapping_neg() } else { x });
                };
                self.min_uint(seq, i, &set, mag)
            }
            (AbiType::Address, AbiValue::Address(addr)) => {
                let pos = self.pool.iter().position(|p| *p == addr).unwrap_or(self.pool.len());
                for p in 0..pos {
                    let mut c = seq[i].clone();
                    c.args[a] = AbiValue::Address(self.pool[p]);
                    if self.try_call(seq, i, c) {
                        return true;
                    }
                }
                false
            }
            (AbiType::Bool, AbiValue::Bool(true)) => {
                let mut c = seq[i].clone();
                c.args[a] = AbiValue::Bool(false);
                self.try_call(seq, i, c)
            }
            (AbiType::Bytes, AbiValue::Bytes(b)) if !b.is_empty() => {
                let mut changed = false;
                for len in [0, b.len() / 2] {
                    let mut c = seq[i].clone();
                    c.args[a] = AbiValue::Bytes(b[..len].to_vec());
                    if self.try_call(seq, i, c) {
                        changed = true;
                        break;
                    }
                }
                changed
            }
            (AbiType::String, AbiValue::String(s)) if !s.is_empty() => {
                let mut c = seq[i].clone();
                c.args[a] = AbiValue::String(String::new());
                self.try_call(seq, i, c)
            }
            (AbiType::Array(_), AbiValue::Array(items)) if !items.is_empty() => {
                let mut changed = false;
                for k in (0..items.len()).rev() {
                    if i >= seq.len() {
                        break;
                    }
                    let AbiValue::Array(cur) = &seq[i].args[a] else { break };
                    if k >= cur.len() {
                        continue;
                    }
                    let mut fewer = cur.clone();
                    fewer.remove(k);
                    let mut c = seq[i].clone();
                    c.args[a] = AbiValue::Array(fewer);
                    changed |= self.try_call(seq, i, c);
                }
                changed
            }
            _ => false,
        }
    }

    fn simplify_calls(&mut self, seq: &mut Sequence) -> bool {
        let mut changed = false;
        let mut i = 0;
        while i < seq.len() {
            for s in 0..seq[i].sender {
                let mut c = seq[i].clone();
                c.sender = s;
                if self.try_call(seq, i, c) {
                    changed = true;
                    break;
                }
            }
            if i < seq.len() && seq[i].warp != DEFAULT_WARP {
                let mut c = seq[i].clone();
                c.warp = DEFAULT_WARP;
                changed |= self.try_call(seq, i, c);
            }
            if i < seq.len() && !seq[i].value.is_zero() {
                let v = seq[i].value;
                changed |= self.min_uint(seq, i, &|c: &mut Call, x| c.value = x, v);
            }
            if i < seq.len() {
                let types = self.exec.campaign.targets[seq[i].target].func.inputs.clone();
                for (a, ty) in types.iter().enumerate() {
                    if i >= seq.len() || seq[i].args.len() != types.len() {
                        break;
                    }
                    changed |= self.simplify_arg(seq, i, a, ty);
                }
            }
            i += 1;
        }
        changed
    }
}

/// Shrinks `seq`, which must violate `oracle` when replayed. Spends at most
/// `budget` executions. Returns the shrunk sequence and statistics.
pub fn shrink(exec: &mut Executor<'_>, seq: &[Call], oracle: Oracle, budget: usize) -> (Sequence, ShrinkStats) {
    let pool = exec.campaign.names.pool();
    let mut sh = Shrinker { exec, oracle, budget, stats: ShrinkStats::default(), pool };
    let Some(mut best) = sh.fails(seq) else {
        // Not reproducible (should not happen: execution is deterministic).
        let n = seq.len();
        return (seq.to_vec(), ShrinkStats { executions: sh.stats.executions, original_len: n, final_len: n });
    };
    sh.stats.original_len = best.len();
    for _ in 0..8 {
        let a = sh.remove_chunks(&mut best);
        let b = sh.simplify_calls(&mut best);
        let l = sh.shrink_linked(&mut best);
        if !(a || b || l) || sh.stats.executions >= sh.budget {
            break;
        }
    }
    sh.stats.final_len = best.len();
    (best, sh.stats)
}
