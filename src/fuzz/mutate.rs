//! Input generation and sequence mutation.
//!
//! Values come from three sources, mixed with fixed probabilities:
//! the *dictionary* (comparison operands seen at runtime plus PUSH constants
//! from the deployed bytecode, each optionally nudged by ±1), *interesting*
//! boundary values for the parameter's width, and uniformly random values
//! whose bit-length is itself uniform (so small numbers are as likely as
//! huge ones). Address parameters only ever receive members of the campaign's
//! address pool, which keeps `sum(a in accounts, ...)` invariants sound.
//!
//! On top of that, *input-to-state* hints (the idea behind Redqueen) are
//! targeted: when a comparison had one operand equal to an argument of the
//! call, the other operand (and its neighbours) becomes a candidate for that
//! specific argument of that specific function.

use super::campaign::Campaign;
use super::sequence::{Call, Sequence, DEFAULT_WARP};
use crate::abi::{sign_extend, width_mask, AbiType, AbiValue};
use crate::fxhash::{FxHashMap, FxHashSet};
use crate::rng::Rng;
use crate::types::Address;
use crate::u256::U256;

/// Values worth trying again: a pinned part (bytecode constants, never
/// evicted) and a bounded runtime part (comparison operands, ring-replaced
/// when full so it tracks recent behaviour).
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    pinned: Vec<U256>,
    values: Vec<U256>,
    seen: FxHashSet<U256>,
    cap: usize,
    next: usize,
}

impl Dictionary {
    /// An empty dictionary keeping at most `cap` runtime values.
    pub fn new(cap: usize) -> Self {
        Dictionary { pinned: Vec::new(), values: Vec::new(), seen: FxHashSet::default(), cap: cap.max(1), next: 0 }
    }

    /// Adds a value that is never evicted; returns true if it was new.
    pub fn pin(&mut self, v: U256) -> bool {
        if !self.seen.insert(v) {
            return false;
        }
        self.pinned.push(v);
        true
    }

    /// Adds a runtime value; returns true if it was new.
    pub fn insert(&mut self, v: U256) -> bool {
        if !self.seen.insert(v) {
            return false;
        }
        if self.values.len() < self.cap {
            self.values.push(v);
        } else {
            let old = std::mem::replace(&mut self.values[self.next], v);
            self.seen.remove(&old);
            self.next = (self.next + 1) % self.cap;
        }
        true
    }

    /// Number of values (pinned plus runtime).
    pub fn len(&self) -> usize {
        self.pinned.len() + self.values.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A random value, if any: pinned and runtime parts are equally likely.
    pub fn pick(&self, rng: &mut Rng) -> Option<U256> {
        match (self.pinned.is_empty(), self.values.is_empty()) {
            (true, true) => None,
            (false, true) => Some(*rng.pick(&self.pinned)),
            (true, false) => Some(*rng.pick(&self.values)),
            (false, false) => Some(if rng.chance(1, 2) { *rng.pick(&self.pinned) } else { *rng.pick(&self.values) }),
        }
    }
}

/// Generates and mutates call sequences.
pub struct Generator<'c> {
    campaign: &'c Campaign,
    pool: Vec<Address>,
    /// Randomness source.
    pub rng: Rng,
    /// Value dictionary (left empty when dictionary feedback is disabled).
    pub dict: Dictionary,
    use_dict: bool,
    max_len: usize,
    /// Per target: calldata head word index -> argument index (single-word static args only).
    word_to_arg: Vec<Vec<Option<usize>>>,
    /// Input-to-state candidates per (target, argument).
    i2s: FxHashMap<(usize, usize), Vec<U256>>,
}

/// Maximum input-to-state candidates kept per argument.
const I2S_CAP: usize = 64;

fn single_word(ty: &AbiType) -> bool {
    matches!(ty, AbiType::Uint(_) | AbiType::Int(_) | AbiType::Address | AbiType::Bool | AbiType::FixedBytes(_))
}

fn head_words(ty: &AbiType) -> usize {
    match ty {
        AbiType::FixedArray(e, k) if !e.is_dynamic() => head_words(e) * k,
        _ => 1,
    }
}

const WARPS: [u64; 6] = [0, 1, 60, 3600, 86_400, 604_800];

impl<'c> Generator<'c> {
    /// A generator for `campaign`.
    pub fn new(campaign: &'c Campaign, seed: u64, use_dict: bool, max_len: usize) -> Self {
        let mut dict = Dictionary::new(1024);
        if use_dict {
            for v in &campaign.constants {
                dict.pin(*v);
            }
        }
        let word_to_arg = campaign
            .targets
            .iter()
            .map(|t| {
                let mut map = Vec::new();
                for (a, ty) in t.func.inputs.iter().enumerate() {
                    if single_word(ty) {
                        map.push(Some(a));
                    } else {
                        map.extend(std::iter::repeat_n(None, head_words(ty)));
                    }
                }
                map
            })
            .collect();
        Generator {
            campaign,
            pool: campaign.names.pool(),
            rng: Rng::new(seed),
            dict,
            use_dict,
            max_len: max_len.max(1),
            word_to_arg,
            i2s: FxHashMap::default(),
        }
    }

    /// Records input-to-state hints `(target, calldata word, value)` from the executor.
    pub fn learn_i2s(&mut self, hints: impl IntoIterator<Item = (usize, usize, U256)>) {
        if !self.use_dict {
            return;
        }
        for (t, w, v) in hints {
            let Some(Some(arg)) = self.word_to_arg.get(t).and_then(|m| m.get(w)) else { continue };
            let ty = &self.campaign.targets[t].func.inputs[*arg];
            if !matches!(ty, AbiType::Uint(_) | AbiType::Int(_)) {
                continue;
            }
            let list = self.i2s.entry((t, *arg)).or_default();
            for cand in [v, v.wrapping_add(U256::ONE), v.wrapping_sub(U256::ONE)] {
                if list.len() < I2S_CAP && !list.contains(&cand) {
                    list.push(cand);
                }
            }
        }
    }

    /// An input-to-state candidate for argument `arg` of `target` that fits its type.
    fn i2s_value(&mut self, target: usize, arg: usize) -> Option<AbiValue> {
        let list = self.i2s.get(&(target, arg))?;
        let v = *self.rng.pick(list);
        match self.campaign.targets[target].func.inputs[arg] {
            AbiType::Uint(bits) => (v <= width_mask(bits)).then_some(AbiValue::Uint(v)),
            AbiType::Int(bits) => {
                let x = sign_extend(v & width_mask(bits), bits);
                (x == v).then_some(AbiValue::Int(x))
            }
            _ => None,
        }
    }

    /// A value for argument `arg` of `target`: an input-to-state candidate a
    /// third of the time when one exists, otherwise a generic value.
    fn arg_value(&mut self, target: usize, arg: usize) -> AbiValue {
        if self.rng.chance(1, 3) {
            if let Some(v) = self.i2s_value(target, arg) {
                return v;
            }
        }
        let ty = self.campaign.targets[target].func.inputs[arg].clone();
        self.value(&ty)
    }

    /// Feeds runtime comparison operands into the dictionary, together with
    /// their neighbours: `x > 1000` is satisfied by 1001, not by 1000.
    pub fn learn(&mut self, values: impl IntoIterator<Item = U256>) {
        if self.use_dict {
            for v in values {
                if self.dict.insert(v) {
                    self.dict.insert(v.wrapping_add(U256::ONE));
                    self.dict.insert(v.wrapping_sub(U256::ONE));
                }
            }
        }
    }

    /// A random unsigned value fitting in `bits` bits.
    fn uint(&mut self, bits: u16) -> U256 {
        let mask = width_mask(bits);
        let roll = self.rng.below(100);
        if self.use_dict && roll < 40 {
            // Prefer dictionary entries that fit the parameter's width.
            let mut picked = self.dict.pick(&mut self.rng);
            for _ in 0..3 {
                match picked {
                    Some(v) if v > mask => picked = self.dict.pick(&mut self.rng),
                    _ => break,
                }
            }
            if let Some(mut v) = picked {
                match self.rng.below(6) {
                    0 => v = v.wrapping_add(U256::ONE),
                    1 => v = v.wrapping_sub(U256::ONE),
                    _ => {}
                }
                return v & mask;
            }
        }
        if roll < 65 {
            return self.interesting(bits);
        }
        let len = self.rng.range(1, bits as usize);
        let mut buf = [0u8; 32];
        self.rng.fill(&mut buf);
        U256::from_be_bytes(buf) & width_mask(len as u16)
    }

    fn interesting(&mut self, bits: u16) -> U256 {
        let mask = width_mask(bits);
        let k = self.rng.below(bits as usize);
        match self.rng.below(8) {
            0 => U256::ZERO,
            1 => U256::from_u64(self.rng.range(1, 16) as u64),
            2 => mask,
            3 => mask.wrapping_sub(U256::from_u64(self.rng.below(4) as u64)),
            4 => U256::ONE.shl_bits(k),
            5 => U256::ONE.shl_bits(k).wrapping_sub(U256::ONE),
            6 => {
                // A power of ten that fits (1e18 style amounts).
                let mut v = U256::ONE;
                let ten = U256::from_u64(10);
                for _ in 0..self.rng.below(78) {
                    match v.checked_mul(ten) {
                        Some(n) if n <= mask => v = n,
                        _ => break,
                    }
                }
                v
            }
            _ => U256::ONE.shl_bits(bits as usize - 1),
        }
    }

    /// A random value of type `ty`.
    pub fn value(&mut self, ty: &AbiType) -> AbiValue {
        match ty {
            AbiType::Uint(bits) => AbiValue::Uint(self.uint(*bits)),
            AbiType::Int(bits) => {
                let raw = self.uint(*bits);
                let v = if self.rng.chance(1, 3) { raw.wrapping_neg() } else { raw };
                AbiValue::Int(sign_extend(v & width_mask(*bits), *bits))
            }
            AbiType::Address => AbiValue::Address(*self.rng.pick(&self.pool)),
            AbiType::Bool => AbiValue::Bool(self.rng.chance(1, 2)),
            AbiType::FixedBytes(n) => {
                let n = *n as usize;
                let mut b = vec![0u8; n];
                match (self.use_dict, self.rng.below(3)) {
                    (true, 0) => {
                        if let Some(v) = self.dict.pick(&mut self.rng) {
                            b.copy_from_slice(&v.to_be_bytes()[..n]);
                        }
                    }
                    (_, 1) => {}
                    _ => self.rng.fill(&mut b),
                }
                AbiValue::FixedBytes(b)
            }
            AbiType::Bytes => {
                let mut b = vec![0u8; self.small_len(96)];
                self.rng.fill(&mut b);
                AbiValue::Bytes(b)
            }
            AbiType::String => {
                let len = self.small_len(32);
                let s: String = (0..len).map(|_| (b'a' + self.rng.below(26) as u8) as char).collect();
                AbiValue::String(s)
            }
            AbiType::Array(e) => {
                let n = self.small_len(4);
                AbiValue::Array((0..n).map(|_| self.value(e)).collect())
            }
            AbiType::FixedArray(e, k) => AbiValue::Array((0..*k).map(|_| self.value(e)).collect()),
        }
    }

    fn small_len(&mut self, max: usize) -> usize {
        // Biased towards short lengths: min of two uniform draws.
        self.rng.below(max + 1).min(self.rng.below(max + 1))
    }

    fn eth_value(&mut self) -> U256 {
        match self.rng.below(4) {
            0 => U256::ZERO,
            1 => U256::from_u64(self.rng.range(1, 1000) as u64),
            2 => U256::from_u64(10u64.pow(self.rng.range(9, 18) as u32)),
            _ => self.uint(72),
        }
    }

    /// A fresh random call.
    pub fn call(&mut self) -> Call {
        let c = self.campaign;
        let target = self.rng.below(c.targets.len());
        let t = &c.targets[target];
        let args = (0..t.func.inputs.len()).map(|a| self.arg_value(target, a)).collect();
        let value = if t.func.payable { self.eth_value() } else { U256::ZERO };
        let warp = if self.rng.chance(1, 10) { *self.rng.pick(&WARPS) } else { DEFAULT_WARP };
        Call { sender: self.rng.below(c.names.actors.len()), target, args, value, warp }
    }

    /// A fresh random sequence of 1..=max_len calls.
    pub fn sequence(&mut self) -> Sequence {
        let n = self.rng.range(1, self.max_len);
        (0..n).map(|_| self.call()).collect()
    }

    /// Mutates a single value in place, keeping its type.
    pub fn mutate_value(&mut self, ty: &AbiType, v: &mut AbiValue) {
        match (ty, &mut *v) {
            (AbiType::Uint(bits), AbiValue::Uint(x)) => {
                let mask = width_mask(*bits);
                *x = match self.rng.below(5) {
                    0 => x.wrapping_add(U256::from_u64(self.rng.range(1, 16) as u64)) & mask,
                    1 => x.wrapping_sub(U256::from_u64(self.rng.range(1, 16) as u64)) & mask,
                    2 => *x ^ (U256::ONE.shl_bits(self.rng.below(*bits as usize)) & mask),
                    _ => self.uint(*bits),
                };
            }
            (AbiType::Array(e), AbiValue::Array(items)) => match self.rng.below(3) {
                0 if !items.is_empty() => {
                    let i = self.rng.below(items.len());
                    items.remove(i);
                }
                1 if items.len() < 8 => items.push(self.value(e)),
                _ if !items.is_empty() => {
                    let i = self.rng.below(items.len());
                    self.mutate_value(e, &mut items[i]);
                }
                _ => items.push(self.value(e)),
            },
            (AbiType::FixedArray(e, _), AbiValue::Array(items)) => {
                let i = self.rng.below(items.len());
                self.mutate_value(e, &mut items[i]);
            }
            _ => *v = self.value(ty),
        }
    }

    /// Applies one to four random mutations to a copy of `seq`.
    /// `other` supplies material for splicing.
    pub fn mutate(&mut self, seq: &[Call], other: Option<&[Call]>) -> Sequence {
        let mut s: Sequence = seq.to_vec();
        let rounds = self.rng.range(1, 4);
        for _ in 0..rounds {
            if s.is_empty() {
                s.push(self.call());
                continue;
            }
            let i = self.rng.below(s.len());
            match self.rng.below(12) {
                0..=2 => {
                    let t = &self.campaign.targets[s[i].target];
                    if t.func.inputs.is_empty() {
                        s[i] = self.call();
                    } else {
                        let a = self.rng.below(t.func.inputs.len());
                        let ty = t.func.inputs[a].clone();
                        let target = s[i].target;
                        match self.rng.chance(1, 3).then(|| self.i2s_value(target, a)).flatten() {
                            Some(v) => s[i].args[a] = v,
                            None => self.mutate_value(&ty, &mut s[i].args[a]),
                        }
                    }
                }
                3 => s[i].sender = self.rng.below(self.campaign.names.actors.len()),
                4 => {
                    if self.campaign.targets[s[i].target].func.payable {
                        s[i].value = self.eth_value();
                    } else {
                        s[i].warp = *self.rng.pick(&WARPS);
                    }
                }
                5 => {
                    let c = self.call();
                    s.insert(self.rng.below(s.len() + 1), c);
                }
                6 if s.len() > 1 => {
                    s.remove(i);
                }
                7 => {
                    let dup = s[i].clone();
                    s.insert(i, dup);
                }
                8 => {
                    let j = self.rng.below(s.len());
                    s.swap(i, j);
                }
                9 | 10 => {
                    // Extend at the end: corpus entries end where they found something new.
                    let c = self.call();
                    s.push(c);
                }
                _ => match other {
                    Some(o) if !o.is_empty() => {
                        let cut = self.rng.below(s.len() + 1);
                        let from = self.rng.below(o.len());
                        s.truncate(cut);
                        s.extend_from_slice(&o[from..]);
                    }
                    _ => s.push(self.call()),
                },
            }
        }
        s.truncate(self.max_len);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_dedups_and_rotates() {
        let mut d = Dictionary::new(2);
        assert!(d.is_empty());
        assert!(d.insert(U256::ONE));
        assert!(!d.insert(U256::ONE));
        assert!(d.insert(U256::from_u64(2)));
        assert!(d.insert(U256::from_u64(3)));
        assert_eq!(d.len(), 2);
        // 1 was evicted, so it is new again.
        assert!(d.insert(U256::ONE));
        let mut rng = Rng::new(1);
        assert!(d.pick(&mut rng).is_some());
        assert!(Dictionary::new(0).pick(&mut rng).is_none());
        // Pinned values survive any number of runtime insertions.
        let mut p = Dictionary::new(1);
        assert!(p.pin(U256::from_u64(42)));
        assert!(!p.pin(U256::from_u64(42)));
        assert!(p.pick(&mut rng) == Some(U256::from_u64(42)));
        for i in 100..200 {
            p.insert(U256::from_u64(i));
        }
        assert_eq!(p.len(), 2);
        assert!((0..64).any(|_| p.pick(&mut rng) == Some(U256::from_u64(42))));
        assert!((0..64).any(|_| p.pick(&mut rng) == Some(U256::from_u64(199))));
    }
}
