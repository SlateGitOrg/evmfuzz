//! A small non-cryptographic hasher (the "Fx" multiply-rotate hash used by
//! rustc) for the interpreter's hot hash maps. Keys are addresses and storage
//! slots chosen by contract code, so HashDoS is not a concern for an offline
//! fuzzer; speed is.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

/// Fx hasher state.
#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            let mut w = [0u8; 8];
            w.copy_from_slice(c);
            self.add(u64::from_le_bytes(w));
        }
        for &b in chunks.remainder() {
            self.add(u64::from(b));
        }
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// `HashMap` keyed with [`FxHasher`].
pub type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;
/// `HashSet` keyed with [`FxHasher`].
pub type FxHashSet<K> = HashSet<K, BuildHasherDefault<FxHasher>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;

    #[test]
    fn distinct_inputs_hash_differently() {
        let h = |v: &[u8]| {
            let mut s = FxHasher::default();
            v.hash(&mut s);
            s.finish()
        };
        assert_ne!(h(&[1, 2, 3]), h(&[1, 2, 4]));
        let mut m: FxHashMap<u64, u64> = FxHashMap::default();
        m.insert(1, 2);
        assert_eq!(m.get(&1), Some(&2));
    }
}
