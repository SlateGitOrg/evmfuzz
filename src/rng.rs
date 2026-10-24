//! A small, seedable, deterministic PRNG (xoshiro256**, seeded through
//! SplitMix64). Campaigns are reproducible from `(seed, budget)` alone, so the
//! fuzzer must not depend on an RNG whose stream could change across crate
//! versions.

/// xoshiro256** generator.
#[derive(Debug, Clone)]
pub struct Rng {
    s: [u64; 4],
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl Rng {
    /// A generator whose whole stream is determined by `seed`.
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let s = [splitmix64(&mut sm), splitmix64(&mut sm), splitmix64(&mut sm), splitmix64(&mut sm)];
        Rng { s }
    }

    /// Next 64 random bits.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform integer in `0..n` (`n > 0`), using Lemire's multiply-shift.
    #[inline]
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0, "below(0)");
        ((u128::from(self.next_u64()) * n as u128) >> 64) as usize
    }

    /// Uniform integer in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    /// True with probability `num / den`.
    #[inline]
    pub fn chance(&mut self, num: u32, den: u32) -> bool {
        self.below(den as usize) < num as usize
    }

    /// A uniformly chosen element of a non-empty slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Fills `buf` with random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_seed_sensitive() {
        let a: Vec<u64> = (0..4).map({
            let mut r = Rng::new(7);
            move |_| r.next_u64()
        })
        .collect();
        let mut r = Rng::new(7);
        let b: Vec<u64> = (0..4).map(|_| r.next_u64()).collect();
        assert_eq!(a, b);
        assert_ne!(Rng::new(8).next_u64(), a[0]);
    }

    #[test]
    fn bounded_helpers_stay_in_range() {
        let mut r = Rng::new(1);
        let mut seen = [false; 5];
        for _ in 0..1000 {
            let x = r.below(5);
            seen[x] = true;
            let y = r.range(3, 4);
            assert!((3..=4).contains(&y));
        }
        assert!(seen.iter().all(|&s| s));
        assert!(!(0..100).any(|_| r.chance(0, 3)));
        assert!((0..100).all(|_| r.chance(3, 3)));
        let mut buf = [0u8; 13];
        r.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
        assert_eq!(*r.pick(&[9]), 9);
    }
}
