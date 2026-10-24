//! Precompiled contracts at addresses `0x01..=0x09`.
//!
//! Implemented exactly: SHA-256 (0x02), RIPEMD-160 (0x03), identity (0x04),
//! and the input-validation path of ECRECOVER (0x01). The elliptic-curve and
//! big-number precompiles (MODEXP, BN254, BLAKE2F) are out of scope: their gas
//! is still charged correctly, and if a call can afford them execution stops
//! with [`Halt::UnsupportedPrecompile`] so callers (the conformance runner,
//! the fuzzer) can report it instead of silently diverging.

use super::gas::words;
use super::Halt;
use crate::crypto::{ripemd160, sha256};
use crate::types::Address;
use crate::u256::U256;

/// Result of running a precompile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileOutput {
    /// Gas consumed.
    pub gas_used: u64,
    /// Returned bytes.
    pub output: Vec<u8>,
}

/// True if `a` is one of the Shanghai precompile addresses.
#[inline]
pub fn is_precompile(a: &Address) -> bool {
    a.0[..19].iter().all(|&b| b == 0) && (1..=9).contains(&a.0[19])
}

/// All Shanghai precompile addresses (warm from the start of every transaction).
pub fn addresses() -> impl Iterator<Item = Address> {
    (1..=9u64).map(Address::from_low_u64)
}

fn linear(base: u64, per_word: u64, input: &[u8]) -> u64 {
    base + per_word * words(input.len() as u64)
}

const SECP256K1_N: U256 = U256([0xBFD2_5E8C_D036_4141, 0xBAAE_DCE6_AF48_A03B, 0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFF]);

fn padded_word(input: &[u8], i: usize) -> U256 {
    let mut buf = [0u8; 32];
    let start = i * 32;
    if start < input.len() {
        let end = (start + 32).min(input.len());
        buf[..end - start].copy_from_slice(&input[start..end]);
    }
    U256::from_be_bytes(buf)
}

/// Runs the precompile at `addr` with `gas` available.
pub fn run(addr: &Address, input: &[u8], gas: u64) -> Result<PrecompileOutput, Halt> {
    let id = addr.0[19];
    let cost = match id {
        1 => 3000,
        2 => linear(60, 12, input),
        3 => linear(600, 120, input),
        4 => linear(15, 3, input),
        5 => 200, // EIP-2565 minimum; the full formula is only needed when supported.
        6 => 150,
        7 => 6000,
        8 => {
            if input.len() % 192 != 0 {
                return Err(Halt::PrecompileFailure);
            }
            45_000 + 34_000 * (input.len() / 192) as u64
        }
        9 => {
            if input.len() != 213 {
                return Err(Halt::PrecompileFailure);
            }
            u64::from(u32::from_be_bytes([input[0], input[1], input[2], input[3]]))
        }
        _ => return Err(Halt::PrecompileFailure),
    };
    if gas < cost {
        return Err(Halt::OutOfGas);
    }
    let output = match id {
        1 => {
            let v = padded_word(input, 1);
            let r = padded_word(input, 2);
            let s = padded_word(input, 3);
            let valid_v = v == U256::from_u64(27) || v == U256::from_u64(28);
            let in_range = |x: U256| !x.is_zero() && x < SECP256K1_N;
            if !valid_v || !in_range(r) || !in_range(s) {
                Vec::new()
            } else {
                return Err(Halt::UnsupportedPrecompile(id));
            }
        }
        2 => sha256(input).to_vec(),
        3 => {
            let mut out = vec![0u8; 12];
            out.extend_from_slice(&ripemd160(input));
            out
        }
        4 => input.to_vec(),
        _ => return Err(Halt::UnsupportedPrecompile(id)),
    };
    Ok(PrecompileOutput { gas_used: cost, output })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pc(n: u64) -> Address {
        Address::from_low_u64(n)
    }

    #[test]
    fn identity_and_hashes() {
        let out = run(&pc(4), &[1, 2, 3], 100).unwrap();
        assert_eq!(out, PrecompileOutput { gas_used: 18, output: vec![1, 2, 3] });
        assert_eq!(run(&pc(2), &[], 60).unwrap().output.len(), 32);
        let r = run(&pc(3), &[], 600).unwrap();
        assert_eq!(r.output.len(), 32);
        assert_eq!(&r.output[..12], &[0u8; 12]);
        assert_eq!(run(&pc(3), &[], 599), Err(Halt::OutOfGas));
    }

    #[test]
    fn ecrecover_rejects_invalid_signatures_without_crypto() {
        let out = run(&pc(1), &[0u8; 128], 3000).unwrap();
        assert!(out.output.is_empty());
        let mut sig = [0u8; 128];
        sig[63] = 27;
        sig[95] = 1;
        sig[127] = 1;
        assert_eq!(run(&pc(1), &sig, 3000), Err(Halt::UnsupportedPrecompile(1)));
    }

    #[test]
    fn unsupported_and_classification() {
        assert!(is_precompile(&pc(9)));
        assert!(!is_precompile(&pc(10)));
        assert!(!is_precompile(&pc(0)));
        assert_eq!(addresses().count(), 9);
        assert_eq!(run(&pc(6), &[], 100), Err(Halt::OutOfGas));
        assert_eq!(run(&pc(6), &[], 150), Err(Halt::UnsupportedPrecompile(6)));
        assert_eq!(run(&pc(8), &[0; 5], 1_000_000), Err(Halt::PrecompileFailure));
        assert_eq!(run(&pc(9), &[0; 5], 1_000_000), Err(Halt::PrecompileFailure));
    }
}
