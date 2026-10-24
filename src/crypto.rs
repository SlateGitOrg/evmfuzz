//! Hash functions: a self-contained Keccak-256 (the pre-NIST padding used by
//! Ethereum) plus thin wrappers over SHA-256 and RIPEMD-160 for precompiles.

use crate::types::B256;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets indexed by lane `x + 5 * y`.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// The Keccak-f[1600] permutation.
fn keccak_f(a: &mut [u64; 25]) {
    for rc in ROUND_CONSTANTS {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho + pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let idx = x + 5 * y;
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[idx].rotate_left(RHO[idx]);
            }
        }
        // chi
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        a[0] ^= rc;
    }
}

/// Keccak-256 as used by Ethereum (`0x01` domain padding, not SHA3-256).
pub fn keccak256(data: &[u8]) -> B256 {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let absorb = |state: &mut [u64; 25], block: &[u8]| {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let mut lane = [0u8; 8];
            lane.copy_from_slice(chunk);
            state[i] ^= u64::from_le_bytes(lane);
        }
        keccak_f(state);
    };
    let mut chunks = data.chunks_exact(RATE);
    for block in &mut chunks {
        absorb(&mut state, block);
    }
    let rest = chunks.remainder();
    let mut last = [0u8; RATE];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    absorb(&mut state, &last);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    B256(out)
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

/// RIPEMD-160 digest.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    use ripemd::Digest;
    ripemd::Ripemd160::digest(data).into()
}

/// `keccak256("")`, the code hash of accounts without code.
pub const EMPTY_CODE_HASH: B256 = B256([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5,
    0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_known_vectors() {
        assert_eq!(keccak256(b""), EMPTY_CODE_HASH);
        assert_eq!(
            keccak256(b"abc").to_string(),
            "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        // Function selector of transfer(address,uint256).
        assert_eq!(&keccak256(b"transfer(address,uint256)").0[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        // Multi-block input (200 bytes crosses the 136-byte rate).
        let long = vec![0x61u8; 200];
        let h1 = keccak256(&long);
        assert_ne!(h1, keccak256(&long[..199]));
        // Event topic of Transfer(address,address,uint256) (a 31-byte input).
        assert_eq!(
            keccak256(b"Transfer(address,address,uint256)").to_string(),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn precompile_hashes() {
        assert_eq!(sha256(b"")[..4], [0xe3, 0xb0, 0xc4, 0x42]);
        assert_eq!(ripemd160(b"")[..4], [0x9c, 0x11, 0x85, 0xa5]);
    }
}
