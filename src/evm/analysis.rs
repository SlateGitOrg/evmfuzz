//! Static bytecode analysis: valid `JUMPDEST` positions (skipping PUSH data).

use super::opcode::{immediate_len, JUMPDEST};
use crate::types::B256;

/// Per-code analysis, cached by code hash.
#[derive(Debug, Clone)]
pub struct Analysis {
    jumpdests: Vec<u64>,
    /// Short identifier of the code (first eight bytes of its hash), used to
    /// key coverage.
    pub code_id: u64,
}

impl Analysis {
    /// Scans `code` once: O(len).
    pub fn new(code: &[u8], hash: B256) -> Self {
        let mut jumpdests = vec![0u64; code.len().div_ceil(64)];
        let mut pc = 0;
        while pc < code.len() {
            let op = code[pc];
            if op == JUMPDEST {
                jumpdests[pc / 64] |= 1 << (pc % 64);
            }
            pc += 1 + immediate_len(op);
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash.0[..8]);
        Analysis { jumpdests, code_id: u64::from_be_bytes(id) }
    }

    /// True if `pc` is a `JUMPDEST` instruction (not inside PUSH data).
    #[inline]
    pub fn is_jumpdest(&self, pc: usize) -> bool {
        self.jumpdests.get(pc / 64).is_some_and(|w| (w >> (pc % 64)) & 1 == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_data_is_not_a_jumpdest() {
        // PUSH1 0x5b JUMPDEST PUSH2 0x5b5b
        let code = [0x60, 0x5b, 0x5b, 0x61, 0x5b, 0x5b];
        let a = Analysis::new(&code, B256::ZERO);
        assert!(!a.is_jumpdest(1));
        assert!(a.is_jumpdest(2));
        assert!(!a.is_jumpdest(4));
        assert!(!a.is_jumpdest(5));
        assert!(!a.is_jumpdest(1000));
    }
}
