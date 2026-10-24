//! Byte-addressed, word-expanding EVM memory with quadratic expansion cost.

use super::gas;
use super::Halt;
use crate::u256::U256;

/// Frame-local memory.
#[derive(Debug, Default, Clone)]
pub struct Memory {
    data: Vec<u8>,
}

impl Memory {
    /// Empty memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current size in bytes (always a multiple of 32).
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when no memory has been touched.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Validates `(offset, size)` from the stack and expands memory to cover it,
    /// charging the expansion cost from `gas_left`. Returns the range as
    /// `(offset, size)` in `usize`; a zero size never expands or faults.
    pub fn expand(&mut self, gas_left: &mut u64, offset: U256, size: U256) -> Result<(usize, usize), Halt> {
        if size.is_zero() {
            return Ok((0, 0));
        }
        let off = offset.to_u64().ok_or(Halt::OutOfGas)?;
        let len = size.to_u64().ok_or(Halt::OutOfGas)?;
        let end = off.checked_add(len).ok_or(Halt::OutOfGas)?;
        if end > gas::MAX_MEMORY {
            return Err(Halt::OutOfGas);
        }
        self.expand_to(gas_left, end)?;
        Ok((off as usize, len as usize))
    }

    /// Expands memory to at least `end` bytes, charging gas.
    pub fn expand_to(&mut self, gas_left: &mut u64, end: u64) -> Result<(), Halt> {
        let cur = self.data.len() as u64;
        if end <= cur {
            return Ok(());
        }
        let new_words = gas::words(end);
        let cost = gas::memory_cost(new_words) - gas::memory_cost(cur / 32);
        if *gas_left < cost {
            return Err(Halt::OutOfGas);
        }
        *gas_left -= cost;
        self.data.resize((new_words * 32) as usize, 0);
        Ok(())
    }

    /// Reads a 32-byte word (memory must already cover it).
    #[inline]
    pub fn load_word(&self, off: usize) -> U256 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.data[off..off + 32]);
        U256::from_be_bytes(buf)
    }

    /// Writes a 32-byte word (memory must already cover it).
    #[inline]
    pub fn store_word(&mut self, off: usize, v: U256) {
        self.data[off..off + 32].copy_from_slice(&v.to_be_bytes());
    }

    /// Writes one byte.
    #[inline]
    pub fn store_byte(&mut self, off: usize, b: u8) {
        self.data[off] = b;
    }

    /// Borrows a range (memory must already cover it).
    #[inline]
    pub fn slice(&self, off: usize, len: usize) -> &[u8] {
        if len == 0 {
            return &[];
        }
        &self.data[off..off + len]
    }

    /// Copies `len` bytes from `src[src_off..]` into memory at `dst`, zero-filling
    /// past the end of `src` (CALLDATACOPY/CODECOPY semantics).
    pub fn copy_padded(&mut self, dst: usize, src: &[u8], src_off: U256, len: usize) {
        if len == 0 {
            return;
        }
        let target = &mut self.data[dst..dst + len];
        let start = src_off.to_usize().unwrap_or(usize::MAX);
        if start >= src.len() {
            target.fill(0);
            return;
        }
        let avail = (src.len() - start).min(len);
        target[..avail].copy_from_slice(&src[start..start + avail]);
        target[avail..].fill(0);
    }

    /// Copies bytes into memory exactly (caller ensures bounds).
    pub fn write(&mut self, dst: usize, bytes: &[u8]) {
        self.data[dst..dst + bytes.len()].copy_from_slice(bytes);
    }

    /// The whole memory as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_charges_incrementally() {
        let mut m = Memory::new();
        let mut gas = 1000;
        m.expand(&mut gas, U256::ZERO, U256::from_u64(32)).unwrap();
        assert_eq!(gas, 997);
        m.expand(&mut gas, U256::from_u64(16), U256::from_u64(16)).unwrap();
        assert_eq!(gas, 997);
        m.expand(&mut gas, U256::from_u64(32), U256::ONE).unwrap();
        assert_eq!(gas, 994);
        assert_eq!(m.len(), 64);
        // Zero size never faults even at absurd offsets.
        assert_eq!(m.expand(&mut gas, U256::MAX, U256::ZERO), Ok((0, 0)));
        assert_eq!(m.expand(&mut gas, U256::MAX, U256::ONE), Err(Halt::OutOfGas));
        let mut tiny = 2;
        assert_eq!(m.expand(&mut tiny, U256::from_u64(64), U256::ONE), Err(Halt::OutOfGas));
    }

    #[test]
    fn padded_copy() {
        let mut m = Memory::new();
        let mut gas = 100;
        m.expand(&mut gas, U256::ZERO, U256::from_u64(8)).unwrap();
        m.copy_padded(0, &[1, 2, 3], U256::ONE, 4);
        assert_eq!(&m.as_bytes()[..4], &[2, 3, 0, 0]);
        m.copy_padded(0, &[1, 2, 3], U256::MAX, 2);
        assert_eq!(&m.as_bytes()[..2], &[0, 0]);
        m.store_word(0, U256::from_u64(0xabcd));
        assert_eq!(m.load_word(0), U256::from_u64(0xabcd));
        m.store_byte(31, 1);
        assert_eq!(m.slice(30, 2), &[0xab, 1]);
    }
}
