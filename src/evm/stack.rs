//! The 1024-entry operand stack.

use super::Halt;
use crate::u256::U256;

/// Maximum stack depth.
pub const STACK_LIMIT: usize = 1024;

/// Operand stack.
#[derive(Debug, Clone)]
pub struct Stack {
    data: Vec<U256>,
}

impl Default for Stack {
    fn default() -> Self {
        Stack { data: Vec::with_capacity(STACK_LIMIT) }
    }
}

impl Stack {
    /// Empty stack.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of items.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Pushes, failing on overflow.
    #[inline]
    pub fn push(&mut self, v: U256) -> Result<(), Halt> {
        if self.data.len() >= STACK_LIMIT {
            return Err(Halt::StackOverflow);
        }
        self.data.push(v);
        Ok(())
    }

    /// Pops, failing on underflow.
    #[inline]
    pub fn pop(&mut self) -> Result<U256, Halt> {
        self.data.pop().ok_or(Halt::StackUnderflow)
    }

    /// Pops `N` items; index 0 is the former top.
    #[inline]
    pub fn pop_n<const N: usize>(&mut self) -> Result<[U256; N], Halt> {
        if self.data.len() < N {
            return Err(Halt::StackUnderflow);
        }
        let mut out = [U256::ZERO; N];
        for o in out.iter_mut() {
            *o = self.data.pop().unwrap_or_default();
        }
        Ok(out)
    }

    /// Duplicates the `n`-th item from the top (1-based).
    #[inline]
    pub fn dup(&mut self, n: usize) -> Result<(), Halt> {
        let len = self.data.len();
        if len < n {
            return Err(Halt::StackUnderflow);
        }
        let v = self.data[len - n];
        self.push(v)
    }

    /// Swaps the top with the `n+1`-th item (1-based `n`).
    #[inline]
    pub fn swap(&mut self, n: usize) -> Result<(), Halt> {
        let len = self.data.len();
        if len <= n {
            return Err(Halt::StackUnderflow);
        }
        self.data.swap(len - 1, len - 1 - n);
        Ok(())
    }

    /// Top-of-stack view (top last).
    pub fn as_slice(&self) -> &[U256] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_ops() {
        let mut s = Stack::new();
        assert_eq!(s.pop(), Err(Halt::StackUnderflow));
        s.push(U256::ONE).unwrap();
        s.push(U256::from_u64(2)).unwrap();
        s.dup(2).unwrap();
        assert_eq!(s.as_slice(), &[U256::ONE, U256::from_u64(2), U256::ONE]);
        s.swap(2).unwrap();
        assert_eq!(s.pop_n::<3>().unwrap(), [U256::ONE, U256::from_u64(2), U256::ONE]);
        assert!(s.is_empty());
        assert_eq!(s.swap(1), Err(Halt::StackUnderflow));
        assert_eq!(s.dup(1), Err(Halt::StackUnderflow));
        assert_eq!(s.pop_n::<1>(), Err(Halt::StackUnderflow));
        for _ in 0..STACK_LIMIT {
            s.push(U256::ZERO).unwrap();
        }
        assert_eq!(s.push(U256::ZERO), Err(Halt::StackOverflow));
        assert_eq!(s.len(), STACK_LIMIT);
    }
}
