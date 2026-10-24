//! Block-level execution context.

use crate::crypto::keccak256;
use crate::types::{Address, B256};
use crate::u256::U256;

/// Block header fields visible to contracts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockEnv {
    /// `COINBASE`.
    pub coinbase: Address,
    /// `NUMBER`.
    pub number: u64,
    /// `TIMESTAMP`.
    pub timestamp: u64,
    /// `GASLIMIT`.
    pub gas_limit: u64,
    /// `BASEFEE` (EIP-1559).
    pub base_fee: U256,
    /// `PREVRANDAO` (EIP-4399).
    pub prevrandao: U256,
    /// `CHAINID`.
    pub chain_id: U256,
}

impl Default for BlockEnv {
    fn default() -> Self {
        BlockEnv {
            coinbase: Address::from_low_u64(0xc0ffee),
            number: 1,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee: U256::ZERO,
            prevrandao: U256::ZERO,
            chain_id: U256::ONE,
        }
    }
}

impl BlockEnv {
    /// `BLOCKHASH(n)`. There is no real chain, so — like the reference test
    /// harnesses for `ethereum/tests` — the hash of block `n` is defined as
    /// `keccak256(decimal_string(n))` for the 256 most recent blocks, else zero.
    pub fn blockhash(&self, n: U256) -> B256 {
        match n.to_u64() {
            Some(n) if n < self.number && self.number - n <= 256 => keccak256(n.to_string().as_bytes()),
            _ => B256::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockhash_window() {
        let env = BlockEnv { number: 300, ..BlockEnv::default() };
        assert_eq!(env.blockhash(U256::from_u64(300)), B256::ZERO);
        assert_eq!(env.blockhash(U256::from_u64(43)), B256::ZERO);
        assert_eq!(env.blockhash(U256::from_u64(44)), keccak256(b"44"));
        assert_eq!(env.blockhash(U256::MAX), B256::ZERO);
    }
}
