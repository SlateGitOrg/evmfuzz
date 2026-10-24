//! Gas schedule constants for the Shanghai fork and helpers for the
//! dynamic components (memory expansion, copies, EIP-2929 access costs).

/// `G_jumpdest` and friends are folded into the opcode table; these are the
/// constants used by dynamic gas rules.
pub const WARM_STORAGE_READ: u64 = 100;
/// EIP-2929 cold `SLOAD`.
pub const COLD_SLOAD: u64 = 2100;
/// EIP-2929 cold account access.
pub const COLD_ACCOUNT_ACCESS: u64 = 2600;
/// `SSTORE` setting a zero slot to non-zero.
pub const SSTORE_SET: u64 = 20000;
/// `SSTORE` changing a non-zero slot (minus the cold surcharge).
pub const SSTORE_RESET: u64 = 5000 - COLD_SLOAD;
/// EIP-3529 refund for clearing a slot.
pub const SSTORE_CLEARS_SCHEDULE: i64 = 4800;
/// EIP-2200 sentry: `SSTORE` fails if no more than this much gas remains.
pub const SSTORE_SENTRY: u64 = 2300;
/// Per-word cost of copy operations.
pub const COPY_WORD: u64 = 3;
/// Per-word cost of `KECCAK256`.
pub const KECCAK_WORD: u64 = 6;
/// Per-byte cost of an `EXP` exponent.
pub const EXP_BYTE: u64 = 50;
/// Per-byte cost of log data.
pub const LOG_DATA_BYTE: u64 = 8;
/// Surcharge for a non-zero value transfer in `CALL`/`CALLCODE`.
pub const CALL_VALUE: u64 = 9000;
/// Gas gifted to the callee of a value-bearing call.
pub const CALL_STIPEND: u64 = 2300;
/// Surcharge for calling (or self-destructing into) an empty account with value.
pub const NEW_ACCOUNT: u64 = 25000;
/// Per-byte cost of deployed code.
pub const CODE_DEPOSIT_BYTE: u64 = 200;
/// EIP-3860 per-word initcode cost.
pub const INITCODE_WORD: u64 = 2;
/// EIP-170 maximum deployed code size.
pub const MAX_CODE_SIZE: usize = 24576;
/// EIP-3860 maximum initcode size.
pub const MAX_INITCODE_SIZE: usize = 2 * MAX_CODE_SIZE;
/// Maximum call depth.
pub const MAX_CALL_DEPTH: usize = 1024;
/// Base transaction cost.
pub const TX_BASE: u64 = 21000;
/// Extra cost of a contract-creation transaction.
pub const TX_CREATE: u64 = 32000;
/// Calldata zero byte.
pub const TX_DATA_ZERO: u64 = 4;
/// Calldata non-zero byte (EIP-2028).
pub const TX_DATA_NONZERO: u64 = 16;
/// EIP-2930 access-list address.
pub const ACCESS_LIST_ADDRESS: u64 = 2400;
/// EIP-2930 access-list storage key.
pub const ACCESS_LIST_STORAGE_KEY: u64 = 1900;
/// EIP-3529 maximum refund quotient.
pub const MAX_REFUND_QUOTIENT: u64 = 5;
/// Memory beyond this many bytes is treated as out of gas (it could never be paid for).
pub const MAX_MEMORY: u64 = 0xFFFF_FFFF;

/// Number of 32-byte words needed to hold `bytes` bytes.
#[inline]
pub fn words(bytes: u64) -> u64 {
    bytes.div_ceil(32)
}

/// Total memory cost for a memory of `w` words: `3w + w²/512`.
#[inline]
pub fn memory_cost(w: u64) -> u64 {
    3 * w + w * w / 512
}

/// Cost of copying `len` bytes.
#[inline]
pub fn copy_cost(len: u64) -> u64 {
    COPY_WORD * words(len)
}

/// Gas of all but one 64th of `gas` (EIP-150).
#[inline]
pub fn all_but_one_64th(gas: u64) -> u64 {
    gas - gas / 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_cost_is_quadratic() {
        assert_eq!(memory_cost(0), 0);
        assert_eq!(memory_cost(1), 3);
        assert_eq!(memory_cost(1024), 3 * 1024 + 2048);
        assert_eq!(words(33), 2);
        assert_eq!(copy_cost(0), 0);
        assert_eq!(all_but_one_64th(6400), 6300);
    }
}
