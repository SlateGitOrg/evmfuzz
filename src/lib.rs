//! # evmfuzz
//!
//! A Shanghai-level Ethereum Virtual Machine interpreter and a
//! coverage-guided, stateful invariant fuzzer built on it.
//!
//! * [`evm`] — the interpreter: gas-metered opcodes, memory, journaled
//!   storage, nested calls/creates, logs, reverts, transaction processing.
//! * [`statetest`] — a runner for `ethereum/tests` GeneralStateTests that
//!   checks post-state roots and log hashes.
//! * [`fuzz`] — the campaign engine: ABI-aware call-sequence generation,
//!   edge-coverage feedback, a comparison-operand dictionary, user-declared
//!   invariants and delta-debugging shrinking of failing sequences.
//!
//! All execution is in-memory and offline; nothing here talks to a network.

#![warn(missing_docs)]

//ABI
pub mod crypto;
pub mod evm;
//FUZZ
pub mod fxhash;
pub mod rlp;
pub mod statetest;
pub mod trie;
pub mod types;
pub mod u256;

pub use types::{Address, B256};
pub use u256::U256;
