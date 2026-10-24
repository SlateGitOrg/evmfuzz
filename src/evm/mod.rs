//! A Shanghai-level EVM interpreter.
//!
//! * [`Evm`] owns a [`JournaledState`], the [`BlockEnv`] and a [`Tracer`].
//! * Message calls and contract creations recurse through
//!   [`Evm::call_message`] / [`Evm::create_message`]; each frame runs the
//!   dispatch loop in `interpreter.rs`.
//! * [`Evm::transact`] (in `tx.rs`) wraps a top-level call with transaction
//!   validation, intrinsic gas, fee payment, refunds and EIP-161 cleanup.
//!
//! Recursion depth is bounded by the 1024-frame call limit; run deep
//! workloads on a thread with a large stack (see [`run_with_big_stack`]).

mod analysis;
pub mod env;
pub mod gas;
mod interpreter;
pub mod memory;
pub mod opcode;
pub mod precompiles;
pub mod stack;
pub mod state;
pub mod tracer;
mod tx;

pub use analysis::Analysis;
pub use env::BlockEnv;
pub use state::{Account, Code, JournaledState, Log, WorldState};
pub use tracer::{NoopTracer, StepRecorder, Tracer};
pub use tx::{GasPrice, Transaction, TxError, TxResult};

use crate::crypto::keccak256;
use crate::fxhash::FxHashMap;
use crate::rlp;
use crate::types::{Address, B256};
use crate::u256::U256;
use std::rc::Rc;

/// Exceptional halting conditions. All of them consume the frame's remaining gas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Halt {
    /// Not enough gas for the next step.
    #[error("out of gas")]
    OutOfGas,
    /// An instruction needed more stack items than available.
    #[error("stack underflow")]
    StackUnderflow,
    /// The stack would exceed 1024 items.
    #[error("stack overflow")]
    StackOverflow,
    /// `JUMP`/`JUMPI` to a non-`JUMPDEST`.
    #[error("invalid jump destination")]
    InvalidJump,
    /// Undefined opcode or `INVALID` (0xfe).
    #[error("invalid opcode 0x{0:02x}")]
    InvalidOpcode(u8),
    /// State modification inside a `STATICCALL` context.
    #[error("state modification in static context")]
    StaticStateChange,
    /// `RETURNDATACOPY` beyond the return buffer.
    #[error("return data out of bounds")]
    ReturnDataOutOfBounds,
    /// Deployed code larger than 24576 bytes (EIP-170).
    #[error("deployed code exceeds size limit")]
    CodeSizeLimit,
    /// Deployed code starting with 0xEF (EIP-3541).
    #[error("deployed code starts with 0xEF")]
    InvalidCodePrefix,
    /// CREATE target already has code or a nonce.
    #[error("contract address collision")]
    CreateCollision,
    /// Malformed precompile input.
    #[error("precompile failure")]
    PrecompileFailure,
    /// A precompile this interpreter does not implement was invoked with enough gas.
    #[error("unsupported precompile 0x{0:02x}")]
    UnsupportedPrecompile(u8),
}

/// How a frame ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// `STOP`, `RETURN`, `SELFDESTRUCT` or running off the end of code.
    Success,
    /// `REVERT`: state rolled back, remaining gas returned.
    Revert,
    /// Exceptional halt: state rolled back, all gas consumed.
    Halt(Halt),
}

impl Status {
    /// True for [`Status::Success`].
    pub fn is_success(&self) -> bool {
        matches!(self, Status::Success)
    }
}

/// Result of a message call or creation frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameResult {
    /// Outcome.
    pub status: Status,
    /// Gas left over (zero after a halt).
    pub gas_left: u64,
    /// Return or revert data.
    pub output: Vec<u8>,
    /// Address of the created contract, for successful creations.
    pub created: Option<Address>,
}

impl FrameResult {
    fn ok(gas_left: u64, output: Vec<u8>) -> Self {
        FrameResult { status: Status::Success, gas_left, output, created: None }
    }

    fn halt(h: Halt) -> Self {
        FrameResult { status: Status::Halt(h), gas_left: 0, output: Vec::new(), created: None }
    }
}

/// The flavour of a message call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// `CALL` (and top-level transactions).
    Call,
    /// `CALLCODE`.
    CallCode,
    /// `DELEGATECALL`.
    DelegateCall,
    /// `STATICCALL`.
    StaticCall,
}

/// Parameters of a message call.
#[derive(Debug, Clone)]
pub struct CallMessage {
    /// Call flavour.
    pub kind: CallKind,
    /// `CALLER` inside the callee.
    pub caller: Address,
    /// Account whose storage and balance the code runs against.
    pub target: Address,
    /// Account whose code is executed.
    pub code_address: Address,
    /// Value transferred (CALL) or apparent value (DELEGATECALL/CALLCODE).
    pub value: U256,
    /// Calldata.
    pub input: Vec<u8>,
    /// Gas made available to the callee.
    pub gas: u64,
    /// Static context flag.
    pub is_static: bool,
    /// Depth of the new frame (0 = transaction).
    pub depth: usize,
}

/// Parameters of a contract creation.
#[derive(Debug, Clone)]
pub struct CreateMessage {
    /// Creator.
    pub caller: Address,
    /// Endowment.
    pub value: U256,
    /// Initialisation code.
    pub init_code: Vec<u8>,
    /// Gas made available to the initcode.
    pub gas: u64,
    /// `Some(salt)` for CREATE2.
    pub salt: Option<U256>,
    /// Depth of the new frame.
    pub depth: usize,
}

/// `keccak256(rlp([sender, nonce]))[12..]`.
pub fn create_address(sender: &Address, nonce: u64) -> Address {
    let enc = rlp::encode_list(&[rlp::encode_bytes(&sender.0), rlp::encode_u64(nonce)]);
    Address::from_slice(&keccak256(&enc).0[12..]).expect("20-byte slice")
}

/// `keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..]` (EIP-1014).
pub fn create2_address(sender: &Address, salt: U256, init_code_hash: &B256) -> Address {
    let mut buf = Vec::with_capacity(85);
    buf.push(0xff);
    buf.extend_from_slice(&sender.0);
    buf.extend_from_slice(&salt.to_be_bytes());
    buf.extend_from_slice(&init_code_hash.0);
    Address::from_slice(&keccak256(&buf).0[12..]).expect("20-byte slice")
}

/// The interpreter.
pub struct Evm<T: Tracer = NoopTracer> {
    /// World state plus transaction substate.
    pub state: JournaledState,
    /// Block context.
    pub block: BlockEnv,
    /// Execution hooks.
    pub tracer: T,
    /// `ORIGIN` of the current transaction.
    pub origin: Address,
    /// `GASPRICE` (effective) of the current transaction.
    pub gas_price: U256,
    analysis_cache: FxHashMap<B256, Rc<Analysis>>,
    unsupported: Option<u8>,
}

impl Evm<NoopTracer> {
    /// An interpreter over `state` without tracing.
    pub fn new(state: WorldState, block: BlockEnv) -> Self {
        Evm::with_tracer(state, block, NoopTracer)
    }
}

impl<T: Tracer> Evm<T> {
    /// An interpreter over `state` with a tracer.
    pub fn with_tracer(state: WorldState, block: BlockEnv, tracer: T) -> Self {
        Evm {
            state: JournaledState::new(state),
            block,
            tracer,
            origin: Address::ZERO,
            gas_price: U256::ZERO,
            analysis_cache: FxHashMap::default(),
            unsupported: None,
        }
    }

    /// Replaces the world state (keeps the jump-table cache warm).
    pub fn reset_state(&mut self, state: WorldState) {
        self.state = JournaledState::new(state);
        self.unsupported = None;
    }

    /// The precompile id if an unsupported precompile was reached since the
    /// last [`Evm::reset_state`] / transaction.
    pub fn unsupported_precompile(&self) -> Option<u8> {
        self.unsupported
    }

    /// Executes a read-only `STATICCALL` from the zero address against the
    /// current state and rolls every effect back (including warm-set
    /// changes), as `eth_call` would. Used to evaluate invariants between
    /// transactions; must not be called while a transaction is in flight.
    pub fn view_call(&mut self, to: Address, input: Vec<u8>, gas: u64) -> FrameResult {
        let cp = self.state.checkpoint();
        self.state.warm_account(to);
        let r = self.call_message(&CallMessage {
            kind: CallKind::StaticCall,
            caller: Address::ZERO,
            target: to,
            code_address: to,
            value: U256::ZERO,
            input,
            gas,
            is_static: true,
            depth: 0,
        });
        self.state.revert_to(cp);
        r
    }

    fn analysis_for(&mut self, code: &[u8], hash: B256) -> Rc<Analysis> {
        if let Some(a) = self.analysis_cache.get(&hash) {
            return a.clone();
        }
        let a = Rc::new(Analysis::new(code, hash));
        self.analysis_cache.insert(hash, a.clone());
        a
    }
}

/// Runs `f` on a fresh thread with a 256 MiB stack (deep call chains recurse
/// through native frames) and returns its result.
pub fn run_with_big_stack<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(f)
        .expect("spawn interpreter thread")
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_addresses_match_known_vectors() {
        // From EIP-1014 example 0.
        let a = create2_address(&Address::ZERO, U256::ZERO, &keccak256(&[0x00]));
        assert_eq!(a.to_string(), "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38");
        let sender: Address = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0".parse().unwrap();
        assert_eq!(create_address(&sender, 0).to_string(), "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d");
        assert_eq!(create_address(&sender, 1).to_string(), "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8");
    }

    #[test]
    fn status_helpers() {
        assert!(Status::Success.is_success());
        assert!(!Status::Revert.is_success());
        assert_eq!(Halt::InvalidOpcode(0xfe).to_string(), "invalid opcode 0xfe");
    }
}
