//! Execution hooks. The interpreter is generic over a [`Tracer`], so the
//! no-op tracer compiles away entirely while the fuzzer's coverage tracer
//! sees every branch and comparison.

use crate::evm::opcode::OPCODES;
use crate::u256::U256;

/// Callbacks invoked by the interpreter. All methods default to no-ops.
pub trait Tracer {
    /// Before each instruction executes (after `code_id`/`pc` are known).
    #[inline]
    fn step(&mut self, _code_id: u64, _pc: usize, _op: u8, _gas: u64, _stack: &[U256], _depth: usize) {}

    /// At every `JUMPI`, with the destination and whether it was taken.
    #[inline]
    fn branch(&mut self, _code_id: u64, _pc: usize, _dest: usize, _taken: bool) {}

    /// Operands of `EQ`, `LT`, `GT`, `SLT`, `SGT` (for dictionary feedback).
    #[inline]
    fn compare(&mut self, _a: U256, _b: U256) {}
}

/// A tracer that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTracer;

impl Tracer for NoopTracer {}

/// One recorded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceStep {
    /// Call depth (0 = transaction frame).
    pub depth: usize,
    /// Program counter.
    pub pc: usize,
    /// Opcode mnemonic.
    pub op: &'static str,
    /// Gas remaining before the instruction.
    pub gas: u64,
    /// Top of stack (up to three items, top first).
    pub stack_top: Vec<U256>,
}

/// Records an instruction-level trace, capped at `limit` steps.
#[derive(Debug, Clone, Default)]
pub struct StepRecorder {
    /// Recorded steps.
    pub steps: Vec<TraceStep>,
    /// Maximum number of steps to keep.
    pub limit: usize,
    /// Steps observed beyond the limit.
    pub dropped: usize,
}

impl StepRecorder {
    /// A recorder keeping at most `limit` steps.
    pub fn with_limit(limit: usize) -> Self {
        StepRecorder { steps: Vec::new(), limit, dropped: 0 }
    }
}

impl Tracer for StepRecorder {
    fn step(&mut self, _code_id: u64, pc: usize, op: u8, gas: u64, stack: &[U256], depth: usize) {
        if self.steps.len() >= self.limit {
            self.dropped += 1;
            return;
        }
        let stack_top = stack.iter().rev().take(3).copied().collect();
        self.steps.push(TraceStep { depth, pc, op: OPCODES[op as usize].name, gas, stack_top });
    }
}
