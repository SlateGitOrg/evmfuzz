//! Sequence execution and oracle checking.
//!
//! Every sequence starts from the campaign's genesis state. Before each call
//! the block number advances by one and the timestamp by the call's warp.
//! After each transaction the executor (optionally) folds coverage, checks the
//! assertion oracle and, if the transaction succeeded, evaluates the active
//! invariants with read-only calls that are rolled back afterwards.

use super::campaign::{Campaign, Names, DEPLOY_GAS};
use super::coverage::CoverageTracer;
use super::invariant::{AddressSet, EvalContext};
use super::sequence::Call;
use crate::abi::{decode_revert, panic_code, PANIC_ASSERT};
use crate::evm::{Evm, Halt, Status, Tracer, Transaction};
use crate::types::Address;
use crate::u256::U256;

/// Gas available to each view call made while evaluating an invariant.
pub const VIEW_GAS: u64 = 10_000_000;

/// Read-only evaluation context over a live interpreter.
pub struct ViewCtx<'a, T: Tracer> {
    /// Interpreter whose current state is inspected.
    pub evm: &'a mut Evm<T>,
    /// Name table.
    pub names: &'a Names,
}

impl<T: Tracer> EvalContext for ViewCtx<'_, T> {
    fn resolve(&self, name: &str) -> Option<Address> {
        self.names.resolve(name)
    }

    fn members(&self, set: AddressSet) -> Vec<Address> {
        self.names.members(set)
    }

    fn view(&mut self, to: Address, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let r = self.evm.view_call(to, data, VIEW_GAS);
        match r.status {
            Status::Success => Ok(r.output),
            Status::Revert => Err(decode_revert(&r.output).unwrap_or_else(|| "revert".into())),
            Status::Halt(h) => Err(h.to_string()),
        }
    }

    fn balance(&self, a: &Address) -> U256 {
        self.evm.state.balance(a)
    }

    fn storage(&self, a: &Address, slot: U256) -> U256 {
        self.evm.state.sload(a, &slot)
    }

    fn name_of(&self, a: &Address) -> String {
        self.names.display(a)
    }
}

/// A property checked during execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Oracle {
    /// Campaign invariant by index.
    Invariant(usize),
    /// The built-in "no failed `assert`" oracle.
    Assertion,
}

/// A broken property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Index of the call after which the property failed.
    pub step: usize,
    /// Which property.
    pub oracle: Oracle,
    /// Explanation (operand values, revert reason, ...).
    pub message: String,
}

/// What happened to one call (recorded when tracing).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StepTrace {
    /// Rendered call.
    pub call: String,
    /// `ok`, `revert: ...`, `halt: ...` or `invalid: ...`.
    pub outcome: String,
    /// Gas charged.
    pub gas_used: u64,
}

/// Result of running a sequence.
#[derive(Debug, Clone, Default)]
pub struct SeqOutcome {
    /// Transactions executed (stops early at a violation).
    pub executed: usize,
    /// First violation, if any.
    pub violation: Option<Violation>,
    /// Index of the last call that produced new coverage.
    pub last_new_coverage: Option<usize>,
    /// Per-call trace (only when requested).
    pub trace: Vec<StepTrace>,
}

/// Which oracles to check.
#[derive(Debug, Clone, Copy)]
pub enum Checks<'a> {
    /// Invariants whose flag is true, plus assertions if enabled.
    Active {
        /// One flag per campaign invariant.
        invariants: &'a [bool],
        /// Check the assertion oracle.
        assertions: bool,
    },
    /// Only this oracle (used while shrinking and replaying).
    Only(Oracle),
}

impl Checks<'_> {
    fn assertions(&self) -> bool {
        match self {
            Checks::Active { assertions, .. } => *assertions,
            Checks::Only(o) => *o == Oracle::Assertion,
        }
    }

    fn invariant(&self, i: usize) -> bool {
        match self {
            Checks::Active { invariants, .. } => invariants[i],
            Checks::Only(o) => *o == Oracle::Invariant(i),
        }
    }
}

/// Executes sequences against a campaign.
pub struct Executor<'c> {
    /// The campaign.
    pub campaign: &'c Campaign,
    /// Interpreter with coverage tracing.
    pub evm: Evm<CoverageTracer>,
    /// Gas limit per call.
    pub tx_gas: u64,
    /// Comparison operands logged by feedback runs, drained by the engine.
    pub cmp_values: Vec<U256>,
}

impl<'c> Executor<'c> {
    /// A fresh executor.
    pub fn new(campaign: &'c Campaign) -> Self {
        Executor {
            campaign,
            evm: Evm::with_tracer(campaign.genesis.clone(), campaign.block.clone(), CoverageTracer::default()),
            tx_gas: DEPLOY_GAS,
            cmp_values: Vec::new(),
        }
    }

    /// Runs `seq` from genesis. With `feedback`, coverage and comparison
    /// operands are recorded; with `trace`, a per-call trace is returned.
    pub fn run(&mut self, seq: &[Call], checks: Checks<'_>, feedback: bool, trace: bool) -> SeqOutcome {
        let c = self.campaign;
        self.evm.reset_state(c.genesis.clone());
        self.evm.block = c.block.clone();
        self.evm.tracer.enabled = feedback;
        let mut out = SeqOutcome::default();
        for (i, call) in seq.iter().enumerate() {
            self.evm.block.number += 1;
            self.evm.block.timestamp = self.evm.block.timestamp.saturating_add(call.warp);
            let target = &c.targets[call.target];
            let to = c.contracts[target.contract].address;
            let Ok(data) = target.func.encode_call(&call.args) else {
                // Only reachable with a hand-edited reproducer whose values do not match the types.
                out.executed += 1;
                continue;
            };
            let tx = Transaction::call(c.names.actors[call.sender], to, data, call.value, self.tx_gas);
            let result = self.evm.transact(&tx);
            out.executed += 1;
            if feedback {
                if self.evm.tracer.commit() {
                    out.last_new_coverage = Some(i);
                }
                // Operands equal to one of our own calldata words (or the call value) are the
                // fuzzer's inputs echoed back, not constants worth learning; drop them.
                let words: Vec<U256> = tx.data[4..].chunks(32).map(U256::from_be_slice).collect();
                let log = self.evm.tracer.take_cmp_log();
                self.cmp_values.extend(log.into_iter().filter(|v| *v != call.value && !words.contains(v)));
            }
            let mut violation = None;
            let (success, outcome, gas_used) = match &result {
                Err(e) => (false, format!("invalid: {e}"), 0),
                Ok(r) => {
                    let outcome = match r.status {
                        Status::Success => "ok".to_string(),
                        Status::Revert => {
                            format!("revert: {}", decode_revert(&r.output).unwrap_or_else(|| "(no reason)".into()))
                        }
                        Status::Halt(h) => format!("halt: {h}"),
                    };
                    let asserted = panic_code(&r.output) == Some(PANIC_ASSERT)
                        || r.status == Status::Halt(Halt::InvalidOpcode(0xfe));
                    if asserted && checks.assertions() {
                        violation = Some(Violation { step: i, oracle: Oracle::Assertion, message: outcome.clone() });
                    }
                    (r.status.is_success(), outcome, r.gas_used)
                }
            };
            if trace {
                out.trace.push(StepTrace { call: call.display(c), outcome, gas_used });
            }
            if violation.is_none() && success {
                violation = self.check_invariants(i, checks);
            }
            if violation.is_some() {
                out.violation = violation;
                break;
            }
        }
        self.evm.tracer.enabled = true;
        out
    }

    fn check_invariants(&mut self, step: usize, checks: Checks<'_>) -> Option<Violation> {
        let c = self.campaign;
        let was = std::mem::replace(&mut self.evm.tracer.enabled, false);
        let mut found = None;
        for (i, inv) in c.invariants.iter().enumerate() {
            if !checks.invariant(i) {
                continue;
            }
            let mut ctx = ViewCtx { evm: &mut self.evm, names: &c.names };
            let message = match inv.expr.eval(&mut ctx) {
                Ok(v) if v.truthy() => continue,
                Ok(_) => inv.expr.explain(&mut ctx).unwrap_or_else(|| "evaluated to false".into()),
                Err(e) => format!("evaluation failed: {e}"),
            };
            found = Some(Violation { step, oracle: Oracle::Invariant(i), message });
            break;
        }
        self.evm.tracer.enabled = was;
        found
    }

    /// Name of an oracle.
    pub fn oracle_name(&self, o: Oracle) -> String {
        oracle_name(self.campaign, o)
    }
}

/// Name of an oracle within a campaign.
pub fn oracle_name(c: &Campaign, o: Oracle) -> String {
    match o {
        Oracle::Invariant(i) => c.invariants[i].name.clone(),
        Oracle::Assertion => super::ASSERTION_ORACLE.to_string(),
    }
}

/// Looks an oracle up by name.
pub fn find_oracle(c: &Campaign, name: &str) -> Option<Oracle> {
    if name == super::ASSERTION_ORACLE {
        return Some(Oracle::Assertion);
    }
    c.invariants.iter().position(|i| i.name == name).map(Oracle::Invariant)
}
