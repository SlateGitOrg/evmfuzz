//! Throughput benchmarks: raw interpreter speed on synthetic loops, and
//! fuzzing executions per second on the fixture campaigns.
//!
//! Each measurement is repeated and the median is reported. Numbers depend
//! on the machine; the README states where its numbers came from.

use crate::evm::{Account, BlockEnv, CallKind, CallMessage, Evm, FrameResult, NoopTracer, Status, Tracer, WorldState};
use crate::fuzz::campaign::Campaign;
use crate::fuzz::exec::{Checks, Executor};
use crate::fuzz::mutate::Generator;
use crate::types::Address;
use crate::u256::U256;
use std::time::Instant;

/// One interpreter benchmark result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InterpBench {
    /// Workload name.
    pub name: &'static str,
    /// Gas consumed per run.
    pub gas: u64,
    /// Instructions executed per run.
    pub instructions: u64,
    /// Median wall-clock seconds per run.
    pub secs: f64,
}

impl InterpBench {
    /// Millions of gas per second.
    pub fn mgas_per_sec(&self) -> f64 {
        self.gas as f64 / self.secs / 1e6
    }

    /// Millions of instructions per second.
    pub fn mips(&self) -> f64 {
        self.instructions as f64 / self.secs / 1e6
    }
}

/// One fuzzing-throughput result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FuzzBench {
    /// Campaign name.
    pub campaign: String,
    /// Whether invariants were evaluated after each successful call.
    pub invariants: bool,
    /// Transactions executed.
    pub tx: u64,
    /// Sequences executed.
    pub sequences: u64,
    /// Median wall-clock seconds.
    pub secs: f64,
}

impl FuzzBench {
    /// Transactions per second.
    pub fn tx_per_sec(&self) -> f64 {
        self.tx as f64 / self.secs
    }
}

#[derive(Default)]
struct Counter(u64);

impl Tracer for Counter {
    fn step(&mut self, _: u64, _: usize, _: u8, _: u64, _: &[U256], _: usize) {
        self.0 += 1;
    }
}

/// Wraps a loop body: `PUSH3 n; loop: JUMPDEST; counter -= 1; <body>; JUMPI loop if counter != 0; STOP`.
/// The body must leave the stack as it found it (counter on top).
fn counted_loop(n: u32, body: &[u8]) -> Vec<u8> {
    let mut code = vec![0x62];
    code.extend_from_slice(&n.to_be_bytes()[1..]);
    code.extend_from_slice(&[0x5b, 0x60, 0x01, 0x90, 0x03]); // JUMPDEST PUSH1 1 SWAP1 SUB
    code.extend_from_slice(body);
    code.extend_from_slice(&[0x80, 0x60, 0x04, 0x57, 0x00]); // DUP1 PUSH1 4 JUMPI STOP
    code
}

fn workloads(scale: u32) -> Vec<(&'static str, Vec<u8>)> {
    let callee = Address::from_low_u64(0xca11);
    let mut call_body = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x73];
    call_body.extend_from_slice(&callee.0);
    call_body.extend_from_slice(&[0x5a, 0xfa, 0x50]); // GAS STATICCALL POP
    vec![
        // DUP1 PUSH1 3 MUL PUSH1 7 ADD PUSH1 5 MOD POP
        (
            "arithmetic",
            counted_loop(200_000 * scale, &[0x80, 0x60, 0x03, 0x02, 0x60, 0x07, 0x01, 0x60, 0x05, 0x06, 0x50]),
        ),
        // DUP1 PUSH0 MSTORE PUSH1 64 PUSH0 KECCAK256 POP
        ("keccak256", counted_loop(50_000 * scale, &[0x80, 0x5f, 0x52, 0x60, 0x40, 0x5f, 0x20, 0x50])),
        // DUP1 DUP1 PUSH1 16 SWAP1 MOD SSTORE  DUP1 PUSH1 16 SWAP1 MOD SLOAD POP
        (
            "storage",
            counted_loop(
                50_000 * scale,
                &[0x80, 0x80, 0x60, 0x10, 0x90, 0x06, 0x55, 0x80, 0x60, 0x10, 0x90, 0x06, 0x54, 0x50],
            ),
        ),
        ("staticcall", counted_loop(20_000 * scale, &call_body)),
    ]
}

fn run_once<T: Tracer>(code: &[u8], tracer: T) -> (FrameResult, T) {
    let target = Address::from_low_u64(0xbe4c);
    let mut ws = WorldState::new();
    ws.insert(target, Account::with_code(code.to_vec()));
    ws.insert(Address::from_low_u64(0xca11), Account::with_code(vec![0x5f, 0x5f, 0xf3])); // PUSH0 PUSH0 RETURN
    let mut evm = Evm::with_tracer(ws, BlockEnv::default(), tracer);
    let gas = 1u64 << 40;
    let r = evm.call_message(&CallMessage {
        kind: CallKind::Call,
        caller: Address::from_low_u64(1),
        target,
        code_address: target,
        value: U256::ZERO,
        input: Vec::new(),
        gas,
        is_static: false,
        depth: 0,
    });
    (FrameResult { gas_left: gas - r.gas_left, ..r }, evm.tracer)
}

fn median_secs(reps: usize, mut f: impl FnMut()) -> f64 {
    let mut v: Vec<f64> = (0..reps.max(1))
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64()
        })
        .collect();
    v.sort_by(f64::total_cmp);
    v[(v.len() - 1) / 2]
}

/// Runs the interpreter workloads. `scale` multiplies loop counts.
pub fn interpreter(scale: u32, reps: usize) -> Vec<InterpBench> {
    workloads(scale.max(1))
        .into_iter()
        .map(|(name, code)| {
            let (r, counter) = run_once(&code, Counter::default());
            assert_eq!(r.status, Status::Success, "benchmark {name} must succeed");
            let secs = median_secs(reps, || {
                let (r, _) = run_once(&code, NoopTracer);
                std::hint::black_box(r);
            });
            InterpBench { name, gas: r.gas_left, instructions: counter.0, secs }
        })
        .collect()
}

/// Executes `tx_budget` transactions worth of random sequences against a
/// campaign, with and without invariant evaluation.
pub fn fuzzing(c: &Campaign, tx_budget: u64, reps: usize) -> Vec<FuzzBench> {
    let checks_all = vec![true; c.invariants.len()];
    let none = vec![false; c.invariants.len()];
    [false, true]
        .into_iter()
        .map(|with_inv| {
            let mut tx = 0;
            let mut sequences = 0;
            let secs = median_secs(reps, || {
                let mut exec = Executor::new(c);
                let mut gen = Generator::new(c, 7, true, c.defaults.max_seq_len);
                tx = 0;
                sequences = 0;
                let flags = if with_inv { &checks_all } else { &none };
                while tx < tx_budget {
                    let seq = gen.sequence();
                    // Violations are ignored here: we only measure execution speed.
                    let out = exec.run(&seq, Checks::Active { invariants: flags, assertions: true }, true, false);
                    gen.learn(exec.cmp_values.drain(..));
                    gen.learn_i2s(exec.i2s.drain(..));
                    tx += out.executed as u64;
                    sequences += 1;
                }
            });
            FuzzBench { campaign: c.name.clone(), invariants: with_inv, tx, sequences, secs }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workloads_run_to_completion() {
        let res = interpreter(1, 1);
        assert_eq!(res.len(), 4);
        for b in &res {
            assert!(b.gas > 0 && b.instructions > 0 && b.secs > 0.0, "{b:?}");
            assert!(b.mgas_per_sec() > 0.0 && b.mips() > 0.0);
        }
        // arithmetic loop: 3 setup-free ops per iteration plus the body; check instruction count exactly.
        // Per iteration: JUMPDEST PUSH1 SWAP1 SUB (4) + body (8) + DUP1 PUSH1 JUMPI (3) = 15; plus PUSH3 and STOP.
        assert_eq!(res[0].instructions, 200_000 * 15 + 2);
    }
}
