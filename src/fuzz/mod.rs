//! The coverage-guided, stateful invariant fuzzer.
//!
//! The campaign loop (see `docs/ARCHITECTURE.md` for the full picture):
//!
//! 1. Pick an input: with probability 4/5 mutate a corpus sequence (when the
//!    corpus is non-empty and coverage guidance is on), otherwise generate a
//!    fresh random sequence.
//! 2. Execute it from genesis, recording branch coverage and comparison
//!    operands; check the assertion oracle after every call and the
//!    invariants after every successful call.
//! 3. If a call produced new coverage, keep the prefix up to that call in the
//!    corpus; feed comparison operands into the dictionary.
//! 4. On a violation, shrink the failing prefix, replay it with tracing,
//!    record a [`Finding`] and stop checking that oracle.
//!
//! Everything is deterministic given the seed and the transaction budget.

pub mod campaign;
pub mod coverage;
pub mod exec;
pub mod invariant;
pub mod mutate;
pub mod report;
pub mod sequence;
pub mod shrink;

use campaign::Campaign;
use exec::{oracle_name, Checks, Executor, Oracle, StepTrace};
use mutate::Generator;
use sequence::{Reproducer, Sequence};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Name of the built-in assertion oracle.
pub const ASSERTION_ORACLE: &str = "assertion";

/// Fuzzing parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FuzzConfig {
    /// RNG seed.
    pub seed: u64,
    /// Budget: transactions executed while fuzzing (shrinking not counted).
    pub max_tx: u64,
    /// Maximum calls per sequence.
    pub max_seq_len: usize,
    /// Keep inputs that reach new coverage and mutate them.
    pub coverage: bool,
    /// Use the value dictionary (bytecode constants + comparison operands).
    pub dictionary: bool,
    /// Check the assertion oracle (Panic 0x01 / INVALID).
    pub assertions: bool,
    /// Shrink failing sequences.
    pub shrink: bool,
    /// Maximum sequence executions per shrink.
    pub shrink_budget: usize,
    /// Optional wall-clock limit in milliseconds (makes runs timing-dependent).
    pub time_limit_ms: Option<u64>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        FuzzConfig {
            seed: 1,
            max_tx: 200_000,
            max_seq_len: 10,
            coverage: true,
            dictionary: true,
            assertions: true,
            shrink: true,
            shrink_budget: 5_000,
            time_limit_ms: None,
        }
    }
}

/// A broken property, shrunk and replayed.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Oracle name (invariant name or `assertion`).
    pub oracle: String,
    /// The property's source text.
    pub property: String,
    /// Explanation from the shrunk replay.
    pub message: String,
    /// Fuzzing transactions executed when the violation was first seen.
    pub found_at_tx: u64,
    /// Sequences executed when the violation was first seen.
    pub found_at_sequence: u64,
    /// Wall-clock milliseconds until discovery.
    pub found_after_ms: f64,
    /// Length of the failing prefix before shrinking.
    pub original_len: usize,
    /// Executions spent shrinking.
    pub shrink_executions: usize,
    /// Replay of the shrunk sequence.
    pub trace: Vec<StepTrace>,
    /// Machine-readable reproducer.
    pub reproducer: Reproducer,
}

/// Outcome of a campaign.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignReport {
    /// Campaign name.
    pub campaign: String,
    /// Parameters used.
    pub config: FuzzConfig,
    /// Fuzzing transactions executed.
    pub tx_executed: u64,
    /// Sequences executed.
    pub sequences: u64,
    /// Total wall-clock milliseconds (fuzzing + shrinking).
    pub elapsed_ms: f64,
    /// Milliseconds spent shrinking.
    pub shrink_ms: f64,
    /// Fuzzing throughput: transactions per second, shrinking excluded.
    pub tx_per_sec: f64,
    /// Corpus entries at the end.
    pub corpus_size: usize,
    /// Dictionary entries at the end.
    pub dictionary_size: usize,
    /// Distinct `JUMPI` directions covered in deployed code.
    pub branches_covered: usize,
    /// Total `JUMPI` directions in deployed code.
    pub branches_total: usize,
    /// Broken properties.
    pub findings: Vec<Finding>,
    /// Properties that held for the whole budget.
    pub holding: Vec<String>,
    /// Loader warnings.
    pub warnings: Vec<String>,
}

/// Periodic progress snapshot.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Transactions so far.
    pub tx: u64,
    /// Sequences so far.
    pub sequences: u64,
    /// Corpus size.
    pub corpus: usize,
    /// Covered `JUMPI` directions (all code).
    pub edges: usize,
    /// Findings so far.
    pub findings: usize,
    /// Elapsed time.
    pub elapsed: Duration,
}

fn property_text(c: &Campaign, o: Oracle) -> String {
    match o {
        Oracle::Invariant(i) => c.invariants[i].source.clone(),
        Oracle::Assertion => "no call fails an assert() (Panic 0x01 or INVALID)".into(),
    }
}

/// Runs a campaign. `progress` is called roughly once per second.
pub fn fuzz(c: &Campaign, cfg: &FuzzConfig, progress: &mut dyn FnMut(&Progress)) -> CampaignReport {
    let start = Instant::now();
    let mut exec = Executor::new(c);
    let mut gen = Generator::new(c, cfg.seed, cfg.dictionary, cfg.max_seq_len);
    let mut active = vec![true; c.invariants.len()];
    let mut assertions = cfg.assertions;
    let mut corpus: Vec<Sequence> = Vec::new();
    let mut findings = Vec::new();
    let (mut tx, mut sequences) = (0u64, 0u64);
    let mut shrink_time = Duration::ZERO;
    let mut last_report = Instant::now();
    let deadline = cfg.time_limit_ms.map(|ms| start + Duration::from_millis(ms));

    while tx < cfg.max_tx && (assertions || active.iter().any(|&a| a)) {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        let seq = if cfg.coverage && !corpus.is_empty() && gen.rng.chance(4, 5) {
            // Favour recent entries half the time: they tend to reach deeper states.
            let pick = if gen.rng.chance(1, 2) {
                corpus.len() - 1 - gen.rng.below(corpus.len().min(8))
            } else {
                gen.rng.below(corpus.len())
            };
            let base = corpus[pick].clone();
            let other = corpus[gen.rng.below(corpus.len())].clone();
            gen.mutate(&base, Some(&other))
        } else {
            gen.sequence()
        };
        let out = exec.run(&seq, Checks::Active { invariants: &active, assertions }, true, false);
        tx += out.executed as u64;
        sequences += 1;
        gen.learn(exec.cmp_values.drain(..));
        gen.learn_i2s(exec.i2s.drain(..));
        if cfg.coverage {
            if let Some(i) = out.last_new_coverage {
                corpus.push(seq[..=i].to_vec());
            }
        }
        if let Some(v) = out.violation {
            let t0 = Instant::now();
            let failing = &seq[..=v.step];
            let shrunk = if cfg.shrink {
                shrink::shrink(&mut exec, failing, v.oracle, cfg.shrink_budget)
            } else {
                let n = failing.len();
                (failing.to_vec(), shrink::ShrinkStats { executions: 0, original_len: n, final_len: n })
            };
            let replay = exec.run(&shrunk.0, Checks::Only(v.oracle), false, true);
            shrink_time += t0.elapsed();
            let name = oracle_name(c, v.oracle);
            log::info!(
                "{}: `{}` broken after {} tx; shrunk {} -> {} calls",
                c.name,
                name,
                tx,
                failing.len(),
                shrunk.0.len()
            );
            findings.push(Finding {
                oracle: name.clone(),
                property: property_text(c, v.oracle),
                message: replay.violation.map_or(v.message, |r| r.message),
                found_at_tx: tx,
                found_at_sequence: sequences,
                found_after_ms: t0.duration_since(start).as_secs_f64() * 1e3,
                original_len: failing.len(),
                shrink_executions: shrunk.1.executions,
                trace: replay.trace,
                reproducer: Reproducer::new(c, &name, &shrunk.0),
            });
            match v.oracle {
                Oracle::Invariant(i) => active[i] = false,
                Oracle::Assertion => assertions = false,
            }
        }
        if last_report.elapsed() >= Duration::from_secs(1) {
            last_report = Instant::now();
            progress(&Progress {
                tx,
                sequences,
                corpus: corpus.len(),
                edges: exec.evm.tracer.edges().len(),
                findings: findings.len(),
                elapsed: start.elapsed(),
            });
        }
    }

    let elapsed = start.elapsed();
    let fuzz_secs = (elapsed - shrink_time).as_secs_f64().max(1e-9);
    let mut holding: Vec<String> =
        c.invariants.iter().zip(&active).filter(|(_, &a)| a).map(|(i, _)| i.name.clone()).collect();
    if assertions {
        holding.push(ASSERTION_ORACLE.into());
    }
    let branches_covered = exec.evm.tracer.edges().iter().filter(|e| c.code_ids.contains(&e.0)).count();
    CampaignReport {
        campaign: c.name.clone(),
        config: cfg.clone(),
        tx_executed: tx,
        sequences,
        elapsed_ms: elapsed.as_secs_f64() * 1e3,
        shrink_ms: shrink_time.as_secs_f64() * 1e3,
        tx_per_sec: tx as f64 / fuzz_secs,
        corpus_size: corpus.len(),
        dictionary_size: gen.dict.len(),
        branches_covered,
        branches_total: c.branch_total,
        findings,
        holding,
        warnings: c.warnings.clone(),
    }
}

/// Replays a reproducer: returns the trace and the violation message if the
/// oracle is still broken.
pub fn replay(c: &Campaign, rep: &Reproducer) -> Result<(Vec<StepTrace>, Option<String>), String> {
    let oracle = exec::find_oracle(c, &rep.oracle).ok_or_else(|| format!("unknown oracle `{}`", rep.oracle))?;
    let seq = rep.to_sequence(c)?;
    let mut exec = Executor::new(c);
    let out = exec.run(&seq, Checks::Only(oracle), false, true);
    Ok((out.trace, out.violation.map(|v| v.message)))
}
