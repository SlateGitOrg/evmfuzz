//! `evmfuzz` command-line interface.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use evmfuzz::evm::{
    self, opcode::disassemble, Account, BlockEnv, CallKind, CallMessage, Evm, StepRecorder, WorldState,
};
use evmfuzz::fuzz::campaign::Campaign;
use evmfuzz::fuzz::sequence::Reproducer;
use evmfuzz::fuzz::{self, report, FuzzConfig};
use evmfuzz::statetest::{self, Summary, Verdict};
use evmfuzz::types::{decode_hex, encode_hex, Address};
use evmfuzz::{abi, bench, eval, U256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "evmfuzz", version, about = "Shanghai EVM interpreter and stateful invariant fuzzer")]
struct Cli {
    /// Log verbosity (-v info, -vv debug).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run ethereum/tests GeneralStateTests (a file or a directory tree).
    Statetest {
        /// Test file or directory.
        path: PathBuf,
        /// Fork section to check.
        #[arg(long, default_value = "Shanghai")]
        fork: String,
        /// Print every non-passing case.
        #[arg(long)]
        show_unsupported: bool,
    },
    /// Fuzz a campaign; exits with status 1 if a property is broken.
    Fuzz {
        /// Campaign TOML file.
        campaign: PathBuf,
        #[command(flatten)]
        opts: FuzzOpts,
        /// Write the full report as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Directory for reproducer files (one JSON per broken property).
        #[arg(long)]
        save_dir: Option<PathBuf>,
    },
    /// Replay a saved reproducer; exits 0 if it still breaks its property, 1 if not.
    Replay {
        /// Campaign TOML file.
        campaign: PathBuf,
        /// Reproducer JSON.
        reproducer: PathBuf,
    },
    /// Run campaigns across seeds and ablation modes and summarise.
    Eval {
        /// Campaign TOML files.
        #[arg(required = true)]
        campaigns: Vec<PathBuf>,
        /// Seed range, e.g. `1001..=1020`.
        #[arg(long, default_value = "1001..=1020")]
        seeds: String,
        /// Comma-separated modes: full, no-dict, no-cov, random.
        #[arg(long, default_value = "full,no-dict,no-cov,random")]
        modes: String,
        /// Transaction budget per run.
        #[arg(long, default_value_t = 100_000)]
        max_tx: u64,
        /// Worker threads.
        #[arg(long, default_value_t = 3)]
        jobs: usize,
        /// Write per-run results as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Measure interpreter and fuzzing throughput.
    Bench {
        /// Campaigns for the fuzzing benchmark.
        campaigns: Vec<PathBuf>,
        /// Loop-count multiplier for interpreter workloads.
        #[arg(long, default_value_t = 1)]
        scale: u32,
        /// Repetitions per measurement (median reported).
        #[arg(long, default_value_t = 5)]
        reps: usize,
        /// Transactions per fuzzing measurement.
        #[arg(long, default_value_t = 50_000)]
        fuzz_tx: u64,
    },
    /// Execute raw bytecode as a contract and print the result.
    Run {
        /// Runtime code as hex, or @file containing hex.
        code: String,
        /// Calldata as hex.
        #[arg(long, default_value = "0x")]
        input: String,
        /// Gas limit.
        #[arg(long, default_value_t = 10_000_000)]
        gas: u64,
        /// Print up to N executed instructions.
        #[arg(long, default_value_t = 0)]
        trace: usize,
    },
    /// Disassemble bytecode (hex or @file).
    Disasm {
        /// Code as hex, or @file containing hex.
        code: String,
    },
}

#[derive(clap::Args)]
struct FuzzOpts {
    /// RNG seed (default: campaign file, else 1).
    #[arg(long)]
    seed: Option<u64>,
    /// Transaction budget (default: campaign file, else 200000).
    #[arg(long)]
    max_tx: Option<u64>,
    /// Maximum calls per sequence.
    #[arg(long)]
    max_seq_len: Option<usize>,
    /// Wall-clock limit in seconds (results then depend on machine speed).
    #[arg(long)]
    time_limit: Option<u64>,
    /// Disable coverage guidance (no corpus).
    #[arg(long)]
    no_coverage: bool,
    /// Disable the value dictionary.
    #[arg(long)]
    no_dictionary: bool,
    /// Do not shrink failing sequences.
    #[arg(long)]
    no_shrink: bool,
    /// Do not treat failed assert() as a violation.
    #[arg(long)]
    no_assertions: bool,
}

impl FuzzOpts {
    fn config(&self, c: &Campaign) -> FuzzConfig {
        let mut cfg = c.defaults.clone();
        if let Some(s) = self.seed {
            cfg.seed = s;
        }
        if let Some(m) = self.max_tx {
            cfg.max_tx = m;
        }
        if let Some(l) = self.max_seq_len {
            cfg.max_seq_len = l.max(1);
        }
        cfg.time_limit_ms = self.time_limit.map(|s| s * 1000);
        cfg.coverage &= !self.no_coverage;
        cfg.dictionary &= !self.no_dictionary;
        cfg.shrink &= !self.no_shrink;
        cfg.assertions &= !self.no_assertions;
        cfg
    }
}

fn load_campaign(path: &Path) -> Result<Campaign> {
    Campaign::load(path).with_context(|| format!("loading campaign {}", path.display()))
}

fn read_code(arg: &str) -> Result<Vec<u8>> {
    let text = match arg.strip_prefix('@') {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?,
        None => arg.to_string(),
    };
    decode_hex(text.trim()).context("code is not valid hex")
}

fn parse_seeds(s: &str) -> Result<Vec<u64>> {
    let (lo, hi, inclusive) = if let Some((a, b)) = s.split_once("..=") {
        (a, b, true)
    } else if let Some((a, b)) = s.split_once("..") {
        (a, b, false)
    } else {
        return s.split(',').map(|x| x.trim().parse::<u64>().context("bad seed")).collect();
    };
    let lo: u64 = lo.trim().parse().context("bad seed range")?;
    let hi: u64 = hi.trim().parse().context("bad seed range")?;
    let hi = if inclusive { hi } else { hi.saturating_sub(1) };
    if lo > hi {
        bail!("empty seed range `{s}`");
    }
    Ok((lo..=hi).collect())
}

fn cmd_statetest(path: &Path, fork: String, show_unsupported: bool) -> Result<ExitCode> {
    let files = statetest::collect_json(path).with_context(|| format!("listing {}", path.display()))?;
    if files.is_empty() {
        bail!("no .json test files under {}", path.display());
    }
    let root = path.to_path_buf();
    let (per_suite, total, lines) = evm::run_with_big_stack(move || -> Result<_> {
        let mut per_suite: BTreeMap<String, Summary> = BTreeMap::new();
        let mut total = Summary::default();
        let mut lines = Vec::new();
        for f in &files {
            let tests = statetest::load_file(f)?;
            let rel = f.strip_prefix(&root).unwrap_or(f);
            let suite = rel.parent().map_or_else(|| ".".into(), |p| p.display().to_string());
            let entry = per_suite.entry(suite).or_default();
            for o in statetest::run_tests(&tests, &fork, entry) {
                match &o.verdict {
                    Verdict::Pass => {}
                    Verdict::Fail { expected_root, got_root, .. } => lines.push(format!(
                        "FAIL {} {} {:?}: root {} != expected {}",
                        rel.display(),
                        o.name,
                        o.indexes,
                        got_root,
                        expected_root
                    )),
                    Verdict::Unsupported(why) if show_unsupported => {
                        lines.push(format!("UNSUPPORTED {} {} {:?}: {why}", rel.display(), o.name, o.indexes));
                    }
                    Verdict::Unsupported(_) => {}
                }
                total.record(&o.verdict);
            }
        }
        for s in per_suite.values() {
            total.skipped_tests += s.skipped_tests;
        }
        Ok((per_suite, total, lines))
    })?;
    for l in &lines {
        println!("{l}");
    }
    println!("{:<52} {:>7} {:>7} {:>12} {:>14}", "suite", "pass", "fail", "unsupported", "no-fork-entry");
    for (suite, s) in &per_suite {
        println!("{:<52} {:>7} {:>7} {:>12} {:>14}", suite, s.passed, s.failed, s.unsupported, s.skipped_tests);
    }
    println!(
        "{:<52} {:>7} {:>7} {:>12} {:>14}",
        "TOTAL", total.passed, total.failed, total.unsupported, total.skipped_tests
    );
    Ok(if total.failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn cmd_fuzz(path: &Path, opts: &FuzzOpts, json: Option<PathBuf>, save_dir: Option<PathBuf>) -> Result<ExitCode> {
    let c = load_campaign(path)?;
    let cfg = opts.config(&c);
    let report = evm::run_with_big_stack(move || {
        fuzz::fuzz(&c, &cfg, &mut |p| {
            log::info!(
                "{} tx, {} seq, corpus {}, edges {}, findings {} ({:.1}s)",
                p.tx,
                p.sequences,
                p.corpus,
                p.edges,
                p.findings,
                p.elapsed.as_secs_f64()
            );
        })
    });
    print!("{}", report::render(&report));
    if let Some(p) = json {
        std::fs::write(&p, serde_json::to_string_pretty(&report)?).with_context(|| format!("writing {}", p.display()))?;
    }
    if let Some(dir) = save_dir {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        for f in &report.findings {
            let p = dir.join(format!("{}-{}.json", report.campaign, f.oracle));
            std::fs::write(&p, serde_json::to_string_pretty(&f.reproducer)?)
                .with_context(|| format!("writing {}", p.display()))?;
            println!("  reproducer: {}", p.display());
        }
    }
    Ok(if report.findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn cmd_replay(campaign: &Path, repro: &Path) -> Result<ExitCode> {
    let c = load_campaign(campaign)?;
    let text = std::fs::read_to_string(repro).with_context(|| format!("reading {}", repro.display()))?;
    let rep: Reproducer = serde_json::from_str(&text).context("parsing reproducer")?;
    if rep.campaign != c.name {
        log::warn!("reproducer was recorded for campaign `{}`, replaying against `{}`", rep.campaign, c.name);
    }
    let (trace, violation) = evm::run_with_big_stack(move || fuzz::replay(&c, &rep)).map_err(anyhow::Error::msg)?;
    for (i, t) in trace.iter().enumerate() {
        println!("{}. {}  => {} (gas {})", i + 1, t.call, t.outcome, t.gas_used);
    }
    Ok(match violation {
        Some(msg) => {
            println!("REPRODUCED: {msg}");
            ExitCode::SUCCESS
        }
        None => {
            println!("NOT REPRODUCED: property holds after replay");
            ExitCode::FAILURE
        }
    })
}

fn cmd_eval(campaigns: &[PathBuf], seeds: &str, modes: &str, max_tx: u64, jobs: usize, json: Option<PathBuf>) -> Result<()> {
    let seeds = parse_seeds(seeds)?;
    let modes = modes
        .split(',')
        .map(|m| eval::Mode::parse(m.trim()).with_context(|| format!("unknown mode `{m}`")))
        .collect::<Result<Vec<_>>>()?;
    let loaded = campaigns.iter().map(|p| load_campaign(p)).collect::<Result<Vec<_>>>()?;
    let base = FuzzConfig { max_tx, ..FuzzConfig::default() };
    let n = loaded.len() * modes.len() * seeds.len();
    eprintln!("running {n} campaigns ({} seeds x {} modes x {} fixtures) on {jobs} threads", seeds.len(), modes.len(), loaded.len());
    let t = std::time::Instant::now();
    let results = eval::run_matrix(&loaded, &modes, &seeds, &base, jobs);
    eprintln!("done in {:.1}s", t.elapsed().as_secs_f64());
    print!("{}", eval::render_markdown(&eval::summarize(&results)));
    if let Some(p) = json {
        std::fs::write(&p, serde_json::to_string_pretty(&results)?).with_context(|| format!("writing {}", p.display()))?;
    }
    Ok(())
}

fn cmd_bench(campaigns: &[PathBuf], scale: u32, reps: usize, fuzz_tx: u64) -> Result<()> {
    let loaded = campaigns.iter().map(|p| load_campaign(p)).collect::<Result<Vec<_>>>()?;
    let (interp, fz) = evm::run_with_big_stack(move || {
        let interp = bench::interpreter(scale, reps);
        let fz: Vec<_> = loaded.iter().flat_map(|c| bench::fuzzing(c, fuzz_tx, reps)).collect();
        (interp, fz)
    });
    println!("interpreter (median of {reps} runs)");
    println!("{:<12} {:>14} {:>14} {:>10} {:>10} {:>10}", "workload", "gas", "instructions", "ms", "Mgas/s", "M instr/s");
    for b in &interp {
        println!(
            "{:<12} {:>14} {:>14} {:>10.2} {:>10.1} {:>10.1}",
            b.name,
            b.gas,
            b.instructions,
            b.secs * 1e3,
            b.mgas_per_sec(),
            b.mips()
        );
    }
    if !fz.is_empty() {
        println!("\nfuzzing executions (random sequences, coverage + cmp logging on, median of {reps} runs)");
        println!("{:<14} {:>11} {:>10} {:>10} {:>10} {:>12}", "campaign", "invariants", "tx", "seqs", "ms", "tx/s");
        for b in &fz {
            println!(
                "{:<14} {:>11} {:>10} {:>10} {:>10.1} {:>12.0}",
                b.campaign,
                if b.invariants { "checked" } else { "off" },
                b.tx,
                b.sequences,
                b.secs * 1e3,
                b.tx_per_sec()
            );
        }
    }
    Ok(())
}

fn cmd_run(code: &str, input: &str, gas: u64, trace: usize) -> Result<()> {
    let code = read_code(code)?;
    let input = decode_hex(input).context("input is not valid hex")?;
    let target = Address::from_low_u64(0xc0de);
    let mut ws = WorldState::new();
    ws.insert(target, Account::with_code(code));
    let (r, rec) = evm::run_with_big_stack(move || {
        let mut evm = Evm::with_tracer(ws, BlockEnv::default(), StepRecorder::with_limit(trace));
        let r = evm.call_message(&CallMessage {
            kind: CallKind::Call,
            caller: Address::from_low_u64(0xca11e4),
            target,
            code_address: target,
            value: U256::ZERO,
            input,
            gas,
            is_static: false,
            depth: 0,
        });
        (r, evm.tracer)
    });
    for s in &rec.steps {
        let stack: Vec<String> = s.stack_top.iter().map(|v| format!("{v:#x}")).collect();
        println!("{:>2} {:>5} {:<14} gas={:<10} stack(top)=[{}]", s.depth, s.pc, s.op, s.gas, stack.join(", "));
    }
    if rec.dropped > 0 {
        println!("... {} more steps", rec.dropped);
    }
    println!("status:   {:?}", r.status);
    println!("gas used: {}", gas - r.gas_left);
    println!("output:   {}", encode_hex(&r.output));
    if let Some(reason) = abi::decode_revert(&r.output) {
        println!("decoded:  {reason}");
    }
    Ok(())
}

fn cmd_disasm(code: &str) -> Result<()> {
    for (pc, name, imm) in disassemble(&read_code(code)?) {
        if imm.is_empty() {
            println!("{pc:>5}  {name}");
        } else {
            println!("{pc:>5}  {name} {}", encode_hex(&imm));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
    let res = match cli.cmd {
        Cmd::Statetest { path, fork, show_unsupported } => cmd_statetest(&path, fork, show_unsupported),
        Cmd::Fuzz { campaign, opts, json, save_dir } => cmd_fuzz(&campaign, &opts, json, save_dir),
        Cmd::Replay { campaign, reproducer } => cmd_replay(&campaign, &reproducer),
        Cmd::Eval { campaigns, seeds, modes, max_tx, jobs, json } => {
            cmd_eval(&campaigns, &seeds, &modes, max_tx, jobs, json).map(|_| ExitCode::SUCCESS)
        }
        Cmd::Bench { campaigns, scale, reps, fuzz_tx } => {
            cmd_bench(&campaigns, scale, reps, fuzz_tx).map(|_| ExitCode::SUCCESS)
        }
        Cmd::Run { code, input, gas, trace } => cmd_run(&code, &input, gas, trace).map(|_| ExitCode::SUCCESS),
        Cmd::Disasm { code } => cmd_disasm(&code).map(|_| ExitCode::SUCCESS),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_ranges() {
        assert_eq!(parse_seeds("1..=3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_seeds("1..3").unwrap(), vec![1, 2]);
        assert_eq!(parse_seeds("5, 9").unwrap(), vec![5, 9]);
        assert!(parse_seeds("3..=1").is_err());
        assert!(parse_seeds("x").is_err());
    }
}
