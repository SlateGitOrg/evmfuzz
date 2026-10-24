//! Evaluation harness: runs campaigns across seeds and fuzzer configurations
//! (ablations) and summarises how quickly each property was broken.
//!
//! Jobs are independent and run on a small thread pool; each job is
//! deterministic, so the summary does not depend on scheduling.

use crate::fuzz::campaign::Campaign;
use crate::fuzz::{fuzz, FuzzConfig};
use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A fuzzer configuration under evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mode {
    /// Coverage guidance and dictionary on (the default fuzzer).
    Full,
    /// Coverage guidance on, dictionary off.
    NoDictionary,
    /// Dictionary on, coverage guidance off (no corpus).
    NoCoverage,
    /// Neither: purely random sequences.
    Random,
}

impl Mode {
    /// Every mode.
    pub const ALL: [Mode; 4] = [Mode::Full, Mode::NoDictionary, Mode::NoCoverage, Mode::Random];

    /// Short name.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Full => "full",
            Mode::NoDictionary => "no-dict",
            Mode::NoCoverage => "no-cov",
            Mode::Random => "random",
        }
    }

    /// Parses a short name.
    pub fn parse(s: &str) -> Option<Mode> {
        Mode::ALL.into_iter().find(|m| m.name() == s)
    }

    /// Adjusts a configuration for this mode.
    pub fn apply(self, cfg: &mut FuzzConfig) {
        cfg.coverage = matches!(self, Mode::Full | Mode::NoDictionary);
        cfg.dictionary = matches!(self, Mode::Full | Mode::NoCoverage);
    }
}

/// Result of one (campaign, mode, seed) run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunResult {
    /// Campaign name.
    pub campaign: String,
    /// Mode name.
    pub mode: &'static str,
    /// Seed.
    pub seed: u64,
    /// `(oracle, tx at discovery, shrunk length)` per broken property.
    pub broken: Vec<(String, u64, usize)>,
    /// Properties that held.
    pub holding: Vec<String>,
    /// Fuzzing transactions executed.
    pub tx_executed: u64,
    /// Fuzzing throughput.
    pub tx_per_sec: f64,
}

/// Runs every combination on `jobs` threads.
pub fn run_matrix(campaigns: &[Campaign], modes: &[Mode], seeds: &[u64], base: &FuzzConfig, jobs: usize) -> Vec<RunResult> {
    let mut work = Vec::new();
    for c in 0..campaigns.len() {
        for &m in modes {
            for &s in seeds {
                work.push((c, m, s));
            }
        }
    }
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(work.len()));
    std::thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, 16) {
            std::thread::Builder::new()
                .stack_size(64 << 20)
                .spawn_scoped(scope, || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(c, mode, seed)) = work.get(i) else { break };
                    let mut cfg = base.clone();
                    cfg.seed = seed;
                    mode.apply(&mut cfg);
                    let r = fuzz(&campaigns[c], &cfg, &mut |_| {});
                    let res = RunResult {
                        campaign: r.campaign,
                        mode: mode.name(),
                        seed,
                        broken: r.findings.iter().map(|f| (f.oracle.clone(), f.found_at_tx, f.trace.len())).collect(),
                        holding: r.holding,
                        tx_executed: r.tx_executed,
                        tx_per_sec: r.tx_per_sec,
                    };
                    results.lock().expect("results lock").push((i, res));
                })
                .expect("spawn eval worker");
        }
    });
    let mut v = results.into_inner().expect("results lock");
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

/// Aggregated row: one (campaign, mode, oracle).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SummaryRow {
    /// Campaign.
    pub campaign: String,
    /// Mode.
    pub mode: &'static str,
    /// Oracle.
    pub oracle: String,
    /// Runs in which it was broken.
    pub found: usize,
    /// Total runs.
    pub runs: usize,
    /// Median transactions to discovery over successful runs.
    pub median_tx: Option<u64>,
    /// Maximum transactions to discovery over successful runs.
    pub max_tx: Option<u64>,
    /// Median shrunk length.
    pub median_len: Option<usize>,
}

fn median<T: Copy + Ord>(v: &mut [T]) -> Option<T> {
    if v.is_empty() {
        return None;
    }
    v.sort();
    Some(v[(v.len() - 1) / 2])
}

/// Groups results by (campaign, mode, oracle). Oracles that were never broken
/// in any run of a campaign appear with `found = 0`.
pub fn summarize(results: &[RunResult]) -> Vec<SummaryRow> {
    let mut keys: Vec<(String, &'static str)> = Vec::new();
    for r in results {
        if !keys.iter().any(|(c, m)| *c == r.campaign && *m == r.mode) {
            keys.push((r.campaign.clone(), r.mode));
        }
    }
    let mut rows = Vec::new();
    for (camp, mode) in keys {
        let runs: Vec<&RunResult> = results.iter().filter(|r| r.campaign == camp && r.mode == mode).collect();
        let mut oracles: Vec<String> = Vec::new();
        for r in results.iter().filter(|r| r.campaign == camp) {
            for o in r.broken.iter().map(|b| &b.0).chain(r.holding.iter()) {
                if !oracles.contains(o) {
                    oracles.push(o.clone());
                }
            }
        }
        for o in oracles {
            let hits: Vec<&(String, u64, usize)> = runs.iter().flat_map(|r| r.broken.iter()).filter(|b| b.0 == o).collect();
            let mut txs: Vec<u64> = hits.iter().map(|b| b.1).collect();
            let mut lens: Vec<usize> = hits.iter().map(|b| b.2).collect();
            rows.push(SummaryRow {
                campaign: camp.clone(),
                mode,
                oracle: o,
                found: hits.len(),
                runs: runs.len(),
                median_tx: median(&mut txs),
                max_tx: txs.iter().max().copied(),
                median_len: median(&mut lens),
            });
        }
    }
    rows
}

/// Renders summary rows as a Markdown table.
pub fn render_markdown(rows: &[SummaryRow]) -> String {
    let mut s = String::from("| campaign | mode | property | broken | median tx | max tx | median shrunk len |\n");
    s.push_str("|---|---|---|---|---:|---:|---:|\n");
    let opt = |v: Option<u64>| v.map_or("-".to_string(), |x| x.to_string());
    for r in rows {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {}/{} | {} | {} | {} |",
            r.campaign,
            r.mode,
            r.oracle,
            r.found,
            r.runs,
            opt(r.median_tx),
            opt(r.max_tx),
            opt(r.median_len.map(|l| l as u64))
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(camp: &str, mode: &'static str, broken: Vec<(&str, u64, usize)>, holding: Vec<&str>) -> RunResult {
        RunResult {
            campaign: camp.into(),
            mode,
            seed: 0,
            broken: broken.into_iter().map(|(o, t, l)| (o.to_string(), t, l)).collect(),
            holding: holding.into_iter().map(String::from).collect(),
            tx_executed: 10,
            tx_per_sec: 1.0,
        }
    }

    #[test]
    fn modes_round_trip_and_apply() {
        for m in Mode::ALL {
            assert_eq!(Mode::parse(m.name()), Some(m));
        }
        assert_eq!(Mode::parse("bogus"), None);
        let mut cfg = FuzzConfig::default();
        Mode::Random.apply(&mut cfg);
        assert!(!cfg.coverage && !cfg.dictionary);
        Mode::NoDictionary.apply(&mut cfg);
        assert!(cfg.coverage && !cfg.dictionary);
    }

    #[test]
    fn summary_medians_and_markdown() {
        let results = vec![
            rr("t", "full", vec![("inv", 100, 1)], vec![]),
            rr("t", "full", vec![("inv", 300, 3)], vec![]),
            rr("t", "full", vec![], vec!["inv"]),
            rr("t", "random", vec![], vec!["inv"]),
        ];
        let rows = summarize(&results);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].found, 2);
        assert_eq!(rows[0].runs, 3);
        assert_eq!(rows[0].median_tx, Some(100));
        assert_eq!(rows[0].max_tx, Some(300));
        assert_eq!(rows[1].found, 0);
        assert_eq!(rows[1].median_tx, None);
        let md = render_markdown(&rows);
        assert!(md.contains("| t | full | inv | 2/3 | 100 | 300 | 1 |"));
        assert!(md.contains("| t | random | inv | 0/1 | - | - | - |"));
    }
}
