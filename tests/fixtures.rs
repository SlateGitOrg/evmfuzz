//! End-to-end fuzzing of the bundled fixtures: every planted violation is
//! found within the documented budget, shrunk to its minimal form, and the
//! bug-free control stays clean.

use evmfuzz::fuzz::campaign::Campaign;
use evmfuzz::fuzz::sequence::Reproducer;
use evmfuzz::fuzz::{fuzz, replay, CampaignReport, FuzzConfig};
use std::path::{Path, PathBuf};

/// The budget documented in the README for the default configuration.
const BUDGET: u64 = 100_000;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name).join("campaign.toml")
}

fn load(name: &str) -> Campaign {
    Campaign::load(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn run(c: &Campaign, seed: u64, max_tx: u64) -> CampaignReport {
    let cfg = FuzzConfig { seed, max_tx, ..c.defaults.clone() };
    fuzz(c, &cfg, &mut |_| {})
}

fn finding_calls(r: &CampaignReport, oracle: &str) -> Vec<String> {
    let f = r.findings.iter().find(|f| f.oracle == oracle).unwrap_or_else(|| panic!("{oracle} not broken: {r:#?}"));
    assert!(f.found_at_tx <= BUDGET);
    f.trace.iter().map(|t| t.call.clone()).collect()
}

#[test]
fn token_self_transfer_is_found_and_shrunk_to_one_call() {
    let c = load("token");
    let r = run(&c, 1, BUDGET);
    assert_eq!(finding_calls(&r, "supply-conservation"), vec!["actor0 -> Token.transfer(actor0, 1)"]);
    assert_eq!(finding_calls(&r, "no-balance-above-supply"), vec!["actor0 -> Token.transfer(actor0, 1)"]);
    let f = &r.findings[0];
    assert!(f.message.contains("lhs = 1000000, rhs = 1000001"), "{}", f.message);
    assert!(r.holding.contains(&"assertion".to_string()));
    assert!(r.branches_covered > 0 && r.branches_covered <= r.branches_total);
}

#[test]
fn bug_free_control_has_no_findings() {
    let c = load("token-fixed");
    let r = run(&c, 1, 30_000);
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
    assert_eq!(r.holding.len(), 3);
    assert!(r.tx_executed >= 30_000);
}

#[test]
fn vault_magic_backdoor_needs_and_gets_the_dictionary() {
    let c = load("vault");
    let r = run(&c, 1, BUDGET);
    let calls = finding_calls(&r, "solvency");
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[2].contains("emergencyExit(6840335473037917935)"), "{calls:?}"); // 0x5eedc0defeedbeef
    assert!(r.holding.contains(&"deposits-add-up".to_string()));
    // Without value feedback the 64-bit magic is out of reach in the same budget.
    let cfg = FuzzConfig { seed: 1, max_tx: 20_000, dictionary: false, ..c.defaults.clone() };
    let blind = fuzz(&c, &cfg, &mut |_| {});
    assert!(blind.findings.is_empty());
}

#[test]
fn staged_state_machine_needs_five_calls() {
    let c = load("staged");
    let r = run(&c, 1, BUDGET);
    let calls = finding_calls(&r, "payout-capped");
    assert_eq!(
        calls,
        vec![
            "actor0 -> Staged.unlock1(42)",
            "actor0 -> Staged.unlock2(1001)",
            "actor0 -> Staged.unlock3()",
            "actor0 -> Staged.payout()",
            "actor0 -> Staged.payout()",
        ]
    );
}

#[test]
fn registry_assertion_failure_with_linked_values_shrunk() {
    let c = load("registry");
    let r = run(&c, 1, BUDGET);
    let calls = finding_calls(&r, "assertion");
    assert_eq!(calls, vec!["actor0 -> Registry.configure(0)", "actor0 -> Registry.store(0, 2147483648)"]);
    let f = &r.findings[0];
    assert!(f.trace[1].outcome.contains("Panic(0x01"), "{:?}", f.trace);
}

#[test]
fn amm_cross_contract_desync() {
    let c = load("amm");
    assert_eq!(c.contracts.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), vec!["Pool", "TokenA", "TokenB"]);
    let r = run(&c, 1, BUDGET);
    let calls = finding_calls(&r, "reserve-b-backed");
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[0].ends_with("Pool.faucet()"));
    assert!(calls[3].contains("removeLiquidity"));
    for holds in ["reserve-a-backed", "shares-add-up"] {
        assert!(r.holding.contains(&holds.to_string()), "{holds}: {:?}", r.holding);
    }
}

#[test]
fn campaigns_are_deterministic_per_seed() {
    let c = load("vault");
    let a = run(&c, 7, 20_000);
    let b = run(&c, 7, 20_000);
    assert_eq!(a.tx_executed, b.tx_executed);
    assert_eq!(a.findings.len(), b.findings.len());
    for (x, y) in a.findings.iter().zip(&b.findings) {
        assert_eq!(x.found_at_tx, y.found_at_tx);
        assert_eq!(x.reproducer, y.reproducer);
    }
    let other = run(&c, 8, 20_000);
    let differs = other.tx_executed != a.tx_executed
        || other.findings.iter().zip(&a.findings).any(|(x, y)| x.found_at_tx != y.found_at_tx);
    assert!(differs || a.findings.is_empty(), "different seeds should explore differently");
}

#[test]
fn reproducers_round_trip_and_replay() {
    let c = load("amm");
    let r = run(&c, 3, BUDGET);
    let rep = &r.findings[0].reproducer;
    let json = serde_json::to_string(rep).unwrap();
    let back: Reproducer = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, rep);
    let (trace, violation) = replay(&c, &back).unwrap();
    assert_eq!(trace.len(), rep.calls.len());
    assert!(violation.is_some());
    // The same calls against the bug-free pool shape would not exist; against a
    // different campaign the function names do not resolve.
    let other = load("token");
    assert!(replay(&other, &back).is_err());
    let mut bad = back.clone();
    bad.oracle = "nope".into();
    assert!(replay(&c, &bad).unwrap_err().contains("unknown oracle"));
}

#[test]
fn time_limit_and_disabled_shrinking() {
    let c = load("token");
    let cfg = FuzzConfig { seed: 1, max_tx: 1_000_000, shrink: false, time_limit_ms: Some(1), ..c.defaults.clone() };
    let r = fuzz(&c, &cfg, &mut |_| {});
    assert!(r.tx_executed < 1_000_000);
    for f in &r.findings {
        assert_eq!(f.shrink_executions, 0);
        assert_eq!(f.trace.len(), f.original_len);
    }
}
