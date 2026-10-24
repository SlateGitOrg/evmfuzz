//! Conformance: the pinned ethereum/tests subset (tests/ethtests) must pass.
//!
//! Every Shanghai case either passes (post-state root and logs hash match)
//! or is reported as unsupported because it reaches a precompile this
//! interpreter does not implement. The expected counts are pinned so a
//! regression that turns a pass into "unsupported" is caught too.
//!
//! The loop-heavy `vmPerformance` suite lives in its own `slow_` test so the
//! instrumented coverage run (`make cov`) can skip it; `make test` runs it.

use evmfuzz::statetest::{collect_json, load_file, run_tests, Summary, Verdict};
use std::path::Path;

/// Runs every file under `rel` whose path passes `keep`.
fn run_dir(rel: &str, keep: fn(&Path) -> bool) -> (Summary, Vec<String>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    evmfuzz::evm::run_with_big_stack(move || {
        let mut s = Summary::default();
        let mut failures = Vec::new();
        for f in collect_json(&root).expect("list fixtures").into_iter().filter(|f| keep(f)) {
            let tests = load_file(&f).expect("parse fixture");
            for o in run_tests(&tests, "Shanghai", &mut s) {
                if let Verdict::Fail { .. } = o.verdict {
                    failures.push(format!("{} {} {:?}", f.display(), o.name, o.indexes));
                }
            }
        }
        (s, failures)
    })
}

fn is_perf(p: &Path) -> bool {
    p.components().any(|c| c.as_os_str() == "vmPerformance")
}

#[test]
fn vm_tests_all_pass() {
    let (s, failures) = run_dir("tests/ethtests/GeneralStateTests/VMTests", |p| !is_perf(p));
    assert!(failures.is_empty(), "failures: {failures:#?}");
    assert_eq!(s.unsupported, 0);
    assert!(s.passed >= 500, "{s:?}");
}

#[test]
fn general_state_tests_subset_matches_pinned_counts() {
    let (s, failures) = run_dir("tests/ethtests/GeneralStateTests", |p| !is_perf(p));
    assert!(failures.is_empty(), "failures: {failures:#?}");
    assert_eq!(s, Summary { passed: 2324, failed: 0, unsupported: 54, skipped_tests: 35 }, "{s:?}");
}

#[test]
fn slow_vm_performance_suite_passes() {
    let (s, failures) = run_dir("tests/ethtests/GeneralStateTests/VMTests/vmPerformance", |_| true);
    assert!(failures.is_empty(), "failures: {failures:#?}");
    assert_eq!(s, Summary { passed: 23, failed: 0, unsupported: 0, skipped_tests: 0 }, "{s:?}");
}
