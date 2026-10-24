//! Component tests for generation, mutation, execution and shrinking,
//! driven through a real fixture campaign.

use evmfuzz::abi::{width_mask, AbiType, AbiValue};
use evmfuzz::fuzz::campaign::Campaign;
use evmfuzz::fuzz::exec::{find_oracle, Checks, Executor, Oracle};
use evmfuzz::fuzz::mutate::Generator;
use evmfuzz::fuzz::sequence::{Call, Reproducer, DEFAULT_WARP};
use evmfuzz::fuzz::shrink::shrink;
use evmfuzz::U256;
use proptest::prelude::*;
use std::path::Path;
use std::sync::OnceLock;

fn campaign(name: &str) -> &'static Campaign {
    static TOKEN: OnceLock<Campaign> = OnceLock::new();
    static REGISTRY: OnceLock<Campaign> = OnceLock::new();
    let cell = match name {
        "token" => &TOKEN,
        "registry" => &REGISTRY,
        _ => unreachable!(),
    };
    cell.get_or_init(|| {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name).join("campaign.toml");
        Campaign::load(&p).unwrap()
    })
}

fn fits(ty: &AbiType, v: &AbiValue, c: &Campaign) -> bool {
    match (ty, v) {
        (AbiType::Uint(b), AbiValue::Uint(x)) => *x <= width_mask(*b),
        (AbiType::Int(_), AbiValue::Int(_)) | (AbiType::Bool, AbiValue::Bool(_)) => true,
        (AbiType::Address, AbiValue::Address(a)) => c.names.pool().contains(a),
        _ => false,
    }
}

fn call_named(c: &Campaign, sender: usize, sig: &str, args: Vec<AbiValue>) -> Call {
    let target = c.find_target(sig).unwrap_or_else(|| panic!("no target {sig}"));
    Call { sender, target, args, value: U256::ZERO, warp: DEFAULT_WARP }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn generated_and_mutated_sequences_are_well_typed(seed in any::<u64>(), max_len in 1usize..12) {
        let c = campaign("token");
        let mut g = Generator::new(c, seed, true, max_len);
        g.learn([U256::from_u64(1000), U256::MAX]);
        let mut seq = g.sequence();
        for _ in 0..20 {
            prop_assert!(!seq.is_empty() && seq.len() <= max_len);
            for call in &seq {
                let t = &c.targets[call.target];
                prop_assert!(call.sender < c.names.actors.len());
                prop_assert_eq!(call.args.len(), t.func.inputs.len());
                for (ty, v) in t.func.inputs.iter().zip(&call.args) {
                    prop_assert!(fits(ty, v, c), "{} does not fit {}", v, ty);
                }
                prop_assert!(t.func.encode_call(&call.args).is_ok());
                prop_assert!(call.value.is_zero() || t.func.payable);
            }
            let other = g.sequence();
            seq = g.mutate(&seq, Some(&other));
        }
    }

    #[test]
    fn shrinking_preserves_the_violation_and_never_grows(seed in 0u64..40) {
        let c = campaign("token");
        let mut g = Generator::new(c, seed, true, 8);
        let mut exec = Executor::new(c);
        let oracle = find_oracle(c, "supply-conservation").unwrap();
        // Random prefix + the bug trigger + random suffix.
        let mut seq = g.sequence();
        seq.push(call_named(c, 0, "Token.transfer(address,uint256)", vec![
            AbiValue::Address(c.names.actors[0]), U256::ONE.into_value(),
        ]));
        seq.extend(g.sequence());
        let out = exec.run(&seq, Checks::Only(oracle), false, false);
        prop_assume!(out.violation.is_some());
        let (best, stats) = shrink(&mut exec, &seq, oracle, 2_000);
        prop_assert!(best.len() <= stats.original_len);
        prop_assert!(stats.original_len <= seq.len());
        let again = exec.run(&best, Checks::Only(oracle), false, false);
        prop_assert_eq!(again.violation.map(|v| v.step), Some(best.len() - 1));
    }
}

trait IntoValue {
    fn into_value(self) -> AbiValue;
}

impl IntoValue for U256 {
    fn into_value(self) -> AbiValue {
        AbiValue::Uint(self)
    }
}

#[test]
fn zero_amount_self_transfer_is_harmless_but_one_is_not() {
    let c = campaign("token");
    let mut exec = Executor::new(c);
    let oracle = find_oracle(c, "supply-conservation").unwrap();
    let t = |amt: u64| {
        vec![call_named(
            c,
            0,
            "Token.transfer(address,uint256)",
            vec![AbiValue::Address(c.names.actors[0]), AbiValue::Uint(U256::from_u64(amt))],
        )]
    };
    assert!(exec.run(&t(0), Checks::Only(oracle), false, false).violation.is_none());
    let out = exec.run(&t(5), Checks::Only(oracle), false, true);
    let v = out.violation.expect("violation");
    assert_eq!(v.step, 0);
    assert_eq!(v.oracle, Oracle::Invariant(0));
    assert_eq!(out.trace[0].outcome, "ok");
    // Shrinking finds the minimal amount by binary search.
    let (best, stats) = shrink(&mut exec, &t(1 << 19), oracle, 1_000);
    assert_eq!(best[0].args[1], AbiValue::Uint(U256::ONE));
    assert!(stats.executions > 2);
}

#[test]
fn feedback_runs_record_coverage_and_comparisons() {
    let c = campaign("registry");
    let mut exec = Executor::new(c);
    let active = vec![];
    let seq = vec![
        call_named(c, 0, "Registry.configure(uint32)", vec![AbiValue::Uint(U256::from_u64(77))]),
        call_named(
            c,
            1,
            "Registry.store(uint32,uint32)",
            vec![AbiValue::Uint(U256::from_u64(5)), AbiValue::Uint(U256::from_u64(6))],
        ),
    ];
    let out = exec.run(&seq, Checks::Active { invariants: &active, assertions: true }, true, false);
    assert!(out.violation.is_none());
    assert_eq!(out.executed, 2);
    assert!(out.last_new_coverage.is_some());
    // store(5, ..) compared 5 against the configured id 77: an input-to-state hint for argument 0.
    assert!(exec.i2s.iter().any(|&(_, w, v)| w == 0 && v == U256::from_u64(77)), "{:?}", exec.i2s);
    // Our own argument values are filtered out of the dictionary feed.
    assert!(!exec.cmp_values.contains(&U256::from_u64(5)));
    // A second identical run adds no new coverage.
    let again = exec.run(&seq, Checks::Active { invariants: &active, assertions: true }, true, false);
    assert!(again.last_new_coverage.is_none());
}

#[test]
fn insufficient_funds_calls_are_reported_not_executed() {
    let c = campaign("token");
    let mut exec = Executor::new(c);
    let mut call = call_named(c, 0, "Token.burn(uint256)", vec![AbiValue::Uint(U256::ONE)]);
    call.value = U256::MAX;
    let out = exec.run(&[call], Checks::Only(Oracle::Assertion), false, true);
    assert!(out.trace[0].outcome.starts_with("invalid:"), "{:?}", out.trace);
    // A reproducer naming the call round-trips through text.
    let rep = Reproducer::new(
        c,
        "assertion",
        &[call_named(
            c,
            2,
            "Token.approve(address,uint256)",
            vec![AbiValue::Address(c.contracts[0].address), AbiValue::Uint(U256::from_u64(9))],
        )],
    );
    assert_eq!(rep.calls[0].args, vec!["Token".to_string(), "9".to_string()]);
    assert_eq!(rep.to_sequence(c).unwrap()[0].sender, 2);
    let mut bad = rep.clone();
    bad.calls[0].sender = "bob".into();
    assert!(bad.to_sequence(c).is_err());
    let mut bad = rep.clone();
    bad.calls[0].args.pop();
    assert!(bad.to_sequence(c).is_err());
    let mut bad = rep;
    bad.calls[0].value = "x".into();
    assert!(bad.to_sequence(c).is_err());
}
