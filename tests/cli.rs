//! The command-line interface, exercised as a subprocess.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn evmfuzz(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evmfuzz")).args(args).current_dir(root()).output().expect("run evmfuzz")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("evmfuzz-cli-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn fuzz_save_and_replay() {
    let dir = scratch("fuzz");
    let json = dir.join("report.json");
    let o = evmfuzz(&[
        "fuzz",
        "fixtures/token/campaign.toml",
        "--max-tx",
        "20000",
        "--seed",
        "3",
        "--save-dir",
        dir.to_str().unwrap(),
        "--json",
        json.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    let out = stdout(&o);
    assert!(out.contains("BROKEN  supply-conservation"), "{out}");
    assert!(out.contains("reproducer:"), "{out}");
    let report: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    assert_eq!(report["campaign"], "token");
    let repro = dir.join("token-supply-conservation.json");
    let o = evmfuzz(&["replay", "fixtures/token/campaign.toml", repro.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("REPRODUCED"));
    // The fixed token has the same API, so the reproducer runs but no longer breaks the property.
    let o = evmfuzz(&["replay", "fixtures/token-fixed/campaign.toml", repro.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("NOT REPRODUCED"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fuzz_clean_campaign_exits_zero_with_ablation_flags() {
    let o = evmfuzz(&[
        "-v",
        "fuzz",
        "fixtures/token-fixed/campaign.toml",
        "--max-tx",
        "3000",
        "--no-coverage",
        "--no-dictionary",
        "--no-shrink",
        "--no-assertions",
        "--max-seq-len",
        "4",
        "--time-limit",
        "60",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains("coverage=off dictionary=off"), "{out}");
    assert!(out.contains("HOLDS   supply-conservation"));
}

#[test]
fn statetest_single_file_and_directory() {
    let o = evmfuzz(&["statetest", "tests/ethtests/GeneralStateTests/stShift", "--show-unsupported"]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains("TOTAL"), "{out}");
    assert!(!out.contains("FAIL "));
    let o = evmfuzz(&[
        "statetest",
        "tests/ethtests/GeneralStateTests/stReturnDataTest/modexp_modsize0_returndatasize.json",
        "--show-unsupported",
    ]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("UNSUPPORTED"));
    let o = evmfuzz(&["statetest", "fixtures"]);
    assert_eq!(o.status.code(), Some(2), "no json tests under fixtures/");
}

#[test]
fn run_and_disasm() {
    // PUSH1 2 PUSH1 3 ADD PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
    let code = "0x60026003015f5260205ff3";
    let o = evmfuzz(&["run", code, "--trace", "3"]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains("status:   Success"), "{out}");
    assert!(out.contains("0x0000000000000000000000000000000000000000000000000000000000000005"));
    assert!(out.contains("more steps"));
    // Revert with Error("x") is decoded.
    let o = evmfuzz(&["run", "@fixtures/staged/Staged.bin", "--input", "0x"]);
    assert_eq!(o.status.code(), Some(0));
    let o = evmfuzz(&["disasm", code]);
    let out = stdout(&o);
    assert!(out.contains("PUSH1 0x02") && out.contains("RETURN"), "{out}");
    let o = evmfuzz(&["disasm", "0xzz"]);
    assert_eq!(o.status.code(), Some(2));
    let o = evmfuzz(&["run", "@does/not/exist"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn eval_and_bench_smoke() {
    let dir = scratch("eval");
    let json = dir.join("eval.json");
    let o = evmfuzz(&[
        "eval",
        "fixtures/registry/campaign.toml",
        "--seeds",
        "1..=2",
        "--modes",
        "full,random",
        "--max-tx",
        "20000",
        "--jobs",
        "2",
        "--json",
        json.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains("| registry | full | assertion | 2/2 |"), "{out}");
    assert!(std::fs::read_to_string(&json).unwrap().contains("\"mode\": \"random\""));
    let o = evmfuzz(&["eval", "fixtures/registry/campaign.toml", "--modes", "bogus"]);
    assert_eq!(o.status.code(), Some(2));
    let o = evmfuzz(&["bench", "fixtures/token/campaign.toml", "--reps", "1", "--fuzz-tx", "300"]);
    assert_eq!(o.status.code(), Some(0));
    let out = stdout(&o);
    assert!(out.contains("arithmetic") && out.contains("staticcall") && out.contains("token"), "{out}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn bad_campaign_is_a_usage_error() {
    let o = evmfuzz(&["fuzz", "fixtures/nope.toml"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("loading campaign"));
    let o = evmfuzz(&["replay", "fixtures/token/campaign.toml", "fixtures/token/Token.bin"]);
    assert_eq!(o.status.code(), Some(2));
}
