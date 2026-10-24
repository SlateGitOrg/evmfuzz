//! Campaign loading: every malformed or inconsistent campaign is rejected
//! with an error that names the problem.

use evmfuzz::fuzz::campaign::{Campaign, CampaignError};
use std::path::{Path, PathBuf};

/// A scratch directory containing copies of the token fixture artefacts.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("evmfuzz-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        for (sub, f) in
            [("token", "Token.bin"), ("token", "Token.abi.json"), ("vault", "Vault.bin"), ("vault", "Vault.abi.json")]
        {
            std::fs::copy(fx.join(sub).join(f), dir.join(f)).unwrap();
        }
        std::fs::write(dir.join("Revert.bin"), "0x5f5ffd").unwrap(); // PUSH0 PUSH0 REVERT
        std::fs::write(dir.join("NotHex.bin"), "zz").unwrap();
        Scratch(dir)
    }

    fn load(&self, toml: &str) -> Result<Campaign, CampaignError> {
        let p = self.0.join("campaign.toml");
        std::fs::write(&p, toml).unwrap();
        Campaign::load(&p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const TOKEN: &str = r#"
[[contracts]]
name = "Token"
bytecode = "Token.bin"
abi = "Token.abi.json"
args = ["1000"]
"#;

fn err(s: &Scratch, toml: &str) -> String {
    match s.load(toml) {
        Ok(_) => panic!("expected an error for:\n{toml}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn valid_minimal_campaign_loads() {
    let s = Scratch::new("ok");
    let c = s.load(&format!("name = \"t\"\n{TOKEN}\n[actors]\ncount = 2\nbalance = \"1 ether\"\n[fuzz]\nseed = 9\nmax_tx = 5\nmax_seq_len = 3\n")).unwrap();
    assert_eq!(c.names.actors.len(), 2);
    assert_eq!(c.defaults.seed, 9);
    assert_eq!(c.defaults.max_tx, 5);
    assert_eq!(c.defaults.max_seq_len, 3);
    assert_eq!(c.targets.len(), 4);
    assert!(c.branch_total > 0);
    assert!(c.invariants.is_empty());
}

#[test]
fn explicit_functions_and_excludes() {
    let s = Scratch::new("funcs");
    let c = s
        .load(&format!("name = \"t\"\n{TOKEN}functions = [\"transfer(address,uint256)\", \"burn(uint256)\"]\nexclude = [\"burn(uint256)\"]\n"))
        .unwrap();
    assert_eq!(c.targets.len(), 1);
    assert_eq!(c.target_name(0), "Token.transfer(address,uint256)");
    let e = err(&s, &format!("name = \"t\"\n{TOKEN}exclude = [\"mint(uint256)\"]\n"));
    assert!(e.contains("not a target"), "{e}");
}

#[test]
fn structural_errors() {
    let s = Scratch::new("struct");
    let cases: Vec<(String, &str)> = vec![
        ("name = \"t\"\nbogus = 1\n".into(), "parsing"),
        ("name = \"t\"\ncontracts = []\n".into(), "at least one"),
        (format!("name = \"t\"\n[actors]\ncount = 0\n{TOKEN}"), "actors.count"),
        (format!("name = \"t\"\n[actors]\nbalance = \"lots\"\n{TOKEN}"), "bad amount"),
        ("name = \"t\"\n[[contracts]]\nname = \"X\"\nbytecode = \"Missing.bin\"\n".into(), "reading"),
        ("name = \"t\"\n[[contracts]]\nname = \"X\"\nbytecode = \"NotHex.bin\"\n".into(), "not hex"),
        ("name = \"t\"\n[[contracts]]\nname = \"X\"\nbytecode = \"Revert.bin\"\nfunctions = [\"f()\"]\n".into(), "deploying X"),
        (format!("name = \"t\"\n{TOKEN}\n[[contracts]]\nname = \"Token\"\nbytecode = \"Token.bin\"\nabi = \"Token.abi.json\"\nargs = [\"1\"]\n"), "duplicate"),
        ("name = \"t\"\n[[contracts]]\nname = \"Token\"\nbytecode = \"Token.bin\"\nabi = \"Token.abi.json\"\n".into(), "constructor takes 1"),
        ("name = \"t\"\n[[contracts]]\nname = \"Token\"\nbytecode = \"Token.bin\"\nabi = \"Token.abi.json\"\nargs = [\"-1\"]\n".into(), "cannot parse"),
        (format!("name = \"t\"\n{TOKEN}deployer = \"Token\"\n"), "deployer must be an actor"),
        (format!("name = \"t\"\n{TOKEN}deployer = \"actor9\"\n"), "does not exist"),
        (format!("name = \"t\"\n{TOKEN}fuzz = false\n"), "no fuzzable functions"),
        (format!("name = \"t\"\n{TOKEN}functions = [\"bad\"]\n"), "malformed function signature"),
        (format!("name = \"t\"\n{TOKEN}\n[fuzz]\nassertions = false\n"), "nothing to check"),
    ];
    for (toml, want) in cases {
        let e = err(&s, &toml);
        assert!(e.contains(want), "expected `{want}` in `{e}` for:\n{toml}");
    }
}

#[test]
fn invariant_and_alias_errors() {
    let s = Scratch::new("inv");
    let cases: Vec<(String, &str)> = vec![
        (format!("name = \"t\"\n{TOKEN}\n[[invariants]]\nname = \"x\"\nexpr = \"Token.totalSupply( ==\"\n"), "syntax error"),
        (format!("name = \"t\"\n{TOKEN}\n[[invariants]]\nname = \"x\"\nexpr = \"Tokn.totalSupply() > 0\"\n"), "unknown name `Tokn`"),
        (format!("name = \"t\"\n{TOKEN}\n[[invariants]]\nname = \"assertion\"\nexpr = \"true\"\n"), "reserved"),
        (format!("name = \"t\"\n{TOKEN}\n[[invariants]]\nname = \"a\"\nexpr = \"true\"\n[[invariants]]\nname = \"a\"\nexpr = \"true\"\n"), "duplicate"),
        (format!("name = \"t\"\n{TOKEN}\n[[aliases]]\nname = \"Token\"\nexpr = \"Token\"\n"), "shadows"),
        (format!("name = \"t\"\n{TOKEN}\n[[aliases]]\nname = \"X\"\nexpr = \"Token.nope()\"\n"), "reverted"),
    ];
    for (toml, want) in cases {
        let e = err(&s, &toml);
        assert!(e.contains(want), "expected `{want}` in `{e}` for:\n{toml}");
    }
    // An alias without code is accepted with a warning.
    let c = s
        .load(&format!("name = \"t\"\n{TOKEN}\n[[aliases]]\nname = \"Nobody\"\nexpr = \"address(0x1234)\"\n"))
        .unwrap();
    assert!(c.warnings.iter().any(|w| w.contains("has no code")), "{:?}", c.warnings);
    assert_eq!(c.names.resolve("Nobody").unwrap().to_string(), "0x0000000000000000000000000000000000001234");
}

#[test]
fn payable_constructor_value_and_vault_abi() {
    let s = Scratch::new("vault");
    let c = s
        .load("name = \"v\"\n[[contracts]]\nname = \"Vault\"\nbytecode = \"Vault.bin\"\nabi = \"Vault.abi.json\"\n[[invariants]]\nname = \"s\"\nexpr = \"balance(Vault) >= Vault.totalDeposits()\"\n")
        .unwrap();
    assert!(c.targets.iter().any(|t| t.func.payable && t.func.name == "deposit"));
    // Vault's constructor is not payable: an endowment makes deployment revert.
    let e = err(&s, "name = \"v\"\n[[contracts]]\nname = \"Vault\"\nbytecode = \"Vault.bin\"\nabi = \"Vault.abi.json\"\nvalue = \"1 ether\"\n");
    assert!(e.contains("deploying Vault"), "{e}");
}
