//! Campaign files: what to deploy, what to call, which invariants to check.
//!
//! A campaign is a TOML file next to the compiled contracts:
//!
//! ```toml
//! name = "token"
//!
//! [actors]
//! count = 3
//! balance = "100 ether"
//!
//! [[contracts]]
//! name = "Token"
//! bytecode = "Token.bin"        # creation code, hex
//! abi = "Token.abi.json"        # solc ABI; mutating functions become targets
//! args = ["1000000"]            # constructor arguments
//!
//! [[invariants]]
//! name = "supply-conservation"
//! expr = "Token.totalSupply() == sum(a in accounts, Token.balanceOf(a))"
//! ```
//!
//! Loading deploys every contract into a fresh in-memory world; the
//! resulting state is the *genesis* every fuzzed call sequence starts from.

use super::exec::ViewCtx;
use super::invariant::{AddressSet, Expr, InvariantError};
use super::FuzzConfig;
use crate::abi::{decode_revert, encode_params, parse_value, AbiError, ContractAbi, Function};
use crate::evm::opcode::{immediate_len, JUMP, JUMPI};
use crate::evm::{Account, BlockEnv, Evm, Transaction, WorldState};
use crate::fxhash::FxHashSet;
use crate::types::{decode_hex, Address};
use crate::u256::U256;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Errors while loading or deploying a campaign.
#[derive(Debug, thiserror::Error)]
pub enum CampaignError {
    /// File could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// Path.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// Malformed TOML.
    #[error("parsing {path}: {source}")]
    Toml {
        /// Path.
        path: PathBuf,
        /// Cause.
        source: toml::de::Error,
    },
    /// Semantic problem in the campaign description.
    #[error("{0}")]
    Invalid(String),
    /// ABI problem.
    #[error("{context}: {source}")]
    Abi {
        /// Where.
        context: String,
        /// Cause.
        source: AbiError,
    },
    /// Invariant parse or name error.
    #[error("invariant `{name}`: {source}")]
    Invariant {
        /// Invariant name.
        name: String,
        /// Cause.
        source: InvariantError,
    },
    /// A constructor failed.
    #[error("deploying {contract}: {reason}")]
    Deploy {
        /// Contract name.
        contract: String,
        /// Why.
        reason: String,
    },
}

fn default_count() -> usize {
    3
}

fn default_balance() -> String {
    "100 ether".into()
}

fn default_true() -> bool {
    true
}

/// `[actors]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorSpec {
    /// Number of externally owned accounts sending transactions.
    #[serde(default = "default_count")]
    pub count: usize,
    /// Starting balance of each actor (an invariant-language amount, e.g. `"10 ether"`).
    #[serde(default = "default_balance")]
    pub balance: String,
}

impl Default for ActorSpec {
    fn default() -> Self {
        ActorSpec { count: default_count(), balance: default_balance() }
    }
}

/// One `[[contracts]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSpec {
    /// Name used in invariants and reports.
    pub name: String,
    /// Path to the hex creation bytecode (relative to the campaign file).
    pub bytecode: PathBuf,
    /// Path to the solc JSON ABI.
    pub abi: Option<PathBuf>,
    /// Constructor arguments as text (`actorN` / contract names allowed for addresses).
    #[serde(default)]
    pub args: Vec<String>,
    /// Deploying actor (default `actor0`).
    pub deployer: Option<String>,
    /// Endowment sent with the deployment.
    pub value: Option<String>,
    /// Whether the contract's functions are fuzzed (default true).
    #[serde(default = "default_true")]
    pub fuzz: bool,
    /// Explicit target signatures (`"f(uint256)"`, `"g() payable"`); overrides the ABI list.
    pub functions: Option<Vec<String>>,
    /// Signatures to leave out of the target set.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// One `[[aliases]]` entry: a name for an address computed after deployment.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasSpec {
    /// Alias name.
    pub name: String,
    /// Address-valued expression, e.g. `Pool.tokenB()`.
    pub expr: String,
}

/// One `[[invariants]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSpec {
    /// Short name.
    pub name: String,
    /// Boolean expression that must hold after every successful transaction.
    pub expr: String,
}

/// Optional `[fuzz]` defaults (command-line flags override them).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FuzzSpec {
    /// RNG seed.
    pub seed: Option<u64>,
    /// Transaction budget.
    pub max_tx: Option<u64>,
    /// Maximum calls per sequence.
    pub max_seq_len: Option<usize>,
    /// Treat `assert` failures (Panic 0x01) as violations.
    pub assertions: Option<bool>,
}

/// The whole campaign file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSpec {
    /// Campaign name.
    pub name: String,
    /// Free-text description.
    #[serde(default)]
    pub description: String,
    /// Actor configuration.
    #[serde(default)]
    pub actors: ActorSpec,
    /// Contracts, deployed in order.
    pub contracts: Vec<ContractSpec>,
    /// Address aliases.
    #[serde(default)]
    pub aliases: Vec<AliasSpec>,
    /// Invariants.
    #[serde(default)]
    pub invariants: Vec<InvariantSpec>,
    /// Defaults.
    #[serde(default)]
    pub fuzz: FuzzSpec,
}

/// Names known to invariants and reports.
#[derive(Debug, Clone, Default)]
pub struct Names {
    /// Actor addresses (`actor0`, `actor1`, ...).
    pub actors: Vec<Address>,
    /// Named contracts and aliases.
    pub contracts: Vec<(String, Address)>,
}

impl Names {
    /// Resolves `actorN` or a contract/alias name.
    pub fn resolve(&self, name: &str) -> Option<Address> {
        if let Some(i) = name.strip_prefix("actor").and_then(|n| n.parse::<usize>().ok()) {
            return self.actors.get(i).copied();
        }
        self.contracts.iter().find(|(n, _)| n == name).map(|(_, a)| *a)
    }

    /// Members of an address set.
    pub fn members(&self, set: AddressSet) -> Vec<Address> {
        match set {
            AddressSet::Actors => self.actors.clone(),
            AddressSet::Contracts => self.contracts.iter().map(|(_, a)| *a).collect(),
            AddressSet::Accounts => self.pool(),
        }
    }

    /// Every address the fuzzer may pass as an `address` argument.
    pub fn pool(&self) -> Vec<Address> {
        let mut v = self.actors.clone();
        v.extend(self.contracts.iter().map(|(_, a)| *a));
        v.push(Address::ZERO);
        v
    }

    /// Human-readable name of an address.
    pub fn display(&self, a: &Address) -> String {
        if let Some(i) = self.actors.iter().position(|x| x == a) {
            return format!("actor{i}");
        }
        if let Some((n, _)) = self.contracts.iter().find(|(_, x)| x == a) {
            return n.clone();
        }
        if *a == Address::ZERO {
            return "address(0)".into();
        }
        a.to_string()
    }
}

/// A fuzzable function on a deployed contract.
#[derive(Debug, Clone)]
pub struct Target {
    /// Index into [`Campaign::contracts`].
    pub contract: usize,
    /// The function.
    pub func: Function,
}

/// A deployed contract (or alias).
#[derive(Debug, Clone)]
pub struct Contract {
    /// Name.
    pub name: String,
    /// Address in the genesis state.
    pub address: Address,
}

/// A declared invariant.
#[derive(Debug, Clone)]
pub struct Invariant {
    /// Name.
    pub name: String,
    /// Source text.
    pub source: String,
    /// Parsed expression.
    pub expr: Expr,
}

/// A loaded, deployed campaign.
#[derive(Debug, Clone)]
pub struct Campaign {
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Address names.
    pub names: Names,
    /// Deployed contracts and aliases.
    pub contracts: Vec<Contract>,
    /// Fuzzable functions.
    pub targets: Vec<Target>,
    /// Invariants.
    pub invariants: Vec<Invariant>,
    /// Defaults from the `[fuzz]` section applied over [`FuzzConfig::default`].
    pub defaults: FuzzConfig,
    /// State after deployment.
    pub genesis: WorldState,
    /// Block context after deployment.
    pub block: BlockEnv,
    /// PUSH constants found in deployed runtime code (static dictionary seed).
    pub constants: Vec<U256>,
    /// Code ids of deployed runtime code.
    pub code_ids: FxHashSet<u64>,
    /// Total `JUMPI` directions (2 per `JUMPI`) in deployed runtime code.
    pub branch_total: usize,
    /// Warnings produced while loading (skipped functions, etc).
    pub warnings: Vec<String>,
}

/// Gas limit used for deployments and as the default per-call limit.
pub const DEPLOY_GAS: u64 = 25_000_000;

/// Parses an amount such as `"100 ether"` or `"0x10"`.
pub fn parse_amount(text: &str) -> Result<U256, CampaignError> {
    struct NoCtx;
    impl super::invariant::EvalContext for NoCtx {
        fn resolve(&self, _: &str) -> Option<Address> {
            None
        }
        fn members(&self, _: AddressSet) -> Vec<Address> {
            Vec::new()
        }
        fn view(&mut self, _: Address, _: Vec<u8>) -> Result<Vec<u8>, String> {
            Err("no calls in amounts".into())
        }
        fn balance(&self, _: &Address) -> U256 {
            U256::ZERO
        }
        fn storage(&self, _: &Address, _: U256) -> U256 {
            U256::ZERO
        }
    }
    let bad = |e: InvariantError| CampaignError::Invalid(format!("bad amount `{text}`: {e}"));
    Ok(Expr::parse(text).map_err(bad)?.eval(&mut NoCtx).map_err(bad)?.word)
}

/// Runtime code without the trailing solc CBOR metadata, if present.
pub fn strip_metadata(code: &[u8]) -> &[u8] {
    if code.len() < 2 {
        return code;
    }
    let n = usize::from(u16::from_be_bytes([code[code.len() - 2], code[code.len() - 1]]));
    if n + 2 <= code.len() {
        let start = code.len() - 2 - n;
        if matches!(code.get(start), Some(0xa1..=0xa3)) {
            return &code[..start];
        }
    }
    code
}

/// Counts `JUMPI`s and collects PUSH constants (2 bytes or wider, excluding
/// jump targets, i.e. pushes immediately followed by `JUMP`/`JUMPI`).
fn scan_code(code: &[u8], constants: &mut FxHashSet<U256>) -> usize {
    let code = strip_metadata(code);
    let mut jumpis = 0;
    let mut pc = 0;
    while pc < code.len() {
        let op = code[pc];
        let n = immediate_len(op);
        if op == JUMPI {
            jumpis += 1;
        }
        let next = code.get(pc + 1 + n).copied();
        if n >= 2 && pc + 1 + n <= code.len() && !matches!(next, Some(JUMP | JUMPI)) {
            constants.insert(U256::from_be_slice(&code[pc + 1..pc + 1 + n]));
        }
        pc += 1 + n;
    }
    jumpis
}

fn read(path: &Path) -> Result<String, CampaignError> {
    std::fs::read_to_string(path).map_err(|source| CampaignError::Io { path: path.into(), source })
}

impl Campaign {
    /// Loads and deploys a campaign file.
    pub fn load(path: &Path) -> Result<Campaign, CampaignError> {
        let text = read(path)?;
        let spec: CampaignSpec =
            toml::from_str(&text).map_err(|source| CampaignError::Toml { path: path.into(), source })?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Campaign::from_spec(spec, base)
    }

    /// Builds a campaign from a parsed spec; relative paths resolve against `base`.
    pub fn from_spec(spec: CampaignSpec, base: &Path) -> Result<Campaign, CampaignError> {
        if spec.actors.count == 0 || spec.actors.count > 64 {
            return Err(CampaignError::Invalid("actors.count must be between 1 and 64".into()));
        }
        if spec.contracts.is_empty() {
            return Err(CampaignError::Invalid("a campaign needs at least one [[contracts]] entry".into()));
        }
        let balance = parse_amount(&spec.actors.balance)?;
        let mut names = Names {
            actors: (1..=spec.actors.count as u64).map(|i| Address::from_low_u64(i << 16)).collect(),
            contracts: Vec::new(),
        };
        let mut ws = WorldState::new();
        for a in &names.actors {
            ws.insert(*a, Account { balance, ..Account::default() });
        }
        let mut evm = Evm::new(ws, BlockEnv::default());
        let mut contracts = Vec::new();
        let mut targets = Vec::new();
        let mut warnings = Vec::new();

        for c in &spec.contracts {
            if names.resolve(&c.name).is_some() || c.name.starts_with("actor") {
                return Err(CampaignError::Invalid(format!("duplicate or reserved contract name `{}`", c.name)));
            }
            let hex = read(&base.join(&c.bytecode))?;
            let mut init = decode_hex(hex.trim()).map_err(|e| CampaignError::Deploy {
                contract: c.name.clone(),
                reason: format!("bytecode is not hex: {e}"),
            })?;
            let abi = match &c.abi {
                Some(p) => {
                    ContractAbi::from_json(&read(&base.join(p))?)
                        .map_err(|source| CampaignError::Abi { context: c.name.clone(), source })?
                }
                None => ContractAbi::default(),
            };
            if c.args.len() != abi.constructor.len() {
                return Err(CampaignError::Invalid(format!(
                    "{}: constructor takes {} argument(s), {} given",
                    c.name,
                    abi.constructor.len(),
                    c.args.len()
                )));
            }
            let lookup = |s: &str| names.resolve(s);
            let args = abi
                .constructor
                .iter()
                .zip(&c.args)
                .map(|(t, a)| parse_value(t, a, &lookup))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| CampaignError::Abi { context: format!("{} constructor", c.name), source })?;
            init.extend(
                encode_params(&abi.constructor, &args)
                    .map_err(|source| CampaignError::Abi { context: c.name.clone(), source })?,
            );
            let deployer_name = c.deployer.as_deref().unwrap_or("actor0");
            let deployer = names.actors.get(
                deployer_name
                    .strip_prefix("actor")
                    .and_then(|n| n.parse::<usize>().ok())
                    .ok_or_else(|| CampaignError::Invalid(format!("deployer must be an actor, got `{deployer_name}`")))?,
            );
            let deployer = *deployer
                .ok_or_else(|| CampaignError::Invalid(format!("deployer `{deployer_name}` does not exist")))?;
            let value = match &c.value {
                Some(v) => parse_amount(v)?,
                None => U256::ZERO,
            };
            let deploy_err = |reason: String| CampaignError::Deploy { contract: c.name.clone(), reason };
            let r = evm
                .transact(&Transaction::create(deployer, init, value, DEPLOY_GAS))
                .map_err(|e| deploy_err(e.to_string()))?;
            let address = match (r.status.is_success(), r.created) {
                (true, Some(a)) => a,
                _ => {
                    let why = decode_revert(&r.output).unwrap_or_else(|| format!("{:?}", r.status));
                    return Err(deploy_err(why));
                }
            };
            names.contracts.push((c.name.clone(), address));
            let idx = contracts.len();
            contracts.push(Contract { name: c.name.clone(), address });

            if !c.fuzz {
                continue;
            }
            let funcs = match &c.functions {
                Some(sigs) => sigs
                    .iter()
                    .map(|s| Function::parse(s))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|source| CampaignError::Abi { context: c.name.clone(), source })?,
                None => abi.mutating.clone(),
            };
            warnings.extend(abi.skipped.iter().map(|s| format!("{}: skipped {s} (unsupported parameter type)", c.name)));
            for ex in &c.exclude {
                let f =
                    Function::parse(ex).map_err(|source| CampaignError::Abi { context: c.name.clone(), source })?;
                if !funcs.iter().any(|g| g.signature() == f.signature()) {
                    return Err(CampaignError::Invalid(format!("{}: excluded function {ex} is not a target", c.name)));
                }
            }
            for func in funcs {
                let excluded = c.exclude.iter().any(|ex| {
                    Function::parse(ex).map(|f| f.signature() == func.signature()).unwrap_or(false)
                });
                if !excluded {
                    targets.push(Target { contract: idx, func });
                }
            }
        }
        if targets.is_empty() {
            return Err(CampaignError::Invalid("no fuzzable functions (check `abi`, `functions`, `fuzz`)".into()));
        }

        for al in &spec.aliases {
            if names.resolve(&al.name).is_some() {
                return Err(CampaignError::Invalid(format!("alias `{}` shadows an existing name", al.name)));
            }
            let err = |source| CampaignError::Invariant { name: format!("alias {}", al.name), source };
            let expr = Expr::parse(&al.expr).map_err(err)?;
            let v = {
                let mut ctx = ViewCtx { evm: &mut evm, names: &names };
                expr.eval(&mut ctx).map_err(err)?
            };
            let address = Address::from_word(v.word);
            if evm.state.code(&address).is_empty() {
                warnings.push(format!("alias {} = {address} has no code", al.name));
            }
            names.contracts.push((al.name.clone(), address));
            contracts.push(Contract { name: al.name.clone(), address });
        }

        let mut invariants = Vec::new();
        for inv in &spec.invariants {
            let err = |source| CampaignError::Invariant { name: inv.name.clone(), source };
            let expr = Expr::parse(&inv.expr).map_err(err)?;
            expr.check_names(&|n| names.resolve(n).is_some()).map_err(err)?;
            if invariants.iter().any(|i: &Invariant| i.name == inv.name) || inv.name == super::ASSERTION_ORACLE {
                return Err(CampaignError::Invalid(format!("duplicate or reserved invariant name `{}`", inv.name)));
            }
            invariants.push(Invariant { name: inv.name.clone(), source: inv.expr.clone(), expr });
        }

        let mut defaults = FuzzConfig::default();
        if let Some(s) = spec.fuzz.seed {
            defaults.seed = s;
        }
        if let Some(m) = spec.fuzz.max_tx {
            defaults.max_tx = m;
        }
        if let Some(l) = spec.fuzz.max_seq_len {
            defaults.max_seq_len = l.max(1);
        }
        if let Some(a) = spec.fuzz.assertions {
            defaults.assertions = a;
        }
        if invariants.is_empty() && !defaults.assertions {
            return Err(CampaignError::Invalid("nothing to check: no invariants and assertions disabled".into()));
        }

        let mut constants = FxHashSet::default();
        let mut code_ids = FxHashSet::default();
        let mut branch_total = 0;
        let genesis = evm.state.world().clone();
        let mut seen = FxHashSet::default();
        for c in &contracts {
            if let Some(acc) = genesis.get(&c.address) {
                if !acc.code.is_empty() && seen.insert(acc.code_hash) {
                    branch_total += 2 * scan_code(&acc.code, &mut constants);
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&acc.code_hash.0[..8]);
                    code_ids.insert(u64::from_be_bytes(id));
                }
            }
        }
        let mut constants: Vec<U256> = constants.into_iter().collect();
        constants.sort();

        Ok(Campaign {
            name: spec.name,
            description: spec.description,
            names,
            contracts,
            targets,
            invariants,
            defaults,
            genesis,
            block: evm.block.clone(),
            constants,
            code_ids,
            branch_total,
            warnings,
        })
    }

    /// Display name of a target, e.g. `Token.transfer(address,uint256)`.
    pub fn target_name(&self, t: usize) -> String {
        let tg = &self.targets[t];
        format!("{}.{}", self.contracts[tg.contract].name, tg.func.signature())
    }

    /// Finds a target by its display name.
    pub fn find_target(&self, name: &str) -> Option<usize> {
        (0..self.targets.len()).find(|&t| self.target_name(t) == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("100 ether").unwrap(), U256::from_u128(100 * 10u128.pow(18)));
        assert_eq!(parse_amount("0x10").unwrap(), U256::from_u64(16));
        assert!(parse_amount("1 +").is_err());
        assert!(parse_amount("Token.x()").is_err());
    }

    #[test]
    fn metadata_stripping_and_scan() {
        // PUSH2 0x1234 JUMPI PUSH2 0xbeef STOP + fake CBOR (a1 ...) of length 3.
        let code = [0x61, 0x12, 0x34, 0x57, 0x61, 0xbe, 0xef, 0x00, 0xa1, 0x57, 0x57, 0x00, 0x03];
        assert_eq!(strip_metadata(&code), &code[..8]);
        let mut consts = FxHashSet::default();
        assert_eq!(scan_code(&code, &mut consts), 1);
        assert!(!consts.contains(&U256::from_u64(0x1234)), "jump targets are not constants");
        assert!(consts.contains(&U256::from_u64(0xbeef)));
        assert_eq!(strip_metadata(&[0x00]), &[0x00]);
        assert_eq!(strip_metadata(&[0x57, 0x00, 0x01]), &[0x57, 0x00, 0x01]);
    }

    #[test]
    fn names_resolve_and_display() {
        let n = Names {
            actors: vec![Address::from_low_u64(0x10000)],
            contracts: vec![("Token".into(), Address::from_low_u64(0x99))],
        };
        assert_eq!(n.resolve("actor0"), Some(Address::from_low_u64(0x10000)));
        assert_eq!(n.resolve("actor1"), None);
        assert_eq!(n.resolve("Token"), Some(Address::from_low_u64(0x99)));
        assert_eq!(n.pool().len(), 3);
        assert_eq!(n.members(AddressSet::Contracts).len(), 1);
        assert_eq!(n.members(AddressSet::Actors).len(), 1);
        assert_eq!(n.display(&Address::ZERO), "address(0)");
        assert_eq!(n.display(&Address::from_low_u64(0x99)), "Token");
        assert_eq!(n.display(&Address::from_low_u64(5)), Address::from_low_u64(5).to_string());
    }
}
