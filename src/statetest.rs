//! Runner for `ethereum/tests` GeneralStateTests (filled JSON format).
//!
//! For each test and each `post.<fork>` entry, the runner builds the
//! pre-state, executes the indexed transaction variant and compares the
//! resulting state-trie root and logs hash with the expected values. Cases
//! that reach an unimplemented precompile are reported as unsupported rather
//! than passed or failed.

use crate::evm::{Account, BlockEnv, Evm, GasPrice, Transaction, WorldState};
use crate::evm::state::logs_hash;
use crate::types::{decode_hex, Address, B256};
use crate::u256::U256;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Errors loading a test file.
#[derive(Debug, thiserror::Error)]
pub enum StateTestError {
    /// I/O failure.
    #[error("reading {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// Malformed JSON.
    #[error("parsing {path}: {source}")]
    Json {
        /// File path.
        path: PathBuf,
        /// Cause.
        source: serde_json::Error,
    },
}

/// Hex-encoded byte string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HexBytes(pub Vec<u8>);

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        decode_hex(&s).map(HexBytes).map_err(serde::de::Error::custom)
    }
}

/// `env` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)]
pub struct Env {
    pub current_coinbase: Address,
    pub current_gas_limit: U256,
    pub current_number: U256,
    pub current_timestamp: U256,
    pub current_base_fee: Option<U256>,
    pub current_random: Option<U256>,
    pub current_difficulty: Option<U256>,
}

/// An account in `pre`.
#[derive(Debug, Clone, Deserialize)]
#[allow(missing_docs)]
pub struct PreAccount {
    pub balance: U256,
    pub code: HexBytes,
    pub nonce: U256,
    pub storage: BTreeMap<U256, U256>,
}

/// One access-list item.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<U256>,
}

/// The parameterised `transaction` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)]
pub struct TxTemplate {
    pub data: Vec<HexBytes>,
    pub gas_limit: Vec<U256>,
    pub value: Vec<U256>,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub nonce: U256,
    pub sender: Address,
    pub to: String,
    #[serde(default)]
    pub access_lists: Option<Vec<Option<Vec<AccessListItem>>>>,
}

/// Indexes selecting one transaction variant.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Indexes {
    pub data: usize,
    pub gas: usize,
    pub value: usize,
}

/// Expected result for one variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)]
pub struct PostEntry {
    pub hash: B256,
    pub logs: B256,
    pub indexes: Indexes,
    pub expect_exception: Option<String>,
}

/// One named state test.
#[derive(Debug, Clone, Deserialize)]
#[allow(missing_docs)]
pub struct StateTest {
    pub env: Env,
    pub pre: BTreeMap<Address, PreAccount>,
    pub transaction: TxTemplate,
    pub post: BTreeMap<String, Vec<PostEntry>>,
}

/// Verdict for one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Root and logs hash matched.
    Pass,
    /// Mismatch.
    Fail {
        /// Expected state root.
        expected_root: B256,
        /// Computed state root.
        got_root: B256,
        /// Expected logs hash.
        expected_logs: B256,
        /// Computed logs hash.
        got_logs: B256,
    },
    /// The case needs an unimplemented feature.
    Unsupported(String),
}

/// Result of one `(test, variant)` case.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    /// Test name.
    pub name: String,
    /// Variant indexes.
    pub indexes: Indexes,
    /// Verdict.
    pub verdict: Verdict,
}

/// Aggregate counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Passing cases.
    pub passed: usize,
    /// Failing cases.
    pub failed: usize,
    /// Unsupported cases.
    pub unsupported: usize,
    /// Tests without an entry for the requested fork.
    pub skipped_tests: usize,
}

impl Summary {
    /// Adds one verdict.
    pub fn record(&mut self, v: &Verdict) {
        match v {
            Verdict::Pass => self.passed += 1,
            Verdict::Fail { .. } => self.failed += 1,
            Verdict::Unsupported(_) => self.unsupported += 1,
        }
    }
}

/// Loads a test file.
pub fn load_file(path: &Path) -> Result<BTreeMap<String, StateTest>, StateTestError> {
    let text = std::fs::read_to_string(path).map_err(|source| StateTestError::Io { path: path.into(), source })?;
    serde_json::from_str(&text).map_err(|source| StateTestError::Json { path: path.into(), source })
}

fn pre_state(pre: &BTreeMap<Address, PreAccount>) -> WorldState {
    let mut ws = WorldState::new();
    for (addr, p) in pre {
        let mut acc = Account::with_code(p.code.0.clone());
        acc.balance = p.balance;
        acc.nonce = p.nonce.saturating_u64();
        for (k, v) in &p.storage {
            if !v.is_zero() {
                acc.storage.insert(*k, *v);
            }
        }
        ws.insert(*addr, acc);
    }
    ws
}

fn block_env(env: &Env) -> BlockEnv {
    BlockEnv {
        coinbase: env.current_coinbase,
        number: env.current_number.saturating_u64(),
        timestamp: env.current_timestamp.saturating_u64(),
        gas_limit: env.current_gas_limit.saturating_u64(),
        base_fee: env.current_base_fee.unwrap_or(U256::ZERO),
        prevrandao: env.current_random.or(env.current_difficulty).unwrap_or(U256::ZERO),
        chain_id: U256::ONE,
    }
}

fn build_tx(t: &TxTemplate, ix: Indexes) -> Option<Transaction> {
    let to = if t.to.trim().is_empty() { None } else { Some(t.to.parse::<Address>().ok()?) };
    let gas_price = match (t.gas_price, t.max_fee_per_gas, t.max_priority_fee_per_gas) {
        (Some(p), _, _) => GasPrice::Legacy(p),
        (None, Some(max_fee), Some(max_priority_fee)) => GasPrice::Eip1559 { max_fee, max_priority_fee },
        _ => return None,
    };
    let access_list = t
        .access_lists
        .as_ref()
        .and_then(|lists| lists.get(ix.data).cloned().flatten())
        .unwrap_or_default()
        .into_iter()
        .map(|item| (item.address, item.storage_keys))
        .collect();
    Some(Transaction {
        caller: t.sender,
        to,
        value: *t.value.get(ix.value)?,
        data: t.data.get(ix.data)?.0.clone(),
        // A limit beyond u64 can never fit in a block; saturate so validation rejects it.
        gas_limit: t.gas_limit.get(ix.gas)?.saturating_u64(),
        nonce: Some(t.nonce.saturating_u64()),
        gas_price,
        access_list,
    })
}

/// Runs one variant of a test.
pub fn run_case(test: &StateTest, entry: &PostEntry) -> Verdict {
    let Some(tx) = build_tx(&test.transaction, entry.indexes) else {
        return Verdict::Unsupported("unsupported transaction encoding".into());
    };
    let mut evm = Evm::new(pre_state(&test.pre), block_env(&test.env));
    let logs = match evm.transact(&tx) {
        Ok(r) => r.logs,
        Err(_) => Vec::new(),
    };
    if let Some(id) = evm.unsupported_precompile() {
        return Verdict::Unsupported(format!("precompile 0x{id:02x}"));
    }
    // Reference harnesses credit a zero mining reward after every transaction,
    // which touches (and, if empty, deletes) the coinbase.
    let coinbase = evm.block.coinbase;
    evm.state.add_balance(coinbase, U256::ZERO);
    evm.state.finalize_tx();
    let got_root = evm.state.world().state_root();
    let got_logs = logs_hash(&logs);
    if got_root == entry.hash && got_logs == entry.logs {
        Verdict::Pass
    } else {
        Verdict::Fail { expected_root: entry.hash, got_root, expected_logs: entry.logs, got_logs }
    }
}

/// Runs every `fork` variant of every test in `tests`.
pub fn run_tests(tests: &BTreeMap<String, StateTest>, fork: &str, summary: &mut Summary) -> Vec<CaseOutcome> {
    let mut out = Vec::new();
    for (name, test) in tests {
        let Some(entries) = test.post.get(fork) else {
            summary.skipped_tests += 1;
            continue;
        };
        for entry in entries {
            let verdict = run_case(test, entry);
            summary.record(&verdict);
            out.push(CaseOutcome { name: name.clone(), indexes: entry.indexes, verdict });
        }
    }
    out
}

/// Recursively collects `*.json` files under `root` (sorted).
pub fn collect_json(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if root.is_file() {
        out.push(root.to_path_buf());
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "json") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINI: &str = r#"{
      "mini": {
        "env": {"currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba", "currentGasLimit": "0x05f5e100",
                "currentNumber": "0x01", "currentTimestamp": "0x03e8", "currentBaseFee": "0x0a",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
                "currentDifficulty": "0x020000"},
        "pre": {
          "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {"balance": "0x0ba1a9ce0ba1a9ce", "code": "0x", "nonce": "0x00", "storage": {}},
          "0xcccccccccccccccccccccccccccccccccccccccc": {"balance": "0x00", "code": "0x600160005500", "nonce": "0x00", "storage": {}}
        },
        "transaction": {"data": ["0x"], "gasLimit": ["0x0186a0"], "value": ["0x00"], "gasPrice": "0x0a", "nonce": "0x00",
                        "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b", "to": "0xcccccccccccccccccccccccccccccccccccccccc",
                        "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"},
        "post": {"Shanghai": [{"hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                               "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                               "indexes": {"data": 0, "gas": 0, "value": 0}}],
                 "London": []}
      }
    }"#;

    #[test]
    fn parses_and_reports_mismatch() {
        let tests: BTreeMap<String, StateTest> = serde_json::from_str(MINI).unwrap();
        let mut s = Summary::default();
        let out = run_tests(&tests, "Shanghai", &mut s);
        assert_eq!(out.len(), 1);
        // The expected root is deliberately wrong; the logs hash (empty list) is right.
        match &out[0].verdict {
            Verdict::Fail { got_logs, expected_logs, .. } => assert_eq!(got_logs, expected_logs),
            v => panic!("unexpected verdict {v:?}"),
        }
        assert_eq!(s.failed, 1);
        let mut s2 = Summary::default();
        assert!(run_tests(&tests, "Cancun", &mut s2).is_empty());
        assert_eq!(s2.skipped_tests, 1);
    }

    #[test]
    fn load_errors_are_reported() {
        assert!(matches!(load_file(Path::new("/nonexistent/x.json")), Err(StateTestError::Io { .. })));
    }
}
