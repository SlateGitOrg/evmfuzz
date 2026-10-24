//! Call sequences: the unit the fuzzer generates, mutates, shrinks and
//! replays, plus a stable JSON form for reproducers.

use super::campaign::Campaign;
use crate::abi::{parse_value, AbiValue};
use crate::u256::U256;
use serde::{Deserialize, Serialize};

/// Seconds the block timestamp advances before a call unless mutated.
pub const DEFAULT_WARP: u64 = 12;

/// One transaction in a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Call {
    /// Index of the sending actor.
    pub sender: usize,
    /// Index into [`Campaign::targets`].
    pub target: usize,
    /// Arguments, matching the target's parameter types.
    pub args: Vec<AbiValue>,
    /// Wei sent (zero unless the function is payable).
    pub value: U256,
    /// Seconds to advance the block timestamp before the call.
    pub warp: u64,
}

/// A call sequence executed from the campaign's genesis state.
pub type Sequence = Vec<Call>;

impl Call {
    /// Renders the call with symbolic names, e.g. `actor1 -> Token.transfer(actor0, 5)`.
    pub fn display(&self, c: &Campaign) -> String {
        let t = &c.targets[self.target];
        let args: Vec<String> = self.args.iter().map(|a| display_value(a, c)).collect();
        let mut s =
            format!("actor{} -> {}.{}({})", self.sender, c.contracts[t.contract].name, t.func.name, args.join(", "));
        if !self.value.is_zero() {
            s.push_str(&format!(" {{value: {}}}", self.value));
        }
        if self.warp != DEFAULT_WARP {
            s.push_str(&format!(" [+{}s]", self.warp));
        }
        s
    }
}

/// Renders a value, naming known addresses.
pub fn display_value(v: &AbiValue, c: &Campaign) -> String {
    match v {
        AbiValue::Address(a) => c.names.display(a),
        AbiValue::Array(items) => {
            let parts: Vec<String> = items.iter().map(|i| display_value(i, c)).collect();
            format!("[{}]", parts.join(", "))
        }
        other => other.to_string(),
    }
}

/// JSON form of a call (stable across runs; uses names, not indices).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRecord {
    /// `actorN`.
    pub sender: String,
    /// `Contract.signature`.
    pub function: String,
    /// Arguments as text (addresses by name where known).
    pub args: Vec<String>,
    /// Wei, decimal.
    pub value: String,
    /// Timestamp advance in seconds.
    pub warp: u64,
}

/// A saved reproducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reproducer {
    /// Campaign name.
    pub campaign: String,
    /// Oracle (invariant name or `assertion`) the sequence violates.
    pub oracle: String,
    /// Calls.
    pub calls: Vec<CallRecord>,
}

fn record_value(v: &AbiValue, c: &Campaign) -> String {
    match v {
        AbiValue::Address(a) => {
            let n = c.names.display(a);
            if n == "address(0)" {
                a.to_string()
            } else {
                n
            }
        }
        AbiValue::Array(items) => {
            let parts: Vec<String> = items.iter().map(|i| record_value(i, c)).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

impl Reproducer {
    /// Encodes a sequence.
    pub fn new(c: &Campaign, oracle: &str, seq: &[Call]) -> Self {
        let calls = seq
            .iter()
            .map(|call| CallRecord {
                sender: format!("actor{}", call.sender),
                function: c.target_name(call.target),
                args: call.args.iter().map(|a| record_value(a, c)).collect(),
                value: call.value.to_string(),
                warp: call.warp,
            })
            .collect();
        Reproducer { campaign: c.name.clone(), oracle: oracle.to_string(), calls }
    }

    /// Decodes the calls against a loaded campaign.
    pub fn to_sequence(&self, c: &Campaign) -> Result<Sequence, String> {
        let lookup = |s: &str| c.names.resolve(s);
        self.calls
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let ctx = |m: String| format!("call {}: {m}", i + 1);
                let sender = r
                    .sender
                    .strip_prefix("actor")
                    .and_then(|n| n.parse::<usize>().ok())
                    .filter(|&n| n < c.names.actors.len())
                    .ok_or_else(|| ctx(format!("unknown sender `{}`", r.sender)))?;
                let target =
                    c.find_target(&r.function).ok_or_else(|| ctx(format!("unknown function `{}`", r.function)))?;
                let inputs = &c.targets[target].func.inputs;
                if inputs.len() != r.args.len() {
                    return Err(ctx(format!("expected {} args, got {}", inputs.len(), r.args.len())));
                }
                let args = inputs
                    .iter()
                    .zip(&r.args)
                    .map(|(t, a)| parse_value(t, a, &lookup).map_err(|e| ctx(e.to_string())))
                    .collect::<Result<Vec<_>, _>>()?;
                let value = U256::from_str_radix_auto(&r.value).map_err(|e| ctx(format!("bad value: {e}")))?;
                Ok(Call { sender, target, args, value, warp: r.warp })
            })
            .collect()
    }
}
