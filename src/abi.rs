//! A Solidity ABI subset: canonical type parsing, function selectors,
//! JSON ABI loading, call encoding, value parsing/printing and revert-reason
//! decoding.
//!
//! Supported types: `uintN`, `intN`, `address`, `bool`, `bytesN`, `bytes`,
//! `string`, dynamic arrays `T[]` and fixed arrays `T[k]` (nestable).
//! Tuples/structs are not supported; functions using them are skipped when an
//! ABI file is loaded.

use crate::crypto::keccak256;
use crate::types::{decode_hex, encode_hex, Address};
use crate::u256::U256;
use std::fmt;

/// Errors from ABI parsing, loading and encoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AbiError {
    /// A type string could not be parsed.
    #[error("unsupported or malformed ABI type `{0}`")]
    BadType(String),
    /// A function signature could not be parsed.
    #[error("malformed function signature `{0}`")]
    BadSignature(String),
    /// A textual value does not fit its type.
    #[error("cannot parse `{text}` as {ty}")]
    BadValue {
        /// Expected type.
        ty: String,
        /// Offending text.
        text: String,
    },
    /// Number of values does not match the number of parameters.
    #[error("expected {expected} arguments, got {got}")]
    Arity {
        /// Parameter count.
        expected: usize,
        /// Argument count.
        got: usize,
    },
    /// An ABI JSON document could not be read.
    #[error("invalid ABI JSON: {0}")]
    Json(String),
}

/// A Solidity ABI type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AbiType {
    /// `uintN`, N in 8..=256 step 8.
    Uint(u16),
    /// `intN`, N in 8..=256 step 8.
    Int(u16),
    /// `address`.
    Address,
    /// `bool`.
    Bool,
    /// `bytesN`, N in 1..=32.
    FixedBytes(u8),
    /// `bytes`.
    Bytes,
    /// `string`.
    String,
    /// `T[]`.
    Array(Box<AbiType>),
    /// `T[k]`.
    FixedArray(Box<AbiType>, usize),
}

impl AbiType {
    /// Parses a canonical type string such as `uint256[][2]`.
    pub fn parse(s: &str) -> Result<AbiType, AbiError> {
        let s = s.trim();
        let bad = || AbiError::BadType(s.to_string());
        if let Some(inner) = s.strip_suffix(']') {
            let open = inner.rfind('[').ok_or_else(bad)?;
            let elem = AbiType::parse(&inner[..open])?;
            let dim = &inner[open + 1..];
            return if dim.is_empty() {
                Ok(AbiType::Array(Box::new(elem)))
            } else {
                let k: usize = dim.parse().map_err(|_| bad())?;
                if k == 0 {
                    return Err(bad());
                }
                Ok(AbiType::FixedArray(Box::new(elem), k))
            };
        }
        let bits = |rest: &str| -> Result<u16, AbiError> {
            if rest.is_empty() {
                return Ok(256);
            }
            let n: u16 = rest.parse().map_err(|_| bad())?;
            if n == 0 || n > 256 || n % 8 != 0 {
                return Err(bad());
            }
            Ok(n)
        };
        match s {
            "address" => Ok(AbiType::Address),
            "bool" => Ok(AbiType::Bool),
            "bytes" => Ok(AbiType::Bytes),
            "string" => Ok(AbiType::String),
            _ => {
                if let Some(rest) = s.strip_prefix("uint") {
                    Ok(AbiType::Uint(bits(rest)?))
                } else if let Some(rest) = s.strip_prefix("int") {
                    Ok(AbiType::Int(bits(rest)?))
                } else if let Some(rest) = s.strip_prefix("bytes") {
                    let n: u8 = rest.parse().map_err(|_| bad())?;
                    if n == 0 || n > 32 {
                        return Err(bad());
                    }
                    Ok(AbiType::FixedBytes(n))
                } else {
                    Err(bad())
                }
            }
        }
    }

    /// True for types encoded in the tail section.
    pub fn is_dynamic(&self) -> bool {
        match self {
            AbiType::Bytes | AbiType::String | AbiType::Array(_) => true,
            AbiType::FixedArray(e, _) => e.is_dynamic(),
            _ => false,
        }
    }

    /// Size of the head encoding in bytes.
    fn head_size(&self) -> usize {
        match self {
            AbiType::FixedArray(e, k) if !e.is_dynamic() => e.head_size() * k,
            _ => 32,
        }
    }
}

impl fmt::Display for AbiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiType::Uint(n) => write!(f, "uint{n}"),
            AbiType::Int(n) => write!(f, "int{n}"),
            AbiType::Address => f.write_str("address"),
            AbiType::Bool => f.write_str("bool"),
            AbiType::FixedBytes(n) => write!(f, "bytes{n}"),
            AbiType::Bytes => f.write_str("bytes"),
            AbiType::String => f.write_str("string"),
            AbiType::Array(e) => write!(f, "{e}[]"),
            AbiType::FixedArray(e, k) => write!(f, "{e}[{k}]"),
        }
    }
}

/// A value of an [`AbiType`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AbiValue {
    /// Unsigned integer (already within the type's width).
    Uint(U256),
    /// Signed integer as a 256-bit two's-complement word.
    Int(U256),
    /// Address.
    Address(Address),
    /// Boolean.
    Bool(bool),
    /// `bytesN` contents (exactly N bytes).
    FixedBytes(Vec<u8>),
    /// `bytes` contents.
    Bytes(Vec<u8>),
    /// `string` contents.
    String(String),
    /// Elements of `T[]` or `T[k]`.
    Array(Vec<AbiValue>),
}

impl fmt::Display for AbiValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiValue::Uint(v) => write!(f, "{v}"),
            AbiValue::Int(v) => {
                if v.is_negative() {
                    write!(f, "-{}", v.wrapping_neg())
                } else {
                    write!(f, "{v}")
                }
            }
            AbiValue::Address(a) => write!(f, "{a}"),
            AbiValue::Bool(b) => write!(f, "{b}"),
            AbiValue::FixedBytes(b) | AbiValue::Bytes(b) => f.write_str(&encode_hex(b)),
            AbiValue::String(s) => write!(f, "{s:?}"),
            AbiValue::Array(items) => {
                f.write_str("[")?;
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{it}")?;
                }
                f.write_str("]")
            }
        }
    }
}

/// Mask with the low `bits` bits set.
pub fn width_mask(bits: u16) -> U256 {
    if bits >= 256 {
        U256::MAX
    } else {
        U256::ONE.shl_bits(bits as usize).wrapping_sub(U256::ONE)
    }
}

/// Sign-extends the low `bits` bits of `v` to 256 bits.
pub fn sign_extend(v: U256, bits: u16) -> U256 {
    if bits >= 256 {
        return v;
    }
    v.evm_signextend(U256::from_u64(u64::from(bits / 8 - 1)))
}

/// Splits a top-level comma-separated list, respecting brackets and quotes.
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '"' => in_str = !in_str,
            '[' | '(' if !in_str => depth += 1,
            ']' | ')' if !in_str => depth -= 1,
            ',' if depth == 0 && !in_str => {
                out.push(std::mem::take(&mut cur).trim().to_string());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() || !out.is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Parses `text` as a value of type `ty`. Address arguments may be names,
/// resolved through `names` (e.g. `actor1`, `Token`).
pub fn parse_value(ty: &AbiType, text: &str, names: &dyn Fn(&str) -> Option<Address>) -> Result<AbiValue, AbiError> {
    let text = text.trim();
    let bad = || AbiError::BadValue { ty: ty.to_string(), text: text.to_string() };
    match ty {
        AbiType::Uint(bits) => {
            let v = U256::from_str_radix_auto(text).map_err(|_| bad())?;
            if v > width_mask(*bits) {
                return Err(bad());
            }
            Ok(AbiValue::Uint(v))
        }
        AbiType::Int(bits) => {
            let (neg, digits) = match text.strip_prefix('-') {
                Some(d) => (true, d),
                None => (false, text),
            };
            let mag = U256::from_str_radix_auto(digits).map_err(|_| bad())?;
            let half = U256::ONE.shl_bits(*bits as usize - 1);
            if (!neg && mag >= half) || (neg && mag > half) {
                return Err(bad());
            }
            Ok(AbiValue::Int(if neg { mag.wrapping_neg() } else { mag }))
        }
        AbiType::Address => {
            if let Some(a) = names(text) {
                return Ok(AbiValue::Address(a));
            }
            text.parse::<Address>().map(AbiValue::Address).map_err(|_| bad())
        }
        AbiType::Bool => match text {
            "true" => Ok(AbiValue::Bool(true)),
            "false" => Ok(AbiValue::Bool(false)),
            _ => Err(bad()),
        },
        AbiType::FixedBytes(n) => {
            let b = decode_hex(text).map_err(|_| bad())?;
            if b.len() != *n as usize {
                return Err(bad());
            }
            Ok(AbiValue::FixedBytes(b))
        }
        AbiType::Bytes => decode_hex(text).map(AbiValue::Bytes).map_err(|_| bad()),
        AbiType::String => {
            let inner = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')).unwrap_or(text);
            Ok(AbiValue::String(inner.to_string()))
        }
        AbiType::Array(elem) | AbiType::FixedArray(elem, _) => {
            let inner = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')).ok_or_else(bad)?;
            let items = split_top_level(inner)
                .iter()
                .map(|t| parse_value(elem, t, names))
                .collect::<Result<Vec<_>, _>>()?;
            if let AbiType::FixedArray(_, k) = ty {
                if items.len() != *k {
                    return Err(bad());
                }
            }
            Ok(AbiValue::Array(items))
        }
    }
}

fn word(v: U256) -> [u8; 32] {
    v.to_be_bytes()
}

fn pad_right(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
    let rem = bytes.len() % 32;
    if rem != 0 {
        out.resize(out.len() + 32 - rem, 0);
    }
}

fn encode_static(ty: &AbiType, v: &AbiValue, out: &mut Vec<u8>) -> Result<(), AbiError> {
    let mismatch = || AbiError::BadValue { ty: ty.to_string(), text: v.to_string() };
    match (ty, v) {
        (AbiType::Uint(_), AbiValue::Uint(x)) | (AbiType::Int(_), AbiValue::Int(x)) => out.extend_from_slice(&word(*x)),
        (AbiType::Address, AbiValue::Address(a)) => out.extend_from_slice(&word(a.to_word())),
        (AbiType::Bool, AbiValue::Bool(b)) => out.extend_from_slice(&word(U256::from(*b))),
        (AbiType::FixedBytes(n), AbiValue::FixedBytes(b)) if b.len() == *n as usize => {
            let mut w = [0u8; 32];
            w[..b.len()].copy_from_slice(b);
            out.extend_from_slice(&w);
        }
        (AbiType::FixedArray(e, k), AbiValue::Array(items)) if items.len() == *k => {
            for it in items {
                encode_static(e, it, out)?;
            }
        }
        _ => return Err(mismatch()),
    }
    Ok(())
}

fn encode_tail(ty: &AbiType, v: &AbiValue) -> Result<Vec<u8>, AbiError> {
    let mismatch = || AbiError::BadValue { ty: ty.to_string(), text: v.to_string() };
    let mut out = Vec::new();
    match (ty, v) {
        (AbiType::Bytes, AbiValue::Bytes(b)) => {
            out.extend_from_slice(&word(U256::from_u64(b.len() as u64)));
            pad_right(&mut out, b);
        }
        (AbiType::String, AbiValue::String(s)) => {
            out.extend_from_slice(&word(U256::from_u64(s.len() as u64)));
            pad_right(&mut out, s.as_bytes());
        }
        (AbiType::Array(e), AbiValue::Array(items)) => {
            out.extend_from_slice(&word(U256::from_u64(items.len() as u64)));
            let types = vec![(**e).clone(); items.len()];
            out.extend(encode_params(&types, items)?);
        }
        (AbiType::FixedArray(e, k), AbiValue::Array(items)) if items.len() == *k => {
            let types = vec![(**e).clone(); items.len()];
            out.extend(encode_params(&types, items)?);
        }
        _ => return Err(mismatch()),
    }
    Ok(out)
}

/// ABI-encodes a parameter list (head/tail layout).
pub fn encode_params(types: &[AbiType], values: &[AbiValue]) -> Result<Vec<u8>, AbiError> {
    if types.len() != values.len() {
        return Err(AbiError::Arity { expected: types.len(), got: values.len() });
    }
    let head_len: usize = types.iter().map(AbiType::head_size).sum();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for (ty, v) in types.iter().zip(values) {
        if ty.is_dynamic() {
            head.extend_from_slice(&word(U256::from_u64((head_len + tail.len()) as u64)));
            tail.extend(encode_tail(ty, v)?);
        } else {
            encode_static(ty, v, &mut head)?;
        }
    }
    head.extend(tail);
    Ok(head)
}

/// A callable contract function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Function {
    /// Function name.
    pub name: String,
    /// Parameter types.
    pub inputs: Vec<AbiType>,
    /// Whether the function accepts Ether.
    pub payable: bool,
}

impl Function {
    /// Parses `name(type,...)` with an optional trailing ` payable`.
    pub fn parse(sig: &str) -> Result<Function, AbiError> {
        let sig = sig.trim();
        let bad = || AbiError::BadSignature(sig.to_string());
        let (body, payable) = match sig.strip_suffix("payable") {
            Some(b) if b.ends_with(' ') || b.ends_with(')') => (b.trim_end(), true),
            _ => (sig, false),
        };
        let open = body.find('(').ok_or_else(bad)?;
        let inner = body[open + 1..].strip_suffix(')').ok_or_else(bad)?;
        let name = body[..open].trim();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
            return Err(bad());
        }
        let inputs = if inner.trim().is_empty() {
            Vec::new()
        } else {
            split_top_level(inner).iter().map(|t| AbiType::parse(t)).collect::<Result<Vec<_>, _>>()?
        };
        Ok(Function { name: name.to_string(), inputs, payable })
    }

    /// Canonical signature, e.g. `transfer(address,uint256)`.
    pub fn signature(&self) -> String {
        let args: Vec<String> = self.inputs.iter().map(ToString::to_string).collect();
        format!("{}({})", self.name, args.join(","))
    }

    /// First four bytes of `keccak256(signature)`.
    pub fn selector(&self) -> [u8; 4] {
        let h = keccak256(self.signature().as_bytes());
        [h.0[0], h.0[1], h.0[2], h.0[3]]
    }

    /// Selector followed by the encoded arguments.
    pub fn encode_call(&self, args: &[AbiValue]) -> Result<Vec<u8>, AbiError> {
        let mut out = self.selector().to_vec();
        out.extend(encode_params(&self.inputs, args)?);
        Ok(out)
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.signature())?;
        if self.payable {
            f.write_str(" payable")?;
        }
        Ok(())
    }
}

/// The parts of a JSON ABI the fuzzer needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContractAbi {
    /// Constructor parameter types (empty if none).
    pub constructor: Vec<AbiType>,
    /// Whether the constructor is payable.
    pub constructor_payable: bool,
    /// State-changing functions (`nonpayable` / `payable`).
    pub mutating: Vec<Function>,
    /// Signatures skipped because they use unsupported types.
    pub skipped: Vec<String>,
}

#[derive(serde::Deserialize)]
struct JsonParam {
    #[serde(rename = "type")]
    ty: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonItem {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    inputs: Vec<JsonParam>,
    #[serde(default)]
    state_mutability: String,
}

impl ContractAbi {
    /// Parses a solc JSON ABI document.
    pub fn from_json(text: &str) -> Result<ContractAbi, AbiError> {
        let items: Vec<JsonItem> = serde_json::from_str(text).map_err(|e| AbiError::Json(e.to_string()))?;
        let mut abi = ContractAbi::default();
        for item in items {
            let types: Result<Vec<AbiType>, AbiError> = item.inputs.iter().map(|p| AbiType::parse(&p.ty)).collect();
            let payable = item.state_mutability == "payable";
            match item.kind.as_str() {
                "constructor" => {
                    abi.constructor = types.map_err(|e| AbiError::Json(format!("constructor: {e}")))?;
                    abi.constructor_payable = payable;
                }
                "function" if matches!(item.state_mutability.as_str(), "nonpayable" | "payable") => match types {
                    Ok(inputs) => abi.mutating.push(Function { name: item.name, inputs, payable }),
                    Err(_) => {
                        let raw: Vec<&str> = item.inputs.iter().map(|p| p.ty.as_str()).collect();
                        abi.skipped.push(format!("{}({})", item.name, raw.join(",")));
                    }
                },
                _ => {}
            }
        }
        Ok(abi)
    }
}

/// Decodes `Error(string)` and `Panic(uint256)` revert payloads.
pub fn decode_revert(output: &[u8]) -> Option<String> {
    if output.len() < 4 {
        return None;
    }
    let (sel, body) = output.split_at(4);
    match sel {
        [0x08, 0xc3, 0x79, 0xa0] if body.len() >= 64 => {
            let len = U256::from_be_slice(&body[32..64]).to_usize()?;
            let bytes = body.get(64..64 + len)?;
            Some(format!("Error({:?})", String::from_utf8_lossy(bytes)))
        }
        [0x4e, 0x48, 0x7b, 0x71] if body.len() >= 32 => {
            let code = U256::from_be_slice(&body[..32]);
            Some(format!("Panic(0x{code:02x}: {})", panic_meaning(code.saturating_u64())))
        }
        _ => None,
    }
}

/// Solidity panic code `0x01`: a failed `assert`.
pub const PANIC_ASSERT: u64 = 0x01;

/// The panic code of a `Panic(uint256)` payload.
pub fn panic_code(output: &[u8]) -> Option<u64> {
    if output.len() >= 36 && output[..4] == [0x4e, 0x48, 0x7b, 0x71] {
        U256::from_be_slice(&output[4..36]).to_u64()
    } else {
        None
    }
}

fn panic_meaning(code: u64) -> &'static str {
    match code {
        0x00 => "generic",
        0x01 => "assert failed",
        0x11 => "arithmetic overflow",
        0x12 => "division by zero",
        0x21 => "invalid enum",
        0x22 => "bad storage byte array",
        0x31 => "pop on empty array",
        0x32 => "index out of bounds",
        0x41 => "out of memory",
        0x51 => "zero function pointer",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_names(_: &str) -> Option<Address> {
        None
    }

    #[test]
    fn type_parsing_round_trips() {
        for s in ["uint256", "uint8", "int24", "address", "bool", "bytes32", "bytes", "string", "uint256[]", "address[3]"]
        {
            assert_eq!(AbiType::parse(s).unwrap().to_string(), s);
        }
        assert_eq!(AbiType::parse("uint").unwrap(), AbiType::Uint(256));
        assert_eq!(AbiType::parse("bool[2][]").unwrap().to_string(), "bool[2][]");
        for bad in ["uint7", "uint264", "bytes33", "bytes0", "tuple", "uint256[0]", "int[x]", "foo]"] {
            assert!(AbiType::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn selectors_match_known_values() {
        let f = Function::parse("transfer(address,uint256)").unwrap();
        assert_eq!(f.selector(), [0xa9, 0x05, 0x9c, 0xbb]);
        let d = Function::parse("deposit() payable").unwrap();
        assert!(d.payable);
        assert_eq!(d.selector(), [0xd0, 0xe3, 0x0d, 0xb0]);
        assert_eq!(d.to_string(), "deposit() payable");
        assert!(Function::parse("nope").is_err());
        assert!(Function::parse("(uint256)").is_err());
        assert!(Function::parse("f(uint7)").is_err());
    }

    #[test]
    fn static_and_dynamic_encoding() {
        // Example from the Solidity ABI specification:
        // f(uint256,uint32[],bytes10,bytes) with (0x123, [0x456, 0x789], "1234567890", "Hello, world!").
        let f = Function::parse("f(uint256,uint32[],bytes10,bytes)").unwrap();
        let args = vec![
            AbiValue::Uint(U256::from_u64(0x123)),
            AbiValue::Array(vec![AbiValue::Uint(U256::from_u64(0x456)), AbiValue::Uint(U256::from_u64(0x789))]),
            AbiValue::FixedBytes(b"1234567890".to_vec()),
            AbiValue::Bytes(b"Hello, world!".to_vec()),
        ];
        let enc = f.encode_call(&args).unwrap();
        assert_eq!(&enc[..4], &[0x8b, 0xe6, 0x52, 0x46]);
        let words: Vec<String> = enc[4..].chunks(32).map(|c| encode_hex(c)[2..].to_string()).collect();
        assert_eq!(words.len(), 9);
        assert!(words[0].ends_with("123"));
        assert!(words[1].ends_with("80"));
        assert!(words[2].starts_with("31323334353637383930"));
        assert!(words[3].ends_with("e0"));
        assert!(words[4].ends_with("02"));
        assert!(words[7].ends_with("0d"));
        assert!(words[8].starts_with("48656c6c6f2c20776f726c6421"));
    }

    #[test]
    fn fixed_arrays_and_strings() {
        let types = vec![AbiType::parse("uint8[2]").unwrap(), AbiType::String];
        let vals = vec![
            AbiValue::Array(vec![AbiValue::Uint(U256::ONE), AbiValue::Uint(U256::from_u64(2))]),
            AbiValue::String("hi".into()),
        ];
        let enc = encode_params(&types, &vals).unwrap();
        assert_eq!(enc.len(), 32 * 5);
        assert_eq!(enc[95], 0x60); // string offset after a 64-byte static array head
        assert!(encode_params(&types, &vals[..1]).is_err());
        assert!(encode_params(&[AbiType::Bool], &[AbiValue::Uint(U256::ONE)]).is_err());
    }

    #[test]
    fn value_parsing() {
        let names = |s: &str| (s == "actor0").then(|| Address::from_low_u64(0x10000));
        let u8t = AbiType::Uint(8);
        assert_eq!(parse_value(&u8t, "255", &no_names).unwrap(), AbiValue::Uint(U256::from_u64(255)));
        assert!(parse_value(&u8t, "256", &no_names).is_err());
        let i8t = AbiType::Int(8);
        assert_eq!(parse_value(&i8t, "-128", &no_names).unwrap().to_string(), "-128");
        assert!(parse_value(&i8t, "128", &no_names).is_err());
        assert!(parse_value(&i8t, "-129", &no_names).is_err());
        assert_eq!(
            parse_value(&AbiType::Address, "actor0", &names).unwrap(),
            AbiValue::Address(Address::from_low_u64(0x10000))
        );
        assert!(parse_value(&AbiType::Address, "bob", &names).is_err());
        assert_eq!(parse_value(&AbiType::Bool, "true", &no_names).unwrap(), AbiValue::Bool(true));
        assert!(parse_value(&AbiType::Bool, "yes", &no_names).is_err());
        assert!(parse_value(&AbiType::FixedBytes(2), "0x0102", &no_names).is_ok());
        assert!(parse_value(&AbiType::FixedBytes(2), "0x01", &no_names).is_err());
        assert_eq!(parse_value(&AbiType::String, "\"a,b\"", &no_names).unwrap(), AbiValue::String("a,b".into()));
        let arr = AbiType::parse("uint256[2]").unwrap();
        assert_eq!(parse_value(&arr, "[1, 0x2]", &no_names).unwrap().to_string(), "[1, 2]");
        assert!(parse_value(&arr, "[1]", &no_names).is_err());
        assert!(parse_value(&arr, "1,2", &no_names).is_err());
        let nested = AbiType::parse("uint8[][]").unwrap();
        assert_eq!(parse_value(&nested, "[[1,2],[]]", &no_names).unwrap().to_string(), "[[1, 2], []]");
        assert_eq!(parse_value(&AbiType::Bytes, "0xab", &no_names).unwrap().to_string(), "0xab");
    }

    #[test]
    fn json_abi_loading_and_revert_decoding() {
        let json = r#"[
          {"type":"constructor","inputs":[{"type":"uint256","name":"s"}],"stateMutability":"nonpayable"},
          {"type":"function","name":"deposit","inputs":[],"stateMutability":"payable"},
          {"type":"function","name":"view","inputs":[],"stateMutability":"view"},
          {"type":"function","name":"tup","inputs":[{"type":"tuple"}],"stateMutability":"nonpayable"},
          {"type":"event","name":"E","inputs":[]}
        ]"#;
        let abi = ContractAbi::from_json(json).unwrap();
        assert_eq!(abi.constructor, vec![AbiType::Uint(256)]);
        assert_eq!(abi.mutating.len(), 1);
        assert!(abi.mutating[0].payable);
        assert_eq!(abi.skipped, vec!["tup(tuple)".to_string()]);
        assert!(ContractAbi::from_json("{").is_err());

        let mut err = vec![0x08, 0xc3, 0x79, 0xa0];
        err.extend(encode_params(&[AbiType::String], &[AbiValue::String("nope".into())]).unwrap());
        assert_eq!(decode_revert(&err).as_deref(), Some("Error(\"nope\")"));
        let mut panic = vec![0x4e, 0x48, 0x7b, 0x71];
        panic.extend_from_slice(&U256::ONE.to_be_bytes());
        assert_eq!(decode_revert(&panic).as_deref(), Some("Panic(0x01: assert failed)"));
        assert_eq!(panic_code(&panic), Some(PANIC_ASSERT));
        assert_eq!(panic_code(&err), None);
        assert_eq!(decode_revert(&[1, 2]), None);
        assert_eq!(decode_revert(&[1, 2, 3, 4, 5]), None);
    }

    #[test]
    fn width_helpers() {
        assert_eq!(width_mask(8), U256::from_u64(255));
        assert_eq!(width_mask(256), U256::MAX);
        assert_eq!(sign_extend(U256::from_u64(0x80), 8), U256::from_u64(128).wrapping_neg());
        assert_eq!(sign_extend(U256::from_u64(0x7f), 8), U256::from_u64(0x7f));
        assert_eq!(sign_extend(U256::MAX, 256), U256::MAX);
    }
}
