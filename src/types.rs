//! Fixed-size byte types used throughout the EVM: 20-byte addresses and
//! 32-byte words, plus hex helpers.

use crate::u256::U256;
use std::fmt;
use std::str::FromStr;

/// Error returned when decoding hex text fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    /// Odd number of hex digits.
    #[error("hex string has an odd number of digits")]
    OddLength,
    /// A non-hex character was found.
    #[error("invalid hex character {0:?}")]
    InvalidChar(char),
    /// The decoded value has the wrong length.
    #[error("expected {expected} bytes, got {got}")]
    WrongLength {
        /// Required byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
}

/// Decodes hex with or without a `0x` prefix.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let nib = |c: u8| -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(HexError::InvalidChar(c as char)),
        }
    };
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

/// Encodes bytes as lower-case hex with a `0x` prefix.
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// A 20-byte account address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// The zero address.
    pub const ZERO: Address = Address([0; 20]);

    /// Low 160 bits of a word.
    pub fn from_word(w: U256) -> Self {
        let b = w.to_be_bytes();
        let mut a = [0u8; 20];
        a.copy_from_slice(&b[12..]);
        Address(a)
    }

    /// Zero-extends to a word.
    pub fn to_word(self) -> U256 {
        U256::from_be_slice(&self.0)
    }

    /// Address whose last eight bytes hold `n` (used for test actors and precompiles).
    pub fn from_low_u64(n: u64) -> Self {
        let mut a = [0u8; 20];
        a[12..].copy_from_slice(&n.to_be_bytes());
        Address(a)
    }

    /// Builds an address from a 20-byte slice.
    pub fn from_slice(s: &[u8]) -> Result<Self, HexError> {
        let arr: [u8; 20] = s.try_into().map_err(|_| HexError::WrongLength { expected: 20, got: s.len() })?;
        Ok(Address(arr))
    }
}

impl FromStr for Address {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_slice(&decode_hex(s)?)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A 32-byte hash or word.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct B256(pub [u8; 32]);

impl B256 {
    /// All-zero hash.
    pub const ZERO: B256 = B256([0; 32]);

    /// Interprets the bytes as a big-endian word.
    pub fn to_u256(self) -> U256 {
        U256::from_be_bytes(self.0)
    }
}

impl From<U256> for B256 {
    fn from(v: U256) -> Self {
        B256(v.to_be_bytes())
    }
}

impl FromStr for B256 {
    type Err = HexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = decode_hex(s)?;
        let arr: [u8; 32] = v.as_slice().try_into().map_err(|_| HexError::WrongLength { expected: 32, got: v.len() })?;
        Ok(B256(arr))
    }
}

impl fmt::Display for B256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex(&self.0))
    }
}

impl fmt::Debug for B256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<'de> serde::Deserialize<'de> for B256 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_errors() {
        assert_eq!(decode_hex("0xdeadBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(encode_hex(&[0, 255]), "0x00ff");
        assert_eq!(decode_hex("abc"), Err(HexError::OddLength));
        assert_eq!(decode_hex("zz"), Err(HexError::InvalidChar('z')));
        assert!("0x1234".parse::<Address>().is_err());
        assert!("0x1234".parse::<B256>().is_err());
    }

    #[test]
    fn address_word_conversion() {
        let a: Address = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b".parse().unwrap();
        assert_eq!(Address::from_word(a.to_word()), a);
        assert_eq!(Address::from_low_u64(3).to_string(), "0x0000000000000000000000000000000000000003");
        let w = U256::MAX;
        assert_eq!(Address::from_word(w).0, [0xff; 20]);
    }
}
