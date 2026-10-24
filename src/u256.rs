//! 256-bit unsigned integer with EVM (two's-complement, modulo 2^256) semantics.
//!
//! Limbs are stored little-endian (`limbs[0]` is the least significant 64 bits).
//! Every arithmetic operation wraps modulo 2^256 exactly like the EVM; signed
//! operations interpret the value as two's complement. Division uses Knuth's
//! algorithm D over 64-bit digits, which is also reused for the 512-bit
//! intermediate in `MULMOD`.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// A 256-bit unsigned integer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256(pub [u64; 4]);

/// Error returned when parsing a [`U256`] from text fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseU256Error {
    /// The input contained a character that is not a digit in the radix.
    #[error("invalid digit in number literal")]
    InvalidDigit,
    /// The value does not fit in 256 bits.
    #[error("number literal does not fit in 256 bits")]
    Overflow,
    /// The input was empty.
    #[error("empty number literal")]
    Empty,
}

impl U256 {
    /// The value 0.
    pub const ZERO: U256 = U256([0; 4]);
    /// The value 1.
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    /// The value 2^256 - 1.
    pub const MAX: U256 = U256([u64::MAX; 4]);

    /// Builds a value from a `u64`.
    pub const fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// Builds a value from a `u128`.
    pub const fn from_u128(v: u128) -> Self {
        U256([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// Returns true when the value is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    /// Lowest 64 bits.
    #[inline]
    pub fn low_u64(&self) -> u64 {
        self.0[0]
    }

    /// Returns the value as `u64` if it fits.
    #[inline]
    pub fn to_u64(&self) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            Some(self.0[0])
        } else {
            None
        }
    }

    /// Returns the value as `usize` if it fits.
    #[inline]
    pub fn to_usize(&self) -> Option<usize> {
        self.to_u64().and_then(|v| usize::try_from(v).ok())
    }

    /// Returns the value as `u128` if it fits.
    pub fn to_u128(&self) -> Option<u128> {
        if self.0[2] == 0 && self.0[3] == 0 {
            Some(u128::from(self.0[0]) | (u128::from(self.0[1]) << 64))
        } else {
            None
        }
    }

    /// Value saturated to `u64::MAX`.
    #[inline]
    pub fn saturating_u64(&self) -> u64 {
        self.to_u64().unwrap_or(u64::MAX)
    }

    /// Number of significant bits (0 for zero).
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    /// Number of significant bytes (0 for zero).
    pub fn byte_len(&self) -> u32 {
        self.bits().div_ceil(8)
    }

    /// Returns bit `i` (0 = least significant).
    #[inline]
    pub fn bit(&self, i: usize) -> bool {
        i < 256 && (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    /// Interprets up to 32 big-endian bytes (shorter slices are left-padded).
    ///
    /// # Panics
    /// Panics if `bytes` is longer than 32.
    pub fn from_be_slice(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= 32, "U256::from_be_slice: more than 32 bytes");
        let mut buf = [0u8; 32];
        buf[32 - bytes.len()..].copy_from_slice(bytes);
        Self::from_be_bytes(buf)
    }

    /// Interprets exactly 32 big-endian bytes.
    pub fn from_be_bytes(b: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = 32 - 8 * (i + 1);
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&b[start..start + 8]);
            *limb = u64::from_be_bytes(chunk);
        }
        U256(limbs)
    }

    /// Big-endian 32-byte encoding.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            let start = 32 - 8 * (i + 1);
            out[start..start + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        out
    }

    /// Minimal big-endian encoding (empty for zero), as used by RLP.
    pub fn to_be_bytes_trimmed(&self) -> Vec<u8> {
        let bytes = self.to_be_bytes();
        let skip = 32 - self.byte_len() as usize;
        bytes[skip..].to_vec()
    }

    /// Parses a `0x`-prefixed hex string or a decimal string.
    pub fn from_str_radix_auto(s: &str) -> Result<Self, ParseU256Error> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Self::from_hex(hex)
        } else {
            Self::from_dec(s)
        }
    }

    /// Parses an unprefixed hex string (an empty string is zero).
    pub fn from_hex(hex: &str) -> Result<Self, ParseU256Error> {
        let hex = hex.trim_start_matches('0');
        if hex.len() > 64 {
            return Err(ParseU256Error::Overflow);
        }
        let mut out = U256::ZERO;
        for c in hex.chars() {
            let d = c.to_digit(16).ok_or(ParseU256Error::InvalidDigit)?;
            out = out.shl_bits(4) | U256::from_u64(u64::from(d));
        }
        Ok(out)
    }

    /// Parses a decimal string.
    pub fn from_dec(dec: &str) -> Result<Self, ParseU256Error> {
        if dec.is_empty() {
            return Err(ParseU256Error::Empty);
        }
        let ten = U256::from_u64(10);
        let mut out = U256::ZERO;
        for c in dec.chars() {
            if c == '_' {
                continue;
            }
            let d = c.to_digit(10).ok_or(ParseU256Error::InvalidDigit)?;
            let (m, o1) = out.overflowing_mul(ten);
            let (a, o2) = m.overflowing_add(U256::from_u64(u64::from(d)));
            if o1 || o2 {
                return Err(ParseU256Error::Overflow);
            }
            out = a;
        }
        Ok(out)
    }

    /// Addition with overflow flag.
    #[inline]
    pub fn overflowing_add(self, rhs: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (i, o) in out.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            *o = s2;
            carry = c1 || c2;
        }
        (U256(out), carry)
    }

    /// Subtraction with borrow flag.
    #[inline]
    pub fn overflowing_sub(self, rhs: U256) -> (U256, bool) {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for (i, o) in out.iter_mut().enumerate() {
            let (d1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            *o = d2;
            borrow = b1 || b2;
        }
        (U256(out), borrow)
    }

    /// Wrapping addition modulo 2^256.
    #[inline]
    pub fn wrapping_add(self, rhs: U256) -> U256 {
        self.overflowing_add(rhs).0
    }

    /// Wrapping subtraction modulo 2^256.
    #[inline]
    pub fn wrapping_sub(self, rhs: U256) -> U256 {
        self.overflowing_sub(rhs).0
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: U256) -> Option<U256> {
        match self.overflowing_add(rhs) {
            (v, false) => Some(v),
            _ => None,
        }
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: U256) -> Option<U256> {
        match self.overflowing_sub(rhs) {
            (v, false) => Some(v),
            _ => None,
        }
    }

    /// Saturating addition.
    pub fn saturating_add(self, rhs: U256) -> U256 {
        self.checked_add(rhs).unwrap_or(U256::MAX)
    }

    /// Saturating subtraction.
    pub fn saturating_sub(self, rhs: U256) -> U256 {
        self.checked_sub(rhs).unwrap_or(U256::ZERO)
    }

    /// Full 256x256 -> 512-bit product, little-endian limbs.
    fn full_mul(self, rhs: U256) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            if self.0[i] == 0 {
                continue;
            }
            let mut carry: u128 = 0;
            for j in 0..4 {
                let t = u128::from(self.0[i]) * u128::from(rhs.0[j]) + u128::from(out[i + j]) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }

    /// Multiplication with overflow flag.
    pub fn overflowing_mul(self, rhs: U256) -> (U256, bool) {
        let full = self.full_mul(rhs);
        let overflow = full[4..].iter().any(|&l| l != 0);
        (U256([full[0], full[1], full[2], full[3]]), overflow)
    }

    /// Wrapping multiplication modulo 2^256.
    #[inline]
    pub fn wrapping_mul(self, rhs: U256) -> U256 {
        // Truncated schoolbook: only the low four limbs are needed.
        let mut out = [0u64; 4];
        for i in 0..4 {
            if self.0[i] == 0 {
                continue;
            }
            let mut carry: u128 = 0;
            for j in 0..4 - i {
                let t = u128::from(self.0[i]) * u128::from(rhs.0[j]) + u128::from(out[i + j]) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
        }
        U256(out)
    }

    /// Unsigned division and remainder; `None` when dividing by zero.
    pub fn div_rem(self, rhs: U256) -> Option<(U256, U256)> {
        if rhs.is_zero() {
            return None;
        }
        if let (Some(a), Some(b)) = (self.to_u128(), rhs.to_u128()) {
            return Some((U256::from_u128(a / b), U256::from_u128(a % b)));
        }
        if self < rhs {
            return Some((U256::ZERO, self));
        }
        let (q, r) = knuth_div_rem(&self.0, &rhs.0);
        Some((limbs_to_u256(&q), limbs_to_u256(&r)))
    }

    /// EVM `DIV`: division by zero yields zero.
    pub fn evm_div(self, rhs: U256) -> U256 {
        self.div_rem(rhs).map_or(U256::ZERO, |(q, _)| q)
    }

    /// EVM `MOD`: modulo zero yields zero.
    pub fn evm_rem(self, rhs: U256) -> U256 {
        self.div_rem(rhs).map_or(U256::ZERO, |(_, r)| r)
    }

    /// Returns true when the two's-complement sign bit is set.
    #[inline]
    pub fn is_negative(&self) -> bool {
        self.0[3] >> 63 == 1
    }

    /// Two's-complement negation.
    #[inline]
    pub fn wrapping_neg(self) -> U256 {
        (!self).wrapping_add(U256::ONE)
    }

    fn abs_signed(self) -> U256 {
        if self.is_negative() {
            self.wrapping_neg()
        } else {
            self
        }
    }

    /// EVM `SDIV` (truncating toward zero, `MIN / -1 == MIN`).
    pub fn evm_sdiv(self, rhs: U256) -> U256 {
        if rhs.is_zero() {
            return U256::ZERO;
        }
        let neg = self.is_negative() != rhs.is_negative();
        let q = self.abs_signed().evm_div(rhs.abs_signed());
        if neg {
            q.wrapping_neg()
        } else {
            q
        }
    }

    /// EVM `SMOD` (result takes the sign of the dividend).
    pub fn evm_smod(self, rhs: U256) -> U256 {
        if rhs.is_zero() {
            return U256::ZERO;
        }
        let r = self.abs_signed().evm_rem(rhs.abs_signed());
        if self.is_negative() {
            r.wrapping_neg()
        } else {
            r
        }
    }

    /// EVM `ADDMOD`: `(a + b) % m` computed without intermediate overflow.
    pub fn evm_addmod(self, b: U256, m: U256) -> U256 {
        if m.is_zero() {
            return U256::ZERO;
        }
        let (sum, carry) = self.overflowing_add(b);
        if !carry {
            return sum.evm_rem(m);
        }
        let wide = [sum.0[0], sum.0[1], sum.0[2], sum.0[3], 1];
        let (_, r) = knuth_div_rem(&wide, &m.0);
        limbs_to_u256(&r)
    }

    /// EVM `MULMOD`: `(a * b) % m` computed over 512 bits.
    pub fn evm_mulmod(self, b: U256, m: U256) -> U256 {
        if m.is_zero() {
            return U256::ZERO;
        }
        let wide = self.full_mul(b);
        let (_, r) = knuth_div_rem(&wide, &m.0);
        limbs_to_u256(&r)
    }

    /// EVM `EXP` (wrapping exponentiation).
    pub fn evm_exp(self, mut exp: U256) -> U256 {
        let mut base = self;
        let mut acc = U256::ONE;
        while !exp.is_zero() {
            if exp.0[0] & 1 == 1 {
                acc = acc.wrapping_mul(base);
            }
            exp = exp.shr_bits(1);
            if !exp.is_zero() {
                base = base.wrapping_mul(base);
            }
        }
        acc
    }

    /// EVM `SIGNEXTEND(b, x)`: extend the sign of byte `b` (0 = least significant).
    pub fn evm_signextend(self, b: U256) -> U256 {
        match b.to_u64() {
            Some(b) if b < 31 => {
                let bit = (b * 8 + 7) as usize;
                let mask = (U256::ONE.shl_bits(bit + 1)).wrapping_sub(U256::ONE);
                if self.bit(bit) {
                    self | !mask
                } else {
                    self & mask
                }
            }
            _ => self,
        }
    }

    /// EVM `BYTE(i, x)`: the `i`-th byte counting from the most significant.
    pub fn evm_byte(self, i: U256) -> U256 {
        match i.to_u64() {
            Some(i) if i < 32 => U256::from_u64(u64::from(self.to_be_bytes()[i as usize])),
            _ => U256::ZERO,
        }
    }

    /// Logical left shift by `n` bits (zero when `n >= 256`).
    pub fn shl_bits(self, n: usize) -> U256 {
        if n >= 256 {
            return U256::ZERO;
        }
        let limb_shift = n / 64;
        let bit_shift = n % 64;
        let mut out = [0u64; 4];
        for i in (limb_shift..4).rev() {
            let src = i - limb_shift;
            out[i] = self.0[src] << bit_shift;
            if bit_shift > 0 && src > 0 {
                out[i] |= self.0[src - 1] >> (64 - bit_shift);
            }
        }
        U256(out)
    }

    /// Logical right shift by `n` bits (zero when `n >= 256`).
    pub fn shr_bits(self, n: usize) -> U256 {
        if n >= 256 {
            return U256::ZERO;
        }
        let limb_shift = n / 64;
        let bit_shift = n % 64;
        let mut out = [0u64; 4];
        for (i, o) in out.iter_mut().enumerate().take(4 - limb_shift) {
            let src = i + limb_shift;
            *o = self.0[src] >> bit_shift;
            if bit_shift > 0 && src + 1 < 4 {
                *o |= self.0[src + 1] << (64 - bit_shift);
            }
        }
        U256(out)
    }

    /// EVM `SHL(shift, value)`.
    pub fn evm_shl(self, shift: U256) -> U256 {
        shift.to_usize().map_or(U256::ZERO, |s| self.shl_bits(s))
    }

    /// EVM `SHR(shift, value)`.
    pub fn evm_shr(self, shift: U256) -> U256 {
        shift.to_usize().map_or(U256::ZERO, |s| self.shr_bits(s))
    }

    /// EVM `SAR(shift, value)` (arithmetic shift).
    pub fn evm_sar(self, shift: U256) -> U256 {
        let neg = self.is_negative();
        match shift.to_usize() {
            Some(s) if s < 256 => {
                let shifted = self.shr_bits(s);
                if neg && s > 0 {
                    shifted | !(U256::MAX.shr_bits(s))
                } else {
                    shifted
                }
            }
            _ => {
                if neg {
                    U256::MAX
                } else {
                    U256::ZERO
                }
            }
        }
    }

    /// Signed (two's-complement) comparison.
    pub fn signed_cmp(&self, other: &U256) -> Ordering {
        match (self.is_negative(), other.is_negative()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.cmp(other),
        }
    }

    /// Lower-case hex with `0x` prefix and no leading zeros (`0x0` for zero).
    pub fn to_hex(&self) -> String {
        format!("{self:#x}")
    }
}

fn limbs_to_u256(limbs: &[u64]) -> U256 {
    let mut out = [0u64; 4];
    for (i, &l) in limbs.iter().enumerate() {
        if i < 4 {
            out[i] = l;
        } else {
            debug_assert_eq!(l, 0, "quotient/remainder exceeds 256 bits");
        }
    }
    U256(out)
}

fn trimmed_len(x: &[u64]) -> usize {
    let mut n = x.len();
    while n > 0 && x[n - 1] == 0 {
        n -= 1;
    }
    n
}

/// Knuth algorithm D (TAOCP vol. 2, 4.3.1) on little-endian 64-bit digits.
///
/// Returns `(quotient, remainder)`. `v` must be non-zero.
fn knuth_div_rem(u: &[u64], v: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let n = trimmed_len(v);
    let m = trimmed_len(u);
    assert!(n > 0, "division by zero");
    if m < n {
        return (vec![0], u[..m.max(1)].to_vec());
    }
    if n == 1 {
        let d = u128::from(v[0]);
        let mut q = vec![0u64; m];
        let mut rem: u128 = 0;
        for i in (0..m).rev() {
            let cur = (rem << 64) | u128::from(u[i]);
            q[i] = (cur / d) as u64;
            rem = cur % d;
        }
        return (q, vec![rem as u64]);
    }
    let s = v[n - 1].leading_zeros();
    let shl = |x: u64, lo: u64| -> u64 {
        if s == 0 {
            x
        } else {
            (x << s) | (lo >> (64 - s))
        }
    };
    let mut vn = vec![0u64; n];
    for i in (1..n).rev() {
        vn[i] = shl(v[i], v[i - 1]);
    }
    vn[0] = v[0] << s;
    let mut un = vec![0u64; m + 1];
    un[m] = if s == 0 { 0 } else { u[m - 1] >> (64 - s) };
    for i in (1..m).rev() {
        un[i] = shl(u[i], u[i - 1]);
    }
    un[0] = u[0] << s;

    let base: u128 = 1 << 64;
    let mut q = vec![0u64; m - n + 1];
    for j in (0..=m - n).rev() {
        let num = (u128::from(un[j + n]) << 64) | u128::from(un[j + n - 1]);
        let mut qhat = num / u128::from(vn[n - 1]);
        let mut rhat = num % u128::from(vn[n - 1]);
        while qhat >= base || qhat * u128::from(vn[n - 2]) > ((rhat << 64) | u128::from(un[j + n - 2])) {
            qhat -= 1;
            rhat += u128::from(vn[n - 1]);
            if rhat >= base {
                break;
            }
        }
        // Multiply and subtract.
        let mut borrow: i128 = 0;
        for i in 0..n {
            let p = qhat * u128::from(vn[i]);
            let t = i128::from(un[i + j]) - borrow - ((p & 0xffff_ffff_ffff_ffff) as i128);
            un[i + j] = t as u64;
            borrow = ((p >> 64) as i128) - (t >> 64);
        }
        let t = i128::from(un[j + n]) - borrow;
        un[j + n] = t as u64;
        q[j] = qhat as u64;
        if t < 0 {
            // Add back.
            q[j] = q[j].wrapping_sub(1);
            let mut carry: u128 = 0;
            for i in 0..n {
                let t = u128::from(un[i + j]) + u128::from(vn[i]) + carry;
                un[i + j] = t as u64;
                carry = t >> 64;
            }
            un[j + n] = un[j + n].wrapping_add(carry as u64);
        }
    }
    let mut r = vec![0u64; n];
    for i in 0..n {
        r[i] = if s == 0 {
            un[i]
        } else {
            (un[i] >> s) | (un[i + 1] << (64 - s))
        };
    }
    (q, r)
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl std::ops::BitAnd for U256 {
    type Output = U256;
    fn bitand(self, r: U256) -> U256 {
        U256([self.0[0] & r.0[0], self.0[1] & r.0[1], self.0[2] & r.0[2], self.0[3] & r.0[3]])
    }
}

impl std::ops::BitOr for U256 {
    type Output = U256;
    fn bitor(self, r: U256) -> U256 {
        U256([self.0[0] | r.0[0], self.0[1] | r.0[1], self.0[2] | r.0[2], self.0[3] | r.0[3]])
    }
}

impl std::ops::BitXor for U256 {
    type Output = U256;
    fn bitxor(self, r: U256) -> U256 {
        U256([self.0[0] ^ r.0[0], self.0[1] ^ r.0[1], self.0[2] ^ r.0[2], self.0[3] ^ r.0[3]])
    }
}

impl std::ops::Not for U256 {
    type Output = U256;
    fn not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }
}

impl From<u64> for U256 {
    fn from(v: u64) -> Self {
        U256::from_u64(v)
    }
}

impl From<u128> for U256 {
    fn from(v: u128) -> Self {
        U256::from_u128(v)
    }
}

impl From<bool> for U256 {
    fn from(v: bool) -> Self {
        U256::from_u64(u64::from(v))
    }
}

impl FromStr for U256 {
    type Err = ParseU256Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        U256::from_str_radix_auto(s)
    }
}

impl fmt::LowerHex for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut started = false;
        for i in (0..4).rev() {
            if started {
                s.push_str(&format!("{:016x}", self.0[i]));
            } else if self.0[i] != 0 {
                s.push_str(&format!("{:x}", self.0[i]));
                started = true;
            }
        }
        if s.is_empty() {
            s.push('0');
        }
        f.pad_integral(true, "0x", &s)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return f.pad_integral(true, "", "0");
        }
        let mut digits = Vec::new();
        let mut cur = *self;
        let ten19 = U256::from_u64(10_000_000_000_000_000_000);
        while !cur.is_zero() {
            let (q, r) = cur.div_rem(ten19).expect("non-zero divisor");
            digits.push(r.low_u64());
            cur = q;
        }
        let mut s = format!("{}", digits.pop().unwrap_or(0));
        for d in digits.iter().rev() {
            s.push_str(&format!("{d:019}"));
        }
        f.pad_integral(true, "", &s)
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:#x}")
    }
}

impl serde::Serialize for U256 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for U256 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let s = s.trim();
        // ethereum/tests uses a `0x:bigint ` prefix for some huge literals.
        let s = s.strip_prefix("0x:bigint ").unwrap_or(s);
        U256::from_str_radix_auto(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> U256 {
        U256::from_str_radix_auto(s).unwrap()
    }

    #[test]
    fn parse_and_display_roundtrip() {
        let v = h("0x1234567890abcdef1234567890abcdef1234567890abcdef");
        assert_eq!(format!("{v:#x}"), "0x1234567890abcdef1234567890abcdef1234567890abcdef");
        assert_eq!(U256::MAX.to_string(), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
        assert_eq!(h("12345678901234567890123").to_string(), "12345678901234567890123");
        assert_eq!(U256::ZERO.to_hex(), "0x0");
        assert_eq!(h("0x"), U256::ZERO);
        assert!(U256::from_dec("").is_err());
        assert!(U256::from_hex(&"f".repeat(65)).is_err());
        assert!(U256::from_dec("1157920892373161954235709850086879078532699846656405640394575840079131296399360").is_err());
        assert!(U256::from_hex("xyz").is_err());
    }

    #[test]
    fn signed_ops() {
        let minus_one = U256::MAX;
        let min = U256::ONE.shl_bits(255);
        assert_eq!(min.evm_sdiv(minus_one), min);
        assert_eq!(h("10").evm_sdiv(minus_one), h("10").wrapping_neg());
        assert_eq!(h("10").wrapping_neg().evm_smod(h("3")), U256::ONE.wrapping_neg());
        assert_eq!(h("10").evm_smod(h("3").wrapping_neg()), U256::ONE);
        assert_eq!(minus_one.evm_sar(h("300")), U256::MAX);
        assert_eq!(min.evm_sar(h("255")), U256::MAX);
        assert_eq!(h("0xff").evm_signextend(U256::ZERO), U256::MAX);
        assert_eq!(h("0x7f").evm_signextend(U256::ZERO), h("0x7f"));
        assert_eq!(minus_one.signed_cmp(&U256::ONE), Ordering::Less);
    }

    #[test]
    fn exp_and_byte() {
        assert_eq!(h("2").evm_exp(h("255")), U256::ONE.shl_bits(255));
        assert_eq!(h("2").evm_exp(h("256")), U256::ZERO);
        assert_eq!(h("3").evm_exp(U256::ZERO), U256::ONE);
        assert_eq!(h("0x1122").evm_byte(h("31")), h("0x22"));
        assert_eq!(h("0x1122").evm_byte(h("32")), U256::ZERO);
        assert_eq!(U256::from_be_slice(&[1, 2]).to_be_bytes_trimmed(), vec![1, 2]);
    }
}
