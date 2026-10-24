//! Property tests: U256 arithmetic agrees with arbitrary-precision integers.

use evmfuzz::U256;
use num_bigint::BigUint;
use proptest::prelude::*;

fn big(v: U256) -> BigUint {
    BigUint::from_bytes_be(&v.to_be_bytes())
}

fn modulus() -> BigUint {
    BigUint::from(1u8) << 256
}

fn from_big(b: &BigUint) -> U256 {
    let m = b % modulus();
    U256::from_be_slice(&m.to_bytes_be())
}

fn signed(v: U256) -> num_bigint::BigInt {
    let b = num_bigint::BigInt::from(big(v));
    if v.is_negative() {
        b - num_bigint::BigInt::from(modulus())
    } else {
        b
    }
}

fn from_signed(b: num_bigint::BigInt) -> U256 {
    let m = num_bigint::BigInt::from(modulus());
    let r = ((b % &m) + &m) % &m;
    from_big(&r.to_biguint().expect("non-negative"))
}

fn arb_u256() -> impl Strategy<Value = U256> {
    prop_oneof![
        any::<[u64; 4]>().prop_map(U256),
        any::<u64>().prop_map(U256::from_u64),
        (0usize..256).prop_map(|k| U256::ONE.shl_bits(k)),
        (0usize..256).prop_map(|k| U256::ONE.shl_bits(k).wrapping_sub(U256::ONE)),
        Just(U256::MAX),
        Just(U256::ZERO),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn add_sub_mul_wrap(a in arb_u256(), b in arb_u256()) {
        prop_assert_eq!(a.wrapping_add(b), from_big(&(big(a) + big(b))));
        prop_assert_eq!(a.wrapping_sub(b), from_big(&(big(a) + modulus() - big(b))));
        prop_assert_eq!(a.wrapping_mul(b), from_big(&(big(a) * big(b))));
        prop_assert_eq!(a.checked_mul(b).is_none(), big(a) * big(b) >= modulus());
    }

    #[test]
    fn div_rem_and_mod_ops(a in arb_u256(), b in arb_u256(), m in arb_u256()) {
        if b.is_zero() {
            prop_assert_eq!(a.evm_div(b), U256::ZERO);
            prop_assert_eq!(a.evm_rem(b), U256::ZERO);
        } else {
            prop_assert_eq!(a.evm_div(b), from_big(&(big(a) / big(b))));
            prop_assert_eq!(a.evm_rem(b), from_big(&(big(a) % big(b))));
        }
        if m.is_zero() {
            prop_assert_eq!(a.evm_addmod(b, m), U256::ZERO);
            prop_assert_eq!(a.evm_mulmod(b, m), U256::ZERO);
        } else {
            prop_assert_eq!(a.evm_addmod(b, m), from_big(&((big(a) + big(b)) % big(m))));
            prop_assert_eq!(a.evm_mulmod(b, m), from_big(&((big(a) * big(b)) % big(m))));
        }
    }

    #[test]
    fn signed_division(a in arb_u256(), b in arb_u256()) {
        let (sa, sb) = (signed(a), signed(b));
        if !b.is_zero() {
            // EVM SDIV truncates toward zero (BigInt division does too); SMOD takes the dividend's sign.
            prop_assert_eq!(a.evm_sdiv(b), from_signed(&sa / &sb));
            prop_assert_eq!(a.evm_smod(b), from_signed(&sa % &sb));
        } else {
            prop_assert_eq!(a.evm_sdiv(b), U256::ZERO);
            prop_assert_eq!(a.evm_smod(b), U256::ZERO);
        }
    }

    #[test]
    fn exp_matches_modpow(a in arb_u256(), e in arb_u256()) {
        prop_assert_eq!(a.evm_exp(e), from_big(&big(a).modpow(&big(e), &modulus())));
    }

    #[test]
    fn shifts(a in arb_u256(), s in 0u64..300) {
        let sh = U256::from_u64(s);
        let expect_shl = if s >= 256 { U256::ZERO } else { from_big(&(big(a) << s as usize)) };
        let expect_shr = if s >= 256 { U256::ZERO } else { from_big(&(big(a) >> s as usize)) };
        prop_assert_eq!(a.evm_shl(sh), expect_shl);
        prop_assert_eq!(a.evm_shr(sh), expect_shr);
        // SAR is floor division by 2^s on the signed value.
        let sa = signed(a);
        let expect_sar = if s >= 256 {
            if a.is_negative() { U256::MAX } else { U256::ZERO }
        } else {
            let d = num_bigint::BigInt::from(1u8) << s as usize;
            let q = num_integer_floor_div(&sa, &d);
            from_signed(q)
        };
        prop_assert_eq!(a.evm_sar(sh), expect_sar);
    }

    #[test]
    fn decimal_and_hex_round_trip(a in arb_u256()) {
        prop_assert_eq!(a.to_string().parse::<U256>().unwrap(), a);
        prop_assert_eq!(U256::from_str_radix_auto(&format!("{a:#x}")).unwrap(), a);
        prop_assert_eq!(U256::from_be_bytes(a.to_be_bytes()), a);
    }

    #[test]
    fn comparisons(a in arb_u256(), b in arb_u256()) {
        prop_assert_eq!(a.cmp(&b), big(a).cmp(&big(b)));
        prop_assert_eq!(a.signed_cmp(&b), signed(a).cmp(&signed(b)));
    }
}

fn num_integer_floor_div(a: &num_bigint::BigInt, d: &num_bigint::BigInt) -> num_bigint::BigInt {
    let q = a / d;
    if (a % d) != num_bigint::BigInt::from(0) && (a.sign() == num_bigint::Sign::Minus) {
        q - 1
    } else {
        q
    }
}
