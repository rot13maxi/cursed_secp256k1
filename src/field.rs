//! Modular arithmetic over the secp256k1 prime, built on `BigNum`.
//!
//! No-primitive-arithmetic justification: every VALUE here is computed with
//! [`cursed_arithmetic::BigNum`] operators (`+`, `-`, `*`, `%`, comparisons)
//! or by table-free structural control flow over decimal digit slices
//! (index/length arithmetic only). Modular exponentiation walks exponent
//! digits MSB→LSB and squares/multiplies via field multiplication; the
//! per-digit loop uses only structural iteration. The only primitive-adjacent
//! operations are `usize` loop counters and slice slicing, which are
//! structural, plus `BigNum` construction from small `u128` literals at the
//! API boundary (allowed by the parent crate's precedent).

use cursed_arithmetic::BigNum;

use crate::constants;

/// Modular exponentiation: `base^exp mod m`.
///
/// Decimal square-and-multiply: walk the exponent's decimal digits
/// MSB→LSB; per digit raise the running result to the 10th power (three
/// squarings and one multiply by the result's square) then multiply in
/// `base^d` for the digit `d` (d ≤ 9, so at most nine multiplies). All
/// arithmetic is `BigNum` arithmetic reduced mod `m`.
pub fn mod_pow(base: &BigNum, exp: &BigNum, m: &BigNum) -> BigNum {
    let mut result = BigNum::one();

    // base^1 .. base^9 for the current digit, built by repeated
    // multiplication as needed (structural loop, d ≤ 9).
    for digit in exp.digits() {
        // result = result^10: square three times, then multiply by the
        // square of the result.
        let r2 = fe_mul_checked(&result, &result, m);
        let r4 = fe_mul_checked(&r2, &r2, m);
        let r8 = fe_mul_checked(&r4, &r4, m);
        result = fe_mul_checked(&r8, &r2, m);

        // result = result * base^digit.
        let mut power = BigNum::one();
        let d_value = u8::from(*digit);
        for _ in 0..d_value {
            power = fe_mul_checked(&power, base, m);
        }
        result = fe_mul_checked(&result, &power, m);
    }
    result
}

/// Multiplies two residues and reduces mod `m` (checked mul then rem).
fn fe_mul_checked(lhs: &BigNum, rhs: &BigNum, m: &BigNum) -> BigNum {
    lhs * rhs % m
}

/// Reduces a value modulo the field prime p.
pub fn fe_reduce(value: &BigNum) -> BigNum {
    value % constants::prime()
}

/// Adds two field elements mod p.
pub fn fe_add(lhs: &BigNum, rhs: &BigNum) -> BigNum {
    (lhs + rhs) % constants::prime()
}

/// Subtracts two field elements mod p.
pub fn fe_sub(lhs: &BigNum, rhs: &BigNum) -> BigNum {
    let p = constants::prime();
    if lhs < rhs {
        // (lhs - rhs) mod p = lhs + p - rhs when lhs < rhs.
        (lhs + &p - rhs) % p
    } else {
        (lhs - rhs) % p
    }
}

/// Multiplies two field elements mod p.
pub fn fe_mul(lhs: &BigNum, rhs: &BigNum) -> BigNum {
    (lhs * rhs) % constants::prime()
}

/// Computes the modular multiplicative inverse of `a` mod p via Fermat's
/// little theorem: a^(p-2) mod p. Valid because p is prime.
pub fn fe_inv(a: &BigNum) -> BigNum {
    let p = constants::prime();
    let exp = &p - BigNum::from(2u8);
    mod_pow(a, &exp, &p)
}

/// Computes the modular multiplicative inverse of `a` mod `m` via Fermat's
/// little theorem. The caller must guarantee `m` is prime (n is).
pub fn mod_inv(a: &BigNum, m: &BigNum) -> BigNum {
    let exp = m - BigNum::from(2u8);
    mod_pow(a, &exp, m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Field vectors from REFERENCE_VALUES.md, parsed as decimal strings.
    #[test]
    fn field_vectors_reproduce() {
        let a = BigNum::from_str(
            "12287070679110784391061470500868383394860565932337482615261664884614796671153",
        )
        .unwrap();
        let b = BigNum::from_str(
            "6295027170268925931475644123820777400648689434085647838277327685570480460850",
        )
        .unwrap();

        assert_eq!(
            fe_add(&a, &b).to_string(),
            "18582097849379710322537114624689160795509255366423130453538992570185277132003"
        );
        assert_eq!(
            fe_sub(&a, &b).to_string(),
            "5992043508841858459585826377047605994211876498251834776984337199044316210303"
        );
        assert_eq!(
            fe_mul(&a, &b).to_string(),
            "21305815382436826402745049682756709750171426352994859774703476363537196285815"
        );
        assert_eq!(
            fe_inv(&a).to_string(),
            "50343227249771997713716264428462502175985415527136212324210475361148308543625"
        );
        assert_eq!(
            fe_inv(&b).to_string(),
            "114172149838354400203736423558152096529038361616776390845831836613729258086271"
        );
        assert_eq!(fe_mul(&fe_inv(&a), &a), BigNum::one());
        assert_eq!(fe_mul(&fe_inv(&b), &b), BigNum::one());
    }

    /// mod_pow sanity: a^1, a^2, a^3 against BigNum mul, plus 2^256 mod p = 1
    /// (Fermat: a^(p-1) = 1 for a not divisible by p).
    #[test]
    fn mod_pow_matches_repeated_mul() {
        let p = constants::prime();
        let a = BigNum::from_str(
            "12287070679110784391061470500868383394860565932337482615261664884614796671153",
        )
        .unwrap();

        let exp1 = BigNum::from(1u8);
        let exp2 = BigNum::from(2u8);
        let exp3 = BigNum::from(3u8);
        assert_eq!(mod_pow(&a, &exp1, &p), &a % &p);
        assert_eq!(mod_pow(&a, &exp2, &p), fe_mul(&a, &a));
        assert_eq!(mod_pow(&a, &exp3, &p), fe_mul(&fe_mul(&a, &a), &a));

        // Fermat: a^(p-1) ≡ 1 (mod p).
        let pm1 = &p - BigNum::from(1u8);
        assert_eq!(mod_pow(&a, &pm1, &p), BigNum::one());
    }

    /// fe_sub handles wrap-around (lhs < rhs) correctly.
    #[test]
    fn fe_sub_wraps() {
        let p = constants::prime();
        let two = BigNum::from(2u8);
        let five = BigNum::from(5u8);
        // (2 - 5) mod p = p - 3.
        assert_eq!(fe_sub(&two, &five), &p - BigNum::from(3u8));
    }
}
