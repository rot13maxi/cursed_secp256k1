//! Decimal digit-array constants for secp256k1.
//!
//! No-primitive-arithmetic justification: this module contains only compile
//! time `u8` digit tables (values 0..=9) copied from independently generated
//! reference values, and builder functions that hand those tables to
//! [`cursed_arithmetic::BigNum::from_digits`]. No primitive arithmetic is used
//! to compute any cryptographic value; the arrays are data, not computations.

use cursed_arithmetic::{BigNum, Digit};

/// The field modulus p = 2^256 - 2^32 - 977 as decimal digits, most
/// significant first.
pub const P_DIGITS: [u8; 78] = [
    1, 1, 5, 7, 9, 2, 0, 8, 9, 2, 3, 7, 3, 1, 6, 1, 9, 5, 4, 2, 3, 5, 7, 0, 9, 8, 5, 0, 0, 8, 6, 8,
    7, 9, 0, 7, 8, 5, 3, 2, 6, 9, 9, 8, 4, 6, 6, 5, 6, 4, 0, 5, 6, 4, 0, 3, 9, 4, 5, 7, 5, 8, 4, 0,
    0, 7, 9, 0, 8, 8, 3, 4, 6, 7, 1, 6, 6, 3,
];

/// The group order n (number of points on the curve) as decimal digits.
pub const N_DIGITS: [u8; 78] = [
    1, 1, 5, 7, 9, 2, 0, 8, 9, 2, 3, 7, 3, 1, 6, 1, 9, 5, 4, 2, 3, 5, 7, 0, 9, 8, 5, 0, 0, 8, 6, 8,
    7, 9, 0, 7, 8, 5, 2, 8, 3, 7, 5, 6, 4, 2, 7, 9, 0, 7, 4, 9, 0, 4, 3, 8, 2, 6, 0, 5, 1, 6, 3, 1,
    4, 1, 5, 1, 8, 1, 6, 1, 4, 9, 4, 3, 3, 7,
];

/// The x coordinate of the generator point G as decimal digits.
pub const GX_DIGITS: [u8; 77] = [
    5, 5, 0, 6, 6, 2, 6, 3, 0, 2, 2, 2, 7, 7, 3, 4, 3, 6, 6, 9, 5, 7, 8, 7, 1, 8, 8, 9, 5, 1, 6, 8,
    5, 3, 4, 3, 2, 6, 2, 5, 0, 6, 0, 3, 4, 5, 3, 7, 7, 7, 5, 9, 4, 1, 7, 5, 5, 0, 0, 1, 8, 7, 3, 6,
    0, 3, 8, 9, 1, 1, 6, 7, 2, 9, 2, 4, 0,
];

/// The y coordinate of the generator point G as decimal digits.
pub const GY_DIGITS: [u8; 77] = [
    3, 2, 6, 7, 0, 5, 1, 0, 0, 2, 0, 7, 5, 8, 8, 1, 6, 9, 7, 8, 0, 8, 3, 0, 8, 5, 1, 3, 0, 5, 0, 7,
    0, 4, 3, 1, 8, 4, 4, 7, 1, 2, 7, 3, 3, 8, 0, 6, 5, 9, 2, 4, 3, 2, 7, 5, 9, 3, 8, 9, 0, 4, 3, 3,
    5, 7, 5, 7, 3, 3, 7, 4, 8, 2, 4, 2, 4,
];

/// n / 2 as decimal digits (used for low-S normalization).
pub const HALF_N_DIGITS: [u8; 77] = [
    5, 7, 8, 9, 6, 0, 4, 4, 6, 1, 8, 6, 5, 8, 0, 9, 7, 7, 1, 1, 7, 8, 5, 4, 9, 2, 5, 0, 4, 3, 4, 3,
    9, 5, 3, 9, 2, 6, 4, 1, 8, 7, 8, 2, 1, 3, 9, 5, 3, 7, 4, 5, 2, 1, 9, 1, 3, 0, 2, 5, 8, 1, 5, 7,
    0, 7, 5, 9, 0, 8, 0, 7, 4, 7, 1, 6, 8,
];

/// Builds a [`BigNum`] from a decimal digit table.
fn big_from_digits(digits: &[u8]) -> BigNum {
    BigNum::from_digits(
        digits
            .iter()
            .map(|&d| Digit::try_from(d).expect("digit tables contain only 0..=9")),
    )
}

/// The field modulus p.
pub fn prime() -> BigNum {
    big_from_digits(&P_DIGITS)
}

/// The group order n.
pub fn order() -> BigNum {
    big_from_digits(&N_DIGITS)
}

/// The generator point G, affine coordinates.
pub fn generator() -> (BigNum, BigNum) {
    (big_from_digits(&GX_DIGITS), big_from_digits(&GY_DIGITS))
}

/// n / 2, used for low-S normalization.
pub fn half_order() -> BigNum {
    big_from_digits(&HALF_N_DIGITS)
}

/// The affine point at infinity sentinel: a Jacobian point with Z = 0.
/// Returned as the zero `BigNum` by convention in this crate.
pub fn zero() -> BigNum {
    BigNum::zero()
}

/// The `BigNum` one.
pub fn one() -> BigNum {
    BigNum::one()
}

/// The `BigNum` three (doubling formula coefficient, since a = 0).
pub fn three() -> BigNum {
    BigNum::from(3u8)
}

/// The `BigNum` four (doubling formula factor).
pub fn four() -> BigNum {
    BigNum::from(4u8)
}
