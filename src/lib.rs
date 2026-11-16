//! The cursed crate: ECDSA over secp256k1 on top of [`cursed_arithmetic`].
//!
//! This crate implements full ECDSA signature generation and verification
//! over the secp256k1 curve. Every field element, scalar, and coordinate is a
//! [`cursed_arithmetic::BigNum`] — a `Vec<Digit>` of decimal enum variants —
//! and every arithmetic operation on those values goes through the
//! table-driven schoolbook arithmetic of the `cursed_arithmetic` crate. The
//! library under test performs **no primitive arithmetic** to compute any
//! cryptographic value; only the tests use primitive arithmetic, as an
//! independent oracle.
//!
//! SHA-256 is implemented here from scratch with one-bit lookup tables for
//! every bitwise operation and a ripple-carry adder; nonces are deterministic
//! per RFC 6979; signatures are normalized to low-S.
//!
//! # !WARNING
//!
//! **DO NOT USE THIS LIBRARY TO PROTECT ANYTHING.** This crate is a joke with
//! a straight face: it produces and verifies real, standards-compliant ECDSA
//! signatures — slowly — while doing so in a manner that is a timing-side-
//! channel paradise. Comparison is variable-time; carries are data-dependent;
//! allocation behavior leaks secrets; every branch in the scalar loop reads
//! like a flush attack waiting to happen. If your threat model includes
//! anyone with a stopwatch, use a real, constant-time implementation instead.
//! This crate exists to demonstrate that correct cryptography can be built
//! from lookup tables and decimal digit vectors, not to secure funds.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod constants;
pub mod ecdsa;
pub mod field;
pub mod jacobian;
pub mod sha256;
