# Cursed secp256k1

ECDSA signature generation and verification over the secp256k1 curve, built
entirely on top of [`cursed_arithmetic`](https://crates.io/crates/cursed_arithmetic).
Every field element, scalar, and coordinate in this crate is a `BigNum` — a
`Vec<Digit>` of decimal enum variants — and every arithmetic operation on those
values goes through the table-driven schoolbook arithmetic of the parent crate.
The library performs **no primitive arithmetic** to compute any cryptographic
value.

SHA-256 is implemented from scratch with one-bit lookup tables for every bitwise
operation and a 32-bit ripple-carry adder built on a full-adder table. ECDSA
nonces are deterministic per RFC 6979 (HMAC-SHA256, spec-faithful steps b–h),
and signatures are normalized to low-S.

```rust,ignore
use cursed_secp256k1::ecdsa::{sign, verify, public_key};
use cursed_arithmetic::BigNum;

let d: BigNum = "91225253027397101270059260515990221874496108017261222445699397644687913215777"
    .parse()
    .unwrap();
let sig = sign(b"sample", &d).unwrap();
let (qx, qy) = public_key(&d).unwrap();
assert!(verify(b"sample", &sig.r, &sig.s, &qx, &qy));
```

## How it works

- **Field arithmetic** (`field`): modular add/sub/mul mod p on `BigNum`
  operands; inversion by Fermat's little theorem, a^(p−2) mod p, with the
  exponentiation done as decimal square-and-multiply — the exponent is walked
  one DECIMAL digit at a time, raising the accumulator to the 10th power
  (three squarings and a multiply) and then multiplying in base^d for the
  digit d.
- **Point arithmetic** (`jacobian`): secp256k1 points live in Jacobian
  coordinates so that a full chain of doublings and additions needs exactly one
  field inversion at the end (affine conversion), not one per operation. Scalar
  multiplication walks the scalar's decimal digits MSB→LSB as Horner's method:
  per digit, Q ← 10·Q + d·G, where 10·Q decomposes into three doublings and one
  addition of Q (10·Q = 2·(2·(2·Q) + Q)).
- **SHA-256** (`sha256`): words are `u32` bit carriers; every logical or
  arithmetic VALUE comes from one-bit lookup tables (`AND_TABLE`, `XOR_TABLE`,
  `FULL_ADDER`), with addition implemented as a 32-iteration ripple-carry.
  Rotations and shifts are structural bit movement. The 64 round constants are
  hex literals: data, not computations.
- **ECDSA** (`ecdsa`): the digest is converted to an integer by Horner
  evaluation in base 256 over `BigNum` (z = z·256 + byte), avoiding any
  primitive binary-to-decimal conversion. Nonces come from RFC 6979 with
  HMAC-SHA256 built on this crate's own SHA-256.

## Performance

Slow, on purpose. Every field element is a heap-allocated `Vec` of decimal
digit enums and every operation is schoolbook decimal arithmetic over those
vectors. Expect a full signature verification to take on the order of
**tens of seconds to minutes** depending on your machine (the parent crate's
benchmarks put its arithmetic at several orders of magnitude behind
`num-bigint`, which itself is far from optimized curve work). Scalar
multiplication of a 77-digit scalar walks ~2,800 point operations, each of
which is dozens of big-integer multiplications.

## Security

**DO NOT USE THIS LIBRARY TO PROTECT ANYTHING.** This crate is a joke with a
straight face: it produces and verifies real, standards-compliant ECDSA
signatures — slowly — while doing so in a manner that is a timing-side-channel
paradise. Comparison is variable-time; carries are data-dependent; allocation
behavior leaks; every branch in the scalar loop reads like a flush attack
waiting to happen. If your threat model includes anyone with a stopwatch, use
a real constant-time implementation. This crate exists to demonstrate that
correct cryptography can be assembled from lookup tables and decimal digit
vectors, not to secure funds.

## Testing

All test vectors were independently generated with a separate Python
implementation (curve equation checked for G, n·G = ∞ verified, signatures
independently verified) and live in `REFERENCE_VALUES.md`. The integration
test suite reproduces every vector digit-for-digit and cross-checks field
arithmetic against `num-bigint`. Run:

```sh
cargo test
```
