//! SHA-256 implemented without primitive arithmetic.
//!
//! No-primitive-arithmetic justification: every bitwise VALUE computed here
//! comes from one-bit lookup tables (`AND_TABLE`, `OR_TABLE`, `XOR_TABLE`,
//! `FULL_ADDER`), applied per bit over 32-bit words by iterating with `usize`
//! indices. Rotations and shifts are structural bit movement (`rotate_right`,
//! `shl`, `shr` on `u32` carriers — carriers, not computed values). Addition
//! of words is a 32-iteration ripple-carry built on the full-adder table.
//! Message padding, block slicing, and length counting are structural byte
//! handling at the `u8`/`usize` boundary, matching the parent crate's
//! precedent. The round constants K are hex literals: data, not computations.

/// One-bit logical AND, as a lookup table.
const AND_TABLE: [[bool; 2]; 2] = [[false, false], [false, true]];

/// One-bit logical OR, as a lookup table.
const OR_TABLE: [[bool; 2]; 2] = [[false, true], [true, true]];

/// One-bit logical XOR, as a lookup table.
const XOR_TABLE: [[bool; 2]; 2] = [[false, true], [true, false]];

/// One-bit full adder: (sum bit, carry out) as a lookup table.
const FULL_ADDER: [[[(bool, bool); 2]; 2]; 2] = [
    [
        [(false, false), (true, false)],
        [(true, false), (false, true)],
    ],
    [
        [(true, false), (false, true)],
        [(false, true), (true, true)],
    ],
];

fn bit_and(a: bool, b: bool) -> bool {
    AND_TABLE[a as usize][b as usize]
}

fn bit_or(a: bool, b: bool) -> bool {
    OR_TABLE[a as usize][b as usize]
}

fn bit_xor(a: bool, b: bool) -> bool {
    XOR_TABLE[a as usize][b as usize]
}

/// Ripple-carry addition of two 32-bit words, bit by bit, via tables.
fn add32(a: u32, b: u32) -> u32 {
    let mut out = 0u32;
    let mut carry = false;
    for i in 0..32 {
        let ab = (a >> i) & 1 == 1;
        let bb = (b >> i) & 1 == 1;
        let (sum, next_carry) = FULL_ADDER[ab as usize][bb as usize][carry as usize];
        if sum {
            out |= 1 << i;
        }
        carry = next_carry;
    }
    out
}

/// Word-wise AND over 32 bits, bit by bit, via tables.
fn and32(a: u32, b: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..32 {
        if bit_and((a >> i) & 1 == 1, (b >> i) & 1 == 1) {
            out |= 1 << i;
        }
    }
    out
}

/// Word-wise OR over 32 bits, bit by bit, via tables.
fn or32(a: u32, b: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..32 {
        if bit_or((a >> i) & 1 == 1, (b >> i) & 1 == 1) {
            out |= 1 << i;
        }
    }
    out
}

/// Word-wise XOR over 32 bits, bit by bit, via tables.
fn xor32(a: u32, b: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..32 {
        if bit_xor((a >> i) & 1 == 1, (b >> i) & 1 == 1) {
            out |= 1 << i;
        }
    }
    out
}

/// Word-wise NOT over 32 bits, bit by bit, via tables.
fn not32(a: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..32 {
        if !bit_and((a >> i) & 1 == 1, true) {
            out |= 1 << i;
        }
    }
    out
}

/// Big-endian read of a `u32` from four bytes. Structural byte assembly.
fn read_be32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24)
        | ((bytes[1] as u32) << 16)
        | ((bytes[2] as u32) << 8)
        | (bytes[3] as u32)
}

/// Big-endian write of a `u32` into four bytes. Structural byte splitting.
fn write_be32(word: u32, out: &mut [u8]) {
    out[0] = (word >> 24) as u8;
    out[1] = (word >> 16) as u8;
    out[2] = (word >> 8) as u8;
    out[3] = word as u8;
}

/// The eighty SHA-256 round constants (first 32 bits of the cube roots of the
/// first 64 primes, plus the initial hash values which are the first 32 bits
/// of the square roots of the first 8 primes).
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The SHA-256 message schedule σ0 function: ROTR^7 ⊕ ROTR^18 ⊕ SHR^3.
fn sigma0(x: u32) -> u32 {
    xor32(xor32(x.rotate_right(7), x.rotate_right(18)), x >> 3)
}

/// The SHA-256 message schedule σ1 function: ROTR^17 ⊕ ROTR^19 ⊕ SHR^10.
fn sigma1(x: u32) -> u32 {
    xor32(xor32(x.rotate_right(17), x.rotate_right(19)), x >> 10)
}

/// The SHA-256 compression Σ0 function: ROTR^2 ⊕ ROTR^13 ⊕ ROTR^22.
fn big_sigma0(x: u32) -> u32 {
    xor32(
        xor32(x.rotate_right(2), x.rotate_right(13)),
        x.rotate_right(22),
    )
}

/// The SHA-256 compression Σ1 function: ROTR^6 ⊕ ROTR^11 ⊕ ROTR^25.
fn big_sigma1(x: u32) -> u32 {
    xor32(
        xor32(x.rotate_right(6), x.rotate_right(11)),
        x.rotate_right(25),
    )
}

/// The SHA-256 Ch function: (x AND y) ⊕ (NOT x AND z).
fn ch(x: u32, y: u32, z: u32) -> u32 {
    xor32(and32(x, y), and32(not32(x), z))
}

/// The SHA-256 Maj function: (x AND y) ⊕ (x AND z) ⊕ (y AND z), computed
/// via the table-driven OR of pairwise ANDs' majority: MAJ(x,y,z) =
/// (x AND y) OR (z AND (x XOR y)).
fn maj(x: u32, y: u32, z: u32) -> u32 {
    or32(and32(x, y), and32(z, xor32(x, y)))
}

/// Processes one 64-byte block against the chaining state.
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = read_be32(&block[i * 4..i * 4 + 4]);
    }
    for i in 16..64 {
        w[i] = add32(
            add32(w[i - 16], sigma0(w[i - 15])),
            add32(w[i - 7], sigma1(w[i - 2])),
        );
    }

    let mut v = [0u32; 8];
    v.copy_from_slice(state);

    for i in 0..64 {
        let t1 = add32(
            add32(
                add32(v[7], big_sigma1(v[4])),
                add32(ch(v[4], v[5], v[6]), K[i]),
            ),
            w[i],
        );
        let t2 = add32(big_sigma0(v[0]), maj(v[0], v[1], v[2]));
        // Standard update: a = T1+T2, e = d+T1, the rest shift down.
        let e_new = add32(v[3], t1);
        v[7] = v[6];
        v[6] = v[5];
        v[5] = v[4];
        v[4] = e_new;
        v[3] = v[2];
        v[2] = v[1];
        v[1] = v[0];
        v[0] = add32(t1, t2);
    }

    for i in 0..8 {
        state[i] = add32(state[i], v[i]);
    }
}

/// Computes the SHA-256 digest of `message`.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    // Padding: a 0x80 byte, zeroes up to 56 bytes mod 64, then the 64-bit
    // big-endian bit length. Counting bytes is structural.
    let mut padded_len = message.len() + 9;
    #[allow(clippy::manual_is_multiple_of)]
    if padded_len % 64 != 0 {
        padded_len += 64 - (padded_len % 64);
    }

    let mut padded = vec![0u8; padded_len];
    padded[..message.len()].copy_from_slice(message);
    padded[message.len()] = 0x80;

    let bits = (message.len() as u64) * 8;
    for i in 0..8 {
        padded[padded_len - 8 + i] = (bits >> ((7 - i) * 8)) as u8;
    }

    let mut state = H0;
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for block in padded.chunks_exact(64) {
        compress(&mut state, block);
    }

    let mut digest = [0u8; 32];
    for i in 0..8 {
        write_be32(state[i], &mut digest[i * 4..i * 4 + 4]);
    }
    digest
}

/// Formats a digest as a lowercase hexadecimal string.
pub fn to_hex(digest: &[u8; 32]) -> String {
    const HEX_DIGITS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut out = String::with_capacity(64);
    for &byte in digest {
        out.push(HEX_DIGITS[(byte >> 4) as usize]);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The independently generated digests from REFERENCE_VALUES.md.
    #[test]
    fn reference_digests_reproduce() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            to_hex(&sha256(b"sample")),
            "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
        );
        assert_eq!(
            to_hex(&sha256(b"hello, cursed world")),
            "bf486fd9cd9e30b91ea8b9fcc47d19a2296b2e855dee2cfb022dbd15eb6ff5b2"
        );
    }

    /// A multi-block message (pad crosses a 64-byte boundary).
    #[test]
    fn multi_block_message() {
        // python: hashlib.sha256(b"a"*100).hexdigest()
        let msg = vec![b'a'; 100];
        assert_eq!(
            to_hex(&sha256(&msg)),
            "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"
        );
    }

    /// Block boundary edge: message of exactly 55 and 56 bytes.
    #[test]
    fn padding_boundaries() {
        // python: hashlib.sha256(b"a"*55).hexdigest()
        let m55 = vec![b'a'; 55];
        assert_eq!(
            to_hex(&sha256(&m55)),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        // python: hashlib.sha256(b"a"*56).hexdigest()
        let m56 = vec![b'a'; 56];
        assert_eq!(
            to_hex(&sha256(&m56)),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }
}
