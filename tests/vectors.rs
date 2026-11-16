//! Integration tests: every vector in REFERENCE_VALUES.md, digit for digit.
//!
//! Tests MAY use primitive arithmetic freely as an independent oracle; the
//! library under test may not.

use cursed_arithmetic::BigNum;
use cursed_secp256k1::ecdsa::{self, KeyError, sign, verify};
use cursed_secp256k1::field::{fe_add, fe_inv, fe_mul, fe_sub};
use cursed_secp256k1::jacobian::{JacobianPoint, scalar_mul};
use cursed_secp256k1::sha256::{sha256, to_hex};
use num_bigint::BigUint;
use std::str::FromStr;

fn big(s: &str) -> BigNum {
    BigNum::from_str(s).unwrap()
}

/// Field vectors from REFERENCE_VALUES.md.
#[test]
fn field_vectors() {
    let a = big("12287070679110784391061470500868383394860565932337482615261664884614796671153");
    let b = big("6295027170268925931475644123820777400648689434085647838277327685570480460850");

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
}

/// Cross-check: fe_mul(a, b) mod p equals num-bigint's (a*b) % p.
#[test]
fn field_mul_cross_check_with_num_bigint() {
    let a_str = "12287070679110784391061470500868383394860565932337482615261664884614796671153";
    let b_str = "6295027170268925931475644123820777400648689434085647838277327685570480460850";
    let p_str = "115792089237316195423570985008687907853269984665640564039457584007908834671663";

    let a = BigUint::parse_bytes(a_str.as_bytes(), 10).unwrap();
    let b = BigUint::parse_bytes(b_str.as_bytes(), 10).unwrap();
    let p = BigUint::parse_bytes(p_str.as_bytes(), 10).unwrap();
    let expected = (a * b) % p;

    let cursed_result = fe_mul(&big(a_str), &big(b_str));
    assert_eq!(cursed_result.to_string(), expected.to_string());
}

/// Scalar multiplication vectors from REFERENCE_VALUES.md.
#[test]
fn scalar_multiplication_vectors() {
    let (gx, gy) = cursed_secp256k1::constants::generator();
    let g = JacobianPoint::from_affine(gx, gy);

    let cases: &[(&str, &str, &str)] = &[
        (
            "1",
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        ),
        (
            "2",
            "89565891926547004231252920425935692360644145829622209833684329913297188986597",
            "12158399299693830322967808612713398636155367887041628176798871954788371653930",
        ),
        (
            "3",
            "112711660439710606056748659173929673102114977341539408544630613555209775888121",
            "25583027980570883691656905877401976406448868254816295069919888960541586679410",
        ),
        (
            "5",
            "21505829891763648114329055987619236494102133314575206970830385799158076338148",
            "98003708678762621233683240503080860129026887322874138805529884920309963580118",
        ),
        (
            "7",
            "41948375291644419605210209193538855353224492619856392092318293986323063962044",
            "48361766907851246668144012348516735800090617714386977531302791340517493990618",
        ),
        (
            "12345",
            "108607064596551879580190606910245687803607295064141551927605737287325610911759",
            "6661302038839728943522144359728938428925407345457796456954441906546235843221",
        ),
    ];

    for (k_str, x_str, y_str) in cases {
        let k = big(k_str);
        let (x, y) = scalar_mul(&k, &g).to_affine().unwrap();
        assert_eq!(x.to_string(), *x_str, "k = {}", k_str);
        assert_eq!(y.to_string(), *y_str, "k = {}", k_str);
    }
}

/// The slowest scalar vector: 2^128·G.
#[test]
fn scalar_multiplication_pow128() {
    let (gx, gy) = cursed_secp256k1::constants::generator();
    let g = JacobianPoint::from_affine(gx, gy);
    let k = big("340282366920938463463374607431768211456");
    let (x, y) = scalar_mul(&k, &g).to_affine().unwrap();
    assert_eq!(
        x.to_string(),
        "64865771952738249789114440545196421582918768733599534045195125031385885360346"
    );
    assert_eq!(
        y.to_string(),
        "46211216742671250426576585530459394900178019437443360579906162037052661563266"
    );
}

/// SHA-256 digests from REFERENCE_VALUES.md.
#[test]
fn sha256_vectors() {
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

/// RFC 6979 nonces for the reference key X, both messages.
#[test]
fn rfc6979_nonces() {
    let x = big("91225253027397101270059260515990221874496108017261222445699397644687913215777");
    assert_eq!(
        ecdsa::rfc6979_nonce(&x, b"sample").to_string(),
        "75486370184466523516702714224272210659255809472406410223340475427961162083680"
    );
    assert_eq!(
        ecdsa::rfc6979_nonce(&x, b"hello, cursed world").to_string(),
        "104335252967661179469373465021259381250378787287844156905605922008810477963755"
    );
}

/// Both reference signatures reproduce exactly.
#[test]
fn signature_vectors() {
    let x = big("91225253027397101270059260515990221874496108017261222445699397644687913215777");
    let sig1 = sign(b"sample", &x).unwrap();
    assert_eq!(
        sig1.r.to_string(),
        "30366917054904991249349557757615711045386803376476662406910637249813244520136"
    );
    assert_eq!(
        sig1.s.to_string(),
        "37544014275429169701540982636181096397351935915263210499287933874359616121705"
    );
    let sig2 = sign(b"hello, cursed world", &x).unwrap();
    assert_eq!(
        sig2.r.to_string(),
        "18030224896525320799036118072171528267147146173991077105841842529739242853473"
    );
    assert_eq!(
        sig2.s.to_string(),
        "741502502450378336590361310818315351196678597832515874229716583342894643061"
    );
}

/// The public key for X reproduces.
#[test]
fn public_key_vector() {
    let x = big("91225253027397101270059260515990221874496108017261222445699397644687913215777");
    let (qx, qy) = ecdsa::public_key(&x).unwrap();
    assert_eq!(
        qx.to_string(),
        "20149468923017862635785269351026469201343513335253737999994330121872194856517"
    );
    assert_eq!(
        qy.to_string(),
        "45558802482409728232371975206855032011893935284936184167394243449917294149765"
    );
}

/// Verify accepts both signatures and rejects tampering.
#[test]
fn verify_accepts_and_rejects() {
    let x = big("91225253027397101270059260515990221874496108017261222445699397644687913215777");
    let (qx, qy) = ecdsa::public_key(&x).unwrap();

    let sig1 = sign(b"sample", &x).unwrap();
    let sig2 = sign(b"hello, cursed world", &x).unwrap();
    assert!(verify(b"sample", &sig1.r, &sig1.s, &qx, &qy));
    assert!(verify(b"hello, cursed world", &sig2.r, &sig2.s, &qx, &qy));

    // Tampered r.
    let bad_r = &sig1.r + BigNum::from(1u8);
    assert!(!verify(b"sample", &bad_r, &sig1.s, &qx, &qy));
    // Tampered s.
    let bad_s = &sig1.s + BigNum::from(1u8);
    assert!(!verify(b"sample", &sig1.r, &bad_s, &qx, &qy));
    // Tampered message.
    assert!(!verify(b"sample!", &sig1.r, &sig1.s, &qx, &qy));
    // Wrong key.
    let (ox, oy) = ecdsa::public_key(&big("1")).unwrap();
    assert!(!verify(b"sample", &sig1.r, &sig1.s, &ox, &oy));
    // Out-of-range signature components.
    let n = cursed_secp256k1::constants::order();
    assert!(!verify(b"sample", &n, &sig1.s, &qx, &qy));
    assert!(!verify(b"sample", &BigNum::zero(), &sig1.s, &qx, &qy));
}

/// Invalid keys are rejected.
#[test]
fn invalid_keys_rejected() {
    assert_eq!(ecdsa::public_key(&BigNum::zero()), Err(KeyError::ZeroKey));
    let n = cursed_secp256k1::constants::order();
    assert_eq!(ecdsa::public_key(&n), Err(KeyError::KeyTooLarge));
}
