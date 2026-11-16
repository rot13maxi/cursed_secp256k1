//! Jacobian projective point arithmetic on secp256k1.
//!
//! No-primitive-arithmetic justification: every VALUE (coordinates, curve
//! constants like 3 and 2 as `BigNum`s) comes from [`BigNum`] operators or
//! [`crate::field`] functions. Structural operations only: `usize` indices
//! into digit slices, `bool` control flow, option handling. Point at
//! infinity is represented by Z = 0; there is no primitive arithmetic
//! anywhere in the coordinate math.

use cursed_arithmetic::BigNum;

use crate::constants;
use crate::field::{fe_add, fe_inv, fe_mul, fe_sub};

/// A point in Jacobian coordinates: x = X/Z², y = Y/Z³. The point at
/// infinity is Z = 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JacobianPoint {
    /// The Jacobian X coordinate (x · Z²).
    pub x: BigNum,
    /// The Jacobian Y coordinate (y · Z³).
    pub y: BigNum,
    /// The Jacobian Z coordinate; zero means the point at infinity.
    pub z: BigNum,
}

impl JacobianPoint {
    /// The point at infinity (Z = 0).
    pub fn infinity() -> Self {
        JacobianPoint {
            x: BigNum::one(),
            y: BigNum::one(),
            z: BigNum::zero(),
        }
    }

    /// True when this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Constructs a point from affine coordinates (Z = 1).
    pub fn from_affine(x: BigNum, y: BigNum) -> Self {
        JacobianPoint {
            x,
            y,
            z: BigNum::one(),
        }
    }

    /// Converts to affine coordinates with a single field inversion.
    /// Returns `None` for the point at infinity.
    pub fn to_affine(&self) -> Option<(BigNum, BigNum)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = fe_inv(&self.z);
        let z_inv2 = fe_mul(&z_inv, &z_inv);
        let z_inv3 = fe_mul(&z_inv2, &z_inv);
        Some((fe_mul(&self.x, &z_inv2), fe_mul(&self.y, &z_inv3)))
    }

    /// Doubles the point. Uses the standard Jacobian doubling formulas with
    /// a = 0 (secp256k1 has no a coefficient):
    ///
    /// S = 4·X·Y², M = 3·X², X' = M² − 2·S, Y' = M·(S − X') − 8·Y⁴, Z' = 2·Y·Z.
    pub fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::infinity();
        }

        // y2 = Y^2, s = 4·X·y2, m = 3·X^2.
        let y2 = fe_mul(&self.y, &self.y);
        let s = fe_mul(&fe_mul(&self.x, &y2), &constants::four());
        let x2 = fe_mul(&self.x, &self.x);
        let m = fe_mul(&x2, &constants::three());

        // S = 4·X·Y², M = 3·X², X' = M² − 2·S, Y' = M·(S − X') − 8·Y⁴.
        let x_new = fe_sub(&fe_mul(&m, &m), &fe_add(&s, &s));
        let y4 = fe_mul(&y2, &y2);
        let y4x2 = fe_add(&y4, &y4); // 2·Y⁴
        let y4x4 = fe_add(&y4x2, &y4x2); // 4·Y⁴
        let y4x8 = fe_add(&y4x4, &y4x4); // 8·Y⁴
        let y_new = fe_sub(&fe_mul(&m, &fe_sub(&s, &x_new)), &y4x8);
        let z_new = fe_mul(&fe_add(&self.y, &self.y), &self.z);

        JacobianPoint {
            x: x_new,
            y: y_new,
            z: z_new,
        }
    }

    /// Adds two points in Jacobian coordinates (mixed additions allowed:
    /// either operand may have Z = 1, both handled generically).
    ///
    /// Standard formulas:
    /// U1 = X1·Z2², U2 = X2·Z1², S1 = Y1·Z2³, S2 = Y2·Z1³,
    /// H = U2 − U1, R = S2 − S1; if H = 0: R = 0 → double, R ≠ 0 → infinity.
    /// X3 = R² − H³ − 2·U1·H², Y3 = R·(U1·H² − X3) − S1·H³, Z3 = Z1·Z2·H.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return other.clone();
        }
        if other.is_infinity() {
            return self.clone();
        }

        let z1 = &self.z;
        let z2 = &other.z;
        let z1sq = fe_mul(z1, z1);
        let z2sq = fe_mul(z2, z2);
        let u1 = fe_mul(&self.x, &z2sq);
        let u2 = fe_mul(&other.x, &z1sq);
        let s1 = fe_mul(&self.y, &fe_mul(&z2sq, z2));
        let s2 = fe_mul(&other.y, &fe_mul(&z1sq, z1));

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            }
            return Self::infinity();
        }

        let h = fe_sub(&u2, &u1);
        let r = fe_sub(&s2, &s1);
        let h2 = fe_mul(&h, &h);
        let h3 = fe_mul(&h2, &h);
        let u1h2 = fe_mul(&u1, &h2);

        let x_new = fe_sub(&fe_sub(&fe_mul(&r, &r), &h3), &fe_add(&u1h2, &u1h2));
        let y_new = fe_sub(&fe_mul(&r, &fe_sub(&u1h2, &x_new)), &fe_mul(&s1, &h3));
        let z_new = fe_mul(&fe_mul(z1, z2), &h);

        JacobianPoint {
            x: x_new,
            y: y_new,
            z: z_new,
        }
    }
}

/// Multiplies the point `G` by the scalar `k`, walking the scalar's DECIMAL
/// digits MSB→LSB (Horner: Q ← 10·Q + G·d). The multiply-by-ten decomposes
/// into point operations as 10·Q = 2·(2·(2·Q) + Q): three doublings and one
/// addition of Q. Per digit: double, double, add(Q), double, then d adds of
/// G (d ≤ 9). Zero digits cost only the four point ops. All operations are
/// Jacobian; a single affine conversion happens in the caller via
/// `to_affine`.
pub fn scalar_mul(k: &BigNum, g: &JacobianPoint) -> JacobianPoint {
    let mut q = JacobianPoint::infinity();
    for digit in k.digits() {
        // Q = 10·Q = 2·(2·(2·Q) + Q): double, double, add the original Q,
        // double again.
        let q_orig = q.clone();
        q = q.double();
        q = q.double();
        q = q.add(&q_orig);
        q = q.double();
        // Q = Q + d·G.
        let d_value = u8::from(*digit);
        for _ in 0..d_value {
            q = q.add(g);
        }
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants;
    use std::str::FromStr;

    fn g_jacobian() -> JacobianPoint {
        let (gx, gy) = constants::generator();
        JacobianPoint::from_affine(gx, gy)
    }

    fn affine_str(p: &JacobianPoint) -> (String, String) {
        let (x, y) = p.to_affine().expect("not infinity");
        (x.to_string(), y.to_string())
    }

    /// k·G for k ∈ {1,2,3,5,7} from REFERENCE_VALUES.md.
    #[test]
    fn small_scalar_multiplications() {
        let g = g_jacobian();
        assert_eq!(
            affine_str(&scalar_mul(&BigNum::from(1u8), &g)).0,
            "55066263022277343669578718895168534326250603453777594175500187360389116729240"
        );
        assert_eq!(
            affine_str(&scalar_mul(&BigNum::from(2u8), &g)),
            (
                "89565891926547004231252920425935692360644145829622209833684329913297188986597"
                    .to_string(),
                "12158399299693830322967808612713398636155367887041628176798871954788371653930"
                    .to_string()
            )
        );
        assert_eq!(
            affine_str(&scalar_mul(&BigNum::from(3u8), &g)).0,
            "112711660439710606056748659173929673102114977341539408544630613555209775888121"
        );
        assert_eq!(
            affine_str(&scalar_mul(&BigNum::from(5u8), &g)).0,
            "21505829891763648114329055987619236494102133314575206970830385799158076338148"
        );
        assert_eq!(
            affine_str(&scalar_mul(&BigNum::from(7u8), &g)).0,
            "41948375291644419605210209193538855353224492619856392092318293986323063962044"
        );
    }

    /// n·G = infinity (the group order kills the generator).
    #[test]
    fn order_times_g_is_infinity() {
        let g = g_jacobian();
        let n = constants::order();
        assert!(scalar_mul(&n, &g).is_infinity());
    }

    /// Point addition consistency: 5G = 2G + 3G, compared in affine
    /// coordinates (Jacobian representations differ but denote the same
    /// point).
    #[test]
    fn add_matches_scalar_mul() {
        let g = g_jacobian();
        let g2 = scalar_mul(&BigNum::from(2u8), &g);
        let g3 = scalar_mul(&BigNum::from(3u8), &g);
        let g5 = scalar_mul(&BigNum::from(5u8), &g);
        assert_eq!(g2.add(&g3).to_affine(), g5.to_affine());
    }

    /// 12345·G from REFERENCE_VALUES.md.
    #[test]
    fn k12345() {
        let g = g_jacobian();
        let k = BigNum::from_str("12345").unwrap();
        assert_eq!(
            affine_str(&scalar_mul(&k, &g)),
            (
                "108607064596551879580190606910245687803607295064141551927605737287325610911759"
                    .to_string(),
                "6661302038839728943522144359728938428925407345457796456954441906546235843221"
                    .to_string()
            )
        );
    }
    /// 2^128·G from REFERENCE_VALUES.md (the slowest vector).
    #[test]
    fn pow128() {
        let g = g_jacobian();
        let k = BigNum::from_str("340282366920938463463374607431768211456").unwrap();
        assert_eq!(
            affine_str(&scalar_mul(&k, &g)),
            (
                "64865771952738249789114440545196421582918768733599534045195125031385885360346"
                    .to_string(),
                "46211216742671250426576585530459394900178019437443360579906162037052661563266"
                    .to_string()
            )
        );
    }
}
