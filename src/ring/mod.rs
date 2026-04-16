//! Cyclotomic ring Rq = Zq[X] / <X^d + 1> arithmetic with NTT acceleration.

pub mod arith;
pub mod extension;
pub mod ntt;
pub mod tensor;

use crate::params::D;
use arith::centered_mod;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A polynomial in Rq, stored as d coefficients in centered representation [−q/2, q/2).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RingElement {
    pub coeffs: [i64; D],
}

impl RingElement {
    /// The zero element.
    pub fn zero() -> Self {
        Self { coeffs: [0; D] }
    }

    /// Constant element (scalar in the ring).
    pub fn from_constant(c: i64) -> Self {
        let mut coeffs = [0i64; D];
        coeffs[0] = c;
        Self { coeffs }
    }

    /// Monomial X^k for 0 <= k < d.
    pub fn monomial(k: usize) -> Self {
        assert!(k < D);
        let mut coeffs = [0i64; D];
        coeffs[k] = 1;
        Self { coeffs }
    }

    /// Extract constant term ct(f) = f[0].
    pub fn ct(&self) -> i64 {
        self.coeffs[0]
    }

    /// Extract coefficient vector cf(f) (identity for this representation).
    pub fn cf(&self) -> &[i64; D] {
        &self.coeffs
    }

    /// Interpret an integer vector as a ring element cf^{-1}(v).
    pub fn cf_inv(v: [i64; D]) -> Self {
        Self { coeffs: v }
    }

    /// Coefficient-wise addition mod q.
    pub fn add(&self, other: &Self, q: u64) -> Self {
        let mut coeffs = [0i64; D];
        for (out, (&a, &b)) in coeffs
            .iter_mut()
            .zip(self.coeffs.iter().zip(other.coeffs.iter()))
        {
            *out = centered_mod(a as i128 + b as i128, q);
        }
        Self { coeffs }
    }

    /// Coefficient-wise subtraction mod q.
    pub fn sub(&self, other: &Self, q: u64) -> Self {
        let mut coeffs = [0i64; D];
        for (out, (&a, &b)) in coeffs
            .iter_mut()
            .zip(self.coeffs.iter().zip(other.coeffs.iter()))
        {
            *out = centered_mod(a as i128 - b as i128, q);
        }
        Self { coeffs }
    }

    /// Polynomial multiplication mod (X^d + 1, q).
    /// Uses schoolbook; NTT-accelerated version in `ntt` module.
    pub fn mul(&self, other: &Self, q: u64) -> Self {
        let mut acc = [0i128; D];
        for i in 0..D {
            for j in 0..D {
                let prod = self.coeffs[i] as i128 * other.coeffs[j] as i128;
                let idx = i + j;
                if idx < D {
                    acc[idx] += prod;
                } else {
                    acc[idx - D] -= prod;
                }
            }
        }
        let mut coeffs = [0i64; D];
        for (out, &a) in coeffs.iter_mut().zip(acc.iter()) {
            *out = centered_mod(a, q);
        }
        Self { coeffs }
    }

    /// Scalar multiplication by a constant.
    pub fn scalar_mul(&self, scalar: i64, q: u64) -> Self {
        let mut coeffs = [0i64; D];
        for (out, &c) in coeffs.iter_mut().zip(self.coeffs.iter()) {
            *out = centered_mod(c as i128 * scalar as i128, q);
        }
        Self { coeffs }
    }

    /// NTT-accelerated polynomial multiplication mod (X^d + 1, q).
    pub fn mul_ntt(&self, other: &Self, ntt: &ntt::NttContext) -> Self {
        ntt.ring_mul(self, other)
    }

    /// Infinity norm: max |coefficient|.
    pub fn norm_inf(&self) -> u64 {
        self.coeffs
            .iter()
            .map(|c| c.unsigned_abs())
            .max()
            .unwrap_or(0)
    }

    /// Squared Euclidean norm: sum of squares of coefficients.
    pub fn norm_sq(&self) -> u128 {
        self.coeffs
            .iter()
            .map(|c| (*c as i128 * *c as i128) as u128)
            .sum()
    }
}

/// A vector of ring elements (e.g., commitment output, witness vector).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RingVector {
    pub elements: Vec<RingElement>,
}

impl From<Vec<RingElement>> for RingVector {
    fn from(elements: Vec<RingElement>) -> Self {
        Self { elements }
    }
}

impl RingVector {
    pub fn zero(len: usize) -> Self {
        Self {
            elements: vec![RingElement::zero(); len],
        }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Squared Euclidean norm of the entire vector (sum over all coefficients).
    pub fn norm_sq(&self) -> u128 {
        self.elements.iter().map(|e| e.norm_sq()).sum()
    }

    /// Inner product: sum_i a[i] * b[i] over Rq.
    pub fn inner_product(&self, other: &Self, q: u64) -> RingElement {
        assert_eq!(self.len(), other.len());
        let mut acc = RingElement::zero();
        for (a, b) in self.elements.iter().zip(other.elements.iter()) {
            let prod = a.mul(b, q);
            acc = acc.add(&prod, q);
        }
        acc
    }

    /// Scalar multiplication by a ring element.
    pub fn ring_scalar_mul(&self, scalar: &RingElement, q: u64) -> Self {
        Self {
            elements: self.elements.iter().map(|e| e.mul(scalar, q)).collect(),
        }
    }

    /// NTT-accelerated inner product: sum_i a[i] * b[i] over Rq.
    /// Accumulates in NTT domain (n forward + n pointwise + 1 inverse).
    pub fn inner_product_ntt(&self, other: &Self, ntt: &ntt::NttContext) -> RingElement {
        assert_eq!(self.len(), other.len());
        let mut acc = [0u64; D];
        for (a, b) in self.elements.iter().zip(other.elements.iter()) {
            let a_ntt = ntt.forward(a);
            let b_ntt = ntt.forward(b);
            let prod = ntt.pointwise_mul(&a_ntt, &b_ntt);
            acc = ntt.pointwise_add(&acc, &prod);
        }
        ntt.inverse(&acc)
    }

    /// NTT-accelerated scalar multiplication by a ring element.
    /// Converts scalar to NTT domain once, then pointwise for each element.
    pub fn ring_scalar_mul_ntt(&self, scalar: &RingElement, ntt: &ntt::NttContext) -> Self {
        let scalar_ntt = ntt.forward(scalar);
        Self {
            elements: self
                .elements
                .iter()
                .map(|e| {
                    let e_ntt = ntt.forward(e);
                    let prod_ntt = ntt.pointwise_mul(&e_ntt, &scalar_ntt);
                    ntt.inverse(&prod_ntt)
                })
                .collect(),
        }
    }

    /// Element-wise addition.
    pub fn add(&self, other: &Self, q: u64) -> Self {
        assert_eq!(self.len(), other.len());
        Self {
            elements: self
                .elements
                .iter()
                .zip(other.elements.iter())
                .map(|(a, b)| a.add(b, q))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_Q: u64 = 257; // small prime for testing

    #[test]
    fn test_ring_add_sub() {
        let a = RingElement::from_constant(10);
        let b = RingElement::from_constant(20);
        let sum = a.add(&b, TEST_Q);
        assert_eq!(sum.ct(), 30);
        let diff = sum.sub(&b, TEST_Q);
        assert_eq!(diff.ct(), 10);
    }

    #[test]
    fn test_ring_mul_constant() {
        let a = RingElement::from_constant(3);
        let b = RingElement::from_constant(7);
        let prod = a.mul(&b, TEST_Q);
        assert_eq!(prod.ct(), 21);
    }

    #[test]
    fn test_monomial_mul() {
        // X * X = X^2
        let x = RingElement::monomial(1);
        let x2 = x.mul(&x, TEST_Q);
        assert_eq!(x2.coeffs[2], 1);
        assert_eq!(x2.ct(), 0);
    }

    #[test]
    fn test_cyclotomic_reduction() {
        // X^{d-1} * X = X^d = -1
        let x_dm1 = RingElement::monomial(D - 1);
        let x = RingElement::monomial(1);
        let result = x_dm1.mul(&x, TEST_Q);
        assert_eq!(result.ct(), -1);
    }
}
