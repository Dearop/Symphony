//! Extension field K = Fq^2 used for sumcheck operations.
//!
//! Elements of K are pairs (a0, a1) ∈ Fq^2 with multiplication defined
//! by an irreducible degree-2 polynomial over Fq.

use super::arith::{centered_mod, mod_pow};

/// An element of K = Fq^2 = Fq[Y] / <Y^2 - alpha> for a non-residue alpha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtFieldElement {
    /// Coefficients (c0 + c1 * Y) in centered representation.
    pub c0: i64,
    pub c1: i64,
}

/// Context for extension field arithmetic, parameterized by the modulus.
#[derive(Debug, Clone)]
pub struct ExtFieldContext {
    pub q: u64,
    /// The non-residue alpha such that Y^2 - alpha is irreducible over Fq.
    pub alpha: i64,
}

impl ExtFieldContext {
    /// Create a new extension field context.
    /// Finds a quadratic non-residue alpha mod q.
    pub fn new(q: u64) -> Self {
        let alpha = find_non_residue(q);
        Self { q, alpha }
    }

    pub fn zero(&self) -> ExtFieldElement {
        ExtFieldElement { c0: 0, c1: 0 }
    }

    pub fn one(&self) -> ExtFieldElement {
        ExtFieldElement { c0: 1, c1: 0 }
    }

    /// Addition in K.
    #[inline]
    pub fn add(&self, a: &ExtFieldElement, b: &ExtFieldElement) -> ExtFieldElement {
        ExtFieldElement {
            c0: self.reduce(a.c0 as i128 + b.c0 as i128),
            c1: self.reduce(a.c1 as i128 + b.c1 as i128),
        }
    }

    /// Subtraction in K.
    #[inline]
    pub fn sub(&self, a: &ExtFieldElement, b: &ExtFieldElement) -> ExtFieldElement {
        ExtFieldElement {
            c0: self.reduce(a.c0 as i128 - b.c0 as i128),
            c1: self.reduce(a.c1 as i128 - b.c1 as i128),
        }
    }

    /// Multiplication in K: (a0 + a1*Y)(b0 + b1*Y) = (a0*b0 + a1*b1*alpha) + (a0*b1 + a1*b0)*Y
    ///
    /// All intermediate products are reduced before summation to prevent
    /// i128 overflow when q is large (up to ~2^60).
    #[inline]
    pub fn mul(&self, a: &ExtFieldElement, b: &ExtFieldElement) -> ExtFieldElement {
        let a1b1_alpha = self.reduce(
            self.reduce(a.c1 as i128 * b.c1 as i128) as i128 * self.alpha as i128,
        );
        let a0b0 = self.reduce(a.c0 as i128 * b.c0 as i128);
        let c0 = a0b0 as i128 + a1b1_alpha as i128;
        let c1 = a.c0 as i128 * b.c1 as i128 + a.c1 as i128 * b.c0 as i128;
        ExtFieldElement {
            c0: self.reduce(c0),
            c1: self.reduce(c1),
        }
    }

    /// Scalar multiplication by an Fq element.
    #[inline]
    pub fn scalar_mul(&self, a: &ExtFieldElement, s: i64) -> ExtFieldElement {
        ExtFieldElement {
            c0: self.reduce(a.c0 as i128 * s as i128),
            c1: self.reduce(a.c1 as i128 * s as i128),
        }
    }

    /// Multiplicative inverse in K using the norm: a^{-1} = conj(a) / N(a).
    #[inline]
    pub fn inv(&self, a: &ExtFieldElement) -> Option<ExtFieldElement> {
        let norm = self
            .reduce(a.c0 as i128 * a.c0 as i128 - self.alpha as i128 * a.c1 as i128 * a.c1 as i128);
        if norm == 0 {
            return None;
        }
        let norm_inv = self.field_inv(norm)?;
        Some(ExtFieldElement {
            c0: self.reduce(a.c0 as i128 * norm_inv as i128),
            c1: self.reduce(-(a.c1 as i128) * norm_inv as i128),
        })
    }

    #[inline]
    fn reduce(&self, x: i128) -> i64 {
        centered_mod(x, self.q)
    }

    fn field_inv(&self, a: i64) -> Option<i64> {
        if a == 0 {
            return None;
        }
        let a_pos = if a < 0 { a + self.q as i64 } else { a } as u64;
        let inv = super::arith::mod_inv(a_pos, self.q);
        let q_half = self.q / 2;
        Some(if inv > q_half {
            inv as i64 - self.q as i64
        } else {
            inv as i64
        })
    }
}

/// Find a quadratic non-residue modulo q.
fn find_non_residue(q: u64) -> i64 {
    let exp = (q - 1) / 2;
    for a in 2..q {
        if mod_pow(a, exp, q) == q - 1 {
            return a as i64;
        }
    }
    panic!("no quadratic non-residue found mod {q}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ext_field_mul_inv() {
        let ctx = ExtFieldContext::new(257);
        let a = ExtFieldElement { c0: 3, c1: 5 };
        let a_inv = ctx.inv(&a).unwrap();
        let product = ctx.mul(&a, &a_inv);
        assert_eq!(product, ctx.one());
    }
}
