//! Extension field K = Fq^2 used for sumcheck operations.
//!
//! Elements of K are pairs (a0, a1) ∈ Fq^2 with multiplication defined
//! by an irreducible degree-2 polynomial over Fq.

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
    pub fn add(&self, a: &ExtFieldElement, b: &ExtFieldElement) -> ExtFieldElement {
        ExtFieldElement {
            c0: self.reduce(a.c0 as i128 + b.c0 as i128),
            c1: self.reduce(a.c1 as i128 + b.c1 as i128),
        }
    }

    /// Subtraction in K.
    pub fn sub(&self, a: &ExtFieldElement, b: &ExtFieldElement) -> ExtFieldElement {
        ExtFieldElement {
            c0: self.reduce(a.c0 as i128 - b.c0 as i128),
            c1: self.reduce(a.c1 as i128 - b.c1 as i128),
        }
    }

    /// Multiplication in K: (a0 + a1*Y)(b0 + b1*Y) = (a0*b0 + a1*b1*alpha) + (a0*b1 + a1*b0)*Y
    pub fn mul(&self, a: &ExtFieldElement, b: &ExtFieldElement) -> ExtFieldElement {
        let c0 = a.c0 as i128 * b.c0 as i128 + a.c1 as i128 * b.c1 as i128 * self.alpha as i128;
        let c1 = a.c0 as i128 * b.c1 as i128 + a.c1 as i128 * b.c0 as i128;
        ExtFieldElement {
            c0: self.reduce(c0),
            c1: self.reduce(c1),
        }
    }

    /// Scalar multiplication by an Fq element.
    pub fn scalar_mul(&self, a: &ExtFieldElement, s: i64) -> ExtFieldElement {
        ExtFieldElement {
            c0: self.reduce(a.c0 as i128 * s as i128),
            c1: self.reduce(a.c1 as i128 * s as i128),
        }
    }

    /// Multiplicative inverse in K using the norm: a^{-1} = conj(a) / N(a).
    pub fn inv(&self, a: &ExtFieldElement) -> Option<ExtFieldElement> {
        let norm = self.reduce(
            a.c0 as i128 * a.c0 as i128 - self.alpha as i128 * a.c1 as i128 * a.c1 as i128,
        );
        if norm == 0 {
            return None;
        }
        let norm_inv = self.field_inv(norm)?;
        Some(ExtFieldElement {
            c0: self.reduce(a.c0 as i128 * norm_inv as i128),
            c1: self.reduce(-(a.c1 as i128) * norm_inv as i128),
        })
    }

    fn reduce(&self, x: i128) -> i64 {
        let q = self.q as i128;
        let q_half = (self.q / 2) as i64;
        let mut r = (x % q) as i64;
        if r > q_half {
            r -= self.q as i64;
        } else if r < -q_half {
            r += self.q as i64;
        }
        r
    }

    fn field_inv(&self, a: i64) -> Option<i64> {
        if a == 0 {
            return None;
        }
        let a_pos = if a < 0 { a + self.q as i64 } else { a } as u64;
        let (mut old_r, mut r) = (a_pos as i128, self.q as i128);
        let (mut old_s, mut s) = (1i128, 0i128);
        while r != 0 {
            let quotient = old_r / r;
            (old_r, r) = (r, old_r - quotient * r);
            (old_s, s) = (s, old_s - quotient * s);
        }
        Some(self.reduce(old_s))
    }
}

/// Find a quadratic non-residue modulo q.
fn find_non_residue(q: u64) -> i64 {
    let exp = (q - 1) / 2;
    for a in 2..q {
        let r = mod_pow(a, exp, q);
        if r == q - 1 {
            // a is a QNR
            return a as i64;
        }
    }
    panic!("no quadratic non-residue found mod {q}");
}

fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let m = modulus as u128;
    base %= modulus;
    let mut b = base as u128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % m;
        }
        exp >>= 1;
        b = (b * b) % m;
    }
    result as u64
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
