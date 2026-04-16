//! Module-Ajtai commitment scheme — the core replacement for Merkle trees.

pub mod opening;

use crate::params::D;
use crate::ring::ntt::NttContext;
use crate::ring::{RingElement, RingVector};

/// Ajtai commitment parameters: a random matrix A ∈ Rq^{κ × n}.
#[derive(Debug, Clone)]
pub struct AjtaiParams {
    /// The κ × n commitment matrix over Rq.
    pub a: Vec<Vec<RingElement>>,
    /// The commitment matrix pre-computed in NTT domain for O(d log d) multiplication.
    pub a_ntt: Vec<Vec<[u64; D]>>,
    /// Precomputed NTT context.
    pub ntt: NttContext,
    /// MSIS rank (number of rows).
    pub kappa: usize,
    /// Witness vector length (number of columns).
    pub n: usize,
    /// Prime modulus.
    pub q: u64,
}

/// A commitment value: κ ring elements.
#[derive(Debug, Clone)]
pub struct Commitment {
    pub value: RingVector,
}

/// An opening for a commitment (the witness vector itself).
#[derive(Debug, Clone)]
pub struct Opening {
    pub witness: RingVector,
}

impl AjtaiParams {
    /// Generate random commitment parameters with pre-computed NTT domain matrix.
    pub fn setup(kappa: usize, n: usize, q: u64, ntt: &NttContext) -> Self {
        use rand::RngExt;
        let mut rng = rand::rng();

        let a: Vec<Vec<RingElement>> = (0..kappa)
            .map(|_| {
                (0..n)
                    .map(|_| {
                        let mut coeffs = [0i64; D];
                        for c in coeffs.iter_mut() {
                            let v: u64 = rng.random_range(0..q);
                            *c = if v > q / 2 {
                                v as i64 - q as i64
                            } else {
                                v as i64
                            };
                        }
                        RingElement { coeffs }
                    })
                    .collect()
            })
            .collect();

        let a_ntt: Vec<Vec<[u64; D]>> = a
            .iter()
            .map(|row| row.iter().map(|elem| ntt.forward(elem)).collect())
            .collect();

        Self {
            a,
            a_ntt,
            ntt: ntt.clone(),
            kappa,
            n,
            q,
        }
    }

    /// NTT-accelerated matrix-vector product: A · v ∈ Rq^κ.
    ///
    /// Pre-transforms `v` into NTT domain once, then accumulates
    /// each row via pointwise multiply-and-add.
    pub fn mul_vec_ntt(&self, v: &RingVector) -> RingVector {
        assert_eq!(v.len(), self.n);
        let v_ntt: Vec<[u64; D]> = v.elements.iter().map(|e| self.ntt.forward(e)).collect();
        let mut result = RingVector::zero(self.kappa);
        for (i, out) in result.elements.iter_mut().enumerate() {
            let mut acc = [0u64; D];
            for (a_ij, v_j) in self.a_ntt[i].iter().zip(v_ntt.iter()) {
                let prod = self.ntt.pointwise_mul(a_ij, v_j);
                acc = self.ntt.pointwise_add(&acc, &prod);
            }
            *out = self.ntt.inverse(&acc);
        }
        result
    }

    /// Commit: c = A · m ∈ Rq^κ, using NTT-accelerated multiplication.
    pub fn commit(&self, witness: &RingVector) -> (Commitment, Opening) {
        let value = self.mul_vec_ntt(witness);
        (
            Commitment { value },
            Opening {
                witness: witness.clone(),
            },
        )
    }

    /// Verify: check A·f = c and ‖f‖_2 < bound.
    #[must_use]
    pub fn verify_open(&self, c: &Commitment, f: &RingVector, bound_sq: u128) -> bool {
        if f.len() != self.n {
            return false;
        }
        if f.norm_sq() >= bound_sq {
            return false;
        }
        self.mul_vec_ntt(f).elements == c.value.elements
    }
}
