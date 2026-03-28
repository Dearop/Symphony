//! Module-Ajtai commitment scheme — the core replacement for Merkle trees.

pub mod opening;
pub mod params;

use crate::ring::{RingElement, RingVector};

/// Ajtai commitment parameters: a random matrix A ∈ Rq^{κ × n}.
#[derive(Debug, Clone)]
pub struct AjtaiParams {
    /// The κ × n commitment matrix over Rq.
    pub a: Vec<Vec<RingElement>>,
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
    /// Generate random commitment parameters.
    pub fn setup(kappa: usize, n: usize, q: u64) -> Self {
        use rand::RngExt;
        let mut rng = rand::rng();

        let a = (0..kappa)
            .map(|_| {
                (0..n)
                    .map(|_| {
                        let mut coeffs = [0i64; crate::params::D];
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

        Self { a, kappa, n, q }
    }

    /// Commit: c = A · m ∈ Rq^κ.
    pub fn commit(&self, witness: &RingVector) -> (Commitment, Opening) {
        assert_eq!(witness.len(), self.n);

        let mut value = RingVector::zero(self.kappa);
        for i in 0..self.kappa {
            for j in 0..self.n {
                let prod = self.a[i][j].mul(&witness.elements[j], self.q);
                value.elements[i] = value.elements[i].add(&prod, self.q);
            }
        }

        (
            Commitment { value },
            Opening {
                witness: witness.clone(),
            },
        )
    }

    /// Verify: check A·f = c and ‖f‖_2 < bound.
    pub fn verify_open(&self, c: &Commitment, f: &RingVector, bound_sq: u128) -> bool {
        if f.len() != self.n {
            return false;
        }

        // Check norm bound
        if f.norm_sq() >= bound_sq {
            return false;
        }

        // Recompute A·f and compare
        let mut recomputed = RingVector::zero(self.kappa);
        for i in 0..self.kappa {
            for j in 0..self.n {
                let prod = self.a[i][j].mul(&f.elements[j], self.q);
                recomputed.elements[i] = recomputed.elements[i].add(&prod, self.q);
            }
        }

        recomputed.elements == c.value.elements
    }
}
