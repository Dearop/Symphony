//! Generalized committed R1CS over ring vectors (Eq. 38).
//!
//! Batches d standard R1CS statements over Zq into one ring R1CS.
//!
//! A statement (x, w) is in the relation if:
//! - F^T = [X_in^T, W^T] ∈ Z^{d × n}
//! - (M_1 × F) ∘ (M_2 × F) = M_3 × F  (Hadamard/entry-wise)
//! - VfyOpen_{ℓ_h, B}(A, c, cf^{-1}(F)) = 1

use crate::params::D;
use crate::r1cs::R1CSMatrices;
use crate::ring::arith::centered_mod;
use crate::ring::RingElement;

/// Parameters for the generalized committed R1CS.
#[derive(Debug, Clone)]
pub struct GeneralizedR1CSParams {
    /// Number of public input ring elements.
    pub n_in: usize,
    /// Number of witness ring elements.
    pub n_w: usize,
    /// Block length for fine-grained norm checking.
    pub ell_h: usize,
    /// Per-block norm bound B.
    pub bound: u64,
    /// The R1CS matrices (over Zq, possibly Kronecker-expanded).
    pub matrices: R1CSMatrices,
}

impl GeneralizedR1CSParams {
    /// Total number of ring elements: n = n_in + n_w.
    pub fn n(&self) -> usize {
        self.n_in + self.n_w
    }
}

/// A generalized R1CS instance.
#[derive(Debug, Clone)]
pub struct GeneralizedR1CSInstance {
    /// Public input as ring elements.
    pub public_input: Vec<RingElement>,
    /// Ajtai commitment to the full witness.
    pub commitment: crate::commitment::Commitment,
}

/// A generalized R1CS witness.
#[derive(Debug, Clone)]
pub struct GeneralizedR1CSWitness {
    /// The witness matrix W ∈ Z^{d × n_w} stored as n_w ring elements.
    pub witness: Vec<RingElement>,
}

/// Check that a generalized R1CS instance-witness pair is satisfying.
///
/// Verifies: (M_1 × F) ∘ (M_2 × F) = M_3 × F for all d coefficient positions.
pub fn check_hadamard(
    params: &GeneralizedR1CSParams,
    public_input: &[RingElement],
    witness: &[RingElement],
    q: u64,
) -> bool {
    assert_eq!(public_input.len(), params.n_in);
    assert_eq!(witness.len(), params.n_w);

    let n = params.n();
    let m = params.matrices.num_constraints;

    // For each coefficient position j in 0..D, extract the j-th column
    // of F and check the R1CS relation
    for j in 0..D {
        // Build the full assignment z_j for coefficient position j
        let mut z_j = Vec::with_capacity(n);
        for x in public_input {
            z_j.push(x.coeffs[j]);
        }
        for w in witness {
            z_j.push(w.coeffs[j]);
        }

        let az = params.matrices.a.mul_vec_mod(&z_j, q);
        let bz = params.matrices.b.mul_vec_mod(&z_j, q);
        let cz = params.matrices.c.mul_vec_mod(&z_j, q);

        for i in 0..m {
            if centered_mod(az[i] as i128 * bz[i] as i128, q) != cz[i] {
                return false;
            }
        }
    }

    true
}
