//! Πrg: Approximate range proof (Figure 2).
//!
//! Reduces norm-checking of a ring vector to linear relations
//! via random projection + monomial embedding.
//!
//! Protocol:
//! 1. Compute projected matrix H := (I_{n/ℓ_h} ⊗ J) × cf(f)
//! 2. Decompose H into k_g layers with ‖H^(i)‖_∞ ≤ d'/2
//! 3. Commit to monomial vectors g^(i) := Exp(flatten(H^(i)))
//! 4. Run Πmon on the monomial commitments
//! 5. Verifier checks consistency via the table polynomial

use crate::commitment::{AjtaiParams, Commitment};
use crate::decomposition::monomial::exp_map;
use crate::params::D;
use crate::ring::extension::ExtFieldContext;
use crate::ring::ntt::NttContext;
use crate::ring::{RingElement, RingVector};
use crate::rok::monomial::{MonomialChallenges, MonomialProof};
use crate::rok::BatchedLinearRelation;

/// Parameters for the range proof.
#[derive(Debug, Clone)]
pub struct RangeProofParams {
    /// Projection output length λ_pj = 256.
    pub lambda_pj: usize,
    /// Projection input block length ℓ_h.
    pub ell_h: usize,
    /// Decomposition range d' = d − 2 = 62.
    pub d_prime: i64,
    /// Number of monomial decomposition layers k_g.
    pub k_g: usize,
    /// Input norm bound B.
    pub input_bound: u64,
}

/// Random projection matrix J ∈ {0, ±1}^{λ_pj × ℓ_h}.
/// Distribution χ: Pr[0] = 1/2, Pr[±1] = 1/4.
#[derive(Debug, Clone)]
pub struct ProjectionMatrix {
    /// Sparse representation: for each row, list of (column, sign) pairs.
    pub entries: Vec<Vec<(usize, i8)>>,
    pub rows: usize,
    pub cols: usize,
}

impl ProjectionMatrix {
    /// Sample a random projection matrix from a seed.
    pub fn sample(lambda_pj: usize, ell_h: usize, seed: &[u8]) -> Self {
        use rand::rngs::StdRng;
        use rand::{RngExt, SeedableRng};

        let mut rng_seed = [0u8; 32];
        for (i, &b) in seed.iter().enumerate().take(32) {
            rng_seed[i] = b;
        }
        let mut rng = StdRng::from_seed(rng_seed);

        let entries = (0..lambda_pj)
            .map(|_| {
                (0..ell_h)
                    .filter_map(|j| {
                        let r: u8 = rng.random_range(0..4);
                        match r {
                            0 => Some((j, 1i8)),
                            1 => Some((j, -1i8)),
                            _ => None,
                        }
                    })
                    .collect()
            })
            .collect();

        Self {
            entries,
            rows: lambda_pj,
            cols: ell_h,
        }
    }

    /// Apply the structured projection (I_{n/ℓ_h} ⊗ J) to a coefficient vector.
    /// Input: flattened coefficient matrix of the witness (n*D values).
    /// Output: projected values.
    pub fn apply_structured(&self, coeffs: &[i64], n_over_ell_h: usize) -> Vec<i64> {
        let mut result = Vec::with_capacity(n_over_ell_h * self.rows);
        for block in 0..n_over_ell_h {
            let offset = block * self.cols;
            for row in &self.entries {
                let mut val = 0i64;
                for &(col, sign) in row {
                    if offset + col < coeffs.len() {
                        val += sign as i64 * coeffs[offset + col];
                    }
                }
                result.push(val);
            }
        }
        result
    }
}

/// Proof for the approximate range proof.
///
/// # Zero-knowledge note
///
/// In a production deployment, `monomial_vectors` and `projected_values`
/// would NOT be included in the proof sent to the verifier. They are
/// included here so the verifier can perform the consistency check
/// directly. A full ZK implementation would instead rely on the Πmon
/// evaluation claims and the table polynomial to verify consistency
/// without seeing the raw vectors.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// Monomial commitments for decomposition layers.
    pub monomial_commitments: Vec<Commitment>,
    /// The monomial vectors g^(i) = Exp(flatten(H^(i))).
    pub monomial_vectors: Vec<Vec<RingElement>>,
    /// The monomial check proof.
    pub monomial_proof: MonomialProof,
    /// Projected and decomposed values (for verifier consistency check).
    pub projected_values: Vec<i64>,
}

/// Challenges for Πrg.
pub struct RangeProofChallenges {
    /// Random projection matrix J.
    pub projection: ProjectionMatrix,
    /// Challenges for the inner Πmon.
    pub monomial_challenges: MonomialChallenges,
}

/// Run the Πrg prover.
///
/// Input: commitment c, witness f with VfyOpen_{ℓ_h, B}(A, c, f) = 1.
/// Output: range proof containing monomial commitments and Πmon proof.
pub fn prove(
    _commitment: &Commitment,
    witness: &RingVector,
    ajtai: &AjtaiParams,
    params: &RangeProofParams,
    challenges: &RangeProofChallenges,
    ctx: &ExtFieldContext,
) -> RangeProof {
    let n = witness.len();

    // Step 1: Flatten the witness coefficient matrix cf(f) ∈ Z^{n·D}
    let mut flat_coeffs = Vec::with_capacity(n * D);
    for elem in &witness.elements {
        flat_coeffs.extend_from_slice(&elem.coeffs);
    }

    // Step 2: Apply structured projection H := (I_{⌈n·D/ℓ_h⌉} ⊗ J) × cf(f)
    // The identity dimension is the number of ℓ_h-sized blocks in the flattened vector.
    let total_coeffs = n * D;
    let n_blocks = if total_coeffs == 0 {
        1
    } else {
        total_coeffs.div_ceil(params.ell_h)
    };
    let projected = challenges
        .projection
        .apply_structured(&flat_coeffs, n_blocks);

    // Step 3: Decompose H into k_g layers: H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g)
    let d_prime = params.d_prime;
    let k_g = params.k_g;
    let mut layers: Vec<Vec<i64>> = vec![Vec::new(); k_g];
    for &h_val in &projected {
        let digits = crate::decomposition::decompose(h_val, d_prime, k_g);
        for (layer, &digit) in layers.iter_mut().zip(digits.iter()) {
            layer.push(digit);
        }
    }

    // Step 4: Commit to monomial vectors g^(i) := Exp(flatten(H^(i)))
    let half_d = (D as i64) / 2;
    let mut monomial_vectors = Vec::with_capacity(k_g);
    let mut monomial_commitments = Vec::with_capacity(k_g);

    for layer in &layers {
        let monomial_vec: Vec<RingElement> = layer
            .iter()
            .map(|&val| {
                assert!(
                    val > -(half_d) && val < half_d,
                    "decomposition digit {val} out of monomial range (−{half_d}, {half_d}); \
                 check that d_prime ({d_prime}) and k_g ({k_g}) are sufficient for the input norm"
                );
                exp_map(val)
            })
            .collect();

        // Pad to power of 2 for sumcheck
        let target_len = monomial_vec.len().next_power_of_two();
        let mut padded = monomial_vec;
        padded.resize(target_len, RingElement::zero());

        let mon_len = padded.len();
        let ring_vec = RingVector {
            elements: padded.clone(),
        };
        // Create a deterministic verifier-reconstructable commitment matrix
        // for monomial vectors. Typed CP uses the same derivation to enforce
        // opening validity in-circuit.
        let mon_ajtai = AjtaiParams::setup_deterministic(
            ajtai.kappa,
            mon_len,
            ajtai.q,
            &ajtai.ntt,
            b"range-proof-monomial",
        );
        let (c, _) = mon_ajtai.commit(&ring_vec);
        monomial_commitments.push(c);
        monomial_vectors.push(padded);
    }

    // Step 5: Run Πmon on the monomial commitments
    let monomial_proof = super::monomial::prove(
        &monomial_commitments,
        &monomial_vectors,
        &challenges.monomial_challenges,
        ctx,
    );

    RangeProof {
        monomial_commitments,
        monomial_vectors,
        monomial_proof,
        projected_values: projected,
    }
}

/// Run the Πrg verifier.
pub fn verify(
    _commitment: &Commitment,
    proof: &RangeProof,
    params: &RangeProofParams,
    challenges: &RangeProofChallenges,
    ctx: &ExtFieldContext,
) -> Result<BatchedLinearRelation, RangeProofError> {
    // Step 1: Verify the Πmon proof
    let batched = super::monomial::verify(
        &proof.monomial_commitments,
        &proof.monomial_proof,
        &challenges.monomial_challenges,
        ctx,
    )
    .map_err(|_| RangeProofError::MonomialCheckFailed)?;

    // Step 2: Verify consistency via the table polynomial.
    // For each monomial g^(i)[b], check that ct(g^(i)[b] · t(X)) gives
    // the decomposition digit, and that the digits reconstruct the projected values.
    let table_poly = crate::decomposition::monomial::table_polynomial();
    let ntt = NttContext::new(ctx.q);
    let d_prime = params.d_prime;

    for (b, &proj_val) in proof.projected_values.iter().enumerate() {
        let mut reconstructed = 0i128;
        let mut d_power = 1i128;
        for mvec in proof.monomial_vectors.iter() {
            if b < mvec.len() {
                let g = &mvec[b];
                let product = g.mul_ntt(&table_poly, &ntt);
                let digit = product.ct() as i128;
                reconstructed += digit * d_power;
            }
            d_power = d_power.checked_mul(d_prime as i128).unwrap_or_else(|| {
                panic!("range proof verifier: d_prime^k_g overflow in reconstruction")
            });
        }
        if reconstructed != proj_val as i128 {
            return Err(RangeProofError::ProjectionFailed);
        }
    }

    Ok(batched)
}

#[derive(Debug)]
pub enum RangeProofError {
    ProjectionFailed,
    MonomialCheckFailed,
    NormBoundExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::extension::ExtFieldElement;

    #[test]
    fn test_projection_matrix() {
        let proj = ProjectionMatrix::sample(4, 8, b"test-seed-1234567890123456");
        assert_eq!(proj.rows, 4);
        assert_eq!(proj.cols, 8);

        let coeffs = vec![1i64; 16];
        let result = proj.apply_structured(&coeffs, 2);
        assert_eq!(result.len(), 2 * 4);
    }

    #[test]
    fn test_range_proof_small() {
        let q = 257u64;
        let ctx = ExtFieldContext::new(q);

        let n = 2;
        let kappa = 2;
        let ntt = crate::ring::ntt::NttContext::new(q);
        let ajtai = AjtaiParams::setup(kappa, n, q, &ntt);

        let witness = RingVector {
            elements: vec![
                RingElement::from_constant(3),
                RingElement::from_constant(-2),
            ],
        };
        let (commitment, _) = ajtai.commit(&witness);

        let params = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };

        let proj = ProjectionMatrix::sample(4, D, b"test-seed-1234567890123456");
        // Monomial vector length = (n*D/ell_h) * lambda_pj = 2*64/64 * 4 = 8
        // num_vars = log2(8) = 3
        let num_vars = 3;
        let mon_challenges = MonomialChallenges {
            s: (0..num_vars)
                .map(|i| ExtFieldElement {
                    c0: 5 + i as i64,
                    c1: 1,
                })
                .collect(),
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: (0..num_vars)
                .map(|i| ExtFieldElement {
                    c0: 7 + i as i64,
                    c1: 3,
                })
                .collect(),
        };
        let challenges = RangeProofChallenges {
            projection: proj,
            monomial_challenges: mon_challenges,
        };

        let proof = prove(&commitment, &witness, &ajtai, &params, &challenges, &ctx);
        let result = verify(&commitment, &proof, &params, &challenges, &ctx);
        assert!(result.is_ok(), "Πrg verify failed: {:?}", result.err());
    }
}
