//! Πgr1cs: Single-instance reduction (Figure 3).
//!
//! Interleaves Πrg (range proof) with Πhad (Hadamard check),
//! sharing sumcheck challenges.
//!
//! Input: (c, X_in) and witness W.
//! Output: linear relation + batched linear relation.

use crate::commitment::{AjtaiParams, Commitment};
use crate::params::D;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::{RingElement, RingVector};
use crate::rok::hadamard::{HadamardChallenges, HadamardProof};
use crate::rok::range_proof::{
    ProjectionMatrix, RangeProof, RangeProofChallenges, RangeProofParams,
};
use crate::rok::{BatchedLinearRelation, LinearRelation};

/// Proof for the single-instance generalized R1CS reduction.
#[derive(Debug, Clone)]
pub struct GR1CSProof {
    /// Hadamard reduction proof.
    pub hadamard_proof: HadamardProof,
    /// Range proof.
    pub range_proof: RangeProof,
}

/// Prover challenges for Πgr1cs.
pub struct GR1CSChallenges {
    /// Random projection matrix J.
    pub projection: ProjectionMatrix,
    /// Sumcheck seed s' (shared between Πhad and Πmon).
    pub sumcheck_seed_had: Vec<ExtFieldElement>,
    /// Random combiner α.
    pub alpha: ExtFieldElement,
    /// Sumcheck challenges for the Hadamard sumcheck.
    pub hadamard_sumcheck_challenges: Vec<ExtFieldElement>,
    /// Sumcheck seed for the monomial check.
    pub sumcheck_seed_mon: Vec<ExtFieldElement>,
    /// Sumcheck challenges for the monomial check.
    pub monomial_sumcheck_challenges: Vec<ExtFieldElement>,
}

/// Run the Πgr1cs prover.
///
/// Input: (c, X_in) and witness W.
/// Output: GR1CS proof containing both Πhad and Πrg.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    commitment: &Commitment,
    public_input: &[i64],
    witness: &RingVector,
    r1cs: &R1CSMatrices,
    ajtai: &AjtaiParams,
    range_params: &RangeProofParams,
    challenges: &GR1CSChallenges,
    ctx: &ExtFieldContext,
) -> GR1CSProof {
    let n = r1cs.num_variables;

    // Build the full assignment F = [X_in, W] as a d × n matrix
    // witness_matrix[j] = the j-th coefficient of each ring element
    let _n_in = public_input.len();
    let mut witness_matrix = Vec::with_capacity(D);
    for j in 0..D {
        let mut col = Vec::with_capacity(n);
        // Public input: encode in coefficient 0 only
        for &x in public_input {
            col.push(if j == 0 { x } else { 0 });
        }
        // Witness: extract coefficient j from each ring element
        for elem in &witness.elements {
            col.push(elem.coeffs[j]);
        }
        // Pad if needed
        while col.len() < n {
            col.push(0);
        }
        witness_matrix.push(col);
    }

    // Run Πhad
    let had_challenges = HadamardChallenges {
        s: challenges.sumcheck_seed_had.clone(),
        alpha: challenges.alpha,
        sumcheck_challenges: challenges.hadamard_sumcheck_challenges.clone(),
    };
    let hadamard_proof =
        super::hadamard::prove(commitment, &witness_matrix, r1cs, &had_challenges, ctx);

    // Run Πrg
    // Build full ring witness for range proof
    let mut full_witness_elems = Vec::with_capacity(n);
    for &x in public_input {
        full_witness_elems.push(RingElement::from_constant(x));
    }
    for elem in &witness.elements {
        full_witness_elems.push(elem.clone());
    }
    while full_witness_elems.len() < n {
        full_witness_elems.push(RingElement::zero());
    }
    let full_witness = RingVector {
        elements: full_witness_elems,
    };

    let rg_challenges = RangeProofChallenges {
        projection: challenges.projection.clone(),
        monomial_challenges: super::monomial::MonomialChallenges {
            s: challenges.sumcheck_seed_mon.clone(),
            alpha: challenges.alpha,
            sumcheck_challenges: challenges.monomial_sumcheck_challenges.clone(),
        },
    };
    let range_proof = super::range_proof::prove(
        commitment,
        &full_witness,
        ajtai,
        range_params,
        &rg_challenges,
        ctx,
    );

    GR1CSProof {
        hadamard_proof,
        range_proof,
    }
}

/// Run the Πgr1cs verifier.
pub fn verify(
    commitment: &Commitment,
    _public_input: &[i64],
    proof: &GR1CSProof,
    _r1cs: &R1CSMatrices,
    range_params: &RangeProofParams,
    challenges: &GR1CSChallenges,
    ctx: &ExtFieldContext,
) -> Result<(LinearRelation, BatchedLinearRelation), GR1CSError> {
    // Verify Πhad
    let had_challenges = HadamardChallenges {
        s: challenges.sumcheck_seed_had.clone(),
        alpha: challenges.alpha,
        sumcheck_challenges: challenges.hadamard_sumcheck_challenges.clone(),
    };
    let linear_rel =
        super::hadamard::verify(commitment, &proof.hadamard_proof, &had_challenges, ctx)
            .map_err(|_| GR1CSError::HadamardFailed)?;

    // Verify Πrg
    let rg_challenges = RangeProofChallenges {
        projection: challenges.projection.clone(),
        monomial_challenges: super::monomial::MonomialChallenges {
            s: challenges.sumcheck_seed_mon.clone(),
            alpha: challenges.alpha,
            sumcheck_challenges: challenges.monomial_sumcheck_challenges.clone(),
        },
    };
    let batched_rel = super::range_proof::verify(
        commitment,
        &proof.range_proof,
        range_params,
        &rg_challenges,
        ctx,
    )
    .map_err(|_| GR1CSError::RangeProofFailed)?;

    Ok((linear_rel, batched_rel))
}

#[derive(Debug)]
pub enum GR1CSError {
    HadamardFailed,
    RangeProofFailed,
    SumcheckFailed,
}
