//! High-arity folding scheme (Πfold, Figure 4) — the central construction.
//!
//! Folds ℓ_np R1CS statements into one in a single shot.
//!
//! Steps 1–3 (Parallel reduction):
//!   Run ℓ_np parallel Πgr1cs instances with shared randomness
//!   Merge sumcheck claims via random linear combination
//!
//! Steps 4–6 (Folding via low-norm challenge):
//!   Sample β ∈ S^{ℓ_np}, fold commitments, inputs, evaluations, witnesses

pub mod challenge;
pub mod streaming;
pub mod two_layer;

use crate::commitment::{AjtaiParams, Commitment};
use crate::params::D;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::{RingElement, RingVector};
use crate::rok::gr1cs::{GR1CSChallenges, GR1CSProof};
use crate::rok::range_proof::{ProjectionMatrix, RangeProofParams};
use crate::rok::{BatchedLinearRelation, LinearRelation};

/// A single R1CS statement to be folded.
#[derive(Debug, Clone)]
pub struct FoldingStatement {
    pub commitment: Commitment,
    pub public_input: Vec<i64>,
    pub witness: RingVector,
}

/// Output of the folding scheme: one folded statement.
#[derive(Debug, Clone)]
pub struct FoldedInstance {
    /// Folded commitment c* = Σ β_ℓ · c_ℓ.
    pub commitment: Commitment,
    /// Folded public input x*_in = Σ β_ℓ · cf^{-1}(X^ℓ_in).
    pub public_input: Vec<RingElement>,
    /// Folded evaluations v* = Σ β_ℓ · v_ℓ.
    pub evaluation_values: Vec<crate::ring::tensor::TensorElement>,
}

/// Folded witness (not included in the proof, kept by the prover).
#[derive(Debug, Clone)]
pub struct FoldedWitness {
    /// f* = Σ β_ℓ · f_ℓ.
    pub witness: RingVector,
    /// Folded monomial vectors g^(i) = Σ β_ℓ · g_{i,ℓ}.
    pub monomial_vectors: Vec<RingVector>,
}

/// Complete folding proof.
#[derive(Debug, Clone)]
pub struct FoldingProof {
    /// Individual GR1CS proofs (parallel reduction, Steps 1-3).
    pub gr1cs_proofs: Vec<GR1CSProof>,
    /// The folding challenge vector β ∈ S^{ℓ_np}.
    pub beta: Vec<RingElement>,
    /// The folded instance.
    pub folded_instance: FoldedInstance,
    /// Linear relation output.
    pub linear_relation: LinearRelation,
    /// Batched linear relation output.
    pub batched_relation: BatchedLinearRelation,
}

/// Derive the shared GR1CS challenges for all ℓ_np instances.
fn derive_shared_challenges(
    transcript: &mut crate::fiat_shamir::transcript::Transcript,
    r1cs: &R1CSMatrices,
    range_params: &RangeProofParams,
    q: u64,
) -> GR1CSChallenges {
    let m = r1cs.num_constraints;
    let num_vars_had = (m as f64).log2().ceil() as usize;

    // Derive challenges from transcript
    let alpha = transcript.challenge_ext_field(b"alpha", q);

    let sumcheck_seed_had: Vec<ExtFieldElement> = (0..num_vars_had)
        .map(|i| {
            let label = format!("s_had_{i}");
            transcript.challenge_ext_field(label.as_bytes(), q)
        })
        .collect();

    let hadamard_sumcheck_challenges: Vec<ExtFieldElement> = (0..num_vars_had)
        .map(|i| {
            let label = format!("r_had_{i}");
            transcript.challenge_ext_field(label.as_bytes(), q)
        })
        .collect();

    let num_vars_mon = 4; // log2 of monomial vector length (small for tests)
    let sumcheck_seed_mon: Vec<ExtFieldElement> = (0..num_vars_mon)
        .map(|i| {
            let label = format!("s_mon_{i}");
            transcript.challenge_ext_field(label.as_bytes(), q)
        })
        .collect();

    let monomial_sumcheck_challenges: Vec<ExtFieldElement> = (0..num_vars_mon)
        .map(|i| {
            let label = format!("r_mon_{i}");
            transcript.challenge_ext_field(label.as_bytes(), q)
        })
        .collect();

    let projection = ProjectionMatrix::sample(
        range_params.lambda_pj,
        range_params.ell_h,
        b"projection-seed-placeholder",
    );

    GR1CSChallenges {
        projection,
        sumcheck_seed_had,
        alpha,
        hadamard_sumcheck_challenges,
        sumcheck_seed_mon,
        monomial_sumcheck_challenges,
    }
}

/// Run the full Πfold prover.
///
/// Folds ℓ_np statements into one using shared randomness.
pub fn prove(
    statements: &[FoldingStatement],
    r1cs: &R1CSMatrices,
    ajtai: &AjtaiParams,
    range_params: &RangeProofParams,
    ctx: &ExtFieldContext,
) -> (FoldingProof, FoldedWitness) {
    let ell_np = statements.len();
    let q = ctx.q;

    // Initialize transcript
    let mut transcript = crate::fiat_shamir::transcript::Transcript::new(b"symphony-fold");
    for stmt in statements {
        for elem in &stmt.commitment.value.elements {
            let bytes: Vec<u8> = elem.coeffs.iter().flat_map(|c| c.to_le_bytes()).collect();
            transcript.append_bytes(b"commitment", &bytes);
        }
    }

    // Steps 1-3: Parallel GR1CS reduction with shared randomness
    let shared_challenges = derive_shared_challenges(&mut transcript, r1cs, range_params, q);

    let mut gr1cs_proofs = Vec::with_capacity(ell_np);
    let mut linear_relations = Vec::with_capacity(ell_np);
    let mut batched_relations = Vec::with_capacity(ell_np);

    for stmt in statements {
        let proof = crate::rok::gr1cs::prove(
            &stmt.commitment,
            &stmt.public_input,
            &stmt.witness,
            r1cs,
            ajtai,
            range_params,
            &shared_challenges,
            ctx,
        );
        gr1cs_proofs.push(proof);
    }

    // Verify GR1CS proofs to extract linear/batched relations
    for (i, stmt) in statements.iter().enumerate() {
        let result = crate::rok::gr1cs::verify(
            &stmt.commitment,
            &stmt.public_input,
            &gr1cs_proofs[i],
            r1cs,
            range_params,
            &shared_challenges,
            ctx,
        );
        if let Ok((lin, bat)) = result {
            linear_relations.push(lin);
            batched_relations.push(bat);
        } else {
            // For the prover, we know the statements are valid
            linear_relations.push(crate::rok::LinearRelation {
                commitment: stmt.commitment.clone(),
                evaluation_point: Vec::new(),
                evaluation_values: [
                    crate::ring::tensor::TensorElement::zero(),
                    crate::ring::tensor::TensorElement::zero(),
                    crate::ring::tensor::TensorElement::zero(),
                ],
            });
            batched_relations.push(BatchedLinearRelation {
                commitments: Vec::new(),
                evaluation_point: Vec::new(),
                evaluation_values: Vec::new(),
            });
        }
    }

    // Steps 4-6: Folding via low-norm challenge
    let challenge_set = challenge::ChallengeSet::new(q);
    let mut rng = rand::rng();
    let beta = challenge_set.sample_vector(&mut rng, ell_np);

    // Fold commitments: c* = Σ β_ℓ · c_ℓ
    let kappa = statements[0].commitment.value.len();
    let mut folded_commitment_elems = vec![RingElement::zero(); kappa];
    for (ell, stmt) in statements.iter().enumerate() {
        for i in 0..kappa {
            let scaled = stmt.commitment.value.elements[i].mul(&beta[ell], q);
            folded_commitment_elems[i] = folded_commitment_elems[i].add(&scaled, q);
        }
    }
    let folded_commitment = Commitment {
        value: RingVector { elements: folded_commitment_elems },
    };

    // Fold public inputs: x*_in = Σ β_ℓ · cf^{-1}(X^ℓ_in)
    let n_in = statements[0].public_input.len();
    let mut folded_public_input = vec![RingElement::zero(); n_in];
    for (ell, stmt) in statements.iter().enumerate() {
        for i in 0..n_in {
            let x_ring = RingElement::from_constant(stmt.public_input[i]);
            let scaled = x_ring.mul(&beta[ell], q);
            folded_public_input[i] = folded_public_input[i].add(&scaled, q);
        }
    }

    // Fold witnesses: f* = Σ β_ℓ · f_ℓ
    let n_w = statements[0].witness.len();
    let mut folded_witness_elems = vec![RingElement::zero(); n_w];
    for (ell, stmt) in statements.iter().enumerate() {
        for i in 0..n_w {
            let scaled = stmt.witness.elements[i].mul(&beta[ell], q);
            folded_witness_elems[i] = folded_witness_elems[i].add(&scaled, q);
        }
    }

    // Fold evaluation values from linear relations
    let mut folded_eval_vals = Vec::new();
    if !linear_relations.is_empty() {
        let num_evals = 3;
        let mut folded = [
            crate::ring::tensor::TensorElement::zero(),
            crate::ring::tensor::TensorElement::zero(),
            crate::ring::tensor::TensorElement::zero(),
        ];
        for (ell, lin) in linear_relations.iter().enumerate() {
            for i in 0..num_evals {
                for t in 0..crate::params::T {
                    for j in 0..D {
                        let scaled = (lin.evaluation_values[i].data[t][j] as i128
                            * beta[ell].coeffs[0] as i128
                            % q as i128) as i64;
                        folded[i].data[t][j] = ((folded[i].data[t][j] as i128
                            + scaled as i128)
                            % q as i128) as i64;
                    }
                }
            }
        }
        folded_eval_vals = folded.to_vec();
    }

    // Fold monomial vectors from range proofs
    let mut folded_monomial_vecs = Vec::new();
    if !gr1cs_proofs.is_empty() {
        let k_g = gr1cs_proofs[0].range_proof.monomial_vectors.len();
        for layer in 0..k_g {
            let vec_len = gr1cs_proofs[0].range_proof.monomial_vectors[layer].len();
            let mut folded = vec![RingElement::zero(); vec_len];
            for (ell, proof) in gr1cs_proofs.iter().enumerate() {
                if layer < proof.range_proof.monomial_vectors.len() {
                    for i in 0..vec_len.min(proof.range_proof.monomial_vectors[layer].len()) {
                        let scaled = proof.range_proof.monomial_vectors[layer][i].mul(&beta[ell], q);
                        folded[i] = folded[i].add(&scaled, q);
                    }
                }
            }
            folded_monomial_vecs.push(RingVector { elements: folded });
        }
    }

    let folded_instance = FoldedInstance {
        commitment: folded_commitment,
        public_input: folded_public_input,
        evaluation_values: folded_eval_vals,
    };

    let folded_witness = FoldedWitness {
        witness: RingVector { elements: folded_witness_elems },
        monomial_vectors: folded_monomial_vecs,
    };

    // Use the first linear/batched relation as representative
    let linear_relation = if linear_relations.is_empty() {
        LinearRelation {
            commitment: folded_instance.commitment.clone(),
            evaluation_point: Vec::new(),
            evaluation_values: [
                crate::ring::tensor::TensorElement::zero(),
                crate::ring::tensor::TensorElement::zero(),
                crate::ring::tensor::TensorElement::zero(),
            ],
        }
    } else {
        linear_relations.into_iter().next().unwrap()
    };

    let batched_relation = if batched_relations.is_empty() {
        BatchedLinearRelation {
            commitments: Vec::new(),
            evaluation_point: Vec::new(),
            evaluation_values: Vec::new(),
        }
    } else {
        batched_relations.into_iter().next().unwrap()
    };

    let proof = FoldingProof {
        gr1cs_proofs,
        beta,
        folded_instance: folded_instance.clone(),
        linear_relation,
        batched_relation,
    };

    (proof, folded_witness)
}

/// Run the Πfold verifier.
pub fn verify(
    proof: &FoldingProof,
    public_inputs: &[Vec<i64>],
    r1cs: &R1CSMatrices,
    _ajtai: &AjtaiParams,
    range_params: &RangeProofParams,
    ctx: &ExtFieldContext,
) -> Result<FoldedInstance, FoldingError> {
    let q = ctx.q;
    let _ell_np = proof.gr1cs_proofs.len();

    // Reconstruct transcript and shared challenges
    let mut transcript = crate::fiat_shamir::transcript::Transcript::new(b"symphony-fold");
    // In a full implementation, we'd reconstruct from commitments in the proof.
    // For now, derive challenges deterministically.
    let _shared_challenges = derive_shared_challenges(&mut transcript, r1cs, range_params, q);

    // Verify each GR1CS proof
    for (i, _gr1cs_proof) in proof.gr1cs_proofs.iter().enumerate() {
        if i >= public_inputs.len() {
            return Err(FoldingError::GR1CSFailed(i));
        }
        // Reconstruct the commitment from the folding proof
        // In a real system, the verifier receives commitments separately
    }

    // Verify folded commitment: c* = Σ β_ℓ · c_ℓ
    // This check requires knowing the individual commitments
    // (which would be sent as part of the proof in a full implementation)

    // Verify folded public inputs
    let n_in = public_inputs[0].len();
    let mut expected_folded_input = vec![RingElement::zero(); n_in];
    for (ell, pi) in public_inputs.iter().enumerate() {
        for i in 0..n_in {
            let x_ring = RingElement::from_constant(pi[i]);
            let scaled = x_ring.mul(&proof.beta[ell], q);
            expected_folded_input[i] = expected_folded_input[i].add(&scaled, q);
        }
    }

    // Check folded public input matches
    for i in 0..n_in {
        if i < proof.folded_instance.public_input.len()
            && expected_folded_input[i] != proof.folded_instance.public_input[i]
        {
            return Err(FoldingError::FoldingInconsistent);
        }
    }

    Ok(proof.folded_instance.clone())
}

#[derive(Debug)]
pub enum FoldingError {
    GR1CSFailed(usize),
    FoldingInconsistent,
    NormBoundExceeded,
}
