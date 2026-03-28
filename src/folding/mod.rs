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
    /// Individual commitments from each statement (needed by verifier).
    pub commitments: Vec<Commitment>,
    /// Individual GR1CS proofs (parallel reduction, Steps 1-3).
    pub gr1cs_proofs: Vec<GR1CSProof>,
    /// The folding challenge vector β ∈ S^{ℓ_np} (derived from transcript).
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
    let num_vars_had = if m <= 1 {
        0
    } else {
        (usize::BITS - (m - 1).leading_zeros()) as usize
    };

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

    let n = r1cs.num_variables;
    let n_blocks = (n * D) / range_params.ell_h;
    let projected_len = n_blocks.max(1) * range_params.lambda_pj;
    let monomial_vec_len = projected_len.next_power_of_two();
    let num_vars_mon = if monomial_vec_len <= 1 {
        0
    } else {
        (usize::BITS - (monomial_vec_len - 1).leading_zeros()) as usize
    };
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

    // Derive projection seed from the transcript so that the projection
    // matrix is bound to the committed statement.
    let mut projection_seed = [0u8; 32];
    transcript.challenge_bytes(b"projection-seed", &mut projection_seed);
    let projection =
        ProjectionMatrix::sample(range_params.lambda_pj, range_params.ell_h, &projection_seed);

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

    // Extract linear/batched relations directly from proof data.
    // The prover constructs these from its own proofs without re-verifying,
    // since the evaluation points and values are deterministic outputs of
    // the sumcheck and monomial protocols.
    for (i, stmt) in statements.iter().enumerate() {
        linear_relations.push(LinearRelation {
            commitment: stmt.commitment.clone(),
            evaluation_point: shared_challenges.hadamard_sumcheck_challenges.clone(),
            evaluation_values: gr1cs_proofs[i].hadamard_proof.evaluation_matrix.clone(),
        });
        batched_relations.push(BatchedLinearRelation {
            commitments: gr1cs_proofs[i].range_proof.monomial_commitments.clone(),
            evaluation_point: shared_challenges.monomial_sumcheck_challenges.clone(),
            evaluation_values: gr1cs_proofs[i]
                .range_proof
                .monomial_proof
                .evaluations
                .clone(),
        });
    }

    // Bind the GR1CS proofs to the Fiat-Shamir transcript before deriving β.
    // This prevents an adversary from reusing challenges across different proofs.
    for proof in &gr1cs_proofs {
        for msg in &proof.hadamard_proof.sumcheck_proof.round_messages {
            for eval in &msg.evaluations {
                transcript.append_bytes(b"sc-eval", &eval.c0.to_le_bytes());
                transcript.append_bytes(b"sc-eval", &eval.c1.to_le_bytes());
            }
        }
        for te in &proof.hadamard_proof.evaluation_matrix {
            for row in &te.data {
                let bytes: Vec<u8> = row.iter().flat_map(|v| v.to_le_bytes()).collect();
                transcript.append_bytes(b"eval-matrix", &bytes);
            }
        }
    }

    // Steps 4-6: Folding via low-norm challenge
    // Derive β deterministically from the Fiat-Shamir transcript.
    let beta = challenge::derive_challenge_vector(&mut transcript, q, ell_np);

    // Fold commitments: c* = Σ β_ℓ · c_ℓ
    let kappa = statements[0].commitment.value.len();
    let mut folded_commitment_elems = vec![RingElement::zero(); kappa];
    for (ell, stmt) in statements.iter().enumerate() {
        for (i, fc_elem) in folded_commitment_elems.iter_mut().enumerate() {
            let scaled = stmt.commitment.value.elements[i].mul(&beta[ell], q);
            *fc_elem = fc_elem.add(&scaled, q);
        }
    }
    let folded_commitment = Commitment {
        value: RingVector {
            elements: folded_commitment_elems,
        },
    };

    // Fold public inputs: x*_in = Σ β_ℓ · cf^{-1}(X^ℓ_in)
    let n_in = statements[0].public_input.len();
    let mut folded_public_input = vec![RingElement::zero(); n_in];
    for (ell, stmt) in statements.iter().enumerate() {
        for (i, fp_elem) in folded_public_input.iter_mut().enumerate() {
            let x_ring = RingElement::from_constant(stmt.public_input[i]);
            let scaled = x_ring.mul(&beta[ell], q);
            *fp_elem = fp_elem.add(&scaled, q);
        }
    }

    // Fold witnesses: f* = Σ β_ℓ · f_ℓ
    let n_w = statements[0].witness.len();
    let mut folded_witness_elems = vec![RingElement::zero(); n_w];
    for (ell, stmt) in statements.iter().enumerate() {
        for (i, fw_elem) in folded_witness_elems.iter_mut().enumerate() {
            let scaled = stmt.witness.elements[i].mul(&beta[ell], q);
            *fw_elem = fw_elem.add(&scaled, q);
        }
    }

    // Fold evaluation values from linear relations.
    // Each evaluation value is a TensorElement (T×D matrix). We fold using
    // the full ring element β[ℓ], performing ring multiplication per row.
    let mut folded_eval_vals = Vec::new();
    if !linear_relations.is_empty() {
        let mut folded = [
            crate::ring::tensor::TensorElement::zero(),
            crate::ring::tensor::TensorElement::zero(),
            crate::ring::tensor::TensorElement::zero(),
        ];
        for (ell, lin) in linear_relations.iter().enumerate() {
            for (i, f_elem) in folded.iter_mut().enumerate() {
                for t in 0..crate::params::T {
                    let row = RingElement {
                        coeffs: lin.evaluation_values[i].data[t],
                    };
                    let scaled = row.mul(&beta[ell], q);
                    let current = RingElement {
                        coeffs: f_elem.data[t],
                    };
                    let sum = current.add(&scaled, q);
                    f_elem.data[t] = sum.coeffs;
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
                    for (f_elem, mono_elem) in folded
                        .iter_mut()
                        .zip(proof.range_proof.monomial_vectors[layer].iter())
                    {
                        let scaled = mono_elem.mul(&beta[ell], q);
                        *f_elem = f_elem.add(&scaled, q);
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
        witness: RingVector {
            elements: folded_witness_elems,
        },
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

    let commitments: Vec<Commitment> = statements.iter().map(|s| s.commitment.clone()).collect();
    let proof = FoldingProof {
        commitments,
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
    let ell_np = proof.gr1cs_proofs.len();

    if proof.commitments.len() != ell_np || public_inputs.len() != ell_np {
        return Err(FoldingError::FoldingInconsistent);
    }

    // Step 1: Reconstruct transcript from the individual commitments in the proof
    let mut transcript = crate::fiat_shamir::transcript::Transcript::new(b"symphony-fold");
    for commitment in &proof.commitments {
        for elem in &commitment.value.elements {
            let bytes: Vec<u8> = elem.coeffs.iter().flat_map(|c| c.to_le_bytes()).collect();
            transcript.append_bytes(b"commitment", &bytes);
        }
    }

    // Step 2: Derive shared GR1CS challenges from transcript (same as prover)
    let shared_challenges = derive_shared_challenges(&mut transcript, r1cs, range_params, q);

    // Step 3: Verify each GR1CS proof
    for (i, gr1cs_proof) in proof.gr1cs_proofs.iter().enumerate() {
        crate::rok::gr1cs::verify(
            &proof.commitments[i],
            &public_inputs[i],
            gr1cs_proof,
            r1cs,
            range_params,
            &shared_challenges,
            ctx,
        )
        .map_err(|_| FoldingError::GR1CSFailed(i))?;
    }

    // Bind the GR1CS proofs to the transcript (must match prover's binding).
    for gr1cs_proof in &proof.gr1cs_proofs {
        for msg in &gr1cs_proof.hadamard_proof.sumcheck_proof.round_messages {
            for eval in &msg.evaluations {
                transcript.append_bytes(b"sc-eval", &eval.c0.to_le_bytes());
                transcript.append_bytes(b"sc-eval", &eval.c1.to_le_bytes());
            }
        }
        for te in &gr1cs_proof.hadamard_proof.evaluation_matrix {
            for row in &te.data {
                let bytes: Vec<u8> = row.iter().flat_map(|v| v.to_le_bytes()).collect();
                transcript.append_bytes(b"eval-matrix", &bytes);
            }
        }
    }

    // Step 4: Derive β from the transcript (must match what prover derived)
    let expected_beta = challenge::derive_challenge_vector(&mut transcript, q, ell_np);
    if expected_beta.len() != proof.beta.len() {
        return Err(FoldingError::FoldingInconsistent);
    }
    for (a, b) in expected_beta.iter().zip(proof.beta.iter()) {
        if a != b {
            return Err(FoldingError::FoldingInconsistent);
        }
    }

    // Step 5: Verify folded commitment: c* = Σ β_ℓ · c_ℓ
    let kappa = proof.commitments[0].value.len();
    let mut expected_folded_commitment = vec![RingElement::zero(); kappa];
    for (ell, commitment) in proof.commitments.iter().enumerate() {
        for (i, efc_elem) in expected_folded_commitment.iter_mut().enumerate() {
            let scaled = commitment.value.elements[i].mul(&proof.beta[ell], q);
            *efc_elem = efc_elem.add(&scaled, q);
        }
    }
    for (i, efc_elem) in expected_folded_commitment.iter().enumerate() {
        if i < proof.folded_instance.commitment.value.len()
            && *efc_elem != proof.folded_instance.commitment.value.elements[i]
        {
            return Err(FoldingError::FoldingInconsistent);
        }
    }

    // Step 6: Verify folded public inputs: x*_in = Σ β_ℓ · cf^{-1}(X^ℓ_in)
    let n_in = public_inputs[0].len();
    let mut expected_folded_input = vec![RingElement::zero(); n_in];
    for (ell, pi) in public_inputs.iter().enumerate() {
        for (i, efi_elem) in expected_folded_input.iter_mut().enumerate() {
            let x_ring = RingElement::from_constant(pi[i]);
            let scaled = x_ring.mul(&proof.beta[ell], q);
            *efi_elem = efi_elem.add(&scaled, q);
        }
    }
    for (i, efi_elem) in expected_folded_input.iter().enumerate() {
        if i < proof.folded_instance.public_input.len()
            && *efi_elem != proof.folded_instance.public_input[i]
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
