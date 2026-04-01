//! Full SNARK prover — orchestrates folding, CP-SNARK, and backend SNARK.

use crate::commitment::{AjtaiParams, Commitment};
use crate::fiat_shamir::hash_commitment::HashCommitment;
use crate::fiat_shamir::transcript::Transcript;
use crate::fiat_shamir::FSCommitment;
use crate::folding::digest::{
    digest_challenges, digest_fold_inputs, digest_fs_commitments, digest_transcript_seed, FoldInput,
};
use crate::folding::FoldingStatement;
use crate::params::SymphonyParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::RingVector;
use crate::rok::range_proof::RangeProofParams;
use crate::snark::cp_snark;
use crate::snark::{BackendSnark, SymphonyProof};

/// Derive range proof parameters from global Symphony parameters.
fn range_proof_params(params: &SymphonyParams) -> RangeProofParams {
    RangeProofParams {
        lambda_pj: params.lambda_pj,
        ell_h: params.ell_h,
        d_prime: (params.d as i64) - 2,
        k_g: params.k_g(),
        input_bound: params.b_input(),
    }
}

/// Orchestrate the complete proof generation pipeline.
///
/// Steps:
/// 1. Convert input witnesses to generalized committed R1CS (gadget decomposition)
/// 2. Run non-interactive folding with Fiat-Shamir commitments
/// 3. Generate backend SNARK proof for the folded statement via `S::prove`
/// 4. Generate CP-SNARK proof for folding correctness via `S::prove`
/// 5. Bundle everything into a `SymphonyProof<S>`
pub fn generate_proof<S: BackendSnark>(
    params: &SymphonyParams,
    ajtai: &AjtaiParams,
    cp_pk: &S::ProvingKey,
    snark_pk: &S::ProvingKey,
    cp_layout: &cp_snark::CpR1csLayout,
    statements: &[(Commitment, Vec<i64>, RingVector)],
    r1cs: &R1CSMatrices,
) -> SymphonyProof<S> {
    let timing = std::env::var("SYMPHONY_TIMING").map_or(false, |v| v == "1");
    let t0 = std::time::Instant::now();

    let mut transcript = Transcript::new(b"symphony-v1");

    // Bind public inputs and R1CS metadata to match the verifier's transcript
    for (_, pi, _) in statements {
        let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
        transcript.append_bytes(b"public-input", &bytes);
    }
    transcript.append_bytes(b"r1cs-m", &(r1cs.num_constraints as u64).to_le_bytes());
    transcript.append_bytes(b"r1cs-n", &(r1cs.num_variables as u64).to_le_bytes());
    transcript.append_bytes(b"r1cs-pub", &(r1cs.num_public as u64).to_le_bytes());

    // Step 1: Build FoldingStatements
    let folding_statements: Vec<FoldingStatement> = statements
        .iter()
        .map(|(c, pi, w)| {
            for elem in &c.value.elements {
                let bytes: Vec<u8> = elem.coeffs.iter().flat_map(|v| v.to_le_bytes()).collect();
                transcript.append_bytes(b"commitment", &bytes);
            }
            FoldingStatement {
                commitment: c.clone(),
                public_input: pi.clone(),
                witness: w.clone(),
            }
        })
        .collect();

    // Step 2: Run folding
    let rp = range_proof_params(params);
    let ext_ctx = crate::ring::extension::ExtFieldContext::new(params.q);

    let (folding_proof, folded_witness, shared_challenges) =
        crate::folding::prove(&folding_statements, r1cs, ajtai, &rp, &ext_ctx);

    // Step 3: Commit to actual folding round messages.
    // Each message is a deterministic encoding of the corresponding GR1CS proof.
    let fs_messages: Vec<Vec<u8>> = folding_proof
        .gr1cs_proofs
        .iter()
        .map(cp_snark::encode_gr1cs_round_message)
        .collect();
    let fs_scheme = HashCommitment::new();
    let mut fs_commitments = Vec::with_capacity(fs_messages.len());
    let mut fs_openings = Vec::with_capacity(fs_messages.len());
    for message in &fs_messages {
        let (commitment, opening) = fs_scheme.commit(message);
        fs_commitments.push(commitment.to_vec());
        fs_openings.push(opening.to_vec());
    }

    // Step 3b: Compute fs_root and transcript_seed_digest for sublinear verifier.
    let fs_root = digest_fs_commitments(&fs_commitments);
    let public_input_vecs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();
    let transcript_seed_digest = digest_transcript_seed(
        &public_input_vecs,
        r1cs.num_constraints,
        r1cs.num_variables,
        r1cs.num_public,
    );

    // Step 4: Build fold inputs and compute digests for compressed CP instance
    let fold_inputs: Vec<FoldInput> = statements
        .iter()
        .enumerate()
        .map(|(i, (c, pi, _))| {
            let commitment_bytes = cp_snark::encode_commitment_to_bytes(c);
            // Serialize eval values from the folding proof for this instance
            let eval_values_bytes = if i < folding_proof.gr1cs_proofs.len() {
                cp_snark::encode_gr1cs_round_message(&folding_proof.gr1cs_proofs[i])
            } else {
                Vec::new()
            };
            FoldInput {
                commitment_bytes,
                public_input: pi.clone(),
                eval_values_bytes,
            }
        })
        .collect();

    let fold_root = digest_fold_inputs(&fold_inputs);

    let t_folding = t0.elapsed();

    // Step 5: Generate CP-SNARK proof via S::prove
    let t_cp_start = std::time::Instant::now();

    // Derive per-round challenges from the full transcript and compute their digest.
    let mut derived_challenges = Vec::with_capacity(fs_commitments.len());
    {
        // Build a fresh transcript mirroring the Fiat-Shamir derivation.
        let mut ch_transcript = Transcript::new(b"symphony-v1");
        for stmt in statements {
            let bytes: Vec<u8> = stmt.1.iter().flat_map(|v| v.to_le_bytes()).collect();
            ch_transcript.append_bytes(b"public-input", &bytes);
        }
        ch_transcript.append_bytes(b"r1cs-m", &(r1cs.num_constraints as u64).to_le_bytes());
        ch_transcript.append_bytes(b"r1cs-n", &(r1cs.num_variables as u64).to_le_bytes());
        ch_transcript.append_bytes(b"r1cs-pub", &(r1cs.num_public as u64).to_le_bytes());
        for fs_comm in &fs_commitments {
            ch_transcript.append_bytes(b"fs-commitment", fs_comm);
        }
        for i in 0..fs_commitments.len() {
            let mut challenge = vec![0u8; 32];
            let label = format!("challenge-{i}");
            ch_transcript.challenge_bytes(label.as_bytes(), &mut challenge);
            derived_challenges.push(challenge);
        }
    }
    let challenge_digest = digest_challenges(&derived_challenges);

    // Build CP instance and witness using R1CS-compatible layout.
    // The instance contains the folded commitment/public input coefficients.
    // The witness contains per-instance commitments, beta, and ring products.
    let public_input_vecs_for_cp: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();
    let commitments_for_cp: Vec<_> = folding_proof.commitments.clone();
    let cp_instance = cp_snark::encode_cp_instance_r1cs(
        &folding_proof.folded_instance,
        cp_layout,
    );
    let cp_witness = cp_snark::encode_cp_witness_r1cs(
        &commitments_for_cp,
        &public_input_vecs_for_cp,
        &folding_proof.beta,
        &folding_proof.folded_instance,
        cp_layout,
        &params.ntt,
        &folding_proof.gr1cs_proofs,
        &shared_challenges.sumcheck_seed_had,
        &shared_challenges.alpha,
        &shared_challenges.hadamard_sumcheck_challenges,
        ext_ctx.alpha,  // QNR from extension field context
        params.q,
    );
    let cp_proof = S::prove(cp_pk, &cp_instance, &cp_witness);

    let t_cp = t_cp_start.elapsed();

    // Step 6: Generate backend SNARK proof for the folded statement via S::prove.
    // Create a fresh output proving key with R1CS context so that backends
    // (e.g. WHIR) can verify the actual R1CS relation, not just a generic sumcheck.
    let t_output_start = std::time::Instant::now();
    let snark_instance = cp_snark::encode_folded_instance(&folding_proof.folded_instance);
    let snark_witness = cp_snark::encode_folded_witness(&folded_witness);

    // Compute expected BabyBear z-vector length to check R1CS compatibility.
    let d = params.d as usize;
    let instance_elems = snark_instance.len() / 8; // i64-encoded
    let witness_elems = snark_witness.len() / 8;
    let total_elems = instance_elems + witness_elems;
    let total_flat = r1cs.num_variables * d;

    let output_pk = if total_elems <= total_flat {
        // R1CS dimensions are compatible with the folded encoding — use full
        // R1CS verification in the backend.
        let output_context = cp_snark::serialize_output_context(r1cs, params.q, d);
        let output_relation = crate::snark::RelationDescription {
            num_instance_vars: params.n(),
            num_witness_vars: params.n(),
            num_constraints: params.m,
            context: Some(output_context),
        };
        let (pk, _) = S::setup(&output_relation);
        pk
    } else {
        // Dimensions don't align — fall back to stored key (CP path).
        // This is a known limitation: full R1CS verification requires
        // the folded encoding to fit the flattened R1CS dimensions.
        snark_pk.clone()
    };
    let snark_proof = S::prove(&output_pk, &snark_instance, &snark_witness);
    let t_output = t_output_start.elapsed();

    if timing {
        let t_total = t0.elapsed();
        eprintln!(
            "[symphony-prove] folding={:.3}ms cp_prove={:.3}ms output_prove={:.3}ms total={:.3}ms",
            t_folding.as_secs_f64() * 1000.0,
            t_cp.as_secs_f64() * 1000.0,
            t_output.as_secs_f64() * 1000.0,
            t_total.as_secs_f64() * 1000.0,
        );
    }

    SymphonyProof {
        cp_proof,
        snark_proof,
        folded_instance: folding_proof.folded_instance.clone(),
        fold_root,
        challenge_digest,
        fs_root,
        transcript_seed_digest,
        witness_data: crate::snark::ProofWitnessData {
            fs_commitments,
            fs_openings: fs_openings.iter().map(|o| o.to_vec()).collect(),
            fs_messages,
            fold_inputs,
            folding_proof,
        },
    }
}
