//! Full SNARK prover — orchestrates folding, CP-SNARK, and backend SNARK.

use crate::commitment::{AjtaiParams, Commitment};
use crate::digest_core::{
    derive_challenges_with_scheme, digest_challenge_digest_with_scheme,
    digest_fold_root_with_scheme, digest_fs_root_with_scheme, digest_transcript_seed_with_scheme,
    fs_commit_with_scheme, FoldInput,
};
use crate::folding::FoldingStatement;
use crate::params::SymphonyParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::RingVector;
use crate::snark::cp_snark;
use crate::snark::{
    build_canonical_transcript_bytes, range_proof_params, BackendSnark, RelationDescription,
    SymphonyProof, TypedCpSetupDescriptor,
};

/// Orchestrate the complete proof generation pipeline.
///
/// Steps:
/// 1. Convert input witnesses to generalized committed R1CS (gadget decomposition)
/// 2. Run non-interactive folding with Fiat-Shamir commitments
/// 3. Generate backend SNARK proof for the folded statement via `S::prove`
/// 4. Generate CP-SNARK proof for folding correctness via `S::prove`
/// 5. Bundle everything into a `SymphonyProof<S>`
#[allow(clippy::too_many_arguments)]
pub fn generate_proof<S: BackendSnark>(
    params: &SymphonyParams,
    ajtai: &AjtaiParams,
    cp_pk: &S::ProvingKey,
    cp_pk_for_relation: &dyn Fn(RelationDescription) -> S::ProvingKey,
    snark_pk: &S::ProvingKey,
    snark_pk_for_context: &dyn Fn(Vec<u8>) -> S::ProvingKey,
    cp_layout: &cp_snark::CpR1csLayout,
    statements: &[(Commitment, Vec<i64>, RingVector)],
    r1cs: &R1CSMatrices,
) -> SymphonyProof<S> {
    let timing = std::env::var("SYMPHONY_TIMING").is_ok_and(|v| v == "1");
    let t0 = std::time::Instant::now();

    // Step 1: Build FoldingStatements
    let folding_statements: Vec<FoldingStatement> = statements
        .iter()
        .map(|(c, pi, w)| FoldingStatement {
            commitment: c.clone(),
            public_input: pi.clone(),
            witness: w.clone(),
        })
        .collect();

    // Step 2: Run folding
    let rp = range_proof_params(params);
    let ext_ctx = crate::ring::extension::ExtFieldContext::new(params.q);

    #[cfg(feature = "whir")]
    let (mut folding_proof, mut folded_witness, shared_challenges) =
        crate::folding::prove(&folding_statements, r1cs, ajtai, &rp, &ext_ctx);
    #[cfg(not(feature = "whir"))]
    let (folding_proof, folded_witness, shared_challenges) =
        crate::folding::prove(&folding_statements, r1cs, ajtai, &rp, &ext_ctx);

    // Step 3: Commit to actual folding round messages.
    // Each message is a deterministic encoding of the corresponding GR1CS proof.
    let fs_messages: Vec<Vec<u8>> = folding_proof
        .gr1cs_proofs
        .iter()
        .map(cp_snark::encode_gr1cs_round_message)
        .collect();
    let digest_scheme = S::public_digest_scheme();
    let mut fs_commitments = Vec::with_capacity(fs_messages.len());
    let mut fs_openings = Vec::with_capacity(fs_messages.len());
    for message in &fs_messages {
        let (commitment, opening) = fs_commit_with_scheme(digest_scheme, message);
        fs_commitments.push(commitment.to_vec());
        fs_openings.push(opening.to_vec());
    }

    // Step 3b: Compute fs_root and transcript_seed_digest for sublinear verifier.
    let fs_root = digest_fs_root_with_scheme(digest_scheme, &fs_commitments);
    let public_input_vecs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();
    let transcript_seed_digest = digest_transcript_seed_with_scheme(
        digest_scheme,
        &public_input_vecs,
        r1cs.num_constraints,
        r1cs.num_variables,
        r1cs.num_public,
    );

    // Step 4: Build fold inputs and compute compressed CP digests.
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

    let fold_root = digest_fold_root_with_scheme(digest_scheme, &fold_inputs);

    let t_folding = t0.elapsed();

    // Step 5: Generate CP-SNARK proof via S::prove
    let t_cp_start = std::time::Instant::now();

    // Derive per-round challenges from canonical transcript bytes.
    let transcript_bytes =
        build_canonical_transcript_bytes(&public_input_vecs, r1cs, &fs_commitments);
    let derived_challenges = derive_challenges_with_scheme(
        digest_scheme,
        &public_input_vecs,
        r1cs.num_constraints,
        r1cs.num_variables,
        r1cs.num_public,
        &fs_commitments,
    );
    let challenge_digest = digest_challenge_digest_with_scheme(digest_scheme, &derived_challenges);

    #[cfg(feature = "whir")]
    if digest_scheme == crate::digest_core::PublicDigestScheme::Poseidon2BabyBear {
        let typed_beta =
            crate::snark::cp_snark::typed_r1cs::poseidon_challenges_to_betas(&derived_challenges)
                .expect("Poseidon2/BabyBear challenge output must map to typed CP beta");
        assert_eq!(
            typed_beta.len(),
            folding_proof.gr1cs_proofs.len(),
            "typed CP beta count must match folding proof arity",
        );
        folding_proof.beta = typed_beta;
        let original_witnesses: Vec<_> = statements.iter().map(|(_, _, w)| w.clone()).collect();
        folded_witness = crate::folding::retarget_folding_proof_to_current_beta(
            &mut folding_proof,
            &public_input_vecs,
            &original_witnesses,
            params.q,
            params.ntt(),
        )
        .expect("typed CP beta must retarget folded state consistently");
    }

    // Build CP instance and witness using R1CS-compatible layout.
    // The instance contains the folded commitment/public input coefficients.
    // The witness contains per-instance commitments, beta, and ring products.
    let public_input_vecs_for_cp: Vec<Vec<i64>> =
        statements.iter().map(|(_, pi, _)| pi.clone()).collect();
    let commitments_for_cp: Vec<_> = folding_proof.commitments.clone();
    let folded_output = crate::folding::folded_output_instance_from_proof(&folding_proof);
    let folded_output_witness = crate::folding::folded_output_witness_from_folded(&folded_witness);
    let typed_cp_public_instance = crate::cp_relation_core::CpPublicInstance {
        fs_root,
        fold_root,
        challenge_digest,
        transcript_seed_digest,
        x_folded: folding_proof.folded_instance.clone(),
        folded_output: folded_output.clone(),
    };
    let typed_cp_public_statement = crate::cp_relation_core::CpPublicStatement::new(
        typed_cp_public_instance.clone(),
        public_input_vecs.clone(),
        r1cs,
        digest_scheme,
    )
    .with_fs_commitments(fs_commitments.clone());
    let typed_cp_witness = crate::cp_relation_core::CpWitnessBundle {
        transcript_bytes: transcript_bytes.clone(),
        fs_commitments: fs_commitments.clone(),
        fs_openings: fs_openings.iter().map(|o| o.to_vec()).collect(),
        fs_messages: fs_messages.clone(),
        fold_inputs: fold_inputs.clone(),
        original_witnesses: statements.iter().map(|(_, _, w)| w.clone()).collect(),
        folded_output: folding_proof.folded_instance.clone(),
        folded_output_instance: folded_output.clone(),
        folded_output_witness: folded_output_witness.clone(),
        folded_witness: folded_witness.clone(),
        folding_proof: folding_proof.clone(),
        shared_challenges: crate::cp_relation_core::CpSharedChallengeData {
            sumcheck_seed_had: shared_challenges.sumcheck_seed_had.clone(),
            alpha: shared_challenges.alpha,
            hadamard_sumcheck_challenges: shared_challenges.hadamard_sumcheck_challenges.clone(),
            sumcheck_seed_mon: shared_challenges.sumcheck_seed_mon.clone(),
            monomial_sumcheck_challenges: shared_challenges.monomial_sumcheck_challenges.clone(),
        },
    };
    let cp_public_instance = cp_snark::CpPublicInstance {
        fold_root,
        fs_root,
        transcript_seed_digest,
        challenge_digest,
        folded_instance: folding_proof.folded_instance.clone(),
    };
    let cp_instance = cp_snark::encode_cp_backend_instance(&cp_public_instance, cp_layout);
    let cp_ntt = Some(crate::ring::ntt::NttContext::new(params.q));
    let cp_witness = cp_snark::encode_cp_witness_r1cs(
        &commitments_for_cp,
        &public_input_vecs_for_cp,
        &folding_proof.beta,
        &folding_proof.folded_instance,
        cp_layout,
        &cp_ntt,
        &folding_proof.gr1cs_proofs,
        &shared_challenges.sumcheck_seed_had,
        &shared_challenges.alpha,
        &shared_challenges.hadamard_sumcheck_challenges,
        ext_ctx.alpha, // QNR from extension field context
        params.q,
    );

    let cp_proof = if S::has_authoritative_typed_cp() {
        let typed_cp_descriptor = TypedCpSetupDescriptor {
            params: params.clone(),
            ajtai: ajtai.clone(),
            original_r1cs: r1cs.clone(),
            cp_r1cs: cp_snark::generate_cp_r1cs(
                params.ell_np,
                params.kappa,
                params.n_in,
                params.m,
                ext_ctx.alpha,
                params.q,
            )
            .0,
            cp_layout: cp_layout.clone(),
        };
        let cp_relation = S::typed_cp_relation_description(&typed_cp_descriptor)
            .expect("authoritative typed CP backend did not provide a typed relation");
        let typed_cp_pk = cp_pk_for_relation(cp_relation);
        S::prove_typed_cp(&typed_cp_pk, &typed_cp_public_statement, &typed_cp_witness)
            .expect("authoritative typed CP backend rejected the typed CP witness")
    } else {
        S::prove(cp_pk, &cp_instance, &cp_witness)
    };

    let t_cp = t_cp_start.elapsed();

    // Step 6: Generate output proof for the folded statement.
    let t_output_start = std::time::Instant::now();
    let output_instance = cp_snark::encode_folded_instance(&folding_proof.folded_instance);
    let output_witness = cp_snark::encode_folded_witness(&folded_witness);

    // Compute expected BabyBear z-vector length to check R1CS compatibility.
    let d = params.d;
    let instance_elems = output_instance.len() / 8; // i64-encoded
    let witness_elems = output_witness.len() / 8;
    let total_elems = instance_elems + witness_elems;
    let total_flat = r1cs.num_variables * d;

    let output_proof = if let Some(output_context) = S::serialize_output_context(r1cs, params.q, d)
    {
        let output_pk = snark_pk_for_context(output_context);
        if S::has_authoritative_typed_output() {
            S::prove_typed_output(&output_pk, &folded_output, &folded_output_witness)
                .expect("authoritative typed output backend rejected folded output relation")
        } else if total_elems <= total_flat {
            S::prove(&output_pk, &output_instance, &output_witness)
        } else {
            S::prove(snark_pk, &output_instance, &output_witness)
        }
    } else {
        S::prove(snark_pk, &output_instance, &output_witness)
    };
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
        snark_proof: output_proof,
        folded_instance: folding_proof.folded_instance.clone(),
        folded_output,
        fold_root,
        challenge_digest,
        fs_root,
        transcript_seed_digest,
        witness_data: crate::snark::ProofWitnessData {
            fs_commitments,
            fs_openings: fs_openings.iter().map(|o| o.to_vec()).collect(),
            fs_messages,
            transcript_bytes,
            fold_inputs,
            original_witnesses: statements.iter().map(|(_, _, w)| w.clone()).collect(),
            folding_proof,
            shared_challenges: crate::cp_relation_core::CpSharedChallengeData {
                sumcheck_seed_had: shared_challenges.sumcheck_seed_had.clone(),
                alpha: shared_challenges.alpha,
                hadamard_sumcheck_challenges: shared_challenges
                    .hadamard_sumcheck_challenges
                    .clone(),
                sumcheck_seed_mon: shared_challenges.sumcheck_seed_mon.clone(),
                monomial_sumcheck_challenges: shared_challenges
                    .monomial_sumcheck_challenges
                    .clone(),
            },
            folded_output_witness,
            folded_witness,
        },
    }
}
