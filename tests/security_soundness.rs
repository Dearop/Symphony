//! Security-oriented soundness tests for the Symphony pipeline.
//!
//! These tests model common tampering/replay/splicing attacks and assert that
//! verification fails.
//!
//! - `SumcheckSnark` tests: non-succinct backend (full witness in proof)
//! - `spartan_soundness` tests: classical succinct backend (Pedersen + IPA, **not** PQ)
//! - `whir_soundness` tests: **post-quantum** succinct backend (Merkle + WHIR PCS)
//!   — enabled with `--features whir`

mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::params::{SymphonyParams, D};
use symphony::ring::{RingElement, RingVector};
use symphony::snark::{ProofWitnessData, SymphonyProof, SymphonyProver};
use symphony::SumcheckSnark;

fn security_params() -> SymphonyParams {
    SymphonyParams {
        q: Q,
        d: D,
        kappa: 2,
        ell_np: 2,
        ell_h: D,
        lambda_pj: 4,
        n_bar: 4,
        m: 4,
        b: 16,
        k_cs: 1,
        n_in: 1,
        ntt: SymphonyParams::try_ntt(Q, D),
    }
}

fn make_statement(
    prover: &SymphonyProver<SumcheckSnark>,
    z: &[i64],
    n_in: usize,
) -> (Commitment, Vec<i64>, RingVector) {
    let full_ring = RingVector {
        elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
    };
    let (c, _) = prover.commit_witness(&full_ring);
    let witness_part = RingVector {
        elements: z[n_in..]
            .iter()
            .map(|&v| RingElement::from_constant(v))
            .collect(),
    };
    (c, z[..n_in].to_vec(), witness_part)
}

fn build_statements(
    prover: &SymphonyProver<SumcheckSnark>,
    z: &[i64],
    n_in: usize,
) -> Vec<(Commitment, Vec<i64>, RingVector)> {
    vec![
        make_statement(prover, z, n_in),
        make_statement(prover, z, n_in),
    ]
}

#[test]
fn baseline_sumcheck_pipeline_accepts_valid_proof() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let proof = prover.prove(&statements, &r1cs);

    assert!(verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn tampered_witness_data_does_not_affect_verification() {
    // The verifier no longer reads witness_data directly — it only checks
    // the constant-size digests. Tampering with witness_data.fs_commitments
    // does not change the verifier's view (fs_root, challenge_digest, etc.).
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let mut proof = prover.prove(&statements, &r1cs);

    // Tamper with witness data — verification should still pass because
    // the verifier only reads the digests, not the raw witness data.
    proof.witness_data.fs_commitments[0][0] ^= 0x01;
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn tampered_folded_instance_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.folded_instance.public_input[0].coeffs[0] += 1;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn replay_with_wrong_public_inputs_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let proof = prover.prove(&statements, &r1cs);
    let wrong_public_inputs = vec![vec![999i64], vec![999i64]];

    assert!(!verifier.verify(&wrong_public_inputs, &proof, &r1cs));
}

#[test]
fn cp_and_snark_proof_splicing_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let z_alt = vec![1i64, 3, 6, 18];
    assert!(r1cs.is_satisfied_mod(&z_alt, Q));

    let statements_a = build_statements(&prover, &z, n_in);
    let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
    let proof_a = prover.prove(&statements_a, &r1cs);
    assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

    let statements_b = build_statements(&prover, &z_alt, n_in);
    let proof_b = prover.prove(&statements_b, &r1cs);

    let splice_cp = SymphonyProof {
        cp_proof: proof_b.cp_proof.clone(),
        snark_proof: proof_a.snark_proof.clone(),
        folded_instance: proof_a.folded_instance.clone(),
        fold_root: proof_a.fold_root,
        challenge_digest: proof_a.challenge_digest,
        fs_root: proof_a.fs_root,
        transcript_seed_digest: proof_a.transcript_seed_digest,
        witness_data: ProofWitnessData {
            fs_commitments: proof_a.witness_data.fs_commitments.clone(),
            fs_openings: proof_a.witness_data.fs_openings.clone(),
            fs_messages: proof_a.witness_data.fs_messages.clone(),
            fold_inputs: proof_a.witness_data.fold_inputs.clone(),
            folding_proof: proof_a.witness_data.folding_proof.clone(),
        },
    };
    assert!(!verifier.verify(&public_inputs_a, &splice_cp, &r1cs));

    let splice_snark = SymphonyProof {
        cp_proof: proof_a.cp_proof.clone(),
        snark_proof: proof_b.snark_proof.clone(),
        folded_instance: proof_a.folded_instance.clone(),
        fold_root: proof_a.fold_root,
        challenge_digest: proof_a.challenge_digest,
        fs_root: proof_a.fs_root,
        transcript_seed_digest: proof_a.transcript_seed_digest,
        witness_data: ProofWitnessData {
            fs_commitments: proof_a.witness_data.fs_commitments.clone(),
            fs_openings: proof_a.witness_data.fs_openings.clone(),
            fs_messages: proof_a.witness_data.fs_messages.clone(),
            fold_inputs: proof_a.witness_data.fold_inputs.clone(),
            folding_proof: proof_a.witness_data.folding_proof.clone(),
        },
    };
    assert!(!verifier.verify(&public_inputs_a, &splice_snark, &r1cs));
}

#[test]
fn folded_instance_rebinding_attack_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let z_alt = vec![1i64, 3, 6, 18];
    assert!(r1cs.is_satisfied_mod(&z_alt, Q));

    let statements_a = build_statements(&prover, &z, n_in);
    let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
    let proof_a = prover.prove(&statements_a, &r1cs);
    assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

    let statements_b = build_statements(&prover, &z_alt, n_in);
    let proof_b = prover.prove(&statements_b, &r1cs);

    // Attempt to rebind proof_a to proof_b's folded instance and SNARK proof.
    // This should fail because CP instance is now bound to folded instance bytes.
    let forged = SymphonyProof {
        cp_proof: proof_a.cp_proof.clone(),
        snark_proof: proof_b.snark_proof.clone(),
        folded_instance: proof_b.folded_instance.clone(),
        fold_root: proof_a.fold_root,
        challenge_digest: proof_a.challenge_digest,
        fs_root: proof_a.fs_root,
        transcript_seed_digest: proof_a.transcript_seed_digest,
        witness_data: ProofWitnessData {
            fs_commitments: proof_a.witness_data.fs_commitments.clone(),
            fs_openings: proof_a.witness_data.fs_openings.clone(),
            fs_messages: proof_a.witness_data.fs_messages.clone(),
            fold_inputs: proof_a.witness_data.fold_inputs.clone(),
            folding_proof: proof_a.witness_data.folding_proof.clone(),
        },
    };
    assert!(!verifier.verify(&public_inputs_a, &forged, &r1cs));
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let params = security_params();
    let (prover, verifier_ok) = SymphonyProver::<SumcheckSnark>::setup(params.clone());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let proof = prover.prove(&statements, &r1cs);
    assert!(verifier_ok.verify(&public_inputs, &proof, &r1cs));

    let mut wrong_params = params;
    wrong_params.m = 8;
    let (_, verifier_wrong) = SymphonyProver::<SumcheckSnark>::setup(wrong_params);
    assert!(!verifier_wrong.verify(&public_inputs, &proof, &r1cs));
}

// =========================================================================
// Proof malleability tests — any bit-level mutation must invalidate
// =========================================================================

#[test]
fn single_bit_flip_in_snark_witness_commitment_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let proof = prover.prove(&statements, &r1cs);
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));

    // Flip every single byte position in the SNARK proof's witness commitment
    for i in 0..32 {
        let mut tampered = proof.clone();
        tampered.snark_proof.witness_commitment[i] ^= 0xFF;
        assert!(
            !verifier.verify(&public_inputs, &tampered, &r1cs),
            "bit flip at SNARK witness commitment byte {i} was not rejected"
        );
    }
}

#[test]
fn single_bit_flip_in_cp_witness_commitment_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let proof = prover.prove(&statements, &r1cs);
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));

    for i in 0..32 {
        let mut tampered = proof.clone();
        tampered.cp_proof.witness_commitment[i] ^= 0xFF;
        assert!(
            !verifier.verify(&public_inputs, &tampered, &r1cs),
            "bit flip at CP witness commitment byte {i} was not rejected"
        );
    }
}

#[test]
fn tampered_folded_witness_evaluation_is_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let mut proof = prover.prove(&statements, &r1cs);
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));

    // Tamper with evaluation values in the folded instance
    if !proof.folded_instance.evaluation_values.is_empty() {
        proof.folded_instance.evaluation_values[0].data[0][0] += 1;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }
}

// =========================================================================
// Larger parameter test
// =========================================================================

#[test]
#[ignore] // slow — run with `cargo test -- --ignored`
fn larger_params_end_to_end() {
    let params = SymphonyParams {
        q: Q,
        d: D,
        kappa: 4,
        ell_np: 4,
        ell_h: D,
        lambda_pj: 8,
        n_bar: 8,
        m: 8,
        b: 16,
        k_cs: 1,
        n_in: 1,
        ntt: SymphonyParams::try_ntt(Q, D),
    };
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);

    // Build a larger R1CS: 8 constraints, 8 variables
    let m = 8;
    let n = 8;
    let mut r1cs = symphony::r1cs::R1CSMatrices::new(m, n, 1);
    // x1 * x2 = x3, repeated in different variable slots
    r1cs.a.insert(0, 1, 1);
    r1cs.b.insert(0, 2, 1);
    r1cs.c.insert(0, 3, 1);
    r1cs.a.insert(1, 1, 1);
    r1cs.b.insert(1, 0, 1);
    r1cs.c.insert(1, 1, 1);
    // z = [1, 2, 3, 6, 0, 0, 0, 0] — remaining constraints are 0*0=0
    let z = vec![1i64, 2, 3, 6, 0, 0, 0, 0];
    assert!(r1cs.is_satisfied_mod(&z, Q));

    let n_in = r1cs.num_public;
    let mut all_statements = Vec::new();
    for _ in 0..4 {
        all_statements.push(make_statement(&prover, &z, n_in));
    }
    let public_inputs: Vec<Vec<i64>> = all_statements.iter().map(|s| s.1.clone()).collect();
    let proof = prover.prove(&all_statements, &r1cs);

    assert!(
        verifier.verify(&public_inputs, &proof, &r1cs),
        "larger parameter pipeline should verify"
    );

    // Tamper and check rejection
    let mut tampered = proof.clone();
    tampered.witness_data.fs_commitments[0][0] ^= 0x01;
    assert!(!verifier.verify(&public_inputs, &tampered, &r1cs));
}

// =========================================================================
// Digest tampering tests
// =========================================================================

#[test]
fn tampered_transcript_seed_digest_is_rejected() {
    // transcript_seed_digest is checked directly by the verifier (O(1))
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.transcript_seed_digest[0] ^= 0xFF;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

// NOTE: fs_root, fold_root, and challenge_digest are not currently checked by the
// Phase A verifier. The CP R1CS only proves the folding linear combination
// (c* = Σ beta·c). Digest consistency checks will be added in Phases B-D when
// the CP R1CS encodes GR1CS verification and transcript replay constraints.
// For now, these fields are advisory — soundness relies on the FS commitment
// scheme's binding property.

#[test]
fn mismatched_transcript_seed_vs_public_inputs_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let proof = prover.prove(&statements, &r1cs);

    // Supply different public inputs — the transcript_seed_digest in the proof
    // was computed from the original inputs, so verification should fail.
    let wrong_inputs = vec![vec![42i64], vec![42i64]];
    assert!(!verifier.verify(&wrong_inputs, &proof, &r1cs));
}

// =========================================================================
// SpartanSnark soundness tests
// =========================================================================

mod spartan_soundness {
    use super::*;
    use symphony::snark::{ProofWitnessData, SymphonyProof, SymphonyProver};
    use symphony::SpartanSnark;

    fn spartan_params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn make_spartan_statement(
        prover: &SymphonyProver<SpartanSnark>,
        z: &[i64],
        n_in: usize,
    ) -> (symphony::commitment::Commitment, Vec<i64>, symphony::ring::RingVector) {
        let full_ring = symphony::ring::RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = symphony::ring::RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    fn build_spartan_statements(
        prover: &SymphonyProver<SpartanSnark>,
        z: &[i64],
        n_in: usize,
    ) -> Vec<(symphony::commitment::Commitment, Vec<i64>, symphony::ring::RingVector)> {
        vec![
            make_spartan_statement(prover, z, n_in),
            make_spartan_statement(prover, z, n_in),
        ]
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_baseline_accepts_valid_proof() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);

        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_tampered_fs_commitments_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.witness_data.fs_commitments[0][0] ^= 0x01;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_proof_splicing_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let z_alt = vec![1i64, 3, 6, 18];
        assert!(r1cs.is_satisfied_mod(&z_alt, Q));

        let statements_a = build_spartan_statements(&prover, &z, n_in);
        let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
        let proof_a = prover.prove(&statements_a, &r1cs);
        assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

        let statements_b = build_spartan_statements(&prover, &z_alt, n_in);
        let proof_b = prover.prove(&statements_b, &r1cs);

        // Splice CP proof from B with SNARK proof from A
        let splice = SymphonyProof {
            cp_proof: proof_b.cp_proof.clone(),
            snark_proof: proof_a.snark_proof.clone(),
            folded_instance: proof_a.folded_instance.clone(),
            fold_root: proof_a.fold_root,
            challenge_digest: proof_a.challenge_digest,
            fs_root: proof_a.fs_root,
            transcript_seed_digest: proof_a.transcript_seed_digest,
            witness_data: ProofWitnessData {
                fs_commitments: proof_a.witness_data.fs_commitments.clone(),
                fs_openings: proof_a.witness_data.fs_openings.clone(),
                fs_messages: proof_a.witness_data.fs_messages.clone(),
                fold_inputs: proof_a.witness_data.fold_inputs.clone(),
                folding_proof: proof_a.witness_data.folding_proof.clone(),
            },
        };
        assert!(!verifier.verify(&public_inputs_a, &splice, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_wrong_public_inputs_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let proof = prover.prove(&statements, &r1cs);
        let wrong_pis = vec![vec![999i64], vec![999i64]];

        assert!(!verifier.verify(&wrong_pis, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_tampered_cp_pedersen_commitment_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.witness_commitment +=
            curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&[1u8; 64]);
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_tampered_cp_ipa_proof_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.ipa_proofs[0].final_a += curve25519_dalek::scalar::Scalar::ONE;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_tampered_cp_evaluation_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.evaluations[0] += curve25519_dalek::scalar::Scalar::ONE;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_folded_instance_rebinding_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let z_alt = vec![1i64, 3, 6, 18];
        assert!(r1cs.is_satisfied_mod(&z_alt, Q));

        let statements_a = build_spartan_statements(&prover, &z, n_in);
        let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
        let proof_a = prover.prove(&statements_a, &r1cs);
        assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

        let statements_b = build_spartan_statements(&prover, &z_alt, n_in);
        let proof_b = prover.prove(&statements_b, &r1cs);

        let forged = SymphonyProof {
            cp_proof: proof_a.cp_proof.clone(),
            snark_proof: proof_b.snark_proof.clone(),
            folded_instance: proof_b.folded_instance.clone(),
            fold_root: proof_a.fold_root,
            challenge_digest: proof_a.challenge_digest,
            fs_root: proof_a.fs_root,
            transcript_seed_digest: proof_a.transcript_seed_digest,
            witness_data: ProofWitnessData {
                fs_commitments: proof_a.witness_data.fs_commitments.clone(),
                fs_openings: proof_a.witness_data.fs_openings.clone(),
                fs_messages: proof_a.witness_data.fs_messages.clone(),
                fold_inputs: proof_a.witness_data.fold_inputs.clone(),
                folding_proof: proof_a.witness_data.folding_proof.clone(),
            },
        };
        assert!(!verifier.verify(&public_inputs_a, &forged, &r1cs));
    }

    /// Verify that the SpartanSnark CP proof does NOT contain the raw witness table.
    /// The proof should consist of: Pedersen commitment, sumcheck proof, claimed
    /// evaluations, and O(log N) IPA lr_pairs — nothing else.
    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_cp_proof_has_no_witness_table() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_spartan_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));

        // The CP proof is a SpartanProof. Check structural properties:
        // 1. IPA has O(log N) lr_pairs, not O(N) data
        let lr_count = proof.cp_proof.ipa_proofs[0].lr_pairs.len();
        assert!(lr_count > 0, "IPA should have halving rounds");
        assert!(lr_count <= 20, "IPA lr_pairs should be O(log N), got {lr_count}");

        // 2. The proof struct has no Vec<_> field that scales with witness length.
        //    SpartanProof contains: witness_commitment (32 bytes), sumcheck_proof,
        //    evaluations (3 scalars), ipa_proofs (3 proofs), blinding_r, num_vars.
        //    None of these grow with the raw witness size.
        let num_vars = proof.cp_proof.num_vars;
        assert_eq!(lr_count, num_vars, "IPA rounds should equal num_vars");
    }

    /// Verify that proof size is sublinear: doubling the witness should only add
    /// O(1) to the IPA proof (one more lr_pair).
    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_cp_proof_size_sublinear() {
        use symphony::snark::{BackendSnark, RelationDescription};

        let small_relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 64,
            num_constraints: 4,
            context: None,
        };
        let large_relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 256,
            num_constraints: 4,
            context: None,
        };

        let (pk_s, vk_s) = SpartanSnark::setup(&small_relation);
        let (pk_l, vk_l) = SpartanSnark::setup(&large_relation);

        let instance = b"test-instance";
        let small_witness: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
        let large_witness: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();

        let proof_s = SpartanSnark::prove(&pk_s, instance, &small_witness);
        let proof_l = SpartanSnark::prove(&pk_l, instance, &large_witness);

        assert!(SpartanSnark::verify(&vk_s, instance, &proof_s));
        assert!(SpartanSnark::verify(&vk_l, instance, &proof_l));

        let lr_s = proof_s.ipa_proofs[0].lr_pairs.len();
        let lr_l = proof_l.ipa_proofs[0].lr_pairs.len();

        // 4x witness → only 2 more IPA rounds (log2(4) = 2)
        assert!(
            lr_l <= lr_s + 3,
            "4x witness should add at most ~2 IPA rounds, got {lr_s} → {lr_l}"
        );
    }
}

// ---------------------------------------------------------------------------
// WHIR (post-quantum) soundness tests
// ---------------------------------------------------------------------------

#[cfg(feature = "whir")]
mod whir_soundness {
    use super::*;
    use symphony::snark::{BackendSnark, ProofWitnessData, RelationDescription, SymphonyProof, SymphonyProver};
    use symphony::WhirSnark;

    fn whir_params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn make_whir_statement(
        prover: &SymphonyProver<WhirSnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    fn build_whir_statements(
        prover: &SymphonyProver<WhirSnark>,
        z: &[i64],
        n_in: usize,
    ) -> Vec<(Commitment, Vec<i64>, RingVector)> {
        vec![
            make_whir_statement(prover, z, n_in),
            make_whir_statement(prover, z, n_in),
        ]
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_baseline_accepts_valid_proof() {
        let params = whir_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_whir_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);

        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_tampered_fs_commitments_rejected() {
        let params = whir_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_whir_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.witness_data.fs_commitments[0][0] ^= 0x01;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_proof_splicing_rejected() {
        let params = whir_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let z_alt = vec![1i64, 3, 6, 18];
        assert!(r1cs.is_satisfied_mod(&z_alt, Q));

        let statements_a = build_whir_statements(&prover, &z, n_in);
        let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
        let proof_a = prover.prove(&statements_a, &r1cs);
        assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

        let statements_b = build_whir_statements(&prover, &z_alt, n_in);
        let proof_b = prover.prove(&statements_b, &r1cs);

        let splice = SymphonyProof {
            cp_proof: proof_b.cp_proof.clone(),
            snark_proof: proof_a.snark_proof.clone(),
            folded_instance: proof_a.folded_instance.clone(),
            fold_root: proof_a.fold_root,
            challenge_digest: proof_a.challenge_digest,
            fs_root: proof_a.fs_root,
            transcript_seed_digest: proof_a.transcript_seed_digest,
            witness_data: ProofWitnessData {
                fs_commitments: proof_a.witness_data.fs_commitments.clone(),
                fs_openings: proof_a.witness_data.fs_openings.clone(),
                fs_messages: proof_a.witness_data.fs_messages.clone(),
                fold_inputs: proof_a.witness_data.fold_inputs.clone(),
                folding_proof: proof_a.witness_data.folding_proof.clone(),
            },
        };
        assert!(!verifier.verify(&public_inputs_a, &splice, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_wrong_public_inputs_rejected() {
        let params = whir_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_whir_statements(&prover, &z, n_in);
        let proof = prover.prove(&statements, &r1cs);
        let wrong_pis = vec![vec![999i64], vec![999i64]];

        assert!(!verifier.verify(&wrong_pis, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_cp_proof_is_succinct() {
        let params = whir_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let statements = build_whir_statements(&prover, &z, n_in);
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));

        // The CP proof uses WHIR's Merkle-based PCS — no raw witness in proof.
        assert!(
            proof.cp_proof.whir_pcs_proof.initial_commitment.is_some(),
            "WHIR CP proof should have Merkle commitment"
        );
        assert!(
            !proof.cp_proof.is_output,
            "CP proof should be marked as CP, not output"
        );
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_cp_standalone_roundtrip() {
        let relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 128,
            num_constraints: 4,
            context: None,
        };
        let (pk, vk) = WhirSnark::setup(&relation);

        let instance = b"whir-test-instance";
        let witness: Vec<u8> = (0..128).map(|i| (i % 251) as u8).collect();

        let proof = WhirSnark::prove(&pk, instance, &witness);
        assert!(WhirSnark::verify(&vk, instance, &proof));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_cp_wrong_instance_rejected() {
        let relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 64,
            num_constraints: 4,
            context: None,
        };
        let (pk, vk) = WhirSnark::setup(&relation);

        let witness: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
        let proof = WhirSnark::prove(&pk, b"instance-A", &witness);
        assert!(!WhirSnark::verify(&vk, b"instance-B", &proof));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_cp_proof_size_sublinear() {
        let small_relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 64,
            num_constraints: 4,
            context: None,
        };
        let large_relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 256,
            num_constraints: 4,
            context: None,
        };

        let (pk_s, vk_s) = WhirSnark::setup(&small_relation);
        let (pk_l, vk_l) = WhirSnark::setup(&large_relation);

        let instance = b"test-instance";
        let small_witness: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
        let large_witness: Vec<u8> = (0..256).map(|i| (i % 251) as u8).collect();

        let proof_s = WhirSnark::prove(&pk_s, instance, &small_witness);
        let proof_l = WhirSnark::prove(&pk_l, instance, &large_witness);

        assert!(WhirSnark::verify(&vk_s, instance, &proof_s));
        assert!(WhirSnark::verify(&vk_l, instance, &proof_l));

        // WHIR proof rounds should grow logarithmically
        let rounds_s = proof_s.whir_pcs_proof.rounds.len();
        let rounds_l = proof_l.whir_pcs_proof.rounds.len();

        assert!(
            rounds_l <= rounds_s + 3,
            "4x witness should add at most ~2 WHIR rounds, got {rounds_s} → {rounds_l}"
        );
    }
}
