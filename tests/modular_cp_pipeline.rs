mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::cp_relation_core::{CpRelation, CpRelationError};
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::{ProofBundle, Prover, Verifier};
use symphony::ring::{RingElement, RingVector};
use symphony::snark::DummySnark;
use symphony::SumcheckSnark;

fn modular_params() -> SymphonyParams {
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

fn make_statement<
    CPB: symphony::cp_backend_api::CpBackend,
    OB: symphony::output_backend_api::OutputBackend,
>(
    prover: &Prover<CPB, OB>,
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

fn run_roundtrip<
    CPB: symphony::cp_backend_api::CpBackend,
    OB: symphony::output_backend_api::OutputBackend,
>()
where
    CPB::Proof: Clone,
    OB::Proof: Clone,
{
    let params = modular_params();
    let (prover, verifier): (Prover<CPB, OB>, Verifier<CPB, OB>) = Prover::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let s1 = make_statement(&prover, &z, n_in);
    let s2 = make_statement(&prover, &z, n_in);
    let statements = vec![s1, s2];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let proof = prover.prove(&statements, &r1cs);
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn split_backend_roundtrip_cp_sumcheck_output_dummy() {
    run_roundtrip::<SumcheckSnark, DummySnark>();
}

#[test]
fn split_backend_roundtrip_cp_dummy_output_sumcheck() {
    run_roundtrip::<DummySnark, SumcheckSnark>();
}

#[test]
fn modular_cp_public_digest_tampering_rejected() {
    let params = modular_params();
    let (prover, verifier): (
        Prover<SumcheckSnark, DummySnark>,
        Verifier<SumcheckSnark, DummySnark>,
    ) = Prover::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let s1 = make_statement(&prover, &z, n_in);
    let s2 = make_statement(&prover, &z, n_in);
    let statements = vec![s1, s2];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.cp_public_instance.fs_root[0] ^= 0x01;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn cp_relation_check_detects_tampering() {
    let params = modular_params();
    let (prover, _verifier): (
        Prover<SumcheckSnark, DummySnark>,
        Verifier<SumcheckSnark, DummySnark>,
    ) = Prover::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let s1 = make_statement(&prover, &z, n_in);
    let s2 = make_statement(&prover, &z, n_in);
    let statements = vec![s1, s2];

    let mut proof = prover.prove(&statements, &r1cs);
    assert!(CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle).is_ok());

    proof.witness_bundle.fs_commitments[0][0] ^= 0x01;
    assert!(CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle).is_err());
}

// =========================================================================
// Security / soundness tests ported from security_soundness.rs
// =========================================================================

fn build_modular_proof() -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    Verifier<SumcheckSnark, SumcheckSnark>,
    Vec<(Commitment, Vec<i64>, RingVector)>,
    Vec<Vec<i64>>,
    symphony::r1cs::R1CSMatrices,
) {
    let params = modular_params();
    let (prover, verifier): (
        Prover<SumcheckSnark, SumcheckSnark>,
        Verifier<SumcheckSnark, SumcheckSnark>,
    ) = Prover::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let s1 = make_statement(&prover, &z, n_in);
    let s2 = make_statement(&prover, &z, n_in);
    let statements = vec![s1, s2];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    (prover, verifier, statements, public_inputs, r1cs)
}

#[test]
fn modular_witness_tampering_does_not_affect_verification() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    // Tamper with witness_bundle — verifier only checks digests, not raw witness data
    proof.witness_bundle.fs_commitments[0][0] ^= 0x01;
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn modular_replay_with_wrong_public_inputs_rejected() {
    let (prover, verifier, statements, _public_inputs, r1cs) = build_modular_proof();
    let proof = prover.prove(&statements, &r1cs);

    let wrong_inputs = vec![vec![999i64], vec![999i64]];
    assert!(!verifier.verify(&wrong_inputs, &proof, &r1cs));
}

#[test]
fn modular_proof_splicing_cp_from_different_statement_rejected() {
    let params = modular_params();
    let (prover, verifier): (
        Prover<SumcheckSnark, SumcheckSnark>,
        Verifier<SumcheckSnark, SumcheckSnark>,
    ) = Prover::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let z_alt = vec![1i64, 3, 6, 18];
    assert!(r1cs.is_satisfied_mod(&z_alt, Q));

    let s_a = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let pi_a: Vec<Vec<i64>> = s_a.iter().map(|s| s.1.clone()).collect();
    let proof_a = prover.prove(&s_a, &r1cs);
    assert!(verifier.verify(&pi_a, &proof_a, &r1cs));

    let s_b = vec![
        make_statement(&prover, &z_alt, n_in),
        make_statement(&prover, &z_alt, n_in),
    ];
    let proof_b = prover.prove(&s_b, &r1cs);

    // Splice: cp_proof from B, everything else from A
    let spliced = ProofBundle {
        cp_proof: proof_b.cp_proof.clone(),
        output_proof: proof_a.output_proof.clone(),
        cp_public_instance: proof_a.cp_public_instance.clone(),
        witness_bundle: proof_a.witness_bundle.clone(),
    };
    assert!(!verifier.verify(&pi_a, &spliced, &r1cs));

    // Splice: output_proof from B, everything else from A
    let spliced_output = ProofBundle {
        cp_proof: proof_a.cp_proof.clone(),
        output_proof: proof_b.output_proof.clone(),
        cp_public_instance: proof_a.cp_public_instance.clone(),
        witness_bundle: proof_a.witness_bundle.clone(),
    };
    assert!(!verifier.verify(&pi_a, &spliced_output, &r1cs));
}

#[test]
fn modular_fold_root_tampering_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.fold_root[0] ^= 0xFF;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn modular_challenge_digest_tampering_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.challenge_digest[0] ^= 0xFF;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn modular_transcript_seed_digest_tampering_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.transcript_seed_digest[0] ^= 0xFF;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn modular_folded_instance_tampering_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.x_folded.public_input[0].coeffs[0] += 1;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

// =========================================================================
// CpRelation::check — exhaustive error variant coverage
// =========================================================================

#[test]
fn cp_relation_fold_root_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);
    assert!(CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle).is_ok());

    proof.witness_bundle.fold_inputs[0].public_input[0] += 999;
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::FoldRootMismatch)
    );
}

#[test]
fn cp_relation_challenge_digest_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    // Corrupt transcript bytes so challenge derivation changes
    proof.witness_bundle.transcript_bytes.push(0xFF);
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::TranscriptParse)
    );
}

#[test]
fn cp_relation_length_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.witness_bundle.fs_openings.pop();
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::LengthMismatch)
    );
}

#[test]
fn cp_relation_folded_output_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.witness_bundle.folded_output.public_input[0].coeffs[0] += 1;
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::FoldedOutputMismatch)
    );
}

// =========================================================================
// WHIR backend through modular orchestrator
// =========================================================================

#[cfg(feature = "whir")]
mod whir_modular {
    use super::*;
    use symphony::WhirSnark;

    #[test]
    #[ignore] // slow — run with `cargo test --features whir -- --ignored`
    fn whir_homogeneous_roundtrip() {
        run_roundtrip::<WhirSnark, WhirSnark>();
    }

    #[test]
    #[ignore] // slow
    fn whir_cp_sumcheck_output_roundtrip() {
        run_roundtrip::<WhirSnark, SumcheckSnark>();
    }

    #[test]
    #[ignore] // slow
    fn whir_digest_tampering_rejected() {
        let params = modular_params();
        let (prover, verifier): (Prover<WhirSnark, WhirSnark>, Verifier<WhirSnark, WhirSnark>) =
            Prover::setup(params);
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let statements = vec![s1, s2];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

        let mut proof = prover.prove(&statements, &r1cs);
        proof.cp_public_instance.fs_root[0] ^= 0x01;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }
}
