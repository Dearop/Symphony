//! Security-oriented soundness tests for the Symphony pipeline.
//!
//! These tests model common tampering/replay/splicing attacks and assert that
//! verification fails under the `SumcheckSnark` backend.

mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::params::{SymphonyParams, D};
use symphony::ring::{RingElement, RingVector};
use symphony::snark::{SymphonyProof, SymphonyProver};
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
fn tampered_fs_commitments_are_rejected() {
    let params = security_params();
    let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = build_statements(&prover, &z, n_in);
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.fs_commitments[0][0] ^= 0x01;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
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
        fs_commitments: proof_a.fs_commitments.clone(),
        folded_instance: proof_a.folded_instance.clone(),
    };
    assert!(!verifier.verify(&public_inputs_a, &splice_cp, &r1cs));

    let splice_snark = SymphonyProof {
        cp_proof: proof_a.cp_proof.clone(),
        snark_proof: proof_b.snark_proof.clone(),
        fs_commitments: proof_a.fs_commitments.clone(),
        folded_instance: proof_a.folded_instance.clone(),
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
        fs_commitments: proof_a.fs_commitments.clone(),
        folded_instance: proof_b.folded_instance.clone(),
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
