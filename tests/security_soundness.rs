//! Security-oriented soundness tests for the modular Symphony pipeline.

mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::Prover;
use symphony::ring::{RingElement, RingVector};
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
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
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

fn build_sumcheck_fixture() -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    symphony::proof_orchestrator::Verifier<SumcheckSnark, SumcheckSnark>,
    Vec<(Commitment, Vec<i64>, RingVector)>,
    Vec<Vec<i64>>,
    symphony::r1cs::R1CSMatrices,
) {
    let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(security_params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    (prover, verifier, statements, public_inputs, r1cs)
}

#[test]
fn baseline_sumcheck_pipeline_accepts_valid_proof() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_sumcheck_fixture();
    let proof = prover.prove(&statements, &r1cs);

    assert!(verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn tampered_witness_bundle_does_not_affect_verification() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_sumcheck_fixture();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.witness_bundle.fs_commitments[0][0] ^= 0x01;
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn tampered_folded_instance_is_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_sumcheck_fixture();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.x_folded.public_input[0].coeffs[0] += 1;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn replay_with_wrong_public_inputs_is_rejected() {
    let (prover, verifier, statements, _public_inputs, r1cs) = build_sumcheck_fixture();
    let proof = prover.prove(&statements, &r1cs);

    let wrong_public_inputs = vec![vec![999i64], vec![999i64]];
    assert!(!verifier.verify(&wrong_public_inputs, &proof, &r1cs));
}

#[test]
fn cp_and_output_proof_splicing_is_rejected() {
    let params = security_params();
    let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let z_alt = vec![1i64, 3, 6, 18];
    assert!(r1cs.is_satisfied_mod(&z_alt, Q));

    let statements_a = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
    let proof_a = prover.prove(&statements_a, &r1cs);
    assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

    let statements_b = vec![
        make_statement(&prover, &z_alt, n_in),
        make_statement(&prover, &z_alt, n_in),
    ];
    let proof_b = prover.prove(&statements_b, &r1cs);

    let mut splice_cp = proof_a.clone();
    splice_cp.cp_proof = proof_b.cp_proof.clone();
    assert!(!verifier.verify(&public_inputs_a, &splice_cp, &r1cs));

    let mut splice_output = proof_a.clone();
    splice_output.output_proof = proof_b.output_proof.clone();
    assert!(!verifier.verify(&public_inputs_a, &splice_output, &r1cs));
}

#[test]
fn folded_instance_rebinding_attack_is_rejected() {
    let params = security_params();
    let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let z_alt = vec![1i64, 3, 6, 18];
    assert!(r1cs.is_satisfied_mod(&z_alt, Q));

    let statements_a = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
    let proof_a = prover.prove(&statements_a, &r1cs);
    assert!(verifier.verify(&public_inputs_a, &proof_a, &r1cs));

    let statements_b = vec![
        make_statement(&prover, &z_alt, n_in),
        make_statement(&prover, &z_alt, n_in),
    ];
    let proof_b = prover.prove(&statements_b, &r1cs);

    let mut forged = proof_a.clone();
    forged.output_proof = proof_b.output_proof.clone();
    forged.cp_public_instance.x_folded = proof_b.cp_public_instance.x_folded.clone();

    assert!(!verifier.verify(&public_inputs_a, &forged, &r1cs));
}

#[test]
fn wrong_verifying_key_is_rejected() {
    let params = security_params();
    let (prover, verifier_ok) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params.clone());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let proof = prover.prove(&statements, &r1cs);
    assert!(verifier_ok.verify(&public_inputs, &proof, &r1cs));

    let mut wrong_params = params;
    wrong_params.m = 8;
    let (_, verifier_wrong) = Prover::<SumcheckSnark, SumcheckSnark>::setup(wrong_params);
    assert!(!verifier_wrong.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn single_bit_flip_in_output_proof_is_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_sumcheck_fixture();
    let proof = prover.prove(&statements, &r1cs);
    assert!(verifier.verify(&public_inputs, &proof, &r1cs));

    for i in 0..32 {
        let mut tampered = proof.clone();
        tampered.output_proof.witness_commitment[i] ^= 0xFF;
        assert!(!verifier.verify(&public_inputs, &tampered, &r1cs));
    }
}

#[test]
fn tampered_transcript_seed_digest_is_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_sumcheck_fixture();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.transcript_seed_digest[0] ^= 0xFF;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

mod spartan_soundness {
    use super::*;
    use symphony::proof_orchestrator::Prover;
    use symphony::SpartanSnark;

    fn make_statement(
        prover: &Prover<SpartanSnark, SpartanSnark>,
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

    #[test]
    #[ignore]
    fn baseline_accepts_valid_proof() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(security_params());
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);

        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn tampered_cp_commitment_is_rejected() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(security_params());
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.witness_commitment +=
            curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&[1u8; 64]);
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn wrong_public_inputs_are_rejected() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(security_params());
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let proof = prover.prove(&statements, &r1cs);

        let wrong_public_inputs = vec![vec![999i64], vec![999i64]];
        assert!(!verifier.verify(&wrong_public_inputs, &proof, &r1cs));
    }
}

#[cfg(feature = "whir")]
mod whir_soundness {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use symphony::proof_orchestrator::Prover;
    use symphony::snark::whir::WhirSnark;

    fn make_statement(
        prover: &Prover<WhirSnark, WhirSnark>,
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

    #[test]
    #[ignore]
    fn baseline_accepts_valid_proof() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(security_params());
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);

        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn tampered_cp_eval_is_rejected() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(security_params());
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.z_eval += p3_baby_bear::BabyBear::ONE;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn wrong_public_inputs_are_rejected() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(security_params());
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let proof = prover.prove(&statements, &r1cs);

        let wrong_public_inputs = vec![vec![999i64], vec![999i64]];
        assert!(!verifier.verify(&wrong_public_inputs, &proof, &r1cs));
    }
}
