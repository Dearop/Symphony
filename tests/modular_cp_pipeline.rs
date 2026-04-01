mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::cp_relation_core::CpRelation;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::{Prover, Verifier};
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
