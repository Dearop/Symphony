//! Regression tests for soundness fixes.

mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::cp_snark::{CPProof, CPSnark, IdentityRelation};
use symphony::fiat_shamir::hash_commitment::HashCommitment;
use symphony::fiat_shamir::transcript::Transcript;
use symphony::fiat_shamir::FSCommitment;
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::Prover as ModularProver;
use symphony::ring::{RingElement, RingVector};
use symphony::snark::{BackendSnark, SymphonyProver};
use symphony::SumcheckSnark;

fn params() -> SymphonyParams {
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

fn make_modular_statement(
    prover: &ModularProver<SumcheckSnark, SumcheckSnark>,
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

fn encode_standalone_cp_instance(
    commitments: &[[u8; 32]],
    public_statement: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut transcript = Transcript::new(b"cp-snark-standalone-v1");
    transcript.append_bytes(b"num-messages", &(commitments.len() as u64).to_le_bytes());
    for c in commitments {
        transcript.append_commitment(b"commitment", c);
    }
    transcript.append_bytes(b"public-statement", public_statement);

    let mut instance = Vec::new();
    instance.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
    for c in commitments {
        instance.extend_from_slice(&(c.len() as u64).to_le_bytes());
        instance.extend_from_slice(c);
    }
    instance.extend_from_slice(&(public_statement.len() as u64).to_le_bytes());
    instance.extend_from_slice(public_statement);

    let mut bind = [0u8; 32];
    transcript.challenge_bytes(b"cp-bind", &mut bind);
    instance.extend_from_slice(&bind);

    let mut digest = [0u8; 32];
    transcript.challenge_bytes(b"proof-digest", &mut digest);
    (instance, digest.to_vec())
}

#[test]
fn standalone_cp_manual_forgery_with_bad_opening_is_rejected() {
    let scheme = HashCommitment::new();
    let cp = CPSnark::<SumcheckSnark, HashCommitment>::setup(1, 64);
    let (commitment, _opening) = scheme.commit(b"real-secret");

    let (instance, transcript_digest) = encode_standalone_cp_instance(&[commitment], b"");
    let bogus_backend_proof = SumcheckSnark::prove(cp.proving_key(), &instance, b"bogus-witness");

    let forged = CPProof::<SumcheckSnark, HashCommitment> {
        backend_proof: bogus_backend_proof,
        transcript_digest,
        revealed_messages: vec![b"real-secret".to_vec()],
        revealed_openings: vec![[0u8; 32]],
    };

    assert!(!cp.verify(&scheme, &[commitment], b"", &IdentityRelation, &forged,));
}

#[test]
fn legacy_original_witness_tampering_is_rejected() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_data.original_witnesses[0].elements[0].coeffs[0] += 1;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn legacy_transcript_bytes_tampering_is_rejected_even_with_cp_relation_shortcuts() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_data.transcript_bytes.push(0xFF);

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn v2_legacy_orchestrator_drops_witness_data_and_fails_closed() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let proof = prover.prove_v2(&statements, &r1cs);

    assert!(!proof.fs_commitments.is_empty());
    assert_eq!(
        proof.fs_root,
        symphony::folding::digest::digest_fs_commitments(&proof.fs_commitments)
    );
    assert!(
        !verifier.verify_v2(&public_inputs, &proof, &r1cs),
        "v2 must fail closed until the backend advertises authoritative typed CP/output"
    );
}

#[test]
fn modular_original_witness_tampering_is_rejected() {
    let (prover, verifier): (
        ModularProver<SumcheckSnark, SumcheckSnark>,
        symphony::proof_orchestrator::Verifier<SumcheckSnark, SumcheckSnark>,
    ) = ModularProver::<SumcheckSnark, SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_modular_statement(&prover, &z, n_in),
        make_modular_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_bundle.original_witnesses[0].elements[0].coeffs[0] += 1;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn v2_modular_orchestrator_drops_witness_bundle_and_fails_closed() {
    let (prover, verifier): (
        ModularProver<SumcheckSnark, SumcheckSnark>,
        symphony::proof_orchestrator::Verifier<SumcheckSnark, SumcheckSnark>,
    ) = ModularProver::<SumcheckSnark, SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_modular_statement(&prover, &z, n_in),
        make_modular_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let proof = prover.prove_v2(&statements, &r1cs);

    assert!(!proof.fs_commitments.is_empty());
    assert_eq!(
        proof.fs_root,
        symphony::digest_core::digest_fs_root(&proof.fs_commitments)
    );
    assert!(
        !verifier.verify_v2(&public_inputs, &proof, &r1cs),
        "v2 must fail closed without authoritative typed CP/output backends"
    );
}

#[test]
fn legacy_public_input_opening_mismatch_is_rejected() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_data.original_witnesses[0].elements[0].coeffs[0] = 999;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn legacy_folded_witness_tampering_is_rejected() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_data.folded_witness.witness.elements[0].coeffs[0] += 1;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn legacy_folded_evaluation_tampering_is_rejected() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.folded_instance.evaluation_values[0].data[0][0] += 1;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn legacy_folded_commitment_tampering_is_rejected() {
    let (prover, verifier): (
        SymphonyProver<SumcheckSnark>,
        symphony::SymphonyVerifier<SumcheckSnark>,
    ) = SymphonyProver::<SumcheckSnark>::setup(params());
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let mut proof = prover.prove(&statements, &r1cs);
    proof.folded_instance.commitment.value.elements[0].coeffs[0] += 1;

    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
}

#[test]
fn spartan_backend_specific_context_serialization_roundtrips() {
    use symphony::snark::spartan::{serialize, SpartanSnark};

    let (r1cs, _) = common::multi_r1cs();
    let out = SpartanSnark::serialize_output_context(&r1cs, Q, D).expect("spartan output context");
    let cp = SpartanSnark::serialize_cp_context(&r1cs, Q, D).expect("spartan cp context");

    let out_ctx = serialize::deserialize_context(&out).expect("must parse output context");
    let cp_ctx = serialize::deserialize_context(&cp).expect("must parse cp context");

    assert!(out_ctx.is_output_snark);
    assert!(!cp_ctx.is_output_snark);
    assert_eq!(out_ctx.r1cs.num_constraints, r1cs.num_constraints);
    assert_eq!(cp_ctx.r1cs.num_constraints, r1cs.num_constraints);
}

#[cfg(feature = "whir")]
#[test]
fn whir_backend_specific_context_serialization_roundtrips() {
    use symphony::snark::whir::{serialize, WhirSnark};

    let (r1cs, _) = common::multi_r1cs();
    let out = WhirSnark::serialize_output_context(&r1cs, Q, D).expect("whir output context");
    let cp = WhirSnark::serialize_cp_context(&r1cs, Q, D).expect("whir cp context");

    let out_ctx = serialize::deserialize_context(&out).expect("must parse output context");
    let cp_ctx = serialize::deserialize_context(&cp).expect("must parse cp context");

    assert!(out_ctx.is_output_snark);
    assert!(!out_ctx.is_cp_snark);
    assert!(!cp_ctx.is_output_snark);
    assert!(cp_ctx.is_cp_snark);
    assert_eq!(out_ctx.r1cs.num_constraints, r1cs.num_constraints);
    assert_eq!(cp_ctx.r1cs.num_constraints, r1cs.num_constraints);
}
