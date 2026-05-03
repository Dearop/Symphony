mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::cp_relation_core::{CpFieldRelation, CpPublicStatement, CpRelation, CpRelationError};
use symphony::digest_core::PublicDigestScheme;
use symphony::folding::{FoldedOutputInstance, FoldedOutputWitness};
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::{ProofBundle, Prover, Verifier};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};
use symphony::snark::{BackendSnark, DummySnark, RelationDescription};
use symphony::SumcheckSnark;

#[derive(Clone)]
struct NonAuthoritativeTypedOutputSnark;
#[derive(Clone)]
struct NonAuthoritativeTypedCpSnark;
#[derive(Clone)]
struct AuthoritativeTypedOutputSnark;

#[derive(Debug, Clone)]
struct NonAuthoritativeKey;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NonAuthoritativeProof {
    Legacy,
    Typed,
}

type AuthoritativeProof = NonAuthoritativeProof;

impl BackendSnark for NonAuthoritativeTypedOutputSnark {
    type ProvingKey = NonAuthoritativeKey;
    type VerifyingKey = NonAuthoritativeKey;
    type Proof = NonAuthoritativeProof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        let _ = relation;
        (NonAuthoritativeKey, NonAuthoritativeKey)
    }

    fn serialize_output_context(_r1cs: &R1CSMatrices, _q: u64, _d: usize) -> Option<Vec<u8>> {
        Some(b"non-authoritative-typed-output-test".to_vec())
    }

    fn prove(_pk: &Self::ProvingKey, _instance: &[u8], _witness: &[u8]) -> Self::Proof {
        NonAuthoritativeProof::Legacy
    }

    fn verify(_vk: &Self::VerifyingKey, _instance: &[u8], proof: &Self::Proof) -> bool {
        *proof == NonAuthoritativeProof::Legacy
    }

    fn prove_typed_output(
        _pk: &Self::ProvingKey,
        _instance: &FoldedOutputInstance,
        _witness: &FoldedOutputWitness,
    ) -> Option<Self::Proof> {
        Some(NonAuthoritativeProof::Typed)
    }

    fn verify_typed_output(
        _vk: &Self::VerifyingKey,
        _instance: &FoldedOutputInstance,
        _proof: &Self::Proof,
    ) -> Option<bool> {
        Some(false)
    }
}

impl BackendSnark for NonAuthoritativeTypedCpSnark {
    type ProvingKey = NonAuthoritativeKey;
    type VerifyingKey = NonAuthoritativeKey;
    type Proof = NonAuthoritativeProof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        let _ = relation;
        (NonAuthoritativeKey, NonAuthoritativeKey)
    }

    fn prove(_pk: &Self::ProvingKey, _instance: &[u8], _witness: &[u8]) -> Self::Proof {
        NonAuthoritativeProof::Legacy
    }

    fn verify(_vk: &Self::VerifyingKey, _instance: &[u8], proof: &Self::Proof) -> bool {
        *proof == NonAuthoritativeProof::Legacy
    }

    fn prove_typed_cp(
        _pk: &Self::ProvingKey,
        _statement: &CpPublicStatement,
        _witness: &symphony::cp_relation_core::CpWitnessBundle,
    ) -> Option<Self::Proof> {
        Some(NonAuthoritativeProof::Typed)
    }

    fn verify_typed_cp(
        _vk: &Self::VerifyingKey,
        _statement: &CpPublicStatement,
        _proof: &Self::Proof,
    ) -> Option<bool> {
        Some(false)
    }
}

impl BackendSnark for AuthoritativeTypedOutputSnark {
    type ProvingKey = NonAuthoritativeKey;
    type VerifyingKey = NonAuthoritativeKey;
    type Proof = AuthoritativeProof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        let _ = relation;
        (NonAuthoritativeKey, NonAuthoritativeKey)
    }

    fn serialize_output_context(_r1cs: &R1CSMatrices, _q: u64, _d: usize) -> Option<Vec<u8>> {
        Some(b"authoritative-typed-output-test".to_vec())
    }

    fn has_authoritative_typed_output() -> bool {
        true
    }

    fn prove(_pk: &Self::ProvingKey, _instance: &[u8], _witness: &[u8]) -> Self::Proof {
        AuthoritativeProof::Legacy
    }

    fn verify(_vk: &Self::VerifyingKey, _instance: &[u8], proof: &Self::Proof) -> bool {
        *proof == AuthoritativeProof::Legacy
    }

    fn prove_typed_output(
        _pk: &Self::ProvingKey,
        _instance: &FoldedOutputInstance,
        _witness: &FoldedOutputWitness,
    ) -> Option<Self::Proof> {
        Some(AuthoritativeProof::Typed)
    }

    fn verify_typed_output(
        _vk: &Self::VerifyingKey,
        _instance: &FoldedOutputInstance,
        proof: &Self::Proof,
    ) -> Option<bool> {
        Some(*proof == AuthoritativeProof::Typed)
    }
}

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
fn non_authoritative_typed_output_hook_is_not_selected() {
    run_roundtrip::<SumcheckSnark, NonAuthoritativeTypedOutputSnark>();
}

#[test]
fn non_authoritative_typed_cp_hook_is_not_selected() {
    run_roundtrip::<NonAuthoritativeTypedCpSnark, DummySnark>();
}

#[test]
fn verify_public_fails_closed_when_only_output_is_authoritative() {
    let params = modular_params();
    let (prover, verifier): (
        Prover<SumcheckSnark, AuthoritativeTypedOutputSnark>,
        Verifier<SumcheckSnark, AuthoritativeTypedOutputSnark>,
    ) = Prover::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let n_in = r1cs.num_public;

    let statements = vec![
        make_statement(&prover, &z, n_in),
        make_statement(&prover, &z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();

    let proof = prover.prove_public(&statements, &r1cs);
    assert!(proof.public_boundary_is_well_formed(&public_inputs, &r1cs));
    assert!(!verifier.verify_public(&public_inputs, &proof, &r1cs));
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

fn cp_field_statement(
    proof: &ProofBundle<SumcheckSnark, SumcheckSnark>,
    public_inputs: &[Vec<i64>],
    r1cs: &R1CSMatrices,
    digest_scheme: PublicDigestScheme,
) -> CpPublicStatement {
    CpPublicStatement::new(
        proof.cp_public_instance.clone(),
        public_inputs.to_vec(),
        r1cs,
        digest_scheme,
    )
}

#[test]
fn typed_cp_field_relation_accepts_valid_bundle() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let proof = prover.prove(&statements, &r1cs);
    let statement = cp_field_statement(&proof, &public_inputs, &r1cs, PublicDigestScheme::Sha256);

    assert!(CpFieldRelation::check(
        &statement,
        &proof.witness_bundle,
        &prover.ajtai,
        &r1cs,
        prover.params.b_input()
    )
    .is_ok());
}

#[test]
fn typed_cp_field_relation_rejects_bad_fs_opening() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_bundle.fs_openings[0][0] ^= 0x01;
    let statement = cp_field_statement(&proof, &public_inputs, &r1cs, PublicDigestScheme::Sha256);

    assert_eq!(
        CpFieldRelation::check(
            &statement,
            &proof.witness_bundle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(CpRelationError::FsOpeningMismatch)
    );
}

#[test]
fn typed_cp_field_relation_rejects_bad_fs_message() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);
    proof.witness_bundle.fs_messages[0].push(0x01);
    let statement = cp_field_statement(&proof, &public_inputs, &r1cs, PublicDigestScheme::Sha256);

    assert!(CpFieldRelation::check(
        &statement,
        &proof.witness_bundle,
        &prover.ajtai,
        &r1cs,
        prover.params.b_input()
    )
    .is_err());
}

#[test]
fn typed_cp_field_relation_rejects_public_input_replay() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let proof = prover.prove(&statements, &r1cs);
    let mut replayed_inputs = public_inputs.clone();
    replayed_inputs[0][0] += 1;
    let statement = cp_field_statement(&proof, &replayed_inputs, &r1cs, PublicDigestScheme::Sha256);

    assert!(CpFieldRelation::check(
        &statement,
        &proof.witness_bundle,
        &prover.ajtai,
        &r1cs,
        prover.params.b_input()
    )
    .is_err());
}

#[test]
fn typed_cp_field_relation_rejects_bad_fold_and_challenge_digests() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let proof = prover.prove(&statements, &r1cs);

    let mut bad_fold = proof.clone();
    bad_fold.cp_public_instance.fold_root[0] ^= 0x01;
    let statement =
        cp_field_statement(&bad_fold, &public_inputs, &r1cs, PublicDigestScheme::Sha256);
    assert_eq!(
        CpFieldRelation::check(
            &statement,
            &bad_fold.witness_bundle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(CpRelationError::FoldRootMismatch)
    );

    let mut bad_challenge = proof;
    bad_challenge.cp_public_instance.challenge_digest[0] ^= 0x01;
    let statement = cp_field_statement(
        &bad_challenge,
        &public_inputs,
        &r1cs,
        PublicDigestScheme::Sha256,
    );
    assert_eq!(
        CpFieldRelation::check(
            &statement,
            &bad_challenge.witness_bundle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(CpRelationError::ChallengeDigestMismatch)
    );
}

#[test]
fn typed_cp_field_relation_rejects_folded_output_and_original_witness_tampering() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let proof = prover.prove(&statements, &r1cs);

    let mut bad_output = proof.clone();
    bad_output
        .cp_public_instance
        .folded_output
        .folded_instance
        .public_input[0]
        .coeffs[0] += 1;
    let statement = cp_field_statement(
        &bad_output,
        &public_inputs,
        &r1cs,
        PublicDigestScheme::Sha256,
    );
    assert_eq!(
        CpFieldRelation::check(
            &statement,
            &bad_output.witness_bundle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(CpRelationError::FoldedOutputMismatch)
    );

    let mut bad_witness = proof;
    bad_witness.witness_bundle.original_witnesses[0].elements[0].coeffs[0] += 1;
    let statement = cp_field_statement(
        &bad_witness,
        &public_inputs,
        &r1cs,
        PublicDigestScheme::Sha256,
    );
    assert_eq!(
        CpFieldRelation::check(
            &statement,
            &bad_witness.witness_bundle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(CpRelationError::FoldedOutputMismatch)
    );
}

#[test]
fn typed_cp_field_relation_rejects_invalid_original_r1cs_assignment() {
    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let proof = prover.prove(&statements, &r1cs);
    let statement = cp_field_statement(&proof, &public_inputs, &r1cs, PublicDigestScheme::Sha256);
    let mut bad_r1cs = r1cs.clone();
    bad_r1cs.c.insert(0, 0, 999);

    assert!(CpFieldRelation::check(
        &statement,
        &proof.witness_bundle,
        &prover.ajtai,
        &bad_r1cs,
        prover.params.b_input()
    )
    .is_err());
}

#[cfg(feature = "whir")]
#[test]
fn typed_cp_field_relation_accepts_poseidon_babybear_bindings() {
    use symphony::digest_core::{
        derive_challenges_with_scheme, digest_challenge_digest_with_scheme,
        digest_fold_root_with_scheme, digest_fs_root_with_scheme,
        digest_transcript_seed_with_scheme, fs_commit_with_scheme,
    };

    let (prover, _verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);
    let scheme = PublicDigestScheme::Poseidon2BabyBear;

    proof.witness_bundle.fs_commitments.clear();
    proof.witness_bundle.fs_openings.clear();
    for message in &proof.witness_bundle.fs_messages {
        let (commitment, opening) = fs_commit_with_scheme(scheme, message);
        proof
            .witness_bundle
            .fs_commitments
            .push(commitment.to_vec());
        proof.witness_bundle.fs_openings.push(opening.to_vec());
    }
    proof.witness_bundle.transcript_bytes.clear();
    proof.cp_public_instance.fs_root =
        digest_fs_root_with_scheme(scheme, &proof.witness_bundle.fs_commitments);
    proof.cp_public_instance.fold_root =
        digest_fold_root_with_scheme(scheme, &proof.witness_bundle.fold_inputs);
    proof.cp_public_instance.transcript_seed_digest = digest_transcript_seed_with_scheme(
        scheme,
        &public_inputs,
        r1cs.num_constraints,
        r1cs.num_variables,
        r1cs.num_public,
    );
    let challenges = derive_challenges_with_scheme(
        scheme,
        &public_inputs,
        r1cs.num_constraints,
        r1cs.num_variables,
        r1cs.num_public,
        &proof.witness_bundle.fs_commitments,
    );
    proof.cp_public_instance.challenge_digest =
        digest_challenge_digest_with_scheme(scheme, &challenges);

    let statement = cp_field_statement(&proof, &public_inputs, &r1cs, scheme);
    assert!(CpFieldRelation::check(
        &statement,
        &proof.witness_bundle,
        &prover.ajtai,
        &r1cs,
        prover.params.b_input()
    )
    .is_ok());
}

// =========================================================================
// Security / soundness tests ported from security_soundness.rs
// =========================================================================

type ModularFixture = (
    Prover<SumcheckSnark, SumcheckSnark>,
    Verifier<SumcheckSnark, SumcheckSnark>,
    Vec<(Commitment, Vec<i64>, RingVector)>,
    Vec<Vec<i64>>,
    symphony::r1cs::R1CSMatrices,
);

fn build_modular_proof() -> ModularFixture {
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
fn modular_witness_tampering_is_rejected() {
    let (prover, verifier, statements, public_inputs, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.witness_bundle.fs_commitments[0][0] ^= 0x01;
    assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
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

    proof.cp_public_instance.challenge_digest[0] ^= 0xFF;
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::ChallengeDigestMismatch)
    );
}

#[test]
fn cp_relation_transcript_parse_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

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
fn cp_relation_transcript_seed_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.cp_public_instance.transcript_seed_digest[0] ^= 0xFF;
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::TranscriptSeedMismatch)
    );
}

#[test]
fn cp_relation_fs_opening_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.witness_bundle.fs_openings[0][0] ^= 0xFF;
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::FsOpeningMismatch)
    );
}

#[test]
fn cp_relation_fs_message_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof.witness_bundle.fs_messages[0].push(0xFF);
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::FsOpeningMismatch)
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

#[test]
fn cp_relation_typed_folded_output_instance_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof
        .witness_bundle
        .folded_output_instance
        .linear_relation
        .evaluation_point[0]
        .c0 += 1;
    assert_eq!(
        CpRelation::check(&proof.cp_public_instance, &proof.witness_bundle),
        Err(CpRelationError::FoldedOutputMismatch)
    );
}

#[test]
fn cp_relation_typed_folded_output_witness_mismatch() {
    let (prover, _verifier, statements, _pi, r1cs) = build_modular_proof();
    let mut proof = prover.prove(&statements, &r1cs);

    proof
        .witness_bundle
        .folded_output_witness
        .folded_witness
        .witness
        .elements[0]
        .coeffs[0] += 1;
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
