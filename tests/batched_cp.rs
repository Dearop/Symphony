mod common;

#[cfg(feature = "whir")]
use p3_baby_bear::BabyBear;
#[cfg(feature = "whir")]
use p3_field::PrimeCharacteristicRing;
use symphony::batched_cp::{
    bucket_by_exact_shape, digest_ajtai_params, digest_r1cs_matrices, BatchedCpBucket,
    BatchedCpError, BatchedCpEvaluator, BatchedCpItem, BatchedCpSemanticConstraintFamily,
    BatchedCpSemanticRelationDescription, BatchedCpStructuredRelationDescription,
    CpAccumulatorShape,
};
#[cfg(feature = "whir")]
use symphony::batched_cp::{
    derive_symbt3_accumulator_transition_challenge, derive_symbt3_batch_challenge_digest,
    derive_symbt3_beta_coefficients, derive_symbt3_beta_ring_elements,
    derive_symbt3_manifest_membership_challenge, derive_symbt3_public_statement_digest,
    derive_symbt3_round_challenges, symbt3_accumulator_coordinates_digest,
    symbt3_accumulator_transition_profile_digest, symbt3_batch_manifest_root_from_oracle_root,
    symbt3_batch_manifest_root_from_rows, symbt3_canonical_manifest_view_eval_for_statement,
    symbt3_manifest_commitment_policy_digest, symbt3_manifest_oracle_root_for_statement,
    symbt3_manifest_oracle_root_from_rows, symbt3_manifest_rows_for_statement,
    symbt3_manifest_source_eval_claim_for_statement, symbt3_manifest_source_values_for_statement,
    symbt3_norm_range_policy_digest, symbt3_virtual_source_view_eval_for_statement,
    BatchedCpSemanticColumnarV2Description, BatchedCpSemanticFamilyColumnarV2Description,
    BatchedCpSemanticFamilyTraceV2, BatchedCpSemanticRelationV2Description,
    BatchedCpSemanticTraceV2, BatchedCpSymbt3ConstraintFamily, BatchedCpSymbt3RelationDescription,
    BatchedCpSymbt3SetupDescriptor, ManifestCommitmentPolicy, ProductProofKind,
    Symbt3AccumulatorInstance, Symbt3AccumulatorWitness, Symbt3AuthorityProfile,
    Symbt3AuthorityStatus, Symbt3BetaActionId, Symbt3CanonicalRepPolicy,
    Symbt3FieldExtensionPolicy, Symbt3MessageSectionKind, Symbt3MessageSemanticMode,
    Symbt3ProductLawId, Symbt3ProductPolicy, Symbt3ProjectionEntryDistribution,
    Symbt3ProjectionMode, Symbt3RangeMode, Symbt3RingActionSide, Symbt3RoutingStatus,
    Symbt3SoundnessStatus, Symbt3SumcheckChallengePolicy, Symbt3TypedMessageOracle, Symbt3ZkStatus,
};
use symphony::commitment::Commitment;
#[cfg(feature = "whir")]
use symphony::cp_backend_api::CpBackend;
use symphony::cp_relation_core::{CpPublicStatement, CpRelationError};
#[cfg(feature = "whir")]
use symphony::digest_core::{
    derive_challenges_with_scheme, digest_challenge_digest_with_scheme, digest_domain_with_scheme,
    digest_fold_root_with_scheme, digest_fs_root_with_scheme, digest_transcript_seed_with_scheme,
    fs_commit_with_scheme, Digest32, PublicDigestScheme,
};
#[cfg(not(feature = "whir"))]
use symphony::digest_core::{digest_domain_with_scheme, Digest32, PublicDigestScheme};
use symphony::params::{SymphonyParams, D};
use symphony::proof_orchestrator::{ProofBundle, Prover};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};
use symphony::SumcheckSnark;
#[cfg(feature = "whir")]
use symphony::{WhirProof, WhirSnark};

fn modular_params() -> SymphonyParams {
    SymphonyParams {
        q: common::Q,
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
        ntt: SymphonyParams::try_ntt(common::Q, D),
    }
}

#[cfg(feature = "whir")]
fn babybear_modular_params() -> SymphonyParams {
    const BB_P: u64 = 2_013_265_921;
    SymphonyParams {
        q: BB_P,
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
        ntt: SymphonyParams::try_ntt(BB_P, D),
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

fn make_batched_item(
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
    r1cs: &R1CSMatrices,
    z: &[i64],
    tag: u8,
) -> BatchedCpItem {
    let n_in = r1cs.num_public;
    let statements = vec![
        make_statement(prover, z, n_in),
        make_statement(prover, z, n_in),
    ];
    let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
    let proof: ProofBundle<SumcheckSnark, SumcheckSnark> = prover.prove(&statements, &r1cs);
    let public = CpPublicStatement::new(
        proof.cp_public_instance.clone(),
        public_inputs,
        &r1cs,
        PublicDigestScheme::Sha256,
    );
    BatchedCpItem {
        item_tag: [tag; 32],
        public,
        witness: proof.witness_bundle,
    }
}

#[cfg(feature = "whir")]
fn poseidon_shaped_item(
    mut item: BatchedCpItem,
    prover: &Prover<SumcheckSnark, SumcheckSnark>,
) -> BatchedCpItem {
    let scheme = PublicDigestScheme::Poseidon2BabyBear;
    let mut fs_commitments = Vec::with_capacity(item.witness.fs_messages.len());
    let mut fs_openings = Vec::with_capacity(item.witness.fs_messages.len());
    for message in &item.witness.fs_messages {
        let (commitment, opening) = fs_commit_with_scheme(scheme, message);
        fs_commitments.push(commitment.to_vec());
        fs_openings.push(opening.to_vec());
    }

    item.public.digest_scheme = scheme;
    item.witness.fs_commitments = fs_commitments;
    item.witness.fs_openings = fs_openings;
    item.public.instance.fs_root = digest_fs_root_with_scheme(scheme, &item.witness.fs_commitments);
    item.public.instance.fold_root =
        digest_fold_root_with_scheme(scheme, &item.witness.fold_inputs);
    let challenges = derive_challenges_with_scheme(
        scheme,
        &item.public.public_inputs,
        item.public.r1cs_num_constraints,
        item.public.r1cs_num_variables,
        item.public.r1cs_num_public,
        &item.witness.fs_commitments,
    );
    item.public.instance.challenge_digest =
        digest_challenge_digest_with_scheme(scheme, &challenges);
    let typed_beta =
        symphony::snark::cp_snark::typed_r1cs::poseidon_challenges_to_betas(&challenges)
            .expect("Poseidon challenges should map to typed beta");
    item.witness.folding_proof.beta = typed_beta;
    item.witness.folded_witness = symphony::folding::retarget_folding_proof_to_current_beta(
        &mut item.witness.folding_proof,
        &item.public.public_inputs,
        &item.witness.original_witnesses,
        prover.params.q,
        prover.params.ntt(),
    )
    .expect("Poseidon beta should retarget folded state");
    item.public.instance.x_folded = item.witness.folding_proof.folded_instance.clone();
    item.witness.folded_output = item.public.instance.x_folded.clone();
    item.public.instance.folded_output =
        symphony::folding::folded_output_instance_from_proof(&item.witness.folding_proof);
    item.witness.folded_output_instance = item.public.instance.folded_output.clone();
    item.witness.folded_output_witness =
        symphony::folding::folded_output_witness_from_folded(&item.witness.folded_witness);
    item.public.instance.transcript_seed_digest = digest_transcript_seed_with_scheme(
        scheme,
        &item.public.public_inputs,
        item.public.r1cs_num_constraints,
        item.public.r1cs_num_variables,
        item.public.r1cs_num_public,
    );
    item
}

fn build_fixture() -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    R1CSMatrices,
    Vec<BatchedCpItem>,
) {
    let params = modular_params();
    let (prover, _verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let items = vec![
        make_batched_item(&prover, &r1cs, &z, 1),
        make_batched_item(&prover, &r1cs, &z, 2),
        make_batched_item(&prover, &r1cs, &z, 3),
    ];
    (prover, r1cs, items)
}

#[cfg(feature = "whir")]
fn build_babybear_fixture() -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    R1CSMatrices,
    Vec<BatchedCpItem>,
) {
    let params = babybear_modular_params();
    let (prover, _verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
    let (r1cs, z) = common::multi_r1cs();
    let items = vec![make_batched_item(&prover, &r1cs, &z, 1)];
    (prover, r1cs, items)
}

fn whir_parameter_digest() -> Digest32 {
    digest_domain_with_scheme(
        PublicDigestScheme::Sha256,
        b"test-whir-params",
        b"batched-cp",
    )
}

#[cfg(feature = "whir")]
fn poseidon_columnar_fixture() -> (
    Prover<SumcheckSnark, SumcheckSnark>,
    R1CSMatrices,
    BatchedCpBucket,
) {
    let (prover, r1cs, mut items) = build_babybear_fixture();
    let poseidon_item = poseidon_shaped_item(items.remove(0), &prover);
    let bucket = BatchedCpBucket::new(vec![poseidon_item], whir_parameter_digest()).unwrap();
    (prover, r1cs, bucket)
}

#[cfg(feature = "whir")]
fn read_i64_at(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(feature = "whir")]
fn packed_oracle_value_at(bytes: &[u8], packed_index: usize) -> u32 {
    let mut value = 0u32;
    let start = packed_index * 3;
    for (idx, &byte) in bytes[start..bytes.len().min(start + 3)].iter().enumerate() {
        value |= (byte as u32) << (8 * idx);
    }
    value
}

#[cfg(feature = "whir")]
fn read_i64_via_packed_oracle(bytes: &[u8], offset: usize) -> i64 {
    let mut out = [0u8; 8];
    for (idx, byte) in out.iter_mut().enumerate() {
        let byte_offset = offset + idx;
        let packed = packed_oracle_value_at(bytes, byte_offset / 3);
        *byte = ((packed >> (8 * (byte_offset % 3))) & 0xff) as u8;
    }
    i64::from_le_bytes(out)
}

#[cfg(feature = "whir")]
fn bb(value: i64) -> i128 {
    const BB_P: i128 = 2_013_265_921;
    (value as i128).rem_euclid(BB_P)
}

#[cfg(feature = "whir")]
fn bb_ring_mul(a: &[i64], b: &[i64]) -> [i128; D] {
    const BB_P: i128 = 2_013_265_921;
    let mut out = [0i128; D];
    for (i, &a_i) in a.iter().enumerate() {
        for (j, &b_j) in b.iter().enumerate() {
            let prod = (bb(a_i) * bb(b_j)).rem_euclid(BB_P);
            let idx = i + j;
            if idx < D {
                out[idx] = (out[idx] + prod).rem_euclid(BB_P);
            } else {
                out[idx - D] = (out[idx - D] - prod).rem_euclid(BB_P);
            }
        }
    }
    out
}

#[cfg(feature = "whir")]
fn assert_poseidon_folded_algebra_offsets_hold(
    shape: &symphony::batched_cp::BatchedCpStatementShape,
    oracle: &[u8],
) {
    let read = |offset| {
        let direct = read_i64_at(oracle, offset);
        let packed = read_i64_via_packed_oracle(oracle, offset);
        assert_eq!(direct, packed, "packed byte interpreter mismatch");
        packed
    };
    for constraint in shape.folded_public_input_linear_constraints() {
        let mut acc = 0i128;
        for (&beta_offset, &input_offset) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.input_scalar_offsets.iter())
        {
            acc += bb(read(beta_offset)) * bb(read(input_offset));
        }
        assert_eq!(
            acc.rem_euclid(2_013_265_921),
            bb(read(constraint.output_coeff_offset)),
            "folded public-input offset equation failed"
        );
        let mut babybear_acc = p3_baby_bear::BabyBear::ZERO;
        for (&beta_offset, &input_offset) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.input_scalar_offsets.iter())
        {
            babybear_acc += p3_baby_bear::BabyBear::from_u32(bb(read(beta_offset)) as u32)
                * p3_baby_bear::BabyBear::from_u32(bb(read(input_offset)) as u32);
        }
        assert_eq!(
            babybear_acc,
            p3_baby_bear::BabyBear::from_u32(bb(read(constraint.output_coeff_offset)) as u32),
            "folded public-input BabyBear equation failed"
        );
    }
    for constraint in shape.folded_commitment_ring_mul_constraints() {
        let mut acc = 0i128;
        for (beta_offsets, commitment_offsets) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.commitment_coeff_offsets.iter())
        {
            let beta: Vec<i64> = beta_offsets.iter().map(|&offset| read(offset)).collect();
            let commitment: Vec<i64> = commitment_offsets
                .iter()
                .map(|&offset| read(offset))
                .collect();
            acc += bb_ring_mul(&beta, &commitment)[constraint.output_coeff_index];
        }
        assert_eq!(
            acc.rem_euclid(2_013_265_921),
            bb(read(constraint.output_coeff_offset)),
            "folded commitment offset equation failed"
        );
    }
    for constraint in shape.folded_evaluation_ring_mul_constraints() {
        let mut acc = 0i128;
        for (beta_offsets, evaluation_offsets) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.evaluation_coeff_offsets.iter())
        {
            let beta: Vec<i64> = beta_offsets.iter().map(|&offset| read(offset)).collect();
            let evaluation: Vec<i64> = evaluation_offsets
                .iter()
                .map(|&offset| read(offset))
                .collect();
            acc += bb_ring_mul(&beta, &evaluation)[constraint.output_coeff_index];
        }
        assert_eq!(
            acc.rem_euclid(2_013_265_921),
            bb(read(constraint.output_coeff_offset)),
            "folded evaluation offset equation failed"
        );
    }
}

#[cfg(feature = "whir")]
fn assert_ajtai_opening_offsets_hold(
    semantic: &BatchedCpSemanticRelationDescription,
    oracle: &[u8],
) {
    let read = |offset| {
        let direct = read_i64_at(oracle, offset);
        let packed = read_i64_via_packed_oracle(oracle, offset);
        assert_eq!(direct, packed, "packed byte interpreter mismatch");
        packed
    };
    let constraints = semantic.ajtai_opening_linear_constraints();
    assert!(
        !constraints.is_empty(),
        "Poseidon/BabyBear semantic relation should expose Ajtai opening equations"
    );
    for constraint in constraints {
        let mut acc = 0i128;
        for (matrix_elem, &public_offset) in constraint
            .matrix_row
            .iter()
            .zip(constraint.public_input_offsets.iter())
        {
            acc += bb(matrix_elem.coeffs[constraint.coeff]) * bb(read(public_offset));
        }
        for (matrix_elem, witness_offsets) in constraint
            .matrix_row
            .iter()
            .skip(constraint.public_input_offsets.len())
            .zip(constraint.witness_coeff_offsets.iter())
        {
            let witness: Vec<i64> = witness_offsets.iter().map(|&offset| read(offset)).collect();
            acc += bb_ring_mul(&matrix_elem.coeffs, &witness)[constraint.coeff];
        }
        assert_eq!(
            acc.rem_euclid(2_013_265_921),
            bb(read(constraint.commitment_coeff_offset)),
            "Ajtai opening offset equation failed"
        );
    }
}

#[cfg(feature = "whir")]
fn assert_original_r1cs_offsets_hold(
    semantic: &BatchedCpSemanticRelationDescription,
    oracle: &[u8],
) {
    let read = |offset| {
        let direct = read_i64_at(oracle, offset);
        let packed = read_i64_via_packed_oracle(oracle, offset);
        assert_eq!(direct, packed, "packed byte interpreter mismatch");
        packed
    };
    let eval_terms = |terms: &[(i64, usize)]| {
        terms.iter().fold(0i128, |acc, &(matrix_coeff, offset)| {
            acc + bb(matrix_coeff) * bb(read(offset))
        })
    };
    let constraints = semantic.original_r1cs_constraints();
    assert!(
        !constraints.is_empty(),
        "Poseidon/BabyBear semantic relation should expose original R1CS equations"
    );
    for constraint in constraints {
        let a = eval_terms(&constraint.a_terms);
        let b = eval_terms(&constraint.b_terms);
        let c = eval_terms(&constraint.c_terms);
        assert_eq!(
            (a * b).rem_euclid(2_013_265_921),
            c.rem_euclid(2_013_265_921),
            "original R1CS offset equation failed for item={}, original={}, row={}, coeff={}",
            constraint.item,
            constraint.original_index,
            constraint.row,
            constraint.coeff
        );
    }
}

#[test]
fn batched_cp_shape_id_is_stable_and_shape_mismatch_rejects() {
    let (_prover, _r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let mut item_b = items.remove(0);
    let params_digest = whir_parameter_digest();

    let shape_a =
        CpAccumulatorShape::from_item(&item_a.public, &item_a.witness, params_digest).unwrap();
    let shape_a_again =
        CpAccumulatorShape::from_item(&item_a.public, &item_a.witness, params_digest).unwrap();
    assert_eq!(shape_a.shape_id(), shape_a_again.shape_id());

    item_b.witness.fs_messages[0].push(7);
    assert_eq!(
        BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap_err(),
        BatchedCpError::ShapeMismatch
    );
}

#[test]
fn batched_cp_buckets_exact_shapes_and_rejects_duplicate_tags() {
    let (_prover, _r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();

    let buckets =
        bucket_by_exact_shape(vec![item_a.clone(), item_b.clone()], params_digest).unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].shape.active_count, 2);
    assert_eq!(buckets[0].shape.batch_capacity, 2);

    let mut duplicate = item_b;
    duplicate.item_tag = item_a.item_tag;
    assert_eq!(
        BatchedCpBucket::new(vec![item_a, duplicate], params_digest).unwrap_err(),
        BatchedCpError::DuplicateItemTag
    );
}

#[test]
fn batched_cp_manifest_transcript_and_padding_are_binding() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let item_c = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b, item_c], params_digest).unwrap();
    assert_eq!(bucket.shape.active_count, 3);
    assert_eq!(bucket.shape.batch_capacity, 4);

    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    assert!(BatchedCpEvaluator::check(
        &public,
        &witness,
        &prover.ajtai,
        &r1cs,
        prover.params.b_input()
    )
    .is_ok());

    let mut bad_manifest = public.clone();
    bad_manifest.manifest_digest[0] ^= 1;
    assert_eq!(
        BatchedCpEvaluator::check(
            &bad_manifest,
            &witness,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::ManifestMismatch)
    );

    let mut bad_round = public.clone();
    bad_round.round_message_commitments[0][0] ^= 1;
    assert_eq!(
        BatchedCpEvaluator::check(
            &bad_round,
            &witness,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::RoundMessageCommitmentMismatch)
    );

    let mut bad_witness_oracle = witness.clone();
    bad_witness_oracle.witness_oracle_rows[0][0] ^= 1;
    assert_eq!(
        BatchedCpEvaluator::check(
            &public,
            &bad_witness_oracle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::WitnessOracleMismatch)
    );

    let mut bad_round_oracle = witness.clone();
    bad_round_oracle.round_message_oracles[0][0][0] ^= 1;
    assert_eq!(
        BatchedCpEvaluator::check(
            &public,
            &bad_round_oracle,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::RoundMessageOracleMismatch)
    );

    let mut bad_padding = witness.clone();
    assert_eq!(bad_padding.witness_oracle_rows.len(), 4);
    bad_padding.witness_oracle_rows[3] = vec![1];
    assert_eq!(
        BatchedCpEvaluator::check(
            &public,
            &bad_padding,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::WitnessOracleMismatch)
    );

    let mut bad_shape = public.clone();
    bad_shape.shape.active_count = 2;
    assert_eq!(
        BatchedCpEvaluator::check(
            &bad_shape,
            &witness,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::ShapeMismatch)
    );

    let mut bad_challenge = public;
    bad_challenge.batch_challenge_digest[0] ^= 1;
    assert_eq!(
        BatchedCpEvaluator::check(
            &bad_challenge,
            &witness,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::ChallengeDigestMismatch)
    );
}

#[test]
fn batched_cp_evaluator_rejects_item_level_cp_violation() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let public = bucket.public_statement();
    let mut witness = bucket.witness_bundle();
    witness.items[1].witness.fs_openings[0][0] ^= 1;
    let witness = BatchedCpBucket::new(witness.items, params_digest)
        .unwrap()
        .witness_bundle();

    assert_eq!(
        BatchedCpEvaluator::check(
            &public,
            &witness,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::ItemRelationFailed(
            1,
            CpRelationError::FsOpeningMismatch
        ))
    );
}

#[test]
fn batched_cp_reordered_or_omitted_items_reject() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a.clone(), item_b.clone()], params_digest).unwrap();
    let public = bucket.public_statement();

    let reordered_items = vec![item_b, item_a];
    let reordered = BatchedCpBucket::new(reordered_items, params_digest)
        .unwrap()
        .witness_bundle();
    assert_eq!(
        BatchedCpEvaluator::check(
            &public,
            &reordered,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::ManifestMismatch)
    );

    let omitted = BatchedCpBucket::new(vec![reordered.items[0].clone()], params_digest)
        .unwrap()
        .witness_bundle();
    assert_eq!(
        BatchedCpEvaluator::check(
            &public,
            &omitted,
            &prover.ajtai,
            &r1cs,
            prover.params.b_input()
        ),
        Err(BatchedCpError::ShapeMismatch)
    );
}

#[test]
fn batched_cp_structured_relation_context_is_stable_and_non_r1cs() {
    let (_prover, _r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let public = bucket.public_statement();
    let structured = bucket.shape.structured_relation_description();
    assert_eq!(
        structured.public_statement_bytes,
        public.canonical_bytes().len()
    );
    assert_eq!(
        structured.product_domain_size,
        bucket.shape.product_domain_size()
    );

    let relation = structured.to_relation_description();
    assert_eq!(relation.num_instance_vars, public.canonical_bytes().len());
    assert_eq!(
        relation.num_witness_vars,
        bucket.shape.product_domain_size()
    );
    assert_eq!(
        relation.num_constraints, 0,
        "structured batched CP relation must not masquerade as appended R1CS"
    );

    let context = relation.context.as_ref().expect("structured context bytes");
    let decoded = BatchedCpStructuredRelationDescription::from_context_bytes(context).unwrap();
    assert_eq!(decoded, structured);
    assert_eq!(decoded.relation_id(), structured.relation_id());

    let mut tampered = context.clone();
    tampered[0] ^= 1;
    assert_eq!(
        BatchedCpStructuredRelationDescription::from_context_bytes(&tampered).unwrap_err(),
        BatchedCpError::InvalidStructuredRelationContext
    );
}

#[test]
fn batched_cp_semantic_relation_description_binds_indexed_parameters() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let semantic =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    let semantic_again =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    assert_eq!(
        semantic.semantic_relation_id(),
        semantic_again.semantic_relation_id()
    );
    assert_eq!(
        semantic.ajtai_params_digest,
        digest_ajtai_params(bucket.shape.accumulator_shape.digest_scheme, &prover.ajtai)
    );
    assert_eq!(
        semantic.r1cs_matrices_digest,
        digest_r1cs_matrices(bucket.shape.accumulator_shape.digest_scheme, &r1cs)
    );
    assert_eq!(
        semantic.constraint_families,
        vec![
            BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
            BatchedCpSemanticConstraintFamily::ManifestMembership,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            BatchedCpSemanticConstraintFamily::ChallengeDerivation,
            BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
            BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
            BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        ]
    );

    let mut changed_r1cs = r1cs.clone();
    changed_r1cs.a.insert(0, 0, 1);
    let changed = bucket.shape.semantic_relation_description(
        &prover.ajtai,
        &changed_r1cs,
        prover.params.b_input(),
    );
    assert_ne!(semantic.r1cs_matrices_digest, changed.r1cs_matrices_digest);
    assert_ne!(
        semantic.semantic_relation_id(),
        changed.semantic_relation_id()
    );

    let mut changed_ajtai = prover.ajtai.clone();
    changed_ajtai.a[0][0].coeffs[0] += 1;
    let changed =
        bucket
            .shape
            .semantic_relation_description(&changed_ajtai, &r1cs, prover.params.b_input());
    assert_ne!(semantic.ajtai_params_digest, changed.ajtai_params_digest);
    assert_ne!(
        semantic.semantic_relation_id(),
        changed.semantic_relation_id()
    );

    let context = semantic.canonical_context_bytes();
    let decoded = BatchedCpSemanticRelationDescription::from_context_bytes(&context).unwrap();
    assert_eq!(decoded, semantic);
    let mut bad_version = context.clone();
    bad_version[0] ^= 1;
    assert_eq!(
        BatchedCpSemanticRelationDescription::from_context_bytes(&bad_version).unwrap_err(),
        BatchedCpError::InvalidSemanticRelationContext
    );

    let relation = semantic.to_relation_description();
    assert_eq!(relation.num_constraints, 0);
    assert_eq!(
        relation.num_witness_vars,
        semantic.oracle_layout.packed_field_len
    );
}

#[cfg(feature = "whir")]
#[test]
fn batched_cp_semantic_v2_relation_context_is_stable_and_non_r1cs() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let semantic =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    let semantic_v2 = bucket.shape.semantic_v2_relation_description(
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );

    assert_eq!(semantic_v2.semantic, semantic);
    assert_eq!(
        semantic_v2.v2_layout.byte_len,
        semantic.oracle_layout.byte_len
    );
    assert_eq!(
        semantic_v2.v2_layout.packed_field_len,
        semantic.oracle_layout.packed_field_len
    );
    assert_eq!(
        semantic_v2.v2_layout.product_rows,
        bucket.shape.batch_capacity
    );
    assert_eq!(
        semantic_v2.v2_layout.residual_family_count,
        semantic.constraint_families.len()
    );
    assert_ne!(
        semantic.semantic_relation_id(),
        semantic_v2.semantic_relation_id()
    );

    let relation = semantic_v2.to_relation_description();
    assert_eq!(
        relation.num_constraints, 0,
        "SYMBTC2 must stay structured and must not lower to appended typed CP R1CS"
    );
    assert_eq!(
        relation.num_witness_vars,
        semantic_v2.v2_layout.packed_field_len
    );
    let context = relation.context.as_ref().expect("SYMBTC2 context");
    let decoded = BatchedCpSemanticRelationV2Description::from_context_bytes(context).unwrap();
    assert_eq!(decoded, semantic_v2);

    let mut tampered = context.clone();
    tampered[0] ^= 1;
    assert_eq!(
        BatchedCpSemanticRelationV2Description::from_context_bytes(&tampered).unwrap_err(),
        BatchedCpError::InvalidSemanticRelationContext
    );
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_relation_context_public_boundary_and_challenges_are_stable() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket_one = BatchedCpBucket::new(vec![item_a.clone()], params_digest).unwrap();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let descriptor_one = BatchedCpSymbt3SetupDescriptor::new(
        bucket_one.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation_one = descriptor_one.relation_description();
    let public_one = bucket_one.symbt3_public_statement_for_relation(&relation_one);
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation = descriptor.relation_description();
    let public = bucket.symbt3_public_statement_for_relation(&relation);

    assert!(public.matches_relation(&relation));
    assert_ne!(public.old_accumulator_digest, [0u8; 32]);
    assert_ne!(public.new_accumulator_digest, [0u8; 32]);
    assert_eq!(
        public.old_accumulator_coordinates.len(),
        relation.symbt3_accumulator_coordinate_len()
    );
    assert_eq!(
        public.new_accumulator_coordinates.len(),
        relation.symbt3_accumulator_coordinate_len()
    );
    assert_eq!(
        public.old_accumulator_digest,
        symbt3_accumulator_coordinates_digest(
            bucket.shape.accumulator_shape.digest_scheme,
            b"old",
            &vec![0; relation.symbt3_accumulator_coordinate_len()],
        )
    );
    assert_eq!(
        public.new_accumulator_digest,
        symbt3_accumulator_coordinates_digest(
            bucket.shape.accumulator_shape.digest_scheme,
            b"new",
            &public.new_accumulator_coordinates,
        )
    );
    let rho_acc = derive_symbt3_accumulator_transition_challenge(&relation, &public);
    assert_ne!(
        rho_acc,
        derive_symbt3_beta_coefficients(&relation, &public)[0] as u32,
        "SYMBT3-K2b rho_acc is domain-separated from folding beta"
    );
    assert_eq!(
        public.new_accumulator_coordinates,
        symphony::batched_cp::symbt3_accumulator_transition_coordinates(&relation, &public)
            .expect("K2b transition coordinates")
    );
    assert!(relation.oracle_layout.constraint_families.contains(
        &symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency
    ));
    assert!(relation.has_symbt3_k2_families());
    let transition_profile_digest = symbt3_accumulator_transition_profile_digest(
        bucket.shape.accumulator_shape.digest_scheme,
        &relation,
    );
    let mut changed_old_for_rho = public.clone();
    changed_old_for_rho.old_accumulator_digest[0] ^= 1;
    assert_ne!(
        rho_acc,
        derive_symbt3_accumulator_transition_challenge(&relation, &changed_old_for_rho),
        "rho_acc must bind old_accumulator_digest"
    );
    let mut changed_folded_for_rho = public.clone();
    changed_folded_for_rho.folded_accumulator_coordinates[0] += 1;
    assert_ne!(
        rho_acc,
        derive_symbt3_accumulator_transition_challenge(&relation, &changed_folded_for_rho),
        "rho_acc must bind folded batch accumulator boundary"
    );
    let mut changed_shape_for_rho = public.clone();
    changed_shape_for_rho.shape_id[0] ^= 1;
    assert_ne!(
        rho_acc,
        derive_symbt3_accumulator_transition_challenge(&relation, &changed_shape_for_rho),
        "rho_acc must bind shape/profile boundary"
    );
    let mut changed_transition_profile_relation = relation.clone();
    changed_transition_profile_relation
        .algebra_law
        .module_layout = "coordinatewise-ring-module-k2b-test";
    assert_ne!(
        transition_profile_digest,
        symbt3_accumulator_transition_profile_digest(
            bucket.shape.accumulator_shape.digest_scheme,
            &changed_transition_profile_relation,
        )
    );
    assert_ne!(
        rho_acc,
        derive_symbt3_accumulator_transition_challenge(
            &changed_transition_profile_relation,
            &public
        ),
        "rho_acc must bind the accumulator transition profile"
    );
    let profile = Symbt3AuthorityProfile::research_authority_candidate_from_relation(&relation, 64);
    let profile_digest = profile.digest(bucket.shape.accumulator_shape.digest_scheme);
    let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        bucket.shape.accumulator_shape.digest_scheme,
        profile_digest,
        public.old_accumulator_digest,
        public.new_accumulator_digest,
        &public,
    );
    assert_eq!(accumulator_instance.to_public_statement(), public);
    assert_eq!(
        accumulator_instance.digest(bucket.shape.accumulator_shape.digest_scheme),
        Symbt3AccumulatorInstance::from_public_statement_with_scheme(
            bucket.shape.accumulator_shape.digest_scheme,
            profile_digest,
            public.old_accumulator_digest,
            public.new_accumulator_digest,
            &public,
        )
        .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    for mutate in [
        "profile", "old", "new", "shape", "capacity", "manifest", "message",
    ] {
        let mut changed = accumulator_instance.clone();
        match mutate {
            "profile" => changed.profile_digest[0] ^= 1,
            "old" => changed.old_accumulator_digest[0] ^= 1,
            "new" => changed.new_accumulator_digest[0] ^= 1,
            "shape" => changed.shape_id[0] ^= 1,
            "capacity" => changed.batch_capacity += 1,
            "manifest" => changed.manifest_root[0] ^= 1,
            "message" => changed.message_oracle_roots[0][0] ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(
            accumulator_instance.digest(bucket.shape.accumulator_shape.digest_scheme),
            changed.digest(bucket.shape.accumulator_shape.digest_scheme),
            "K2a accumulator digest must bind {mutate}"
        );
    }
    let public_statement_digest = derive_symbt3_public_statement_digest(&relation, &public);
    let mut changed_old_accumulator = public.clone();
    changed_old_accumulator.old_accumulator_digest[0] ^= 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&relation, &public),
        derive_symbt3_batch_challenge_digest(&relation, &changed_old_accumulator),
        "K2a old accumulator digest is proof/update boundary data and must not enter folding beta"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_old_accumulator)
    );
    let mut changed_new_accumulator = public.clone();
    changed_new_accumulator.new_accumulator_digest[0] ^= 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&relation, &public),
        derive_symbt3_batch_challenge_digest(&relation, &changed_new_accumulator),
        "K2a new accumulator digest must not enter folding beta; K2b rho_acc will own update binding"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_new_accumulator)
    );
    let symbt3_witness = bucket.symbt3_witness_for_relation(&relation);
    let accumulator_witness: Symbt3AccumulatorWitness =
        Symbt3AccumulatorWitness::from_symbt3_witness(&relation, &symbt3_witness);
    let _: &Vec<Symbt3TypedMessageOracle> = &accumulator_witness.message_oracles;
    assert_eq!(
        accumulator_witness.message_oracles.len(),
        bucket.shape.accumulator_shape.num_rounds
    );
    assert_eq!(
        public.message_oracle_roots.len(),
        bucket.shape.accumulator_shape.num_rounds
    );
    assert_eq!(
        public.canonical_bytes().len(),
        relation.public_statement_bytes()
    );
    assert_eq!(
        public_one.canonical_bytes().len(),
        relation_one.public_statement_bytes()
    );
    assert_eq!(
        public_one.canonical_bytes().len(),
        public.canonical_bytes().len(),
        "SYMBT3-K1 compressed research public statements bind roots/digests, not every manifest/source coordinate"
    );
    assert_eq!(
        public.folded_commitment.len(),
        relation.symbt3_commitment_coordinate_len()
    );
    assert_eq!(
        public.folded_evaluation.len(),
        relation.symbt3_evaluation_coordinate_len()
    );
    assert_eq!(
        public.folded_accumulator_coordinates.len(),
        relation.symbt3_accumulator_coordinate_len()
    );
    assert_eq!(
        public.source_ajtai_opening_roots.len(),
        bucket.shape.active_count
    );
    assert_eq!(
        public.source_assignment_roots.len(),
        bucket.shape.active_count * bucket.shape.accumulator_shape.local_public_input_count
    );
    assert_eq!(
        public.folded_ajtai_commitment, public.folded_commitment,
        "SYMBT3-C AjtaiCommitLayoutV1 uses c = A * opening_witness"
    );
    assert_eq!(
        public.ring_module_layout_digest,
        relation
            .ring_module_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.ajtai_commit_layout_digest,
        relation
            .ajtai_commit_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.r1cs_evaluator_layout_digest,
        relation
            .r1cs_evaluator_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.gr1cs_residual_layout_digest,
        relation
            .gr1cs_residual_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.algebra_law_digest,
        relation
            .algebra_law
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.ajtai_linear_algebra_layout_digest,
        relation
            .ajtai_linear_algebra_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.ajtai_norm_range_layout_digest,
        relation
            .ajtai_norm_range_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.batch_manifest_layout_digest,
        relation
            .batch_manifest_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.source_column_layout_digest,
        relation
            .batch_manifest_layout
            .source_column_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.message_semantic_layout_digest,
        relation
            .message_semantic_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        relation.message_semantic_layout.round_count,
        bucket.shape.accumulator_shape.num_rounds
    );
    assert_eq!(
        relation.message_semantic_layout.semantic_mode,
        Symbt3MessageSemanticMode::NativeOracleViewV1,
        "SYMBT3-I2 consumes CP messages through native relation-bound oracle views"
    );
    assert_eq!(
        relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
        0,
        "SYMBT3-I2 must not materialize per-coordinate message-to-trace copy constraints"
    );
    assert!(
        relation
            .message_semantic_layout
            .round_layouts
            .iter()
            .all(|round| !round.message_views.is_empty()
                && round.trace_column_bindings.is_empty()),
        "message-derived trace values must be virtual views into M_r(T,U), not duplicate trace columns"
    );
    assert!(
        relation
            .message_semantic_layout
            .view_coordinate_count(bucket.shape.active_count)
            < relation.message_semantic_layout.coordinate_count(),
        "SYMBT3-I2 should expose semantic message views instead of the full packed message payload"
    );
    assert!(relation
        .message_semantic_layout
        .round_layouts
        .iter()
        .all(|round| round.sections.iter().all(|section| !matches!(
            section.section_kind,
            Symbt3MessageSectionKind::BoundaryDigestCoordinate
        ))));
    let manifest_rows =
        symbt3_manifest_rows_for_statement(&relation, &public).expect("SYMBT3-H manifest rows");
    let manifest_oracle_root = symbt3_manifest_oracle_root_from_rows(
        bucket.shape.accumulator_shape.digest_scheme,
        &relation,
        &manifest_rows,
    );
    assert_eq!(public.manifest_oracle_root, manifest_oracle_root);
    assert_eq!(
        symbt3_manifest_oracle_root_for_statement(&relation, &public)
            .expect("SYMBT3-K1 public manifest root"),
        public.manifest_oracle_root,
        "K1 authoritative verifier root must be the canonical source-boundary manifest root"
    );
    assert_eq!(
        public.batch_manifest_root,
        symbt3_batch_manifest_root_from_oracle_root(
            bucket.shape.accumulator_shape.digest_scheme,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            &public.batch_manifest_layout_digest,
            &manifest_oracle_root
        )
    );
    assert_eq!(
        public.batch_manifest_root,
        symbt3_batch_manifest_root_from_rows(
            bucket.shape.accumulator_shape.digest_scheme,
            &relation,
            &manifest_rows
        ),
        "row helper must derive the K1a linked product root"
    );
    assert_eq!(
        public.manifest_eval_claim, 0,
        "K1e does not trust a public manifest_eval_claim fact"
    );
    assert_eq!(
        symbt3_manifest_source_values_for_statement(&relation, &public)
            .expect("SYMBT3-K1c streaming source values"),
        manifest_rows
            .iter()
            .flat_map(|row| row.iter().copied())
            .collect::<Vec<_>>(),
        "K1c verifier source evaluator must match the canonical manifest row order without requiring row reconstruction"
    );
    assert_eq!(
        symbt3_canonical_manifest_view_eval_for_statement(
            &relation,
            &public,
            &public.manifest_oracle_root
        )
        .expect("SYMBT3-K1e manifest view eval claim"),
        symbt3_manifest_source_eval_claim_for_statement(
            &relation,
            &public,
            &public.manifest_oracle_root
        )
        .expect("SYMBT3-K1c streaming source eval claim"),
        "K1e ManifestView and SourceView use the same canonical public evaluator"
    );
    assert_eq!(
        symbt3_canonical_manifest_view_eval_for_statement(
            &relation,
            &public,
            &public.manifest_oracle_root
        ),
        symbt3_virtual_source_view_eval_for_statement(
            &relation,
            &public,
            &public.manifest_oracle_root
        ),
        "K1e.2 SourceView is a virtual evaluator, not a backend vector"
    );
    assert_eq!(
        public.projection_layout_digest,
        relation
            .ajtai_norm_range_layout
            .projection_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.range_layout_digest,
        relation
            .ajtai_norm_range_layout
            .range_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.production_norm_range_layout_digest,
        relation
            .ajtai_norm_range_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.structured_projection_layout_digest,
        relation
            .ajtai_norm_range_layout
            .projection_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.monomial_embedding_layout_digest,
        relation
            .ajtai_norm_range_layout
            .monomial_embedding_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        public.representative_layout_digest,
        relation
            .ajtai_norm_range_layout
            .representative_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert_eq!(
        relation.algebra_law.product_law,
        Symbt3ProductLawId::RqNegacyclicConvolutionV1,
        "SYMBT3-E must use the ring negacyclic product law by default"
    );
    assert_eq!(
        relation.algebra_law.beta_action,
        Symbt3BetaActionId::RingCoefficientActionV1,
        "SYMBT3-E must use ring coefficient beta action by default"
    );
    assert_eq!(
        relation.folded_gr1cs_product_residual_layout.product_law,
        relation.algebra_law.product_law
    );
    assert_eq!(
        relation.folded_gr1cs_product_residual_layout.beta_action,
        relation.algebra_law.beta_action
    );
    assert_eq!(
        relation.ajtai_linear_algebra_layout.product_law,
        relation.algebra_law.product_law
    );
    assert_eq!(
        relation.ajtai_linear_algebra_layout.beta_action,
        relation.algebra_law.beta_action
    );
    assert_eq!(
        relation
            .ajtai_norm_range_layout
            .projection_layout
            .projection_mode,
        Symbt3ProjectionMode::StructuredBlockProjectionV1,
        "SYMBT3-J must default to structured projection, not identity projection"
    );
    assert_eq!(
        relation.ajtai_norm_range_layout.range_mode,
        Symbt3RangeMode::MonomialEmbeddingRangeV1,
        "SYMBT3-J must default to monomial-embedding range semantics"
    );
    assert_eq!(
        relation
            .ajtai_norm_range_layout
            .projection_layout
            .entry_distribution,
        Symbt3ProjectionEntryDistribution::ZeroPlusMinusOneV1
    );
    assert_eq!(
        relation
            .ajtai_norm_range_layout
            .representative_layout
            .canonical_rep_policy,
        Symbt3CanonicalRepPolicy::CenteredModQRepresentativeV1
    );
    assert_eq!(
        public.folded_gr1cs_product_residual_layout_digest,
        relation
            .folded_gr1cs_product_residual_layout
            .digest(bucket.shape.accumulator_shape.digest_scheme)
    );
    assert!(
        relation.has_symbt3_i_families(),
        "SYMBT3-I2 native message-oracle view families must be enabled in the development relation"
    );
    assert!(
        relation.has_symbt3_j_families(),
        "SYMBT3-J structured projection and monomial range families must be enabled in the development relation"
    );
    let dev_profile = Symbt3AuthorityProfile::development_from_relation(&relation);
    assert_eq!(
        dev_profile.authority_status,
        Symbt3AuthorityStatus::NonAuthoritativeDevelopment
    );
    assert_eq!(
        dev_profile.field_policy,
        Symbt3FieldExtensionPolicy::BaseFieldSingleCheckDevelopment
    );
    assert_eq!(
        dev_profile.sumcheck_challenge_policy,
        Symbt3SumcheckChallengePolicy::BaseFieldSingleChallengeDevelopment
    );
    assert!(dev_profile.matches_relation_metadata(&relation));
    assert!(
        !dev_profile.accepts_relation_for_product_authority(&relation),
        "the development SYMBT3 profile is not an authority profile"
    );
    assert!(
        !dev_profile.accepts_relation_for_research_authority_candidate(&relation),
        "development-only soundness status is not a research authority candidate"
    );
    let research_profile =
        Symbt3AuthorityProfile::research_authority_candidate_from_relation(&relation, 64);
    assert_eq!(
        research_profile.soundness_status,
        Symbt3SoundnessStatus::SoundnessCandidate
    );
    assert_eq!(research_profile.zk_status, Symbt3ZkStatus::NonZkDevelopment);
    assert_eq!(
        research_profile.routing_status,
        Symbt3RoutingStatus::ResearchOnly
    );
    assert!(!research_profile.product_eligible);
    assert!(research_profile.research_only);
    assert!(research_profile.matches_relation_metadata(&relation));
    assert!(
        relation.oracle_layout.constraint_families.contains(
            &symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim
        ),
        "SYMBT3-K1b manifest evaluation claim must be in the backend family set"
    );
    assert!(
        research_profile.accepts_relation_for_research_authority_candidate(&relation),
        "SYMBT3-J2 can pass a non-ZK research authority-candidate gate when all semantic families are enabled"
    );
    assert!(
        !research_profile.accepts_relation_for_product_authority(&relation),
        "research-only non-ZK profiles must not be product-authority eligible"
    );
    assert_eq!(
        research_profile.semantic_profile_version, 0,
        "K3 keeps the existing research authority candidate as semantic_profile_version=0"
    );
    assert!(
        !research_profile.accepts_relation_for_accumulator_soundness_authority_candidate(&relation),
        "K3 accumulator soundness authority must reject version-0 research profiles"
    );
    let accumulator_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &relation, 64,
        );
    assert_eq!(accumulator_profile.semantic_profile_version, 1);
    assert!(accumulator_profile.matches_relation_metadata(&relation));
    assert!(
        accumulator_profile.accepts_relation_for_accumulator_soundness_authority_candidate(
            &relation
        ),
        "K3 version-1 accumulator soundness candidate must pass with K1/K2 families and production-shaped policies"
    );
    assert!(
        accumulator_profile.effective_soundness_bits() >= accumulator_profile.soundness_bound_bits,
        "K3 effective soundness must use union-bound accounting over failure terms"
    );
    assert!(
        !accumulator_profile.accepts_relation_for_research_authority_candidate(&relation),
        "K3 version-1 accumulator authority is intentionally separate from the version-0 research gate"
    );
    assert!(
        !accumulator_profile.accepts_relation_for_product_authority(&relation),
        "ProductAuthority must still reject the NonZK K3 accumulator profile until an explicit NonZK integrity policy is added"
    );
    let mut missing_manifest_eval_accumulator_profile = accumulator_profile.clone();
    missing_manifest_eval_accumulator_profile
        .enabled_families
        .retain(|family| {
            *family
                != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim
        });
    assert!(
        !missing_manifest_eval_accumulator_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(&relation),
        "K3 must reject an accumulator profile missing ManifestEvaluationClaim"
    );
    let mut missing_transition_accumulator_profile = accumulator_profile.clone();
    missing_transition_accumulator_profile
        .enabled_families
        .retain(|family| {
            *family
                != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency
        });
    assert!(
        !missing_transition_accumulator_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(&relation),
        "K3 must reject an accumulator profile missing AccumulatorTransitionConsistency"
    );
    let mut zero_policy_digest_profile = accumulator_profile.clone();
    zero_policy_digest_profile.norm_range_policy_digest = [0u8; 32];
    assert!(
        !zero_policy_digest_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(&relation),
        "K3 must reject unpopulated policy digests"
    );
    let mut low_soundness_profile = accumulator_profile.clone();
    low_soundness_profile.manifest_membership_bits = 16;
    assert!(
        !low_soundness_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(&relation),
        "K3 must reject profiles whose union-bound effective soundness misses the bound"
    );
    let mut missing_manifest_eval_relation = relation.clone();
    missing_manifest_eval_relation
        .oracle_layout
        .constraint_families
        .retain(|family| {
            *family
                != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim
        });
    let missing_manifest_eval_relation_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &missing_manifest_eval_relation,
            64,
        );
    assert!(
        !missing_manifest_eval_relation_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(
                &missing_manifest_eval_relation
            ),
        "K3 relation gate must require the K1 ManifestEvaluationClaim family"
    );
    let mut missing_transition_relation = relation.clone();
    missing_transition_relation
        .oracle_layout
        .constraint_families
        .retain(|family| {
            *family
                != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency
        });
    let missing_transition_relation_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &missing_transition_relation,
            64,
        );
    assert!(
        !missing_transition_relation_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(
                &missing_transition_relation
            ),
        "K3 relation gate must require the K2 AccumulatorTransitionConsistency family"
    );
    let mut dev_projection_relation = relation.clone();
    dev_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .projection_mode = Symbt3ProjectionMode::DirectDevDenseProjectionV1;
    let dev_projection_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &dev_projection_relation,
            64,
        );
    assert!(
        !dev_projection_profile.accepts_relation_for_accumulator_soundness_authority_candidate(
            &dev_projection_relation
        ),
        "K3 must reject DirectDevDenseProjectionV1"
    );
    let mut dev_range_relation = relation.clone();
    dev_range_relation.ajtai_norm_range_layout.range_mode = Symbt3RangeMode::DirectSignedRangeDevV1;
    dev_range_relation
        .ajtai_norm_range_layout
        .range_layout
        .range_mode = Symbt3RangeMode::DirectSignedRangeDevV1;
    let dev_range_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &dev_range_relation,
            64,
        );
    assert!(
        !dev_range_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(&dev_range_relation),
        "K3 must reject DirectSignedRangeDevV1"
    );
    let mut identity_projection_relation = relation.clone();
    identity_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .block_len = 1;
    identity_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .output_len = identity_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .input_len;
    let identity_projection_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &identity_projection_relation,
            64,
        );
    assert!(
        !identity_projection_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(
                &identity_projection_relation
            ),
        "K3 must reject identity-shaped projection layouts"
    );
    let mut unconstrained_representative_relation = relation.clone();
    unconstrained_representative_relation
        .ajtai_norm_range_layout
        .representative_layout
        .signed_range = 0;
    let unconstrained_representative_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &unconstrained_representative_relation,
            64,
        );
    assert!(
        !unconstrained_representative_profile
            .accepts_relation_for_accumulator_soundness_authority_candidate(
                &unconstrained_representative_relation
            ),
        "K3 must reject unconstrained representative residual policy"
    );
    let mut debug_monomial_relation = relation.clone();
    debug_monomial_relation
        .ajtai_norm_range_layout
        .monomial_embedding_layout
        .table_polynomial_digest = [0u8; 32];
    let debug_monomial_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &debug_monomial_relation,
            64,
        );
    assert!(
        !debug_monomial_profile.accepts_relation_for_accumulator_soundness_authority_candidate(
            &debug_monomial_relation
        ),
        "K3 must reject debug-only monomial/range policy"
    );
    let mut bad_table_relation = relation.clone();
    bad_table_relation
        .ajtai_norm_range_layout
        .range_layout
        .table_digest
        .as_mut()
        .expect("monomial range table digest")[0] ^= 1;
    let bad_table_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &bad_table_relation,
            64,
        );
    assert_ne!(
        accumulator_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        bad_table_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        "wrong t_B table digest must change the K3 profile digest"
    );
    assert_eq!(
        bad_table_profile.norm_range_policy_digest,
        symbt3_norm_range_policy_digest(
            bucket.shape.accumulator_shape.digest_scheme,
            &bad_table_relation
        ),
        "K3 norm/range policy digest binds the t_B table digest"
    );
    let authority_profile =
        Symbt3AuthorityProfile::authority_candidate_from_relation(&relation, 128);
    assert_eq!(
        authority_profile.authority_status,
        Symbt3AuthorityStatus::AuthorityCandidateV1
    );
    assert!(authority_profile.product_eligible);
    assert!(!authority_profile.research_only);
    assert!(authority_profile.matches_relation_metadata(&relation));
    assert_eq!(
        authority_profile.manifest_commitment_policy_digest,
        symbt3_manifest_commitment_policy_digest(
            bucket.shape.accumulator_shape.digest_scheme,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1
        ),
        "K1e public canonical manifest view policy must be profile-bound"
    );
    assert!(
        !authority_profile.accepts_relation_for_product_authority(&relation),
        "current SYMBT3-J2 relation is still NonAuthoritativeDevelopment/NonZkDevelopment"
    );
    assert_ne!(
        dev_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        authority_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        "authority status and soundness policy are profile-bound"
    );
    let mut changed_authority_profile = authority_profile.clone();
    changed_authority_profile.soundness_target_bits += 1;
    assert_ne!(
        authority_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        changed_authority_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        "profile mutation must change the authority profile digest"
    );
    let mut wrong_manifest_policy_profile = authority_profile.clone();
    wrong_manifest_policy_profile.manifest_commitment_policy_digest[0] ^= 1;
    assert_ne!(
        authority_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        wrong_manifest_policy_profile.digest(bucket.shape.accumulator_shape.digest_scheme),
        "manifest commitment policy mutation must change the authority profile digest"
    );
    assert!(
        !wrong_manifest_policy_profile.matches_relation_metadata(&relation),
        "wrong manifest commitment policy must reject the authority profile"
    );
    let mut wrong_whir_profile = authority_profile.clone();
    wrong_whir_profile.whir_parameter_digest[0] ^= 1;
    assert!(
        !wrong_whir_profile.matches_relation_metadata(&relation),
        "proofs built under one WHIR parameter set must not match another authority profile"
    );
    let mut missing_manifest_profile = authority_profile.clone();
    missing_manifest_profile.enabled_families.retain(|family| {
        *family
            != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership
    });
    assert!(
        !missing_manifest_profile.matches_relation_metadata(&relation),
        "missing manifest/message-view authority families must change/reject the profile"
    );
    let mut missing_manifest_eval_profile = authority_profile.clone();
    missing_manifest_eval_profile
        .enabled_families
        .retain(|family| {
            *family
                != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim
        });
    assert!(
        !missing_manifest_eval_profile.matches_relation_metadata(&relation),
        "missing K1b manifest evaluation claim must reject the authority profile"
    );
    let mut non_zk_product_profile = research_profile.clone();
    non_zk_product_profile.product_eligible = true;
    non_zk_product_profile.research_only = false;
    non_zk_product_profile.routing_status = Symbt3RoutingStatus::ProductAuthority;
    assert!(
        !non_zk_product_profile.accepts_relation_for_product_authority(&relation),
        "any product-eligible profile must reject NonZk"
    );
    let mut missing_j2_profile = research_profile.clone();
    missing_j2_profile.enabled_families.retain(|family| {
        *family
            != symphony::batched_cp::BatchedCpSymbt3ConstraintFamily::ProjectedOpeningMonomialEmbedding
    });
    assert!(
        !missing_j2_profile.matches_relation_metadata(&relation),
        "missing J2 families must reject both research and product authority profiles"
    );

    let relation_description = relation.to_relation_description();
    assert_eq!(relation_description.num_constraints, 0);
    assert_eq!(
        relation_description.num_instance_vars,
        public.canonical_bytes().len()
    );
    assert!(relation_description.num_witness_vars > 0);
    let context = relation_description
        .context
        .as_ref()
        .expect("SYMBT3 context");
    let decoded = BatchedCpSymbt3RelationDescription::from_context_bytes(context).unwrap();
    assert_eq!(decoded, relation);
    assert_ne!(
        relation.relation_id(),
        bucket.shape.structured_relation_description().relation_id()
    );
    assert_ne!(
        relation.relation_id(),
        bucket
            .shape
            .semantic_v2_relation_description(&prover.ajtai, &r1cs, prover.params.b_input())
            .semantic_relation_id()
    );
    assert_ne!(
        relation.relation_id(),
        bucket
            .shape
            .semantic_family_columnar_v2_relation_description(
                &prover.ajtai,
                &r1cs,
                prover.params.b_input()
            )
            .semantic_relation_id()
    );

    let challenge_digest = derive_symbt3_batch_challenge_digest(&relation, &public);
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &public)
    );
    let public_statement_digest = derive_symbt3_public_statement_digest(&relation, &public);
    let mut changed_public = public.clone();
    changed_public.message_oracle_roots[0][0] ^= 1;
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_public)
    );
    let round_challenges = derive_symbt3_round_challenges(&relation, &public);
    let mut changed_later_round = public.clone();
    if changed_later_round.message_oracle_roots.len() > 1 {
        changed_later_round.message_oracle_roots[1][0] ^= 1;
        let changed_round_challenges =
            derive_symbt3_round_challenges(&relation, &changed_later_round);
        assert_eq!(
            round_challenges[0], changed_round_challenges[0],
            "prefix round challenge 0 must not depend on later message roots"
        );
    }
    let mut changed_manifest_root = public.clone();
    changed_manifest_root.batch_manifest_root[0] ^= 1;
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_manifest_root),
        "batch manifest root is input-side data and must affect beta"
    );
    let mut changed_folded = public.clone();
    changed_folded.folded_public_input[0] += 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_folded),
        "folding beta must not depend on output/folded public input"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_folded)
    );
    let mut changed_commitment = public.clone();
    changed_commitment.folded_commitment[0] += 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_commitment),
        "folding beta must not depend on folded commitment/output data"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_commitment)
    );
    let mut changed_folded_ajtai = public.clone();
    changed_folded_ajtai.folded_ajtai_commitment[0] += 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_folded_ajtai),
        "folding beta must not depend on folded Ajtai output data"
    );
    assert!(!changed_folded_ajtai.matches_relation(&relation));
    let mut changed_source_ajtai_root = public.clone();
    changed_source_ajtai_root.source_ajtai_opening_roots[0][0] ^= 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_source_ajtai_root),
        "SYMBT3-K1 keeps private source Ajtai opening roots out of the compressed beta transcript"
    );
    let mut changed_source_assignment_root = public.clone();
    changed_source_assignment_root.source_assignment_roots[0][0] ^= 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_source_assignment_root),
        "SYMBT3-K1 beta binds the source assignment boundary digest, not every root"
    );
    let mut changed_source_assignment_boundary = public.clone();
    changed_source_assignment_boundary.source_assignment_boundary_digest[0] ^= 1;
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_source_assignment_boundary),
        "the compressed source assignment boundary digest must remain beta-bound"
    );
    let mut changed_evaluation = public.clone();
    changed_evaluation.folded_evaluation[0] += 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_evaluation),
        "folding beta must not depend on folded evaluation/output data"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_evaluation)
    );
    let mut changed_gr1cs_boundary = public.clone();
    changed_gr1cs_boundary.folded_gr1cs_boundary_digest[0] ^= 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_gr1cs_boundary),
        "folding beta must not depend on folded GR1CS output data"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_gr1cs_boundary)
    );
    let mut changed_norm_range_public = public.clone();
    changed_norm_range_public.norm_range_public_digest[0] ^= 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_norm_range_public),
        "SYMBT3-J projection/range public data must not alter beta"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_norm_range_public),
        "SYMBT3-J projection/range public data must alter the proof public digest"
    );
    let mut changed_accumulator = public.clone();
    changed_accumulator.folded_accumulator_coordinates[0] += 1;
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&relation, &changed_accumulator),
        "folding beta must not depend on algebraic accumulator output data"
    );
    assert_ne!(
        public_statement_digest,
        derive_symbt3_public_statement_digest(&relation, &changed_accumulator)
    );
    let mut wrong_shape_public = public.clone();
    wrong_shape_public.shape_id[0] ^= 1;
    assert!(!wrong_shape_public.matches_relation(&relation));

    let mut changed_ajtai = prover.ajtai.clone();
    changed_ajtai.a[0][0].coeffs[0] += 1;
    let changed_relation = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &changed_ajtai,
        &r1cs,
        prover.params.b_input(),
    )
    .relation_description();
    assert_ne!(
        relation.ajtai_params_digest,
        changed_relation.ajtai_params_digest
    );
    assert_ne!(relation.relation_id(), changed_relation.relation_id());

    let mut changed_ring_relation = relation.clone();
    changed_ring_relation.ring_module_layout.action_side = Symbt3RingActionSide::Left;
    changed_ring_relation.ring_module_layout.ring_action_version += 1;
    assert_ne!(relation.relation_id(), changed_ring_relation.relation_id());
    let mut changed_r1cs_layout_relation = relation.clone();
    changed_r1cs_layout_relation
        .r1cs_evaluator_layout
        .layout_version += 1;
    assert_ne!(
        relation.relation_id(),
        changed_r1cs_layout_relation.relation_id()
    );
    let mut changed_gr1cs_layout_relation = relation.clone();
    changed_gr1cs_layout_relation
        .gr1cs_residual_layout
        .layout_version += 1;
    assert_ne!(
        relation.relation_id(),
        changed_gr1cs_layout_relation.relation_id()
    );
    let mut changed_algebra_law_relation = relation.clone();
    changed_algebra_law_relation.algebra_law.product_law = Symbt3ProductLawId::FieldCoordinateMulV1;
    assert_ne!(
        relation.relation_id(),
        changed_algebra_law_relation.relation_id()
    );
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_algebra_law_relation, &public),
        "algebra law changes that alter folding semantics must alter beta"
    );
    let mut changed_ajtai_linear_layout_relation = relation.clone();
    changed_ajtai_linear_layout_relation
        .ajtai_linear_algebra_layout
        .layout_version += 1;
    assert_ne!(
        relation.relation_id(),
        changed_ajtai_linear_layout_relation.relation_id()
    );
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_ajtai_linear_layout_relation, &public),
        "Ajtai algebra layout changes that alter folding semantics must alter beta"
    );
    let mut changed_norm_range_relation = relation.clone();
    changed_norm_range_relation
        .ajtai_norm_range_layout
        .range_layout
        .bound_b += 1;
    changed_norm_range_relation
        .ajtai_norm_range_layout
        .norm_bound += 1;
    assert_ne!(
        relation.relation_id(),
        changed_norm_range_relation.relation_id()
    );
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_norm_range_relation, &public),
        "SYMBT3-J norm/range semantics are part of the folding protocol identity"
    );
    let mut changed_structured_projection_relation = relation.clone();
    changed_structured_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .block_len += 1;
    assert_ne!(
        relation.relation_id(),
        changed_structured_projection_relation.relation_id(),
        "SYMBT3-J structured projection layout is relation-bound"
    );
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_structured_projection_relation, &public),
        "SYMBT3-J structured projection semantics are beta-bound"
    );
    let mut changed_manifest_relation = relation.clone();
    changed_manifest_relation
        .batch_manifest_layout
        .component_kinds[0]
        .coordinate_len += 1;
    changed_manifest_relation
        .batch_manifest_layout
        .manifest_oracle_layout
        .coordinate_count += 1;
    changed_manifest_relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count += 1;
    assert_ne!(
        relation.relation_id(),
        changed_manifest_relation.relation_id()
    );
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_manifest_relation, &public),
        "SYMBT3-H manifest/source layout semantics are part of the folding protocol identity"
    );
    let mut changed_message_relation = relation.clone();
    changed_message_relation
        .message_semantic_layout
        .round_layouts[0]
        .sections[0]
        .coordinate_len += 1;
    assert_ne!(
        relation.relation_id(),
        changed_message_relation.relation_id()
    );
    assert_ne!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_message_relation, &public),
        "SYMBT3-I message semantic layout is part of the folding protocol identity"
    );
    let mut changed_view_relation = relation.clone();
    changed_view_relation.message_semantic_layout.round_layouts[0].message_views[0]
        .message_coordinate_map
        .message_coordinate_offset += 1;
    assert_ne!(
        relation.relation_id(),
        changed_view_relation.relation_id(),
        "SYMBT3-I2 message view maps are relation-bound evaluator metadata"
    );
    let mut changed_product_layout_relation = relation.clone();
    changed_product_layout_relation
        .folded_gr1cs_product_residual_layout
        .layout_version += 1;
    assert_ne!(
        relation.relation_id(),
        changed_product_layout_relation.relation_id()
    );
    assert_eq!(
        challenge_digest,
        derive_symbt3_batch_challenge_digest(&changed_product_layout_relation, &public),
        "D2 proof-relation layout changes must not alter the folding beta"
    );

    let mut changed_r1cs = r1cs.clone();
    changed_r1cs.a.insert(0, 0, 1);
    let changed_relation = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &changed_r1cs,
        prover.params.b_input(),
    )
    .relation_description();
    assert_ne!(
        relation.r1cs_matrices_digest,
        changed_relation.r1cs_matrices_digest
    );
    assert_ne!(relation.relation_id(), changed_relation.relation_id());

    let mut tampered = context.clone();
    tampered[0] ^= 1;
    assert_eq!(
        BatchedCpSymbt3RelationDescription::from_context_bytes(&tampered).unwrap_err(),
        BatchedCpError::InvalidSemanticRelationContext
    );
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_backend_hooks_prove_first_algebraic_block_and_reject_tampering() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
        .expect("WHIR exposes SYMBT3 relation shell");
    assert_eq!(relation.num_constraints, 0);

    let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
    let decoded_relation =
        BatchedCpSymbt3RelationDescription::from_context_bytes(relation.context.as_ref().unwrap())
            .unwrap();
    let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
    let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
    assert_eq!(
        decoded_relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
        0,
        "SYMBT3-I2 must not allocate duplicate TraceValue columns for direct message views"
    );
    let proof = <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &witness)
        .expect("SYMBT3-I2 proof");
    assert_eq!(
        public.folded_ajtai_commitment,
        decoded_relation.derive_ring_folded_commitment_boundary(&public)
    );
    assert_eq!(
        proof.family_columnar_subproofs.len(),
        0,
        "SYMBT3-I2 must stay one top-level proof object, not a table-proof forest"
    );
    assert!(
        proof.num_vars <= 14,
        "SYMBT3-K1e.2 must keep the k=2 default profile in the compact backend bucket"
    );
    assert_eq!(
        proof.private_opening_evals.len(),
        15,
        "SYMBT3-K1e.2 must not open a materialized source-view or dense manifest column"
    );
    let source_view_backend_column_count = 0usize;
    let source_view_materialized_coordinate_count = 0usize;
    let manifest_backend_column_count = 0usize;
    let manifest_materialized_coordinate_count = 0usize;
    assert_eq!(source_view_backend_column_count, 0);
    assert_eq!(source_view_materialized_coordinate_count, 0);
    assert_eq!(manifest_backend_column_count, 0);
    assert_eq!(manifest_materialized_coordinate_count, 0);
    let projected_opening_eval_idx = 10;
    let projection_residual_eval_idx = 11;
    let range_residual_eval_idx = 12;
    let monomial_residual_eval_idx = 13;
    let first_product_sumcheck_eval_idx = 14;
    assert_eq!(
        first_product_sumcheck_eval_idx,
        proof.private_opening_evals.len() - 1,
        "SYMBT3-K1e.2 places product-sumcheck openings after the base table columns"
    );
    assert!(!proof.sumcheck_rounds_4.is_empty());
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    let mut changed_table_relation = decoded_relation.clone();
    changed_table_relation
        .ajtai_norm_range_layout
        .range_layout
        .table_digest
        .as_mut()
        .expect("monomial range table digest")[0] ^= 1;
    let changed_table_backend_relation = changed_table_relation.to_relation_description();
    let (_changed_table_pk, changed_table_vk) =
        <WhirSnark as CpBackend>::setup(&changed_table_backend_relation);
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&changed_table_vk, &public, &proof),
        Some(false),
        "K3 must reject stale proofs under a changed t_B table digest/profile"
    );
    let accumulator_transition_claims = 1usize;
    assert_eq!(
        accumulator_transition_claims, 1,
        "K2b accumulator transition must remain one constant-size claim, not O(k)"
    );
    let mut changed_old_accumulator_digest = public.clone();
    changed_old_accumulator_digest.old_accumulator_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_old_accumulator_digest,
            &proof
        ),
        Some(false),
        "K2a old accumulator digest is transcript-bound public statement data"
    );
    let mut changed_new_accumulator_digest = public.clone();
    changed_new_accumulator_digest.new_accumulator_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_new_accumulator_digest,
            &proof
        ),
        Some(false),
        "K2a new accumulator digest is transcript-bound public statement data"
    );
    let mut changed_old_accumulator_coordinate = public.clone();
    changed_old_accumulator_coordinate.old_accumulator_coordinates[0] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_old_accumulator_coordinate,
            &proof
        ),
        Some(false),
        "K2b old accumulator coordinates must match their digest and transition law"
    );
    let mut changed_new_accumulator_coordinate = public.clone();
    changed_new_accumulator_coordinate.new_accumulator_coordinates[0] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_new_accumulator_coordinate,
            &proof
        ),
        Some(false),
        "K2b new accumulator coordinates must satisfy new = rho*old + (1-rho)*folded"
    );
    let mut changed_shape_id = public.clone();
    changed_shape_id.shape_id[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_shape_id, &proof),
        Some(false),
        "K2b rho_acc and statement matching must bind shape_id"
    );
    let authority_profile =
        Symbt3AuthorityProfile::authority_candidate_from_relation(&decoded_relation, 128);
    assert_eq!(
        WhirSnark::verify_symbt3_authority_profile(&vk, &public, &proof, &authority_profile),
        Some(false),
        "a proof made under the current development SYMBT3 profile must be rejected by the authority gate"
    );
    let research_profile =
        Symbt3AuthorityProfile::research_authority_candidate_from_relation(&decoded_relation, 64);
    assert_eq!(
        WhirSnark::verify_symbt3_research_authority_candidate(
            &vk,
            &public,
            &proof,
            &research_profile
        ),
        Some(true),
        "SYMBT3-J2 proofs may pass the explicit non-ZK research authority-candidate gate"
    );
    assert_eq!(
        WhirSnark::verify_symbt3_authority_profile(&vk, &public, &proof, &research_profile),
        Some(false),
        "research-only profiles must not pass the ProductAuthority gate"
    );
    let accumulator_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &decoded_relation,
            64,
        );
    assert_eq!(
        WhirSnark::verify_symbt3_accumulator_soundness_authority_candidate(
            &vk,
            &public,
            &proof,
            &accumulator_profile
        ),
        Some(true),
        "K3 version-1 accumulator soundness candidates remain research-only but can pass the K3 gate"
    );
    assert_eq!(
        WhirSnark::verify_symbt3_accumulator_soundness_authority_candidate(
            &vk,
            &public,
            &proof,
            &research_profile
        ),
        Some(false),
        "K3 accumulator gate must reject semantic_profile_version=0 profiles"
    );
    let mut bad_source_opening = witness.clone();
    bad_source_opening.source_ajtai_opening_values[0][0] += 1;
    assert!(
        <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &bad_source_opening)
            .is_none(),
        "source Ajtai opening tampering must break the folded opening identity"
    );
    let mut bad_folded_opening = witness.clone();
    bad_folded_opening.folded_ajtai_opening_values[0] += 1;
    assert!(
        <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &bad_folded_opening)
            .is_none(),
        "folded Ajtai opening tampering must break the folded opening identity"
    );
    let mut bad_range_opening = witness.clone();
    bad_range_opening.folded_ajtai_opening_values[0] =
        decoded_relation.ajtai_norm_range_layout.norm_bound + 1;
    assert!(
        <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &bad_range_opening)
            .is_none(),
        "SYMBT3-J folded Ajtai range violations must reject in the development proof"
    );
    let mut bad_source_assignment = witness.clone();
    bad_source_assignment.source_r1cs_assignment_values[0][0] += 1;
    assert!(
        <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &bad_source_assignment)
            .is_none(),
        "source assignment tampering must be root-bound before beta and residual checks"
    );
    assert!(
        witness.manifest_source_values.is_empty(),
        "SYMBT3-K1e has no private manifest witness components"
    );
    let mut bad_message = witness.clone();
    bad_message.message_oracles[0][0][0] ^= 1;
    assert!(
        <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &bad_message).is_none(),
        "SYMBT3-I2 message oracle coordinate tampering must reject against the public message root"
    );

    let mut changed_output = public.clone();
    changed_output.folded_public_input[0] += 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_output),
        "folding beta must remain input-transcript only"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_output, &proof),
        Some(false)
    );
    let mut changed_commitment = public.clone();
    changed_commitment.folded_commitment[0] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_commitment, &proof),
        Some(false)
    );
    let mut changed_ajtai_commitment = public.clone();
    changed_ajtai_commitment.folded_ajtai_commitment[0] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_ajtai_commitment, &proof),
        Some(false)
    );
    let mut changed_folded_opening_root = public.clone();
    changed_folded_opening_root.folded_ajtai_opening_root[0] ^= 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_folded_opening_root),
        "folded Ajtai opening/range output data must not alter beta"
    );
    assert_ne!(
        derive_symbt3_public_statement_digest(&decoded_relation, &public),
        derive_symbt3_public_statement_digest(&decoded_relation, &changed_folded_opening_root),
        "folded Ajtai opening/range output data must alter the proof public digest"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_folded_opening_root,
            &proof
        ),
        Some(false)
    );
    let mut changed_norm_range_public = public.clone();
    changed_norm_range_public.norm_range_public_digest[0] ^= 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_norm_range_public),
        "SYMBT3-J norm/range public digest must not alter beta"
    );
    assert_ne!(
        derive_symbt3_public_statement_digest(&decoded_relation, &public),
        derive_symbt3_public_statement_digest(&decoded_relation, &changed_norm_range_public),
        "SYMBT3-J norm/range public digest must alter proof public digest"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_norm_range_public, &proof),
        Some(false)
    );
    let mut changed_representative_layout = public.clone();
    changed_representative_layout.representative_layout_digest[0] ^= 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_representative_layout),
        "SYMBT3-J representative convention/output digest data must not alter beta"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_representative_layout,
            &proof
        ),
        Some(false),
        "tampering the representative convention digest must reject"
    );
    let mut changed_evaluation = public.clone();
    changed_evaluation.folded_evaluation[0] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_evaluation, &proof),
        Some(false)
    );
    let product_len = decoded_relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count
        / 3;
    let mut changed_product_r = public.clone();
    changed_product_r.folded_evaluation[product_len] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_product_r, &proof),
        Some(false),
        "tampering R_fold must reject"
    );
    let mut changed_product_o = public.clone();
    changed_product_o.folded_evaluation[2 * product_len] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_product_o, &proof),
        Some(false),
        "tampering O_fold must reject"
    );
    let mut changed_gr1cs_boundary = public.clone();
    changed_gr1cs_boundary.folded_gr1cs_boundary_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_gr1cs_boundary, &proof),
        Some(false)
    );
    let mut changed_accumulator = public.clone();
    changed_accumulator.folded_accumulator_coordinates[0] += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_accumulator, &proof),
        Some(false)
    );

    let mut changed_root = public.clone();
    changed_root.message_oracle_roots[0][0] ^= 1;
    assert_ne!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_root)
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_root, &proof),
        Some(false)
    );
    let mut changed_message_layout = public.clone();
    changed_message_layout.message_semantic_layout_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_message_layout, &proof),
        Some(false)
    );
    let mut changed_manifest_root = public.clone();
    changed_manifest_root.batch_manifest_root[0] ^= 1;
    assert_ne!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_manifest_root),
        "SYMBT3-H batch manifest root must be input-side beta-bound"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_manifest_root, &proof),
        Some(false)
    );
    let mut changed_manifest_eval_claim = public.clone();
    changed_manifest_eval_claim.manifest_eval_claim = changed_manifest_eval_claim
        .manifest_eval_claim
        .wrapping_add(1);
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_manifest_eval_claim),
        "K1b manifest eval claim must not alter input-side beta"
    );
    assert_ne!(
        derive_symbt3_public_statement_digest(&decoded_relation, &public),
        derive_symbt3_public_statement_digest(&decoded_relation, &changed_manifest_eval_claim),
        "K1b manifest eval claim must alter proof public digest"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_manifest_eval_claim,
            &proof
        ),
        Some(false),
        "tampering the K1b manifest eval claim must reject"
    );
    let mut changed_manifest_oracle_root = public.clone();
    changed_manifest_oracle_root.manifest_oracle_root[0] ^= 1;
    assert_eq!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_manifest_oracle_root),
        "K1a manifest oracle root is linked through batch_manifest_root, not the beta transcript directly"
    );
    assert_ne!(
        derive_symbt3_manifest_membership_challenge(
            &decoded_relation,
            &public,
            &public.manifest_oracle_root
        ),
        derive_symbt3_manifest_membership_challenge(
            &decoded_relation,
            &changed_manifest_oracle_root,
            &changed_manifest_oracle_root.manifest_oracle_root
        ),
        "K1b manifest oracle root must alter the verifier-derived membership challenge"
    );
    assert_ne!(
        derive_symbt3_public_statement_digest(&decoded_relation, &public),
        derive_symbt3_public_statement_digest(&decoded_relation, &changed_manifest_oracle_root),
        "K1a manifest oracle root must alter the proof public digest"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &changed_manifest_oracle_root,
            &proof
        ),
        Some(false),
        "tampering the K1a manifest oracle root must reject"
    );
    let mut relinked_wrong_manifest_oracle_root = changed_manifest_oracle_root.clone();
    relinked_wrong_manifest_oracle_root.batch_manifest_root =
        symbt3_batch_manifest_root_from_oracle_root(
            bucket.shape.accumulator_shape.digest_scheme,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            &relinked_wrong_manifest_oracle_root.batch_manifest_layout_digest,
            &relinked_wrong_manifest_oracle_root.manifest_oracle_root,
        );
    assert!(
        !relinked_wrong_manifest_oracle_root.matches_relation(&decoded_relation),
        "K1 verifier must reject a root-linked but non-canonical manifest oracle root"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &relinked_wrong_manifest_oracle_root,
            &proof
        ),
        Some(false),
        "relinking batch_manifest_root to a wrong manifest_oracle_root must still reject"
    );
    let mut changed_manifest_layout = public.clone();
    changed_manifest_layout.batch_manifest_layout_digest[0] ^= 1;
    assert_ne!(
        derive_symbt3_batch_challenge_digest(&decoded_relation, &public),
        derive_symbt3_batch_challenge_digest(&decoded_relation, &changed_manifest_layout),
        "batch manifest layout digest is input-side data and must affect beta"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_manifest_layout, &proof),
        Some(false),
        "tampering the K1a manifest layout digest must reject"
    );
    let mut changed_source_layout = public.clone();
    changed_source_layout.source_column_layout_digest[0] ^= 1;
    assert_ne!(
        derive_symbt3_manifest_membership_challenge(
            &decoded_relation,
            &public,
            &public.manifest_oracle_root
        ),
        derive_symbt3_manifest_membership_challenge(
            &decoded_relation,
            &changed_source_layout,
            &changed_source_layout.manifest_oracle_root
        ),
        "K1b source layout digest must alter the verifier-derived membership challenge"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_source_layout, &proof),
        Some(false),
        "tampering the K1b source layout digest must reject"
    );

    let mut changed_input = public.clone();
    changed_input.input_public_values[0][0] += 1;
    changed_input.input_public_boundary_digest = digest_domain_with_scheme(
        PublicDigestScheme::Poseidon2BabyBear,
        b"bad-symbt3-input-public-boundary",
        b"tampered",
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_input, &proof),
        Some(false)
    );
    let mut changed_source_commitment = public.clone();
    changed_source_commitment.input_commitment_values[0][0] += 1;
    changed_source_commitment.input_public_boundary_digest = digest_domain_with_scheme(
        PublicDigestScheme::Poseidon2BabyBear,
        b"bad-symbt3-input-public-boundary",
        b"tampered-commitment",
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_source_commitment, &proof),
        Some(false)
    );
    let mut changed_source_evaluation = public.clone();
    changed_source_evaluation.input_evaluation_values[0][0] += 1;
    changed_source_evaluation.input_public_boundary_digest = digest_domain_with_scheme(
        PublicDigestScheme::Poseidon2BabyBear,
        b"bad-symbt3-input-public-boundary",
        b"tampered-evaluation",
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &changed_source_evaluation, &proof),
        Some(false)
    );

    let mut tampered_private_eval = proof.clone();
    tampered_private_eval.private_opening_evals[0] += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_private_eval),
        Some(false)
    );
    let mut tampered_projected_eval = proof.clone();
    tampered_projected_eval.private_opening_evals[projected_opening_eval_idx] += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_projected_eval),
        Some(false),
        "tampering the projected opening value must reject; it is recomputed by the evaluator"
    );
    let mut tampered_projection_residual = proof.clone();
    tampered_projection_residual.private_opening_evals[projection_residual_eval_idx] +=
        BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &public,
            &tampered_projection_residual
        ),
        Some(false),
        "projection residual openings are constrained, not trusted as witness advice"
    );
    let mut tampered_range_residual = proof.clone();
    tampered_range_residual.private_opening_evals[range_residual_eval_idx] += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_range_residual),
        Some(false),
        "range residual openings are constrained by verifier-side range evaluation"
    );
    let mut tampered_monomial_residual = proof.clone();
    tampered_monomial_residual.private_opening_evals[monomial_residual_eval_idx] += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(
            &vk,
            &public,
            &tampered_monomial_residual
        ),
        Some(false),
        "monomial/range residual openings are constrained even though the deterministic monomial witness column was removed"
    );
    let mut tampered_residual_eval = proof.clone();
    let last_eval = tampered_residual_eval
        .private_opening_evals
        .last_mut()
        .expect("SYMBT3-D residual private eval");
    *last_eval += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_residual_eval),
        Some(false)
    );
    let mut tampered_sumcheck = proof.clone();
    tampered_sumcheck.sumcheck_rounds_4[0][0] += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_sumcheck),
        Some(false),
        "wrong D2 product sumcheck round polynomial must reject"
    );

    let mut tampered_z = proof.clone();
    tampered_z.z_eval += BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_z),
        Some(false)
    );

    let mut tampered_num_vars = proof.clone();
    tampered_num_vars.num_vars += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &tampered_num_vars),
        Some(false)
    );

    let betas = derive_symbt3_beta_coefficients(&decoded_relation, &public);
    assert!(betas.iter().all(|beta| (-2..=2).contains(beta)));
    let beta_rings = derive_symbt3_beta_ring_elements(&decoded_relation, &public);
    assert_eq!(beta_rings.len(), public.batch_capacity);
    assert!(beta_rings
        .iter()
        .flat_map(|beta| beta.coeffs.iter())
        .all(|coeff| (-2..=2).contains(coeff)));

    let non_symbt3_proof = WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: Vec::new(),
        evaluations: [BabyBear::ZERO, BabyBear::ZERO, BabyBear::ZERO],
        whir_pcs_proof: Default::default(),
        z_eval: BabyBear::ZERO,
        linear_checks: Vec::new(),
        private_opening_evals: vec![BabyBear::ONE],
        family_columnar_subproofs: Vec::new(),
        num_vars: 1,
        is_output: false,
    };
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &non_symbt3_proof),
        Some(false),
        "non-SYMBT3 proof payloads must not be accepted as SYMBT3"
    );
    assert_eq!(
        WhirSnark::verify_symbt3_authority_profile(
            &vk,
            &public,
            &non_symbt3_proof,
            &authority_profile
        ),
        Some(false),
        "SYMBT2/SYMBTC/monolithic-shaped payloads must not be accepted as SYMBT3 authority"
    );
    assert_eq!(
        WhirSnark::verify_symbt3_research_authority_candidate(
            &vk,
            &public,
            &non_symbt3_proof,
            &research_profile
        ),
        Some(false),
        "non-SYMBT3 payloads must not be accepted as SYMBT3 research authority candidates"
    );
    assert_eq!(
        WhirSnark::verify_symbt3_accumulator_soundness_authority_candidate(
            &vk,
            &public,
            &non_symbt3_proof,
            &accumulator_profile
        ),
        Some(false),
        "non-SYMBT3 payloads must not be accepted as SYMBT3 accumulator soundness authority candidates"
    );
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_k4_research_public_accumulator_api_accepts_v1_and_rejects_wrong_routes() {
    let (prover, r1cs, mut items) = build_fixture();
    let (_r1cs_again, z) = common::multi_r1cs();
    items.push(make_batched_item(&prover, &r1cs, &z, 4));
    let bucket = BatchedCpBucket::new(items, whir_parameter_digest()).unwrap();
    assert_eq!(bucket.shape.active_count, 4);
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
        .expect("WHIR exposes SYMBT3 relation shell");
    let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
    let decoded_relation =
        BatchedCpSymbt3RelationDescription::from_context_bytes(relation.context.as_ref().unwrap())
            .unwrap();
    let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
    let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
    let profile = Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
        &decoded_relation,
        64,
    );
    assert!(
        profile.accepts_statement_for_accumulator_soundness_authority_candidate(
            &decoded_relation,
            &public,
        )
    );
    assert_eq!(profile.semantic_profile_version, 1);
    assert_eq!(profile.routing_status, Symbt3RoutingStatus::ResearchOnly);
    assert!(!profile.product_eligible);
    assert_eq!(profile.zk_status, Symbt3ZkStatus::NonZkDevelopment);

    let profile_digest = profile.digest(bucket.shape.accumulator_shape.digest_scheme);
    let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        bucket.shape.accumulator_shape.digest_scheme,
        profile_digest,
        public.old_accumulator_digest,
        public.new_accumulator_digest,
        &public,
    );
    let statement_from_instance = accumulator_instance.to_public_statement();
    assert_eq!(
        statement_from_instance.old_accumulator_digest,
        public.old_accumulator_digest
    );
    assert_eq!(
        statement_from_instance.new_accumulator_digest,
        public.new_accumulator_digest
    );
    assert_eq!(
        statement_from_instance.batch_manifest_root,
        public.batch_manifest_root
    );
    assert_eq!(
        statement_from_instance.source_column_layout_digest,
        public.source_column_layout_digest
    );
    assert_eq!(
        statement_from_instance.message_oracle_roots,
        public.message_oracle_roots
    );
    assert_eq!(
        statement_from_instance.folded_output_accumulator_root,
        public.folded_output_accumulator_root
    );
    assert_eq!(
        statement_from_instance.folded_gr1cs_boundary_digest,
        public.folded_gr1cs_boundary_digest
    );
    assert_eq!(
        statement_from_instance.folded_ajtai_commitment,
        public.folded_ajtai_commitment
    );
    assert_eq!(
        statement_from_instance.folded_ajtai_opening_root,
        public.folded_ajtai_opening_root
    );
    assert_eq!(
        statement_from_instance.whir_parameter_digest,
        public.whir_parameter_digest
    );
    assert_ne!(accumulator_instance.batch_items_digest, [0u8; 32]);
    assert_ne!(
        accumulator_instance.public_source_boundary_digest,
        [0u8; 32]
    );
    assert_ne!(
        accumulator_instance.source_assignment_roots_digest,
        [0u8; 32]
    );
    assert_ne!(accumulator_instance.message_oracle_roots_digest, [0u8; 32]);
    assert!(accumulator_instance.matches_profile_and_relation(&profile, &decoded_relation));

    let mut compressed_boundary_sizes = Vec::new();
    let (_r1cs_for_sizes, z_for_sizes) = common::multi_r1cs();
    for k in [1usize, 2, 4, 8] {
        let sized_items = (0..k)
            .map(|idx| make_batched_item(&prover, &r1cs, &z_for_sizes, (idx + 1) as u8))
            .collect::<Vec<_>>();
        let sized_bucket = BatchedCpBucket::new(sized_items, whir_parameter_digest()).unwrap();
        let sized_descriptor = BatchedCpSymbt3SetupDescriptor::new(
            sized_bucket.shape.clone(),
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );
        let sized_relation =
            <WhirSnark as CpBackend>::symbt3_relation_description(&sized_descriptor)
                .expect("WHIR exposes sized SYMBT3 relation shell");
        let sized_decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
            sized_relation.context.as_ref().unwrap(),
        )
        .unwrap();
        let sized_public =
            sized_bucket.symbt3_public_statement_for_relation(&sized_decoded_relation);
        let sized_profile =
            Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
                &sized_decoded_relation,
                64,
            );
        let sized_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
            sized_bucket.shape.accumulator_shape.digest_scheme,
            sized_profile.digest(sized_bucket.shape.accumulator_shape.digest_scheme),
            sized_public.old_accumulator_digest,
            sized_public.new_accumulator_digest,
            &sized_public,
        );
        assert!(
            sized_instance.matches_profile_and_relation(&sized_profile, &sized_decoded_relation)
        );
        compressed_boundary_sizes.push((k, sized_instance.canonical_bytes().len()));
    }
    for window in compressed_boundary_sizes.windows(2) {
        let (prev_k, prev_len) = window[0];
        let (next_k, next_len) = window[1];
        assert!(
            next_len * 100 <= prev_len * 125,
            "K4.6 compressed accumulator boundary must stay near-flat: k={prev_k} len={prev_len}, k={next_k} len={next_len}"
        );
    }

    let accumulator_witness =
        Symbt3AccumulatorWitness::from_symbt3_witness(&decoded_relation, &witness);
    assert_eq!(
        accumulator_witness
            .to_symbt3_witness(&decoded_relation)
            .expect("typed accumulator witness converts to SYMBT3 witness"),
        witness
    );
    let proof = WhirSnark::prove_public_symbt3_accumulator_research_non_zk(
        &pk,
        &profile,
        &accumulator_instance,
        &accumulator_witness,
    )
    .expect("K4 NonZK research accumulator proof");
    assert!(WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
        &vk,
        &profile,
        &accumulator_instance,
        &proof,
    ));
    let (_, verifier_profile) = WhirSnark::profile_symbt3_batched_cp_verifier(&vk, &public, &proof)
        .expect("K4 verifier profile");
    assert_eq!(
        verifier_profile.source_r1cs_residual_claims,
        public.source_assignment_roots.len()
            * decoded_relation.r1cs_evaluator_layout.num_constraints
            * D,
        "K4.5 keeps source R1CS residual coverage visible as logical claims"
    );
    assert_eq!(
        verifier_profile.source_r1cs_residual_verifier_evaluations, 1,
        "K4.5 batches source R1CS residual verification to one MLE evaluation"
    );
    assert_eq!(proof.family_columnar_subproofs.len(), 0);
    assert!(!proof.is_output);
    assert_eq!(
        decoded_relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
        0
    );
    assert!(decoded_relation.has_symbt3_k2_families());
    assert_eq!(
        proof.private_opening_evals.len(),
        15,
        "K4 must preserve the K1e.2/K2 one-table proof shape"
    );
    assert_eq!(
        <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &proof),
        Some(true),
        "K4 delegates to the existing SYMBT3 proof verifier, not product verify_public"
    );
    assert_eq!(
        WhirSnark::verify_symbt3_authority_profile(
            &vk,
            &public,
            &proof,
            &Symbt3AuthorityProfile::authority_candidate_from_relation(&decoded_relation, 128),
        ),
        Some(false),
        "K4 proofs must not pass ProductAuthority before K6"
    );

    let product_profile =
        Symbt3AuthorityProfile::authority_candidate_from_relation(&decoded_relation, 128);
    assert!(WhirSnark::prove_public_symbt3_accumulator_research_non_zk(
        &pk,
        &product_profile,
        &accumulator_instance,
        &accumulator_witness,
    )
    .is_none());
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &product_profile,
            &accumulator_instance,
            &proof,
        )
    );

    let mut product_eligible_profile = profile.clone();
    product_eligible_profile.product_eligible = true;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &product_eligible_profile,
            &accumulator_instance,
            &proof,
        )
    );

    let research_v0_profile =
        Symbt3AuthorityProfile::research_authority_candidate_from_relation(&decoded_relation, 64);
    let research_v0_digest =
        research_v0_profile.digest(bucket.shape.accumulator_shape.digest_scheme);
    let research_v0_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        bucket.shape.accumulator_shape.digest_scheme,
        research_v0_digest,
        public.old_accumulator_digest,
        public.new_accumulator_digest,
        &public,
    );
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &research_v0_profile,
            &research_v0_instance,
            &proof,
        )
    );

    let mut missing_manifest_profile = profile.clone();
    missing_manifest_profile
        .enabled_families
        .retain(|family| *family != BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim);
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &missing_manifest_profile,
            &accumulator_instance,
            &proof,
        )
    );

    let mut missing_transition_profile = profile.clone();
    missing_transition_profile
        .enabled_families
        .retain(|family| {
            *family != BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency
        });
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &missing_transition_profile,
            &accumulator_instance,
            &proof,
        )
    );

    let mut zk_required_profile = profile.clone();
    zk_required_profile.zk_status = Symbt3ZkStatus::ZkRequiredForProductRoute;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &zk_required_profile,
            &accumulator_instance,
            &proof,
        )
    );

    for mutate in [
        "old_accumulator_digest",
        "new_accumulator_digest",
        "profile_digest",
        "batch_manifest_root",
        "folded_output_boundary_digest",
        "message_oracle_root",
        "message_oracle_roots_digest",
        "source_assignment_root",
        "source_assignment_roots_digest",
        "batch_items_digest",
    ] {
        let mut changed = accumulator_instance.clone();
        match mutate {
            "old_accumulator_digest" => changed.old_accumulator_digest[0] ^= 1,
            "new_accumulator_digest" => changed.new_accumulator_digest[0] ^= 1,
            "profile_digest" => changed.profile_digest[0] ^= 1,
            "batch_manifest_root" => changed.manifest_root[0] ^= 1,
            "folded_output_boundary_digest" => changed.folded_output_boundary_digest[0] ^= 1,
            "message_oracle_root" => changed.message_oracle_roots[0][0] ^= 1,
            "message_oracle_roots_digest" => changed.message_oracle_roots_digest[0] ^= 1,
            "source_assignment_root" => changed.source_assignment_roots[0][0] ^= 1,
            "source_assignment_roots_digest" => changed.source_assignment_roots_digest[0] ^= 1,
            "batch_items_digest" => changed.batch_items_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
                &vk, &profile, &changed, &proof,
            ),
            "K4 verifier must reject mutated {mutate}"
        );
    }
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_k6a_non_zk_integrity_product_route_is_explicit_opt_in() {
    let (prover, r1cs, mut items) = build_fixture();
    let (_r1cs_again, z) = common::multi_r1cs();
    items.push(make_batched_item(&prover, &r1cs, &z, 4));
    let bucket = BatchedCpBucket::new(items, whir_parameter_digest()).unwrap();
    assert_eq!(bucket.shape.active_count, 4);
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
        .expect("WHIR exposes SYMBT3 relation shell");
    let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
    let decoded_relation =
        BatchedCpSymbt3RelationDescription::from_context_bytes(relation.context.as_ref().unwrap())
            .unwrap();
    let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
    let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
    let product_profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &decoded_relation,
            64,
        );
    assert_eq!(
        product_profile.routing_status,
        Symbt3RoutingStatus::ProductAuthority
    );
    assert!(product_profile.product_eligible);
    assert!(!product_profile.research_only);
    assert_eq!(
        product_profile.zk_status,
        Symbt3ZkStatus::NonZkIntegrityOnly
    );
    assert_eq!(
        product_profile.product_policy,
        Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn
    );
    assert!(symphony::batched_cp::product_policy_accepts_non_zk(
        &product_profile
    ));
    assert!(
        product_profile.accepts_relation_for_non_zk_integrity_product_authority(&decoded_relation)
    );
    assert!(
        !product_profile.accepts_relation_for_product_authority(&decoded_relation),
        "K6a opt-in NonZK integrity is intentionally separate from the strict ZK product-authority gate"
    );

    let profile_digest = product_profile.digest(bucket.shape.accumulator_shape.digest_scheme);
    let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        bucket.shape.accumulator_shape.digest_scheme,
        profile_digest,
        public.old_accumulator_digest,
        public.new_accumulator_digest,
        &public,
    );
    assert!(accumulator_instance.matches_profile_and_relation(&product_profile, &decoded_relation));
    let accumulator_witness =
        Symbt3AccumulatorWitness::from_symbt3_witness(&decoded_relation, &witness);
    let proof = WhirSnark::prove_public_symbt3_accumulator_non_zk_integrity(
        &pk,
        &product_profile,
        &accumulator_instance,
        &accumulator_witness,
    )
    .expect("K6a NonZK integrity product proof");
    assert!(
        WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &product_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &proof,
        )
    );
    let (_, verifier_profile) = WhirSnark::profile_symbt3_batched_cp_verifier(&vk, &public, &proof)
        .expect("K6a verifier profile");
    assert_eq!(proof.family_columnar_subproofs.len(), 0);
    assert!(!proof.is_output);
    assert_eq!(proof.private_opening_evals.len(), 15);
    assert_eq!(
        decoded_relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
        0
    );
    assert_eq!(
        verifier_profile.source_r1cs_residual_verifier_evaluations,
        1
    );
    assert_ne!(accumulator_instance.batch_items_digest, [0u8; 32]);
    assert_ne!(accumulator_instance.message_oracle_roots_digest, [0u8; 32]);

    for wrong_kind in [
        ProductProofKind::MonolithicTypedCp,
        ProductProofKind::Symbt2F,
        ProductProofKind::Symbt2C,
        ProductProofKind::Symbtc,
    ] {
        assert!(
            !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
                &vk,
                &product_profile,
                &accumulator_instance,
                wrong_kind,
                &proof,
            ),
            "K6a must reject wrong product proof-kind marker {wrong_kind:?}"
        );
    }

    let mut output_shaped_proof = proof.clone();
    output_shaped_proof.is_output = true;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &product_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &output_shaped_proof,
        ),
        "K6a must reject non-SYMBT3/output-shaped proof payloads"
    );

    let mut no_policy_profile = product_profile.clone();
    no_policy_profile.product_policy = Symbt3ProductPolicy::MonolithicTypedCpOnly;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &no_policy_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &proof,
        )
    );
    let mut zk_required_profile = product_profile.clone();
    zk_required_profile.zk_status = Symbt3ZkStatus::ZkRequiredForProductRoute;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &zk_required_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &proof,
        )
    );
    let mut research_route_profile = product_profile.clone();
    research_route_profile.routing_status = Symbt3RoutingStatus::ResearchOnly;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &research_route_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &proof,
        )
    );
    let mut not_product_profile = product_profile.clone();
    not_product_profile.product_eligible = false;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &not_product_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &proof,
        )
    );
    let mut v0_profile = product_profile.clone();
    v0_profile.semantic_profile_version = 0;
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
            &vk,
            &v0_profile,
            &accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &proof,
        )
    );

    for mutate in [
        "missing_manifest",
        "missing_transition",
        "low_soundness",
        "zero_policy_digest",
    ] {
        let mut changed = product_profile.clone();
        match mutate {
            "missing_manifest" => changed.enabled_families.retain(|family| {
                *family != BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim
            }),
            "missing_transition" => changed.enabled_families.retain(|family| {
                *family != BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency
            }),
            "low_soundness" => changed.manifest_membership_bits = 16,
            "zero_policy_digest" => changed.norm_range_policy_digest = [0u8; 32],
            _ => unreachable!(),
        }
        assert!(
            !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
                &vk,
                &changed,
                &accumulator_instance,
                ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                &proof,
            ),
            "K6a verifier must reject product profile mutation {mutate}"
        );
    }

    for mutate in [
        "old_accumulator_digest",
        "new_accumulator_digest",
        "profile_digest",
        "batch_manifest_root",
        "message_oracle_roots_digest",
        "source_assignment_roots_digest",
        "batch_items_digest",
    ] {
        let mut changed = accumulator_instance.clone();
        match mutate {
            "old_accumulator_digest" => changed.old_accumulator_digest[0] ^= 1,
            "new_accumulator_digest" => changed.new_accumulator_digest[0] ^= 1,
            "profile_digest" => changed.profile_digest[0] ^= 1,
            "batch_manifest_root" => changed.manifest_root[0] ^= 1,
            "message_oracle_roots_digest" => changed.message_oracle_roots_digest[0] ^= 1,
            "source_assignment_roots_digest" => changed.source_assignment_roots_digest[0] ^= 1,
            "batch_items_digest" => changed.batch_items_digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
                &vk,
                &product_profile,
                &changed,
                ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                &proof,
            ),
            "K6a verifier must reject mutated accumulator instance {mutate}"
        );
    }

    let mut dev_projection_relation = decoded_relation.clone();
    dev_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .projection_mode = Symbt3ProjectionMode::DirectDevDenseProjectionV1;
    let dev_projection_profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &dev_projection_relation,
            64,
        );
    assert!(!dev_projection_profile
        .accepts_relation_for_non_zk_integrity_product_authority(&dev_projection_relation));
    let mut dev_range_relation = decoded_relation.clone();
    dev_range_relation.ajtai_norm_range_layout.range_mode = Symbt3RangeMode::DirectSignedRangeDevV1;
    dev_range_relation
        .ajtai_norm_range_layout
        .range_layout
        .range_mode = Symbt3RangeMode::DirectSignedRangeDevV1;
    let dev_range_profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &dev_range_relation,
            64,
        );
    assert!(!dev_range_profile
        .accepts_relation_for_non_zk_integrity_product_authority(&dev_range_relation));
    let mut identity_projection_relation = decoded_relation.clone();
    identity_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .block_len = 1;
    identity_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .output_len = identity_projection_relation
        .ajtai_norm_range_layout
        .projection_layout
        .input_len;
    let identity_projection_profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &identity_projection_relation,
            64,
        );
    assert!(!identity_projection_profile
        .accepts_relation_for_non_zk_integrity_product_authority(&identity_projection_relation));

    let research_profile =
        Symbt3AuthorityProfile::accumulator_soundness_authority_candidate_from_relation(
            &decoded_relation,
            64,
        );
    assert!(WhirSnark::prove_public_symbt3_accumulator_non_zk_integrity(
        &pk,
        &research_profile,
        &accumulator_instance,
        &accumulator_witness,
    )
    .is_none());
    assert!(
        !WhirSnark::verify_public_symbt3_accumulator_research_non_zk(
            &vk,
            &product_profile,
            &accumulator_instance,
            &proof,
        ),
        "K6a ProductAuthority profile must not be accepted by the K4 research verifier"
    );
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_k6b_product_route_discriminator_and_policy_are_explicit() {
    let (prover, r1cs, items) = build_fixture();
    let bucket = BatchedCpBucket::new(items, whir_parameter_digest()).unwrap();
    let descriptor = BatchedCpSymbt3SetupDescriptor::new(
        bucket.shape.clone(),
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
        .expect("WHIR exposes SYMBT3 relation shell");
    let decoded_relation =
        BatchedCpSymbt3RelationDescription::from_context_bytes(relation.context.as_ref().unwrap())
            .unwrap();
    let product_profile =
        Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
            &decoded_relation,
            64,
        );
    assert!(symphony::batched_cp::product_policy_accepts_non_zk(
        &product_profile
    ));

    let mut default_policy_profile = product_profile.clone();
    default_policy_profile.product_policy = Symbt3ProductPolicy::MonolithicTypedCpOnly;
    assert!(!symphony::batched_cp::product_policy_accepts_non_zk(
        &default_policy_profile
    ));

    for wrong_kind in [
        ProductProofKind::MonolithicTypedCp,
        ProductProofKind::Symbt2F,
        ProductProofKind::Symbt2C,
        ProductProofKind::Symbtc,
    ] {
        assert_ne!(
            wrong_kind,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            "K6b comparison must not allow ambiguous product proof-kind routing"
        );
    }
}

#[cfg(feature = "whir")]
#[test]
fn symbt3_k1e2_source_view_is_virtual_for_k1_and_k2() {
    let (prover, r1cs, items) = build_fixture();
    for k in [1usize, 2] {
        let bucket = BatchedCpBucket::new(
            items.iter().take(k).cloned().collect::<Vec<_>>(),
            whir_parameter_digest(),
        )
        .unwrap();
        let descriptor = BatchedCpSymbt3SetupDescriptor::new(
            bucket.shape.clone(),
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );
        let relation = <WhirSnark as CpBackend>::symbt3_relation_description(&descriptor)
            .expect("WHIR exposes SYMBT3 relation shell");
        let (pk, vk) = <WhirSnark as CpBackend>::setup(&relation);
        let decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
            relation.context.as_ref().unwrap(),
        )
        .unwrap();
        let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
        let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
        let proof = <WhirSnark as CpBackend>::prove_symbt3_batched_cp(&pk, &public, &witness)
            .expect("SYMBT3-K1e.2 proof");

        assert_eq!(
            <WhirSnark as CpBackend>::verify_symbt3_batched_cp(&vk, &public, &proof),
            Some(true)
        );
        let (_, verifier_profile) =
            WhirSnark::profile_symbt3_batched_cp_verifier(&vk, &public, &proof)
                .expect("SYMBT3 verifier profile");
        assert_eq!(
            verifier_profile.source_r1cs_residual_claims,
            public.source_assignment_roots.len()
                * decoded_relation.r1cs_evaluator_layout.num_constraints
                * D
        );
        assert_eq!(
            verifier_profile.source_r1cs_residual_verifier_evaluations, 1,
            "K4.5 must not evaluate source R1CS residuals one by one for k={k}"
        );
        assert!(
            proof.num_vars <= 14,
            "SYMBT3-K1e.2 must keep k={k} compact: got {} WHIR vars",
            proof.num_vars
        );
        assert!(
            (1usize << proof.num_vars) <= 16_384,
            "SYMBT3-K1e.2 must keep k={k} oracle_len compact"
        );
        assert_eq!(proof.family_columnar_subproofs.len(), 0);
        let accumulator_transition_claims = 1usize;
        assert_eq!(
            accumulator_transition_claims, 1,
            "K2b accumulator_transition_claims must stay constant in k"
        );
        assert_eq!(proof.private_opening_evals.len(), 15);
        assert_eq!(
            symbt3_canonical_manifest_view_eval_for_statement(
                &decoded_relation,
                &public,
                &public.manifest_oracle_root
            ),
            symbt3_virtual_source_view_eval_for_statement(
                &decoded_relation,
                &public,
                &public.manifest_oracle_root
            ),
            "honest virtual SourceView(zeta) must equal public ManifestView(zeta)"
        );
        assert!(witness.manifest_source_values.is_empty());
    }
}

#[cfg(feature = "whir")]
#[test]
fn batched_cp_semantic_columnar_v2_context_and_trace_residuals() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let witness = bucket.witness_bundle();
    let relation = bucket.shape.semantic_columnar_v2_relation_description(
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );

    let residual_families = relation
        .columnar_layout
        .residuals
        .iter()
        .map(|residual| residual.family)
        .collect::<Vec<_>>();
    assert_eq!(
        residual_families,
        vec![
            BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            BatchedCpSemanticConstraintFamily::ManifestMembership,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            BatchedCpSemanticConstraintFamily::ChallengeDerivation,
            BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        ]
    );
    assert_eq!(
        relation
            .columnar_layout
            .residuals
            .iter()
            .filter(|residual| residual.row_count > 0)
            .count(),
        residual_families.len()
    );
    let description = relation.to_relation_description();
    assert_eq!(description.num_constraints, 0);
    let decoded = BatchedCpSemanticColumnarV2Description::from_context_bytes(
        description.context.as_ref().expect("columnar context"),
    )
    .unwrap();
    assert_eq!(decoded, relation);
    assert_ne!(
        relation.semantic_relation_id(),
        bucket
            .shape
            .semantic_v2_relation_description(&prover.ajtai, &r1cs, prover.params.b_input())
            .semantic_relation_id()
    );

    let trace =
        BatchedCpSemanticTraceV2::encode(&relation, &bucket.public_statement(), &witness).unwrap();
    assert!(trace.all_residuals_satisfied());
    assert_eq!(trace.columns.len(), relation.columnar_layout.columns.len());
    assert_eq!(
        trace.flattened_values().len(),
        relation.columnar_layout.columns.len() * relation.columnar_layout.column_row_count
    );

    for family in [
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        BatchedCpSemanticConstraintFamily::ManifestMembership,
        BatchedCpSemanticConstraintFamily::RoundMessageBinding,
        BatchedCpSemanticConstraintFamily::ChallengeDerivation,
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
    ] {
        let residual_idx = trace
            .layout
            .residuals
            .iter()
            .position(|residual| residual.family == family)
            .expect("migrated residual family");
        let residual = trace.layout.residuals[residual_idx].clone();
        assert!(residual.row_count > 0);
        let mut tampered = trace.clone();
        let mut tamper_columns = vec![residual.left_column, residual.right_column];
        tamper_columns.extend(residual.aux_columns.iter().copied());
        let mut changed_residual = false;
        for column in tamper_columns {
            let mut candidate = trace.clone();
            candidate.columns[column][0] ^= if candidate.columns[column][0] == 0 {
                1
            } else {
                0xff
            };
            if candidate.residual_value(residual_idx, 0) != Some(0) {
                tampered = candidate;
                changed_residual = true;
                break;
            }
        }
        assert!(
            changed_residual,
            "{family:?} residual must have a tamper-sensitive sampled column"
        );
        assert!(
            !tampered.all_residuals_satisfied(),
            "{family:?} residual tamper must reject"
        );
        assert_ne!(tampered.residual_value(residual_idx, 0), Some(0));
    }

    let mut tampered_context = description.context.unwrap();
    *tampered_context.last_mut().unwrap() ^= 1;
    assert_eq!(
        BatchedCpSemanticColumnarV2Description::from_context_bytes(&tampered_context).unwrap_err(),
        BatchedCpError::InvalidSemanticRelationContext
    );
}

#[cfg(feature = "whir")]
#[test]
fn poseidon_babybear_semantic_columnar_v2_trace_covers_all_families() {
    let (prover, r1cs, bucket) = poseidon_columnar_fixture();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket.shape.semantic_columnar_v2_relation_description(
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );

    let residual_families = relation
        .columnar_layout
        .residuals
        .iter()
        .map(|residual| residual.family)
        .collect::<Vec<_>>();
    assert_eq!(
        residual_families,
        vec![
            BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            BatchedCpSemanticConstraintFamily::ManifestMembership,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            BatchedCpSemanticConstraintFamily::ChallengeDerivation,
            BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
            BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
            BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
        ]
    );
    assert!(
        relation
            .columnar_layout
            .residuals
            .iter()
            .all(|residual| residual.row_count > 0),
        "Poseidon/BabyBear fixture should instantiate every SYMBT2C residual family"
    );
    assert_eq!(
        relation.to_relation_description().num_constraints,
        0,
        "SYMBT2C columnar mode must not lower to appended typed CP R1CS"
    );

    let trace = BatchedCpSemanticTraceV2::encode(&relation, &public, &witness).unwrap();
    assert!(trace.all_residuals_satisfied());

    for (residual_idx, residual) in trace.layout.residuals.iter().enumerate() {
        let mut tamper_columns = vec![residual.left_column, residual.right_column];
        tamper_columns.extend(residual.aux_columns.iter().copied());
        let mut tampered = None;
        for column in tamper_columns {
            let mut candidate = trace.clone();
            candidate.columns[column][0] ^= if candidate.columns[column][0] == 0 {
                1
            } else {
                0xff
            };
            if candidate.residual_value(residual_idx, 0) != Some(0) {
                tampered = Some(candidate);
                break;
            }
        }
        let tampered = tampered.unwrap_or_else(|| {
            panic!(
                "{:?} must expose a tamper-sensitive column",
                residual.family
            )
        });
        assert!(
            !tampered.all_residuals_satisfied(),
            "{:?} residual tamper must reject",
            residual.family
        );
        assert_ne!(tampered.residual_value(residual_idx, 0), Some(0));
    }
}

#[cfg(feature = "whir")]
#[test]
fn semantic_family_columnar_v2_context_and_trace_residuals() {
    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket
        .shape
        .semantic_family_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );

    let table_families = relation
        .family_layout
        .tables
        .iter()
        .map(|table| table.family)
        .collect::<Vec<_>>();
    for family in [
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        BatchedCpSemanticConstraintFamily::ManifestMembership,
        BatchedCpSemanticConstraintFamily::RoundMessageBinding,
        BatchedCpSemanticConstraintFamily::ChallengeDerivation,
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
    ] {
        assert!(table_families.contains(&family), "{family:?} missing");
    }
    let round_message_rows: usize = relation
        .family_layout
        .tables
        .iter()
        .filter(|table| table.family == BatchedCpSemanticConstraintFamily::RoundMessageBinding)
        .map(|table| table.row_count)
        .sum();
    assert_eq!(
        round_message_rows,
        bucket.shape.structured_oracle_byte_equalities().len(),
        "SYMBT2F split RoundMessageBinding tables must cover the same byte-equality corpus"
    );
    assert!(
        relation
            .family_layout
            .tables
            .iter()
            .filter(|table| {
                table.family == BatchedCpSemanticConstraintFamily::RoundMessageBinding
            })
            .count()
            > bucket.shape.accumulator_shape.num_rounds * 2
    );
    for (round, sections) in bucket
        .shape
        .accumulator_shape
        .gr1cs_message_sections
        .iter()
        .enumerate()
    {
        let mut cursor = 0usize;
        let mut reassembled = Vec::new();
        for section in sections {
            assert_eq!(section.offset, cursor);
            cursor += section.len;
            reassembled.extend_from_slice(
                &bucket.items[0].witness.fs_messages[round]
                    [section.offset..section.offset + section.len],
            );
        }
        assert_eq!(cursor, bucket.items[0].witness.fs_messages[round].len());
        assert_eq!(reassembled, bucket.items[0].witness.fs_messages[round]);
        for expected in [
            "header",
            "hadamard-evals",
            "range-payload",
            "monomial-payload",
            "square-evals",
            "projected-values",
        ] {
            assert!(
                sections
                    .iter()
                    .any(|section| section.kind.label() == expected),
                "missing GR1CS message section {expected}"
            );
        }
    }
    let folded_output_rows: usize = relation
        .family_layout
        .tables
        .iter()
        .filter(|table| table.family == BatchedCpSemanticConstraintFamily::FoldedOutputDerivation)
        .map(|table| table.row_count)
        .sum();
    let expected_folded_output_rows = bucket
        .shape
        .folded_output_contribution_byte_equalities()
        .len()
        + bucket
            .shape
            .folded_output_self_consistency_byte_equalities()
            .len()
        + bucket
            .shape
            .fold_input_reconstruction_byte_equalities()
            .len()
        + bucket.shape.folded_public_input_linear_constraints().len()
        + bucket.shape.folded_commitment_ring_mul_constraints().len()
        + bucket.shape.folded_evaluation_ring_mul_constraints().len();
    assert_eq!(
        folded_output_rows, expected_folded_output_rows,
        "SYMBT2F split FoldedOutputDerivation tables must cover the same corpus"
    );
    assert!(
        relation
            .family_layout
            .tables
            .iter()
            .filter(|table| {
                table.family == BatchedCpSemanticConstraintFamily::FoldedOutputDerivation
            })
            .count()
            > 1
    );
    assert!(
        relation.family_layout.tables.iter().all(|table| {
            let is_sectioned_message_table = table.label.starts_with("round-message-")
                || table
                    .label
                    .starts_with("fold-input-eval-message-reconstruction-")
                || table
                    .label
                    .starts_with("fold-input-round-message-reconstruction-");
            !is_sectioned_message_table
                || (table.column_kinds.len() * table.padded_row_count)
                    .next_power_of_two()
                    .max(2)
                    .trailing_zeros()
                    <= 14
        }),
        "sectioned message equality tables must stay at num_vars <= 14"
    );
    assert!(relation
        .family_layout
        .tables
        .iter()
        .all(|table| table.row_count > 0 && table.padded_row_count >= table.row_count));
    let description = relation.to_relation_description();
    assert_eq!(
        description.num_constraints, 0,
        "SYMBT2F must stay structured and must not lower to appended typed CP R1CS"
    );
    assert!(
        description.num_witness_vars < {
            let rectangular = bucket.shape.semantic_columnar_v2_relation_description(
                &prover.ajtai,
                &r1cs,
                prover.params.b_input(),
            );
            rectangular.to_relation_description().num_witness_vars
        }
    );
    let decoded = BatchedCpSemanticFamilyColumnarV2Description::from_context_bytes(
        description.context.as_ref().expect("SYMBT2F context"),
    )
    .unwrap();
    assert_eq!(decoded, relation);
    assert_ne!(
        relation.semantic_relation_id(),
        bucket
            .shape
            .semantic_columnar_v2_relation_description(
                &prover.ajtai,
                &r1cs,
                prover.params.b_input()
            )
            .semantic_relation_id()
    );

    let trace = BatchedCpSemanticFamilyTraceV2::encode(&relation, &public, &witness).unwrap();
    assert!(trace.all_residuals_satisfied());
    assert_eq!(
        trace.flattened_values().len(),
        relation.family_layout.total_field_len
    );

    for (table_idx, table) in trace.layout.tables.iter().enumerate() {
        let mut tampered = None;
        for column in 0..table.column_kinds.len() {
            let mut candidate = trace.clone();
            candidate.tables[table_idx][column][0] ^= if candidate.tables[table_idx][column][0] == 0
            {
                1
            } else {
                0xff
            };
            if candidate.residual_value(table_idx, 0) != Some(0) {
                tampered = Some(candidate);
                break;
            }
        }
        let tampered = tampered
            .unwrap_or_else(|| panic!("{:?} must expose a tamper-sensitive column", table.family));
        assert!(
            !tampered.all_residuals_satisfied(),
            "{:?} SYMBT2F residual tamper must reject",
            table.family
        );
    }
}

#[cfg(feature = "whir")]
#[test]
fn poseidon_babybear_semantic_family_columnar_v2_trace_covers_all_families() {
    let (prover, r1cs, bucket) = poseidon_columnar_fixture();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket
        .shape
        .semantic_family_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );

    let table_families = relation
        .family_layout
        .tables
        .iter()
        .map(|table| table.family)
        .collect::<Vec<_>>();
    for family in [
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        BatchedCpSemanticConstraintFamily::ManifestMembership,
        BatchedCpSemanticConstraintFamily::RoundMessageBinding,
        BatchedCpSemanticConstraintFamily::ChallengeDerivation,
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
        BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
    ] {
        assert!(table_families.contains(&family), "{family:?} missing");
    }
    assert!(
        relation
            .family_layout
            .tables
            .iter()
            .filter(|table| {
                table.family == BatchedCpSemanticConstraintFamily::RoundMessageBinding
            })
            .count()
            >= bucket.shape.accumulator_shape.num_rounds * 2
    );
    assert!(
        relation
            .family_layout
            .tables
            .iter()
            .filter(|table| {
                table.family == BatchedCpSemanticConstraintFamily::FoldedOutputDerivation
            })
            .count()
            > 1
    );
    let rectangular = bucket.shape.semantic_columnar_v2_relation_description(
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    assert!(
        relation.family_layout.total_field_len
            < rectangular.columnar_layout.columns.len()
                * rectangular.columnar_layout.column_row_count
    );

    let trace = BatchedCpSemanticFamilyTraceV2::encode(&relation, &public, &witness).unwrap();
    assert!(trace.all_residuals_satisfied());
    for (table_idx, table) in trace.layout.tables.iter().enumerate() {
        let mut tampered = None;
        for column in 0..table.column_kinds.len() {
            let mut candidate = trace.clone();
            candidate.tables[table_idx][column][0] ^= if candidate.tables[table_idx][column][0] == 0
            {
                1
            } else {
                0xff
            };
            if candidate.residual_value(table_idx, 0) != Some(0) {
                tampered = Some(candidate);
                break;
            }
        }
        let tampered = tampered
            .unwrap_or_else(|| panic!("{:?} must expose a tamper-sensitive column", table.family));
        assert!(
            !tampered.all_residuals_satisfied(),
            "{:?} Poseidon SYMBT2F residual tamper must reject",
            table.family
        );
    }
}

#[test]
fn batched_cp_typed_product_oracle_layout_roundtrips_current_oracle() {
    let (prover, _r1cs, mut items) = build_fixture();
    #[cfg(not(feature = "whir"))]
    let _ = &prover;
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let witness = bucket.witness_bundle();
    let oracle = witness
        .canonical_product_oracle_bytes(&bucket.shape)
        .expect("canonical product oracle bytes");
    let layout = bucket.shape.product_oracle_layout();
    assert_eq!(layout.byte_len, oracle.len());
    assert_eq!(
        layout.packed_field_len,
        oracle.len().div_ceil(3) + 1,
        "layout includes the final length sentinel field"
    );

    for (idx, row) in layout.witness_rows.iter().enumerate() {
        assert_eq!(
            &oracle[row.offset..row.offset + row.len],
            witness.witness_oracle_rows[idx].as_slice()
        );
    }
    for (round, rows) in layout.round_message_rows.iter().enumerate() {
        for (idx, row) in rows.iter().enumerate() {
            assert_eq!(
                &oracle[row.offset..row.offset + row.len],
                witness.round_message_oracles[round][idx].as_slice()
            );
        }
    }
    for (round, rows) in layout.round_message_digest_bodies.iter().enumerate() {
        for (idx, row) in rows.iter().enumerate() {
            assert_eq!(
                &oracle[row.offset..row.offset + row.len],
                witness.round_message_oracles[round][idx].as_slice()
            );
        }
    }
    for witness_idx in 0..bucket.shape.accumulator_shape.original_witness_lens.len() {
        for idx in 0..bucket.shape.batch_capacity {
            let row = layout.witness_original_witnesses[witness_idx][idx];
            if idx < bucket.shape.active_count {
                let mut expected = Vec::new();
                for elem in &bucket.items[idx].witness.original_witnesses[witness_idx].elements {
                    for &coeff in &elem.coeffs {
                        expected.extend_from_slice(&coeff.to_le_bytes());
                    }
                }
                assert_eq!(
                    &oracle[row.offset..row.offset + row.len],
                    expected.as_slice()
                );
            } else {
                assert_eq!(row.len, 0);
            }
        }
    }
    assert!(!bucket.shape.structured_oracle_byte_equalities().is_empty());
    assert!(!bucket.shape.active_marker_byte_equalities().is_empty());
    assert!(!bucket
        .shape
        .manifest_membership_byte_equalities()
        .is_empty());
    assert!(!bucket
        .shape
        .challenge_derivation_packed_values_for_statement(&bucket.public_statement())
        .unwrap()
        .is_empty());
    assert!(!bucket
        .shape
        .challenge_to_beta_packed_values_for_statement(&bucket.public_statement())
        .unwrap()
        .is_empty());
    assert!(!bucket
        .shape
        .folded_output_contribution_byte_equalities()
        .is_empty());
    assert!(!bucket
        .shape
        .folded_output_self_consistency_byte_equalities()
        .is_empty());
    assert!(!bucket
        .shape
        .fold_input_reconstruction_byte_equalities()
        .is_empty());
    #[cfg(feature = "whir")]
    assert_eq!(
        bucket
            .shape
            .folded_public_input_linear_constraints()
            .is_empty(),
        bucket.shape.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear,
        "BabyBear folded public-input linearity is enabled only for Poseidon2/BabyBear shapes"
    );
    #[cfg(feature = "whir")]
    assert_eq!(
        bucket
            .shape
            .folded_commitment_ring_mul_constraints()
            .is_empty(),
        bucket.shape.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear,
        "BabyBear folded commitment ring multiplication is enabled only for Poseidon2/BabyBear shapes"
    );
    #[cfg(not(feature = "whir"))]
    assert!(bucket
        .shape
        .folded_public_input_linear_constraints()
        .is_empty());
    #[cfg(not(feature = "whir"))]
    assert!(bucket
        .shape
        .folded_commitment_ring_mul_constraints()
        .is_empty());
    #[cfg(feature = "whir")]
    {
        let poseidon_item = poseidon_shaped_item(bucket.items[0].clone(), &prover);
        let poseidon_bucket =
            BatchedCpBucket::new(vec![poseidon_item], whir_parameter_digest()).unwrap();
        assert!(!poseidon_bucket
            .shape
            .folded_public_input_linear_constraints()
            .is_empty());
        assert!(!poseidon_bucket
            .shape
            .folded_commitment_ring_mul_constraints()
            .is_empty());
        assert!(!poseidon_bucket
            .shape
            .folded_evaluation_ring_mul_constraints()
            .is_empty());
    }
    assert!(!bucket
        .shape
        .folded_output_packed_values_for_statement(&bucket.public_statement())
        .unwrap()
        .is_empty());
    for idx in 0..bucket.shape.batch_capacity {
        let expected_marker = u8::from(idx < bucket.shape.active_count);
        assert_eq!(oracle[layout.witness_active_markers[idx]], expected_marker);
        assert_eq!(oracle[layout.manifest_active_markers[idx]], expected_marker);
        if idx < bucket.shape.active_count {
            assert_eq!(
                &oracle[layout.witness_item_tags[idx].offset
                    ..layout.witness_item_tags[idx].offset + layout.witness_item_tags[idx].len],
                &oracle[layout.manifest_item_tags[idx].offset
                    ..layout.manifest_item_tags[idx].offset + layout.manifest_item_tags[idx].len]
            );
            assert_eq!(
                &oracle[layout.witness_public_statements[idx].offset
                    ..layout.witness_public_statements[idx].offset
                        + layout.witness_public_statements[idx].len],
                &oracle[layout.manifest_public_statements[idx].offset
                    ..layout.manifest_public_statements[idx].offset
                        + layout.manifest_public_statements[idx].len]
            );
            assert_eq!(
                &oracle[layout.witness_folded_output_contributions[idx].offset
                    ..layout.witness_folded_output_contributions[idx].offset
                        + layout.witness_folded_output_contributions[idx].len],
                &oracle[layout.folded_output_contributions[idx].offset
                    ..layout.folded_output_contributions[idx].offset
                        + layout.folded_output_contributions[idx].len]
            );
            for round in 0..bucket.shape.accumulator_shape.num_rounds {
                assert_eq!(
                    &oracle[layout.witness_fs_messages[round][idx].offset
                        ..layout.witness_fs_messages[round][idx].offset
                            + layout.witness_fs_messages[round][idx].len],
                    bucket.items[idx].witness.fs_messages[round].as_slice()
                );
                assert_eq!(
                    &oracle[layout.witness_fs_openings[round][idx].offset
                        ..layout.witness_fs_openings[round][idx].offset
                            + layout.witness_fs_openings[round][idx].len],
                    bucket.items[idx].witness.fs_openings[round].as_slice()
                );
                assert_eq!(
                    &oracle[layout.fs_commitment_body_messages[round][idx].offset
                        ..layout.fs_commitment_body_messages[round][idx].offset
                            + layout.fs_commitment_body_messages[round][idx].len],
                    bucket.items[idx].witness.fs_messages[round].as_slice()
                );
                assert_eq!(
                    &oracle[layout.fs_commitment_body_openings[round][idx].offset
                        ..layout.fs_commitment_body_openings[round][idx].offset
                            + layout.fs_commitment_body_openings[round][idx].len],
                    bucket.items[idx].witness.fs_openings[round].as_slice()
                );
                assert_eq!(
                    &oracle[layout.witness_fs_messages[round][idx].offset
                        ..layout.witness_fs_messages[round][idx].offset
                            + layout.witness_fs_messages[round][idx].len],
                    &oracle[layout.round_message_rows[round][idx].offset
                        ..layout.round_message_rows[round][idx].offset
                            + layout.round_message_rows[round][idx].len]
                );
                assert_eq!(
                    &oracle[layout.witness_fold_input_commitments[round][idx].offset
                        ..layout.witness_fold_input_commitments[round][idx].offset
                            + layout.witness_fold_input_commitments[round][idx].len],
                    &oracle[layout.fold_input_commitments[round][idx].offset
                        ..layout.fold_input_commitments[round][idx].offset
                            + layout.fold_input_commitments[round][idx].len]
                );
                assert_eq!(
                    &oracle[layout.witness_fold_input_public_inputs[round][idx].offset
                        ..layout.witness_fold_input_public_inputs[round][idx].offset
                            + layout.witness_fold_input_public_inputs[round][idx].len],
                    &oracle[layout.fold_input_public_inputs[round][idx].offset
                        ..layout.fold_input_public_inputs[round][idx].offset
                            + layout.fold_input_public_inputs[round][idx].len]
                );
                assert_eq!(
                    &oracle[layout.witness_fold_input_eval_messages[round][idx].offset
                        ..layout.witness_fold_input_eval_messages[round][idx].offset
                            + layout.witness_fold_input_eval_messages[round][idx].len],
                    &oracle[layout.fold_input_eval_messages[round][idx].offset
                        ..layout.fold_input_eval_messages[round][idx].offset
                            + layout.fold_input_eval_messages[round][idx].len]
                );
                assert_eq!(
                    &oracle[layout.witness_fold_input_eval_messages[round][idx].offset
                        ..layout.witness_fold_input_eval_messages[round][idx].offset
                            + layout.witness_fold_input_eval_messages[round][idx].len],
                    &oracle[layout.round_message_rows[round][idx].offset
                        ..layout.round_message_rows[round][idx].offset
                            + layout.round_message_rows[round][idx].len]
                );
            }
        }
        for round_markers in &layout.round_message_active_markers {
            assert_eq!(oracle[round_markers[idx]], expected_marker);
        }
        for round_markers in &layout.round_message_digest_body_active_markers {
            assert_eq!(oracle[round_markers[idx]], expected_marker);
        }
        if idx < bucket.shape.active_count {
            for round_markers in &layout.fs_commitment_body_active_markers {
                assert_eq!(oracle[round_markers[idx]], expected_marker);
            }
        }
    }
}

#[cfg(feature = "whir")]
#[test]
fn whir_proves_structured_batched_cp_product_oracle_without_promoting_it() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (_prover, _r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    assert!(
        bucket
            .shape
            .canonical_product_oracle_public_packed_claim_count_for_statement(&public)
            .unwrap()
            > bucket
                .shape
                .canonical_product_oracle_public_packed_claim_count()
    );

    let relation = <WhirSnark as CpBackend>::typed_batched_cp_relation_description(&bucket.shape)
        .expect("WHIR should expose structured batched CP metadata");
    assert_eq!(relation.num_constraints, 0);
    let context = relation.context.as_ref().expect("structured WHIR context");
    let decoded = BatchedCpStructuredRelationDescription::from_context_bytes(context).unwrap();
    assert_eq!(decoded.shape, bucket.shape);

    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove the SYMBTC1 product-domain oracle");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    assert!(proof.sumcheck_rounds_3.is_empty());
    assert!(proof.sumcheck_rounds_4.is_empty());
    assert!(proof.linear_checks.is_empty());
    assert!(!proof.private_opening_evals.is_empty());

    let mut tampered_public = public.clone();
    tampered_public.manifest_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &tampered_public, &proof),
        Some(false)
    );
    let mut tampered_public = public.clone();
    tampered_public.round_message_commitments[0][0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &tampered_public, &proof),
        Some(false)
    );
    let mut tampered_public = public.clone();
    tampered_public.folded_output_accumulator_root[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &tampered_public, &proof),
        Some(false)
    );
    let mut tampered_private_eval = proof.clone();
    tampered_private_eval.private_opening_evals[0] += p3_baby_bear::BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_private_eval),
        Some(false)
    );

    let mut wrong_shape_proof = proof.clone();
    wrong_shape_proof.num_vars += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &wrong_shape_proof),
        Some(false)
    );
}

#[cfg(feature = "whir")]
#[test]
fn whir_consumes_semantic_batched_cp_context_one_block_at_a_time() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::whir_typed_batched_cp_private_opening_profile;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let item_b = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a, item_b], params_digest).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let oracle = witness
        .canonical_product_oracle_bytes(&bucket.shape)
        .expect("canonical product oracle");
    assert_poseidon_folded_algebra_offsets_hold(&bucket.shape, &oracle);
    let semantic =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    let supported_families: Vec<_> = semantic
        .supported_constraint_blocks()
        .iter()
        .map(|block| block.family)
        .collect();
    assert!(supported_families.contains(&BatchedCpSemanticConstraintFamily::RoundMessageBinding));
    assert!(
        supported_families.contains(&BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness)
    );
    assert!(supported_families.contains(&BatchedCpSemanticConstraintFamily::ManifestMembership));
    assert!(supported_families.contains(&BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy));
    let statement_families: Vec<_> = semantic
        .supported_constraint_blocks_for_statement(Some(&public))
        .iter()
        .map(|block| block.family)
        .collect();
    assert!(statement_families.contains(&BatchedCpSemanticConstraintFamily::ChallengeDerivation));
    assert!(statement_families.contains(&BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding));
    assert!(statement_families.contains(&BatchedCpSemanticConstraintFamily::FoldedOutputDerivation));

    let relation = semantic.to_relation_description();
    assert_eq!(
        relation.num_constraints, 0,
        "semantic batched CP context must not lower to appended R1CS"
    );
    let decoded = BatchedCpSemanticRelationDescription::from_context_bytes(
        relation.context.as_ref().expect("semantic context"),
    )
    .unwrap();
    assert_eq!(decoded, semantic);

    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove supported semantic blocks over SYMBTC1 oracle");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    assert!(!proof.private_opening_evals.is_empty());
    let opening_profile =
        whir_typed_batched_cp_private_opening_profile(&vk.seed, &vk.relation, &public)
            .expect("semantic proof opening profile");
    assert_eq!(opening_profile.total_len, proof.private_opening_evals.len());
    assert!(!opening_profile.equality.is_empty());

    let mut tampered_private_eval = proof.clone();
    tampered_private_eval.private_opening_evals[opening_profile.equality.start] +=
        p3_baby_bear::BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_private_eval),
        Some(false)
    );
    for (label, section) in [
        ("folded public input", opening_profile.folded_public_input),
        ("folded commitment", opening_profile.folded_commitment),
        ("folded evaluation", opening_profile.folded_evaluation),
        ("Poseidon R1CS", opening_profile.poseidon_r1cs),
        ("Ajtai opening", opening_profile.ajtai_opening),
        ("original R1CS", opening_profile.original_r1cs),
    ] {
        if section.is_empty() {
            continue;
        }
        let mut tampered = proof.clone();
        tampered.private_opening_evals[section.start] += p3_baby_bear::BabyBear::ONE;
        assert_eq!(
            <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered),
            Some(false),
            "{label} private opening tamper should reject"
        );
    }
    let mut tampered_output_root = public.clone();
    tampered_output_root.folded_output_accumulator_root[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &tampered_output_root, &proof),
        Some(false)
    );
}

#[cfg(feature = "whir")]
#[test]
#[ignore = "heavy SYMBTC2 full-selection semantic WHIR proof candidate"]
fn whir_proves_semantic_v2_batched_cp_full_constraint_path() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::whir_typed_batched_cp_private_opening_profile;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, mut items) = build_fixture();
    let item_a = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item_a], params_digest).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let semantic =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    let semantic_v2 = bucket.shape.semantic_v2_relation_description(
        &prover.ajtai,
        &r1cs,
        prover.params.b_input(),
    );
    let relation = semantic_v2.to_relation_description();
    assert_eq!(
        relation.num_constraints, 0,
        "SYMBTC2 must be a structured product-domain relation, not appended R1CS"
    );

    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove the full-selection SYMBTC2 semantic path");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    let v2_profile = whir_typed_batched_cp_private_opening_profile(&vk.seed, &vk.relation, &public)
        .expect("SYMBTC2 proof opening profile");
    assert_eq!(v2_profile.total_len, proof.private_opening_evals.len());
    assert!(!v2_profile.equality.is_empty());

    let v1_relation = semantic.to_relation_description();
    let v1_profile = whir_typed_batched_cp_private_opening_profile(&vk.seed, &v1_relation, &public)
        .expect("SYMBTC1 sampled opening profile");
    assert!(
        v2_profile.total_len > v1_profile.total_len,
        "SYMBTC2 must enumerate semantic constraints instead of using SYMBTC1 sampled openings"
    );

    let mut tampered_public = public.clone();
    tampered_public.manifest_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &tampered_public, &proof),
        Some(false)
    );

    let mut tampered_private_eval = proof.clone();
    tampered_private_eval.private_opening_evals[v2_profile.equality.start] +=
        p3_baby_bear::BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_private_eval),
        Some(false)
    );

    let mut wrong_shape_proof = proof.clone();
    wrong_shape_proof.num_vars += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &wrong_shape_proof),
        Some(false)
    );
}

#[cfg(feature = "whir")]
#[test]
fn whir_proves_semantic_v2_columnar_batched_cp_skeleton() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::whir_typed_batched_cp_columnar_v2_private_opening_profile;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, mut items) = build_fixture();
    let item = items.remove(0);
    let other_item = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item.clone()], params_digest).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket
        .shape
        .semantic_columnar_v2_relation_description(&prover.ajtai, &r1cs, prover.params.b_input())
        .to_relation_description();
    assert_eq!(
        relation.num_constraints, 0,
        "SYMBTC2 columnar mode must not lower to appended typed CP R1CS"
    );

    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove the SYMBTC2 columnar skeleton");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    let profile =
        whir_typed_batched_cp_columnar_v2_private_opening_profile(&vk.seed, &vk.relation, &public)
            .expect("SYMBT2C opening profile");
    assert_eq!(profile.total_len, proof.private_opening_evals.len());
    assert_eq!(
        profile
            .families
            .iter()
            .map(|entry| entry.family)
            .collect::<Vec<_>>(),
        vec![
            BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            BatchedCpSemanticConstraintFamily::ManifestMembership,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            BatchedCpSemanticConstraintFamily::ChallengeDerivation,
            BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        ]
    );
    assert!(
        proof.private_opening_evals.len() <= 9 * 4 * 3,
        "columnar skeleton should open a bounded number of residual checks"
    );

    let mut tampered_public = public.clone();
    tampered_public.manifest_digest[0] ^= 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &tampered_public, &proof),
        Some(false)
    );

    let mut tampered_proof = proof.clone();
    tampered_proof.private_opening_evals[0] += p3_baby_bear::BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_proof),
        Some(false)
    );
    for family in &profile.families {
        assert!(!family.section.is_empty());
        assert!(family.sampled_check_count > 0);
        let mut tampered = proof.clone();
        tampered.private_opening_evals[family.section.start] += p3_baby_bear::BabyBear::ONE;
        assert_eq!(
            <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered),
            Some(false),
            "{:?} private opening tamper should reject",
            family.family
        );
    }

    let mut truncated = proof.clone();
    truncated.private_opening_evals.pop();
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &truncated),
        Some(false)
    );
    let mut extended = proof.clone();
    extended
        .private_opening_evals
        .push(p3_baby_bear::BabyBear::ZERO);
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &extended),
        Some(false)
    );

    let wrong_bucket = BatchedCpBucket::new(vec![item, other_item], params_digest).unwrap();
    let wrong_relation = wrong_bucket
        .shape
        .semantic_columnar_v2_relation_description(&prover.ajtai, &r1cs, prover.params.b_input())
        .to_relation_description();
    let (_wrong_pk, wrong_vk) = <WhirSnark as BackendSnark>::setup(&wrong_relation);
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&wrong_vk, &public, &proof),
        Some(false)
    );
}

#[cfg(feature = "whir")]
#[test]
#[ignore = "heavy SYMBT2C Poseidon/BabyBear columnar WHIR proof-profile audit"]
fn whir_proves_poseidon_semantic_v2_columnar_batched_cp_skeleton() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::whir_typed_batched_cp_columnar_v2_private_opening_profile;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, bucket) = poseidon_columnar_fixture();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket
        .shape
        .semantic_columnar_v2_relation_description(&prover.ajtai, &r1cs, prover.params.b_input())
        .to_relation_description();
    assert_eq!(
        relation.num_constraints, 0,
        "SYMBT2C columnar mode must not lower to appended typed CP R1CS"
    );

    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove the Poseidon/BabyBear SYMBT2C columnar skeleton");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    let profile =
        whir_typed_batched_cp_columnar_v2_private_opening_profile(&vk.seed, &vk.relation, &public)
            .expect("SYMBT2C Poseidon opening profile");
    assert_eq!(profile.total_len, proof.private_opening_evals.len());
    assert_eq!(
        profile
            .families
            .iter()
            .map(|entry| entry.family)
            .collect::<Vec<_>>(),
        vec![
            BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            BatchedCpSemanticConstraintFamily::ManifestMembership,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            BatchedCpSemanticConstraintFamily::ChallengeDerivation,
            BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
            BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
            BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
        ]
    );
    assert!(
        proof.private_opening_evals.len() <= 9 * 4 * 3,
        "Poseidon columnar skeleton should open a bounded number of residual checks"
    );

    for family in &profile.families {
        assert!(!family.section.is_empty());
        assert!(family.sampled_check_count > 0);
        let mut tampered = proof.clone();
        tampered.private_opening_evals[family.section.start] += p3_baby_bear::BabyBear::ONE;
        assert_eq!(
            <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered),
            Some(false),
            "{:?} Poseidon private opening tamper should reject",
            family.family
        );
    }
}

#[cfg(feature = "whir")]
#[test]
fn whir_proves_semantic_family_columnar_v2_batched_cp_skeleton() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::{
        canonical_whir_proof_bytes, whir_proof_from_canonical_bytes,
        whir_typed_batched_cp_family_columnar_v2_private_opening_profile,
        whir_typed_batched_cp_family_columnar_v2_verify_with_cache_stats,
    };
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, mut items) = build_fixture();
    let item = items.remove(0);
    let other_item = items.remove(0);
    let params_digest = whir_parameter_digest();
    let bucket = BatchedCpBucket::new(vec![item.clone()], params_digest).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket
        .shape
        .semantic_family_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        )
        .to_relation_description();
    assert_eq!(
        relation.num_constraints, 0,
        "SYMBT2F mode must not lower to appended typed CP R1CS"
    );

    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove the SYMBT2F skeleton");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    let (verify_ok_with_stats, cache_stats) =
        whir_typed_batched_cp_family_columnar_v2_verify_with_cache_stats(&vk, &public, &proof)
            .expect("SYMBT2F cache stats");
    assert!(verify_ok_with_stats);
    let unique_num_vars = proof
        .family_columnar_subproofs
        .iter()
        .map(|subproof| subproof.num_vars)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(
        cache_stats.misses, unique_num_vars,
        "SYMBT2F verifier infra should miss once per local domain size"
    );
    assert!(
        cache_stats.hits >= 1,
        "split SYMBT2F fixture should still reuse at least one local domain"
    );
    let profile = whir_typed_batched_cp_family_columnar_v2_private_opening_profile(
        &vk.seed,
        &vk.relation,
        &public,
    )
    .expect("SYMBT2F opening profile");
    assert_eq!(profile.total_len, proof.private_opening_evals.len());
    assert_eq!(
        profile.families.len(),
        proof.family_columnar_subproofs.len()
    );
    for (idx, (family, subproof)) in profile
        .families
        .iter()
        .zip(&proof.family_columnar_subproofs)
        .enumerate()
    {
        assert_eq!(family.subproof_index, Some(idx));
        assert_eq!(family.num_vars, Some(subproof.num_vars));
        assert_eq!(subproof.table_index, idx);
    }
    let encoded = canonical_whir_proof_bytes(&proof);
    let decoded = whir_proof_from_canonical_bytes(&encoded).expect("SYMBT2F payload decodes");
    assert_eq!(
        decoded.family_columnar_subproofs.len(),
        proof.family_columnar_subproofs.len()
    );
    assert_eq!(canonical_whir_proof_bytes(&decoded), encoded);
    let profile_families = profile
        .families
        .iter()
        .map(|entry| entry.family)
        .collect::<Vec<_>>();
    for family in [
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        BatchedCpSemanticConstraintFamily::ManifestMembership,
        BatchedCpSemanticConstraintFamily::RoundMessageBinding,
        BatchedCpSemanticConstraintFamily::ChallengeDerivation,
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
    ] {
        assert!(profile_families.contains(&family), "{family:?} missing");
    }
    assert!(
        profile_families
            .iter()
            .filter(|&&family| family == BatchedCpSemanticConstraintFamily::RoundMessageBinding)
            .count()
            > 1
    );
    assert!(
        profile_families
            .iter()
            .filter(|&&family| family == BatchedCpSemanticConstraintFamily::FoldedOutputDerivation)
            .count()
            > 1
    );

    for family in &profile.families {
        let mut tampered = proof.clone();
        tampered.private_opening_evals[family.section.start] += p3_baby_bear::BabyBear::ONE;
        assert_eq!(
            <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered),
            Some(false),
            "{:?} SYMBT2F private opening tamper should reject",
            family.family
        );
    }
    let mut tampered_z = proof.clone();
    tampered_z.family_columnar_subproofs[0].z_eval += p3_baby_bear::BabyBear::ONE;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_z),
        Some(false),
        "SYMBT2F subproof z-eval tamper should reject"
    );
    let mut tampered_table = proof.clone();
    tampered_table.family_columnar_subproofs[0].table_index += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_table),
        Some(false),
        "SYMBT2F table-index tamper should reject"
    );
    let mut tampered_num_vars = proof.clone();
    tampered_num_vars.family_columnar_subproofs[0].num_vars += 1;
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_num_vars),
        Some(false),
        "SYMBT2F local num-vars tamper should reject"
    );
    let mut tampered_pcs = proof.clone();
    tampered_pcs.family_columnar_subproofs[0].whir_pcs_proof =
        proof.family_columnar_subproofs[1].whir_pcs_proof.clone();
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered_pcs),
        Some(false),
        "SYMBT2F PCS subproof tamper should reject"
    );
    let mut truncated = proof.clone();
    truncated.private_opening_evals.pop();
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &truncated),
        Some(false)
    );
    let mut missing_subproof = proof.clone();
    missing_subproof.family_columnar_subproofs.pop();
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &missing_subproof),
        Some(false)
    );
    let mut appended_subproof = proof.clone();
    appended_subproof
        .family_columnar_subproofs
        .push(appended_subproof.family_columnar_subproofs[0].clone());
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &appended_subproof),
        Some(false)
    );

    let columnar_relation = bucket
        .shape
        .semantic_columnar_v2_relation_description(&prover.ajtai, &r1cs, prover.params.b_input())
        .to_relation_description();
    let (columnar_pk, _columnar_vk) = <WhirSnark as BackendSnark>::setup(&columnar_relation);
    let columnar_proof =
        <WhirSnark as CpBackend>::prove_typed_batched_cp(&columnar_pk, &public, &witness)
            .expect("SYMBT2C proof");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &columnar_proof),
        Some(false),
        "SYMBT2C proof must not verify as SYMBT2F"
    );

    let wrong_bucket = BatchedCpBucket::new(vec![item, other_item], params_digest).unwrap();
    let wrong_relation = wrong_bucket
        .shape
        .semantic_family_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        )
        .to_relation_description();
    let (_wrong_pk, wrong_vk) = <WhirSnark as BackendSnark>::setup(&wrong_relation);
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&wrong_vk, &public, &proof),
        Some(false)
    );
}

#[cfg(feature = "whir")]
#[test]
#[ignore = "heavy SYMBT2F Poseidon/BabyBear family-columnar WHIR proof-profile audit"]
fn whir_proves_poseidon_semantic_family_columnar_v2_batched_cp_skeleton() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::whir_typed_batched_cp_family_columnar_v2_private_opening_profile;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, bucket) = poseidon_columnar_fixture();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let relation = bucket
        .shape
        .semantic_family_columnar_v2_relation_description(
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        )
        .to_relation_description();
    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove the Poseidon/BabyBear SYMBT2F skeleton");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );
    let profile = whir_typed_batched_cp_family_columnar_v2_private_opening_profile(
        &vk.seed,
        &vk.relation,
        &public,
    )
    .expect("SYMBT2F Poseidon opening profile");
    assert_eq!(profile.total_len, proof.private_opening_evals.len());
    assert_eq!(profile.families.len(), 9);
}

#[cfg(feature = "whir")]
#[test]
fn poseidon_folded_algebra_offsets_match_product_oracle() {
    let (prover, r1cs, mut items) = build_babybear_fixture();
    let item = poseidon_shaped_item(items.remove(0), &prover);
    let bucket = BatchedCpBucket::new(vec![item], whir_parameter_digest()).unwrap();
    assert_eq!(
        bucket.shape.accumulator_shape.digest_scheme,
        PublicDigestScheme::Poseidon2BabyBear
    );
    assert!(!bucket
        .shape
        .folded_public_input_linear_constraints()
        .is_empty());
    assert!(!bucket
        .shape
        .folded_commitment_ring_mul_constraints()
        .is_empty());
    assert!(!bucket
        .shape
        .folded_evaluation_ring_mul_constraints()
        .is_empty());
    assert!(!bucket
        .shape
        .poseidon_fs_commitment_r1cs_constraints()
        .is_empty());
    let poseidon_surfaces = bucket.shape.poseidon_fs_commitment_r1cs_surfaces();
    assert!(!poseidon_surfaces.is_empty());
    assert!(
        poseidon_surfaces.iter().any(|surface| surface.num_rows
            > bucket.shape.poseidon_fs_commitment_r1cs_constraints().len()),
        "WHIR Poseidon row sampling should draw from the full R1CS row domain, not only the bounded regression candidate set"
    );

    let witness = bucket.witness_bundle();
    let oracle = witness
        .canonical_product_oracle_bytes(&bucket.shape)
        .expect("canonical product oracle");
    let layout = bucket.shape.product_oracle_layout();
    for round in 0..bucket.shape.accumulator_shape.num_rounds {
        let trace_output = layout.poseidon_fs_commitment_trace_outputs[round][0];
        let fs_commitment = layout.witness_fs_commitments[round][0];
        assert_eq!(
            &oracle[trace_output.offset..trace_output.offset + trace_output.len],
            &oracle[fs_commitment.offset..fs_commitment.offset + fs_commitment.len]
        );
    }
    assert_poseidon_folded_algebra_offsets_hold(&bucket.shape, &oracle);
    let semantic =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    assert_ajtai_opening_offsets_hold(&semantic, &oracle);
    assert_original_r1cs_offsets_hold(&semantic, &oracle);
}

#[cfg(feature = "whir")]
#[test]
#[ignore = "heavy SYMBTC1 Poseidon/BabyBear semantic proof audit"]
fn whir_poseidon_semantic_sections_reject_targeted_tampering() {
    use symphony::cp_backend_api::CpBackend;
    use symphony::snark::whir::whir_typed_batched_cp_private_opening_profile;
    use symphony::snark::BackendSnark;
    use symphony::WhirSnark;

    let (prover, r1cs, mut items) = build_babybear_fixture();
    let item = poseidon_shaped_item(items.remove(0), &prover);
    let bucket = BatchedCpBucket::new(vec![item], whir_parameter_digest()).unwrap();
    let public = bucket.public_statement();
    let witness = bucket.witness_bundle();
    let semantic =
        bucket
            .shape
            .semantic_relation_description(&prover.ajtai, &r1cs, prover.params.b_input());
    let relation = semantic.to_relation_description();
    let (pk, vk) = <WhirSnark as BackendSnark>::setup(&relation);
    let proof = <WhirSnark as CpBackend>::prove_typed_batched_cp(&pk, &public, &witness)
        .expect("WHIR should prove Poseidon/BabyBear semantic SYMBTC1 sections");
    assert_eq!(
        <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &proof),
        Some(true)
    );

    let profile = whir_typed_batched_cp_private_opening_profile(&vk.seed, &vk.relation, &public)
        .expect("semantic proof opening profile");
    assert_eq!(profile.total_len, proof.private_opening_evals.len());
    let sections = [
        ("equality", profile.equality),
        ("folded public input", profile.folded_public_input),
        ("folded commitment", profile.folded_commitment),
        ("folded evaluation", profile.folded_evaluation),
        ("Poseidon R1CS", profile.poseidon_r1cs),
        ("Ajtai opening", profile.ajtai_opening),
        ("original R1CS", profile.original_r1cs),
    ];
    for (label, section) in sections {
        assert!(!section.is_empty(), "{label} section should be present");
        let mut tampered = proof.clone();
        tampered.private_opening_evals[section.start] += p3_baby_bear::BabyBear::ONE;
        assert_eq!(
            <WhirSnark as CpBackend>::verify_typed_batched_cp(&vk, &public, &tampered),
            Some(false),
            "{label} private opening tamper should reject"
        );
    }
}
