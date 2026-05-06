mod common;

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
    BatchedCpSemanticColumnarV2Description, BatchedCpSemanticFamilyColumnarV2Description,
    BatchedCpSemanticFamilyTraceV2, BatchedCpSemanticRelationV2Description,
    BatchedCpSemanticTraceV2,
};
use symphony::commitment::Commitment;
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
    *tampered.last_mut().unwrap() ^= 1;
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
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        BatchedCpSemanticRelationV2Description::from_context_bytes(&tampered).unwrap_err(),
        BatchedCpError::InvalidSemanticRelationContext
    );
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
