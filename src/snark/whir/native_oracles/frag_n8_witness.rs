pub fn build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness(
    pk: &WhirProvingKey,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
) -> Option<Symbt3N7bNativeTupleLeafProofParts> {
    build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
        pk,
        accumulator_instance,
        witness,
        adapter,
        None,
    )
}

fn build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
    pk: &WhirProvingKey,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    mut profile: Option<&mut N8DirectSemanticInputBuildProfileV1>,
) -> Option<Symbt3N7bNativeTupleLeafProofParts> {
    if !adapter.full_accumulator_workload
        || adapter.smoke_profile
        || adapter.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || adapter.proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || adapter.profile_digest != accumulator_instance.profile_digest
        || adapter.manifest_oracle_root != accumulator_instance.manifest_oracle_root
        || adapter.native_message_roots_digest != accumulator_instance.message_oracle_roots_digest
        || adapter.batch_size != accumulator_instance.batch_capacity as u64
        || adapter.active_count != accumulator_instance.active_count as u64
        || accumulator_instance.message_oracle_roots.len() != witness.message_oracles.len()
    {
        return None;
    }

    let section_start = Instant::now();
    let mut raw_evaluations = Vec::with_capacity(2 + witness.message_oracles.len());
    let mut manifest_values = n7b_rows_to_babybear_values(&witness.manifest_oracle);
    if manifest_values.is_empty() {
        manifest_values = n7b_digest_values(&[
            accumulator_instance.manifest_oracle_root,
            adapter.batch_manifest_root,
            accumulator_instance.manifest_layout_digest,
        ]);
    }
    raw_evaluations.push(manifest_values);
    raw_evaluations.push(n7b_rows_to_babybear_values(&witness.source_columns));
    raw_evaluations.extend(
        witness
            .message_oracles
            .iter()
            .map(n7b_typed_message_oracle_values),
    );
    if raw_evaluations.iter().any(Vec::is_empty) {
        return None;
    }
    let (num_vars, evaluations) = n7b_pad_to_common_num_vars(raw_evaluations)?;
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_raw_values_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
    let opening_schedule = WhirNativeOpeningSchedule::TranscriptDerived {
        domain_separator: SYMBT3_RLC_TUPLE_LEAF_PACKING_DOMAIN,
    };
    let mut specs = Vec::with_capacity(evaluations.len());
    specs.push(WhirNativeOracleSpec {
        version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
        oracle_id: SYMBT3_N2_MANIFEST_ORACLE_ID,
        role: WhirNativeOracleRole::Manifest,
        layout_digest: accumulator_instance.manifest_layout_digest,
        num_vars,
        opening_schedule: opening_schedule.clone(),
    });
    specs.push(WhirNativeOracleSpec {
        version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
        oracle_id: SYMBT3_N2_SOURCE_ORACLE_ID,
        role: WhirNativeOracleRole::Source,
        layout_digest: accumulator_instance.source_column_layout_digest,
        num_vars,
        opening_schedule: opening_schedule.clone(),
    });
    for (round, root) in accumulator_instance
        .message_oracle_roots
        .iter()
        .copied()
        .enumerate()
    {
        let round_u32 = u32::try_from(round).ok()?;
        specs.push(WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N4_MESSAGE_ORACLE_ID_BASE.checked_add(round_u32)?,
            role: WhirNativeOracleRole::MessageRound { round: round_u32 },
            layout_digest: n7b_message_round_layout_digest(
                accumulator_instance.message_semantic_layout_digest,
                round,
                root,
            ),
            num_vars,
            opening_schedule: opening_schedule.clone(),
        });
    }
    let eval_requests = specs
        .iter()
        .map(|spec| WhirNativeEvalRequest {
            oracle_id: spec.oracle_id,
            claim_kind: WhirNativeEvalClaimKind::DirectOpening,
        })
        .collect::<Vec<_>>();
    validate_same_domain_tuple_leaf_inputs(&specs, &evaluations, &eval_requests).ok()?;

    let mode = Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1;
    let logical_oracle_count = specs.len();
    let descriptor_digest = native_oracle_spec_digest(&specs);
    let repetition_log_size =
        symbt3_tuple_leaf_repetition_log_size(SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT)?;
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        mode,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    );
    let repeated_packing_challenges = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        mode,
        adapter.main_symbt3_relation_id,
        adapter.public_statement_digest,
        adapter.whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        logical_oracle_count,
        num_vars,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
    )?;
    let packing_challenge_digest =
        symbt3_tuple_leaf_repeated_packing_challenge_digest(&repeated_packing_challenges);
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_descriptor_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
    let claim_kind = WhirNativeEvalClaimKind::DirectOpening;
    let evals_by_id = specs
        .iter()
        .zip(evaluations.iter())
        .map(|(spec, evaluations)| (spec.oracle_id, evaluations.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let packed_num_vars = num_vars.checked_add(repetition_log_size)?;
    let mut logical_claims =
        Vec::with_capacity(eval_requests.len() * SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT);
    let mut packed_eval_claims = Vec::with_capacity(SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT);
    let mut packed_evaluations = Vec::new();
    for (repetition_index, packing_challenges) in repeated_packing_challenges.iter().enumerate() {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            adapter.main_symbt3_relation_id,
            adapter.public_statement_digest,
            adapter.whir_param_digest,
            descriptor_digest,
            tuple_leaf_layout_digest,
            claim_kind,
            num_vars,
        );
        let point_digest = native_oracle_point_digest(&point);
        let mut repetition_claims = Vec::with_capacity(eval_requests.len());
        for request in &eval_requests {
            let evaluations = *evals_by_id.get(&request.oracle_id)?;
            repetition_claims.push(WhirNativeOracleEvalClaim {
                oracle_id: request.oracle_id,
                point_digest,
                value: mle_eval_bb(evaluations, &point),
                claim_kind: request.claim_kind,
            });
        }
        let logical_values = repetition_claims
            .iter()
            .map(|claim| claim.value)
            .collect::<Vec<_>>();
        let packed_value = symbt3_tuple_leaf_pack_values(packing_challenges, &logical_values)?;
        let repetition_packed_evaluations =
            symbt3_tuple_leaf_pack_evaluations(packing_challenges, &evaluations)?;
        let mut packed_point = point;
        packed_point.extend(tuple_leaf_boolean_point_for_index(
            repetition_index,
            repetition_log_size,
        ));
        let packed_point_digest = native_oracle_point_digest(&packed_point);
        packed_eval_claims.push(Symbt3TupleLeafPackedEvalClaim {
            point_digest: packed_point_digest,
            value: packed_value,
            claim_kind,
        });
        packed_evaluations.extend(repetition_packed_evaluations);
        logical_claims.extend(repetition_claims);
    }
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_claims_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
    let packed_root = whir_initial_root_digest(
        &pk.seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        packed_num_vars,
        &packed_evaluations,
    )?;
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_packed_root_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }
    let counters = tuple_leaf_counters_for(
        logical_oracle_count,
        logical_claims.len(),
        num_vars,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    );
    let proof = Symbt3TupleLeafMultiOracleProof {
        version: SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION,
        mode,
        proof_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        logical_descriptors: specs,
        descriptor_digest,
        tuple_leaf_layout_digest,
        packing_challenge_digest,
        packed_root,
        packed_eval_claims,
        logical_eval_claims: logical_claims,
        whir_pcs_proof: WhirPcsProof::<F, EF, WhirMmcs>::default(),
        counters,
    };
    let source_oracle_root = accumulator_instance.source_assignment_roots_digest;
    let descriptors = proof
        .logical_descriptors
        .iter()
        .zip(
            std::iter::once(accumulator_instance.manifest_oracle_root)
                .chain(std::iter::once(source_oracle_root))
                .chain(accumulator_instance.message_oracle_roots.iter().copied()),
        )
        .map(|(spec, root)| spec.descriptor_with_root(root))
        .collect::<Vec<_>>();
    let native_oracle_descriptor_digest = native_oracle_descriptor_digest(&descriptors);
    Some(Symbt3N7bNativeTupleLeafProofParts {
        proof,
        native_oracle_descriptor_digest,
        native_message_roots_digest: adapter.native_message_roots_digest,
        manifest_oracle_root: accumulator_instance.manifest_oracle_root,
        source_oracle_root,
    })
}

#[derive(Debug, Clone, Copy)]
struct N8DirectValidatedK6aSetupMaterialV1 {
    relation_id: Digest32,
    profile_digest: Digest32,
    accumulator_instance_digest: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
}

fn n8_direct_timed_digest<T>(
    digest_canonical_serialization_ms: &mut f64,
    build: impl FnOnce() -> T,
) -> T {
    let start = Instant::now();
    let value = build();
    *digest_canonical_serialization_ms += start.elapsed().as_secs_f64() * 1_000.0;
    value
}

fn n8_direct_product_non_zk_profile_ok(
    profile: &Symbt3AuthorityProfile,
    relation: &BatchedCpSymbt3RelationDescription,
) -> bool {
    profile.routing_status == crate::batched_cp::Symbt3RoutingStatus::ProductAuthority
        && profile.product_eligible
        && !profile.research_only
        && profile.zk_status == crate::batched_cp::Symbt3ZkStatus::NonZkIntegrityOnly
        && crate::batched_cp::product_policy_accepts_non_zk(profile)
        && crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        && profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
}

fn n8_direct_accumulator_instance_matches_prebuilt_statement(
    profile_digest: Digest32,
    accumulator_instance: &Symbt3AccumulatorInstance,
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    digest_canonical_serialization_ms: &mut f64,
) -> bool {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let expected_source_assignment_roots_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-assignment-roots",
                &accumulator_instance.source_assignment_roots,
            )
        });
    let expected_source_ajtai_opening_roots_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-ajtai-opening-roots",
                &accumulator_instance.source_ajtai_opening_roots,
            )
        });
    let expected_message_oracle_roots_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-message-oracle-roots",
                &accumulator_instance.message_oracle_roots,
            )
        });
    let expected_batch_items_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_batch_items_digest(
                scheme,
                &accumulator_instance.input_public_values,
                &accumulator_instance.input_commitment_values,
                &accumulator_instance.input_evaluation_values,
                &accumulator_instance.input_accumulator_values,
                &accumulator_instance.source_assignment_roots,
                &accumulator_instance.message_oracle_roots,
            )
        });
    let expected_public_source_boundary_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_public_source_boundary_digest(
                scheme,
                &expected_source_assignment_roots_digest,
                &accumulator_instance.source_assignment_boundary_digest,
                &expected_source_ajtai_opening_roots_digest,
                &accumulator_instance.source_ajtai_commitment_boundary_digest,
            )
        });
    let statement_bytes_len = n8_direct_timed_digest(digest_canonical_serialization_ms, || {
        statement.canonical_bytes().len()
    });

    accumulator_instance.profile_digest == profile_digest
        && accumulator_instance.shape_id == relation.shape.shape_id
        && accumulator_instance.batch_capacity == relation.shape.batch_capacity
        && accumulator_instance.active_count == relation.shape.active_count
        && accumulator_instance.batch_items_digest == expected_batch_items_digest
        && accumulator_instance.public_source_boundary_digest
            == expected_public_source_boundary_digest
        && accumulator_instance.source_assignment_roots_digest
            == expected_source_assignment_roots_digest
        && accumulator_instance.source_ajtai_opening_roots_digest
            == expected_source_ajtai_opening_roots_digest
        && accumulator_instance.message_oracle_roots_digest == expected_message_oracle_roots_digest
        && statement.matches_relation(relation)
        && statement_bytes_len == relation.public_statement_bytes()
}

fn n8_direct_validated_k6a_setup_material(
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    relation: &BatchedCpSymbt3RelationDescription,
    digest_canonical_serialization_ms: &mut f64,
) -> Option<(
    crate::batched_cp::BatchedCpSymbt3PublicStatement,
    N8DirectValidatedK6aSetupMaterialV1,
)> {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let relation_id =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || relation.relation_id());
    let profile_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || profile.digest(scheme));
    if !n8_direct_product_non_zk_profile_ok(profile, relation)
        || profile.semantic_profile_version < 1
    {
        return None;
    }
    let statement = accumulator_instance.to_public_statement();
    if !n8_direct_accumulator_instance_matches_prebuilt_statement(
        profile_digest,
        accumulator_instance,
        relation,
        &statement,
        digest_canonical_serialization_ms,
    ) {
        return None;
    }
    let public_statement_digest = n8_direct_timed_digest(digest_canonical_serialization_ms, || {
        derive_symbt3_public_statement_digest(relation, &statement)
    });
    let accumulator_instance_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            accumulator_instance.digest(scheme)
        });
    let whir_param_digest = statement.whir_parameter_digest;
    Some((
        statement,
        N8DirectValidatedK6aSetupMaterialV1 {
            relation_id,
            profile_digest,
            accumulator_instance_digest,
            public_statement_digest,
            whir_param_digest,
        },
    ))
}

fn symbt3_k6a_relation_from_context(context: &[u8]) -> Option<BatchedCpSymbt3RelationDescription> {
    BatchedCpSymbt3RelationDescription::from_context_bytes(context).ok()
}

fn symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_proof(
    relation: &BatchedCpSymbt3RelationDescription,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    proof: &WhirProof,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || proof.is_output
        || !proof.sumcheck_rounds_3.is_empty()
        || !proof.linear_checks.is_empty()
        || !proof.family_columnar_subproofs.is_empty()
        || !crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        || !crate::batched_cp::product_policy_accepts_non_zk(profile)
        || !profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
        || !accumulator_instance.matches_profile_and_relation(profile, relation)
    {
        return None;
    }
    let statement = accumulator_instance.to_public_statement();
    if !profile.accepts_statement_for_non_zk_integrity_product_authority(relation, &statement) {
        return None;
    }
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        full_accumulator_workload: true,
        smoke_profile: false,
        proof_kind,
        profile_digest: profile.digest(scheme),
        accumulator_instance_digest: accumulator_instance.digest(scheme),
        public_statement_digest: derive_symbt3_public_statement_digest(relation, &statement),
        whir_param_digest: statement.whir_parameter_digest,
        main_symbt3_relation_id: relation.relation_id(),
        main_symbt3_proof_digest: symbt3_main_whir_proof_digest(proof),
        old_accumulator_digest: statement.old_accumulator_digest,
        new_accumulator_digest: statement.new_accumulator_digest,
        batch_manifest_root: statement.batch_manifest_root,
        manifest_oracle_root: statement.manifest_oracle_root,
        native_message_roots_digest: accumulator_instance.message_oracle_roots_digest,
        batch_size: statement.batch_capacity as u64,
        active_count: statement.active_count as u64,
        main_whir_num_vars: proof.num_vars,
        main_oracle_len: 1usize.checked_shl(proof.num_vars as u32).unwrap_or(0),
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: proof.family_columnar_subproofs.len(),
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        source_r1cs_residual_verifier_evaluations: 1,
    };
    symbt3_native_accumulator_k6a_workload_adapter_from_parts((&adapter).into())
}

#[cfg(test)]
fn symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_semantic_source(
    relation: &BatchedCpSymbt3RelationDescription,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    source: &Symbt3N8K6aSemanticSourceV1,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    let statement = super::symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
        profile,
        accumulator_instance,
        relation,
    )?;
    symbt3_native_accumulator_k6a_workload_adapter_from_relation_statement_and_semantic_source(
        relation,
        profile,
        accumulator_instance,
        &statement,
        proof_kind,
        source,
    )
}

#[cfg(test)]
fn symbt3_native_accumulator_k6a_workload_adapter_from_relation_statement_and_semantic_source(
    relation: &BatchedCpSymbt3RelationDescription,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    proof_kind: ProductProofKind,
    source: &Symbt3N8K6aSemanticSourceV1,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || source.source_digest == [0u8; 32]
        || source.relation_id != relation.relation_id()
        || source.num_vars == 0
        || source.oracle_len != symbt3_n8_oracle_len(source.num_vars)?
        || source.verifier_claims.is_empty()
        || source.verifier_points.len() != source.verifier_claims.len()
        || source
            .final_residuals
            .iter()
            .any(|&value| value != BabyBear::ZERO)
        || !crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        || !crate::batched_cp::product_policy_accepts_non_zk(profile)
        || !profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
        || !accumulator_instance.matches_profile_and_relation(profile, relation)
    {
        return None;
    }
    let public_statement_digest = derive_symbt3_public_statement_digest(relation, statement);
    if source.public_statement_digest != public_statement_digest
        || source.whir_param_digest != statement.whir_parameter_digest
        || !profile.accepts_statement_for_non_zk_integrity_product_authority(relation, statement)
    {
        return None;
    }
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        full_accumulator_workload: true,
        smoke_profile: false,
        proof_kind,
        profile_digest: profile.digest(scheme),
        accumulator_instance_digest: accumulator_instance.digest(scheme),
        public_statement_digest,
        whir_param_digest: statement.whir_parameter_digest,
        main_symbt3_relation_id: relation.relation_id(),
        main_symbt3_proof_digest: source.source_digest,
        old_accumulator_digest: statement.old_accumulator_digest,
        new_accumulator_digest: statement.new_accumulator_digest,
        batch_manifest_root: statement.batch_manifest_root,
        manifest_oracle_root: statement.manifest_oracle_root,
        native_message_roots_digest: accumulator_instance.message_oracle_roots_digest,
        batch_size: statement.batch_capacity as u64,
        active_count: statement.active_count as u64,
        main_whir_num_vars: source.num_vars,
        main_oracle_len: source.oracle_len,
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        source_r1cs_residual_verifier_evaluations: 1,
    };
    symbt3_native_accumulator_k6a_workload_adapter_from_parts((&adapter).into())
}

fn symbt3_native_accumulator_k6a_workload_adapter_from_validated_direct_material(
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    source: &Symbt3N8K6aSemanticSourceV1,
    material: N8DirectValidatedK6aSetupMaterialV1,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || source.source_digest == [0u8; 32]
        || source.relation_id != material.relation_id
        || source.public_statement_digest != material.public_statement_digest
        || source.whir_param_digest != material.whir_param_digest
        || source.num_vars == 0
        || source.oracle_len != symbt3_n8_oracle_len(source.num_vars)?
        || source.verifier_claims.is_empty()
        || source.verifier_points.len() != source.verifier_claims.len()
        || source
            .final_residuals
            .iter()
            .any(|&value| value != BabyBear::ZERO)
        || statement.whir_parameter_digest != material.whir_param_digest
    {
        return None;
    }
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        full_accumulator_workload: true,
        smoke_profile: false,
        proof_kind,
        profile_digest: material.profile_digest,
        accumulator_instance_digest: material.accumulator_instance_digest,
        public_statement_digest: material.public_statement_digest,
        whir_param_digest: material.whir_param_digest,
        main_symbt3_relation_id: material.relation_id,
        main_symbt3_proof_digest: source.source_digest,
        old_accumulator_digest: statement.old_accumulator_digest,
        new_accumulator_digest: statement.new_accumulator_digest,
        batch_manifest_root: statement.batch_manifest_root,
        manifest_oracle_root: statement.manifest_oracle_root,
        native_message_roots_digest: accumulator_instance.message_oracle_roots_digest,
        batch_size: statement.batch_capacity as u64,
        active_count: statement.active_count as u64,
        main_whir_num_vars: source.num_vars,
        main_oracle_len: source.oracle_len,
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        source_r1cs_residual_verifier_evaluations: 1,
    };
    symbt3_native_accumulator_k6a_workload_adapter_from_parts((&adapter).into())
}

#[must_use]
pub fn build_n8_semantic_inputs_from_k6a_witness(
    pk: &WhirProvingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
) -> Option<N8DirectSemanticInputsV1> {
    let total_start = Instant::now();
    let mut build_profile = N8DirectSemanticInputBuildProfileV1::default();

    let relation_statement_start = Instant::now();
    let section_start = Instant::now();
    let relation = symbt3_k6a_relation_from_context(pk.relation.context.as_ref()?)?;
    build_profile.k6a_relation_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let (statement, setup_material) = n8_direct_validated_k6a_setup_material(
        profile,
        accumulator_instance,
        &relation,
        &mut build_profile.digest_canonical_serialization_ms,
    )?;
    build_profile.k6a_public_statement_construction_ms =
        section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let symbt3_witness = witness.to_symbt3_witness(&relation)?;
    build_profile.k6a_witness_conversion_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    build_profile.relation_statement_ms =
        relation_statement_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let k6a_semantic_source = symbt3_n8_k6a_semantic_source_from_witness_with_public_digest(
        &pk.seed,
        &relation,
        &statement,
        &symbt3_witness,
        Some(setup_material.public_statement_digest),
        Some(setup_material.relation_id),
        Some(&mut build_profile.digest_canonical_serialization_ms),
    )?;
    build_profile.k6a_claim_extraction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let k6a_adapter =
        symbt3_native_accumulator_k6a_workload_adapter_from_validated_direct_material(
            &statement,
            accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &k6a_semantic_source,
            setup_material,
        )?;
    build_profile.adapter_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let native_tuple_leaf = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
        pk,
        accumulator_instance,
        witness,
        &k6a_adapter,
        Some(&mut build_profile),
    )?;
    build_profile.tuple_rlc_input_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    build_profile.total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;

    Some(N8DirectSemanticInputsV1 {
        relation,
        statement,
        k6a_semantic_source,
        k6a_adapter,
        native_tuple_leaf,
        profile: build_profile,
    })
}

