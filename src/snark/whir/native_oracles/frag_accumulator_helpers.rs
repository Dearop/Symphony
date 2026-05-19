fn native_accumulator_authority_counters(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    tuple_proof: &Symbt3TupleLeafMultiOracleProof,
    main_symbt3_whir_proof: &WhirProof,
    workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
) -> Option<Symbt3NativeAccumulatorAuthorityCounters> {
    let round_count = instance.round_layouts.len();
    if tuple_proof.counters
        != tuple_leaf_counters_for(
            tuple_proof.logical_descriptors.len(),
            tuple_proof.logical_eval_claims.len(),
            tuple_proof.logical_descriptors.first()?.num_vars,
            tuple_proof.counters.rlc_repetition_count,
            tuple_proof.counters.rlc_batching_bits_per_repetition,
        )
    {
        return None;
    }
    let rlc_repetition_count = tuple_proof.counters.rlc_repetition_count;
    let rlc_batching_bits_per_repetition = tuple_proof.counters.rlc_batching_bits_per_repetition;
    let total_rlc_batching_bits =
        rlc_repetition_count.saturating_mul(rlc_batching_bits_per_repetition);
    Some(Symbt3NativeAccumulatorAuthorityCounters {
        full_accumulator_workload: matches!(
            workload_kind,
            Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        ),
        smoke_profile: matches!(
            workload_kind,
            Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1
        ),
        workload_kind,
        main_whir_num_vars: main_symbt3_whir_proof.num_vars,
        main_oracle_len: 1usize
            .checked_shl(main_symbt3_whir_proof.num_vars as u32)
            .unwrap_or(0),
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        backend_table_count: instance.backend_table_count,
        native_multi_oracle: tuple_proof.mode
            == Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1
            && tuple_proof.counters.whir_instance_count == 1
            && tuple_proof.counters.root_count == 1,
        tuple_leaf_layout: tuple_proof.counters.tuple_leaf_layout.clone(),
        whir_instance_count: tuple_proof.counters.whir_instance_count,
        root_count: tuple_proof.counters.root_count,
        query_schedule_count: tuple_proof.counters.query_schedule_count,
        transcript_count: tuple_proof.counters.transcript_count,
        native_oracle_pcs_opening_count: tuple_proof.counters.native_oracle_pcs_opening_count,
        logical_oracle_count: tuple_proof.counters.logical_oracle_count,
        native_manifest_source_oracle_count: 2,
        native_message_oracle_count: round_count,
        accumulator_transition_claims: instance.accumulator_transition_claims,
        source_r1cs_residual_verifier_evaluations: instance.backend_table_count,
        rlc_batching_bits: total_rlc_batching_bits,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
        total_rlc_batching_bits,
        effective_soundness_bits: total_rlc_batching_bits,
        native_oracle_eval_claim_count: tuple_proof.counters.logical_eval_claim_count,
        fallback_used: instance.monolithic_fallback,
    })
}

#[must_use]
pub fn symbt3_native_accumulator_authority_profile_metadata(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    counters: &Symbt3NativeAccumulatorAuthorityCounters,
) -> Symbt3NativeAccumulatorAuthorityProfileMetadata {
    let (target_soundness_bits, soundness_bound_bits) = match counters.workload_kind {
        Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1 => (
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_TARGET_SOUNDNESS_BITS,
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_TARGET_SOUNDNESS_BITS,
        ),
        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1 => (
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS,
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS,
        ),
    };
    Symbt3NativeAccumulatorAuthorityProfileMetadata {
        workload_kind: counters.workload_kind,
        full_accumulator_workload: counters.full_accumulator_workload,
        smoke_profile: counters.smoke_profile,
        native_profile: instance.native_profile,
        manifest_policy: Some(instance.manifest_policy),
        source_policy: Some(instance.source_policy),
        message_oracle_policy: Some(instance.message_oracle_policy),
        root_policy: instance.root_policy,
        zk_status: instance.zk_status,
        multi_oracle_mode: Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1,
        tuple_leaf_layout: counters.tuple_leaf_layout.clone(),
        rlc_batching_bits: Some(counters.rlc_batching_bits),
        rlc_repetition_count: counters.rlc_repetition_count,
        rlc_batching_bits_per_repetition: counters.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: counters.total_rlc_batching_bits,
        effective_soundness_bits: counters.effective_soundness_bits,
        target_soundness_bits,
        soundness_bound_bits,
        committed_private_component_count: instance.committed_private_component_count,
        native_manifest_source_oracle_count: counters.native_manifest_source_oracle_count,
        native_message_round_count: instance.round_layouts.len(),
        native_message_oracle_count: counters.native_message_oracle_count,
        logical_oracle_count: counters.logical_oracle_count,
        whir_instance_count: counters.whir_instance_count,
        root_count: counters.root_count,
        query_schedule_count: counters.query_schedule_count,
        transcript_count: counters.transcript_count,
        native_oracle_pcs_opening_count: counters.native_oracle_pcs_opening_count,
        batch_size: usize::try_from(instance.batch_size).unwrap_or(usize::MAX),
        batch_axis_log_size: instance.batch_axis_log_size,
        message_round_layouts: instance.round_layouts.clone(),
        top_level_whir_proof_count: counters.top_level_whir_proof_count,
        family_columnar_subproof_count: counters.family_columnar_subproof_count,
        message_to_trace_binding_count: 0,
        semantic_profile_version: instance.semantic_profile_version,
        required_semantic_families: instance.required_semantic_families,
        k5_masking_available: instance.k5_masking_available,
        monolithic_fallback: instance.monolithic_fallback || counters.fallback_used,
        product_default_route_attempted: instance.product_default_route_attempted,
        product_eligible: instance.product_eligible,
        native_product_route_version_exists: instance.native_product_route_version_exists,
    }
}

fn symbt3_native_accumulator_authority_semantics_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    symbt3_native_accumulator_authority_tuple_leaf_semantics_ok(instance, proof)
        && symbt3_native_accumulator_authority_manifest_source_semantics_ok(proof)
        && symbt3_native_accumulator_authority_message_semantics_ok(instance, proof)
        && symbt3_native_accumulator_authority_binding_ok(instance, proof)
}

fn symbt3_native_accumulator_authority_tuple_leaf_semantics_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    let tuple_proof = &proof.rlc_tuple_leaf_multi_oracle_proof;
    let Some(descriptors) = symbt3_native_accumulator_authority_logical_descriptors(proof) else {
        return false;
    };
    let Some(expected_counters) = native_accumulator_authority_counters(
        instance,
        tuple_proof,
        &proof.main_symbt3_whir_proof,
        proof.workload_kind,
    ) else {
        return false;
    };
    if proof.counters != expected_counters
        || tuple_proof.version != SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION
        || tuple_proof.mode != Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1
        || tuple_proof.proof_relation_id != instance.symbt3_relation_id
        || tuple_proof.public_statement_digest != proof.public_statement_digest
        || tuple_proof.whir_param_digest != instance.whir_param_digest
        || tuple_proof.logical_descriptors.len() != 2 + instance.round_layouts.len()
        || tuple_proof.logical_eval_claims.len()
            != tuple_proof
                .logical_descriptors
                .len()
                .saturating_mul(tuple_proof.counters.rlc_repetition_count)
        || proof.native_oracle_descriptor_digest != native_oracle_descriptor_digest(&descriptors)
        || proof.rlc_tuple_leaf_layout_digest != tuple_proof.tuple_leaf_layout_digest
        || proof.rlc_tuple_leaf_root != tuple_proof.packed_root
        || proof.counters.native_oracle_pcs_opening_count != 1
        || !proof.counters.native_multi_oracle
        || proof.counters.tuple_leaf_layout != SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
    {
        return false;
    }
    let common_num_vars = tuple_proof.logical_descriptors[0].num_vars;
    let Some(expected_specs) =
        symbt3_native_accumulator_authority_tuple_leaf_specs(instance, common_num_vars)
    else {
        return false;
    };
    tuple_proof.logical_descriptors == expected_specs
}

fn symbt3_native_accumulator_authority_manifest_source_semantics_ok(
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    let claims = &proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims;
    let specs = &proof.rlc_tuple_leaf_multi_oracle_proof.logical_descriptors;
    if claims.len() < 2 || specs.len() < 2 {
        return false;
    }
    let manifest_spec = &specs[0];
    let source_spec = &specs[1];
    let manifest_claim = &claims[0];
    let source_claim = &claims[1];
    manifest_spec.oracle_id == SYMBT3_N2_MANIFEST_ORACLE_ID
        && source_spec.oracle_id == SYMBT3_N2_SOURCE_ORACLE_ID
        && manifest_spec.role == WhirNativeOracleRole::Manifest
        && source_spec.role == WhirNativeOracleRole::Source
        && manifest_claim.oracle_id == SYMBT3_N2_MANIFEST_ORACLE_ID
        && source_claim.oracle_id == SYMBT3_N2_SOURCE_ORACLE_ID
        && manifest_claim.claim_kind == WhirNativeEvalClaimKind::DirectOpening
        && source_claim.claim_kind == WhirNativeEvalClaimKind::DirectOpening
        && manifest_claim.point_digest == source_claim.point_digest
        && manifest_claim.value == source_claim.value
}

fn symbt3_native_accumulator_authority_message_semantics_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    let Some(descriptors) = symbt3_native_accumulator_authority_logical_descriptors(proof) else {
        return false;
    };
    let message_descriptors = &descriptors[2..];
    if proof.native_message_roots_digest != native_message_roots_digest(message_descriptors)
        || proof.native_message_roots.len() != instance.round_layouts.len()
        || proof.counters.logical_oracle_count != 2 + instance.round_layouts.len()
        || proof.counters.native_message_oracle_count != instance.round_layouts.len()
    {
        return false;
    }
    let first_repetition_claims =
        &proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[..descriptors.len()];
    for ((descriptor, layout), claim) in message_descriptors
        .iter()
        .zip(instance.round_layouts.iter())
        .zip(first_repetition_claims[2..].iter())
    {
        if descriptor.oracle_id != layout.oracle_id
            || descriptor.role
                != (WhirNativeOracleRole::MessageRound {
                    round: layout.round_index,
                })
            || descriptor.layout_digest != layout.layout_digest
            || descriptor.num_vars < layout.total_num_vars
            || claim.oracle_id != layout.oracle_id
            || claim.claim_kind != WhirNativeEvalClaimKind::DirectOpening
        {
            return false;
        }
    }
    let context =
        symbt3_native_folding_integrity_challenge_context(instance, proof.batch_manifest_root);
    let Some(round_challenges) =
        derive_native_round_challenges(message_descriptors, &instance.round_layouts, &context)
    else {
        return false;
    };
    proof.round_challenges == round_challenges
}

fn symbt3_native_accumulator_authority_binding_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    if proof.batch_manifest_root
        != native_batch_manifest_root(
            instance.manifest_layout_digest,
            proof.manifest_oracle_root,
            native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
        )
        || proof.old_accumulator_digest != symbt3_native_accumulator_old_digest(instance)
        || proof.new_accumulator_digest
            != symbt3_native_accumulator_new_digest(
                instance,
                proof.old_accumulator_digest,
                proof.batch_manifest_root,
            )
    {
        return false;
    }
    proof.native_binding_digest
        == native_accumulator_authority_binding_digest(
            proof.workload_kind,
            proof.profile_digest,
            proof.accumulator_instance_digest,
            proof.public_statement_digest,
            instance.whir_param_digest,
            instance.symbt3_relation_id,
            proof.main_symbt3_proof_digest,
            proof.rlc_tuple_leaf_root,
            proof.rlc_tuple_leaf_layout_digest,
            proof.native_oracle_descriptor_digest,
            proof.native_message_roots_digest,
            proof.manifest_oracle_root,
            proof.source_oracle_root,
            proof.batch_manifest_root,
            proof.old_accumulator_digest,
            proof.new_accumulator_digest,
            instance.batch_size,
            instance.active_count,
        )
}

fn symbt3_native_accumulator_authority_logical_descriptors(
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> Option<Vec<WhirNativeOracleDescriptor>> {
    let specs = &proof.rlc_tuple_leaf_multi_oracle_proof.logical_descriptors;
    if specs.len() < 2 || proof.native_message_roots.len() != specs.len().saturating_sub(2) {
        return None;
    }
    let mut roots = Vec::with_capacity(specs.len());
    roots.push(proof.manifest_oracle_root);
    roots.push(proof.source_oracle_root);
    roots.extend(proof.native_message_roots.iter().copied());
    let descriptors = specs
        .iter()
        .zip(roots)
        .map(|(spec, root)| spec.descriptor_with_root(root))
        .collect::<Vec<_>>();
    validate_descriptors(&descriptors).ok()?;
    Some(descriptors)
}

fn native_manifest_source_fail_report(
    proof: &WhirNativeMultiOracleProof,
) -> WhirNativeOracleVerifyReport {
    WhirNativeOracleVerifyReport {
        ok: false,
        counters: proof.counters.clone(),
        native_oracle_verify_ms: 0.0,
    }
}

fn committed_private_manifest_fail_report(
    proof: &Symbt3CommittedPrivateManifestMembershipProof,
) -> Symbt3CommittedPrivateManifestVerifyReport {
    let native_report = native_manifest_source_fail_report(&proof.membership_proof.native_proof);
    Symbt3CommittedPrivateManifestVerifyReport {
        ok: false,
        native_report,
        committed_private_component_count: proof
            .public_statement
            .committed_private_component_count(),
        committed_private_public_bytes: proof.public_statement.committed_private_public_bytes(),
        public_statement_bytes: proof.public_statement.public_statement_bytes(),
    }
}

fn native_round_message_fail_report(
    proof: &Symbt3NativeRoundMessageOracleProof,
    round_challenges: Vec<BabyBear>,
) -> Symbt3NativeRoundMessageOracleVerifyReport {
    Symbt3NativeRoundMessageOracleVerifyReport {
        ok: false,
        native_report: native_manifest_source_fail_report(&proof.native_proof),
        native_message_round_count: proof.native_proof.descriptors.len(),
        message_to_trace_binding_count: 0,
        round_challenges,
    }
}

fn num_vars_for_evals(evaluations: &[BabyBear]) -> Option<usize> {
    if evaluations.len() < 2 || !evaluations.len().is_power_of_two() {
        return None;
    }
    Some(evaluations.len().trailing_zeros() as usize)
}

fn validate_specs(specs: &[WhirNativeOracleSpec]) -> Result<(), ()> {
    if specs.is_empty() {
        return Err(());
    }
    let mut previous = None;
    for spec in specs {
        if spec.version != WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION || spec.num_vars == 0 {
            return Err(());
        }
        if let Some(prev) = previous {
            if spec.oracle_id <= prev {
                return Err(());
            }
        }
        previous = Some(spec.oracle_id);
    }
    Ok(())
}

fn validate_same_domain_tuple_leaf_inputs(
    specs: &[WhirNativeOracleSpec],
    logical_evaluations: &[Vec<BabyBear>],
    eval_requests: &[WhirNativeEvalRequest],
) -> Result<(), ()> {
    validate_same_domain_tuple_leaf_specs(specs)?;
    if specs.len() != logical_evaluations.len() || specs.len() != eval_requests.len() {
        return Err(());
    }
    let num_vars = specs[0].num_vars;
    let expected_len = 1usize.checked_shl(num_vars as u32).ok_or(())?;
    for evaluations in logical_evaluations {
        if evaluations.len() != expected_len {
            return Err(());
        }
    }
    let claim_kind = eval_requests.first().ok_or(())?.claim_kind;
    for (spec, request) in specs.iter().zip(eval_requests.iter()) {
        if request.oracle_id != spec.oracle_id || request.claim_kind != claim_kind {
            return Err(());
        }
    }
    Ok(())
}

fn validate_same_domain_tuple_leaf_specs(specs: &[WhirNativeOracleSpec]) -> Result<(), ()> {
    validate_specs(specs)?;
    let num_vars = specs[0].num_vars;
    let schedule = specs[0].opening_schedule.canonical_bytes();
    if matches!(
        specs[0].opening_schedule,
        WhirNativeOpeningSchedule::PerOraclePoint
    ) {
        return Err(());
    }
    for spec in specs {
        if spec.num_vars != num_vars
            || spec.opening_schedule.canonical_bytes() != schedule
            || matches!(
                spec.opening_schedule,
                WhirNativeOpeningSchedule::PerOraclePoint
            )
        {
            return Err(());
        }
    }
    Ok(())
}

fn validate_same_domain_tuple_leaf_claim_shape(
    specs: &[WhirNativeOracleSpec],
    claims: &[WhirNativeOracleEvalClaim],
) -> Result<(), ()> {
    validate_same_domain_tuple_leaf_specs(specs)?;
    if claims.is_empty() || claims.len() % specs.len() != 0 {
        return Err(());
    }
    let claim_kind = claims.first().ok_or(())?.claim_kind;
    for claim_chunk in claims.chunks(specs.len()) {
        for (spec, claim) in specs.iter().zip(claim_chunk.iter()) {
            if claim.oracle_id != spec.oracle_id || claim.claim_kind != claim_kind {
                return Err(());
            }
        }
    }
    Ok(())
}

fn validate_descriptors(descriptors: &[WhirNativeOracleDescriptor]) -> Result<(), ()> {
    if descriptors.is_empty() {
        return Err(());
    }
    let mut previous = None;
    for descriptor in descriptors {
        if descriptor.version != WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION || descriptor.num_vars == 0 {
            return Err(());
        }
        if let Some(prev) = previous {
            if descriptor.oracle_id <= prev {
                return Err(());
            }
        }
        previous = Some(descriptor.oracle_id);
    }
    Ok(())
}

fn tuple_leaf_counters_for(
    logical_oracle_count: usize,
    logical_eval_claim_count: usize,
    num_vars: usize,
    rlc_repetition_count: usize,
    rlc_batching_bits_per_repetition: usize,
) -> Symbt3TupleLeafMultiOracleCounters {
    let oracle_len = 1usize.checked_shl(num_vars as u32).unwrap_or(0);
    let total_rlc_batching_bits =
        rlc_repetition_count.saturating_mul(rlc_batching_bits_per_repetition);
    Symbt3TupleLeafMultiOracleCounters {
        logical_oracle_count,
        whir_instance_count: 1,
        query_schedule_count: 1,
        transcript_count: 1,
        root_count: 1,
        native_oracle_pcs_opening_count: 1,
        logical_eval_claim_count,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
        total_rlc_batching_bits,
        effective_soundness_bits: total_rlc_batching_bits,
        tuple_leaf_layout: SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT.to_owned(),
        same_domain: true,
        same_field: true,
        same_rate: true,
        same_folding_parameter: true,
        merkle_path_proxy: num_vars.max(1),
        hash_estimate: num_vars.max(1).saturating_mul(2).saturating_add(1),
        field_op_estimate: logical_oracle_count
            .saturating_mul(oracle_len)
            .saturating_add(logical_oracle_count.saturating_mul(logical_eval_claim_count)),
    }
}

fn tuple_leaf_boolean_point_for_index(index: usize, len: usize) -> Vec<BabyBear> {
    (0..len)
        .map(|bit| {
            if ((index >> bit) & 1) == 1 {
                BabyBear::ONE
            } else {
                BabyBear::ZERO
            }
        })
        .collect()
}

fn counters_for(
    descriptors: &[WhirNativeOracleDescriptor],
    claim_count: usize,
    pcs_opening_count: usize,
) -> WhirNativeOracleCounters {
    WhirNativeOracleCounters {
        native_oracle_count: descriptors.len(),
        native_oracle_descriptor_bytes: native_oracle_descriptor_bytes_len(descriptors),
        native_oracle_eval_claim_count: claim_count,
        native_oracle_opening_count: claim_count,
        native_oracle_pcs_opening_count: pcs_opening_count,
        native_oracle_transcript_squeezes: claim_count,
    }
}
