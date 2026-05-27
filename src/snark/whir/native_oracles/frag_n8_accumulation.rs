/// ACC.P for the explicit N8 integrated accumulation route.
///
/// This prover derives a new accumulator object and one integrated WHIR proof
/// for the opt-in same-shape, nonempty NonZK N8 boundary. It is separate from
/// both the default product `verify_public` route and the K6a/N7b explicit
/// routes.
pub fn accumulate_symbt3_n8_non_zk(
    pk: &WhirProvingKey,
    batch: &Symbt3AccumulationBatch,
    old_accumulator: &Symbt3AccumulatorObject,
    witness: &Symbt3AccumulatorWitness,
) -> Result<(Symbt3AccumulatorObject, Symbt3AccumulationProof), Symbt3N8IntegratedPrototypeBlocker>
{
    let context =
        symbt3_n8_accumulation_public_context_from_pk(pk, batch, &old_accumulator.public_instance)?;
    let semantic_inputs = build_n8_semantic_inputs_from_k6a_witness(
        pk,
        &batch.profile,
        &context.accumulator_instance,
        witness,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)?;
    let descriptor =
        build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs(
            &semantic_inputs,
        )?;
    let proof_plan = build_n8_integrated_whir_proof_plan(
        &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
    )?;
    let output = prove_symbt3_integrated_whir_from_claim_plan(pk, &descriptor, &proof_plan)?;
    let gate_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
    if gate_report.blocked {
        return Err(gate_report
            .blocker
            .unwrap_or(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected));
    }
    let proof = symbt3_n8_accumulation_proof_from_descriptor_output(
        context.public_statement_digest,
        context.accumulator_instance_digest,
        descriptor,
        output,
    );
    Ok((context.new_accumulator, proof))
}

/// ACC.V for the explicit N8 integrated accumulation route.
///
/// This verifies only the N8 public accumulation boundary: public batch,
/// old/new public accumulators, the N8 authority gate, and one integrated WHIR
/// backend proof. It does not dispatch to K6a, N7b, or the default product
/// `verify_public` route.
#[must_use]
pub fn verify_symbt3_n8_accumulation_non_zk(
    vk: &WhirVerifyingKey,
    public_batch: &Symbt3AccumulationBatch,
    old_accumulator_public: &Symbt3AccumulatorPublicInstance,
    new_accumulator_public: &Symbt3AccumulatorPublicInstance,
    proof: &Symbt3AccumulationProof,
) -> Symbt3AccumulationVerificationReport {
    let context = match symbt3_n8_accumulation_public_context_from_vk(
        vk,
        public_batch,
        old_accumulator_public,
        new_accumulator_public,
    ) {
        Ok(context) => context,
        Err(blocker) => return Symbt3AccumulationVerificationReport::blocked(blocker),
    };
    if let Some(blocker) =
        symbt3_n8_accumulation_binding_blocker(&context.relation, &context, proof)
    {
        return Symbt3AccumulationVerificationReport::blocked(blocker);
    }
    let authority_report =
        verify_symbt3_n8_integrated_prover_output_authority_gate(&proof.descriptor, &proof.output);
    if authority_report.blocked {
        return Symbt3AccumulationVerificationReport::from_gate_report(authority_report);
    }
    let verifier_input = proof.output.verifier_input(&proof.descriptor);
    let backend_report =
        verify_symbt3_integrated_whir_backend_from_verifier_input(vk, &verifier_input);
    if backend_report.blocked {
        return Symbt3AccumulationVerificationReport::from_gate_report(backend_report);
    }
    Symbt3AccumulationVerificationReport::ok(authority_report.semantic_completion)
}

/// ACC.D for the explicit N8 integrated accumulation route.
///
/// This is the route-selection decision entry point for
/// `N8NonZkSameShapeV1`. It first checks the explicit N8 authority-profile
/// version and then delegates to ACC.V. It does not alter or shadow the
/// default product `verify_public` path.
#[must_use]
pub fn decide_symbt3_n8_accumulator_non_zk(
    authority_profile: Symbt3AccumulationAuthorityProfile,
    vk: &WhirVerifyingKey,
    public_batch: &Symbt3AccumulationBatch,
    old_accumulator_public: &Symbt3AccumulatorPublicInstance,
    new_accumulator_public: &Symbt3AccumulatorPublicInstance,
    proof: &Symbt3AccumulationProof,
) -> Symbt3AccumulationVerificationReport {
    if authority_profile.version() != SYMBT3_ACCUMULATION_AUTHORITY_PROFILE_VERSION {
        return Symbt3AccumulationVerificationReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch,
        );
    }
    verify_symbt3_n8_accumulation_non_zk(
        vk,
        public_batch,
        old_accumulator_public,
        new_accumulator_public,
        proof,
    )
}

#[must_use]
fn symbt3_n8_integrated_constraint_digest(
    kind: Symbt3N8IntegratedConstraintKind,
    payload: impl FnOnce(&mut Vec<u8>),
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_N8_INTEGRATED_CONSTRAINT_DIGEST_V1");
    push_bytes(&mut bytes, &kind.canonical_bytes());
    payload(&mut bytes);
    digest_bytes(&bytes)
}

#[must_use]
fn symbt3_n8_integrated_transcript_binding_digest(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        SYMBT3_N8_INTEGRATED_K6A_NATIVE_TRANSCRIPT_DOMAIN.as_bytes(),
    );
    push_bytes(
        &mut bytes,
        &descriptor.canonical_bytes_without_transcript_digest(),
    );
    digest_bytes(&bytes)
}

#[must_use]
fn symbt3_n8_integrated_logical_oracle_descriptors_digest(
    descriptors: &[IntegratedK6aNativeLogicalOracleDescriptorV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"INTEGRATED_K6A_NATIVE_LOGICAL_ORACLE_DESCRIPTORS_DIGEST_V1",
    );
    push_u64(&mut bytes, descriptors.len() as u64);
    for descriptor in descriptors {
        push_bytes(&mut bytes, &descriptor.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
fn symbt3_n8_integrated_constraint_descriptors_digest(
    descriptors: &[Symbt3N8IntegratedConstraintDescriptor],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"INTEGRATED_K6A_NATIVE_CONSTRAINT_DESCRIPTORS_DIGEST_V1",
    );
    push_u64(&mut bytes, descriptors.len() as u64);
    for descriptor in descriptors {
        push_bytes(&mut bytes, &descriptor.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
fn symbt3_n8_integrated_claim_descriptors_digest(
    descriptors: &[IntegratedK6aNativeClaimDescriptorV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"INTEGRATED_K6A_NATIVE_CLAIM_DESCRIPTORS_DIGEST_V1",
    );
    push_u64(&mut bytes, descriptors.len() as u64);
    for descriptor in descriptors {
        push_bytes(&mut bytes, &descriptor.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
fn symbt3_n8_integrated_claim_plan_digest(plan: &IntegratedK6aNativeClaimPlanV1) -> Digest32 {
    digest_bytes(&plan.canonical_bytes_without_digest())
}

#[must_use]
fn symbt3_n8_integrated_committed_table_layout_digest(
    table: &IntegratedK6aNativeCommittedTableV1,
) -> Digest32 {
    digest_bytes(&table.canonical_layout_bytes_without_digest())
}

#[must_use]
fn symbt3_n8_integrated_committed_table_digest(
    table: &IntegratedK6aNativeCommittedTableV1,
) -> Digest32 {
    digest_bytes(&table.canonical_table_bytes_without_digest())
}

#[must_use]
fn n8_integrated_whir_claim_bridge_descriptor(
    kind: N8IntegratedWhirClaimBridgeKindV1,
    claim_count: usize,
    source_num_vars: usize,
    integrated_num_vars: usize,
    source_constraint_digest: Digest32,
    source_claim_digest: Digest32,
    table_layout_digest: Digest32,
) -> N8IntegratedWhirClaimBridgeDescriptorV1 {
    let mut descriptor = N8IntegratedWhirClaimBridgeDescriptorV1 {
        kind,
        claim_count,
        source_num_vars,
        integrated_num_vars,
        source_constraint_digest,
        source_claim_digest,
        table_layout_digest,
        descriptor_digest: [0u8; 32],
    };
    descriptor.descriptor_digest = digest_bytes(&descriptor.canonical_bytes_without_digest());
    descriptor
}

#[must_use]
fn n8_integrated_whir_claim_bridge_descriptors_digest(
    descriptors: &[N8IntegratedWhirClaimBridgeDescriptorV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_WHIR_CLAIM_BRIDGE_DESCRIPTORS_DIGEST_V1",
    );
    push_u64(&mut bytes, descriptors.len() as u64);
    for descriptor in descriptors {
        push_bytes(&mut bytes, &descriptor.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[cfg(test)]
fn n8_integrated_evaluator_row_is_k6a_source(row: &RealIntegratedK6aNativeEvaluatorRowV1) -> bool {
    matches!(
        row.kind,
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorResidualClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorZEvalClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aProductSumcheckRoundClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1
    )
}

fn n8_integrated_evaluator_row_semantic_batching_family(
    row: &RealIntegratedK6aNativeEvaluatorRowV1,
) -> Option<N8SemanticBatchingFamilyV1> {
    match row.kind {
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorResidualClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorZEvalClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aProductSumcheckRoundClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1 => {
            Some(N8SemanticBatchingFamilyV1::K6aSourceRowsV1)
        }
        RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticVerifierOpeningClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticZEvalBindingV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticProductSumcheckAcceptedV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticPaddingZeroV1 => {
            Some(N8SemanticBatchingFamilyV1::K6aSemanticRowsV1)
        }
        RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1
        | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1 => {
            Some(N8SemanticBatchingFamilyV1::TupleRlcSemanticRowsV1)
        }
        RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1 => {
            Some(N8SemanticBatchingFamilyV1::TransitionBindingSemanticRowsV1)
        }
    }
}

fn n8_semantic_batching_family_rows_digest_and_count(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
    family: N8SemanticBatchingFamilyV1,
) -> (Digest32, usize) {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_SEMANTIC_BATCHING_FAMILY_ROWS_DIGEST_V1");
    push_bytes(&mut bytes, &family.canonical_bytes());
    let rows = evaluator
        .rows
        .iter()
        .filter(|row| n8_integrated_evaluator_row_semantic_batching_family(row) == Some(family))
        .collect::<Vec<_>>();
    let row_count = rows.len();
    push_u64(&mut bytes, row_count as u64);
    for row in rows {
        push_bytes(&mut bytes, &row.canonical_bytes());
    }
    (digest_bytes(&bytes), row_count)
}

fn n8_semantic_batching_binding_digest(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_SEMANTIC_BATCHING_BINDING_V1");
    push_digest(&mut bytes, &descriptor.transcript_binding_digest);
    push_digest(&mut bytes, &descriptor.claim_plan.claim_plan_digest);
    push_digest(&mut bytes, &descriptor.committed_table.layout_digest);
    push_digest(&mut bytes, &descriptor.committed_table.table_digest);
    push_digest(
        &mut bytes,
        &descriptor.k6a_semantic_constraints.descriptor_digest,
    );
    push_digest(
        &mut bytes,
        &descriptor.tuple_rlc_semantic_constraints.descriptor_digest,
    );
    push_digest(
        &mut bytes,
        &descriptor
            .transition_binding_semantic_constraints
            .descriptor_digest,
    );
    push_digest(&mut bytes, &descriptor.real_evaluator.rows_digest);
    push_digest(&mut bytes, &descriptor.real_evaluator.table_digest);
    digest_bytes(&bytes)
}

fn n8_semantic_batching_point(
    descriptor_binding_digest: Digest32,
    family: N8SemanticBatchingFamilyV1,
    integrated_num_vars: usize,
) -> Vec<BabyBear> {
    let mut transcript = Vec::new();
    push_bytes(&mut transcript, b"N8_SEMANTIC_BATCHING_POINT_V1");
    push_digest(&mut transcript, &descriptor_binding_digest);
    push_bytes(&mut transcript, &family.canonical_bytes());
    (0..integrated_num_vars)
        .map(|axis| {
            let challenge =
                derive_challenge(&transcript, axis, b"N8_SEMANTIC_BATCHING_POINT_AXIS_V1");
            if challenge == BabyBear::ZERO {
                BabyBear::from_u32(2)
            } else if challenge == BabyBear::ONE {
                BabyBear::from_u32(3)
            } else {
                challenge
            }
        })
        .collect()
}

fn n8_semantic_batching_family_descriptor_digest(
    descriptor: &N8SemanticBatchingFamilyDescriptorV1,
) -> Digest32 {
    digest_bytes(&descriptor.canonical_bytes_without_digest())
}

fn n8_semantic_batching_family_descriptor(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
    descriptor_binding_digest: Digest32,
    family: N8SemanticBatchingFamilyV1,
) -> N8SemanticBatchingFamilyDescriptorV1 {
    let (row_digest, source_row_count) =
        n8_semantic_batching_family_rows_digest_and_count(evaluator, family);
    let point_digest = if source_row_count == 0 {
        [0u8; 32]
    } else {
        native_oracle_point_digest(&n8_semantic_batching_point(
            descriptor_binding_digest,
            family,
            evaluator.integrated_num_vars,
        ))
    };
    let mut descriptor = N8SemanticBatchingFamilyDescriptorV1 {
        family,
        source_row_count,
        batched_query_count: usize::from(source_row_count > 0),
        row_digest,
        challenge_point_digest: point_digest,
        soundness_bits: if source_row_count == 0 {
            0
        } else {
            N8_SEMANTIC_BATCHING_CHALLENGE_SOUNDNESS_BITS
        },
        descriptor_digest: [0u8; 32],
    };
    descriptor.descriptor_digest = n8_semantic_batching_family_descriptor_digest(&descriptor);
    descriptor
}

fn n8_k6a_source_row_batching_descriptor_digest(
    source_batching: &N8K6aSourceRowBatchingV1,
) -> Digest32 {
    digest_bytes(&source_batching.canonical_bytes_without_digest())
}

fn n8_semantic_batching_descriptor_digest(batching: &N8SemanticBatchingV1) -> Digest32 {
    digest_bytes(&batching.canonical_bytes_without_digest())
}

fn n8_semantic_batching_descriptor(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> N8SemanticBatchingV1 {
    let descriptor_binding_digest = n8_semantic_batching_binding_digest(descriptor);
    let source_descriptor = n8_semantic_batching_family_descriptor(
        &descriptor.real_evaluator,
        descriptor_binding_digest,
        N8SemanticBatchingFamilyV1::K6aSourceRowsV1,
    );
    let mut k6a_source = N8K6aSourceRowBatchingV1 {
        version: N8_SEMANTIC_BATCHING_VERSION,
        enabled: source_descriptor.source_row_count > 0,
        descriptor: source_descriptor,
        unbatched_source_opening_count: source_descriptor.source_row_count,
        batched_source_opening_count: source_descriptor.batched_query_count,
        effective_soundness_bits: source_descriptor.soundness_bits,
        descriptor_digest: [0u8; 32],
    };
    k6a_source.descriptor_digest = n8_k6a_source_row_batching_descriptor_digest(&k6a_source);
    let k6a = n8_semantic_batching_family_descriptor(
        &descriptor.real_evaluator,
        descriptor_binding_digest,
        N8SemanticBatchingFamilyV1::K6aSemanticRowsV1,
    );
    let tuple_rlc = n8_semantic_batching_family_descriptor(
        &descriptor.real_evaluator,
        descriptor_binding_digest,
        N8SemanticBatchingFamilyV1::TupleRlcSemanticRowsV1,
    );
    let transition_binding = n8_semantic_batching_family_descriptor(
        &descriptor.real_evaluator,
        descriptor_binding_digest,
        N8SemanticBatchingFamilyV1::TransitionBindingSemanticRowsV1,
    );
    let unbatched_semantic_opening_count = k6a
        .source_row_count
        .saturating_add(tuple_rlc.source_row_count)
        .saturating_add(transition_binding.source_row_count);
    let batched_semantic_opening_count = k6a
        .batched_query_count
        .saturating_add(tuple_rlc.batched_query_count)
        .saturating_add(transition_binding.batched_query_count);
    let effective_soundness_bits = [k6a, tuple_rlc, transition_binding]
        .into_iter()
        .chain(std::iter::once(k6a_source.descriptor))
        .filter(|descriptor| descriptor.source_row_count > 0)
        .map(|descriptor| descriptor.soundness_bits)
        .min()
        .unwrap_or(0);
    let mut batching = N8SemanticBatchingV1 {
        version: N8_SEMANTIC_BATCHING_VERSION,
        enabled: true,
        descriptor_binding_digest,
        k6a_source,
        k6a,
        tuple_rlc,
        transition_binding,
        unbatched_semantic_opening_count,
        batched_semantic_opening_count,
        effective_soundness_bits,
        descriptor_digest: [0u8; 32],
    };
    batching.descriptor_digest = n8_semantic_batching_descriptor_digest(&batching);
    batching
}

#[must_use]
fn n8_integrated_whir_query_claims_digest(claims: &[N8IntegratedWhirQueryClaimV1]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_INTEGRATED_WHIR_QUERY_CLAIMS_DIGEST_V1");
    push_u64(&mut bytes, claims.len() as u64);
    for claim in claims {
        push_bytes(&mut bytes, &claim.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
fn n8_integrated_whir_query_schedule_digest(
    schedule: &N8IntegratedWhirQueryScheduleV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_INTEGRATED_WHIR_QUERY_SCHEDULE_DIGEST_V1");
    push_bytes(&mut bytes, &schedule.canonical_bytes_without_digest());
    digest_bytes(&bytes)
}

#[must_use]
pub fn build_n8_integrated_whir_query_schedule_for_claims(
    proof_plan: &N8IntegratedWhirProofPlan,
    query_claims: Vec<N8IntegratedWhirQueryClaimV1>,
) -> N8IntegratedWhirQueryScheduleV1 {
    let query_claims_digest = n8_integrated_whir_query_claims_digest(&query_claims);
    let mut schedule = N8IntegratedWhirQueryScheduleV1 {
        version: N8_INTEGRATED_WHIR_QUERY_SCHEDULE_VERSION,
        integrated_num_vars: proof_plan.integrated_num_vars,
        transcript_digest: proof_plan.transcript_digest,
        combined_bridge_claim_descriptor_digest: proof_plan.combined_bridge_claim_descriptor_digest,
        query_claims,
        query_claims_digest,
        query_schedule_digest: [0u8; 32],
    };
    schedule.query_schedule_digest = n8_integrated_whir_query_schedule_digest(&schedule);
    schedule
}

#[must_use]
fn n8_integrated_whir_tuple_repeated_rlc_claim_bridge_digest(
    packed_claim_descriptor: &IntegratedK6aNativeClaimDescriptorV1,
    logical_claim_descriptor: &IntegratedK6aNativeClaimDescriptorV1,
    tuple_repetition_axis: &IntegratedK6aNativeTupleRepetitionAxisMappingV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_WHIR_TUPLE_REPEATED_RLC_CLAIM_BRIDGE_V1",
    );
    push_bytes(&mut bytes, &packed_claim_descriptor.canonical_bytes());
    push_bytes(&mut bytes, &logical_claim_descriptor.canonical_bytes());
    push_bytes(&mut bytes, &tuple_repetition_axis.canonical_bytes());
    digest_bytes(&bytes)
}

#[must_use]
#[allow(clippy::too_many_arguments)]
fn n8_integrated_whir_accumulator_transition_binding_claim_bridge_digest_from_parts(
    main_symbt3_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    claim_plan_digest: Digest32,
    committed_table_layout_digest: Digest32,
    committed_table_digest: Digest32,
    old_accumulator_digest: Digest32,
    new_accumulator_digest: Digest32,
    batch_manifest_root: Digest32,
    tuple_leaf_root: Digest32,
    native_message_roots_digest: Digest32,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_WHIR_ACCUMULATOR_TRANSITION_BINDING_CLAIM_BRIDGE_PARTS_V1",
    );
    push_digest(&mut bytes, &main_symbt3_relation_id);
    push_digest(&mut bytes, &public_statement_digest);
    push_digest(&mut bytes, &whir_param_digest);
    push_digest(&mut bytes, &claim_plan_digest);
    push_digest(&mut bytes, &committed_table_layout_digest);
    push_digest(&mut bytes, &committed_table_digest);
    push_digest(&mut bytes, &old_accumulator_digest);
    push_digest(&mut bytes, &new_accumulator_digest);
    push_digest(&mut bytes, &batch_manifest_root);
    push_digest(&mut bytes, &tuple_leaf_root);
    push_digest(&mut bytes, &native_message_roots_digest);
    digest_bytes(&bytes)
}

#[must_use]
fn n8_integrated_whir_accumulator_transition_binding_claim_bridge_digest(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_WHIR_ACCUMULATOR_TRANSITION_BINDING_CLAIM_BRIDGE_V1",
    );
    push_digest(&mut bytes, &descriptor.main_symbt3_relation_id);
    push_digest(&mut bytes, &descriptor.public_statement_digest);
    push_digest(&mut bytes, &descriptor.whir_param_digest);
    push_digest(&mut bytes, &descriptor.claim_plan.claim_plan_digest);
    push_digest(&mut bytes, &descriptor.committed_table.layout_digest);
    push_digest(&mut bytes, &descriptor.committed_table.table_digest);
    push_digest(&mut bytes, &descriptor.real_evaluator.evaluator_digest);
    push_digest(&mut bytes, &descriptor.real_evaluator.rows_digest);
    push_digest(&mut bytes, &descriptor.transcript_binding_digest);
    push_digest(
        &mut bytes,
        &descriptor
            .transition_binding_semantic_constraints
            .descriptor_digest,
    );
    push_digest(
        &mut bytes,
        &descriptor
            .transition_binding_semantic_constraints
            .transition_binding_digest,
    );
    push_digest(
        &mut bytes,
        &descriptor
            .transition_binding_semantic_constraints
            .rows_digest,
    );
    if let Some(k6a_claim_descriptor) = descriptor.claim_plan.claim_descriptors.first() {
        push_bytes(&mut bytes, &k6a_claim_descriptor.canonical_bytes());
    }
    if let Some(k6a_constraint_descriptor) = descriptor.claim_plan.constraint_descriptors.first() {
        push_bytes(&mut bytes, &k6a_constraint_descriptor.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
fn n8_integrated_whir_proof_plan_transcript_digest(plan: &N8IntegratedWhirProofPlan) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        SYMBT3_N8_INTEGRATED_K6A_NATIVE_TRANSCRIPT_DOMAIN.as_bytes(),
    );
    push_bytes(&mut bytes, b"N8_INTEGRATED_WHIR_PROOF_PLAN_TRANSCRIPT_V1");
    push_bytes(
        &mut bytes,
        &plan.canonical_bytes_without_transcript_digest(),
    );
    digest_bytes(&bytes)
}

#[must_use]
fn symbt3_tuple_leaf_packed_eval_claims_digest(
    claims: &[Symbt3TupleLeafPackedEvalClaim],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_TUPLE_LEAF_PACKED_EVAL_CLAIMS_V1");
    push_u64(&mut bytes, claims.len() as u64);
    for claim in claims {
        push_bytes(&mut bytes, &claim.canonical_bytes());
    }
    digest_bytes(&bytes)
}

fn symbt3_n8_k6a_semantic_source_digest(
    relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    num_vars: usize,
    oracle_len: usize,
    verifier_points_digest: Digest32,
    verifier_claims_digest: Digest32,
    final_residual_digest: Digest32,
    product_sumcheck_digest: Digest32,
    z_eval: BabyBear,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_K6A_SEMANTIC_SOURCE_FROM_CLAIMS_V1");
    push_digest(&mut bytes, &relation_id);
    push_digest(&mut bytes, &public_statement_digest);
    push_digest(&mut bytes, &whir_param_digest);
    push_u64(&mut bytes, num_vars as u64);
    push_u64(&mut bytes, oracle_len as u64);
    push_digest(&mut bytes, &verifier_points_digest);
    push_digest(&mut bytes, &verifier_claims_digest);
    push_digest(&mut bytes, &final_residual_digest);
    push_digest(&mut bytes, &product_sumcheck_digest);
    push_babybear(&mut bytes, z_eval);
    digest_bytes(&bytes)
}

fn symbt3_n8_k6a_semantic_source_from_claims(
    relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    claims: super::Symbt3CClaims,
) -> Option<Symbt3N8K6aSemanticSourceV1> {
    let oracle_len = symbt3_n8_oracle_len(claims.num_vars)?;
    let verifier_points_digest = n8_integrated_k6a_verifier_points_digest(&claims.points);
    let verifier_claims_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
        &claims.claimed,
    );
    let final_residual_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
        &claims.evaluations,
    );
    let product_sumcheck_digest =
        n8_integrated_k6a_product_sumcheck_digest(&claims.product_sumcheck_rounds);
    let source_digest = symbt3_n8_k6a_semantic_source_digest(
        relation_id,
        public_statement_digest,
        whir_param_digest,
        claims.num_vars,
        oracle_len,
        verifier_points_digest,
        verifier_claims_digest,
        final_residual_digest,
        product_sumcheck_digest,
        claims.z_eval,
    );
    Some(Symbt3N8K6aSemanticSourceV1 {
        source_digest,
        relation_id,
        public_statement_digest,
        whir_param_digest,
        num_vars: claims.num_vars,
        oracle_len,
        verifier_points: claims.points,
        verifier_claims: claims.claimed,
        final_residuals: claims.evaluations,
        z_eval: claims.z_eval,
        product_sumcheck_rounds: claims.product_sumcheck_rounds,
    })
}

#[cfg(test)]
fn symbt3_n8_k6a_semantic_source_from_witness(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    witness: &crate::batched_cp::BatchedCpSymbt3Witness,
) -> Option<Symbt3N8K6aSemanticSourceV1> {
    symbt3_n8_k6a_semantic_source_from_witness_with_public_digest(
        seed, relation, statement, witness, None, None, None,
    )
}

fn symbt3_n8_k6a_semantic_source_from_witness_with_public_digest(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    public_statement_digest: Option<Digest32>,
    relation_id: Option<Digest32>,
    digest_canonical_serialization_ms: Option<&mut f64>,
) -> Option<Symbt3N8K6aSemanticSourceV1> {
    let claims = super::symbt3_c_table_and_claims_with_public_digest(
        seed,
        relation,
        statement,
        Some(witness),
        None,
        None,
        public_statement_digest,
    )?;
    if claims.table.is_none()
        || claims.claimed.is_empty()
        || claims.points.len() != claims.claimed.len()
        || claims
            .evaluations
            .iter()
            .any(|&value| value != BabyBear::ZERO)
    {
        return None;
    }
    let digest_start = Instant::now();
    let source = symbt3_n8_k6a_semantic_source_from_claims(
        relation_id.unwrap_or_else(|| relation.relation_id()),
        claims.public_statement_digest,
        statement.whir_parameter_digest,
        claims,
    )?;
    if let Some(total) = digest_canonical_serialization_ms {
        *total += digest_start.elapsed().as_secs_f64() * 1_000.0;
    }
    Some(source)
}

#[cfg(test)]
fn symbt3_n8_k6a_semantic_source_from_proof(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    proof: &WhirProof,
) -> Option<Symbt3N8K6aSemanticSourceV1> {
    let claims = super::symbt3_c_table_and_claims(
        seed,
        relation,
        statement,
        None,
        Some(&proof.private_opening_evals),
        Some(&proof.sumcheck_rounds_4),
    )?;
    if proof.is_output
        || !proof.sumcheck_rounds_3.is_empty()
        || !proof.linear_checks.is_empty()
        || !proof.family_columnar_subproofs.is_empty()
        || proof.num_vars != claims.num_vars
        || proof.evaluations != claims.evaluations
        || proof.z_eval != claims.z_eval
        || proof.private_opening_evals != claims.claimed
        || claims.points.len() != claims.claimed.len()
        || claims
            .evaluations
            .iter()
            .any(|&value| value != BabyBear::ZERO)
    {
        return None;
    }
    symbt3_n8_k6a_semantic_source_from_claims(
        relation.relation_id(),
        claims.public_statement_digest,
        statement.whir_parameter_digest,
        claims,
    )
}

fn symbt3_n8_k6a_claim_descriptor_digest_from_source(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    source: &Symbt3N8K6aSemanticSourceV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"INTEGRATED_K6A_NATIVE_K6A_CLAIM_DESCRIPTOR_V1");
    push_digest(&mut bytes, &adapter.main_symbt3_relation_id);
    push_digest(&mut bytes, &adapter.public_statement_digest);
    push_digest(&mut bytes, &adapter.whir_param_digest);
    push_digest(&mut bytes, &adapter.main_symbt3_proof_digest);
    push_u64(&mut bytes, adapter.main_whir_num_vars as u64);
    push_u64(&mut bytes, adapter.main_oracle_len as u64);
    push_u64(&mut bytes, adapter.accumulator_transition_claims as u64);
    push_u64(
        &mut bytes,
        adapter.source_r1cs_residual_verifier_evaluations as u64,
    );
    push_babybear_vec(&mut bytes, &source.verifier_claims);
    push_babybear_vec(&mut bytes, &source.final_residuals);
    push_babybear(&mut bytes, source.z_eval);
    push_u64(&mut bytes, source.product_sumcheck_rounds.len() as u64);
    for round in &source.product_sumcheck_rounds {
        for &value in round {
            push_babybear(&mut bytes, value);
        }
    }
    digest_bytes(&bytes)
}

fn symbt3_n8_k6a_claim_row_count_from_source(source: &Symbt3N8K6aSemanticSourceV1) -> usize {
    source
        .verifier_claims
        .len()
        .saturating_add(source.final_residuals.len())
        .saturating_add(1)
        .saturating_add(source.product_sumcheck_rounds.len().saturating_mul(4))
}

#[must_use]
fn symbt3_n8_k6a_claim_descriptor_digest(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    k6a_proof: &WhirProof,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"INTEGRATED_K6A_NATIVE_K6A_CLAIM_DESCRIPTOR_V1");
    push_digest(&mut bytes, &adapter.main_symbt3_relation_id);
    push_digest(&mut bytes, &adapter.public_statement_digest);
    push_digest(&mut bytes, &adapter.whir_param_digest);
    push_digest(&mut bytes, &adapter.main_symbt3_proof_digest);
    push_u64(&mut bytes, adapter.main_whir_num_vars as u64);
    push_u64(&mut bytes, adapter.main_oracle_len as u64);
    push_u64(&mut bytes, adapter.accumulator_transition_claims as u64);
    push_u64(
        &mut bytes,
        adapter.source_r1cs_residual_verifier_evaluations as u64,
    );
    push_babybear_vec(&mut bytes, &k6a_proof.private_opening_evals);
    push_babybear_vec(&mut bytes, &k6a_proof.evaluations);
    push_babybear(&mut bytes, k6a_proof.z_eval);
    push_u64(&mut bytes, k6a_proof.sumcheck_rounds_4.len() as u64);
    for round in &k6a_proof.sumcheck_rounds_4 {
        for &value in round {
            push_babybear(&mut bytes, value);
        }
    }
    digest_bytes(&bytes)
}

fn symbt3_n8_k6a_claim_row_count(k6a_proof: &WhirProof) -> usize {
    k6a_proof
        .private_opening_evals
        .len()
        .saturating_add(k6a_proof.evaluations.len())
        .saturating_add(1)
        .saturating_add(k6a_proof.sumcheck_rounds_4.len().saturating_mul(4))
}

fn n8_integrated_k6a_verifier_points_digest(points: &[Vec<BabyBear>]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_INTEGRATED_K6A_VERIFIER_POINTS_DIGEST_V1");
    push_u64(&mut bytes, points.len() as u64);
    for point in points {
        push_babybear_vec(&mut bytes, point);
    }
    digest_bytes(&bytes)
}

fn n8_integrated_k6a_product_sumcheck_digest(rounds: &[[BabyBear; 4]]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_INTEGRATED_K6A_PRODUCT_SUMCHECK_DIGEST_V1");
    push_u64(&mut bytes, rounds.len() as u64);
    for round in rounds {
        for &value in round {
            push_babybear(&mut bytes, value);
        }
    }
    digest_bytes(&bytes)
}

fn digest_babybear_slice(domain: &[u8], values: &[BabyBear]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, domain);
    push_babybear_vec(&mut bytes, values);
    digest_bytes(&bytes)
}

fn n8_integrated_k6a_semantic_rows_digest(
    rows: &[N8IntegratedK6aSemanticConstraintRowV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_INTEGRATED_K6A_SEMANTIC_ROWS_DIGEST_V1");
    push_u64(&mut bytes, rows.len() as u64);
    for row in rows {
        push_bytes(&mut bytes, &row.canonical_bytes());
    }
    digest_bytes(&bytes)
}

fn n8_integrated_tuple_rlc_semantic_rows_digest(
    rows: &[N8IntegratedTupleRlcSemanticConstraintRowV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_ROWS_DIGEST_V1",
    );
    push_u64(&mut bytes, rows.len() as u64);
    for row in rows {
        push_bytes(&mut bytes, &row.canonical_bytes());
    }
    digest_bytes(&bytes)
}

fn n8_integrated_transition_binding_semantic_rows_digest(
    rows: &[N8IntegratedTransitionBindingSemanticConstraintRowV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_ROWS_DIGEST_V1",
    );
    push_u64(&mut bytes, rows.len() as u64);
    for row in rows {
        push_bytes(&mut bytes, &row.canonical_bytes());
    }
    digest_bytes(&bytes)
}

fn n8_integrated_transition_binding_semantic_descriptor_digest(
    constraints: &N8IntegratedTransitionBindingSemanticConstraintsV1,
) -> Digest32 {
    digest_bytes(&constraints.canonical_bytes_without_digest())
}

fn n8_integrated_tuple_rlc_semantic_descriptor_digest(
    constraints: &N8IntegratedTupleRlcSemanticConstraintsV1,
) -> Digest32 {
    digest_bytes(&constraints.canonical_bytes_without_digest())
}

fn n8_integrated_transition_binding_semantic_digest(
    constraints: &N8IntegratedTransitionBindingSemanticConstraintsV1,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_BINDING_V1",
    );
    push_bytes(&mut bytes, &constraints.workload_kind.canonical_bytes());
    push_digest(&mut bytes, &constraints.profile_digest);
    push_digest(&mut bytes, &constraints.accumulator_instance_digest);
    push_digest(&mut bytes, &constraints.old_accumulator_digest);
    push_digest(&mut bytes, &constraints.new_accumulator_digest);
    push_digest(&mut bytes, &constraints.public_statement_digest);
    push_digest(&mut bytes, &constraints.whir_param_digest);
    push_digest(&mut bytes, &constraints.main_symbt3_relation_id);
    push_digest(&mut bytes, &constraints.k6a_proof_digest);
    push_digest(&mut bytes, &constraints.tuple_leaf_root);
    push_digest(&mut bytes, &constraints.tuple_leaf_layout_digest);
    push_digest(&mut bytes, &constraints.tuple_leaf_descriptor_digest);
    push_digest(&mut bytes, &constraints.tuple_leaf_packing_challenge_digest);
    push_digest(&mut bytes, &constraints.native_oracle_descriptor_digest);
    push_digest(&mut bytes, &constraints.native_message_roots_digest);
    push_digest(&mut bytes, &constraints.manifest_oracle_root);
    push_digest(&mut bytes, &constraints.source_oracle_root);
    push_digest(&mut bytes, &constraints.batch_manifest_root);
    push_u64(&mut bytes, constraints.batch_size);
    push_u64(&mut bytes, constraints.active_count);
    push_u64(&mut bytes, constraints.k6a_num_vars as u64);
    push_u64(&mut bytes, constraints.k6a_oracle_len as u64);
    push_u64(&mut bytes, constraints.tuple_logical_oracle_count as u64);
    push_u64(&mut bytes, constraints.tuple_logical_num_vars as u64);
    push_u64(&mut bytes, constraints.tuple_packed_num_vars as u64);
    push_u64(&mut bytes, constraints.tuple_packed_oracle_len as u64);
    push_u64(&mut bytes, constraints.integrated_num_vars as u64);
    push_u64(&mut bytes, constraints.integrated_oracle_len as u64);
    push_u64(&mut bytes, constraints.rlc_repetition_count as u64);
    push_u64(
        &mut bytes,
        constraints.rlc_batching_bits_per_repetition as u64,
    );
    push_u64(&mut bytes, constraints.total_rlc_batching_bits as u64);
    push_u64(&mut bytes, constraints.effective_soundness_bits as u64);
    push_digest(&mut bytes, &constraints.k6a_semantic_descriptor_digest);
    push_digest(
        &mut bytes,
        &constraints.tuple_rlc_semantic_descriptor_digest,
    );
    push_digest(&mut bytes, &constraints.n8_claim_plan_digest);
    push_digest(&mut bytes, &constraints.n8_committed_table_layout_digest);
    push_digest(&mut bytes, &constraints.n8_committed_table_digest);
    push_digest(
        &mut bytes,
        &constraints.n8_combined_constraint_descriptor_digest,
    );
    push_digest(&mut bytes, &constraints.n8_combined_claim_descriptor_digest);
    push_digest(&mut bytes, &constraints.k6a_constraint_descriptor_digest);
    push_digest(&mut bytes, &constraints.tuple_constraint_descriptor_digest);
    push_digest(
        &mut bytes,
        &constraints.transition_constraint_descriptor_digest,
    );
    digest_bytes(&bytes)
}

fn n8_integrated_tuple_rlc_opening_points_digest(points: &[(Digest32, Digest32)]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_TUPLE_RLC_OPENING_POINTS_DIGEST_V1",
    );
    push_u64(&mut bytes, points.len() as u64);
    for (logical_point_digest, packed_point_digest) in points {
        push_digest(&mut bytes, logical_point_digest);
        push_digest(&mut bytes, packed_point_digest);
    }
    digest_bytes(&bytes)
}

fn n8_integrated_tuple_rlc_residuals_digest(residuals: &[BabyBear]) -> Digest32 {
    digest_babybear_slice(b"N8_INTEGRATED_TUPLE_RLC_RESIDUALS_DIGEST_V1", residuals)
}

fn n8_integrated_incomplete_k6a_semantic_descriptor_digest(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    k6a_proof: &WhirProof,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_K6A_SEMANTIC_DESCRIPTOR_INCOMPLETE_V1",
    );
    push_digest(&mut bytes, &adapter.main_symbt3_relation_id);
    push_digest(&mut bytes, &adapter.public_statement_digest);
    push_digest(&mut bytes, &adapter.whir_param_digest);
    push_digest(&mut bytes, &adapter.main_symbt3_proof_digest);
    push_u64(&mut bytes, k6a_proof.num_vars as u64);
    push_u64(&mut bytes, k6a_proof.private_opening_evals.len() as u64);
    push_u64(&mut bytes, k6a_proof.sumcheck_rounds_4.len() as u64);
    digest_bytes(&bytes)
}

fn n8_integrated_k6a_main_constraint_descriptor_digest_from_parts(
    profile_digest: Digest32,
    accumulator_instance_digest: Digest32,
    public_statement_digest: Digest32,
    k6a_semantic_descriptor_digest: Digest32,
    whir_param_digest: Digest32,
    main_symbt3_relation_id: Digest32,
    old_accumulator_digest: Digest32,
    new_accumulator_digest: Digest32,
    batch_manifest_root: Digest32,
    manifest_oracle_root: Digest32,
    native_message_roots_digest: Digest32,
    batch_size: u64,
    active_count: u64,
    k6a_num_vars: usize,
    k6a_oracle_len: usize,
) -> Digest32 {
    symbt3_n8_integrated_constraint_digest(
        Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1,
        |bytes| {
            push_digest(bytes, &profile_digest);
            push_digest(bytes, &accumulator_instance_digest);
            push_digest(bytes, &public_statement_digest);
            push_digest(bytes, &k6a_semantic_descriptor_digest);
            push_digest(bytes, &whir_param_digest);
            push_digest(bytes, &main_symbt3_relation_id);
            push_digest(bytes, &old_accumulator_digest);
            push_digest(bytes, &new_accumulator_digest);
            push_digest(bytes, &batch_manifest_root);
            push_digest(bytes, &manifest_oracle_root);
            push_digest(bytes, &native_message_roots_digest);
            push_u64(bytes, batch_size);
            push_u64(bytes, active_count);
            push_u64(bytes, k6a_num_vars as u64);
            push_u64(bytes, k6a_oracle_len as u64);
        },
    )
}

fn n8_integrated_tuple_leaf_constraint_descriptor_digest_from_parts(
    tuple_leaf_descriptor_digest: Digest32,
    tuple_leaf_layout_digest: Digest32,
    tuple_leaf_packing_challenge_digest: Digest32,
    tuple_leaf_root: Digest32,
    native_oracle_descriptor_digest: Digest32,
    native_message_roots_digest: Digest32,
    manifest_oracle_root: Digest32,
    source_oracle_root: Digest32,
    logical_oracle_count: usize,
    tuple_logical_num_vars: usize,
    tuple_packed_num_vars: usize,
    rlc_repetition_count: usize,
    rlc_batching_bits_per_repetition: usize,
    total_rlc_batching_bits: usize,
    effective_soundness_bits: usize,
) -> Digest32 {
    symbt3_n8_integrated_constraint_digest(
        Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1,
        |bytes| {
            push_digest(bytes, &tuple_leaf_descriptor_digest);
            push_digest(bytes, &tuple_leaf_layout_digest);
            push_digest(bytes, &tuple_leaf_packing_challenge_digest);
            push_digest(bytes, &tuple_leaf_root);
            push_digest(bytes, &native_oracle_descriptor_digest);
            push_digest(bytes, &native_message_roots_digest);
            push_digest(bytes, &manifest_oracle_root);
            push_digest(bytes, &source_oracle_root);
            push_u64(bytes, logical_oracle_count as u64);
            push_u64(bytes, tuple_logical_num_vars as u64);
            push_u64(bytes, tuple_packed_num_vars as u64);
            push_u64(bytes, rlc_repetition_count as u64);
            push_u64(bytes, rlc_batching_bits_per_repetition as u64);
            push_u64(bytes, total_rlc_batching_bits as u64);
            push_u64(bytes, effective_soundness_bits as u64);
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn n8_integrated_transition_constraint_descriptor_digest_from_parts(
    k6a_constraint_descriptor_digest: Digest32,
    tuple_constraint_descriptor_digest: Digest32,
    profile_digest: Digest32,
    accumulator_instance_digest: Digest32,
    old_accumulator_digest: Digest32,
    new_accumulator_digest: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    main_symbt3_relation_id: Digest32,
    k6a_proof_digest: Digest32,
    tuple_leaf_root: Digest32,
    tuple_leaf_layout_digest: Digest32,
    native_oracle_descriptor_digest: Digest32,
    native_message_roots_digest: Digest32,
    manifest_oracle_root: Digest32,
    source_oracle_root: Digest32,
    batch_manifest_root: Digest32,
    batch_size: u64,
    active_count: u64,
    integrated_num_vars: usize,
    integrated_oracle_len: usize,
) -> Digest32 {
    symbt3_n8_integrated_constraint_digest(
        Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1,
        |bytes| {
            push_digest(bytes, &k6a_constraint_descriptor_digest);
            push_digest(bytes, &tuple_constraint_descriptor_digest);
            push_digest(bytes, &profile_digest);
            push_digest(bytes, &accumulator_instance_digest);
            push_digest(bytes, &old_accumulator_digest);
            push_digest(bytes, &new_accumulator_digest);
            push_digest(bytes, &public_statement_digest);
            push_digest(bytes, &whir_param_digest);
            push_digest(bytes, &main_symbt3_relation_id);
            push_digest(bytes, &k6a_proof_digest);
            push_digest(bytes, &tuple_leaf_root);
            push_digest(bytes, &tuple_leaf_layout_digest);
            push_digest(bytes, &native_oracle_descriptor_digest);
            push_digest(bytes, &native_message_roots_digest);
            push_digest(bytes, &manifest_oracle_root);
            push_digest(bytes, &source_oracle_root);
            push_digest(bytes, &batch_manifest_root);
            push_u64(bytes, batch_size);
            push_u64(bytes, active_count);
            push_u64(bytes, integrated_num_vars as u64);
            push_u64(bytes, integrated_oracle_len as u64);
        },
    )
}

fn n8_integrated_complete_k6a_semantic_descriptor_digest_from_claims(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    k6a_proof: &WhirProof,
    points_digest: Digest32,
    claims_digest: Digest32,
    final_residual_digest: Digest32,
    product_sumcheck_digest: Digest32,
    verifier_point_count: usize,
    verifier_claim_count: usize,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_K6A_SEMANTIC_DESCRIPTOR_COMPLETE_V1",
    );
    push_digest(&mut bytes, &adapter.main_symbt3_relation_id);
    push_digest(&mut bytes, &adapter.public_statement_digest);
    push_digest(&mut bytes, &adapter.whir_param_digest);
    push_digest(&mut bytes, &adapter.main_symbt3_proof_digest);
    push_u64(&mut bytes, k6a_proof.num_vars as u64);
    push_u64(&mut bytes, adapter.main_oracle_len as u64);
    push_u64(&mut bytes, verifier_point_count as u64);
    push_u64(&mut bytes, verifier_claim_count as u64);
    push_digest(&mut bytes, &points_digest);
    push_digest(&mut bytes, &claims_digest);
    push_digest(&mut bytes, &final_residual_digest);
    push_digest(&mut bytes, &product_sumcheck_digest);
    push_babybear(&mut bytes, k6a_proof.z_eval);
    digest_bytes(&bytes)
}

fn n8_integrated_complete_k6a_semantic_descriptor_digest_from_source(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    source: &Symbt3N8K6aSemanticSourceV1,
    points_digest: Digest32,
    claims_digest: Digest32,
    final_residual_digest: Digest32,
    product_sumcheck_digest: Digest32,
    verifier_point_count: usize,
    verifier_claim_count: usize,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_K6A_SEMANTIC_DESCRIPTOR_COMPLETE_V1",
    );
    push_digest(&mut bytes, &adapter.main_symbt3_relation_id);
    push_digest(&mut bytes, &adapter.public_statement_digest);
    push_digest(&mut bytes, &adapter.whir_param_digest);
    push_digest(&mut bytes, &adapter.main_symbt3_proof_digest);
    push_u64(&mut bytes, source.num_vars as u64);
    push_u64(&mut bytes, adapter.main_oracle_len as u64);
    push_u64(&mut bytes, verifier_point_count as u64);
    push_u64(&mut bytes, verifier_claim_count as u64);
    push_digest(&mut bytes, &points_digest);
    push_digest(&mut bytes, &claims_digest);
    push_digest(&mut bytes, &final_residual_digest);
    push_digest(&mut bytes, &product_sumcheck_digest);
    push_babybear(&mut bytes, source.z_eval);
    digest_bytes(&bytes)
}

fn n8_integrated_complete_k6a_semantic_descriptor_digest(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    k6a_proof: &WhirProof,
) -> Result<Digest32, Symbt3N8IntegratedPrototypeBlocker> {
    let claims = super::symbt3_c_table_and_claims(
        seed,
        relation,
        statement,
        None,
        Some(&k6a_proof.private_opening_evals),
        Some(&k6a_proof.sumcheck_rounds_4),
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)?;
    if k6a_proof.num_vars != claims.num_vars
        || k6a_proof.evaluations != claims.evaluations
        || k6a_proof.z_eval != claims.z_eval
        || claims.claimed != k6a_proof.private_opening_evals
        || claims
            .evaluations
            .iter()
            .any(|&value| value != BabyBear::ZERO)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }
    let points_digest = n8_integrated_k6a_verifier_points_digest(&claims.points);
    let claims_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
        &claims.claimed,
    );
    let final_residual_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
        &claims.evaluations,
    );
    let product_sumcheck_digest =
        n8_integrated_k6a_product_sumcheck_digest(&claims.product_sumcheck_rounds);
    Ok(
        n8_integrated_complete_k6a_semantic_descriptor_digest_from_claims(
            adapter,
            k6a_proof,
            points_digest,
            claims_digest,
            final_residual_digest,
            product_sumcheck_digest,
            claims.points.len(),
            claims.claimed.len(),
        ),
    )
}

fn symbt3_n8_oracle_len(num_vars: usize) -> Option<usize> {
    if num_vars >= usize::BITS as usize {
        return None;
    }
    1usize.checked_shl(num_vars as u32)
}

fn symbt3_n8_k6a_padding_policy(
    k6a_num_vars: usize,
    integrated_num_vars: usize,
) -> Option<IntegratedK6aNativeK6aPaddingPolicyV1> {
    if k6a_num_vars > integrated_num_vars {
        return None;
    }
    let source_oracle_len = symbt3_n8_oracle_len(k6a_num_vars)?;
    let target_oracle_len = symbt3_n8_oracle_len(integrated_num_vars)?;
    let added_num_vars = integrated_num_vars.checked_sub(k6a_num_vars)?;
    let padded_row_count = target_oracle_len.checked_sub(source_oracle_len)?;
    let mode = if added_num_vars == 0 {
        IntegratedK6aNativeK6aPaddingModeV1::NoPadding
    } else {
        IntegratedK6aNativeK6aPaddingModeV1::ZeroExtendRowsToIntegratedNumVars
    };
    Some(IntegratedK6aNativeK6aPaddingPolicyV1 {
        mode,
        source_num_vars: k6a_num_vars,
        target_num_vars: integrated_num_vars,
        source_oracle_len,
        target_oracle_len,
        added_num_vars,
        padded_row_count,
    })
}

fn symbt3_n8_tuple_repetition_axis_mapping(
    tuple_logical_num_vars: usize,
    rlc_repetition_count: usize,
    integrated_num_vars: usize,
) -> Option<IntegratedK6aNativeTupleRepetitionAxisMappingV1> {
    let repetition_axis_len = symbt3_tuple_leaf_repetition_log_size(rlc_repetition_count)?;
    let packed_num_vars = tuple_logical_num_vars.checked_add(repetition_axis_len)?;
    if packed_num_vars > integrated_num_vars {
        return None;
    }
    Some(IntegratedK6aNativeTupleRepetitionAxisMappingV1 {
        placement: IntegratedK6aNativeTupleRepetitionAxisPlacementV1::AppendedAfterLogicalAxes,
        logical_num_vars: tuple_logical_num_vars,
        repetition_axis_start: tuple_logical_num_vars,
        repetition_axis_len,
        rlc_repetition_count,
        packed_num_vars,
        integrated_num_vars,
        integrated_padding_num_vars: integrated_num_vars.checked_sub(packed_num_vars)?,
    })
}

#[must_use]
fn symbt3_n8_tuple_leaf_repeated_rlc_ok(
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
) -> bool {
    let proof = &native_tuple_leaf.proof;
    let counters = &proof.counters;
    counters.rlc_batching_bits_per_repetition > 0
        && counters.total_rlc_batching_bits
            == counters
                .rlc_repetition_count
                .saturating_mul(counters.rlc_batching_bits_per_repetition)
        && counters.rlc_repetition_count
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        && counters.total_rlc_batching_bits
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS
        && counters.effective_soundness_bits
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS
        && proof.packed_eval_claims.len() >= counters.rlc_repetition_count
        && proof.logical_eval_claims.len()
            >= counters
                .logical_oracle_count
                .saturating_mul(counters.rlc_repetition_count)
}

pub fn build_integrated_k6a_native_claim_plan_v1(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
) -> Result<IntegratedK6aNativeClaimPlanV1, Symbt3N8IntegratedPrototypeBlocker> {
    let k6a_semantic_descriptor_digest =
        n8_integrated_incomplete_k6a_semantic_descriptor_digest(adapter, k6a_proof);
    build_integrated_k6a_native_claim_plan_v1_with_k6a_semantic_descriptor_digest(
        adapter,
        native_tuple_leaf,
        k6a_proof,
        k6a_semantic_descriptor_digest,
    )
}

fn build_integrated_k6a_native_claim_plan_v1_with_k6a_semantic_descriptor_digest(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
    k6a_semantic_descriptor_digest: Digest32,
) -> Result<IntegratedK6aNativeClaimPlanV1, Symbt3N8IntegratedPrototypeBlocker> {
    if adapter.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if adapter.smoke_profile {
        return Err(Symbt3N8IntegratedPrototypeBlocker::SmokeProfile);
    }
    if !adapter.full_accumulator_workload {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aNotFullWorkload);
    }
    if !symbt3_n7b_native_tuple_leaf_profile_compatible(adapter, native_tuple_leaf) {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleLeafProfileIncompatible);
    }
    if !symbt3_n8_tuple_leaf_repeated_rlc_ok(native_tuple_leaf) {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    }
    if symbt3_main_whir_proof_digest(k6a_proof) != adapter.main_symbt3_proof_digest
        || k6a_proof.num_vars != adapter.main_whir_num_vars
        || k6a_proof.is_output
        || !k6a_proof.sumcheck_rounds_3.is_empty()
        || !k6a_proof.linear_checks.is_empty()
        || !k6a_proof.family_columnar_subproofs.is_empty()
        || k6a_proof.private_opening_evals.is_empty()
        || symbt3_n8_k6a_claim_row_count(k6a_proof) == 0
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }

    let proof = &native_tuple_leaf.proof;
    let tuple_logical_num_vars = proof
        .logical_descriptors
        .first()
        .map(|descriptor| descriptor.num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::MissingNativeTupleLeafProof)?;
    if proof
        .logical_descriptors
        .iter()
        .any(|descriptor| descriptor.num_vars != tuple_logical_num_vars)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleLeafProfileIncompatible);
    }
    let repetition_log_size =
        symbt3_tuple_leaf_repetition_log_size(proof.counters.rlc_repetition_count)
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak)?;
    let tuple_packed_num_vars = tuple_logical_num_vars
        .checked_add(repetition_log_size)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let tuple_packed_oracle_len = symbt3_n8_oracle_len(tuple_packed_num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let k6a_oracle_len = symbt3_n8_oracle_len(adapter.main_whir_num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    if k6a_oracle_len != adapter.main_oracle_len {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    }
    let integrated_num_vars = adapter.main_whir_num_vars.max(tuple_packed_num_vars);
    let integrated_oracle_len = symbt3_n8_oracle_len(integrated_num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let k6a_padding_policy =
        symbt3_n8_k6a_padding_policy(adapter.main_whir_num_vars, integrated_num_vars)
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch)?;
    let tuple_repetition_axis = symbt3_n8_tuple_repetition_axis_mapping(
        tuple_logical_num_vars,
        proof.counters.rlc_repetition_count,
        integrated_num_vars,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
    let k6a_main_descriptor_digest = n8_integrated_k6a_main_constraint_descriptor_digest_from_parts(
        adapter.profile_digest,
        adapter.accumulator_instance_digest,
        adapter.public_statement_digest,
        k6a_semantic_descriptor_digest,
        adapter.whir_param_digest,
        adapter.main_symbt3_relation_id,
        adapter.old_accumulator_digest,
        adapter.new_accumulator_digest,
        adapter.batch_manifest_root,
        adapter.manifest_oracle_root,
        adapter.native_message_roots_digest,
        adapter.batch_size,
        adapter.active_count,
        adapter.main_whir_num_vars,
        adapter.main_oracle_len,
    );
    let tuple_leaf_descriptor_digest =
        n8_integrated_tuple_leaf_constraint_descriptor_digest_from_parts(
            proof.descriptor_digest,
            proof.tuple_leaf_layout_digest,
            proof.packing_challenge_digest,
            proof.packed_root,
            native_tuple_leaf.native_oracle_descriptor_digest,
            native_tuple_leaf.native_message_roots_digest,
            native_tuple_leaf.manifest_oracle_root,
            native_tuple_leaf.source_oracle_root,
            proof.counters.logical_oracle_count,
            tuple_logical_num_vars,
            tuple_packed_num_vars,
            proof.counters.rlc_repetition_count,
            proof.counters.rlc_batching_bits_per_repetition,
            proof.counters.total_rlc_batching_bits,
            proof.counters.effective_soundness_bits,
        );
    let transition_descriptor_digest =
        n8_integrated_transition_constraint_descriptor_digest_from_parts(
            k6a_main_descriptor_digest,
            tuple_leaf_descriptor_digest,
            adapter.profile_digest,
            adapter.accumulator_instance_digest,
            adapter.old_accumulator_digest,
            adapter.new_accumulator_digest,
            adapter.public_statement_digest,
            adapter.whir_param_digest,
            adapter.main_symbt3_relation_id,
            adapter.main_symbt3_proof_digest,
            proof.packed_root,
            proof.tuple_leaf_layout_digest,
            native_tuple_leaf.native_oracle_descriptor_digest,
            native_tuple_leaf.native_message_roots_digest,
            native_tuple_leaf.manifest_oracle_root,
            native_tuple_leaf.source_oracle_root,
            adapter.batch_manifest_root,
            adapter.batch_size,
            adapter.active_count,
            integrated_num_vars,
            integrated_oracle_len,
        );

    let mut logical_oracle_descriptors = Vec::with_capacity(proof.logical_descriptors.len() + 2);
    logical_oracle_descriptors.push(IntegratedK6aNativeLogicalOracleDescriptorV1 {
        kind: IntegratedK6aNativeLogicalOracleKindV1::K6aAccumulatorMainV1,
        oracle_id: None,
        role: None,
        layout_digest: adapter.main_symbt3_relation_id,
        root_digest: None,
        source_num_vars: adapter.main_whir_num_vars,
        integrated_num_vars,
        descriptor_digest: k6a_main_descriptor_digest,
    });
    logical_oracle_descriptors.push(IntegratedK6aNativeLogicalOracleDescriptorV1 {
        kind: IntegratedK6aNativeLogicalOracleKindV1::NativeTupleLeafPackedV1,
        oracle_id: None,
        role: None,
        layout_digest: proof.tuple_leaf_layout_digest,
        root_digest: Some(proof.packed_root),
        source_num_vars: tuple_packed_num_vars,
        integrated_num_vars,
        descriptor_digest: tuple_leaf_descriptor_digest,
    });
    for spec in &proof.logical_descriptors {
        logical_oracle_descriptors.push(IntegratedK6aNativeLogicalOracleDescriptorV1 {
            kind: IntegratedK6aNativeLogicalOracleKindV1::NativeTupleLeafLogicalV1,
            oracle_id: Some(spec.oracle_id),
            role: Some(spec.role.clone()),
            layout_digest: spec.layout_digest,
            root_digest: None,
            source_num_vars: spec.num_vars,
            integrated_num_vars,
            descriptor_digest: digest_bytes(&spec.canonical_bytes()),
        });
    }

    let constraint_descriptors = vec![
        Symbt3N8IntegratedConstraintDescriptor {
            kind: Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1,
            num_vars: adapter.main_whir_num_vars,
            oracle_len: adapter.main_oracle_len,
            integrated_num_vars,
            integrated_oracle_len,
            descriptor_digest: k6a_main_descriptor_digest,
        },
        Symbt3N8IntegratedConstraintDescriptor {
            kind: Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1,
            num_vars: tuple_packed_num_vars,
            oracle_len: tuple_packed_oracle_len,
            integrated_num_vars,
            integrated_oracle_len,
            descriptor_digest: tuple_leaf_descriptor_digest,
        },
        Symbt3N8IntegratedConstraintDescriptor {
            kind: Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1,
            num_vars: integrated_num_vars,
            oracle_len: integrated_oracle_len,
            integrated_num_vars,
            integrated_oracle_len,
            descriptor_digest: transition_descriptor_digest,
        },
    ];

    let claim_descriptors = vec![
        IntegratedK6aNativeClaimDescriptorV1 {
            kind: IntegratedK6aNativeClaimDescriptorKindV1::K6aAccumulatorMainClaimsV1,
            claim_count: symbt3_n8_k6a_claim_row_count(k6a_proof),
            num_vars: adapter.main_whir_num_vars,
            claims_digest: symbt3_n8_k6a_claim_descriptor_digest(adapter, k6a_proof),
        },
        IntegratedK6aNativeClaimDescriptorV1 {
            kind: IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafPackedClaimsV1,
            claim_count: proof.packed_eval_claims.len(),
            num_vars: tuple_packed_num_vars,
            claims_digest: symbt3_tuple_leaf_packed_eval_claims_digest(&proof.packed_eval_claims),
        },
        IntegratedK6aNativeClaimDescriptorV1 {
            kind: IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafLogicalClaimsV1,
            claim_count: proof.logical_eval_claims.len(),
            num_vars: tuple_logical_num_vars,
            claims_digest: native_oracle_eval_claims_digest(&proof.logical_eval_claims),
        },
    ];

    let combined_logical_oracle_descriptor_digest =
        symbt3_n8_integrated_logical_oracle_descriptors_digest(&logical_oracle_descriptors);
    let combined_constraint_descriptor_digest =
        symbt3_n8_integrated_constraint_descriptors_digest(&constraint_descriptors);
    let combined_claim_descriptor_digest =
        symbt3_n8_integrated_claim_descriptors_digest(&claim_descriptors);

    let mut plan = IntegratedK6aNativeClaimPlanV1 {
        version: INTEGRATED_K6A_NATIVE_CLAIM_PLAN_VERSION,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        k6a_relation_id: adapter.main_symbt3_relation_id,
        k6a_public_statement_digest: adapter.public_statement_digest,
        k6a_semantic_descriptor_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        k6a_num_vars: adapter.main_whir_num_vars,
        k6a_oracle_len: adapter.main_oracle_len,
        tuple_logical_oracle_count: proof.counters.logical_oracle_count,
        tuple_logical_num_vars,
        tuple_packed_num_vars,
        tuple_packed_oracle_len,
        integrated_num_vars,
        integrated_oracle_len,
        rlc_repetition_count: proof.counters.rlc_repetition_count,
        rlc_batching_bits_per_repetition: proof.counters.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: proof.counters.total_rlc_batching_bits,
        effective_soundness_bits: proof.counters.effective_soundness_bits,
        k6a_padding_policy,
        tuple_repetition_axis,
        logical_oracle_descriptors,
        constraint_descriptors,
        claim_descriptors,
        combined_logical_oracle_descriptor_digest,
        combined_constraint_descriptor_digest,
        combined_claim_descriptor_digest,
        claim_plan_digest: [0u8; 32],
    };
    plan.claim_plan_digest = symbt3_n8_integrated_claim_plan_digest(&plan);
    Ok(plan)
}

fn build_integrated_k6a_native_claim_plan_v1_with_k6a_semantic_source(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    source: &Symbt3N8K6aSemanticSourceV1,
    k6a_semantic_descriptor_digest: Digest32,
) -> Result<IntegratedK6aNativeClaimPlanV1, Symbt3N8IntegratedPrototypeBlocker> {
    if adapter.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if adapter.smoke_profile {
        return Err(Symbt3N8IntegratedPrototypeBlocker::SmokeProfile);
    }
    if !adapter.full_accumulator_workload {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aNotFullWorkload);
    }
    if !symbt3_n7b_native_tuple_leaf_profile_compatible(adapter, native_tuple_leaf) {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleLeafProfileIncompatible);
    }
    if !symbt3_n8_tuple_leaf_repeated_rlc_ok(native_tuple_leaf) {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    }
    if source.source_digest != adapter.main_symbt3_proof_digest
        || source.relation_id != adapter.main_symbt3_relation_id
        || source.public_statement_digest != adapter.public_statement_digest
        || source.whir_param_digest != adapter.whir_param_digest
        || source.num_vars != adapter.main_whir_num_vars
        || source.oracle_len != adapter.main_oracle_len
        || source.verifier_claims.is_empty()
        || source.verifier_points.len() != source.verifier_claims.len()
        || symbt3_n8_k6a_claim_row_count_from_source(source) == 0
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }

    let proof = &native_tuple_leaf.proof;
    let tuple_logical_num_vars = proof
        .logical_descriptors
        .first()
        .map(|descriptor| descriptor.num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::MissingNativeTupleLeafProof)?;
    if proof
        .logical_descriptors
        .iter()
        .any(|descriptor| descriptor.num_vars != tuple_logical_num_vars)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleLeafProfileIncompatible);
    }
    let repetition_log_size =
        symbt3_tuple_leaf_repetition_log_size(proof.counters.rlc_repetition_count)
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak)?;
    let tuple_packed_num_vars = tuple_logical_num_vars
        .checked_add(repetition_log_size)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let tuple_packed_oracle_len = symbt3_n8_oracle_len(tuple_packed_num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let k6a_oracle_len = symbt3_n8_oracle_len(adapter.main_whir_num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    if k6a_oracle_len != adapter.main_oracle_len {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    }
    let integrated_num_vars = adapter.main_whir_num_vars.max(tuple_packed_num_vars);
    let integrated_oracle_len = symbt3_n8_oracle_len(integrated_num_vars)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let k6a_padding_policy =
        symbt3_n8_k6a_padding_policy(adapter.main_whir_num_vars, integrated_num_vars)
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch)?;
    let tuple_repetition_axis = symbt3_n8_tuple_repetition_axis_mapping(
        tuple_logical_num_vars,
        proof.counters.rlc_repetition_count,
        integrated_num_vars,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
    let k6a_main_descriptor_digest = n8_integrated_k6a_main_constraint_descriptor_digest_from_parts(
        adapter.profile_digest,
        adapter.accumulator_instance_digest,
        adapter.public_statement_digest,
        k6a_semantic_descriptor_digest,
        adapter.whir_param_digest,
        adapter.main_symbt3_relation_id,
        adapter.old_accumulator_digest,
        adapter.new_accumulator_digest,
        adapter.batch_manifest_root,
        adapter.manifest_oracle_root,
        adapter.native_message_roots_digest,
        adapter.batch_size,
        adapter.active_count,
        adapter.main_whir_num_vars,
        adapter.main_oracle_len,
    );
    let tuple_leaf_descriptor_digest =
        n8_integrated_tuple_leaf_constraint_descriptor_digest_from_parts(
            proof.descriptor_digest,
            proof.tuple_leaf_layout_digest,
            proof.packing_challenge_digest,
            proof.packed_root,
            native_tuple_leaf.native_oracle_descriptor_digest,
            native_tuple_leaf.native_message_roots_digest,
            native_tuple_leaf.manifest_oracle_root,
            native_tuple_leaf.source_oracle_root,
            proof.counters.logical_oracle_count,
            tuple_logical_num_vars,
            tuple_packed_num_vars,
            proof.counters.rlc_repetition_count,
            proof.counters.rlc_batching_bits_per_repetition,
            proof.counters.total_rlc_batching_bits,
            proof.counters.effective_soundness_bits,
        );
    let transition_descriptor_digest =
        n8_integrated_transition_constraint_descriptor_digest_from_parts(
            k6a_main_descriptor_digest,
            tuple_leaf_descriptor_digest,
            adapter.profile_digest,
            adapter.accumulator_instance_digest,
            adapter.old_accumulator_digest,
            adapter.new_accumulator_digest,
            adapter.public_statement_digest,
            adapter.whir_param_digest,
            adapter.main_symbt3_relation_id,
            adapter.main_symbt3_proof_digest,
            proof.packed_root,
            proof.tuple_leaf_layout_digest,
            native_tuple_leaf.native_oracle_descriptor_digest,
            native_tuple_leaf.native_message_roots_digest,
            native_tuple_leaf.manifest_oracle_root,
            native_tuple_leaf.source_oracle_root,
            adapter.batch_manifest_root,
            adapter.batch_size,
            adapter.active_count,
            integrated_num_vars,
            integrated_oracle_len,
        );

    let mut logical_oracle_descriptors = Vec::with_capacity(proof.logical_descriptors.len() + 2);
    logical_oracle_descriptors.push(IntegratedK6aNativeLogicalOracleDescriptorV1 {
        kind: IntegratedK6aNativeLogicalOracleKindV1::K6aAccumulatorMainV1,
        oracle_id: None,
        role: None,
        layout_digest: adapter.main_symbt3_relation_id,
        root_digest: None,
        source_num_vars: adapter.main_whir_num_vars,
        integrated_num_vars,
        descriptor_digest: k6a_main_descriptor_digest,
    });
    logical_oracle_descriptors.push(IntegratedK6aNativeLogicalOracleDescriptorV1 {
        kind: IntegratedK6aNativeLogicalOracleKindV1::NativeTupleLeafPackedV1,
        oracle_id: None,
        role: None,
        layout_digest: proof.tuple_leaf_layout_digest,
        root_digest: Some(proof.packed_root),
        source_num_vars: tuple_packed_num_vars,
        integrated_num_vars,
        descriptor_digest: tuple_leaf_descriptor_digest,
    });
    for spec in &proof.logical_descriptors {
        logical_oracle_descriptors.push(IntegratedK6aNativeLogicalOracleDescriptorV1 {
            kind: IntegratedK6aNativeLogicalOracleKindV1::NativeTupleLeafLogicalV1,
            oracle_id: Some(spec.oracle_id),
            role: Some(spec.role.clone()),
            layout_digest: spec.layout_digest,
            root_digest: None,
            source_num_vars: spec.num_vars,
            integrated_num_vars,
            descriptor_digest: digest_bytes(&spec.canonical_bytes()),
        });
    }

    let constraint_descriptors = vec![
        Symbt3N8IntegratedConstraintDescriptor {
            kind: Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1,
            num_vars: adapter.main_whir_num_vars,
            oracle_len: adapter.main_oracle_len,
            integrated_num_vars,
            integrated_oracle_len,
            descriptor_digest: k6a_main_descriptor_digest,
        },
        Symbt3N8IntegratedConstraintDescriptor {
            kind: Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1,
            num_vars: tuple_packed_num_vars,
            oracle_len: tuple_packed_oracle_len,
            integrated_num_vars,
            integrated_oracle_len,
            descriptor_digest: tuple_leaf_descriptor_digest,
        },
        Symbt3N8IntegratedConstraintDescriptor {
            kind: Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1,
            num_vars: integrated_num_vars,
            oracle_len: integrated_oracle_len,
            integrated_num_vars,
            integrated_oracle_len,
            descriptor_digest: transition_descriptor_digest,
        },
    ];

    let claim_descriptors = vec![
        IntegratedK6aNativeClaimDescriptorV1 {
            kind: IntegratedK6aNativeClaimDescriptorKindV1::K6aAccumulatorMainClaimsV1,
            claim_count: symbt3_n8_k6a_claim_row_count_from_source(source),
            num_vars: adapter.main_whir_num_vars,
            claims_digest: symbt3_n8_k6a_claim_descriptor_digest_from_source(adapter, source),
        },
        IntegratedK6aNativeClaimDescriptorV1 {
            kind: IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafPackedClaimsV1,
            claim_count: proof.packed_eval_claims.len(),
            num_vars: tuple_packed_num_vars,
            claims_digest: symbt3_tuple_leaf_packed_eval_claims_digest(&proof.packed_eval_claims),
        },
        IntegratedK6aNativeClaimDescriptorV1 {
            kind: IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafLogicalClaimsV1,
            claim_count: proof.logical_eval_claims.len(),
            num_vars: tuple_logical_num_vars,
            claims_digest: native_oracle_eval_claims_digest(&proof.logical_eval_claims),
        },
    ];

    let combined_logical_oracle_descriptor_digest =
        symbt3_n8_integrated_logical_oracle_descriptors_digest(&logical_oracle_descriptors);
    let combined_constraint_descriptor_digest =
        symbt3_n8_integrated_constraint_descriptors_digest(&constraint_descriptors);
    let combined_claim_descriptor_digest =
        symbt3_n8_integrated_claim_descriptors_digest(&claim_descriptors);

    let mut plan = IntegratedK6aNativeClaimPlanV1 {
        version: INTEGRATED_K6A_NATIVE_CLAIM_PLAN_VERSION,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        k6a_relation_id: adapter.main_symbt3_relation_id,
        k6a_public_statement_digest: adapter.public_statement_digest,
        k6a_semantic_descriptor_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        k6a_num_vars: adapter.main_whir_num_vars,
        k6a_oracle_len: adapter.main_oracle_len,
        tuple_logical_oracle_count: proof.counters.logical_oracle_count,
        tuple_logical_num_vars,
        tuple_packed_num_vars,
        tuple_packed_oracle_len,
        integrated_num_vars,
        integrated_oracle_len,
        rlc_repetition_count: proof.counters.rlc_repetition_count,
        rlc_batching_bits_per_repetition: proof.counters.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: proof.counters.total_rlc_batching_bits,
        effective_soundness_bits: proof.counters.effective_soundness_bits,
        k6a_padding_policy,
        tuple_repetition_axis,
        logical_oracle_descriptors,
        constraint_descriptors,
        claim_descriptors,
        combined_logical_oracle_descriptor_digest,
        combined_constraint_descriptor_digest,
        combined_claim_descriptor_digest,
        claim_plan_digest: [0u8; 32],
    };
    plan.claim_plan_digest = symbt3_n8_integrated_claim_plan_digest(&plan);
    Ok(plan)
}

pub fn build_integrated_k6a_native_committed_table_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
) -> Result<IntegratedK6aNativeCommittedTableV1, Symbt3N8IntegratedPrototypeBlocker> {
    if let Some(blocker) = symbt3_n8_integrated_claim_plan_consistency_blocker(plan) {
        return Err(blocker);
    }

    let mut row_ownership = Vec::new();
    row_ownership.push(IntegratedK6aNativeCommittedTableRowRangeV1 {
        owner: IntegratedK6aNativeCommittedTableRowOwnerV1::K6aAccumulatorMainRows,
        integrated_start: 0,
        row_count: plan.k6a_oracle_len,
        source_start: 0,
        source_row_count: plan.k6a_oracle_len,
    });
    if plan.k6a_padding_policy.padded_row_count > 0 {
        row_ownership.push(IntegratedK6aNativeCommittedTableRowRangeV1 {
            owner: IntegratedK6aNativeCommittedTableRowOwnerV1::K6aZeroPaddingRows,
            integrated_start: plan.k6a_oracle_len,
            row_count: plan.k6a_padding_policy.padded_row_count,
            source_start: plan.k6a_oracle_len,
            source_row_count: 0,
        });
    }
    row_ownership.push(IntegratedK6aNativeCommittedTableRowRangeV1 {
        owner: IntegratedK6aNativeCommittedTableRowOwnerV1::NativeTupleLeafRepeatedRlcRows,
        integrated_start: 0,
        row_count: plan.tuple_packed_oracle_len,
        source_start: 0,
        source_row_count: plan.tuple_packed_oracle_len,
    });
    let tuple_padding_rows = plan
        .integrated_oracle_len
        .checked_sub(plan.tuple_packed_oracle_len)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    if tuple_padding_rows > 0 {
        row_ownership.push(IntegratedK6aNativeCommittedTableRowRangeV1 {
            owner:
                IntegratedK6aNativeCommittedTableRowOwnerV1::NativeTupleLeafIntegratedPaddingRows,
            integrated_start: plan.tuple_packed_oracle_len,
            row_count: tuple_padding_rows,
            source_start: plan.tuple_packed_oracle_len,
            source_row_count: 0,
        });
    }

    let mut axis_ownership = Vec::new();
    axis_ownership.push(IntegratedK6aNativeCommittedTableAxisRangeV1 {
        owner: IntegratedK6aNativeCommittedTableAxisOwnerV1::K6aSourceAxes,
        axis_start: 0,
        axis_len: plan.k6a_num_vars,
    });
    if plan.k6a_padding_policy.added_num_vars > 0 {
        axis_ownership.push(IntegratedK6aNativeCommittedTableAxisRangeV1 {
            owner: IntegratedK6aNativeCommittedTableAxisOwnerV1::K6aPaddingAxes,
            axis_start: plan.k6a_num_vars,
            axis_len: plan.k6a_padding_policy.added_num_vars,
        });
    }
    axis_ownership.push(IntegratedK6aNativeCommittedTableAxisRangeV1 {
        owner: IntegratedK6aNativeCommittedTableAxisOwnerV1::TupleLeafLogicalAxes,
        axis_start: 0,
        axis_len: plan.tuple_repetition_axis.logical_num_vars,
    });
    axis_ownership.push(IntegratedK6aNativeCommittedTableAxisRangeV1 {
        owner: IntegratedK6aNativeCommittedTableAxisOwnerV1::TupleLeafRepetitionAxes,
        axis_start: plan.tuple_repetition_axis.repetition_axis_start,
        axis_len: plan.tuple_repetition_axis.repetition_axis_len,
    });
    if plan.tuple_repetition_axis.integrated_padding_num_vars > 0 {
        axis_ownership.push(IntegratedK6aNativeCommittedTableAxisRangeV1 {
            owner: IntegratedK6aNativeCommittedTableAxisOwnerV1::TupleLeafIntegratedPaddingAxes,
            axis_start: plan.tuple_packed_num_vars,
            axis_len: plan.tuple_repetition_axis.integrated_padding_num_vars,
        });
    }

    let counters = IntegratedK6aNativeCommittedTableCountersV1 {
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        k6a_padded_rows: plan.k6a_padding_policy.padded_row_count,
        tuple_rows: plan.tuple_packed_oracle_len,
        combined_constraint_count: plan.constraint_descriptors.len(),
        table_digest: [0u8; 32],
        layout_digest: [0u8; 32],
    };
    let mut table = IntegratedK6aNativeCommittedTableV1 {
        version: INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_VERSION,
        workload_kind: plan.workload_kind,
        plan_digest: plan.claim_plan_digest,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        k6a_padding_policy: plan.k6a_padding_policy.clone(),
        tuple_repetition_axis: plan.tuple_repetition_axis.clone(),
        row_ownership,
        axis_ownership,
        logical_integrated_oracle_count: 1,
        one_oracle_per_batch_item_layout: false,
        introduced_whir_root_count: 0,
        introduced_whir_proof_count: 0,
        counters,
        layout_digest: [0u8; 32],
        table_digest: [0u8; 32],
    };
    table.layout_digest = symbt3_n8_integrated_committed_table_layout_digest(&table);
    table.table_digest = symbt3_n8_integrated_committed_table_digest(&table);
    table.counters.layout_digest = table.layout_digest;
    table.counters.table_digest = table.table_digest;
    Ok(table)
}

fn n8_integrated_boolean_point_for_row(row: usize, num_vars: usize) -> Vec<BabyBear> {
    (0..num_vars)
        .map(|bit| {
            if ((row >> bit) & 1) == 1 {
                BabyBear::ONE
            } else {
                BabyBear::ZERO
            }
        })
        .collect()
}

fn n8_integrated_tuple_row(
    axis: &IntegratedK6aNativeTupleRepetitionAxisMappingV1,
    repetition_index: usize,
    logical_index: usize,
) -> Option<usize> {
    if repetition_index >= axis.rlc_repetition_count {
        return None;
    }
    let logical_mask = if axis.logical_num_vars >= usize::BITS as usize {
        return None;
    } else {
        (1usize << axis.logical_num_vars).saturating_sub(1)
    };
    let repetition_bits = repetition_index.checked_shl(axis.repetition_axis_start as u32)?;
    Some((logical_index & logical_mask) | repetition_bits)
}

fn n8_integrated_row_aux_digest(
    kind: RealIntegratedK6aNativeEvaluatorRowKindV1,
    payload: impl FnOnce(&mut Vec<u8>),
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"REAL_INTEGRATED_K6A_NATIVE_ROW_AUX_V1");
    push_bytes(&mut bytes, &kind.canonical_bytes());
    payload(&mut bytes);
    digest_bytes(&bytes)
}

fn n8_integrated_k6a_semantic_row_aux_digest(
    kind: N8IntegratedK6aSemanticConstraintRowKindV1,
    payload: impl FnOnce(&mut Vec<u8>),
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"N8_INTEGRATED_K6A_SEMANTIC_ROW_AUX_V1");
    push_bytes(&mut bytes, &kind.canonical_bytes());
    payload(&mut bytes);
    digest_bytes(&bytes)
}

fn n8_integrated_k6a_semantic_to_evaluator_row_kind(
    kind: N8IntegratedK6aSemanticConstraintRowKindV1,
) -> RealIntegratedK6aNativeEvaluatorRowKindV1 {
    match kind {
        N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1 => {
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticVerifierOpeningClaimV1
        }
        N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1 => {
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1
        }
        N8IntegratedK6aSemanticConstraintRowKindV1::ZEvalBindingV1 => {
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticZEvalBindingV1
        }
        N8IntegratedK6aSemanticConstraintRowKindV1::ProductSumcheckAcceptedV1 => {
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticProductSumcheckAcceptedV1
        }
        N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1 => {
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticPaddingZeroV1
        }
    }
}

fn n8_integrated_evaluator_rows_digest(rows: &[RealIntegratedK6aNativeEvaluatorRowV1]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"REAL_INTEGRATED_K6A_NATIVE_ROWS_DIGEST_V1");
    push_u64(&mut bytes, rows.len() as u64);
    for row in rows {
        push_bytes(&mut bytes, &row.canonical_bytes());
    }
    digest_bytes(&bytes)
}

fn n8_integrated_logical_column_weight(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
    column: RealIntegratedK6aNativeLogicalColumnV1,
) -> BabyBear {
    let mut transcript = Vec::new();
    push_bytes(
        &mut transcript,
        b"REAL_INTEGRATED_K6A_NATIVE_LOGICAL_COLUMN_RLC_V1",
    );
    push_digest(&mut transcript, &evaluator.plan_digest);
    push_digest(&mut transcript, &evaluator.committed_table_layout_digest);
    push_digest(&mut transcript, &evaluator.rows_digest);
    push_bytes(&mut transcript, &column.canonical_bytes());
    derive_challenge(&transcript, 0, b"n8-real-integrated-logical-column")
}

fn n8_integrated_evaluator_table_values(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
) -> Result<Vec<BabyBear>, Symbt3N8IntegratedPrototypeBlocker> {
    let mut table = vec![BabyBear::ZERO; evaluator.integrated_oracle_len];
    let k6a_weight = n8_integrated_logical_column_weight(
        evaluator,
        RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
    );
    let tuple_packed_weight = n8_integrated_logical_column_weight(
        evaluator,
        RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafPacked,
    );
    let tuple_logical_weight = n8_integrated_logical_column_weight(
        evaluator,
        RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafLogical,
    );
    let transition_weight = n8_integrated_logical_column_weight(
        evaluator,
        RealIntegratedK6aNativeLogicalColumnV1::AccumulatorTransitionBinding,
    );
    for row in &evaluator.rows {
        if row.integrated_row >= evaluator.integrated_oracle_len {
            return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch);
        }
        let weight = match row.logical_column {
            RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain => k6a_weight,
            RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafPacked => tuple_packed_weight,
            RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafLogical => tuple_logical_weight,
            RealIntegratedK6aNativeLogicalColumnV1::AccumulatorTransitionBinding => {
                transition_weight
            }
        };
        table[row.integrated_row] += weight * row.value;
    }
    Ok(table)
}

fn n8_integrated_evaluator_table_digest(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
) -> Result<Digest32, Symbt3N8IntegratedPrototypeBlocker> {
    let table = n8_integrated_evaluator_table_values(evaluator)?;
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_TABLE_DIGEST_V1",
    );
    push_u64(&mut bytes, table.len() as u64);
    push_babybear_vec(&mut bytes, &table);
    Ok(digest_bytes(&bytes))
}

fn n8_integrated_evaluator_digest(evaluator: &RealIntegratedK6aNativeEvaluatorV1) -> Digest32 {
    digest_bytes(&evaluator.canonical_bytes_without_digests())
}

fn build_incomplete_n8_integrated_k6a_semantic_constraints_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    k6a_proof: &WhirProof,
) -> N8IntegratedK6aSemanticConstraintsV1 {
    N8IntegratedK6aSemanticConstraintsV1 {
        version: N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_VERSION,
        complete: false,
        k6a_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        k6a_num_vars: plan.k6a_num_vars,
        k6a_oracle_len: plan.k6a_oracle_len,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        verifier_point_count: 0,
        verifier_claim_count: symbt3_n8_k6a_claim_row_count(k6a_proof),
        final_residual_count: 0,
        product_sumcheck_round_count: k6a_proof.sumcheck_rounds_4.len(),
        padding_row_count: 0,
        verifier_points_digest: [0u8; 32],
        verifier_claims_digest: digest_babybear_slice(
            b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
            &k6a_proof.private_opening_evals,
        ),
        final_residual_digest: digest_babybear_slice(
            b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
            &k6a_proof.evaluations,
        ),
        product_sumcheck_digest: n8_integrated_k6a_product_sumcheck_digest(
            &k6a_proof.sumcheck_rounds_4,
        ),
        rows: Vec::new(),
        rows_digest: n8_integrated_k6a_semantic_rows_digest(&[]),
        descriptor_digest: plan.k6a_semantic_descriptor_digest,
    }
}

fn build_n8_integrated_k6a_semantic_constraints_v1(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    plan: &IntegratedK6aNativeClaimPlanV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    k6a_proof: &WhirProof,
) -> Result<N8IntegratedK6aSemanticConstraintsV1, Symbt3N8IntegratedPrototypeBlocker> {
    let claims = super::symbt3_c_table_and_claims(
        seed,
        relation,
        statement,
        None,
        Some(&k6a_proof.private_opening_evals),
        Some(&k6a_proof.sumcheck_rounds_4),
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)?;
    if k6a_proof.num_vars != claims.num_vars
        || k6a_proof.num_vars != plan.k6a_num_vars
        || k6a_proof.evaluations != claims.evaluations
        || k6a_proof.z_eval != claims.z_eval
        || claims.claimed != k6a_proof.private_opening_evals
        || claims
            .evaluations
            .iter()
            .any(|&value| value != BabyBear::ZERO)
        || claims.points.len() != claims.claimed.len()
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }

    let points_digest = n8_integrated_k6a_verifier_points_digest(&claims.points);
    let claims_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
        &claims.claimed,
    );
    let final_residual_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
        &claims.evaluations,
    );
    let product_sumcheck_digest =
        n8_integrated_k6a_product_sumcheck_digest(&claims.product_sumcheck_rounds);
    let descriptor_digest = n8_integrated_complete_k6a_semantic_descriptor_digest_from_claims(
        adapter,
        k6a_proof,
        points_digest,
        claims_digest,
        final_residual_digest,
        product_sumcheck_digest,
        claims.points.len(),
        claims.claimed.len(),
    );
    if descriptor_digest != plan.k6a_semantic_descriptor_digest {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }

    let mut rows = Vec::new();
    let semantic_base = symbt3_n8_k6a_claim_row_count(k6a_proof);
    let push_semantic_row = |rows: &mut Vec<N8IntegratedK6aSemanticConstraintRowV1>,
                             kind: N8IntegratedK6aSemanticConstraintRowKindV1,
                             source_index: usize,
                             value: BabyBear,
                             aux_digest: Digest32| {
        let semantic_index = rows.len();
        let integrated_row = (semantic_base + semantic_index) % plan.integrated_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(N8IntegratedK6aSemanticConstraintRowV1 {
            kind,
            source_index,
            integrated_row,
            point_digest: native_oracle_point_digest(&point),
            value,
            aux_digest,
        });
    };

    for (index, (point, &value)) in claims.points.iter().zip(claims.claimed.iter()).enumerate() {
        push_semantic_row(
            &mut rows,
            N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1,
            index,
            value,
            n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1,
                |bytes| {
                    push_u64(bytes, index as u64);
                    push_digest(bytes, &native_oracle_point_digest(point));
                    push_babybear(bytes, value);
                },
            ),
        );
    }
    for (index, &value) in claims.evaluations.iter().enumerate() {
        push_semantic_row(
            &mut rows,
            N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1,
            index,
            value,
            n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1,
                |bytes| {
                    push_u64(bytes, index as u64);
                    push_babybear(bytes, value);
                },
            ),
        );
    }
    let first_claim = claims
        .claimed
        .first()
        .copied()
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)?;
    for (index, value) in [
        k6a_proof.z_eval - claims.z_eval,
        claims.z_eval - first_claim,
    ]
    .into_iter()
    .enumerate()
    {
        push_semantic_row(
            &mut rows,
            N8IntegratedK6aSemanticConstraintRowKindV1::ZEvalBindingV1,
            index,
            value,
            n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::ZEvalBindingV1,
                |bytes| {
                    push_u64(bytes, index as u64);
                    push_babybear(bytes, k6a_proof.z_eval);
                    push_babybear(bytes, claims.z_eval);
                    push_babybear(bytes, first_claim);
                },
            ),
        );
    }
    push_semantic_row(
        &mut rows,
        N8IntegratedK6aSemanticConstraintRowKindV1::ProductSumcheckAcceptedV1,
        0,
        BabyBear::ZERO,
        n8_integrated_k6a_semantic_row_aux_digest(
            N8IntegratedK6aSemanticConstraintRowKindV1::ProductSumcheckAcceptedV1,
            |bytes| {
                push_digest(bytes, &product_sumcheck_digest);
                push_u64(bytes, claims.product_sumcheck_rounds.len() as u64);
            },
        ),
    );
    let padding_row_count = usize::from(plan.k6a_padding_policy.padded_row_count > 0);
    if padding_row_count > 0 {
        let integrated_row = plan.k6a_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(N8IntegratedK6aSemanticConstraintRowV1 {
            kind: N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1,
            source_index: 0,
            integrated_row,
            point_digest: native_oracle_point_digest(&point),
            value: BabyBear::ZERO,
            aux_digest: n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1,
                |bytes| {
                    push_bytes(bytes, &plan.k6a_padding_policy.canonical_bytes());
                    push_u64(bytes, plan.k6a_padding_policy.padded_row_count as u64);
                },
            ),
        });
    }

    let rows_digest = n8_integrated_k6a_semantic_rows_digest(&rows);
    Ok(N8IntegratedK6aSemanticConstraintsV1 {
        version: N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_VERSION,
        complete: true,
        k6a_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        k6a_num_vars: plan.k6a_num_vars,
        k6a_oracle_len: plan.k6a_oracle_len,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        verifier_point_count: claims.points.len(),
        verifier_claim_count: claims.claimed.len(),
        final_residual_count: claims.evaluations.len(),
        product_sumcheck_round_count: claims.product_sumcheck_rounds.len(),
        padding_row_count,
        verifier_points_digest: points_digest,
        verifier_claims_digest: claims_digest,
        final_residual_digest,
        product_sumcheck_digest,
        rows,
        rows_digest,
        descriptor_digest,
    })
}

fn build_n8_integrated_k6a_semantic_constraints_v1_from_source(
    plan: &IntegratedK6aNativeClaimPlanV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    source: &Symbt3N8K6aSemanticSourceV1,
) -> Result<N8IntegratedK6aSemanticConstraintsV1, Symbt3N8IntegratedPrototypeBlocker> {
    if source.source_digest != adapter.main_symbt3_proof_digest
        || source.relation_id != adapter.main_symbt3_relation_id
        || source.public_statement_digest != adapter.public_statement_digest
        || source.whir_param_digest != adapter.whir_param_digest
        || source.num_vars != plan.k6a_num_vars
        || source.oracle_len != plan.k6a_oracle_len
        || source.verifier_points.len() != source.verifier_claims.len()
        || source
            .final_residuals
            .iter()
            .any(|&value| value != BabyBear::ZERO)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }

    let points_digest = n8_integrated_k6a_verifier_points_digest(&source.verifier_points);
    let claims_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
        &source.verifier_claims,
    );
    let final_residual_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
        &source.final_residuals,
    );
    let product_sumcheck_digest =
        n8_integrated_k6a_product_sumcheck_digest(&source.product_sumcheck_rounds);
    let descriptor_digest = n8_integrated_complete_k6a_semantic_descriptor_digest_from_source(
        adapter,
        source,
        points_digest,
        claims_digest,
        final_residual_digest,
        product_sumcheck_digest,
        source.verifier_points.len(),
        source.verifier_claims.len(),
    );
    if descriptor_digest != plan.k6a_semantic_descriptor_digest {
        return Err(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }

    let mut rows = Vec::new();
    let semantic_base = symbt3_n8_k6a_claim_row_count_from_source(source);
    let push_semantic_row = |rows: &mut Vec<N8IntegratedK6aSemanticConstraintRowV1>,
                             kind: N8IntegratedK6aSemanticConstraintRowKindV1,
                             source_index: usize,
                             value: BabyBear,
                             aux_digest: Digest32| {
        let semantic_index = rows.len();
        let integrated_row = (semantic_base + semantic_index) % plan.integrated_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(N8IntegratedK6aSemanticConstraintRowV1 {
            kind,
            source_index,
            integrated_row,
            point_digest: native_oracle_point_digest(&point),
            value,
            aux_digest,
        });
    };

    for (index, (point, &value)) in source
        .verifier_points
        .iter()
        .zip(source.verifier_claims.iter())
        .enumerate()
    {
        push_semantic_row(
            &mut rows,
            N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1,
            index,
            value,
            n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1,
                |bytes| {
                    push_u64(bytes, index as u64);
                    push_digest(bytes, &native_oracle_point_digest(point));
                    push_babybear(bytes, value);
                },
            ),
        );
    }
    for (index, &value) in source.final_residuals.iter().enumerate() {
        push_semantic_row(
            &mut rows,
            N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1,
            index,
            value,
            n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1,
                |bytes| {
                    push_u64(bytes, index as u64);
                    push_babybear(bytes, value);
                },
            ),
        );
    }
    let first_claim = source
        .verifier_claims
        .first()
        .copied()
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)?;
    for (index, value) in [BabyBear::ZERO, source.z_eval - first_claim]
        .into_iter()
        .enumerate()
    {
        push_semantic_row(
            &mut rows,
            N8IntegratedK6aSemanticConstraintRowKindV1::ZEvalBindingV1,
            index,
            value,
            n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::ZEvalBindingV1,
                |bytes| {
                    push_u64(bytes, index as u64);
                    push_babybear(bytes, source.z_eval);
                    push_babybear(bytes, source.z_eval);
                    push_babybear(bytes, first_claim);
                },
            ),
        );
    }
    push_semantic_row(
        &mut rows,
        N8IntegratedK6aSemanticConstraintRowKindV1::ProductSumcheckAcceptedV1,
        0,
        BabyBear::ZERO,
        n8_integrated_k6a_semantic_row_aux_digest(
            N8IntegratedK6aSemanticConstraintRowKindV1::ProductSumcheckAcceptedV1,
            |bytes| {
                push_digest(bytes, &product_sumcheck_digest);
                push_u64(bytes, source.product_sumcheck_rounds.len() as u64);
            },
        ),
    );
    let padding_row_count = usize::from(plan.k6a_padding_policy.padded_row_count > 0);
    if padding_row_count > 0 {
        let integrated_row = plan.k6a_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(N8IntegratedK6aSemanticConstraintRowV1 {
            kind: N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1,
            source_index: 0,
            integrated_row,
            point_digest: native_oracle_point_digest(&point),
            value: BabyBear::ZERO,
            aux_digest: n8_integrated_k6a_semantic_row_aux_digest(
                N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1,
                |bytes| {
                    push_bytes(bytes, &plan.k6a_padding_policy.canonical_bytes());
                    push_u64(bytes, plan.k6a_padding_policy.padded_row_count as u64);
                },
            ),
        });
    }

    let rows_digest = n8_integrated_k6a_semantic_rows_digest(&rows);
    Ok(N8IntegratedK6aSemanticConstraintsV1 {
        version: N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_VERSION,
        complete: true,
        k6a_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        k6a_num_vars: plan.k6a_num_vars,
        k6a_oracle_len: plan.k6a_oracle_len,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        verifier_point_count: source.verifier_points.len(),
        verifier_claim_count: source.verifier_claims.len(),
        final_residual_count: source.final_residuals.len(),
        product_sumcheck_round_count: source.product_sumcheck_rounds.len(),
        padding_row_count,
        verifier_points_digest: points_digest,
        verifier_claims_digest: claims_digest,
        final_residual_digest,
        product_sumcheck_digest,
        rows,
        rows_digest,
        descriptor_digest,
    })
}

fn build_incomplete_n8_integrated_tuple_rlc_semantic_constraints_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
) -> N8IntegratedTupleRlcSemanticConstraintsV1 {
    let proof = &native_tuple_leaf.proof;
    let packed_claims_digest =
        symbt3_tuple_leaf_packed_eval_claims_digest(&proof.packed_eval_claims);
    let logical_claims_digest = native_oracle_eval_claims_digest(&proof.logical_eval_claims);
    let claim_kind = proof
        .logical_eval_claims
        .first()
        .map_or(WhirNativeEvalClaimKind::DirectOpening, |claim| {
            claim.claim_kind
        });
    let rows = Vec::new();
    let mut constraints = N8IntegratedTupleRlcSemanticConstraintsV1 {
        version: N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINTS_VERSION,
        complete: false,
        proof_relation_id: proof.proof_relation_id,
        public_statement_digest: proof.public_statement_digest,
        whir_param_digest: proof.whir_param_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        packed_root: proof.packed_root,
        logical_oracle_count: plan.tuple_logical_oracle_count,
        logical_num_vars: plan.tuple_logical_num_vars,
        packed_num_vars: plan.tuple_packed_num_vars,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        rlc_repetition_count: plan.rlc_repetition_count,
        rlc_batching_bits_per_repetition: plan.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: plan.total_rlc_batching_bits,
        effective_soundness_bits: plan.effective_soundness_bits,
        tuple_leaf_layout: proof.counters.tuple_leaf_layout.clone(),
        same_domain: proof.counters.same_domain,
        same_field: proof.counters.same_field,
        same_rate: proof.counters.same_rate,
        same_folding_parameter: proof.counters.same_folding_parameter,
        claim_kind,
        packing_challenge_digest: proof.packing_challenge_digest,
        derived_packing_challenge_digest: [0u8; 32],
        packed_claims_digest,
        logical_claims_digest,
        opening_points_digest: [0u8; 32],
        residuals_digest: n8_integrated_tuple_rlc_residuals_digest(&[]),
        packed_row_count: 0,
        logical_row_count: 0,
        residual_row_count: 0,
        padding_row_count: 0,
        rows,
        rows_digest: n8_integrated_tuple_rlc_semantic_rows_digest(&[]),
        descriptor_digest: [0u8; 32],
    };
    constraints.descriptor_digest =
        n8_integrated_tuple_rlc_semantic_descriptor_digest(&constraints);
    constraints
}

fn build_n8_integrated_tuple_rlc_semantic_constraints_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
) -> Result<N8IntegratedTupleRlcSemanticConstraintsV1, Symbt3N8IntegratedPrototypeBlocker> {
    let proof = &native_tuple_leaf.proof;
    if !symbt3_n8_tuple_leaf_repeated_rlc_ok(native_tuple_leaf)
        || proof.version != SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION
        || proof.mode != Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1
        || proof.counters.tuple_leaf_layout != SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
        || !proof.counters.same_domain
        || !proof.counters.same_field
        || !proof.counters.same_rate
        || !proof.counters.same_folding_parameter
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    }

    let logical_oracle_count = proof.logical_descriptors.len();
    let first_descriptor = proof
        .logical_descriptors
        .first()
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)?;
    let logical_num_vars = first_descriptor.num_vars;
    if logical_oracle_count != plan.tuple_logical_oracle_count
        || logical_num_vars != plan.tuple_logical_num_vars
        || proof.counters.rlc_repetition_count != plan.rlc_repetition_count
        || proof.counters.rlc_batching_bits_per_repetition != plan.rlc_batching_bits_per_repetition
        || proof.counters.total_rlc_batching_bits != plan.total_rlc_batching_bits
        || proof.counters.effective_soundness_bits != plan.effective_soundness_bits
        || proof.logical_eval_claims.len()
            != logical_oracle_count.saturating_mul(plan.rlc_repetition_count)
        || proof.packed_eval_claims.len() != plan.rlc_repetition_count
        || validate_same_domain_tuple_leaf_claim_shape(
            &proof.logical_descriptors,
            &proof.logical_eval_claims,
        )
        .is_err()
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    let descriptor_digest = native_oracle_spec_digest(&proof.logical_descriptors);
    if descriptor_digest != proof.descriptor_digest {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }
    let expected_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        proof.mode,
        descriptor_digest,
        logical_oracle_count,
        logical_num_vars,
        plan.rlc_repetition_count,
        plan.rlc_batching_bits_per_repetition,
    );
    if expected_layout_digest != proof.tuple_leaf_layout_digest {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }
    let Some(repeated_packing_challenges) = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        proof.mode,
        proof.proof_relation_id,
        proof.public_statement_digest,
        proof.whir_param_digest,
        proof.descriptor_digest,
        proof.tuple_leaf_layout_digest,
        logical_oracle_count,
        logical_num_vars,
        plan.rlc_repetition_count,
    ) else {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    };
    let derived_packing_challenge_digest =
        symbt3_tuple_leaf_repeated_packing_challenge_digest(&repeated_packing_challenges);
    if derived_packing_challenge_digest != proof.packing_challenge_digest {
        return Err(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    let claim_kind = proof
        .logical_eval_claims
        .first()
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)?
        .claim_kind;
    let repetition_log_size = symbt3_tuple_leaf_repetition_log_size(plan.rlc_repetition_count)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak)?;
    let packed_num_vars = logical_num_vars
        .checked_add(repetition_log_size)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    if packed_num_vars != plan.tuple_packed_num_vars {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
    }

    let mut packed_rows = Vec::new();
    let mut logical_rows = Vec::new();
    let mut residual_rows = Vec::new();
    let mut opening_point_digests = Vec::with_capacity(plan.rlc_repetition_count);
    let mut residuals = Vec::with_capacity(plan.rlc_repetition_count);

    for (repetition_index, packing_challenges) in repeated_packing_challenges.iter().enumerate() {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            proof.proof_relation_id,
            proof.public_statement_digest,
            proof.whir_param_digest,
            proof.descriptor_digest,
            proof.tuple_leaf_layout_digest,
            claim_kind,
            logical_num_vars,
        );
        let logical_point_digest = native_oracle_point_digest(&point);
        let mut packed_point = point;
        packed_point.extend(tuple_leaf_boolean_point_for_index(
            repetition_index,
            repetition_log_size,
        ));
        let packed_point_digest = native_oracle_point_digest(&packed_point);
        opening_point_digests.push((logical_point_digest, packed_point_digest));

        let packed_claim = &proof.packed_eval_claims[repetition_index];
        if packed_claim.point_digest != packed_point_digest
            || packed_claim.claim_kind != WhirNativeEvalClaimKind::DirectOpening
        {
            return Err(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
        }
        let packed_integrated_row =
            n8_integrated_tuple_row(&plan.tuple_repetition_axis, repetition_index, 0)
                .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
        packed_rows.push(N8IntegratedTupleRlcSemanticConstraintRowV1 {
            kind: N8IntegratedTupleRlcSemanticConstraintRowKindV1::PackedOpeningClaimV1,
            source_index: repetition_index,
            integrated_row: packed_integrated_row,
            repetition_index: Some(repetition_index),
            oracle_id: None,
            point_digest: native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                packed_integrated_row,
                plan.integrated_num_vars,
            )),
            value: packed_claim.value,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1,
                |bytes| {
                    push_digest(bytes, &packed_claim.point_digest);
                    push_babybear(bytes, packed_claim.value);
                    encode_claim_kind(bytes, packed_claim.claim_kind);
                },
            ),
        });

        let start = repetition_index.saturating_mul(logical_oracle_count);
        let end = start.saturating_add(logical_oracle_count);
        let repetition_claims = &proof.logical_eval_claims[start..end];
        let mut logical_values = Vec::with_capacity(logical_oracle_count);
        for (oracle_offset, (spec, logical_claim)) in proof
            .logical_descriptors
            .iter()
            .zip(repetition_claims.iter())
            .enumerate()
        {
            if logical_claim.oracle_id != spec.oracle_id
                || logical_claim.point_digest != logical_point_digest
                || logical_claim.claim_kind != claim_kind
            {
                return Err(
                    Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation,
                );
            }
            let source_index = start + oracle_offset;
            let integrated_row = n8_integrated_tuple_row(
                &plan.tuple_repetition_axis,
                repetition_index,
                oracle_offset,
            )
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
            logical_rows.push(N8IntegratedTupleRlcSemanticConstraintRowV1 {
                kind: N8IntegratedTupleRlcSemanticConstraintRowKindV1::LogicalOpeningClaimV1,
                source_index,
                integrated_row,
                repetition_index: Some(repetition_index),
                oracle_id: Some(logical_claim.oracle_id),
                point_digest: native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                    integrated_row,
                    plan.integrated_num_vars,
                )),
                value: logical_claim.value,
                aux_digest: n8_integrated_row_aux_digest(
                    RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
                    |bytes| {
                        push_digest(bytes, &logical_claim.point_digest);
                        push_u32(bytes, logical_claim.oracle_id);
                        push_babybear(bytes, logical_claim.value);
                        encode_claim_kind(bytes, logical_claim.claim_kind);
                    },
                ),
            });
            logical_values.push(logical_claim.value);
        }

        let packed_value = symbt3_tuple_leaf_pack_values(packing_challenges, &logical_values)
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak)?;
        let residual = packed_claim.value - packed_value;
        residuals.push(residual);
        let residual_integrated_row = n8_integrated_tuple_row(
            &plan.tuple_repetition_axis,
            repetition_index,
            logical_oracle_count,
        )
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
        residual_rows.push(N8IntegratedTupleRlcSemanticConstraintRowV1 {
            kind: N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1,
            source_index: repetition_index,
            integrated_row: residual_integrated_row,
            repetition_index: Some(repetition_index),
            oracle_id: None,
            point_digest: native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                residual_integrated_row,
                plan.integrated_num_vars,
            )),
            value: residual,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
                |bytes| {
                    push_u64(bytes, repetition_index as u64);
                    push_babybear_vec(bytes, packing_challenges);
                    push_babybear(bytes, packed_claim.value);
                    push_babybear(bytes, packed_value);
                },
            ),
        });
    }

    let tuple_padding_rows = plan
        .integrated_oracle_len
        .checked_sub(plan.tuple_packed_oracle_len)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    let padding_row_count = usize::from(tuple_padding_rows > 0);
    let mut rows = Vec::with_capacity(
        packed_rows
            .len()
            .saturating_add(logical_rows.len())
            .saturating_add(residual_rows.len())
            .saturating_add(padding_row_count),
    );
    rows.extend(packed_rows);
    rows.extend(logical_rows);
    rows.extend(residual_rows);
    if padding_row_count > 0 {
        let integrated_row = plan.tuple_packed_oracle_len;
        rows.push(N8IntegratedTupleRlcSemanticConstraintRowV1 {
            kind: N8IntegratedTupleRlcSemanticConstraintRowKindV1::TuplePaddingZeroV1,
            source_index: 0,
            integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                integrated_row,
                plan.integrated_num_vars,
            )),
            value: BabyBear::ZERO,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1,
                |bytes| {
                    push_bytes(bytes, &plan.tuple_repetition_axis.canonical_bytes());
                    push_u64(bytes, 0);
                },
            ),
        });
    }

    let rows_digest = n8_integrated_tuple_rlc_semantic_rows_digest(&rows);
    let packed_claims_digest =
        symbt3_tuple_leaf_packed_eval_claims_digest(&proof.packed_eval_claims);
    let logical_claims_digest = native_oracle_eval_claims_digest(&proof.logical_eval_claims);
    let opening_points_digest =
        n8_integrated_tuple_rlc_opening_points_digest(&opening_point_digests);
    let residuals_digest = n8_integrated_tuple_rlc_residuals_digest(&residuals);
    let mut constraints = N8IntegratedTupleRlcSemanticConstraintsV1 {
        version: N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINTS_VERSION,
        complete: true,
        proof_relation_id: proof.proof_relation_id,
        public_statement_digest: proof.public_statement_digest,
        whir_param_digest: proof.whir_param_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        packed_root: proof.packed_root,
        logical_oracle_count,
        logical_num_vars,
        packed_num_vars,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        rlc_repetition_count: plan.rlc_repetition_count,
        rlc_batching_bits_per_repetition: plan.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: plan.total_rlc_batching_bits,
        effective_soundness_bits: plan.effective_soundness_bits,
        tuple_leaf_layout: proof.counters.tuple_leaf_layout.clone(),
        same_domain: proof.counters.same_domain,
        same_field: proof.counters.same_field,
        same_rate: proof.counters.same_rate,
        same_folding_parameter: proof.counters.same_folding_parameter,
        claim_kind,
        packing_challenge_digest: proof.packing_challenge_digest,
        derived_packing_challenge_digest,
        packed_claims_digest,
        logical_claims_digest,
        opening_points_digest,
        residuals_digest,
        packed_row_count: plan.rlc_repetition_count,
        logical_row_count: logical_oracle_count.saturating_mul(plan.rlc_repetition_count),
        residual_row_count: plan.rlc_repetition_count,
        padding_row_count,
        rows,
        rows_digest,
        descriptor_digest: [0u8; 32],
    };
    constraints.descriptor_digest =
        n8_integrated_tuple_rlc_semantic_descriptor_digest(&constraints);
    Ok(constraints)
}

fn n8_integrated_transition_semantic_row_aux_digest(
    kind: N8IntegratedTransitionBindingSemanticConstraintRowKindV1,
    payload: impl FnOnce(&mut Vec<u8>),
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_ROW_AUX_V1",
    );
    push_bytes(&mut bytes, &kind.canonical_bytes());
    payload(&mut bytes);
    digest_bytes(&bytes)
}

fn build_incomplete_n8_integrated_transition_binding_semantic_constraints_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
    committed_table: &IntegratedK6aNativeCommittedTableV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    tuple_rlc_semantic_constraints: &N8IntegratedTupleRlcSemanticConstraintsV1,
) -> N8IntegratedTransitionBindingSemanticConstraintsV1 {
    let proof = &native_tuple_leaf.proof;
    let transition_constraint_descriptor_digest = plan
        .constraint_descriptors
        .get(2)
        .map_or([0u8; 32], |descriptor| descriptor.descriptor_digest);
    let mut constraints = N8IntegratedTransitionBindingSemanticConstraintsV1 {
        version: N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_CONSTRAINTS_VERSION,
        complete: false,
        workload_kind: adapter.workload_kind,
        profile_digest: adapter.profile_digest,
        accumulator_instance_digest: adapter.accumulator_instance_digest,
        old_accumulator_digest: adapter.old_accumulator_digest,
        new_accumulator_digest: adapter.new_accumulator_digest,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        main_symbt3_relation_id: adapter.main_symbt3_relation_id,
        k6a_proof_digest: adapter.main_symbt3_proof_digest,
        tuple_leaf_root: proof.packed_root,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_packing_challenge_digest: proof.packing_challenge_digest,
        native_oracle_descriptor_digest: native_tuple_leaf.native_oracle_descriptor_digest,
        native_message_roots_digest: native_tuple_leaf.native_message_roots_digest,
        manifest_oracle_root: native_tuple_leaf.manifest_oracle_root,
        source_oracle_root: native_tuple_leaf.source_oracle_root,
        batch_manifest_root: adapter.batch_manifest_root,
        batch_size: adapter.batch_size,
        active_count: adapter.active_count,
        k6a_num_vars: plan.k6a_num_vars,
        k6a_oracle_len: plan.k6a_oracle_len,
        tuple_logical_oracle_count: plan.tuple_logical_oracle_count,
        tuple_logical_num_vars: plan.tuple_logical_num_vars,
        tuple_packed_num_vars: plan.tuple_packed_num_vars,
        tuple_packed_oracle_len: plan.tuple_packed_oracle_len,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        rlc_repetition_count: plan.rlc_repetition_count,
        rlc_batching_bits_per_repetition: plan.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: plan.total_rlc_batching_bits,
        effective_soundness_bits: plan.effective_soundness_bits,
        k6a_semantic_descriptor_digest: plan.k6a_semantic_descriptor_digest,
        tuple_rlc_semantic_descriptor_digest: tuple_rlc_semantic_constraints.descriptor_digest,
        n8_claim_plan_digest: plan.claim_plan_digest,
        n8_committed_table_layout_digest: committed_table.layout_digest,
        n8_committed_table_digest: committed_table.table_digest,
        n8_combined_constraint_descriptor_digest: plan.combined_constraint_descriptor_digest,
        n8_combined_claim_descriptor_digest: plan.combined_claim_descriptor_digest,
        k6a_constraint_descriptor_digest: plan.constraint_descriptors[0].descriptor_digest,
        tuple_constraint_descriptor_digest: plan.constraint_descriptors[1].descriptor_digest,
        transition_constraint_descriptor_digest,
        transition_binding_digest: [0u8; 32],
        rows: Vec::new(),
        rows_digest: n8_integrated_transition_binding_semantic_rows_digest(&[]),
        descriptor_digest: [0u8; 32],
    };
    constraints.transition_binding_digest =
        n8_integrated_transition_binding_semantic_digest(&constraints);
    constraints.descriptor_digest =
        n8_integrated_transition_binding_semantic_descriptor_digest(&constraints);
    constraints
}

fn n8_integrated_transition_semantic_rows(
    constraints: &N8IntegratedTransitionBindingSemanticConstraintsV1,
) -> Vec<N8IntegratedTransitionBindingSemanticConstraintRowV1> {
    let kinds = [
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::AccumulatorBoundaryDigestV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::PublicStatementAndK6aProofV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::TupleLeafRootAndLayoutV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::NativeDescriptorAndMessageRootsV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::ManifestSourceBatchRootsV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::BatchShapeV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::WorkloadKindV1,
        N8IntegratedTransitionBindingSemanticConstraintRowKindV1::N8PlanTableLayoutV1,
    ];
    let row_count = kinds.len();
    let base_row = constraints.integrated_oracle_len.saturating_sub(row_count);
    kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let integrated_row = if constraints.integrated_oracle_len == 0 {
                0
            } else {
                (base_row + index) % constraints.integrated_oracle_len
            };
            let point = n8_integrated_boolean_point_for_row(
                integrated_row,
                constraints.integrated_num_vars,
            );
            let aux_digest = n8_integrated_transition_semantic_row_aux_digest(kind, |bytes| {
                push_digest(bytes, &constraints.transition_binding_digest);
                match kind {
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::AccumulatorBoundaryDigestV1 => {
                        push_digest(bytes, &constraints.accumulator_instance_digest);
                        push_digest(bytes, &constraints.old_accumulator_digest);
                        push_digest(bytes, &constraints.new_accumulator_digest);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::PublicStatementAndK6aProofV1 => {
                        push_digest(bytes, &constraints.public_statement_digest);
                        push_digest(bytes, &constraints.whir_param_digest);
                        push_digest(bytes, &constraints.main_symbt3_relation_id);
                        push_digest(bytes, &constraints.k6a_proof_digest);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::TupleLeafRootAndLayoutV1 => {
                        push_digest(bytes, &constraints.tuple_leaf_root);
                        push_digest(bytes, &constraints.tuple_leaf_layout_digest);
                        push_digest(bytes, &constraints.tuple_leaf_descriptor_digest);
                        push_digest(bytes, &constraints.tuple_leaf_packing_challenge_digest);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::NativeDescriptorAndMessageRootsV1 => {
                        push_digest(bytes, &constraints.native_oracle_descriptor_digest);
                        push_digest(bytes, &constraints.native_message_roots_digest);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::ManifestSourceBatchRootsV1 => {
                        push_digest(bytes, &constraints.manifest_oracle_root);
                        push_digest(bytes, &constraints.source_oracle_root);
                        push_digest(bytes, &constraints.batch_manifest_root);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::BatchShapeV1 => {
                        push_u64(bytes, constraints.batch_size);
                        push_u64(bytes, constraints.active_count);
                        push_u64(bytes, constraints.integrated_num_vars as u64);
                        push_u64(bytes, constraints.integrated_oracle_len as u64);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::WorkloadKindV1 => {
                        push_bytes(bytes, &constraints.workload_kind.canonical_bytes());
                        push_digest(bytes, &constraints.profile_digest);
                    }
                    N8IntegratedTransitionBindingSemanticConstraintRowKindV1::N8PlanTableLayoutV1 => {
                        push_digest(bytes, &constraints.n8_claim_plan_digest);
                        push_digest(bytes, &constraints.n8_committed_table_layout_digest);
                        push_digest(bytes, &constraints.n8_committed_table_digest);
                        push_digest(bytes, &constraints.n8_combined_constraint_descriptor_digest);
                        push_digest(bytes, &constraints.n8_combined_claim_descriptor_digest);
                        push_digest(bytes, &constraints.k6a_constraint_descriptor_digest);
                        push_digest(bytes, &constraints.tuple_constraint_descriptor_digest);
                        push_digest(bytes, &constraints.transition_constraint_descriptor_digest);
                        push_digest(bytes, &constraints.k6a_semantic_descriptor_digest);
                        push_digest(bytes, &constraints.tuple_rlc_semantic_descriptor_digest);
                    }
                }
            });
            N8IntegratedTransitionBindingSemanticConstraintRowV1 {
                kind,
                source_index: index,
                integrated_row,
                point_digest: native_oracle_point_digest(&point),
                value: BabyBear::ZERO,
                aux_digest,
            }
        })
        .collect()
}

fn build_n8_integrated_transition_binding_semantic_constraints_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
    committed_table: &IntegratedK6aNativeCommittedTableV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
    tuple_rlc_semantic_constraints: &N8IntegratedTupleRlcSemanticConstraintsV1,
) -> Result<N8IntegratedTransitionBindingSemanticConstraintsV1, Symbt3N8IntegratedPrototypeBlocker>
{
    if plan.constraint_descriptors.len() != 3
        || adapter.main_symbt3_proof_digest != symbt3_main_whir_proof_digest(k6a_proof)
        || adapter.main_symbt3_proof_digest == [0u8; 32]
        || adapter.accumulator_instance_digest == [0u8; 32]
        || adapter.old_accumulator_digest == [0u8; 32]
        || adapter.new_accumulator_digest == [0u8; 32]
        || adapter.public_statement_digest == [0u8; 32]
        || adapter.batch_manifest_root == [0u8; 32]
        || adapter.batch_size == 0
        || adapter.active_count == 0
        || adapter.active_count > adapter.batch_size
        || adapter.accumulator_transition_claims != 1
        || native_tuple_leaf.proof.packed_root == [0u8; 32]
        || native_tuple_leaf.proof.tuple_leaf_layout_digest == [0u8; 32]
        || native_tuple_leaf.native_oracle_descriptor_digest == [0u8; 32]
        || native_tuple_leaf.native_message_roots_digest == [0u8; 32]
        || native_tuple_leaf.manifest_oracle_root != adapter.manifest_oracle_root
        || native_tuple_leaf.native_message_roots_digest != adapter.native_message_roots_digest
    {
        return Err(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    let mut constraints = build_incomplete_n8_integrated_transition_binding_semantic_constraints_v1(
        plan,
        committed_table,
        adapter,
        native_tuple_leaf,
        tuple_rlc_semantic_constraints,
    );
    constraints.complete = true;
    constraints.rows = n8_integrated_transition_semantic_rows(&constraints);
    constraints.rows_digest =
        n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows);
    constraints.transition_binding_digest =
        n8_integrated_transition_binding_semantic_digest(&constraints);
    constraints.rows = n8_integrated_transition_semantic_rows(&constraints);
    constraints.rows_digest =
        n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows);
    constraints.descriptor_digest =
        n8_integrated_transition_binding_semantic_descriptor_digest(&constraints);
    Ok(constraints)
}

fn build_n8_integrated_transition_binding_semantic_constraints_v1_from_source(
    plan: &IntegratedK6aNativeClaimPlanV1,
    committed_table: &IntegratedK6aNativeCommittedTableV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_source: &Symbt3N8K6aSemanticSourceV1,
    tuple_rlc_semantic_constraints: &N8IntegratedTupleRlcSemanticConstraintsV1,
) -> Result<N8IntegratedTransitionBindingSemanticConstraintsV1, Symbt3N8IntegratedPrototypeBlocker>
{
    if plan.constraint_descriptors.len() != 3
        || adapter.main_symbt3_proof_digest != k6a_source.source_digest
        || adapter.main_symbt3_proof_digest == [0u8; 32]
        || adapter.accumulator_instance_digest == [0u8; 32]
        || adapter.old_accumulator_digest == [0u8; 32]
        || adapter.new_accumulator_digest == [0u8; 32]
        || adapter.public_statement_digest == [0u8; 32]
        || adapter.batch_manifest_root == [0u8; 32]
        || adapter.batch_size == 0
        || adapter.active_count == 0
        || adapter.active_count > adapter.batch_size
        || adapter.accumulator_transition_claims != 1
        || native_tuple_leaf.proof.packed_root == [0u8; 32]
        || native_tuple_leaf.proof.tuple_leaf_layout_digest == [0u8; 32]
        || native_tuple_leaf.native_oracle_descriptor_digest == [0u8; 32]
        || native_tuple_leaf.native_message_roots_digest == [0u8; 32]
        || native_tuple_leaf.manifest_oracle_root != adapter.manifest_oracle_root
        || native_tuple_leaf.native_message_roots_digest != adapter.native_message_roots_digest
    {
        return Err(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    let mut constraints = build_incomplete_n8_integrated_transition_binding_semantic_constraints_v1(
        plan,
        committed_table,
        adapter,
        native_tuple_leaf,
        tuple_rlc_semantic_constraints,
    );
    constraints.complete = true;
    constraints.rows = n8_integrated_transition_semantic_rows(&constraints);
    constraints.rows_digest =
        n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows);
    constraints.transition_binding_digest =
        n8_integrated_transition_binding_semantic_digest(&constraints);
    constraints.rows = n8_integrated_transition_semantic_rows(&constraints);
    constraints.rows_digest =
        n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows);
    constraints.descriptor_digest =
        n8_integrated_transition_binding_semantic_descriptor_digest(&constraints);
    Ok(constraints)
}

#[derive(Debug, Clone, Copy)]
struct N8K6aEvaluatorRowMaterial<'a> {
    verifier_claims: &'a [BabyBear],
    final_residuals: &'a [BabyBear; 3],
    z_eval: BabyBear,
    product_sumcheck_rounds: &'a [[BabyBear; 4]],
}

impl<'a> N8K6aEvaluatorRowMaterial<'a> {
    fn from_proof(proof: &'a WhirProof) -> Self {
        Self {
            verifier_claims: &proof.private_opening_evals,
            final_residuals: &proof.evaluations,
            z_eval: proof.z_eval,
            product_sumcheck_rounds: &proof.sumcheck_rounds_4,
        }
    }

    fn from_source(source: &'a Symbt3N8K6aSemanticSourceV1) -> Self {
        Self {
            verifier_claims: &source.verifier_claims,
            final_residuals: &source.final_residuals,
            z_eval: source.z_eval,
            product_sumcheck_rounds: &source.product_sumcheck_rounds,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_real_integrated_k6a_native_evaluator_v1_from_material(
    plan: &IntegratedK6aNativeClaimPlanV1,
    committed_table: &IntegratedK6aNativeCommittedTableV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_material: N8K6aEvaluatorRowMaterial<'_>,
    k6a_semantic_constraints: &N8IntegratedK6aSemanticConstraintsV1,
    transition_binding_semantic_constraints: &N8IntegratedTransitionBindingSemanticConstraintsV1,
) -> Result<RealIntegratedK6aNativeEvaluatorV1, Symbt3N8IntegratedPrototypeBlocker> {
    // The claim-plan and transition builders enforce the source digest binding.
    // The evaluator only materializes the accepted K6a row values into the
    // integrated table.
    let tuple_proof = &native_tuple_leaf.proof;
    let logical_oracle_count = tuple_proof.logical_descriptors.len();
    if logical_oracle_count == 0
        || tuple_proof.packed_eval_claims.len() < plan.rlc_repetition_count
        || tuple_proof.logical_eval_claims.len()
            < logical_oracle_count.saturating_mul(plan.rlc_repetition_count)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    }

    let mut rows = Vec::new();
    let mut k6a_claim_rows = 0usize;
    let mut k6a_semantic_rows = 0usize;
    let mut tuple_claim_rows = 0usize;
    let mut padding_rows = 0usize;

    for (index, &value) in k6a_material.verifier_claims.iter().enumerate() {
        let integrated_row = index % plan.integrated_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
            source_index: index,
            integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: native_oracle_point_digest(&point),
            value,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1,
                |bytes| {
                    push_digest(bytes, &adapter.main_symbt3_proof_digest);
                    push_u64(bytes, index as u64);
                    push_babybear(bytes, value);
                },
            ),
        });
        k6a_claim_rows += 1;
    }

    for (index, &value) in k6a_material.final_residuals.iter().enumerate() {
        let source_index = k6a_claim_rows;
        let integrated_row = source_index % plan.integrated_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorResidualClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
            source_index,
            integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: native_oracle_point_digest(&point),
            value,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorResidualClaimV1,
                |bytes| {
                    push_digest(bytes, &adapter.main_symbt3_proof_digest);
                    push_u64(bytes, index as u64);
                    push_babybear(bytes, value);
                },
            ),
        });
        k6a_claim_rows += 1;
    }

    let z_source_index = k6a_claim_rows;
    let z_integrated_row = z_source_index % plan.integrated_oracle_len;
    let z_point = n8_integrated_boolean_point_for_row(z_integrated_row, plan.integrated_num_vars);
    rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
        kind: RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorZEvalClaimV1,
        logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
        source_index: z_source_index,
        integrated_row: z_integrated_row,
        repetition_index: None,
        oracle_id: None,
        point_digest: native_oracle_point_digest(&z_point),
        value: k6a_material.z_eval,
        aux_digest: n8_integrated_row_aux_digest(
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorZEvalClaimV1,
            |bytes| {
                push_digest(bytes, &adapter.main_symbt3_proof_digest);
                push_babybear(bytes, k6a_material.z_eval);
            },
        ),
    });
    k6a_claim_rows += 1;

    for (round_index, round) in k6a_material.product_sumcheck_rounds.iter().enumerate() {
        for (coeff_index, &value) in round.iter().enumerate() {
            let source_index = k6a_claim_rows;
            let integrated_row = source_index % plan.integrated_oracle_len;
            let point =
                n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
            rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
                kind: RealIntegratedK6aNativeEvaluatorRowKindV1::K6aProductSumcheckRoundClaimV1,
                logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
                source_index,
                integrated_row,
                repetition_index: None,
                oracle_id: None,
                point_digest: native_oracle_point_digest(&point),
                value,
                aux_digest: n8_integrated_row_aux_digest(
                    RealIntegratedK6aNativeEvaluatorRowKindV1::K6aProductSumcheckRoundClaimV1,
                    |bytes| {
                        push_digest(bytes, &adapter.main_symbt3_proof_digest);
                        push_u64(bytes, round_index as u64);
                        push_u64(bytes, coeff_index as u64);
                        push_babybear(bytes, value);
                    },
                ),
            });
            k6a_claim_rows += 1;
        }
    }

    if plan.k6a_padding_policy.padded_row_count > 0 {
        let integrated_row = plan.k6a_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
            source_index: 0,
            integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: native_oracle_point_digest(&point),
            value: BabyBear::ZERO,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1,
                |bytes| {
                    push_bytes(bytes, &plan.k6a_padding_policy.canonical_bytes());
                    push_u64(bytes, 0);
                },
            ),
        });
        padding_rows += 1;
    }

    if k6a_semantic_constraints.complete {
        for semantic_row in &k6a_semantic_constraints.rows {
            rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
                kind: n8_integrated_k6a_semantic_to_evaluator_row_kind(semantic_row.kind),
                logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
                source_index: semantic_row.source_index,
                integrated_row: semantic_row.integrated_row,
                repetition_index: None,
                oracle_id: None,
                point_digest: semantic_row.point_digest,
                value: semantic_row.value,
                aux_digest: semantic_row.aux_digest,
            });
            k6a_semantic_rows += 1;
        }
    }

    for (repetition_index, packed_claim) in tuple_proof.packed_eval_claims.iter().enumerate() {
        let integrated_row =
            n8_integrated_tuple_row(&plan.tuple_repetition_axis, repetition_index, 0)
                .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafPacked,
            source_index: repetition_index,
            integrated_row,
            repetition_index: Some(repetition_index),
            oracle_id: None,
            point_digest: native_oracle_point_digest(&point),
            value: packed_claim.value,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1,
                |bytes| {
                    push_digest(bytes, &packed_claim.point_digest);
                    push_babybear(bytes, packed_claim.value);
                    encode_claim_kind(bytes, packed_claim.claim_kind);
                },
            ),
        });
        tuple_claim_rows += 1;
    }

    for (index, logical_claim) in tuple_proof.logical_eval_claims.iter().enumerate() {
        let repetition_index = index / logical_oracle_count;
        let oracle_offset = index % logical_oracle_count;
        let integrated_row =
            n8_integrated_tuple_row(&plan.tuple_repetition_axis, repetition_index, oracle_offset)
                .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafLogical,
            source_index: index,
            integrated_row,
            repetition_index: Some(repetition_index),
            oracle_id: Some(logical_claim.oracle_id),
            point_digest: native_oracle_point_digest(&point),
            value: logical_claim.value,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
                |bytes| {
                    push_digest(bytes, &logical_claim.point_digest);
                    push_u32(bytes, logical_claim.oracle_id);
                    push_babybear(bytes, logical_claim.value);
                    encode_claim_kind(bytes, logical_claim.claim_kind);
                },
            ),
        });
        tuple_claim_rows += 1;
    }

    let Some(repeated_packing_challenges) = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        tuple_proof.mode,
        tuple_proof.proof_relation_id,
        tuple_proof.public_statement_digest,
        tuple_proof.whir_param_digest,
        tuple_proof.descriptor_digest,
        tuple_proof.tuple_leaf_layout_digest,
        logical_oracle_count,
        plan.tuple_logical_num_vars,
        plan.rlc_repetition_count,
    ) else {
        return Err(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    };
    for (repetition_index, challenges) in repeated_packing_challenges.iter().enumerate() {
        let start = repetition_index.saturating_mul(logical_oracle_count);
        let end = start.saturating_add(logical_oracle_count);
        let logical_values = tuple_proof.logical_eval_claims[start..end]
            .iter()
            .map(|claim| claim.value)
            .collect::<Vec<_>>();
        let packed_value = symbt3_tuple_leaf_pack_values(challenges, &logical_values)
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak)?;
        let residual = tuple_proof.packed_eval_claims[repetition_index].value - packed_value;
        let integrated_row = n8_integrated_tuple_row(
            &plan.tuple_repetition_axis,
            repetition_index,
            logical_oracle_count,
        )
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)?;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafLogical,
            source_index: repetition_index,
            integrated_row,
            repetition_index: Some(repetition_index),
            oracle_id: None,
            point_digest: native_oracle_point_digest(&point),
            value: residual,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
                |bytes| {
                    push_u64(bytes, repetition_index as u64);
                    push_babybear_vec(bytes, challenges);
                    push_babybear(
                        bytes,
                        tuple_proof.packed_eval_claims[repetition_index].value,
                    );
                    push_babybear(bytes, packed_value);
                },
            ),
        });
        tuple_claim_rows += 1;
    }

    let tuple_padding_rows = plan
        .integrated_oracle_len
        .checked_sub(plan.tuple_packed_oracle_len)
        .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    if tuple_padding_rows > 0 {
        let integrated_row = plan.tuple_packed_oracle_len;
        let point = n8_integrated_boolean_point_for_row(integrated_row, plan.integrated_num_vars);
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind:
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafPacked,
            source_index: 0,
            integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: native_oracle_point_digest(&point),
            value: BabyBear::ZERO,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1,
                |bytes| {
                    push_bytes(bytes, &plan.tuple_repetition_axis.canonical_bytes());
                    push_u64(bytes, 0);
                },
            ),
        });
        padding_rows += 1;
    }

    let transition_binding_rows = if transition_binding_semantic_constraints.complete {
        for semantic_row in &transition_binding_semantic_constraints.rows {
            rows.push(n8_integrated_transition_semantic_to_evaluator_row(
                semantic_row,
            ));
        }
        transition_binding_semantic_constraints.rows.len()
    } else {
        let transition_integrated_row = plan.integrated_oracle_len.saturating_sub(1);
        let transition_point = n8_integrated_boolean_point_for_row(
            transition_integrated_row,
            plan.integrated_num_vars,
        );
        let transition_digest =
            n8_integrated_whir_accumulator_transition_binding_claim_bridge_digest_from_parts(
                adapter.main_symbt3_relation_id,
                adapter.public_statement_digest,
                adapter.whir_param_digest,
                plan.claim_plan_digest,
                committed_table.layout_digest,
                committed_table.table_digest,
                adapter.old_accumulator_digest,
                adapter.new_accumulator_digest,
                adapter.batch_manifest_root,
                tuple_proof.packed_root,
                native_tuple_leaf.native_message_roots_digest,
            );
        let transition_value = BabyBear::from_u32(u32::from_le_bytes(
            transition_digest[..4]
                .try_into()
                .expect("digest prefix is four bytes"),
        ));
        rows.push(RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::AccumulatorTransitionBinding,
            source_index: 0,
            integrated_row: transition_integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: native_oracle_point_digest(&transition_point),
            value: transition_value,
            aux_digest: n8_integrated_row_aux_digest(
                RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
                |bytes| {
                    push_digest(bytes, &adapter.old_accumulator_digest);
                    push_digest(bytes, &adapter.new_accumulator_digest);
                    push_digest(bytes, &adapter.batch_manifest_root);
                    push_digest(bytes, &native_tuple_leaf.proof.packed_root);
                    push_digest(bytes, &native_tuple_leaf.native_message_roots_digest);
                },
            ),
        });
        1
    };
    let counters = RealIntegratedK6aNativeEvaluatorCountersV1 {
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        k6a_claim_rows,
        k6a_semantic_rows,
        tuple_claim_rows,
        padding_rows,
        transition_binding_rows,
    };
    let mut evaluator = RealIntegratedK6aNativeEvaluatorV1 {
        version: REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_VERSION,
        plan_digest: plan.claim_plan_digest,
        committed_table_layout_digest: committed_table.layout_digest,
        committed_table_digest: committed_table.table_digest,
        integrated_num_vars: plan.integrated_num_vars,
        integrated_oracle_len: plan.integrated_oracle_len,
        rows,
        counters,
        rows_digest: [0u8; 32],
        table_digest: [0u8; 32],
        evaluator_digest: [0u8; 32],
    };
    evaluator.rows_digest = n8_integrated_evaluator_rows_digest(&evaluator.rows);
    evaluator.table_digest = n8_integrated_evaluator_table_digest(&evaluator)?;
    evaluator.evaluator_digest = n8_integrated_evaluator_digest(&evaluator);
    Ok(evaluator)
}

#[allow(clippy::too_many_arguments)]
fn build_real_integrated_k6a_native_evaluator_v1(
    plan: &IntegratedK6aNativeClaimPlanV1,
    committed_table: &IntegratedK6aNativeCommittedTableV1,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
    k6a_semantic_constraints: &N8IntegratedK6aSemanticConstraintsV1,
    transition_binding_semantic_constraints: &N8IntegratedTransitionBindingSemanticConstraintsV1,
) -> Result<RealIntegratedK6aNativeEvaluatorV1, Symbt3N8IntegratedPrototypeBlocker> {
    build_real_integrated_k6a_native_evaluator_v1_from_material(
        plan,
        committed_table,
        adapter,
        native_tuple_leaf,
        N8K6aEvaluatorRowMaterial::from_proof(k6a_proof),
        k6a_semantic_constraints,
        transition_binding_semantic_constraints,
    )
}

pub fn build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
) -> Result<Symbt3IntegratedK6aNativeWhirRelationV1, Symbt3N8IntegratedPrototypeBlocker> {
    let plan = build_integrated_k6a_native_claim_plan_v1(adapter, native_tuple_leaf, k6a_proof)?;
    let committed_table = build_integrated_k6a_native_committed_table_v1(&plan)?;
    let k6a_semantic_constraints =
        build_incomplete_n8_integrated_k6a_semantic_constraints_v1(&plan, adapter, k6a_proof);
    let tuple_rlc_semantic_constraints =
        build_incomplete_n8_integrated_tuple_rlc_semantic_constraints_v1(&plan, native_tuple_leaf);
    let transition_binding_semantic_constraints =
        build_incomplete_n8_integrated_transition_binding_semantic_constraints_v1(
            &plan,
            &committed_table,
            adapter,
            native_tuple_leaf,
            &tuple_rlc_semantic_constraints,
        );
    let semantic_completion = N8IntegratedSemanticCompletionFlagsV1::none_complete();
    let real_evaluator = build_real_integrated_k6a_native_evaluator_v1(
        &plan,
        &committed_table,
        adapter,
        native_tuple_leaf,
        k6a_proof,
        &k6a_semantic_constraints,
        &transition_binding_semantic_constraints,
    )?;
    let proof = &native_tuple_leaf.proof;
    let mut descriptor = Symbt3IntegratedK6aNativeWhirRelationV1 {
        version: SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        main_symbt3_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        same_field: proof.counters.same_field,
        same_rate: proof.counters.same_rate,
        same_folding_parameter: proof.counters.same_folding_parameter,
        claim_plan: plan,
        committed_table,
        k6a_semantic_constraints,
        tuple_rlc_semantic_constraints,
        transition_binding_semantic_constraints,
        semantic_completion,
        real_evaluator,
        transcript_binding_digest: [0u8; 32],
    };
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);
    Ok(descriptor)
}

#[allow(clippy::too_many_arguments)]
pub fn build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
) -> Result<Symbt3IntegratedK6aNativeWhirRelationV1, Symbt3N8IntegratedPrototypeBlocker> {
    build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics_profiled(
        seed,
        relation,
        statement,
        adapter,
        native_tuple_leaf,
        k6a_proof,
    )
    .map(|(descriptor, _profile)| descriptor)
}

#[allow(clippy::too_many_arguments)]
pub fn build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics_profiled(
    seed: &[u8; 32],
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    k6a_proof: &WhirProof,
) -> Result<
    (
        Symbt3IntegratedK6aNativeWhirRelationV1,
        N8IntegratedDescriptorBuildProfileV1,
    ),
    Symbt3N8IntegratedPrototypeBlocker,
> {
    let total_start = Instant::now();
    let mut profile = N8IntegratedDescriptorBuildProfileV1::default();

    let section_start = Instant::now();
    let k6a_semantic_descriptor_digest = n8_integrated_complete_k6a_semantic_descriptor_digest(
        seed, relation, statement, adapter, k6a_proof,
    )?;
    profile.k6a_semantic_descriptor_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let plan = build_integrated_k6a_native_claim_plan_v1_with_k6a_semantic_descriptor_digest(
        adapter,
        native_tuple_leaf,
        k6a_proof,
        k6a_semantic_descriptor_digest,
    )?;
    profile.claim_plan_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let committed_table = build_integrated_k6a_native_committed_table_v1(&plan)?;
    profile.integrated_table_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let k6a_semantic_constraints = build_n8_integrated_k6a_semantic_constraints_v1(
        seed, relation, statement, &plan, adapter, k6a_proof,
    )?;
    profile.k6a_semantic_rows_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let tuple_rlc_semantic_constraints =
        build_n8_integrated_tuple_rlc_semantic_constraints_v1(&plan, native_tuple_leaf)?;
    profile.tuple_rlc_semantic_rows_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let transition_binding_semantic_constraints =
        build_n8_integrated_transition_binding_semantic_constraints_v1(
            &plan,
            &committed_table,
            adapter,
            native_tuple_leaf,
            k6a_proof,
            &tuple_rlc_semantic_constraints,
        )?;
    profile.transition_binding_semantic_rows_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    profile.semantic_row_construction_ms = profile.k6a_semantic_rows_ms.max(0.0)
        + profile.tuple_rlc_semantic_rows_ms.max(0.0)
        + profile.transition_binding_semantic_rows_ms.max(0.0);
    let semantic_completion = N8IntegratedSemanticCompletionFlagsV1 {
        version: N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION,
        k6a_semantics_complete: true,
        tuple_rlc_semantics_complete: true,
        transition_semantics_complete: true,
    };

    let section_start = Instant::now();
    let real_evaluator = build_real_integrated_k6a_native_evaluator_v1(
        &plan,
        &committed_table,
        adapter,
        native_tuple_leaf,
        k6a_proof,
        &k6a_semantic_constraints,
        &transition_binding_semantic_constraints,
    )?;
    profile.real_evaluator_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    let proof = &native_tuple_leaf.proof;
    let mut descriptor = Symbt3IntegratedK6aNativeWhirRelationV1 {
        version: SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        main_symbt3_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        same_field: proof.counters.same_field,
        same_rate: proof.counters.same_rate,
        same_folding_parameter: proof.counters.same_folding_parameter,
        claim_plan: plan,
        committed_table,
        k6a_semantic_constraints,
        tuple_rlc_semantic_constraints,
        transition_binding_semantic_constraints,
        semantic_completion,
        real_evaluator,
        transcript_binding_digest: [0u8; 32],
    };
    let section_start = Instant::now();
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);
    profile.descriptor_digest_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    profile.total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;
    Ok((descriptor, profile))
}

pub fn build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs(
    inputs: &N8DirectSemanticInputsV1,
) -> Result<Symbt3IntegratedK6aNativeWhirRelationV1, Symbt3N8IntegratedPrototypeBlocker> {
    build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs_profiled(
        inputs,
    )
    .map(|(descriptor, _profile)| descriptor)
}

pub fn build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs_profiled(
    inputs: &N8DirectSemanticInputsV1,
) -> Result<
    (
        Symbt3IntegratedK6aNativeWhirRelationV1,
        N8IntegratedDescriptorBuildProfileV1,
    ),
    Symbt3N8IntegratedPrototypeBlocker,
> {
    let total_start = Instant::now();
    let mut profile = N8IntegratedDescriptorBuildProfileV1::default();
    let adapter = &inputs.k6a_adapter;
    let native_tuple_leaf = &inputs.native_tuple_leaf;
    let source = &inputs.k6a_semantic_source;

    let section_start = Instant::now();
    let points_digest = n8_integrated_k6a_verifier_points_digest(&source.verifier_points);
    let claims_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
        &source.verifier_claims,
    );
    let final_residual_digest = digest_babybear_slice(
        b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
        &source.final_residuals,
    );
    let product_sumcheck_digest =
        n8_integrated_k6a_product_sumcheck_digest(&source.product_sumcheck_rounds);
    let k6a_semantic_descriptor_digest =
        n8_integrated_complete_k6a_semantic_descriptor_digest_from_source(
            adapter,
            source,
            points_digest,
            claims_digest,
            final_residual_digest,
            product_sumcheck_digest,
            source.verifier_points.len(),
            source.verifier_claims.len(),
        );
    profile.k6a_semantic_descriptor_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let plan = build_integrated_k6a_native_claim_plan_v1_with_k6a_semantic_source(
        adapter,
        native_tuple_leaf,
        source,
        k6a_semantic_descriptor_digest,
    )?;
    profile.claim_plan_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let committed_table = build_integrated_k6a_native_committed_table_v1(&plan)?;
    profile.integrated_table_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let k6a_semantic_constraints =
        build_n8_integrated_k6a_semantic_constraints_v1_from_source(&plan, adapter, source)?;
    profile.k6a_semantic_rows_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let tuple_rlc_semantic_constraints =
        build_n8_integrated_tuple_rlc_semantic_constraints_v1(&plan, native_tuple_leaf)?;
    profile.tuple_rlc_semantic_rows_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let transition_binding_semantic_constraints =
        build_n8_integrated_transition_binding_semantic_constraints_v1_from_source(
            &plan,
            &committed_table,
            adapter,
            native_tuple_leaf,
            source,
            &tuple_rlc_semantic_constraints,
        )?;
    profile.transition_binding_semantic_rows_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    profile.semantic_row_construction_ms = profile.k6a_semantic_rows_ms.max(0.0)
        + profile.tuple_rlc_semantic_rows_ms.max(0.0)
        + profile.transition_binding_semantic_rows_ms.max(0.0);
    let semantic_completion = N8IntegratedSemanticCompletionFlagsV1 {
        version: N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION,
        k6a_semantics_complete: true,
        tuple_rlc_semantics_complete: true,
        transition_semantics_complete: true,
    };

    let section_start = Instant::now();
    let real_evaluator = build_real_integrated_k6a_native_evaluator_v1_from_material(
        &plan,
        &committed_table,
        adapter,
        native_tuple_leaf,
        N8K6aEvaluatorRowMaterial::from_source(source),
        &k6a_semantic_constraints,
        &transition_binding_semantic_constraints,
    )?;
    profile.real_evaluator_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    let proof = &native_tuple_leaf.proof;
    let mut descriptor = Symbt3IntegratedK6aNativeWhirRelationV1 {
        version: SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        main_symbt3_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        tuple_leaf_descriptor_digest: proof.descriptor_digest,
        tuple_leaf_layout_digest: proof.tuple_leaf_layout_digest,
        same_field: proof.counters.same_field,
        same_rate: proof.counters.same_rate,
        same_folding_parameter: proof.counters.same_folding_parameter,
        claim_plan: plan,
        committed_table,
        k6a_semantic_constraints,
        tuple_rlc_semantic_constraints,
        transition_binding_semantic_constraints,
        semantic_completion,
        real_evaluator,
        transcript_binding_digest: [0u8; 32],
    };
    let section_start = Instant::now();
    descriptor.transcript_binding_digest =
        symbt3_n8_integrated_transcript_binding_digest(&descriptor);
    profile.descriptor_digest_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    profile.total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;
    Ok((descriptor, profile))
}

fn symbt3_n8_integrated_claim_plan_consistency_blocker(
    plan: &IntegratedK6aNativeClaimPlanV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    if plan.version != INTEGRATED_K6A_NATIVE_CLAIM_PLAN_VERSION
        || plan.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if plan.k6a_semantic_descriptor_digest == [0u8; 32] {
        return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }
    if plan.combined_logical_oracle_descriptor_digest
        != symbt3_n8_integrated_logical_oracle_descriptors_digest(&plan.logical_oracle_descriptors)
        || plan.combined_constraint_descriptor_digest
            != symbt3_n8_integrated_constraint_descriptors_digest(&plan.constraint_descriptors)
        || plan.combined_claim_descriptor_digest
            != symbt3_n8_integrated_claim_descriptors_digest(&plan.claim_descriptors)
        || plan.claim_plan_digest != symbt3_n8_integrated_claim_plan_digest(plan)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ClaimPlanDigestMismatch);
    }
    let Some(k6a_oracle_len) = symbt3_n8_oracle_len(plan.k6a_num_vars) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    };
    let Some(tuple_packed_oracle_len) = symbt3_n8_oracle_len(plan.tuple_packed_num_vars) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    };
    let Some(integrated_oracle_len) = symbt3_n8_oracle_len(plan.integrated_num_vars) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    };
    if k6a_oracle_len != plan.k6a_oracle_len
        || tuple_packed_oracle_len != plan.tuple_packed_oracle_len
        || integrated_oracle_len != plan.integrated_oracle_len
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    }
    let Some(expected_repetition_axis) = symbt3_n8_tuple_repetition_axis_mapping(
        plan.tuple_logical_num_vars,
        plan.rlc_repetition_count,
        plan.integrated_num_vars,
    ) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
    };
    let expected_tuple_packed_num_vars = expected_repetition_axis.packed_num_vars;
    if plan.tuple_packed_num_vars != expected_tuple_packed_num_vars {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
    }
    let expected_integrated_num_vars = plan.k6a_num_vars.max(plan.tuple_packed_num_vars);
    if plan.integrated_num_vars != expected_integrated_num_vars {
        return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch);
    }
    let Some(expected_padding_policy) =
        symbt3_n8_k6a_padding_policy(plan.k6a_num_vars, plan.integrated_num_vars)
    else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch);
    };
    if plan.k6a_padding_policy != expected_padding_policy {
        return Some(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch);
    }
    if plan.tuple_repetition_axis != expected_repetition_axis {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
    }
    if plan.constraint_descriptors.len() != 3
        || plan.constraint_descriptors[0].kind
            != Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1
        || plan.constraint_descriptors[1].kind
            != Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1
        || plan.constraint_descriptors[2].kind
            != Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1
        || plan.constraint_descriptors.iter().any(|descriptor| {
            descriptor.integrated_num_vars != plan.integrated_num_vars
                || descriptor.integrated_oracle_len != plan.integrated_oracle_len
        })
        || plan.constraint_descriptors[0].num_vars != plan.k6a_num_vars
        || plan.constraint_descriptors[0].oracle_len != plan.k6a_oracle_len
        || plan.constraint_descriptors[1].num_vars != plan.tuple_packed_num_vars
        || plan.constraint_descriptors[1].oracle_len != plan.tuple_packed_oracle_len
        || plan.constraint_descriptors[2].num_vars != plan.integrated_num_vars
        || plan.constraint_descriptors[2].oracle_len != plan.integrated_oracle_len
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if plan.logical_oracle_descriptors.len() < 2 + plan.tuple_logical_oracle_count
        || plan.logical_oracle_descriptors[0].kind
            != IntegratedK6aNativeLogicalOracleKindV1::K6aAccumulatorMainV1
        || plan.logical_oracle_descriptors[1].kind
            != IntegratedK6aNativeLogicalOracleKindV1::NativeTupleLeafPackedV1
        || plan.logical_oracle_descriptors[0].layout_digest != plan.k6a_relation_id
        || plan.logical_oracle_descriptors[1].layout_digest != plan.tuple_leaf_layout_digest
        || plan.logical_oracle_descriptors.iter().any(|descriptor| {
            descriptor.integrated_num_vars != plan.integrated_num_vars
                || descriptor.source_num_vars > plan.integrated_num_vars
        })
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if plan.claim_descriptors.len() != 3
        || plan.claim_descriptors[0].kind
            != IntegratedK6aNativeClaimDescriptorKindV1::K6aAccumulatorMainClaimsV1
        || plan.claim_descriptors[1].kind
            != IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafPackedClaimsV1
        || plan.claim_descriptors[2].kind
            != IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafLogicalClaimsV1
        || plan.claim_descriptors[0].num_vars != plan.k6a_num_vars
        || plan.claim_descriptors[1].num_vars != plan.tuple_packed_num_vars
        || plan.claim_descriptors[2].num_vars != plan.tuple_logical_num_vars
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if plan.rlc_batching_bits_per_repetition == 0
        || plan.total_rlc_batching_bits
            != plan
                .rlc_repetition_count
                .saturating_mul(plan.rlc_batching_bits_per_repetition)
        || plan.rlc_repetition_count < SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        || plan.total_rlc_batching_bits
            < SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS
        || plan.effective_soundness_bits
            < SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    }
    None
}

fn symbt3_n8_integrated_committed_table_consistency_blocker(
    plan: &IntegratedK6aNativeClaimPlanV1,
    table: &IntegratedK6aNativeCommittedTableV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    if table.version != INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_VERSION
        || table.workload_kind != plan.workload_kind
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if table.plan_digest != plan.claim_plan_digest {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch);
    }
    if table.integrated_num_vars != plan.integrated_num_vars {
        return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch);
    }
    if table.integrated_oracle_len != plan.integrated_oracle_len {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    }
    if table.k6a_padding_policy != plan.k6a_padding_policy {
        return Some(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch);
    }
    if table.tuple_repetition_axis != plan.tuple_repetition_axis {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
    }
    if table.logical_integrated_oracle_count != 1 || table.one_oracle_per_batch_item_layout {
        return Some(Symbt3N8IntegratedPrototypeBlocker::OneOraclePerBatchItemLayout);
    }
    if table.introduced_whir_root_count != 0 || table.introduced_whir_proof_count != 0 {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot);
    }
    if table.counters.integrated_num_vars != plan.integrated_num_vars
        || table.counters.integrated_oracle_len != plan.integrated_oracle_len
        || table.counters.k6a_padded_rows != plan.k6a_padding_policy.padded_row_count
        || table.counters.tuple_rows != plan.tuple_packed_oracle_len
        || table.counters.combined_constraint_count != plan.constraint_descriptors.len()
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch);
    }
    if table.layout_digest != symbt3_n8_integrated_committed_table_layout_digest(table)
        || table.table_digest != symbt3_n8_integrated_committed_table_digest(table)
        || table.counters.layout_digest != table.layout_digest
        || table.counters.table_digest != table.table_digest
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableDigestMismatch);
    }
    let Ok(expected_table) = build_integrated_k6a_native_committed_table_v1(plan) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch);
    };
    if table != &expected_table {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch);
    }
    None
}

fn symbt3_n8_real_evaluator_consistency_blocker(
    plan: &IntegratedK6aNativeClaimPlanV1,
    table: &IntegratedK6aNativeCommittedTableV1,
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    if evaluator.version != REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_VERSION
        || evaluator.plan_digest != plan.claim_plan_digest
        || evaluator.committed_table_layout_digest != table.layout_digest
        || evaluator.committed_table_digest != table.table_digest
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if evaluator.integrated_num_vars != plan.integrated_num_vars
        || evaluator.integrated_oracle_len != plan.integrated_oracle_len
        || evaluator.counters.integrated_num_vars != plan.integrated_num_vars
        || evaluator.counters.integrated_oracle_len != plan.integrated_oracle_len
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch);
    }
    if evaluator.rows.is_empty()
        || evaluator.counters.k6a_claim_rows == 0
        || evaluator.counters.tuple_claim_rows == 0
        || evaluator.counters.transition_binding_rows == 0
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CombinedConstraintEvaluatorMissing);
    }
    let mut k6a_rows = 0usize;
    let mut k6a_semantic_rows = 0usize;
    let mut tuple_rows = 0usize;
    let mut padding_rows = 0usize;
    let mut transition_rows = 0usize;
    for row in &evaluator.rows {
        if row.integrated_row >= evaluator.integrated_oracle_len
            || row.point_digest
                != native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                    row.integrated_row,
                    evaluator.integrated_num_vars,
                ))
        {
            return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
        }
        match row.kind {
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorResidualClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorZEvalClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aProductSumcheckRoundClaimV1 => {
                k6a_rows += 1
            }
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticVerifierOpeningClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticZEvalBindingV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticProductSumcheckAcceptedV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticPaddingZeroV1 => {
                k6a_semantic_rows += 1
            }
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1 => {
                padding_rows += 1
            }
            RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1
            | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1 => {
                tuple_rows += 1
            }
            RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1 => {
                transition_rows += 1
            }
        }
    }
    if evaluator.counters.k6a_claim_rows != k6a_rows
        || evaluator.counters.k6a_semantic_rows != k6a_semantic_rows
        || evaluator.counters.tuple_claim_rows != tuple_rows
        || evaluator.counters.padding_rows != padding_rows
        || evaluator.counters.transition_binding_rows != transition_rows
        || evaluator.rows_digest != n8_integrated_evaluator_rows_digest(&evaluator.rows)
        || evaluator.evaluator_digest != n8_integrated_evaluator_digest(evaluator)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::ClaimPlanDigestMismatch);
    }
    let Ok(table_digest) = n8_integrated_evaluator_table_digest(evaluator) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableDigestMismatch);
    };
    if evaluator.table_digest != table_digest {
        return Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableDigestMismatch);
    }
    None
}

fn symbt3_n8_k6a_semantic_constraints_consistency_blocker(
    plan: &IntegratedK6aNativeClaimPlanV1,
    constraints: &N8IntegratedK6aSemanticConstraintsV1,
    semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    if constraints.version != N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_VERSION
        || semantic_completion.version != N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION
        || constraints.k6a_relation_id != plan.k6a_relation_id
        || constraints.public_statement_digest != plan.k6a_public_statement_digest
        || constraints.k6a_num_vars != plan.k6a_num_vars
        || constraints.k6a_oracle_len != plan.k6a_oracle_len
        || constraints.integrated_num_vars != plan.integrated_num_vars
        || constraints.integrated_oracle_len != plan.integrated_oracle_len
        || constraints.descriptor_digest != plan.k6a_semantic_descriptor_digest
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }
    let k6a_semantics_complete = constraints.complete && !constraints.rows.is_empty();
    if semantic_completion.k6a_semantics_complete != k6a_semantics_complete {
        return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete);
    }
    if constraints.rows_digest != n8_integrated_k6a_semantic_rows_digest(&constraints.rows) {
        return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }
    if !constraints.complete {
        if !constraints.rows.is_empty() || evaluator.counters.k6a_semantic_rows != 0 {
            return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
        }
        return None;
    }
    if constraints.rows.is_empty()
        || constraints.verifier_point_count == 0
        || constraints.verifier_claim_count == 0
        || constraints.final_residual_count != 3
        || constraints.product_sumcheck_round_count == 0
        || constraints.verifier_points_digest == [0u8; 32]
        || constraints.verifier_claims_digest == [0u8; 32]
        || constraints.final_residual_digest == [0u8; 32]
        || constraints.product_sumcheck_digest == [0u8; 32]
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }

    let mut opening_rows = 0usize;
    let mut final_residual_rows = 0usize;
    let mut z_binding_rows = 0usize;
    let mut product_rows = 0usize;
    let mut padding_rows = 0usize;
    let mut verifier_claim_values = Vec::with_capacity(constraints.verifier_claim_count);
    let mut final_residual_values = Vec::with_capacity(constraints.final_residual_count);
    for row in &constraints.rows {
        if row.integrated_row >= constraints.integrated_oracle_len
            || row.point_digest
                != native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                    row.integrated_row,
                    constraints.integrated_num_vars,
                ))
        {
            return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
        }
        match row.kind {
            N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1 => {
                opening_rows += 1;
                verifier_claim_values.push(row.value);
            }
            N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1 => {
                final_residual_rows += 1;
                final_residual_values.push(row.value);
                if row.value != BabyBear::ZERO {
                    return Some(
                        Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation,
                    );
                }
            }
            N8IntegratedK6aSemanticConstraintRowKindV1::ZEvalBindingV1 => {
                z_binding_rows += 1;
                if row.value != BabyBear::ZERO {
                    return Some(
                        Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation,
                    );
                }
            }
            N8IntegratedK6aSemanticConstraintRowKindV1::ProductSumcheckAcceptedV1 => {
                product_rows += 1;
                if row.value != BabyBear::ZERO {
                    return Some(
                        Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation,
                    );
                }
            }
            N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1 => {
                padding_rows += 1;
                if row.value != BabyBear::ZERO {
                    return Some(
                        Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation,
                    );
                }
            }
        }
    }
    if opening_rows != constraints.verifier_claim_count
        || final_residual_rows != constraints.final_residual_count
        || z_binding_rows != 2
        || product_rows != 1
        || padding_rows != constraints.padding_row_count
        || padding_rows != usize::from(plan.k6a_padding_policy.padded_row_count > 0)
        || constraints.verifier_claims_digest
            != digest_babybear_slice(
                b"N8_INTEGRATED_K6A_VERIFIER_CLAIMS_DIGEST_V1",
                &verifier_claim_values,
            )
        || constraints.final_residual_digest
            != digest_babybear_slice(
                b"N8_INTEGRATED_K6A_FINAL_RESIDUAL_DIGEST_V1",
                &final_residual_values,
            )
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }
    let expected_evaluator_rows = constraints
        .rows
        .iter()
        .map(|row| RealIntegratedK6aNativeEvaluatorRowV1 {
            kind: n8_integrated_k6a_semantic_to_evaluator_row_kind(row.kind),
            logical_column: RealIntegratedK6aNativeLogicalColumnV1::K6aAccumulatorMain,
            source_index: row.source_index,
            integrated_row: row.integrated_row,
            repetition_index: None,
            oracle_id: None,
            point_digest: row.point_digest,
            value: row.value,
            aux_digest: row.aux_digest,
        })
        .collect::<Vec<_>>();
    let actual_evaluator_rows = evaluator
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.kind,
                RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticVerifierOpeningClaimV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticZEvalBindingV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticProductSumcheckAcceptedV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticPaddingZeroV1
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if actual_evaluator_rows != expected_evaluator_rows
        || evaluator.counters.k6a_semantic_rows != expected_evaluator_rows.len()
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation);
    }
    None
}

fn n8_integrated_tuple_rlc_semantic_to_evaluator_row(
    row: &N8IntegratedTupleRlcSemanticConstraintRowV1,
) -> RealIntegratedK6aNativeEvaluatorRowV1 {
    match row.kind {
        N8IntegratedTupleRlcSemanticConstraintRowKindV1::PackedOpeningClaimV1 => {
            RealIntegratedK6aNativeEvaluatorRowV1 {
                kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1,
                logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafPacked,
                source_index: row.source_index,
                integrated_row: row.integrated_row,
                repetition_index: row.repetition_index,
                oracle_id: None,
                point_digest: row.point_digest,
                value: row.value,
                aux_digest: row.aux_digest,
            }
        }
        N8IntegratedTupleRlcSemanticConstraintRowKindV1::LogicalOpeningClaimV1 => {
            RealIntegratedK6aNativeEvaluatorRowV1 {
                kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
                logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafLogical,
                source_index: row.source_index,
                integrated_row: row.integrated_row,
                repetition_index: row.repetition_index,
                oracle_id: row.oracle_id,
                point_digest: row.point_digest,
                value: row.value,
                aux_digest: row.aux_digest,
            }
        }
        N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1 => {
            RealIntegratedK6aNativeEvaluatorRowV1 {
                kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
                logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafLogical,
                source_index: row.source_index,
                integrated_row: row.integrated_row,
                repetition_index: row.repetition_index,
                oracle_id: None,
                point_digest: row.point_digest,
                value: row.value,
                aux_digest: row.aux_digest,
            }
        }
        N8IntegratedTupleRlcSemanticConstraintRowKindV1::TuplePaddingZeroV1 => {
            RealIntegratedK6aNativeEvaluatorRowV1 {
                kind: RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1,
                logical_column: RealIntegratedK6aNativeLogicalColumnV1::NativeTupleLeafPacked,
                source_index: row.source_index,
                integrated_row: row.integrated_row,
                repetition_index: None,
                oracle_id: None,
                point_digest: row.point_digest,
                value: row.value,
                aux_digest: row.aux_digest,
            }
        }
    }
}

fn n8_integrated_transition_semantic_to_evaluator_row(
    row: &N8IntegratedTransitionBindingSemanticConstraintRowV1,
) -> RealIntegratedK6aNativeEvaluatorRowV1 {
    RealIntegratedK6aNativeEvaluatorRowV1 {
        kind: RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
        logical_column: RealIntegratedK6aNativeLogicalColumnV1::AccumulatorTransitionBinding,
        source_index: row.source_index,
        integrated_row: row.integrated_row,
        repetition_index: None,
        oracle_id: None,
        point_digest: row.point_digest,
        value: row.value,
        aux_digest: row.aux_digest,
    }
}

fn symbt3_n8_tuple_rlc_semantic_constraints_consistency_blocker(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    let plan = &descriptor.claim_plan;
    let constraints = &descriptor.tuple_rlc_semantic_constraints;
    if constraints.version != N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINTS_VERSION
        || constraints.proof_relation_id != plan.k6a_relation_id
        || constraints.public_statement_digest != plan.k6a_public_statement_digest
        || constraints.whir_param_digest != descriptor.whir_param_digest
        || constraints.tuple_leaf_descriptor_digest != plan.tuple_leaf_descriptor_digest
        || constraints.tuple_leaf_descriptor_digest != descriptor.tuple_leaf_descriptor_digest
        || constraints.tuple_leaf_layout_digest != plan.tuple_leaf_layout_digest
        || constraints.tuple_leaf_layout_digest != descriptor.tuple_leaf_layout_digest
        || constraints.logical_oracle_count != plan.tuple_logical_oracle_count
        || constraints.logical_num_vars != plan.tuple_logical_num_vars
        || constraints.packed_num_vars != plan.tuple_packed_num_vars
        || constraints.integrated_num_vars != plan.integrated_num_vars
        || constraints.integrated_oracle_len != plan.integrated_oracle_len
        || constraints.rlc_repetition_count != plan.rlc_repetition_count
        || constraints.rlc_batching_bits_per_repetition != plan.rlc_batching_bits_per_repetition
        || constraints.total_rlc_batching_bits != plan.total_rlc_batching_bits
        || constraints.effective_soundness_bits != plan.effective_soundness_bits
        || constraints.tuple_leaf_layout != SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
        || !constraints.same_domain
        || !constraints.same_field
        || !constraints.same_rate
        || !constraints.same_folding_parameter
        || !descriptor.same_field
        || !descriptor.same_rate
        || !descriptor.same_folding_parameter
        || constraints.rows_digest
            != n8_integrated_tuple_rlc_semantic_rows_digest(&constraints.rows)
        || constraints.descriptor_digest
            != n8_integrated_tuple_rlc_semantic_descriptor_digest(constraints)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    let tuple_rlc_semantics_complete = constraints.complete && !constraints.rows.is_empty();
    if descriptor.semantic_completion.tuple_rlc_semantics_complete != tuple_rlc_semantics_complete {
        return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete);
    }
    if !constraints.complete {
        if !constraints.rows.is_empty() {
            return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
        }
        return None;
    }

    if constraints.rlc_batching_bits_per_repetition == 0
        || constraints.rlc_repetition_count
            < SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        || constraints.total_rlc_batching_bits
            != constraints
                .rlc_repetition_count
                .saturating_mul(constraints.rlc_batching_bits_per_repetition)
        || constraints.total_rlc_batching_bits
            < SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS
        || constraints.effective_soundness_bits
            < SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    }

    let expected_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1,
        constraints.tuple_leaf_descriptor_digest,
        constraints.logical_oracle_count,
        constraints.logical_num_vars,
        constraints.rlc_repetition_count,
        constraints.rlc_batching_bits_per_repetition,
    );
    if expected_layout_digest != constraints.tuple_leaf_layout_digest {
        return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    let Some(repeated_packing_challenges) = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1,
        constraints.proof_relation_id,
        constraints.public_statement_digest,
        constraints.whir_param_digest,
        constraints.tuple_leaf_descriptor_digest,
        constraints.tuple_leaf_layout_digest,
        constraints.logical_oracle_count,
        constraints.logical_num_vars,
        constraints.rlc_repetition_count,
    ) else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    };
    let derived_packing_challenge_digest =
        symbt3_tuple_leaf_repeated_packing_challenge_digest(&repeated_packing_challenges);
    if constraints.derived_packing_challenge_digest != derived_packing_challenge_digest
        || constraints.packing_challenge_digest != derived_packing_challenge_digest
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    let Some(repetition_log_size) =
        symbt3_tuple_leaf_repetition_log_size(constraints.rlc_repetition_count)
    else {
        return Some(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
    };
    let expected_row_count = constraints
        .rlc_repetition_count
        .saturating_add(
            constraints
                .logical_oracle_count
                .saturating_mul(constraints.rlc_repetition_count),
        )
        .saturating_add(constraints.rlc_repetition_count)
        .saturating_add(constraints.padding_row_count);
    if constraints.rows.len() != expected_row_count
        || constraints.packed_row_count != constraints.rlc_repetition_count
        || constraints.logical_row_count
            != constraints
                .logical_oracle_count
                .saturating_mul(constraints.rlc_repetition_count)
        || constraints.residual_row_count != constraints.rlc_repetition_count
        || constraints.padding_row_count
            != usize::from(plan.integrated_oracle_len > plan.tuple_packed_oracle_len)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    let mut opening_point_digests = Vec::with_capacity(constraints.rlc_repetition_count);
    let mut residuals = Vec::with_capacity(constraints.rlc_repetition_count);
    let mut expected_packed_claims = Vec::with_capacity(constraints.rlc_repetition_count);
    let mut expected_logical_claims = Vec::with_capacity(constraints.logical_row_count);
    let logical_base = constraints.rlc_repetition_count;
    let residual_base = logical_base.saturating_add(constraints.logical_row_count);
    let expected_oracle_ids = plan
        .logical_oracle_descriptors
        .iter()
        .skip(2)
        .take(constraints.logical_oracle_count)
        .map(|descriptor| descriptor.oracle_id)
        .collect::<Vec<_>>();
    if expected_oracle_ids.len() != constraints.logical_oracle_count
        || expected_oracle_ids.iter().any(Option::is_none)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }

    for (repetition_index, packing_challenges) in repeated_packing_challenges.iter().enumerate() {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            constraints.proof_relation_id,
            constraints.public_statement_digest,
            constraints.whir_param_digest,
            constraints.tuple_leaf_descriptor_digest,
            constraints.tuple_leaf_layout_digest,
            constraints.claim_kind,
            constraints.logical_num_vars,
        );
        let logical_point_digest = native_oracle_point_digest(&point);
        let mut packed_point = point;
        packed_point.extend(tuple_leaf_boolean_point_for_index(
            repetition_index,
            repetition_log_size,
        ));
        let packed_point_digest = native_oracle_point_digest(&packed_point);
        opening_point_digests.push((logical_point_digest, packed_point_digest));

        let packed_row = &constraints.rows[repetition_index];
        let Some(expected_packed_integrated_row) =
            n8_integrated_tuple_row(&plan.tuple_repetition_axis, repetition_index, 0)
        else {
            return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
        };
        if packed_row.kind != N8IntegratedTupleRlcSemanticConstraintRowKindV1::PackedOpeningClaimV1
            || packed_row.source_index != repetition_index
            || packed_row.integrated_row != expected_packed_integrated_row
            || packed_row.repetition_index != Some(repetition_index)
            || packed_row.oracle_id.is_some()
            || packed_row.point_digest
                != native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                    expected_packed_integrated_row,
                    plan.integrated_num_vars,
                ))
            || packed_row.aux_digest
                != n8_integrated_row_aux_digest(
                    RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1,
                    |bytes| {
                        push_digest(bytes, &packed_point_digest);
                        push_babybear(bytes, packed_row.value);
                        encode_claim_kind(bytes, WhirNativeEvalClaimKind::DirectOpening);
                    },
                )
        {
            return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
        }
        expected_packed_claims.push(Symbt3TupleLeafPackedEvalClaim {
            point_digest: packed_point_digest,
            value: packed_row.value,
            claim_kind: WhirNativeEvalClaimKind::DirectOpening,
        });

        let mut logical_values = Vec::with_capacity(constraints.logical_oracle_count);
        for oracle_offset in 0..constraints.logical_oracle_count {
            let logical_index = logical_base
                + repetition_index.saturating_mul(constraints.logical_oracle_count)
                + oracle_offset;
            let logical_row = &constraints.rows[logical_index];
            let Some(expected_oracle_id) = expected_oracle_ids[oracle_offset] else {
                return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
            };
            let Some(expected_integrated_row) = n8_integrated_tuple_row(
                &plan.tuple_repetition_axis,
                repetition_index,
                oracle_offset,
            ) else {
                return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
            };
            let expected_source_index = repetition_index
                .saturating_mul(constraints.logical_oracle_count)
                .saturating_add(oracle_offset);
            if logical_row.kind
                != N8IntegratedTupleRlcSemanticConstraintRowKindV1::LogicalOpeningClaimV1
                || logical_row.source_index != expected_source_index
                || logical_row.integrated_row != expected_integrated_row
                || logical_row.repetition_index != Some(repetition_index)
                || logical_row.oracle_id != Some(expected_oracle_id)
                || logical_row.point_digest
                    != native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                        expected_integrated_row,
                        plan.integrated_num_vars,
                    ))
                || logical_row.aux_digest
                    != n8_integrated_row_aux_digest(
                        RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
                        |bytes| {
                            push_digest(bytes, &logical_point_digest);
                            push_u32(bytes, expected_oracle_id);
                            push_babybear(bytes, logical_row.value);
                            encode_claim_kind(bytes, constraints.claim_kind);
                        },
                    )
            {
                return Some(
                    Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation,
                );
            }
            logical_values.push(logical_row.value);
            expected_logical_claims.push(WhirNativeOracleEvalClaim {
                oracle_id: expected_oracle_id,
                point_digest: logical_point_digest,
                value: logical_row.value,
                claim_kind: constraints.claim_kind,
            });
        }

        let residual_row = &constraints.rows[residual_base + repetition_index];
        let Some(packed_value) = symbt3_tuple_leaf_pack_values(packing_challenges, &logical_values)
        else {
            return Some(Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak);
        };
        let expected_residual = packed_row.value - packed_value;
        residuals.push(expected_residual);
        let Some(expected_residual_integrated_row) = n8_integrated_tuple_row(
            &plan.tuple_repetition_axis,
            repetition_index,
            constraints.logical_oracle_count,
        ) else {
            return Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch);
        };
        if residual_row.kind != N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1
            || residual_row.source_index != repetition_index
            || residual_row.integrated_row != expected_residual_integrated_row
            || residual_row.repetition_index != Some(repetition_index)
            || residual_row.oracle_id.is_some()
            || residual_row.point_digest
                != native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                    expected_residual_integrated_row,
                    plan.integrated_num_vars,
                ))
            || residual_row.value != expected_residual
            || residual_row.value != BabyBear::ZERO
            || residual_row.aux_digest
                != n8_integrated_row_aux_digest(
                    RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
                    |bytes| {
                        push_u64(bytes, repetition_index as u64);
                        push_babybear_vec(bytes, packing_challenges);
                        push_babybear(bytes, packed_row.value);
                        push_babybear(bytes, packed_value);
                    },
                )
        {
            return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
        }
    }

    if constraints.opening_points_digest
        != n8_integrated_tuple_rlc_opening_points_digest(&opening_point_digests)
        || constraints.residuals_digest != n8_integrated_tuple_rlc_residuals_digest(&residuals)
        || constraints.packed_claims_digest
            != symbt3_tuple_leaf_packed_eval_claims_digest(&expected_packed_claims)
        || constraints.logical_claims_digest
            != native_oracle_eval_claims_digest(&expected_logical_claims)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }

    if constraints.padding_row_count > 0 {
        let Some(padding_row) = constraints.rows.last() else {
            return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
        };
        if padding_row.kind
            != N8IntegratedTupleRlcSemanticConstraintRowKindV1::TuplePaddingZeroV1
            || padding_row.source_index != 0
            || padding_row.integrated_row != plan.tuple_packed_oracle_len
            || padding_row.repetition_index.is_some()
            || padding_row.oracle_id.is_some()
            || padding_row.value != BabyBear::ZERO
            || padding_row.point_digest
                != native_oracle_point_digest(&n8_integrated_boolean_point_for_row(
                    plan.tuple_packed_oracle_len,
                    plan.integrated_num_vars,
                ))
            || padding_row.aux_digest
                != n8_integrated_row_aux_digest(
                    RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1,
                    |bytes| {
                        push_bytes(bytes, &plan.tuple_repetition_axis.canonical_bytes());
                        push_u64(bytes, 0);
                    },
                )
        {
            return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
        }
    }

    let expected_evaluator_rows = constraints
        .rows
        .iter()
        .map(n8_integrated_tuple_rlc_semantic_to_evaluator_row)
        .collect::<Vec<_>>();
    let actual_evaluator_rows = descriptor
        .real_evaluator
        .rows
        .iter()
        .filter(|row| {
            matches!(
                row.kind,
                RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafPackedRlcClaimV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1
                    | RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafIntegratedPaddingClaimV1
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if actual_evaluator_rows != expected_evaluator_rows
        || descriptor.real_evaluator.counters.tuple_claim_rows
            != constraints
                .packed_row_count
                .saturating_add(constraints.logical_row_count)
                .saturating_add(constraints.residual_row_count)
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation);
    }
    None
}

fn symbt3_n8_transition_binding_semantic_constraints_consistency_blocker(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    let plan = &descriptor.claim_plan;
    let table = &descriptor.committed_table;
    let constraints = &descriptor.transition_binding_semantic_constraints;
    if plan.constraint_descriptors.len() != 3 {
        return Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if constraints.version != N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_CONSTRAINTS_VERSION
        || constraints.workload_kind != descriptor.workload_kind
        || constraints.workload_kind
            != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || constraints.public_statement_digest != descriptor.public_statement_digest
        || constraints.public_statement_digest != plan.k6a_public_statement_digest
        || constraints.whir_param_digest != descriptor.whir_param_digest
        || constraints.main_symbt3_relation_id != descriptor.main_symbt3_relation_id
        || constraints.main_symbt3_relation_id != plan.k6a_relation_id
        || constraints.k6a_semantic_descriptor_digest != plan.k6a_semantic_descriptor_digest
        || constraints.k6a_semantic_descriptor_digest
            != descriptor.k6a_semantic_constraints.descriptor_digest
        || constraints.tuple_rlc_semantic_descriptor_digest
            != descriptor.tuple_rlc_semantic_constraints.descriptor_digest
        || constraints.tuple_leaf_root
            != plan.logical_oracle_descriptors[1]
                .root_digest
                .unwrap_or([0u8; 32])
        || constraints.tuple_leaf_layout_digest != descriptor.tuple_leaf_layout_digest
        || constraints.tuple_leaf_layout_digest != plan.tuple_leaf_layout_digest
        || constraints.tuple_leaf_descriptor_digest != descriptor.tuple_leaf_descriptor_digest
        || constraints.tuple_leaf_descriptor_digest != plan.tuple_leaf_descriptor_digest
        || constraints.tuple_leaf_packing_challenge_digest
            != descriptor
                .tuple_rlc_semantic_constraints
                .packing_challenge_digest
        || constraints.native_message_roots_digest == [0u8; 32]
        || constraints.native_oracle_descriptor_digest == [0u8; 32]
        || constraints.manifest_oracle_root == [0u8; 32]
        || constraints.source_oracle_root == [0u8; 32]
        || constraints.batch_manifest_root == [0u8; 32]
        || constraints.k6a_proof_digest == [0u8; 32]
        || constraints.accumulator_instance_digest == [0u8; 32]
        || constraints.old_accumulator_digest == [0u8; 32]
        || constraints.new_accumulator_digest == [0u8; 32]
        || constraints.batch_size == 0
        || constraints.active_count == 0
        || constraints.active_count > constraints.batch_size
        || constraints.k6a_num_vars != plan.k6a_num_vars
        || constraints.k6a_oracle_len != plan.k6a_oracle_len
        || constraints.tuple_logical_oracle_count != plan.tuple_logical_oracle_count
        || constraints.tuple_logical_num_vars != plan.tuple_logical_num_vars
        || constraints.tuple_packed_num_vars != plan.tuple_packed_num_vars
        || constraints.tuple_packed_oracle_len != plan.tuple_packed_oracle_len
        || constraints.integrated_num_vars != plan.integrated_num_vars
        || constraints.integrated_oracle_len != plan.integrated_oracle_len
        || constraints.rlc_repetition_count != plan.rlc_repetition_count
        || constraints.rlc_batching_bits_per_repetition != plan.rlc_batching_bits_per_repetition
        || constraints.total_rlc_batching_bits != plan.total_rlc_batching_bits
        || constraints.effective_soundness_bits != plan.effective_soundness_bits
        || constraints.n8_claim_plan_digest != plan.claim_plan_digest
        || constraints.n8_committed_table_layout_digest != table.layout_digest
        || constraints.n8_committed_table_digest != table.table_digest
        || constraints.n8_combined_constraint_descriptor_digest
            != plan.combined_constraint_descriptor_digest
        || constraints.n8_combined_claim_descriptor_digest != plan.combined_claim_descriptor_digest
        || constraints.k6a_constraint_descriptor_digest
            != plan.constraint_descriptors[0].descriptor_digest
        || constraints.tuple_constraint_descriptor_digest
            != plan.constraint_descriptors[1].descriptor_digest
        || constraints.transition_constraint_descriptor_digest
            != plan.constraint_descriptors[2].descriptor_digest
        || constraints.rows_digest
            != n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows)
        || constraints.transition_binding_digest
            != n8_integrated_transition_binding_semantic_digest(constraints)
        || constraints.descriptor_digest
            != n8_integrated_transition_binding_semantic_descriptor_digest(constraints)
    {
        return Some(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }

    let expected_k6a_descriptor = n8_integrated_k6a_main_constraint_descriptor_digest_from_parts(
        constraints.profile_digest,
        constraints.accumulator_instance_digest,
        constraints.public_statement_digest,
        constraints.k6a_semantic_descriptor_digest,
        constraints.whir_param_digest,
        constraints.main_symbt3_relation_id,
        constraints.old_accumulator_digest,
        constraints.new_accumulator_digest,
        constraints.batch_manifest_root,
        constraints.manifest_oracle_root,
        constraints.native_message_roots_digest,
        constraints.batch_size,
        constraints.active_count,
        constraints.k6a_num_vars,
        constraints.k6a_oracle_len,
    );
    let expected_tuple_descriptor =
        n8_integrated_tuple_leaf_constraint_descriptor_digest_from_parts(
            constraints.tuple_leaf_descriptor_digest,
            constraints.tuple_leaf_layout_digest,
            constraints.tuple_leaf_packing_challenge_digest,
            constraints.tuple_leaf_root,
            constraints.native_oracle_descriptor_digest,
            constraints.native_message_roots_digest,
            constraints.manifest_oracle_root,
            constraints.source_oracle_root,
            constraints.tuple_logical_oracle_count,
            constraints.tuple_logical_num_vars,
            constraints.tuple_packed_num_vars,
            constraints.rlc_repetition_count,
            constraints.rlc_batching_bits_per_repetition,
            constraints.total_rlc_batching_bits,
            constraints.effective_soundness_bits,
        );
    let expected_transition_descriptor =
        n8_integrated_transition_constraint_descriptor_digest_from_parts(
            expected_k6a_descriptor,
            expected_tuple_descriptor,
            constraints.profile_digest,
            constraints.accumulator_instance_digest,
            constraints.old_accumulator_digest,
            constraints.new_accumulator_digest,
            constraints.public_statement_digest,
            constraints.whir_param_digest,
            constraints.main_symbt3_relation_id,
            constraints.k6a_proof_digest,
            constraints.tuple_leaf_root,
            constraints.tuple_leaf_layout_digest,
            constraints.native_oracle_descriptor_digest,
            constraints.native_message_roots_digest,
            constraints.manifest_oracle_root,
            constraints.source_oracle_root,
            constraints.batch_manifest_root,
            constraints.batch_size,
            constraints.active_count,
            constraints.integrated_num_vars,
            constraints.integrated_oracle_len,
        );
    if expected_k6a_descriptor != constraints.k6a_constraint_descriptor_digest
        || expected_tuple_descriptor != constraints.tuple_constraint_descriptor_digest
        || expected_transition_descriptor != constraints.transition_constraint_descriptor_digest
    {
        return Some(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }

    let transition_semantics_complete = constraints.complete && !constraints.rows.is_empty();
    if descriptor.semantic_completion.transition_semantics_complete != transition_semantics_complete
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete);
    }
    if !constraints.complete {
        if !constraints.rows.is_empty() {
            return Some(
                Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
            );
        }
        return None;
    }

    let expected_rows = n8_integrated_transition_semantic_rows(constraints);
    if constraints.rows != expected_rows
        || constraints
            .rows
            .iter()
            .any(|row| row.value != BabyBear::ZERO)
    {
        return Some(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    let expected_evaluator_rows = constraints
        .rows
        .iter()
        .map(n8_integrated_transition_semantic_to_evaluator_row)
        .collect::<Vec<_>>();
    let actual_evaluator_rows = descriptor
        .real_evaluator
        .rows
        .iter()
        .filter(|row| {
            row.kind
                == RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1
        })
        .cloned()
        .collect::<Vec<_>>();
    if actual_evaluator_rows != expected_evaluator_rows
        || descriptor.real_evaluator.counters.transition_binding_rows != expected_rows.len()
    {
        return Some(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    None
}

fn n8_integrated_row_ranges_overlap(
    left: &IntegratedK6aNativeCommittedTableRowRangeV1,
    right: &IntegratedK6aNativeCommittedTableRowRangeV1,
) -> bool {
    let Some(left_end) = left.integrated_start.checked_add(left.row_count) else {
        return true;
    };
    let Some(right_end) = right.integrated_start.checked_add(right.row_count) else {
        return true;
    };
    left.row_count > 0
        && right.row_count > 0
        && left.integrated_start < right_end
        && right.integrated_start < left_end
}

fn n8_integrated_axis_ranges_overlap(
    left: &IntegratedK6aNativeCommittedTableAxisRangeV1,
    right: &IntegratedK6aNativeCommittedTableAxisRangeV1,
) -> bool {
    let Some(left_end) = left.axis_start.checked_add(left.axis_len) else {
        return true;
    };
    let Some(right_end) = right.axis_start.checked_add(right.axis_len) else {
        return true;
    };
    left.axis_len > 0
        && right.axis_len > 0
        && left.axis_start < right_end
        && right.axis_start < left_end
}

fn n8_integrated_layout_representation_blocker(
    table: &IntegratedK6aNativeCommittedTableV1,
    representation: N8IntegratedWhirTableRepresentationV1,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    let row_overlap = table.row_ownership.iter().enumerate().any(|(index, left)| {
        table
            .row_ownership
            .iter()
            .skip(index + 1)
            .any(|right| n8_integrated_row_ranges_overlap(left, right))
    });
    let same_owner_row_overlap =
        table.row_ownership.iter().enumerate().any(|(index, left)| {
            table.row_ownership.iter().skip(index + 1).any(|right| {
                left.owner == right.owner && n8_integrated_row_ranges_overlap(left, right)
            })
        });
    let axis_overlap = table
        .axis_ownership
        .iter()
        .enumerate()
        .any(|(index, left)| {
            table
                .axis_ownership
                .iter()
                .skip(index + 1)
                .any(|right| n8_integrated_axis_ranges_overlap(left, right))
        });
    let same_owner_axis_overlap = table
        .axis_ownership
        .iter()
        .enumerate()
        .any(|(index, left)| {
            table.axis_ownership.iter().skip(index + 1).any(|right| {
                left.owner == right.owner && n8_integrated_axis_ranges_overlap(left, right)
            })
        });

    match representation {
        N8IntegratedWhirTableRepresentationV1::SameDomainMultipleLogicalColumns => {
            if same_owner_row_overlap || same_owner_axis_overlap {
                Some(Symbt3N8IntegratedPrototypeBlocker::AmbiguousIntegratedLayout)
            } else {
                None
            }
        }
        N8IntegratedWhirTableRepresentationV1::ScalarOracleSelectorGatedRegions => {
            if row_overlap || axis_overlap {
                Some(Symbt3N8IntegratedPrototypeBlocker::AmbiguousIntegratedLayout)
            } else {
                None
            }
        }
    }
}

fn n8_integrated_whir_claim_bridge_descriptors_with_batching(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    semantic_batching: &N8SemanticBatchingV1,
) -> Result<Vec<N8IntegratedWhirClaimBridgeDescriptorV1>, Symbt3N8IntegratedPrototypeBlocker> {
    let plan = &descriptor.claim_plan;
    if plan.constraint_descriptors.len() != 3 || plan.claim_descriptors.len() != 3 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    let k6a_constraint = &plan.constraint_descriptors[0];
    let tuple_constraint = &plan.constraint_descriptors[1];
    let transition_constraint = &plan.constraint_descriptors[2];
    let k6a_claim = &plan.claim_descriptors[0];
    let tuple_packed_claim = &plan.claim_descriptors[1];
    let tuple_logical_claim = &plan.claim_descriptors[2];

    if k6a_constraint.kind != Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1
        || tuple_constraint.kind != Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1
        || transition_constraint.kind
            != Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1
        || k6a_claim.kind != IntegratedK6aNativeClaimDescriptorKindV1::K6aAccumulatorMainClaimsV1
        || tuple_packed_claim.kind
            != IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafPackedClaimsV1
        || tuple_logical_claim.kind
            != IntegratedK6aNativeClaimDescriptorKindV1::NativeTupleLeafLogicalClaimsV1
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }

    let tuple_claim_digest = n8_integrated_whir_tuple_repeated_rlc_claim_bridge_digest(
        tuple_packed_claim,
        tuple_logical_claim,
        &plan.tuple_repetition_axis,
    );
    let transition_binding_digest =
        n8_integrated_whir_accumulator_transition_binding_claim_bridge_digest(descriptor);
    let k6a_source_bridge_count = semantic_batching.k6a_source.batched_source_opening_count;
    let k6a_semantic_bridge_count = semantic_batching.k6a.batched_query_count;
    let tuple_bridge_count = semantic_batching.tuple_rlc.batched_query_count;
    let transition_bridge_count = semantic_batching.transition_binding.batched_query_count;

    Ok(vec![
        n8_integrated_whir_claim_bridge_descriptor(
            N8IntegratedWhirClaimBridgeKindV1::K6aAccumulatorConstraintsV1,
            k6a_source_bridge_count.saturating_add(k6a_semantic_bridge_count),
            k6a_claim.num_vars,
            plan.integrated_num_vars,
            k6a_constraint.descriptor_digest,
            descriptor.real_evaluator.rows_digest,
            descriptor.committed_table.layout_digest,
        ),
        n8_integrated_whir_claim_bridge_descriptor(
            N8IntegratedWhirClaimBridgeKindV1::NativeTupleLeafRepeatedRlcConstraintsV1,
            tuple_bridge_count,
            tuple_packed_claim.num_vars,
            plan.integrated_num_vars,
            tuple_constraint.descriptor_digest,
            tuple_claim_digest,
            descriptor.committed_table.layout_digest,
        ),
        n8_integrated_whir_claim_bridge_descriptor(
            N8IntegratedWhirClaimBridgeKindV1::AccumulatorTransitionBindingConstraintsV1,
            transition_bridge_count,
            plan.integrated_num_vars,
            plan.integrated_num_vars,
            transition_constraint.descriptor_digest,
            transition_binding_digest,
            descriptor.committed_table.layout_digest,
        ),
    ])
}

pub fn build_n8_integrated_whir_proof_plan(
    inputs: &N8IntegratedWhirProofInputs<'_>,
) -> Result<N8IntegratedWhirProofPlan, Symbt3N8IntegratedPrototypeBlocker> {
    build_n8_integrated_whir_proof_plan_profiled(inputs).map(|(plan, _profile)| plan)
}

pub fn build_n8_integrated_whir_proof_plan_profiled(
    inputs: &N8IntegratedWhirProofInputs<'_>,
) -> Result<
    (
        N8IntegratedWhirProofPlan,
        N8IntegratedProofPlanBuildProfileV1,
    ),
    Symbt3N8IntegratedPrototypeBlocker,
> {
    let total_start = Instant::now();
    let mut profile = N8IntegratedProofPlanBuildProfileV1::default();
    if inputs.version != N8_INTEGRATED_WHIR_PROOF_INPUTS_VERSION {
        return Err(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }

    let gate_report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(inputs.descriptor);
    if gate_report.blocked
        && !matches!(
            gate_report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
        )
    {
        return Err(gate_report
            .blocker
            .unwrap_or(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch));
    }

    if inputs.extra_whir_root_count != 0 || inputs.extra_whir_proof_count != 0 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot);
    }
    let integrated_whir_root_count = usize::from(inputs.integrated_whir_root.is_some());
    let integrated_whir_proof_count = usize::from(inputs.integrated_whir_proof.is_some());
    if integrated_whir_root_count > 1 || integrated_whir_proof_count > 1 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot);
    }

    let plan = build_n8_integrated_whir_proof_plan_from_counts_profiled(
        inputs.descriptor,
        inputs.table_representation,
        integrated_whir_root_count,
        integrated_whir_proof_count,
        inputs.legacy_k6a_proof.is_some() || inputs.legacy_tuple_leaf_proof.is_some(),
        Some(&mut profile),
    )?;
    profile.total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;
    Ok((plan, profile))
}

fn build_n8_integrated_whir_proof_plan_from_counts(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    table_representation: N8IntegratedWhirTableRepresentationV1,
    integrated_whir_root_count: usize,
    integrated_whir_proof_count: usize,
    delegated_split_proof_material_present: bool,
) -> Result<N8IntegratedWhirProofPlan, Symbt3N8IntegratedPrototypeBlocker> {
    build_n8_integrated_whir_proof_plan_from_counts_profiled(
        descriptor,
        table_representation,
        integrated_whir_root_count,
        integrated_whir_proof_count,
        delegated_split_proof_material_present,
        None,
    )
}

fn build_n8_integrated_whir_proof_plan_from_counts_profiled(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    table_representation: N8IntegratedWhirTableRepresentationV1,
    integrated_whir_root_count: usize,
    integrated_whir_proof_count: usize,
    delegated_split_proof_material_present: bool,
    mut profile: Option<&mut N8IntegratedProofPlanBuildProfileV1>,
) -> Result<N8IntegratedWhirProofPlan, Symbt3N8IntegratedPrototypeBlocker> {
    if integrated_whir_root_count > 1 || integrated_whir_proof_count > 1 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot);
    }

    if let Some(blocker) = n8_integrated_layout_representation_blocker(
        &descriptor.committed_table,
        table_representation,
    ) {
        return Err(blocker);
    }

    let section_start = Instant::now();
    let semantic_batching = n8_semantic_batching_descriptor(descriptor);
    if let Some(profile) = profile.as_deref_mut() {
        profile.semantic_batching_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
    let bridge_claim_descriptors =
        n8_integrated_whir_claim_bridge_descriptors_with_batching(descriptor, &semantic_batching)?;
    let combined_bridge_claim_descriptor_digest =
        n8_integrated_whir_claim_bridge_descriptors_digest(&bridge_claim_descriptors);
    if let Some(profile) = profile.as_deref_mut() {
        profile.bridge_descriptor_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let mut plan = N8IntegratedWhirProofPlan {
        version: N8_INTEGRATED_WHIR_PROOF_PLAN_VERSION,
        workload_kind: descriptor.workload_kind,
        table_representation,
        descriptor_transcript_digest: descriptor.transcript_binding_digest,
        claim_plan_digest: descriptor.claim_plan.claim_plan_digest,
        committed_table_layout_digest: descriptor.committed_table.layout_digest,
        committed_table_digest: descriptor.committed_table.table_digest,
        integrated_num_vars: descriptor.claim_plan.integrated_num_vars,
        integrated_oracle_len: descriptor.claim_plan.integrated_oracle_len,
        integrated_whir_root_count,
        integrated_whir_proof_count,
        delegated_split_proof_material_present,
        semantic_batching,
        bridge_claim_descriptors,
        combined_bridge_claim_descriptor_digest,
        transcript_digest: [0u8; 32],
    };
    let section_start = Instant::now();
    plan.transcript_digest = n8_integrated_whir_proof_plan_transcript_digest(&plan);
    if let Some(profile) = profile.as_deref_mut() {
        profile.transcript_digest_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }
    Ok(plan)
}

fn n8_integrated_whir_verify_query_schedule_shape(
    proof_plan: &N8IntegratedWhirProofPlan,
    schedule: &N8IntegratedWhirQueryScheduleV1,
) -> Result<(), Symbt3N8IntegratedPrototypeBlocker> {
    if schedule.version != N8_INTEGRATED_WHIR_QUERY_SCHEDULE_VERSION
        || schedule.integrated_num_vars != proof_plan.integrated_num_vars
        || schedule.transcript_digest != proof_plan.transcript_digest
        || schedule.combined_bridge_claim_descriptor_digest
            != proof_plan.combined_bridge_claim_descriptor_digest
        || schedule.query_claims_digest
            != n8_integrated_whir_query_claims_digest(&schedule.query_claims)
        || schedule.query_schedule_digest != n8_integrated_whir_query_schedule_digest(schedule)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
    }

    for claim in &schedule.query_claims {
        if claim.point.len() != proof_plan.integrated_num_vars
            || claim.point_digest != native_oracle_point_digest(&claim.point)
        {
            return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
        }
    }

    for descriptor in &proof_plan.bridge_claim_descriptors {
        if descriptor.integrated_num_vars != proof_plan.integrated_num_vars {
            return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
        }
        let actual_count = schedule
            .query_claims
            .iter()
            .filter(|claim| claim.bridge_kind == descriptor.kind)
            .count();
        if actual_count != descriptor.claim_count {
            return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
        }
    }

    Ok(())
}

fn verify_symbt3_integrated_whir_backend_inner(
    vk: &WhirVerifyingKey,
    input: &N8IntegratedWhirVerifierInput<'_>,
) -> Result<(), Symbt3N8IntegratedPrototypeBlocker> {
    if input.version != N8_INTEGRATED_WHIR_VERIFIER_INPUT_VERSION {
        return Err(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if matches!(
        input.prover_mode,
        N8IntegratedWhirProverModeV1::SyntheticNonAuthoritativeV1
    ) && input.legacy_k6a_proof.is_some()
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput);
    }
    if input.legacy_k6a_proof.is_some() || input.legacy_tuple_leaf_proof.is_some() {
        return Err(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt);
    }
    if input.extra_whir_root_count != 0 || input.extra_whir_proof_count != 0 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot);
    }

    let Some(integrated_proof) = input.integrated_whir_proof else {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing);
    };
    let Some(integrated_root) = input.integrated_whir_root else {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing);
    };
    if input.whir_instance_count != 1 || input.root_count != 1 {
        return Err(if input.whir_instance_count == 0 || input.root_count == 0 {
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing
        } else {
            Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot
        });
    }
    if integrated_proof.is_output || !integrated_proof.family_columnar_subproofs.is_empty() {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected);
    }

    let mut proof_inputs = N8IntegratedWhirProofInputs::from_descriptor(input.descriptor);
    proof_inputs.table_representation = input.proof_plan.table_representation;
    proof_inputs.integrated_whir_root = Some(integrated_root);
    proof_inputs.integrated_whir_proof = Some(integrated_proof);
    let expected_plan = build_n8_integrated_whir_proof_plan(&proof_inputs)?;
    if expected_plan != *input.proof_plan {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }

    if input.claim_plan != &input.descriptor.claim_plan {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if input.committed_table_layout_digest != input.descriptor.committed_table.layout_digest
        || input.committed_table_layout_digest != input.proof_plan.committed_table_layout_digest
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch);
    }
    if input.committed_table_digest != input.descriptor.committed_table.table_digest
        || input.committed_table_digest != input.proof_plan.committed_table_digest
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::CommittedTableDigestMismatch);
    }
    if input.combined_claim_descriptors != input.proof_plan.bridge_claim_descriptors.as_slice() {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    if input.combined_claim_descriptor_digest
        != input.proof_plan.combined_bridge_claim_descriptor_digest
        || input.combined_claim_descriptor_digest
            != n8_integrated_whir_claim_bridge_descriptors_digest(input.combined_claim_descriptors)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ClaimPlanDigestMismatch);
    }
    if integrated_proof.num_vars != input.proof_plan.integrated_num_vars
        || input.claim_plan.integrated_num_vars != input.proof_plan.integrated_num_vars
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch);
    }

    let Some(query_schedule) = input.query_schedule else {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing);
    };
    n8_integrated_whir_verify_query_schedule_shape(input.proof_plan, query_schedule)?;
    if matches!(
        input.prover_mode,
        N8IntegratedWhirProverModeV1::RealIntegratedK6aNativeEvaluatorV1
    ) {
        let expected_query_claims = n8_integrated_whir_real_query_claims(
            &input.descriptor.real_evaluator,
            &input.proof_plan.semantic_batching,
        )?;
        if query_schedule.query_claims != expected_query_claims {
            return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch);
        }
    }

    let Some(actual_root) = whir_pcs_initial_root_digest(
        &integrated_proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    ) else {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch);
    };
    if actual_root != integrated_root {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch);
    }

    let opening_points: Vec<Vec<BabyBear>> = query_schedule
        .query_claims
        .iter()
        .map(|claim| claim.point.clone())
        .collect();
    let opening_values: Vec<BabyBear> = query_schedule
        .query_claims
        .iter()
        .map(|claim| claim.value)
        .collect();
    if !whir_verify_opening_multi(
        &vk.seed,
        input.proof_plan.integrated_num_vars,
        &integrated_proof.whir_pcs_proof,
        &opening_points,
        &opening_values,
    ) {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected);
    }

    Ok(())
}

fn n8_integrated_whir_synthetic_table_evaluations(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    proof_plan: &N8IntegratedWhirProofPlan,
    committed_table: &IntegratedK6aNativeCommittedTableV1,
) -> Vec<BabyBear> {
    let mut evaluations = Vec::with_capacity(proof_plan.integrated_oracle_len);
    for row in 0..proof_plan.integrated_oracle_len {
        let mut bytes = Vec::new();
        push_bytes(
            &mut bytes,
            b"N8_SYNTHETIC_NON_AUTHORITATIVE_INTEGRATED_TABLE_VALUE_V1",
        );
        push_digest(&mut bytes, &descriptor.transcript_binding_digest);
        push_digest(&mut bytes, &descriptor.claim_plan.claim_plan_digest);
        push_digest(&mut bytes, &committed_table.layout_digest);
        push_digest(&mut bytes, &committed_table.table_digest);
        push_digest(&mut bytes, &proof_plan.transcript_digest);
        push_u64(&mut bytes, row as u64);
        let digest = digest_bytes(&bytes);
        evaluations.push(BabyBear::from_u32(u32::from_le_bytes(
            digest[..4].try_into().expect("digest prefix is four bytes"),
        )));
    }
    evaluations
}

fn n8_integrated_whir_synthetic_query_points(
    proof_plan: &N8IntegratedWhirProofPlan,
) -> Vec<(N8IntegratedWhirClaimBridgeKindV1, Vec<BabyBear>)> {
    let mut points = Vec::new();
    for descriptor in &proof_plan.bridge_claim_descriptors {
        for claim_index in 0..descriptor.claim_count {
            let mut transcript = Vec::new();
            push_bytes(
                &mut transcript,
                b"N8_SYNTHETIC_NON_AUTHORITATIVE_QUERY_POINT_V1",
            );
            push_digest(&mut transcript, &proof_plan.transcript_digest);
            push_bytes(&mut transcript, &descriptor.kind.canonical_bytes());
            push_digest(&mut transcript, &descriptor.descriptor_digest);
            push_u64(&mut transcript, claim_index as u64);
            let point = (0..proof_plan.integrated_num_vars)
                .map(|axis| {
                    derive_challenge(
                        &transcript,
                        axis,
                        b"N8_SYNTHETIC_NON_AUTHORITATIVE_QUERY_AXIS_V1",
                    )
                })
                .collect();
            points.push((descriptor.kind, point));
        }
    }
    points
}

fn n8_integrated_semantic_batch_query_claim(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
    table: &[BabyBear],
    semantic_batching: &N8SemanticBatchingV1,
    family: N8SemanticBatchingFamilyV1,
) -> Option<N8IntegratedWhirQueryClaimV1> {
    let family_descriptor = match family {
        N8SemanticBatchingFamilyV1::K6aSourceRowsV1 => semantic_batching.k6a_source.descriptor,
        N8SemanticBatchingFamilyV1::K6aSemanticRowsV1 => semantic_batching.k6a,
        N8SemanticBatchingFamilyV1::TupleRlcSemanticRowsV1 => semantic_batching.tuple_rlc,
        N8SemanticBatchingFamilyV1::TransitionBindingSemanticRowsV1 => {
            semantic_batching.transition_binding
        }
    };
    if family_descriptor.source_row_count == 0 {
        return None;
    }
    let point = n8_semantic_batching_point(
        semantic_batching.descriptor_binding_digest,
        family,
        evaluator.integrated_num_vars,
    );
    let point_digest = native_oracle_point_digest(&point);
    if point_digest != family_descriptor.challenge_point_digest {
        return None;
    }
    Some(N8IntegratedWhirQueryClaimV1 {
        bridge_kind: match family {
            N8SemanticBatchingFamilyV1::K6aSourceRowsV1 => {
                N8IntegratedWhirClaimBridgeKindV1::K6aAccumulatorConstraintsV1
            }
            N8SemanticBatchingFamilyV1::K6aSemanticRowsV1 => {
                N8IntegratedWhirClaimBridgeKindV1::K6aAccumulatorConstraintsV1
            }
            N8SemanticBatchingFamilyV1::TupleRlcSemanticRowsV1 => {
                N8IntegratedWhirClaimBridgeKindV1::NativeTupleLeafRepeatedRlcConstraintsV1
            }
            N8SemanticBatchingFamilyV1::TransitionBindingSemanticRowsV1 => {
                N8IntegratedWhirClaimBridgeKindV1::AccumulatorTransitionBindingConstraintsV1
            }
        },
        point_digest,
        value: mle_eval_bb(table, &point),
        point,
    })
}

fn n8_integrated_whir_real_query_claims(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
    semantic_batching: &N8SemanticBatchingV1,
) -> Result<Vec<N8IntegratedWhirQueryClaimV1>, Symbt3N8IntegratedPrototypeBlocker> {
    let table = n8_integrated_evaluator_table_values(evaluator)?;
    n8_integrated_whir_real_query_claims_for_table(evaluator, semantic_batching, &table)
}

fn n8_integrated_whir_real_query_claims_for_table(
    evaluator: &RealIntegratedK6aNativeEvaluatorV1,
    semantic_batching: &N8SemanticBatchingV1,
    table: &[BabyBear],
) -> Result<Vec<N8IntegratedWhirQueryClaimV1>, Symbt3N8IntegratedPrototypeBlocker> {
    if semantic_batching.version != N8_SEMANTIC_BATCHING_VERSION
        || !semantic_batching.enabled
        || semantic_batching.descriptor_digest
            != n8_semantic_batching_descriptor_digest(semantic_batching)
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    let mut claims = Vec::new();
    for family in [
        N8SemanticBatchingFamilyV1::K6aSourceRowsV1,
        N8SemanticBatchingFamilyV1::K6aSemanticRowsV1,
        N8SemanticBatchingFamilyV1::TupleRlcSemanticRowsV1,
        N8SemanticBatchingFamilyV1::TransitionBindingSemanticRowsV1,
    ] {
        if let Some(claim) =
            n8_integrated_semantic_batch_query_claim(evaluator, &table, semantic_batching, family)
        {
            claims.push(claim);
        }
    }
    Ok(claims)
}

#[must_use]
pub fn verify_symbt3_integrated_whir_backend_from_verifier_input(
    vk: &WhirVerifyingKey,
    input: &N8IntegratedWhirVerifierInput<'_>,
) -> Symbt3N8IntegratedPrototypeGateReport {
    match verify_symbt3_integrated_whir_backend_inner(vk, input) {
        Ok(()) => Symbt3N8IntegratedPrototypeGateReport::ok(),
        Err(blocker) => Symbt3N8IntegratedPrototypeGateReport::blocked(blocker),
    }
}

#[must_use]
pub fn verify_symbt3_integrated_whir_query_openings_for_benchmark(
    vk: &WhirVerifyingKey,
    input: &N8IntegratedWhirVerifierInput<'_>,
) -> Symbt3N8IntegratedPrototypeGateReport {
    let Some(integrated_proof) = input.integrated_whir_proof else {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing,
        );
    };
    let Some(query_schedule) = input.query_schedule else {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing,
        );
    };
    if let Err(blocker) =
        n8_integrated_whir_verify_query_schedule_shape(input.proof_plan, query_schedule)
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker);
    }
    let opening_points = query_schedule
        .query_claims
        .iter()
        .map(|claim| claim.point.clone())
        .collect::<Vec<_>>();
    let opening_values = query_schedule
        .query_claims
        .iter()
        .map(|claim| claim.value)
        .collect::<Vec<_>>();
    if whir_verify_opening_multi(
        &vk.seed,
        input.proof_plan.integrated_num_vars,
        &integrated_proof.whir_pcs_proof,
        &opening_points,
        &opening_values,
    ) {
        Symbt3N8IntegratedPrototypeGateReport::ok()
    } else {
        Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected,
        )
    }
}

pub fn prove_symbt3_n8_integrated_whir_non_zk(
    _pk: &WhirProvingKey,
    inputs: &N8IntegratedWhirProofInputs<'_>,
) -> Result<N8IntegratedWhirProofPlan, Symbt3N8IntegratedPrototypeBlocker> {
    let plan = build_n8_integrated_whir_proof_plan(inputs)?;
    if plan.delegated_split_proof_material_present {
        return Err(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt);
    }
    if inputs.descriptor.semantic_completion.all_complete() {
        Ok(plan)
    } else {
        Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
    }
}

pub fn prove_symbt3_integrated_whir_from_claim_plan(
    pk: &WhirProvingKey,
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    proof_plan: &N8IntegratedWhirProofPlan,
) -> Result<N8IntegratedWhirProverOutput, Symbt3N8IntegratedPrototypeBlocker> {
    prove_symbt3_integrated_whir_from_claim_plan_profiled(pk, descriptor, proof_plan)
        .map(|(output, _profile)| output)
}

pub fn prove_symbt3_integrated_whir_from_claim_plan_profiled(
    pk: &WhirProvingKey,
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    proof_plan: &N8IntegratedWhirProofPlan,
) -> Result<
    (N8IntegratedWhirProverOutput, N8IntegratedWhirProveProfileV1),
    Symbt3N8IntegratedPrototypeBlocker,
> {
    let total_start = Instant::now();
    let mut profile = N8IntegratedWhirProveProfileV1::default();

    let section_start = Instant::now();
    let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(descriptor);
    inputs.table_representation = proof_plan.table_representation;
    let empty_plan = build_n8_integrated_whir_proof_plan(&inputs)?;
    let materialized_plan = build_n8_integrated_whir_proof_plan_from_counts(
        descriptor,
        proof_plan.table_representation,
        1,
        1,
        false,
    )?;
    if proof_plan != &empty_plan && proof_plan != &materialized_plan {
        return Err(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch);
    }
    profile.proof_plan_validation_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let committed_table = build_integrated_k6a_native_committed_table_v1(&descriptor.claim_plan)?;
    profile.committed_table_rebuild_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    if committed_table != descriptor.committed_table
        || committed_table.layout_digest != materialized_plan.committed_table_layout_digest
        || committed_table.table_digest != materialized_plan.committed_table_digest
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::CommittedTableDigestMismatch);
    }

    let section_start = Instant::now();
    let table = n8_integrated_evaluator_table_values(&descriptor.real_evaluator)?;
    profile.integrated_table_values_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let query_claims = n8_integrated_whir_real_query_claims_for_table(
        &descriptor.real_evaluator,
        &materialized_plan.semantic_batching,
        &table,
    )?;
    profile.query_claim_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    let opening_points: Vec<Vec<BabyBear>> = query_claims
        .iter()
        .map(|claim| claim.point.clone())
        .collect();

    let section_start = Instant::now();
    let (whir_pcs_proof, opening_evals) = whir_commit_and_prove_multi(
        &pk.seed,
        materialized_plan.integrated_num_vars,
        &table,
        &opening_points,
    );
    profile.whir_prove_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    if opening_evals
        != query_claims
            .iter()
            .map(|claim| claim.value)
            .collect::<Vec<_>>()
    {
        return Err(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected);
    }

    let section_start = Instant::now();
    let query_schedule =
        build_n8_integrated_whir_query_schedule_for_claims(&materialized_plan, query_claims);
    profile.query_schedule_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    let integrated_whir_proof = WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: Vec::new(),
        evaluations: [BabyBear::ZERO; 3],
        whir_pcs_proof,
        z_eval: BabyBear::ZERO,
        linear_checks: Vec::new(),
        private_opening_evals: Vec::new(),
        family_columnar_subproofs: Vec::new(),
        num_vars: materialized_plan.integrated_num_vars,
        is_output: false,
    };
    let integrated_whir_root = whir_pcs_initial_root_digest(
        &integrated_whir_proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)?;

    profile.total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;
    Ok((
        N8IntegratedWhirProverOutput {
            version: N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION,
            mode: N8IntegratedWhirProverModeV1::RealIntegratedK6aNativeEvaluatorV1,
            proof_plan: materialized_plan,
            integrated_whir_root,
            integrated_whir_proof,
            query_schedule,
            counters: N8IntegratedWhirPrototypeCounters {
                whir_instance_count: 1,
                root_count: 1,
                query_schedule_count: 1,
                tuple_pcs_proof_count: 0,
                delegated_split_proof_material_present: false,
                synthetic_non_authoritative: false,
            },
        },
        profile,
    ))
}

pub fn prove_symbt3_synthetic_integrated_whir_from_claim_plan(
    pk: &WhirProvingKey,
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    proof_plan: &N8IntegratedWhirProofPlan,
) -> Result<N8IntegratedWhirProverOutput, Symbt3N8IntegratedPrototypeBlocker> {
    let materialized_plan = build_n8_integrated_whir_proof_plan_from_counts(
        descriptor,
        proof_plan.table_representation,
        1,
        1,
        false,
    )?;
    let committed_table = build_integrated_k6a_native_committed_table_v1(&descriptor.claim_plan)?;
    let query_points_with_kinds = n8_integrated_whir_synthetic_query_points(&materialized_plan);
    let opening_points: Vec<Vec<BabyBear>> = query_points_with_kinds
        .iter()
        .map(|(_, point)| point.clone())
        .collect();
    let table = n8_integrated_whir_synthetic_table_evaluations(
        descriptor,
        &materialized_plan,
        &committed_table,
    );
    let (whir_pcs_proof, opening_evals) = whir_commit_and_prove_multi(
        &pk.seed,
        materialized_plan.integrated_num_vars,
        &table,
        &opening_points,
    );
    let query_claims = query_points_with_kinds
        .into_iter()
        .zip(opening_evals)
        .map(
            |((bridge_kind, point), value)| N8IntegratedWhirQueryClaimV1 {
                bridge_kind,
                point_digest: native_oracle_point_digest(&point),
                point,
                value,
            },
        )
        .collect();
    let query_schedule =
        build_n8_integrated_whir_query_schedule_for_claims(&materialized_plan, query_claims);
    let integrated_whir_proof = WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: Vec::new(),
        evaluations: [BabyBear::ZERO; 3],
        whir_pcs_proof,
        z_eval: BabyBear::ZERO,
        linear_checks: Vec::new(),
        private_opening_evals: Vec::new(),
        family_columnar_subproofs: Vec::new(),
        num_vars: materialized_plan.integrated_num_vars,
        is_output: false,
    };
    let integrated_whir_root = whir_pcs_initial_root_digest(
        &integrated_whir_proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)?;

    Ok(N8IntegratedWhirProverOutput {
        version: N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION,
        mode: N8IntegratedWhirProverModeV1::SyntheticNonAuthoritativeV1,
        proof_plan: materialized_plan,
        integrated_whir_root,
        integrated_whir_proof,
        query_schedule,
        counters: N8IntegratedWhirPrototypeCounters {
            whir_instance_count: 1,
            root_count: 1,
            query_schedule_count: 1,
            tuple_pcs_proof_count: 0,
            delegated_split_proof_material_present: false,
            synthetic_non_authoritative: true,
        },
    })
}

#[must_use]
pub fn verify_symbt3_integrated_whir_from_claim_plan(
    vk: &WhirVerifyingKey,
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    proof_plan: &N8IntegratedWhirProofPlan,
    integrated_root: Option<Digest32>,
    integrated_proof: Option<&WhirProof>,
) -> Symbt3N8IntegratedPrototypeGateReport {
    let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
        descriptor,
        proof_plan,
        integrated_root,
        integrated_proof,
        None,
    );
    verify_symbt3_integrated_whir_backend_from_verifier_input(vk, &verifier_input)
}

#[must_use]
pub fn verify_symbt3_n8_integrated_prover_output_authority_gate(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
    output: &N8IntegratedWhirProverOutput,
) -> Symbt3N8IntegratedPrototypeGateReport {
    if output.mode == N8IntegratedWhirProverModeV1::SyntheticNonAuthoritativeV1
        || output.counters.synthetic_non_authoritative
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput,
        );
    }
    if output.counters.delegated_split_proof_material_present
        || output.counters.tuple_pcs_proof_count != 0
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt,
        );
    }
    if output.counters.whir_instance_count != 1
        || output.counters.root_count != 1
        || output.counters.query_schedule_count != 1
        || output.proof_plan.integrated_whir_root_count != 1
        || output.proof_plan.integrated_whir_proof_count != 1
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing,
        );
    }
    if output.integrated_whir_proof.num_vars != output.proof_plan.integrated_num_vars
        || output.integrated_whir_proof.is_output
        || !output
            .integrated_whir_proof
            .family_columnar_subproofs
            .is_empty()
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected,
        );
    }
    let Some(actual_root) = whir_pcs_initial_root_digest(
        &output.integrated_whir_proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    ) else {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch,
        );
    };
    if actual_root != output.integrated_whir_root {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch,
        );
    }
    if output.proof_plan.descriptor_transcript_digest != descriptor.transcript_binding_digest
        || output.proof_plan.claim_plan_digest != descriptor.claim_plan.claim_plan_digest
        || output.proof_plan.committed_table_layout_digest
            != descriptor.committed_table.layout_digest
        || output.proof_plan.committed_table_digest != descriptor.committed_table.table_digest
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch,
        );
    }
    let expected_plan = match build_n8_integrated_whir_proof_plan_from_counts(
        descriptor,
        output.proof_plan.table_representation,
        1,
        1,
        false,
    ) {
        Ok(plan) => plan,
        Err(blocker) => return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker),
    };
    if expected_plan != output.proof_plan {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch,
        );
    }
    if let Err(blocker) =
        n8_integrated_whir_verify_query_schedule_shape(&output.proof_plan, &output.query_schedule)
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker);
    }
    let expected_query_claims = match n8_integrated_whir_real_query_claims(
        &descriptor.real_evaluator,
        &output.proof_plan.semantic_batching,
    ) {
        Ok(claims) => claims,
        Err(blocker) => return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker),
    };
    if output.query_schedule.query_claims != expected_query_claims {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch,
        );
    }
    let relation_report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(descriptor);
    if relation_report.blocked {
        return relation_report;
    }
    Symbt3N8IntegratedPrototypeGateReport::ok_with_semantic_completion(
        descriptor.semantic_completion,
    )
}

#[must_use]
pub fn verify_symbt3_n8_integrated_whir_non_zk(
    _vk: &WhirVerifyingKey,
    inputs: &N8IntegratedWhirProofInputs<'_>,
) -> Symbt3N8IntegratedPrototypeGateReport {
    match build_n8_integrated_whir_proof_plan(inputs) {
        Ok(plan) if plan.delegated_split_proof_material_present => {
            Symbt3N8IntegratedPrototypeGateReport::blocked(
                Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt,
            )
        }
        Ok(_plan) if inputs.descriptor.semantic_completion.all_complete() => {
            Symbt3N8IntegratedPrototypeGateReport::ok_with_semantic_completion(
                inputs.descriptor.semantic_completion,
            )
        }
        Ok(_plan) => Symbt3N8IntegratedPrototypeGateReport::blocked_with_semantic_completion(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete,
            inputs.descriptor.semantic_completion,
        ),
        Err(blocker) => Symbt3N8IntegratedPrototypeGateReport::blocked(blocker),
    }
}

#[must_use]
pub fn verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(
    descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
) -> Symbt3N8IntegratedPrototypeGateReport {
    if descriptor.version != SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION
        || descriptor.workload_kind
            != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch,
        );
    }
    if descriptor.transcript_binding_digest
        != symbt3_n8_integrated_transcript_binding_digest(descriptor)
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::ClaimPlanDigestMismatch,
        );
    }
    if !descriptor.same_field || !descriptor.same_rate || !descriptor.same_folding_parameter {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch,
        );
    }
    if descriptor.claim_plan.workload_kind != descriptor.workload_kind {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch,
        );
    }
    if descriptor.claim_plan.k6a_relation_id != descriptor.main_symbt3_relation_id
        || descriptor.claim_plan.k6a_public_statement_digest != descriptor.public_statement_digest
        || descriptor.claim_plan.tuple_leaf_descriptor_digest
            != descriptor.tuple_leaf_descriptor_digest
        || descriptor.claim_plan.tuple_leaf_layout_digest != descriptor.tuple_leaf_layout_digest
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(
            Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch,
        );
    }
    if let Some(blocker) =
        symbt3_n8_integrated_claim_plan_consistency_blocker(&descriptor.claim_plan)
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker);
    }
    if let Some(blocker) = symbt3_n8_integrated_committed_table_consistency_blocker(
        &descriptor.claim_plan,
        &descriptor.committed_table,
    ) {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker);
    }
    if let Some(blocker) = symbt3_n8_real_evaluator_consistency_blocker(
        &descriptor.claim_plan,
        &descriptor.committed_table,
        &descriptor.real_evaluator,
    ) {
        return Symbt3N8IntegratedPrototypeGateReport::blocked(blocker);
    }
    if let Some(blocker) = symbt3_n8_k6a_semantic_constraints_consistency_blocker(
        &descriptor.claim_plan,
        &descriptor.k6a_semantic_constraints,
        descriptor.semantic_completion,
        &descriptor.real_evaluator,
    ) {
        return Symbt3N8IntegratedPrototypeGateReport::blocked_with_semantic_completion(
            blocker,
            descriptor.semantic_completion,
        );
    }
    if let Some(blocker) = symbt3_n8_tuple_rlc_semantic_constraints_consistency_blocker(descriptor)
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked_with_semantic_completion(
            blocker,
            descriptor.semantic_completion,
        );
    }
    if let Some(blocker) =
        symbt3_n8_transition_binding_semantic_constraints_consistency_blocker(descriptor)
    {
        return Symbt3N8IntegratedPrototypeGateReport::blocked_with_semantic_completion(
            blocker,
            descriptor.semantic_completion,
        );
    }

    if descriptor.semantic_completion.all_complete() {
        Symbt3N8IntegratedPrototypeGateReport::ok_with_semantic_completion(
            descriptor.semantic_completion,
        )
    } else {
        Symbt3N8IntegratedPrototypeGateReport::blocked_with_semantic_completion(
            Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete,
            descriptor.semantic_completion,
        )
    }
}
