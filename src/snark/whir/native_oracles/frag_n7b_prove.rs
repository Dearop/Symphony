impl Symbt3N7bFullAuthorityVerificationReport {
    fn blocked(blocker: Symbt3N7bFullAuthorityBlocker) -> Self {
        Self {
            ok: false,
            blocked: true,
            blocker: Some(blocker),
        }
    }

    fn ok() -> Self {
        Self {
            ok: true,
            blocked: false,
            blocker: None,
        }
    }
}

#[must_use]
pub fn symbt3_n7b_full_authority_binding_inputs(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
) -> Symbt3N7bFullAuthorityBindingInputs {
    Symbt3N7bFullAuthorityBindingInputs {
        profile_digest: adapter.profile_digest,
        accumulator_instance_digest: adapter.accumulator_instance_digest,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        main_symbt3_relation_id: adapter.main_symbt3_relation_id,
        main_symbt3_proof_digest: adapter.main_symbt3_proof_digest,
        tuple_leaf_root: native_tuple_leaf.proof.packed_root,
        tuple_leaf_layout_digest: native_tuple_leaf.proof.tuple_leaf_layout_digest,
        native_oracle_descriptor_digest: native_tuple_leaf.native_oracle_descriptor_digest,
        native_message_roots_digest: native_tuple_leaf.native_message_roots_digest,
        manifest_oracle_root: native_tuple_leaf.manifest_oracle_root,
        source_oracle_root: native_tuple_leaf.source_oracle_root,
        batch_manifest_root: adapter.batch_manifest_root,
        old_accumulator_digest: adapter.old_accumulator_digest,
        new_accumulator_digest: adapter.new_accumulator_digest,
        batch_size: adapter.batch_size,
        active_count: adapter.active_count,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
    }
}

pub fn compose_symbt3_n7b_full_authority_wrapper(
    parts: Symbt3N7bFullAuthorityWrapperParts,
) -> Result<Symbt3N7bFullAuthorityWrapperProof, Symbt3N7bFullAuthorityBlocker> {
    let workload_kind = parts
        .workload_kind
        .ok_or(Symbt3N7bFullAuthorityBlocker::WorkloadKindMismatch)?;
    let k6a_adapter = parts
        .k6a_adapter
        .ok_or(Symbt3N7bFullAuthorityBlocker::MissingK6aAdapter)?;
    let native_tuple_leaf = parts
        .native_tuple_leaf
        .ok_or(Symbt3N7bFullAuthorityBlocker::MissingNativeTupleLeafProof)?;
    if workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || k6a_adapter.workload_kind != workload_kind
    {
        return Err(Symbt3N7bFullAuthorityBlocker::WorkloadKindMismatch);
    }
    if k6a_adapter.smoke_profile {
        return Err(Symbt3N7bFullAuthorityBlocker::SmokeProfile);
    }
    if !k6a_adapter.full_accumulator_workload {
        return Err(Symbt3N7bFullAuthorityBlocker::AdapterNotFullWorkload);
    }
    if k6a_adapter.proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity {
        return Err(Symbt3N7bFullAuthorityBlocker::PublicCanonicalOrMonolithicAuthority);
    }
    if parts.fallback_used {
        return Err(Symbt3N7bFullAuthorityBlocker::FallbackUsed);
    }
    if k6a_adapter.family_columnar_subproof_count != 0 {
        return Err(Symbt3N7bFullAuthorityBlocker::FamilySubproofsPresent);
    }
    if !symbt3_n7b_native_tuple_leaf_profile_compatible(&k6a_adapter, &native_tuple_leaf) {
        return Err(Symbt3N7bFullAuthorityBlocker::TupleLeafProfileIncompatible);
    }
    let counters =
        symbt3_n7b_full_authority_counters(&k6a_adapter, &native_tuple_leaf, parts.fallback_used)
            .ok_or(Symbt3N7bFullAuthorityBlocker::TupleLeafProfileIncompatible)?;
    let binding_inputs = symbt3_n7b_full_authority_binding_inputs(&k6a_adapter, &native_tuple_leaf);
    let expected_binding_digest = build_symbt3_n7b_full_authority_binding_digest(&binding_inputs);
    let binding_digest = parts.binding_digest.unwrap_or(expected_binding_digest);
    if binding_digest != expected_binding_digest {
        return Err(Symbt3N7bFullAuthorityBlocker::BindingDigestMismatch);
    }
    Ok(Symbt3N7bFullAuthorityWrapperProof {
        version: SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_WRAPPER_VERSION,
        workload_kind,
        k6a_adapter,
        native_tuple_leaf,
        binding_digest,
        counters,
    })
}

#[must_use]
pub fn verify_symbt3_n7b_full_authority_wrapper_non_zk(
    context: &Symbt3N7bFullAuthorityVerificationContext<'_>,
    proof: &Symbt3N7bFullAuthorityWrapperProof,
) -> Symbt3N7bFullAuthorityVerificationReport {
    if proof.version != SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_WRAPPER_VERSION
        || proof.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || proof.k6a_adapter.workload_kind != proof.workload_kind
    {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::WorkloadKindMismatch,
        );
    }
    if context.proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::PublicCanonicalOrMonolithicAuthority,
        );
    }
    if !symbt3_native_accumulator_k6a_workload_adapter_matches(
        &proof.k6a_adapter,
        context.k6a_vk,
        context.profile,
        context.accumulator_instance,
        context.proof_kind,
        context.k6a_proof,
    ) {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::K6aProofMismatch,
        );
    }
    let recomposed =
        match compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
            workload_kind: Some(proof.workload_kind),
            k6a_adapter: Some(proof.k6a_adapter.clone()),
            native_tuple_leaf: Some(proof.native_tuple_leaf.clone()),
            binding_digest: Some(proof.binding_digest),
            fallback_used: proof.counters.fallback_used,
        }) {
            Ok(recomposed) => recomposed,
            Err(blocker) => return Symbt3N7bFullAuthorityVerificationReport::blocked(blocker),
        };
    if recomposed.counters != proof.counters {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::TupleLeafProfileIncompatible,
        );
    }
    if !whir_verify_same_domain_multi_oracle(
        context.tuple_leaf_vk,
        proof.k6a_adapter.main_symbt3_relation_id,
        proof.k6a_adapter.public_statement_digest,
        proof.k6a_adapter.whir_param_digest,
        &proof.native_tuple_leaf.proof,
        &proof.native_tuple_leaf.proof.logical_eval_claims,
    ) {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::TupleLeafVerificationFailed,
        );
    }
    if !symbt3_n7b_full_authority_repeated_rlc_evidence_ok(proof) {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::RepeatedRlcSoundnessMissingOrWeak,
        );
    }
    Symbt3N7bFullAuthorityVerificationReport::ok()
}

fn symbt3_n7b_native_tuple_leaf_profile_compatible(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
) -> bool {
    let proof = &native_tuple_leaf.proof;
    if proof.version != SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION
        || proof.mode != Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1
        || proof.proof_relation_id != adapter.main_symbt3_relation_id
        || proof.public_statement_digest != adapter.public_statement_digest
        || proof.whir_param_digest != adapter.whir_param_digest
        || proof.packed_root == [0u8; 32]
        || proof.tuple_leaf_layout_digest == [0u8; 32]
        || native_tuple_leaf.native_oracle_descriptor_digest == [0u8; 32]
        || native_tuple_leaf.native_message_roots_digest == [0u8; 32]
        || native_tuple_leaf.manifest_oracle_root == [0u8; 32]
        || native_tuple_leaf.source_oracle_root == [0u8; 32]
        || native_tuple_leaf.manifest_oracle_root != adapter.manifest_oracle_root
        || native_tuple_leaf.native_message_roots_digest != adapter.native_message_roots_digest
        || proof.counters.whir_instance_count != 1
        || proof.counters.root_count != 1
        || proof.counters.query_schedule_count != 1
        || proof.counters.transcript_count != 1
        || proof.counters.native_oracle_pcs_opening_count != 1
        || proof.counters.tuple_leaf_layout != SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
    {
        return false;
    }
    let Some(first_descriptor) = proof.logical_descriptors.first() else {
        return false;
    };
    tuple_leaf_counters_for(
        proof.logical_descriptors.len(),
        proof.logical_eval_claims.len(),
        first_descriptor.num_vars,
        proof.counters.rlc_repetition_count,
        proof.counters.rlc_batching_bits_per_repetition,
    ) == proof.counters
}

fn symbt3_n7b_full_authority_counters(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    fallback_used: bool,
) -> Option<Symbt3NativeAccumulatorAuthorityCounters> {
    let proof = &native_tuple_leaf.proof;
    let native_message_oracle_count = proof.logical_descriptors.len().checked_sub(2)?;
    let rlc_repetition_count = proof.counters.rlc_repetition_count;
    let rlc_batching_bits_per_repetition = proof.counters.rlc_batching_bits_per_repetition;
    let total_rlc_batching_bits = proof.counters.total_rlc_batching_bits;
    Some(Symbt3NativeAccumulatorAuthorityCounters {
        full_accumulator_workload: true,
        smoke_profile: false,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        main_whir_num_vars: adapter.main_whir_num_vars,
        main_oracle_len: adapter.main_oracle_len,
        top_level_whir_proof_count: adapter.top_level_whir_proof_count,
        family_columnar_subproof_count: adapter.family_columnar_subproof_count,
        backend_table_count: adapter.backend_table_count,
        native_multi_oracle: true,
        tuple_leaf_layout: proof.counters.tuple_leaf_layout.clone(),
        whir_instance_count: proof.counters.whir_instance_count,
        root_count: proof.counters.root_count,
        query_schedule_count: proof.counters.query_schedule_count,
        transcript_count: proof.counters.transcript_count,
        native_oracle_pcs_opening_count: proof.counters.native_oracle_pcs_opening_count,
        logical_oracle_count: proof.counters.logical_oracle_count,
        native_manifest_source_oracle_count: 2,
        native_message_oracle_count,
        accumulator_transition_claims: adapter.accumulator_transition_claims,
        source_r1cs_residual_verifier_evaluations: adapter
            .source_r1cs_residual_verifier_evaluations,
        rlc_batching_bits: total_rlc_batching_bits,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
        total_rlc_batching_bits,
        effective_soundness_bits: proof.counters.effective_soundness_bits,
        native_oracle_eval_claim_count: proof.counters.logical_eval_claim_count,
        fallback_used,
    })
}

fn symbt3_n7b_full_authority_repeated_rlc_evidence_ok(
    proof: &Symbt3N7bFullAuthorityWrapperProof,
) -> bool {
    let counters = &proof.counters;
    counters.rlc_batching_bits > 0
        && counters.rlc_batching_bits == counters.total_rlc_batching_bits
        && counters.rlc_batching_bits_per_repetition > 0
        && counters.rlc_repetition_count
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        && counters.total_rlc_batching_bits
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS
        && counters.effective_soundness_bits
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS
        && proof.native_tuple_leaf.proof.packed_eval_claims.len() >= counters.rlc_repetition_count
        && proof.native_tuple_leaf.proof.logical_eval_claims.len()
            >= counters
                .logical_oracle_count
                .saturating_mul(counters.rlc_repetition_count)
}

fn n7b_i64_to_babybear(value: i64) -> BabyBear {
    BabyBear::from_u32((value as i128).rem_euclid(BabyBear::ORDER_U64 as i128) as u32)
}

fn n7b_rows_to_babybear_values(rows: &[Vec<i64>]) -> Vec<BabyBear> {
    rows.iter()
        .flat_map(|row| row.iter().copied().map(n7b_i64_to_babybear))
        .collect()
}

fn n7b_typed_message_oracle_values(oracle: &Symbt3TypedMessageOracle) -> Vec<BabyBear> {
    let mut out = Vec::new();
    out.push(BabyBear::from_u32(oracle.round as u32));
    for row in &oracle.rows {
        out.push(BabyBear::from_u32(row.row_index as u32));
        for section in &row.sections {
            out.push(BabyBear::from_u32(section.offset as u32));
            out.push(BabyBear::from_u32(section.values.len() as u32));
            out.extend(section.values.iter().copied().map(BabyBear::from_u32));
        }
    }
    out
}

fn n7b_digest_values(digests: &[Digest32]) -> Vec<BabyBear> {
    digests
        .iter()
        .flat_map(|digest| {
            digest
                .iter()
                .copied()
                .map(|byte| BabyBear::from_u32(byte.into()))
        })
        .collect()
}

fn n7b_pad_to_common_num_vars(
    evaluations: Vec<Vec<BabyBear>>,
) -> Option<(usize, Vec<Vec<BabyBear>>)> {
    let target_len = evaluations
        .iter()
        .map(|values| values.len().max(2).next_power_of_two())
        .max()?;
    let num_vars = target_len.trailing_zeros() as usize;
    let padded = evaluations
        .into_iter()
        .map(|mut values| {
            if values.len() > target_len {
                return None;
            }
            values.resize(target_len, BabyBear::ZERO);
            Some(values)
        })
        .collect::<Option<Vec<_>>>()?;
    Some((num_vars, padded))
}

fn n7b_message_round_layout_digest(
    message_semantic_layout_digest: Digest32,
    round: usize,
    root: Digest32,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_N7B_NATIVE_MESSAGE_ROUND_LAYOUT_V1");
    push_digest(&mut bytes, &message_semantic_layout_digest);
    push_u64(&mut bytes, round as u64);
    push_digest(&mut bytes, &root);
    digest_bytes(&bytes)
}

#[must_use]
pub fn prove_symbt3_n7b_full_native_tuple_leaf_from_k6a(
    pk: &WhirProvingKey,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
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
    let Some(proof) = whir_commit_and_prove_same_domain_multi_oracle(
        pk,
        adapter.main_symbt3_relation_id,
        adapter.public_statement_digest,
        adapter.whir_param_digest,
        &specs,
        &evaluations,
        &eval_requests,
    ) else {
        return None;
    };
    let source_oracle_root = accumulator_instance.source_assignment_roots_digest;
    let descriptors = specs
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

#[must_use]
pub fn symbt3_n7b_full_authority_proof_canonical_bytes(
    proof: &Symbt3N7bFullAuthorityProof,
) -> Option<Vec<u8>> {
    let mut out = symbt3_n7b_full_authority_proof_header_bytes(proof);
    push_bytes(&mut out, &canonical_whir_proof_bytes(&proof.k6a_main_proof));
    push_bytes(&mut out, &proof.wrapper.k6a_adapter.canonical_bytes());
    push_bytes(
        &mut out,
        &symbt3_tuple_leaf_multi_oracle_proof_canonical_bytes_compact(
            &proof.wrapper.native_tuple_leaf.proof,
        )?,
    );
    push_bytes(
        &mut out,
        &symbt3_n7b_native_tuple_leaf_part_metadata_bytes(&proof.wrapper.native_tuple_leaf),
    );
    push_bytes(
        &mut out,
        &symbt3_n7b_binding_digest_profile_metadata_bytes(&proof.wrapper),
    );
    push_bytes(&mut out, &proof.wrapper.counters.canonical_bytes());
    Some(out)
}

#[must_use]
pub fn symbt3_n7b_full_authority_proof_byte_sections(
    proof: &Symbt3N7bFullAuthorityProof,
) -> Symbt3N7bFullAuthorityProofByteSections {
    let proof_header_bytes = symbt3_n7b_full_authority_proof_header_bytes(proof).len();
    let main_k6a_whir_proof_bytes = canonical_whir_proof_bytes(&proof.k6a_main_proof).len();
    let k6a_adapter_bytes = proof.wrapper.k6a_adapter.canonical_bytes().len();
    let tuple_leaf_native_proof_bytes =
        symbt3_tuple_leaf_multi_oracle_proof_canonical_bytes_compact(
            &proof.wrapper.native_tuple_leaf.proof,
        )
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    debug_assert_eq!(
        tuple_leaf_native_proof_bytes,
        proof
            .wrapper
            .native_tuple_leaf
            .proof
            .accounting_serialized_bytes_len()
    );
    let native_tuple_leaf_part_metadata_bytes =
        symbt3_n7b_native_tuple_leaf_part_metadata_bytes(&proof.wrapper.native_tuple_leaf).len();
    let binding_digest_profile_metadata_bytes =
        symbt3_n7b_binding_digest_profile_metadata_bytes(&proof.wrapper).len();
    let wrapper_counters_bytes = proof.wrapper.counters.canonical_bytes().len();
    let serialization_framing_bytes = 6 * std::mem::size_of::<u64>();
    let total_bytes = proof_header_bytes
        + main_k6a_whir_proof_bytes
        + k6a_adapter_bytes
        + tuple_leaf_native_proof_bytes
        + native_tuple_leaf_part_metadata_bytes
        + binding_digest_profile_metadata_bytes
        + wrapper_counters_bytes
        + serialization_framing_bytes;
    debug_assert_eq!(
        symbt3_n7b_full_authority_proof_canonical_bytes(proof).map(|bytes| bytes.len()),
        Some(total_bytes)
    );

    Symbt3N7bFullAuthorityProofByteSections {
        proof_header_bytes,
        main_k6a_whir_proof_bytes,
        k6a_adapter_bytes,
        tuple_leaf_native_proof_bytes,
        native_tuple_leaf_part_metadata_bytes,
        binding_digest_profile_metadata_bytes,
        wrapper_counters_bytes,
        serialization_framing_bytes,
        total_bytes,
    }
}

fn symbt3_n7b_full_authority_proof_header_bytes(proof: &Symbt3N7bFullAuthorityProof) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"SYMBT3_N7B_FULL_AUTHORITY_PROOF_CANONICAL_V1");
    push_u64(&mut out, proof.version);
    push_bytes(&mut out, n7b_product_proof_kind_label(proof.proof_kind));
    push_bytes(&mut out, &proof.workload_kind.canonical_bytes());
    push_u64(&mut out, proof.wrapper.version);
    push_bytes(&mut out, &proof.wrapper.workload_kind.canonical_bytes());
    out
}

fn symbt3_n7b_native_tuple_leaf_part_metadata_bytes(
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"SYMBT3_N7B_NATIVE_TUPLE_LEAF_PARTS_V1");
    push_digest(&mut out, &native_tuple_leaf.native_oracle_descriptor_digest);
    push_digest(&mut out, &native_tuple_leaf.native_message_roots_digest);
    push_digest(&mut out, &native_tuple_leaf.manifest_oracle_root);
    push_digest(&mut out, &native_tuple_leaf.source_oracle_root);
    out
}

fn symbt3_n7b_binding_digest_profile_metadata_bytes(
    wrapper: &Symbt3N7bFullAuthorityWrapperProof,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"SYMBT3_N7B_FULL_AUTHORITY_BINDING_METADATA_V1");
    push_digest(&mut out, &wrapper.binding_digest);
    out
}

fn n7b_product_proof_kind_label(proof_kind: ProductProofKind) -> &'static [u8] {
    match proof_kind {
        ProductProofKind::MonolithicTypedCp => b"MonolithicTypedCp",
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity => b"Symbt3AccumulatorNonZkIntegrity",
        ProductProofKind::Symbt2F => b"Symbt2F",
        ProductProofKind::Symbt2C => b"Symbt2C",
        ProductProofKind::Symbtc => b"Symbtc",
    }
}

