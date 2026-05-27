#[must_use]
pub fn symbt3_native_accumulator_authority_instance_digest(
    instance: &Symbt3NativeFoldingIntegrityInstance,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_INSTANCE_DIGEST_V1",
    );
    push_bytes(&mut bytes, &instance.canonical_public_statement_bytes());
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_native_accumulator_old_digest(
    instance: &Symbt3NativeFoldingIntegrityInstance,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_OLD_ACCUMULATOR_DIGEST_V1",
    );
    push_digest(&mut bytes, &instance.input_public_boundary_digest);
    push_digest(&mut bytes, &instance.source_roots_digest);
    push_u64(&mut bytes, instance.active_count);
    push_u64(&mut bytes, instance.batch_size);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_native_accumulator_new_digest(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    old_accumulator_digest: Digest32,
    batch_manifest_root: Digest32,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_NEW_ACCUMULATOR_DIGEST_V1",
    );
    push_digest(&mut bytes, &old_accumulator_digest);
    push_digest(&mut bytes, &instance.folded_output_digest);
    push_digest(&mut bytes, &batch_manifest_root);
    push_u64(&mut bytes, instance.active_count);
    push_u64(&mut bytes, instance.batch_size);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_main_whir_proof_digest(proof: &WhirProof) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_AUTHORITY_MAIN_WHIR_PROOF_DIGEST_V1",
    );
    push_bytes(&mut bytes, &canonical_whir_proof_bytes(proof));
    digest_bytes(&bytes)
}

impl From<&Symbt3NativeAccumulatorK6aWorkloadAdapter>
    for Symbt3NativeAccumulatorK6aWorkloadAdapterParts
{
    fn from(adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter) -> Self {
        Self {
            workload_kind: Some(adapter.workload_kind),
            full_accumulator_workload: Some(adapter.full_accumulator_workload),
            smoke_profile: Some(adapter.smoke_profile),
            proof_kind: Some(adapter.proof_kind),
            profile_digest: Some(adapter.profile_digest),
            accumulator_instance_digest: Some(adapter.accumulator_instance_digest),
            public_statement_digest: Some(adapter.public_statement_digest),
            whir_param_digest: Some(adapter.whir_param_digest),
            main_symbt3_relation_id: Some(adapter.main_symbt3_relation_id),
            main_symbt3_proof_digest: Some(adapter.main_symbt3_proof_digest),
            old_accumulator_digest: Some(adapter.old_accumulator_digest),
            new_accumulator_digest: Some(adapter.new_accumulator_digest),
            batch_manifest_root: Some(adapter.batch_manifest_root),
            manifest_oracle_root: Some(adapter.manifest_oracle_root),
            native_message_roots_digest: Some(adapter.native_message_roots_digest),
            batch_size: Some(adapter.batch_size),
            active_count: Some(adapter.active_count),
            main_whir_num_vars: Some(adapter.main_whir_num_vars),
            main_oracle_len: Some(adapter.main_oracle_len),
            top_level_whir_proof_count: Some(adapter.top_level_whir_proof_count),
            family_columnar_subproof_count: Some(adapter.family_columnar_subproof_count),
            backend_table_count: Some(adapter.backend_table_count),
            accumulator_transition_claims: Some(adapter.accumulator_transition_claims),
            source_r1cs_residual_verifier_evaluations: Some(
                adapter.source_r1cs_residual_verifier_evaluations,
            ),
        }
    }
}

#[must_use]
fn symbt3_native_accumulator_k6a_workload_adapter_from_parts(
    parts: Symbt3NativeAccumulatorK6aWorkloadAdapterParts,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: parts.workload_kind?,
        full_accumulator_workload: parts.full_accumulator_workload?,
        smoke_profile: parts.smoke_profile?,
        proof_kind: parts.proof_kind?,
        profile_digest: parts.profile_digest?,
        accumulator_instance_digest: parts.accumulator_instance_digest?,
        public_statement_digest: parts.public_statement_digest?,
        whir_param_digest: parts.whir_param_digest?,
        main_symbt3_relation_id: parts.main_symbt3_relation_id?,
        main_symbt3_proof_digest: parts.main_symbt3_proof_digest?,
        old_accumulator_digest: parts.old_accumulator_digest?,
        new_accumulator_digest: parts.new_accumulator_digest?,
        batch_manifest_root: parts.batch_manifest_root?,
        manifest_oracle_root: parts.manifest_oracle_root?,
        native_message_roots_digest: parts.native_message_roots_digest?,
        batch_size: parts.batch_size?,
        active_count: parts.active_count?,
        main_whir_num_vars: parts.main_whir_num_vars?,
        main_oracle_len: parts.main_oracle_len?,
        top_level_whir_proof_count: parts.top_level_whir_proof_count?,
        family_columnar_subproof_count: parts.family_columnar_subproof_count?,
        backend_table_count: parts.backend_table_count?,
        accumulator_transition_claims: parts.accumulator_transition_claims?,
        source_r1cs_residual_verifier_evaluations: parts
            .source_r1cs_residual_verifier_evaluations?,
    };
    if adapter.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || !adapter.full_accumulator_workload
        || adapter.smoke_profile
        || adapter.proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || adapter.profile_digest == [0u8; 32]
        || adapter.accumulator_instance_digest == [0u8; 32]
        || adapter.public_statement_digest == [0u8; 32]
        || adapter.whir_param_digest == [0u8; 32]
        || adapter.main_symbt3_relation_id == [0u8; 32]
        || adapter.main_symbt3_proof_digest == [0u8; 32]
        || adapter.old_accumulator_digest == [0u8; 32]
        || adapter.new_accumulator_digest == [0u8; 32]
        || adapter.batch_manifest_root == [0u8; 32]
        || adapter.manifest_oracle_root == [0u8; 32]
        || adapter.native_message_roots_digest == [0u8; 32]
        || adapter.batch_size == 0
        || adapter.active_count == 0
        || adapter.active_count > adapter.batch_size
        || adapter.main_oracle_len == 0
        || adapter.top_level_whir_proof_count != 1
        || adapter.family_columnar_subproof_count != 0
        || adapter.backend_table_count == 0
        || adapter.accumulator_transition_claims == 0
        || adapter.source_r1cs_residual_verifier_evaluations == 0
    {
        return None;
    }
    Some(adapter)
}

#[must_use]
pub fn symbt3_native_accumulator_k6a_workload_adapter(
    input: Symbt3NativeAccumulatorK6aWorkloadAdapterInput<'_>,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    match input {
        Symbt3NativeAccumulatorK6aWorkloadAdapterInput::FullK6a {
            vk,
            profile,
            accumulator_instance,
            proof_kind,
            proof,
        } => symbt3_native_accumulator_k6a_workload_adapter_from_verified_proof(
            vk,
            profile,
            accumulator_instance,
            proof_kind,
            proof,
        ),
        Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke { instance, proof } => {
            let _ = instance.public_statement_digest();
            if proof.workload_kind == Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1
                || proof.counters.smoke_profile
                || !proof.counters.full_accumulator_workload
            {
                return None;
            }
            None
        }
    }
}

#[must_use]
pub fn prove_symbt3_native_accumulator_k6a_workload_adapter(
    pk: &WhirProvingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
) -> Option<(WhirProof, Symbt3NativeAccumulatorK6aWorkloadAdapter)> {
    let proof = WhirSnark::prove_public_symbt3_accumulator_non_zk_integrity(
        pk,
        profile,
        accumulator_instance,
        witness,
    )?;
    let relation = symbt3_k6a_relation_from_context(pk.relation.context.as_ref()?)?;
    let adapter = symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_proof(
        &relation,
        profile,
        accumulator_instance,
        ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        &proof,
    )?;
    Some((proof, adapter))
}

#[must_use]
pub fn symbt3_native_accumulator_k6a_workload_adapter_from_verified_proof(
    vk: &WhirVerifyingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    proof: &WhirProof,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if !WhirSnark::verify_public_symbt3_accumulator_non_zk_integrity(
        vk,
        profile,
        accumulator_instance,
        proof_kind,
        proof,
    ) {
        return None;
    }
    let relation = symbt3_k6a_relation_from_context(vk.relation.context.as_ref()?)?;
    symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_proof(
        &relation,
        profile,
        accumulator_instance,
        proof_kind,
        proof,
    )
}

#[must_use]
pub fn symbt3_native_accumulator_k6a_workload_adapter_matches(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    vk: &WhirVerifyingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    proof: &WhirProof,
) -> bool {
    symbt3_native_accumulator_k6a_workload_adapter_from_verified_proof(
        vk,
        profile,
        accumulator_instance,
        proof_kind,
        proof,
    )
    .is_some_and(|expected| expected == *adapter)
}

