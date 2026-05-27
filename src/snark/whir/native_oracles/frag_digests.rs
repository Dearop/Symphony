pub fn native_oracle_spec_digest(specs: &[WhirNativeOracleSpec]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_ORACLE_SPECS_V1");
    push_u64(&mut bytes, specs.len() as u64);
    for spec in specs {
        push_bytes(&mut bytes, &spec.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_oracle_descriptor_digest(descriptors: &[WhirNativeOracleDescriptor]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_ORACLE_DESCRIPTORS_V1");
    push_u64(&mut bytes, descriptors.len() as u64);
    for descriptor in descriptors {
        push_bytes(&mut bytes, &descriptor.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_multi_oracle_envelope_digest(proof: &WhirNativeMultiOracleProof) -> Digest32 {
    digest_bytes(&proof.metadata_canonical_bytes())
}

#[must_use]
pub fn native_oracle_eval_claims_digest(claims: &[WhirNativeOracleEvalClaim]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_ORACLE_EVAL_CLAIMS_V1");
    push_u64(&mut bytes, claims.len() as u64);
    for claim in claims {
        push_bytes(&mut bytes, &claim.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_oracle_point_digest(point: &[BabyBear]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_ORACLE_POINT_V1");
    push_babybear_vec(&mut bytes, point);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_tuple_leaf_layout_digest(layout: &Symbt3TupleLeafLayoutV1) -> Digest32 {
    digest_bytes(&layout.canonical_bytes())
}

fn symbt3_tuple_leaf_repetition_log_size(rlc_repetition_count: usize) -> Option<usize> {
    if rlc_repetition_count == 0 || !rlc_repetition_count.is_power_of_two() {
        return None;
    }
    Some(rlc_repetition_count.trailing_zeros() as usize)
}

#[must_use]
pub fn symbt3_tuple_leaf_rlc_layout_domain_digest(
    mode: Symbt3NativeMultiOracleMode,
    descriptor_digest: Digest32,
    logical_oracle_count: usize,
    num_vars: usize,
    rlc_repetition_count: usize,
    rlc_batching_bits_per_repetition: usize,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_TUPLE_LEAF_REPEATED_RLC_LAYOUT_DOMAIN_V1",
    );
    push_bytes(&mut bytes, &mode.canonical_bytes());
    push_digest(&mut bytes, &descriptor_digest);
    push_u64(&mut bytes, logical_oracle_count as u64);
    push_u64(&mut bytes, num_vars as u64);
    push_u64(&mut bytes, rlc_repetition_count as u64);
    push_u64(&mut bytes, rlc_batching_bits_per_repetition as u64);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
    mode: Symbt3NativeMultiOracleMode,
    descriptor_digest: Digest32,
    logical_oracle_count: usize,
    num_vars: usize,
    rlc_repetition_count: usize,
    rlc_batching_bits_per_repetition: usize,
) -> Digest32 {
    let layout = Symbt3TupleLeafLayoutV1 {
        version: SYMBT3_TUPLE_LEAF_LAYOUT_VERSION,
        mode,
        logical_oracle_count,
        num_vars,
        packing_challenge_digest: symbt3_tuple_leaf_rlc_layout_domain_digest(
            mode,
            descriptor_digest,
            logical_oracle_count,
            num_vars,
            rlc_repetition_count,
            rlc_batching_bits_per_repetition,
        ),
        descriptor_digest,
    };
    symbt3_tuple_leaf_layout_digest(&layout)
}

#[must_use]
pub fn symbt3_tuple_leaf_packing_challenges(
    mode: Symbt3NativeMultiOracleMode,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptor_digest: Digest32,
    logical_oracle_count: usize,
    num_vars: usize,
) -> Option<Vec<BabyBear>> {
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        mode,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
        1,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    );
    symbt3_tuple_leaf_packing_challenges_for_repetition(
        mode,
        0,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        logical_oracle_count,
        num_vars,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn symbt3_tuple_leaf_packing_challenges_for_repetition(
    mode: Symbt3NativeMultiOracleMode,
    repetition_index: usize,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptor_digest: Digest32,
    tuple_leaf_layout_digest: Digest32,
    logical_oracle_count: usize,
    num_vars: usize,
) -> Option<Vec<BabyBear>> {
    if logical_oracle_count == 0 || num_vars == 0 {
        return None;
    }
    let mut transcript = Vec::new();
    push_bytes(
        &mut transcript,
        SYMBT3_RLC_TUPLE_LEAF_PACKING_DOMAIN.as_bytes(),
    );
    push_u64(&mut transcript, repetition_index as u64);
    push_digest(&mut transcript, &proof_relation_id);
    push_digest(&mut transcript, &public_statement_digest);
    push_digest(&mut transcript, &whir_param_digest);
    push_digest(&mut transcript, &descriptor_digest);
    push_digest(&mut transcript, &tuple_leaf_layout_digest);
    push_bytes(
        &mut transcript,
        symbt3_tuple_leaf_layout_name(mode).as_bytes(),
    );
    push_u64(&mut transcript, logical_oracle_count as u64);
    push_u64(&mut transcript, num_vars as u64);
    Some(
        (0..logical_oracle_count)
            .map(|index| derive_challenge(&transcript, index, b"tuple-leaf-packing"))
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn symbt3_tuple_leaf_packing_challenges_for_repetitions(
    mode: Symbt3NativeMultiOracleMode,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptor_digest: Digest32,
    tuple_leaf_layout_digest: Digest32,
    logical_oracle_count: usize,
    num_vars: usize,
    rlc_repetition_count: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    (0..rlc_repetition_count)
        .map(|repetition_index| {
            symbt3_tuple_leaf_packing_challenges_for_repetition(
                mode,
                repetition_index,
                proof_relation_id,
                public_statement_digest,
                whir_param_digest,
                descriptor_digest,
                tuple_leaf_layout_digest,
                logical_oracle_count,
                num_vars,
            )
        })
        .collect()
}

#[must_use]
pub fn symbt3_tuple_leaf_packing_challenge_digest(challenges: &[BabyBear]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_MULTI_ORACLE_PACKING_CHALLENGES_V1",
    );
    push_babybear_vec(&mut bytes, challenges);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_tuple_leaf_repeated_packing_challenge_digest(
    repeated_challenges: &[Vec<BabyBear>],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_MULTI_ORACLE_REPEATED_PACKING_CHALLENGES_V1",
    );
    push_u64(&mut bytes, repeated_challenges.len() as u64);
    for challenges in repeated_challenges {
        push_babybear_vec(&mut bytes, challenges);
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_tuple_leaf_pack_values(
    challenges: &[BabyBear],
    values: &[BabyBear],
) -> Option<BabyBear> {
    if challenges.len() != values.len() || challenges.is_empty() {
        return None;
    }
    Some(
        challenges
            .iter()
            .zip(values.iter())
            .fold(BabyBear::ZERO, |acc, (&gamma, &value)| acc + gamma * value),
    )
}

#[must_use]
pub fn symbt3_tuple_leaf_pack_evaluations(
    challenges: &[BabyBear],
    logical_evaluations: &[Vec<BabyBear>],
) -> Option<Vec<BabyBear>> {
    if challenges.len() != logical_evaluations.len()
        || challenges.is_empty()
        || logical_evaluations.is_empty()
    {
        return None;
    }
    let len = logical_evaluations.first()?.len();
    if len == 0
        || logical_evaluations
            .iter()
            .any(|evaluations| evaluations.len() != len)
    {
        return None;
    }
    let mut packed = vec![BabyBear::ZERO; len];
    for (&gamma, evaluations) in challenges.iter().zip(logical_evaluations.iter()) {
        for (packed_value, &logical_value) in packed.iter_mut().zip(evaluations.iter()) {
            *packed_value += gamma * logical_value;
        }
    }
    Some(packed)
}

#[must_use]
pub fn derive_same_domain_tuple_leaf_opening_point(
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptor_digest: Digest32,
    tuple_leaf_layout_digest: Digest32,
    claim_kind: WhirNativeEvalClaimKind,
    num_vars: usize,
) -> Vec<BabyBear> {
    derive_same_domain_tuple_leaf_opening_point_for_repetition(
        0,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        claim_kind,
        num_vars,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn derive_same_domain_tuple_leaf_opening_point_for_repetition(
    repetition_index: usize,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptor_digest: Digest32,
    tuple_leaf_layout_digest: Digest32,
    claim_kind: WhirNativeEvalClaimKind,
    num_vars: usize,
) -> Vec<BabyBear> {
    let mut transcript = Vec::new();
    push_bytes(
        &mut transcript,
        SYMBT3_RLC_TUPLE_LEAF_PACKING_DOMAIN.as_bytes(),
    );
    push_bytes(&mut transcript, b"zeta");
    push_u64(&mut transcript, repetition_index as u64);
    push_digest(&mut transcript, &proof_relation_id);
    push_digest(&mut transcript, &public_statement_digest);
    push_digest(&mut transcript, &whir_param_digest);
    push_digest(&mut transcript, &descriptor_digest);
    push_digest(&mut transcript, &tuple_leaf_layout_digest);
    encode_claim_kind(&mut transcript, claim_kind);
    (0..num_vars)
        .map(|index| derive_challenge(&transcript, index, b"tuple-leaf-opening-point"))
        .collect()
}

#[must_use]
pub fn native_oracle_descriptor_bytes_len(descriptors: &[WhirNativeOracleDescriptor]) -> usize {
    descriptors
        .iter()
        .map(|descriptor| descriptor.canonical_bytes().len())
        .sum()
}

/// Build deterministic N1 benchmark oracle specs with strictly sorted ids.
///
/// These helpers are intentionally protocol-neutral: they exercise the native
/// multi-oracle WHIR envelope without opting into K6a, N6b, or any product
/// route.
#[must_use]
pub fn native_oracle_root_policy_digest(root_policy: NativeOracleRootPolicy) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_ORACLE_ROOT_POLICY_DIGEST_V1");
    push_bytes(&mut bytes, &root_policy.canonical_bytes());
    digest_bytes(&bytes)
}

#[must_use]
pub fn manifest_commitment_policy_digest(policy: ManifestCommitmentPolicy) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_MANIFEST_COMMITMENT_POLICY_DIGEST_V1");
    push_bytes(&mut bytes, &policy.canonical_bytes());
    digest_bytes(&bytes)
}

#[must_use]
pub fn source_commitment_policy_digest(policy: SourceCommitmentPolicy) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_SOURCE_COMMITMENT_POLICY_DIGEST_V1");
    push_bytes(&mut bytes, &policy.canonical_bytes());
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_message_oracle_policy_digest(policy: Symbt3MessageOraclePolicy) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_MESSAGE_ORACLE_POLICY_DIGEST_V1");
    push_bytes(&mut bytes, &policy.canonical_bytes());
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_native_oracle_profile_digest(profile: Symbt3NativeOracleProfile) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_ORACLE_PROFILE_DIGEST_V1");
    push_bytes(&mut bytes, &profile.canonical_bytes());
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_manifest_source_membership_policy_digest() -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_MANIFEST_SOURCE_MEMBERSHIP_POLICY_V1",
    );
    push_bytes(
        &mut bytes,
        &ManifestCommitmentPolicy::NativeManifestOracleOpeningV1.canonical_bytes(),
    );
    push_bytes(
        &mut bytes,
        &SourceCommitmentPolicy::NativeSourceOracleOpeningV1.canonical_bytes(),
    );
    push_bytes(&mut bytes, b"NonZK");
    push_bytes(
        &mut bytes,
        SYMBT3_N2_MANIFEST_SOURCE_EQUALITY_DOMAIN.as_bytes(),
    );
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_batch_manifest_root(
    manifest_layout_digest: Digest32,
    manifest_oracle_root: Digest32,
    native_oracle_root_policy_digest: Digest32,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_MANIFEST");
    push_digest(&mut bytes, &manifest_layout_digest);
    push_digest(&mut bytes, &manifest_oracle_root);
    push_digest(&mut bytes, &native_oracle_root_policy_digest);
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_manifest_source_challenge_binding_digest(
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    batch_manifest_root: Digest32,
    root_policy: NativeOracleRootPolicy,
    manifest_policy: ManifestCommitmentPolicy,
    source_policy: SourceCommitmentPolicy,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_MANIFEST_SOURCE_EQUALITY_BINDING_V1",
    );
    push_digest(&mut bytes, &manifest_layout_digest);
    push_digest(&mut bytes, &source_layout_digest);
    push_digest(&mut bytes, &batch_manifest_root);
    push_digest(&mut bytes, &native_oracle_root_policy_digest(root_policy));
    push_digest(
        &mut bytes,
        &manifest_commitment_policy_digest(manifest_policy),
    );
    push_digest(&mut bytes, &source_commitment_policy_digest(source_policy));
    push_digest(
        &mut bytes,
        &native_manifest_source_membership_policy_digest(),
    );
    digest_bytes(&bytes)
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn native_folding_integrity_binding_digest(
    symbt3_relation_id: Digest32,
    symbt3_public_statement_digest: Digest32,
    profile_digest: Digest32,
    whir_param_digest: Digest32,
    native_oracle_descriptor_digest: Digest32,
    native_message_roots_digest: Digest32,
    manifest_oracle_root: Digest32,
    source_oracle_root: Digest32,
    batch_manifest_root: Digest32,
    source_column_layout_digest: Digest32,
    message_oracle_policy_digest: Digest32,
    manifest_commitment_policy_digest: Digest32,
    active_count: u64,
    batch_size: u64,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_FOLDING_INTEGRITY_BINDING_V1");
    push_digest(&mut bytes, &symbt3_relation_id);
    push_digest(&mut bytes, &symbt3_public_statement_digest);
    push_digest(&mut bytes, &profile_digest);
    push_digest(&mut bytes, &whir_param_digest);
    push_digest(&mut bytes, &native_oracle_descriptor_digest);
    push_digest(&mut bytes, &native_message_roots_digest);
    push_digest(&mut bytes, &manifest_oracle_root);
    push_digest(&mut bytes, &source_oracle_root);
    push_digest(&mut bytes, &batch_manifest_root);
    push_digest(&mut bytes, &source_column_layout_digest);
    push_digest(&mut bytes, &message_oracle_policy_digest);
    push_digest(&mut bytes, &manifest_commitment_policy_digest);
    push_u64(&mut bytes, active_count);
    push_u64(&mut bytes, batch_size);
    digest_bytes(&bytes)
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn native_accumulator_authority_binding_digest(
    workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    profile_digest: Digest32,
    accumulator_instance_digest: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    main_symbt3_relation_id: Digest32,
    main_symbt3_proof_digest: Digest32,
    rlc_tuple_leaf_root: Digest32,
    rlc_tuple_leaf_layout_digest: Digest32,
    native_oracle_descriptor_digest: Digest32,
    native_message_roots_digest: Digest32,
    manifest_oracle_root: Digest32,
    source_oracle_root: Digest32,
    batch_manifest_root: Digest32,
    old_accumulator_digest: Digest32,
    new_accumulator_digest: Digest32,
    batch_size: u64,
    active_count: u64,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_BINDING_V1",
    );
    push_bytes(&mut bytes, &workload_kind.canonical_bytes());
    push_digest(&mut bytes, &profile_digest);
    push_digest(&mut bytes, &accumulator_instance_digest);
    push_digest(&mut bytes, &public_statement_digest);
    push_digest(&mut bytes, &whir_param_digest);
    push_digest(&mut bytes, &main_symbt3_relation_id);
    push_digest(&mut bytes, &main_symbt3_proof_digest);
    push_digest(&mut bytes, &rlc_tuple_leaf_root);
    push_digest(&mut bytes, &rlc_tuple_leaf_layout_digest);
    push_digest(&mut bytes, &native_oracle_descriptor_digest);
    push_digest(&mut bytes, &native_message_roots_digest);
    push_digest(&mut bytes, &manifest_oracle_root);
    push_digest(&mut bytes, &source_oracle_root);
    push_digest(&mut bytes, &batch_manifest_root);
    push_digest(&mut bytes, &old_accumulator_digest);
    push_digest(&mut bytes, &new_accumulator_digest);
    push_u64(&mut bytes, batch_size);
    push_u64(&mut bytes, active_count);
    digest_bytes(&bytes)
}
