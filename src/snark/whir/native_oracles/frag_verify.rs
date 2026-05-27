/// Verify the explicit N7 smoke native accumulator-authority route.
///
/// This is the smoke-profile native authority path, not the full K6a workload
/// and not the default product `verify_public` boundary.
#[must_use]
pub fn verify_symbt3_native_accumulator_authority_non_zk(
    vk: &WhirVerifyingKey,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    if proof.version != SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_PROOF_VERSION
        || proof.proof_kind != Symbt3NativeFoldingProofKind::Symbt3NativeAccumulatorAuthorityV1
        || proof.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1
        || !symbt3_native_folding_integrity_instance_shape_ok(instance)
        || proof.public_statement_digest != instance.public_statement_digest()
        || proof.accumulator_instance_digest
            != symbt3_native_accumulator_authority_instance_digest(instance)
        || proof.whir_param_digest != instance.whir_param_digest
        || proof.main_symbt3_relation_id != instance.symbt3_relation_id
        || proof.profile_digest
            != symbt3_native_oracle_profile_digest(
                Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1,
            )
        || proof.main_symbt3_proof_digest
            != symbt3_main_whir_proof_digest(&proof.main_symbt3_whir_proof)
        || proof.rlc_tuple_leaf_root != proof.rlc_tuple_leaf_multi_oracle_proof.packed_root
        || proof.rlc_tuple_leaf_layout_digest
            != proof
                .rlc_tuple_leaf_multi_oracle_proof
                .tuple_leaf_layout_digest
    {
        return false;
    }

    let Some(expected_counters) = native_accumulator_authority_counters(
        instance,
        &proof.rlc_tuple_leaf_multi_oracle_proof,
        &proof.main_symbt3_whir_proof,
        proof.workload_kind,
    ) else {
        return false;
    };
    if proof.counters != expected_counters {
        return false;
    }
    let metadata = symbt3_native_accumulator_authority_profile_metadata(instance, &proof.counters);
    if !profile_meets_native_accumulator_authority(&metadata)
        || !symbt3_native_accumulator_authority_semantics_ok(instance, proof)
    {
        return false;
    }
    if !whir_verify_same_domain_multi_oracle(
        vk,
        instance.symbt3_relation_id,
        proof.public_statement_digest,
        instance.whir_param_digest,
        &proof.rlc_tuple_leaf_multi_oracle_proof,
        &proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims,
    ) {
        return false;
    }

    <WhirSnark as BackendSnark>::verify(vk, &instance.main_instance, &proof.main_symbt3_whir_proof)
}

/// Build the explicit N7b full native wrapper proof.
///
/// N7b combines the real K6a workload with native tuple-leaf repeated-RLC
/// evidence and a wrapper binding digest. It remains an opt-in NonZK route and
/// does not replace the default product verifier.
pub fn prove_symbt3_native_accumulator_authority_full_non_zk(
    pk: &WhirProvingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
) -> Option<Symbt3N7bFullAuthorityProof> {
    let (k6a_main_proof, adapter) = prove_symbt3_native_accumulator_k6a_workload_adapter(
        pk,
        profile,
        accumulator_instance,
        witness,
    )?;
    let native_tuple_leaf = prove_symbt3_n7b_full_native_tuple_leaf_from_k6a(
        pk,
        accumulator_instance,
        witness,
        &adapter,
    )?;
    let wrapper = compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
        workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
        k6a_adapter: Some(adapter),
        native_tuple_leaf: Some(native_tuple_leaf),
        binding_digest: None,
        fallback_used: false,
    })
    .ok()?;
    Some(Symbt3N7bFullAuthorityProof {
        version: SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_WRAPPER_VERSION,
        proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        k6a_main_proof,
        wrapper,
    })
}

/// Verify the explicit N7b full native wrapper route and return a blocker report.
///
/// This is the full-workload native wrapper candidate around K6a plus native
/// tuple-leaf evidence. It is route-specific and remains separate from the
/// default product `verify_public` boundary.
#[must_use]
pub fn verify_symbt3_native_accumulator_authority_full_non_zk_report(
    vk: &WhirVerifyingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof: &Symbt3N7bFullAuthorityProof,
) -> Symbt3N7bFullAuthorityVerificationReport {
    if proof.version != SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_WRAPPER_VERSION
        || proof.proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || proof.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
    {
        return Symbt3N7bFullAuthorityVerificationReport::blocked(
            Symbt3N7bFullAuthorityBlocker::PublicCanonicalOrMonolithicAuthority,
        );
    }
    verify_symbt3_n7b_full_authority_wrapper_non_zk(
        &Symbt3N7bFullAuthorityVerificationContext {
            k6a_vk: vk,
            tuple_leaf_vk: vk,
            profile,
            accumulator_instance,
            proof_kind: proof.proof_kind,
            k6a_proof: &proof.k6a_main_proof,
        },
        &proof.wrapper,
    )
}

/// Verify the explicit N7b full native wrapper route.
///
/// This is the boolean convenience wrapper over
/// [`verify_symbt3_native_accumulator_authority_full_non_zk_report`]. It does
/// not dispatch to the default product verifier.
#[must_use]
pub fn verify_symbt3_native_accumulator_authority_full_non_zk(
    vk: &WhirVerifyingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof: &Symbt3N7bFullAuthorityProof,
) -> bool {
    verify_symbt3_native_accumulator_authority_full_non_zk_report(
        vk,
        profile,
        accumulator_instance,
        proof,
    )
    .ok
}

#[must_use]
pub fn symbt3_native_accumulator_authority_proof_size_hint(
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> usize {
    let main_sumcheck_bytes = proof.main_symbt3_whir_proof.sumcheck_rounds_3.len() * 3 * 8
        + proof.main_symbt3_whir_proof.sumcheck_rounds_4.len() * 4 * 8
        + proof.main_symbt3_whir_proof.linear_checks.len() * 64
        + proof.main_symbt3_whir_proof.whir_pcs_proof.rounds.len() * 256
        + 128;
    proof.metadata_canonical_bytes().len()
        + proof
            .rlc_tuple_leaf_multi_oracle_proof
            .metadata_canonical_bytes()
            .len()
        + 256
        + main_sumcheck_bytes
}

#[must_use]
pub fn symbt3_n7b_full_authority_proof_size_hint(proof: &Symbt3N7bFullAuthorityProof) -> usize {
    symbt3_n7b_full_authority_proof_canonical_bytes(proof)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

pub fn whir_verify_oracle_openings(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
    expected_claims: &[WhirNativeOracleEvalClaim],
) -> bool {
    whir_verify_oracle_openings_for_profile(
        vk,
        NativeOracleVerificationProfile::Infrastructure,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptors,
        proof,
        expected_claims,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn whir_verify_oracle_openings_with_counters(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
    expected_claims: &[WhirNativeOracleEvalClaim],
) -> WhirNativeOracleVerifyReport {
    whir_verify_oracle_openings_with_counters_for_profile(
        vk,
        NativeOracleVerificationProfile::Infrastructure,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptors,
        proof,
        expected_claims,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn whir_verify_oracle_openings_with_root_policy(
    vk: &WhirVerifyingKey,
    expected_root_policy: NativeOracleRootPolicy,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
    expected_claims: &[WhirNativeOracleEvalClaim],
) -> bool {
    verify_oracle_openings_inner(
        vk,
        NativeOracleVerificationProfile::Development,
        Some(expected_root_policy),
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptors,
        proof,
        expected_claims,
    )
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn whir_verify_oracle_openings_for_profile(
    vk: &WhirVerifyingKey,
    profile: NativeOracleVerificationProfile,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
    expected_claims: &[WhirNativeOracleEvalClaim],
) -> bool {
    whir_verify_oracle_openings_with_counters_for_profile(
        vk,
        profile,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptors,
        proof,
        expected_claims,
    )
    .ok
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn whir_verify_oracle_openings_with_counters_for_profile(
    vk: &WhirVerifyingKey,
    profile: NativeOracleVerificationProfile,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
    expected_claims: &[WhirNativeOracleEvalClaim],
) -> WhirNativeOracleVerifyReport {
    let start = Instant::now();
    let ok = verify_oracle_openings_inner(
        vk,
        profile,
        None,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptors,
        proof,
        expected_claims,
    );
    WhirNativeOracleVerifyReport {
        ok,
        counters: proof.counters.clone(),
        native_oracle_verify_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_oracle_openings_inner(
    vk: &WhirVerifyingKey,
    profile: NativeOracleVerificationProfile,
    expected_root_policy: Option<NativeOracleRootPolicy>,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
    expected_claims: &[WhirNativeOracleEvalClaim],
) -> bool {
    if let Some(expected_root_policy) = expected_root_policy {
        if proof.root_policy != expected_root_policy {
            return false;
        }
    }
    if proof.version != WHIR_NATIVE_MULTI_ORACLE_PROOF_VERSION
        || !native_oracle_root_policy_allowed_for_profile(proof.root_policy, profile)
        || proof.proof_relation_id != proof_relation_id
        || proof.public_statement_digest != public_statement_digest
        || proof.whir_param_digest != whir_param_digest
        || proof.descriptors != descriptors
        || proof.eval_claims != expected_claims
        || validate_descriptors(descriptors).is_err()
        || native_oracle_descriptor_digest(descriptors) != proof.native_oracle_descriptor_digest
        || native_oracle_eval_claims_digest(expected_claims)
            != proof.native_oracle_eval_claims_digest
        || native_multi_oracle_envelope_digest(proof) != proof.native_multi_oracle_envelope_digest
        || proof.counters
            != counters_for(
                descriptors,
                proof.eval_claims.len(),
                proof.pcs_openings.len(),
            )
    {
        return false;
    }

    let descriptor_by_id = descriptors
        .iter()
        .map(|descriptor| (descriptor.oracle_id, descriptor))
        .collect::<BTreeMap<_, _>>();
    let mut seen_pcs = BTreeSet::new();
    let mut points_by_oracle = BTreeMap::<u32, Vec<Vec<BabyBear>>>::new();
    let mut evals_by_oracle = BTreeMap::<u32, Vec<BabyBear>>::new();

    for (request_index, claim) in proof.eval_claims.iter().enumerate() {
        let Some(descriptor) = descriptor_by_id.get(&claim.oracle_id).copied() else {
            return false;
        };
        let point = derive_native_oracle_opening_point(
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            proof.native_oracle_descriptor_digest,
            proof.root_policy,
            descriptor,
            claim.claim_kind,
            request_index,
        );
        if native_oracle_point_digest(&point) != claim.point_digest {
            return false;
        }
        points_by_oracle
            .entry(claim.oracle_id)
            .or_default()
            .push(point);
        evals_by_oracle
            .entry(claim.oracle_id)
            .or_default()
            .push(claim.value);
    }

    if points_by_oracle.len() != descriptors.len()
        || evals_by_oracle.len() != descriptors.len()
        || proof.pcs_openings.len() != descriptors.len()
    {
        return false;
    }

    for opening in &proof.pcs_openings {
        if !seen_pcs.insert(opening.oracle_id) {
            return false;
        }
        let Some(descriptor) = descriptor_by_id.get(&opening.oracle_id).copied() else {
            return false;
        };
        if whir_pcs_initial_root_digest(&opening.proof, proof.root_policy) != Some(descriptor.root)
        {
            return false;
        }
        let Some(points) = points_by_oracle.get(&opening.oracle_id) else {
            return false;
        };
        let Some(values) = evals_by_oracle.get(&opening.oracle_id) else {
            return false;
        };
        if !whir_verify_opening_multi(
            &vk.seed,
            descriptor.num_vars,
            &opening.proof,
            points,
            values,
        ) {
            return false;
        }
    }

    seen_pcs.len() == descriptors.len()
}

#[must_use]
pub fn derive_native_oracle_opening_point(
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    native_oracle_descriptor_digest: Digest32,
    root_policy: NativeOracleRootPolicy,
    descriptor: &WhirNativeOracleDescriptor,
    claim_kind: WhirNativeEvalClaimKind,
    request_index: usize,
) -> Vec<BabyBear> {
    let mut transcript = Vec::new();
    push_bytes(
        &mut transcript,
        b"SYMBT3_NATIVE_ORACLE_OPENING_CHALLENGE_V1",
    );
    push_digest(&mut transcript, &proof_relation_id);
    push_digest(&mut transcript, &public_statement_digest);
    push_digest(&mut transcript, &whir_param_digest);
    push_digest(&mut transcript, &native_oracle_descriptor_digest);
    push_bytes(&mut transcript, &root_policy.canonical_bytes());
    encode_schedule(&mut transcript, &descriptor.opening_schedule);
    encode_claim_kind(&mut transcript, claim_kind);
    match &descriptor.opening_schedule {
        WhirNativeOpeningSchedule::SamePoint => {
            push_bytes(&mut transcript, b"SYMBT3_NATIVE_ORACLE_SAME_POINT_V1");
        }
        WhirNativeOpeningSchedule::PerOraclePoint => {
            push_u64(&mut transcript, request_index as u64);
            push_u32(&mut transcript, descriptor.oracle_id);
            push_bytes(&mut transcript, &descriptor.canonical_bytes());
        }
        WhirNativeOpeningSchedule::TranscriptDerived { domain_separator } => {
            push_bytes(&mut transcript, domain_separator.as_bytes());
        }
        WhirNativeOpeningSchedule::TranscriptDerivedWithBinding {
            domain_separator,
            binding_digest,
        } => {
            push_bytes(&mut transcript, domain_separator.as_bytes());
            push_digest(&mut transcript, binding_digest);
        }
    }
    (0..descriptor.num_vars)
        .map(|i| derive_challenge(&transcript, i, b"native-oracle-point"))
        .collect()
}

struct PreparedCommittedPrivateManifestWitness {
    public_views: Vec<Symbt3ManifestComponentPublicView>,
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    manifest_evals: Vec<BabyBear>,
    source_evals: Vec<BabyBear>,
    committed_private_component_count: usize,
}

fn prepare_committed_private_manifest_witness(
    components: &[Symbt3ManifestSourceComponentValues],
) -> Option<PreparedCommittedPrivateManifestWitness> {
    if components.is_empty() {
        return None;
    }
    let mut previous_component_id = None;
    let mut public_views = Vec::with_capacity(components.len());
    let mut manifest_evals = Vec::new();
    let mut source_evals = Vec::new();
    let mut committed_private_component_count = 0usize;
    for component in components {
        if component.manifest_values.is_empty()
            || component.manifest_values.len() != component.source_values.len()
        {
            return None;
        }
        if let Some(previous) = previous_component_id {
            if component.component_id <= previous {
                return None;
            }
        }
        previous_component_id = Some(component.component_id);
        if component.visibility == Symbt3ManifestVisibility::CommittedPrivateNonZk {
            committed_private_component_count += 1;
        }
        manifest_evals.extend_from_slice(&component.manifest_values);
        source_evals.extend_from_slice(&component.source_values);
        public_views.push(component.public_view()?);
    }
    let manifest_layout_digest =
        symbt3_manifest_oracle_layout_digest(WhirNativeOracleRole::Manifest, &public_views);
    let source_layout_digest =
        symbt3_manifest_oracle_layout_digest(WhirNativeOracleRole::Source, &public_views);
    Some(PreparedCommittedPrivateManifestWitness {
        public_views,
        manifest_layout_digest,
        source_layout_digest,
        manifest_evals,
        source_evals,
        committed_private_component_count,
    })
}

fn committed_private_manifest_public_statement_ok(
    statement: &Symbt3CommittedPrivateManifestPublicStatement,
) -> bool {
    if statement.components.is_empty()
        || statement.committed_private_component_count() == 0
        || statement.committed_private_public_bytes() != 0
        || !manifest_commitment_policy_allowed_for_native_manifest_membership(
            statement.manifest_policy,
        )
        || !source_commitment_policy_allowed_for_native_manifest_membership(statement.source_policy)
        || !native_oracle_root_policy_allowed_for_profile(
            statement.root_policy,
            NativeOracleVerificationProfile::NativeManifestAuthority,
        )
    {
        return false;
    }

    let mut previous_component_id = None;
    for component in &statement.components {
        if component.value_count == 0 {
            return false;
        }
        if let Some(previous) = previous_component_id {
            if component.component_id <= previous {
                return false;
            }
        }
        previous_component_id = Some(component.component_id);
        if !symbt3_manifest_visibility_allowed_for_policies(
            component.visibility,
            statement.zk_status,
            statement.manifest_policy,
            statement.source_policy,
        ) {
            return false;
        }
        match component.visibility {
            Symbt3ManifestVisibility::PublicBoundary => {
                if component.public_manifest_values.len() != component.value_count
                    || component.public_source_values.len() != component.value_count
                    || component.manifest_component_root
                        != symbt3_manifest_component_values_root(
                            WhirNativeOracleRole::Manifest,
                            component.component_id,
                            component.kind,
                            component.visibility,
                            component.layout_digest,
                            &component.public_manifest_values,
                        )
                    || component.source_component_root
                        != symbt3_manifest_component_values_root(
                            WhirNativeOracleRole::Source,
                            component.component_id,
                            component.kind,
                            component.visibility,
                            component.layout_digest,
                            &component.public_source_values,
                        )
                {
                    return false;
                }
            }
            Symbt3ManifestVisibility::CommittedPrivateNonZk => {
                if !component.public_manifest_values.is_empty()
                    || !component.public_source_values.is_empty()
                {
                    return false;
                }
            }
        }
    }

    statement.manifest_layout_digest
        == symbt3_manifest_oracle_layout_digest(
            WhirNativeOracleRole::Manifest,
            &statement.components,
        )
        && statement.source_layout_digest
            == symbt3_manifest_oracle_layout_digest(
                WhirNativeOracleRole::Source,
                &statement.components,
            )
        && statement.batch_manifest_root
            == native_batch_manifest_root(
                statement.manifest_layout_digest,
                statement.manifest_oracle_root,
                native_oracle_root_policy_digest(statement.root_policy),
            )
}

#[allow(clippy::too_many_arguments)]
fn native_round_message_semantics_challenges(
    challenge_context: &Symbt3NativeRoundChallengeContext,
    batch_log_size: usize,
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    expected_message_oracle_roots_digest: Digest32,
    expected_message_round_layouts_digest: Digest32,
    expected_message_oracle_policy_digest: Digest32,
    expected_policy: Symbt3MessageOraclePolicy,
    expected_root_policy: NativeOracleRootPolicy,
    proof: &Symbt3NativeRoundMessageOracleProof,
) -> Option<Vec<BabyBear>> {
    if !symbt3_message_oracle_policy_allowed_for_native_message_oracles(expected_policy)
        || proof.message_oracle_policy != expected_policy
        || proof.message_oracle_policy_digest != expected_message_oracle_policy_digest
        || proof.message_oracle_policy_digest
            != symbt3_message_oracle_policy_digest(expected_policy)
        || proof.message_oracle_roots_digest != expected_message_oracle_roots_digest
        || proof.message_round_layouts_digest != expected_message_round_layouts_digest
        || proof.message_round_layouts_digest != native_message_round_layouts_digest(round_layouts)
        || !native_oracle_root_policy_allowed_for_profile(
            expected_root_policy,
            NativeOracleVerificationProfile::NativeMessageAuthority,
        )
        || proof.native_proof.root_policy != expected_root_policy
        || proof.native_proof.descriptors.len() != round_layouts.len()
        || proof.native_proof.eval_claims.len() != round_layouts.len()
    {
        return None;
    }

    let expected_specs = build_native_message_oracle_specs(round_layouts, batch_log_size)?;
    if expected_specs.len() != proof.native_proof.descriptors.len() {
        return None;
    }
    for ((layout, spec), descriptor) in round_layouts
        .iter()
        .zip(expected_specs.iter())
        .zip(proof.native_proof.descriptors.iter())
    {
        if spec.descriptor_with_root(descriptor.root) != *descriptor
            || descriptor.oracle_id != layout.oracle_id
            || &descriptor.role
                != &(WhirNativeOracleRole::MessageRound {
                    round: layout.round_index,
                })
            || descriptor.layout_digest != layout.layout_digest
            || descriptor.num_vars != layout.total_num_vars
        {
            return None;
        }
    }

    if native_message_roots_digest(&proof.native_proof.descriptors)
        != expected_message_oracle_roots_digest
    {
        return None;
    }

    for (claim, layout) in proof
        .native_proof
        .eval_claims
        .iter()
        .zip(round_layouts.iter())
    {
        if claim.oracle_id != layout.oracle_id
            || claim.claim_kind != WhirNativeEvalClaimKind::MessageView
        {
            return None;
        }
    }

    let round_challenges = derive_native_round_challenges(
        &proof.native_proof.descriptors,
        round_layouts,
        challenge_context,
    )?;
    if proof.round_challenges != round_challenges {
        return None;
    }
    Some(round_challenges)
}

#[allow(clippy::too_many_arguments)]
fn native_manifest_source_semantics_ok(
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    batch_manifest_root: Digest32,
    manifest_policy: ManifestCommitmentPolicy,
    source_policy: SourceCommitmentPolicy,
    expected_root_policy: NativeOracleRootPolicy,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
) -> bool {
    if !manifest_commitment_policy_allowed_for_native_manifest_membership(manifest_policy)
        || !source_commitment_policy_allowed_for_native_manifest_membership(source_policy)
        || !native_oracle_root_policy_allowed_for_profile(
            expected_root_policy,
            NativeOracleVerificationProfile::NativeManifestAuthority,
        )
        || proof.root_policy != expected_root_policy
        || proof.descriptors != descriptors
        || descriptors.len() != 2
        || proof.eval_claims.len() != 2
    {
        return false;
    }

    let manifest_descriptor = &descriptors[0];
    let source_descriptor = &descriptors[1];
    if manifest_descriptor.oracle_id != SYMBT3_N2_MANIFEST_ORACLE_ID
        || source_descriptor.oracle_id != SYMBT3_N2_SOURCE_ORACLE_ID
        || manifest_descriptor.role != WhirNativeOracleRole::Manifest
        || source_descriptor.role != WhirNativeOracleRole::Source
        || manifest_descriptor.layout_digest != manifest_layout_digest
        || source_descriptor.layout_digest != source_layout_digest
        || manifest_descriptor.num_vars == 0
        || manifest_descriptor.num_vars != source_descriptor.num_vars
    {
        return false;
    }

    let expected_batch_manifest_root = native_batch_manifest_root(
        manifest_layout_digest,
        manifest_descriptor.root,
        native_oracle_root_policy_digest(expected_root_policy),
    );
    if batch_manifest_root != expected_batch_manifest_root {
        return false;
    }

    let Some(expected_specs) = build_n2_native_manifest_source_oracle_specs(
        manifest_layout_digest,
        source_layout_digest,
        manifest_descriptor.num_vars,
        source_descriptor.num_vars,
        batch_manifest_root,
        expected_root_policy,
    ) else {
        return false;
    };
    if expected_specs[0].descriptor_with_root(manifest_descriptor.root) != *manifest_descriptor
        || expected_specs[1].descriptor_with_root(source_descriptor.root) != *source_descriptor
    {
        return false;
    }

    let manifest_claim = &proof.eval_claims[0];
    let source_claim = &proof.eval_claims[1];
    manifest_claim.oracle_id == SYMBT3_N2_MANIFEST_ORACLE_ID
        && source_claim.oracle_id == SYMBT3_N2_SOURCE_ORACLE_ID
        && manifest_claim.claim_kind == WhirNativeEvalClaimKind::EqualitySide
        && source_claim.claim_kind == WhirNativeEvalClaimKind::EqualitySide
        && manifest_claim.point_digest == source_claim.point_digest
        && manifest_claim.value == source_claim.value
}

fn symbt3_native_folding_integrity_instance_shape_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
) -> bool {
    if instance.batch_size == 0
        || instance.active_count == 0
        || instance.active_count > instance.batch_size
        || instance.batch_axis_log_size >= u64::BITS as usize
        || instance.round_layouts.is_empty()
        || instance.backend_table_count != 1
        || instance.accumulator_transition_claims != 1
        || instance.main_instance.is_empty()
    {
        return false;
    }
    let expected_batch_size = 1u64 << instance.batch_axis_log_size;
    instance.batch_size == expected_batch_size
        && build_native_message_oracle_specs(&instance.round_layouts, instance.batch_axis_log_size)
            .is_some()
}

fn symbt3_native_folding_integrity_public_route_ok(
    public_profile: &Symbt3NativeFoldingIntegrityPublicProfile,
    instance: &Symbt3NativeFoldingIntegrityInstance,
) -> bool {
    let route_status_ok = symbt3_native_folding_integrity_public_route_selected(public_profile);
    let zk_status_ok = public_profile.zk_status == instance.zk_status
        && matches!(
            public_profile.zk_status,
            Symbt3ZkStatus::NonZkIntegrityOnly | Symbt3ZkStatus::ExplicitNonZkResearch
        );

    route_status_ok
        && public_profile.product_accepts_native_non_zk_folding_integrity
        && zk_status_ok
        && !public_profile.k5_masking_required
        && !public_profile.allow_monolithic_fallback
        && !instance.monolithic_fallback
        && !instance.product_default_route_attempted
        && !instance.product_eligible
        && !instance.native_product_route_version_exists
}

fn native_folding_message_descriptors(
    proof: &WhirNativeMultiOracleProof,
) -> Option<&[WhirNativeOracleDescriptor]> {
    if proof.descriptors.len() < 2 {
        return None;
    }
    Some(&proof.descriptors[2..])
}

fn native_folding_integrity_counters(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    native_proof: &WhirNativeMultiOracleProof,
) -> Option<Symbt3NativeFoldingIntegrityCounters> {
    let round_count = instance.round_layouts.len();
    let expected_native_counters = counters_for(
        &native_proof.descriptors,
        native_proof.eval_claims.len(),
        native_proof.pcs_openings.len(),
    );
    if native_proof.counters != expected_native_counters {
        return None;
    }
    Some(Symbt3NativeFoldingIntegrityCounters {
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        backend_table_count: instance.backend_table_count,
        native_oracle_count: native_proof.descriptors.len(),
        native_manifest_source_oracle_count: 2,
        native_message_oracle_count: round_count,
        native_oracle_eval_claim_count: native_proof.eval_claims.len(),
        native_oracle_pcs_opening_count: native_proof.pcs_openings.len(),
        native_oracle_descriptor_bytes: native_oracle_descriptor_bytes_len(
            &native_proof.descriptors,
        ),
        message_to_trace_binding_count: 0,
        accumulator_transition_claims: instance.accumulator_transition_claims,
    })
}

fn symbt3_native_folding_integrity_semantics_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    symbt3_native_folding_integrity_manifest_source_semantics_ok(instance, proof)
        && symbt3_native_folding_integrity_message_semantics_ok(instance, proof)
        && symbt3_native_folding_integrity_binding_ok(instance, proof)
}

fn symbt3_native_folding_integrity_manifest_source_semantics_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    let native_proof = &proof.native_oracle_proof;
    if native_proof.root_policy != instance.root_policy
        || native_proof.descriptors.len() < 2
        || native_proof.eval_claims.len() < 2
        || !manifest_commitment_policy_allowed_for_native_manifest_membership(
            instance.manifest_policy,
        )
        || !source_commitment_policy_allowed_for_native_manifest_membership(instance.source_policy)
        || !native_oracle_root_policy_allowed_for_profile(
            instance.root_policy,
            NativeOracleVerificationProfile::NativeManifestAuthority,
        )
    {
        return false;
    }

    let manifest_descriptor = &native_proof.descriptors[0];
    let source_descriptor = &native_proof.descriptors[1];
    if manifest_descriptor.oracle_id != SYMBT3_N2_MANIFEST_ORACLE_ID
        || source_descriptor.oracle_id != SYMBT3_N2_SOURCE_ORACLE_ID
        || manifest_descriptor.role != WhirNativeOracleRole::Manifest
        || source_descriptor.role != WhirNativeOracleRole::Source
        || manifest_descriptor.layout_digest != instance.manifest_layout_digest
        || source_descriptor.layout_digest != instance.source_layout_digest
        || manifest_descriptor.num_vars == 0
        || manifest_descriptor.num_vars != source_descriptor.num_vars
        || proof.manifest_oracle_root != manifest_descriptor.root
        || proof.source_oracle_root != source_descriptor.root
        || proof.batch_manifest_root
            != native_batch_manifest_root(
                instance.manifest_layout_digest,
                manifest_descriptor.root,
                native_oracle_root_policy_digest(instance.root_policy),
            )
    {
        return false;
    }

    let Some(expected_specs) = build_n2_native_manifest_source_oracle_specs(
        instance.manifest_layout_digest,
        instance.source_layout_digest,
        manifest_descriptor.num_vars,
        source_descriptor.num_vars,
        proof.batch_manifest_root,
        instance.root_policy,
    ) else {
        return false;
    };
    if expected_specs[0].descriptor_with_root(manifest_descriptor.root) != *manifest_descriptor
        || expected_specs[1].descriptor_with_root(source_descriptor.root) != *source_descriptor
    {
        return false;
    }

    let manifest_claim = &native_proof.eval_claims[0];
    let source_claim = &native_proof.eval_claims[1];
    manifest_claim.oracle_id == SYMBT3_N2_MANIFEST_ORACLE_ID
        && source_claim.oracle_id == SYMBT3_N2_SOURCE_ORACLE_ID
        && manifest_claim.claim_kind == WhirNativeEvalClaimKind::EqualitySide
        && source_claim.claim_kind == WhirNativeEvalClaimKind::EqualitySide
        && manifest_claim.point_digest == source_claim.point_digest
        && manifest_claim.value == source_claim.value
}

fn symbt3_native_folding_integrity_message_semantics_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    let native_proof = &proof.native_oracle_proof;
    let round_count = instance.round_layouts.len();
    if native_proof.descriptors.len() != 2 + round_count
        || native_proof.eval_claims.len() != 2 + round_count
        || proof.counters.native_oracle_count != 2 + round_count
        || proof.counters.native_message_oracle_count != round_count
        || proof.counters.native_oracle_pcs_opening_count != 2 + round_count
        || !symbt3_message_oracle_policy_allowed_for_native_message_oracles(
            instance.message_oracle_policy,
        )
        || proof.message_oracle_policy_digest
            != symbt3_message_oracle_policy_digest(instance.message_oracle_policy)
    {
        return false;
    }

    let Some(message_descriptors) = native_folding_message_descriptors(native_proof) else {
        return false;
    };
    if proof.native_message_roots_digest != native_message_roots_digest(message_descriptors) {
        return false;
    }
    let Some(expected_specs) =
        build_native_message_oracle_specs(&instance.round_layouts, instance.batch_axis_log_size)
    else {
        return false;
    };
    for ((layout, spec), descriptor) in instance
        .round_layouts
        .iter()
        .zip(expected_specs.iter())
        .zip(message_descriptors.iter())
    {
        if spec.descriptor_with_root(descriptor.root) != *descriptor
            || descriptor.oracle_id != layout.oracle_id
            || descriptor.role
                != (WhirNativeOracleRole::MessageRound {
                    round: layout.round_index,
                })
            || descriptor.layout_digest != layout.layout_digest
            || descriptor.num_vars != layout.total_num_vars
        {
            return false;
        }
    }

    for (claim, layout) in native_proof.eval_claims[2..]
        .iter()
        .zip(instance.round_layouts.iter())
    {
        if claim.oracle_id != layout.oracle_id
            || claim.claim_kind != WhirNativeEvalClaimKind::MessageView
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

fn symbt3_native_folding_integrity_binding_ok(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    proof.binding_digest
        == native_folding_integrity_binding_digest(
            instance.symbt3_relation_id,
            proof.public_statement_digest,
            proof.profile_digest,
            instance.whir_param_digest,
            proof.native_oracle_descriptor_digest,
            proof.native_message_roots_digest,
            proof.manifest_oracle_root,
            proof.source_oracle_root,
            proof.batch_manifest_root,
            instance.source_column_layout_digest,
            proof.message_oracle_policy_digest,
            proof.manifest_commitment_policy_digest,
            instance.active_count,
            instance.batch_size,
        )
}

struct Symbt3NativeAuthorityTupleLeafInputs {
    specs: Vec<WhirNativeOracleSpec>,
    evaluations: Vec<Vec<BabyBear>>,
    eval_requests: Vec<WhirNativeEvalRequest>,
    manifest_oracle_root: Digest32,
    source_oracle_root: Digest32,
    batch_manifest_root: Digest32,
    native_message_roots: Vec<Digest32>,
    message_descriptors: Vec<WhirNativeOracleDescriptor>,
    native_oracle_descriptor_digest: Digest32,
    native_message_roots_digest: Digest32,
    packed_root: Digest32,
}

fn build_symbt3_native_accumulator_authority_tuple_leaf_inputs(
    seed: &[u8; 32],
    instance: &Symbt3NativeFoldingIntegrityInstance,
    witness: &Symbt3NativeFoldingIntegrityWitness,
) -> Option<Symbt3NativeAuthorityTupleLeafInputs> {
    if instance.round_layouts.len() != witness.message_oracle_evaluations.len()
        || instance.root_policy != NativeOracleRootPolicy::CanonicalWhirRootV1
        || !symbt3_message_oracle_policy_allowed_for_native_message_oracles(
            instance.message_oracle_policy,
        )
    {
        return None;
    }
    let manifest_num_vars = num_vars_for_evals(&witness.manifest_evals)?;
    let source_num_vars = num_vars_for_evals(&witness.source_evals)?;
    let mut common_num_vars = manifest_num_vars.max(source_num_vars);
    for evaluations in &witness.message_oracle_evaluations {
        common_num_vars = common_num_vars.max(num_vars_for_evals(evaluations)?);
    }
    let manifest_evals =
        pad_native_authority_evaluations(&witness.manifest_evals, common_num_vars)?;
    let source_evals = pad_native_authority_evaluations(&witness.source_evals, common_num_vars)?;
    let message_evals = witness
        .message_oracle_evaluations
        .iter()
        .map(|evaluations| pad_native_authority_evaluations(evaluations, common_num_vars))
        .collect::<Option<Vec<_>>>()?;

    let manifest_oracle_root = whir_initial_root_digest(
        seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        common_num_vars,
        &manifest_evals,
    )?;
    let source_oracle_root = whir_initial_root_digest(
        seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        common_num_vars,
        &source_evals,
    )?;
    let batch_manifest_root = native_batch_manifest_root(
        instance.manifest_layout_digest,
        manifest_oracle_root,
        native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
    );

    let specs = symbt3_native_accumulator_authority_tuple_leaf_specs(instance, common_num_vars)?;
    let mut evaluations = Vec::with_capacity(specs.len());
    evaluations.push(manifest_evals);
    evaluations.push(source_evals);
    evaluations.extend(message_evals);
    if specs.len() != evaluations.len() {
        return None;
    }
    let mut roots = Vec::with_capacity(specs.len());
    roots.push(manifest_oracle_root);
    roots.push(source_oracle_root);
    for evaluations in evaluations.iter().skip(2) {
        roots.push(whir_initial_root_digest(
            seed,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            common_num_vars,
            evaluations,
        )?);
    }
    let descriptors = specs
        .iter()
        .zip(roots.iter().copied())
        .map(|(spec, root)| spec.descriptor_with_root(root))
        .collect::<Vec<_>>();
    let message_descriptors = descriptors[2..].to_vec();
    let native_message_roots = roots[2..].to_vec();
    let native_oracle_descriptor_digest = native_oracle_descriptor_digest(&descriptors);
    let native_message_roots_digest = native_message_roots_digest(&message_descriptors);
    let eval_requests = specs
        .iter()
        .map(|spec| WhirNativeEvalRequest {
            oracle_id: spec.oracle_id,
            claim_kind: WhirNativeEvalClaimKind::DirectOpening,
        })
        .collect::<Vec<_>>();
    let descriptor_digest = native_oracle_spec_digest(&specs);
    let rlc_repetition_count = SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT;
    let rlc_batching_bits_per_repetition = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
    let repetition_log_size = symbt3_tuple_leaf_repetition_log_size(rlc_repetition_count)?;
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1,
        descriptor_digest,
        specs.len(),
        common_num_vars,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
    );
    let repeated_packing_challenges = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1,
        instance.symbt3_relation_id,
        instance.public_statement_digest(),
        instance.whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        specs.len(),
        common_num_vars,
        rlc_repetition_count,
    )?;
    let mut packed_evaluations =
        Vec::with_capacity((1usize << common_num_vars) * rlc_repetition_count);
    for packing_challenges in &repeated_packing_challenges {
        packed_evaluations.extend(symbt3_tuple_leaf_pack_evaluations(
            packing_challenges,
            &evaluations,
        )?);
    }
    let packed_num_vars = common_num_vars.checked_add(repetition_log_size)?;
    let packed_root = whir_initial_root_digest(
        seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        packed_num_vars,
        &packed_evaluations,
    )?;

    Some(Symbt3NativeAuthorityTupleLeafInputs {
        specs,
        evaluations,
        eval_requests,
        manifest_oracle_root,
        source_oracle_root,
        batch_manifest_root,
        native_message_roots,
        message_descriptors,
        native_oracle_descriptor_digest,
        native_message_roots_digest,
        packed_root,
    })
}

fn pad_native_authority_evaluations(
    evaluations: &[BabyBear],
    target_num_vars: usize,
) -> Option<Vec<BabyBear>> {
    let source_num_vars = num_vars_for_evals(evaluations)?;
    if source_num_vars > target_num_vars {
        return None;
    }
    let target_len = 1usize.checked_shl(target_num_vars as u32)?;
    if evaluations.len() == target_len {
        return Some(evaluations.to_vec());
    }
    let mut padded = vec![BabyBear::ZERO; target_len];
    padded[..evaluations.len()].copy_from_slice(evaluations);
    Some(padded)
}

fn symbt3_native_accumulator_authority_tuple_leaf_specs(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    common_num_vars: usize,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if common_num_vars == 0 {
        return None;
    }
    let opening_schedule = WhirNativeOpeningSchedule::TranscriptDerived {
        domain_separator: SYMBT3_N7_TUPLE_LEAF_OPENING_DOMAIN,
    };
    let mut specs = vec![
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N2_MANIFEST_ORACLE_ID,
            role: WhirNativeOracleRole::Manifest,
            layout_digest: instance.manifest_layout_digest,
            num_vars: common_num_vars,
            opening_schedule: opening_schedule.clone(),
        },
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N2_SOURCE_ORACLE_ID,
            role: WhirNativeOracleRole::Source,
            layout_digest: instance.source_layout_digest,
            num_vars: common_num_vars,
            opening_schedule: opening_schedule.clone(),
        },
    ];
    let message_specs =
        build_native_message_oracle_specs(&instance.round_layouts, instance.batch_axis_log_size)?;
    for spec in message_specs {
        if spec.num_vars > common_num_vars {
            return None;
        }
        specs.push(WhirNativeOracleSpec {
            version: spec.version,
            oracle_id: spec.oracle_id,
            role: spec.role,
            layout_digest: spec.layout_digest,
            num_vars: common_num_vars,
            opening_schedule: opening_schedule.clone(),
        });
    }
    validate_same_domain_tuple_leaf_specs(&specs).ok()?;
    Some(specs)
}

