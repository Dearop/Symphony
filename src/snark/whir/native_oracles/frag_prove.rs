
impl WhirNativeOracleCounters {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_ORACLE_COUNTERS_V1");
        push_u64(&mut out, self.native_oracle_count as u64);
        push_u64(&mut out, self.native_oracle_descriptor_bytes as u64);
        push_u64(&mut out, self.native_oracle_eval_claim_count as u64);
        push_u64(&mut out, self.native_oracle_opening_count as u64);
        push_u64(&mut out, self.native_oracle_pcs_opening_count as u64);
        push_u64(&mut out, self.native_oracle_transcript_squeezes as u64);
        out
    }
}

#[allow(clippy::too_many_arguments)]
pub fn whir_commit_and_prove_oracles(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    oracle_specs: &[WhirNativeOracleSpec],
    oracle_evaluations: &[Vec<BabyBear>],
    eval_requests: &[WhirNativeEvalRequest],
) -> Option<WhirNativeMultiOracleProof> {
    whir_commit_and_prove_oracles_with_root_policy(
        pk,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        oracle_specs,
        oracle_evaluations,
        eval_requests,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn whir_commit_and_prove_oracles_with_root_policy(
    pk: &WhirProvingKey,
    root_policy: NativeOracleRootPolicy,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    oracle_specs: &[WhirNativeOracleSpec],
    oracle_evaluations: &[Vec<BabyBear>],
    eval_requests: &[WhirNativeEvalRequest],
) -> Option<WhirNativeMultiOracleProof> {
    validate_specs(oracle_specs).ok()?;
    if oracle_specs.len() != oracle_evaluations.len() || eval_requests.is_empty() {
        return None;
    }

    for (spec, evaluations) in oracle_specs.iter().zip(oracle_evaluations.iter()) {
        if evaluations.len() != (1usize << spec.num_vars) {
            return None;
        }
    }

    let mut roots = Vec::with_capacity(oracle_specs.len());
    for (spec, evaluations) in oracle_specs.iter().zip(oracle_evaluations.iter()) {
        roots.push(whir_initial_root_digest(
            &pk.seed,
            root_policy,
            spec.num_vars,
            evaluations,
        )?);
    }

    let descriptors = oracle_specs
        .iter()
        .zip(roots)
        .map(|(spec, root)| spec.descriptor_with_root(root))
        .collect::<Vec<_>>();
    validate_descriptors(&descriptors).ok()?;

    let descriptor_digest = native_oracle_descriptor_digest(&descriptors);
    let descriptor_by_id = descriptors
        .iter()
        .map(|descriptor| (descriptor.oracle_id, descriptor))
        .collect::<BTreeMap<_, _>>();
    let evals_by_id = oracle_specs
        .iter()
        .zip(oracle_evaluations.iter())
        .map(|(spec, evaluations)| (spec.oracle_id, evaluations.as_slice()))
        .collect::<BTreeMap<_, _>>();

    let mut points_by_oracle = BTreeMap::<u32, Vec<Vec<BabyBear>>>::new();
    let mut claims = Vec::with_capacity(eval_requests.len());
    for (request_index, request) in eval_requests.iter().enumerate() {
        let descriptor = *descriptor_by_id.get(&request.oracle_id)?;
        let evaluations = *evals_by_id.get(&request.oracle_id)?;
        let point = derive_native_oracle_opening_point(
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            descriptor_digest,
            root_policy,
            descriptor,
            request.claim_kind,
            request_index,
        );
        let value = mle_eval_bb(evaluations, &point);
        points_by_oracle
            .entry(request.oracle_id)
            .or_default()
            .push(point.clone());
        claims.push(WhirNativeOracleEvalClaim {
            oracle_id: request.oracle_id,
            point_digest: native_oracle_point_digest(&point),
            value,
            claim_kind: request.claim_kind,
        });
    }

    if points_by_oracle.len() != descriptors.len() {
        return None;
    }

    let mut pcs_openings = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        let points = points_by_oracle.get(&descriptor.oracle_id)?;
        let evaluations = *evals_by_id.get(&descriptor.oracle_id)?;
        let (proof, opened_values) =
            whir_commit_and_prove_multi(&pk.seed, descriptor.num_vars, evaluations, points);
        if whir_pcs_initial_root_digest(&proof, root_policy)? != descriptor.root {
            return None;
        }
        let expected_values = claims
            .iter()
            .filter(|claim| claim.oracle_id == descriptor.oracle_id)
            .map(|claim| claim.value)
            .collect::<Vec<_>>();
        if opened_values != expected_values {
            return None;
        }
        pcs_openings.push(WhirNativeOraclePcsOpening {
            oracle_id: descriptor.oracle_id,
            proof,
        });
    }

    let counters = counters_for(&descriptors, claims.len(), pcs_openings.len());
    let eval_claims_digest = native_oracle_eval_claims_digest(&claims);
    let mut proof = WhirNativeMultiOracleProof {
        version: WHIR_NATIVE_MULTI_ORACLE_PROOF_VERSION,
        root_policy,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        native_oracle_descriptor_digest: descriptor_digest,
        native_oracle_eval_claims_digest: eval_claims_digest,
        native_multi_oracle_envelope_digest: [0u8; 32],
        descriptors,
        eval_claims: claims,
        pcs_openings,
        counters,
    };
    proof.native_multi_oracle_envelope_digest = native_multi_oracle_envelope_digest(&proof);
    Some(proof)
}

#[allow(clippy::too_many_arguments)]
pub fn whir_commit_and_prove_same_domain_multi_oracle(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    logical_specs: &[WhirNativeOracleSpec],
    logical_evaluations: &[Vec<BabyBear>],
    eval_requests: &[WhirNativeEvalRequest],
) -> Option<Symbt3TupleLeafMultiOracleProof> {
    whir_commit_and_prove_same_domain_multi_oracle_with_repetitions(
        pk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        logical_specs,
        logical_evaluations,
        eval_requests,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn whir_commit_and_prove_same_domain_multi_oracle_with_repetitions(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    logical_specs: &[WhirNativeOracleSpec],
    logical_evaluations: &[Vec<BabyBear>],
    eval_requests: &[WhirNativeEvalRequest],
    rlc_repetition_count: usize,
    rlc_batching_bits_per_repetition: usize,
) -> Option<Symbt3TupleLeafMultiOracleProof> {
    validate_same_domain_tuple_leaf_inputs(logical_specs, logical_evaluations, eval_requests)
        .ok()?;
    let mode = Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1;
    let logical_oracle_count = logical_specs.len();
    let num_vars = logical_specs.first()?.num_vars;
    let descriptor_digest = native_oracle_spec_digest(logical_specs);
    let repetition_log_size = symbt3_tuple_leaf_repetition_log_size(rlc_repetition_count)?;
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        mode,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
    );
    let repeated_packing_challenges = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        mode,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        logical_oracle_count,
        num_vars,
        rlc_repetition_count,
    )?;
    let packing_challenge_digest =
        symbt3_tuple_leaf_repeated_packing_challenge_digest(&repeated_packing_challenges);
    let claim_kind = eval_requests.first()?.claim_kind;

    let evals_by_id = logical_specs
        .iter()
        .zip(logical_evaluations.iter())
        .map(|(spec, evaluations)| (spec.oracle_id, evaluations.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let oracle_len = 1usize.checked_shl(num_vars as u32)?;
    let packed_num_vars = num_vars.checked_add(repetition_log_size)?;
    let mut logical_claims = Vec::with_capacity(eval_requests.len() * rlc_repetition_count);
    let mut packed_eval_claims = Vec::with_capacity(rlc_repetition_count);
    let mut packed_opening_points = Vec::with_capacity(rlc_repetition_count);
    let mut packed_values = Vec::with_capacity(rlc_repetition_count);
    let mut packed_evaluations = Vec::with_capacity(oracle_len * rlc_repetition_count);
    for (repetition_index, packing_challenges) in repeated_packing_challenges.iter().enumerate() {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            descriptor_digest,
            tuple_leaf_layout_digest,
            claim_kind,
            num_vars,
        );
        let point_digest = native_oracle_point_digest(&point);
        let mut repetition_claims = Vec::with_capacity(eval_requests.len());
        for request in eval_requests {
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
            symbt3_tuple_leaf_pack_evaluations(packing_challenges, logical_evaluations)?;
        let mut packed_point = point;
        packed_point.extend(tuple_leaf_boolean_point_for_index(
            repetition_index,
            repetition_log_size,
        ));
        let packed_point_digest = native_oracle_point_digest(&packed_point);
        packed_eval_claims.push(Symbt3TupleLeafPackedEvalClaim {
            point_digest: packed_point_digest,
            value: packed_value,
            claim_kind: WhirNativeEvalClaimKind::DirectOpening,
        });
        packed_opening_points.push(packed_point);
        packed_values.push(packed_value);
        packed_evaluations.extend(repetition_packed_evaluations);
        logical_claims.extend(repetition_claims);
    }
    let (whir_pcs_proof, opened_values) = whir_commit_and_prove_multi(
        &pk.seed,
        packed_num_vars,
        &packed_evaluations,
        &packed_opening_points,
    );
    if opened_values != packed_values {
        return None;
    }
    let packed_root =
        whir_pcs_initial_root_digest(&whir_pcs_proof, NativeOracleRootPolicy::CanonicalWhirRootV1)?;
    let counters = tuple_leaf_counters_for(
        logical_oracle_count,
        logical_claims.len(),
        num_vars,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
    );

    Some(Symbt3TupleLeafMultiOracleProof {
        version: SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION,
        mode,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        logical_descriptors: logical_specs.to_vec(),
        descriptor_digest,
        tuple_leaf_layout_digest,
        packing_challenge_digest,
        packed_root,
        packed_eval_claims,
        logical_eval_claims: logical_claims,
        whir_pcs_proof,
        counters,
    })
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn whir_verify_same_domain_multi_oracle(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    proof: &Symbt3TupleLeafMultiOracleProof,
    expected_logical_claims: &[WhirNativeOracleEvalClaim],
) -> bool {
    if proof.version != SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION
        || proof.mode != Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1
        || proof.proof_relation_id != proof_relation_id
        || proof.public_statement_digest != public_statement_digest
        || proof.whir_param_digest != whir_param_digest
        || proof.logical_eval_claims != expected_logical_claims
        || validate_same_domain_tuple_leaf_claim_shape(
            &proof.logical_descriptors,
            expected_logical_claims,
        )
        .is_err()
    {
        return false;
    }

    let logical_oracle_count = proof.logical_descriptors.len();
    let num_vars = proof.logical_descriptors[0].num_vars;
    let rlc_repetition_count = proof.counters.rlc_repetition_count;
    let rlc_batching_bits_per_repetition = proof.counters.rlc_batching_bits_per_repetition;
    let Some(repetition_log_size) = symbt3_tuple_leaf_repetition_log_size(rlc_repetition_count)
    else {
        return false;
    };
    let descriptor_digest = native_oracle_spec_digest(&proof.logical_descriptors);
    if descriptor_digest != proof.descriptor_digest {
        return false;
    }
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        proof.mode,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
    );
    if tuple_leaf_layout_digest != proof.tuple_leaf_layout_digest {
        return false;
    }
    let Some(repeated_packing_challenges) = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        proof.mode,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        proof.tuple_leaf_layout_digest,
        logical_oracle_count,
        num_vars,
        rlc_repetition_count,
    ) else {
        return false;
    };
    let packing_challenge_digest =
        symbt3_tuple_leaf_repeated_packing_challenge_digest(&repeated_packing_challenges);
    if packing_challenge_digest != proof.packing_challenge_digest {
        return false;
    }
    if tuple_leaf_counters_for(
        logical_oracle_count,
        expected_logical_claims.len(),
        num_vars,
        rlc_repetition_count,
        rlc_batching_bits_per_repetition,
    ) != proof.counters
    {
        return false;
    }

    let claim_kind = expected_logical_claims[0].claim_kind;
    if expected_logical_claims.len() != logical_oracle_count * rlc_repetition_count
        || proof.packed_eval_claims.len() != rlc_repetition_count
    {
        return false;
    }
    let mut expected_packed_claims = Vec::with_capacity(rlc_repetition_count);
    let mut opening_points = Vec::with_capacity(rlc_repetition_count);
    let mut packed_values = Vec::with_capacity(rlc_repetition_count);
    for (repetition_index, packing_challenges) in repeated_packing_challenges.iter().enumerate() {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            descriptor_digest,
            proof.tuple_leaf_layout_digest,
            claim_kind,
            num_vars,
        );
        let point_digest = native_oracle_point_digest(&point);
        let start = repetition_index * logical_oracle_count;
        let end = start + logical_oracle_count;
        let repetition_claims = &expected_logical_claims[start..end];
        if repetition_claims
            .iter()
            .any(|claim| claim.point_digest != point_digest)
        {
            return false;
        }
        let logical_values = repetition_claims
            .iter()
            .map(|claim| claim.value)
            .collect::<Vec<_>>();
        let Some(packed_value) = symbt3_tuple_leaf_pack_values(packing_challenges, &logical_values)
        else {
            return false;
        };
        let mut packed_point = point;
        packed_point.extend(tuple_leaf_boolean_point_for_index(
            repetition_index,
            repetition_log_size,
        ));
        let packed_point_digest = native_oracle_point_digest(&packed_point);
        expected_packed_claims.push(Symbt3TupleLeafPackedEvalClaim {
            point_digest: packed_point_digest,
            value: packed_value,
            claim_kind: WhirNativeEvalClaimKind::DirectOpening,
        });
        opening_points.push(packed_point);
        packed_values.push(packed_value);
    }
    if proof.packed_eval_claims != expected_packed_claims {
        return false;
    }
    if whir_pcs_initial_root_digest(
        &proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    ) != Some(proof.packed_root)
    {
        return false;
    }

    let Some(packed_num_vars) = num_vars.checked_add(repetition_log_size) else {
        return false;
    };
    whir_verify_opening_multi(
        &vk.seed,
        packed_num_vars,
        &proof.whir_pcs_proof,
        &opening_points,
        &packed_values,
    )
}

#[must_use]
pub fn build_n2_native_manifest_source_oracle_specs(
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    manifest_num_vars: usize,
    source_num_vars: usize,
    batch_manifest_root: Digest32,
    root_policy: NativeOracleRootPolicy,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if manifest_num_vars == 0 || manifest_num_vars != source_num_vars {
        return None;
    }
    let manifest_policy = ManifestCommitmentPolicy::NativeManifestOracleOpeningV1;
    let source_policy = SourceCommitmentPolicy::NativeSourceOracleOpeningV1;
    let binding_digest = native_manifest_source_challenge_binding_digest(
        manifest_layout_digest,
        source_layout_digest,
        batch_manifest_root,
        root_policy,
        manifest_policy,
        source_policy,
    );
    let opening_schedule = WhirNativeOpeningSchedule::TranscriptDerivedWithBinding {
        domain_separator: SYMBT3_N2_MANIFEST_SOURCE_EQUALITY_DOMAIN,
        binding_digest,
    };

    Some(vec![
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N2_MANIFEST_ORACLE_ID,
            role: WhirNativeOracleRole::Manifest,
            layout_digest: manifest_layout_digest,
            num_vars: manifest_num_vars,
            opening_schedule: opening_schedule.clone(),
        },
        WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: SYMBT3_N2_SOURCE_ORACLE_ID,
            role: WhirNativeOracleRole::Source,
            layout_digest: source_layout_digest,
            num_vars: source_num_vars,
            opening_schedule,
        },
    ])
}

#[must_use]
pub fn native_manifest_source_membership_eval_requests() -> Vec<WhirNativeEvalRequest> {
    vec![
        WhirNativeEvalRequest {
            oracle_id: SYMBT3_N2_MANIFEST_ORACLE_ID,
            claim_kind: WhirNativeEvalClaimKind::EqualitySide,
        },
        WhirNativeEvalRequest {
            oracle_id: SYMBT3_N2_SOURCE_ORACLE_ID,
            claim_kind: WhirNativeEvalClaimKind::EqualitySide,
        },
    ]
}

#[must_use]
pub fn build_native_message_oracle_specs(
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    batch_log_size: usize,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if round_layouts.is_empty() {
        return None;
    }
    let mut specs = Vec::with_capacity(round_layouts.len());
    for (index, layout) in round_layouts.iter().enumerate() {
        let expected_round = u32::try_from(index).ok()?;
        let expected_oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE.checked_add(expected_round)?;
        let total_num_vars = layout
            .batch_axis_log_size
            .checked_add(layout.message_axis_log_size)?;
        if layout.round_index != expected_round
            || layout.oracle_id != expected_oracle_id
            || layout.batch_axis_log_size != batch_log_size
            || layout.total_num_vars != total_num_vars
            || layout.total_num_vars == 0
        {
            return None;
        }
        specs.push(WhirNativeOracleSpec {
            version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
            oracle_id: layout.oracle_id,
            role: WhirNativeOracleRole::MessageRound {
                round: layout.round_index,
            },
            layout_digest: layout.layout_digest,
            num_vars: layout.total_num_vars,
            opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                domain_separator: SYMBT3_N4_ROUND_MESSAGE_VIEW_DOMAIN,
            },
        });
    }
    validate_specs(&specs).ok()?;
    Some(specs)
}

#[must_use]
pub fn native_round_message_view_eval_requests(
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
) -> Vec<WhirNativeEvalRequest> {
    round_layouts
        .iter()
        .map(|layout| WhirNativeEvalRequest {
            oracle_id: layout.oracle_id,
            claim_kind: WhirNativeEvalClaimKind::MessageView,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn prove_native_manifest_source_membership(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    manifest_evals: &[BabyBear],
    source_evals: &[BabyBear],
) -> Option<NativeManifestSourceMembershipProof> {
    let root_policy = NativeOracleRootPolicy::CanonicalWhirRootV1;
    let manifest_num_vars = num_vars_for_evals(manifest_evals)?;
    let source_num_vars = num_vars_for_evals(source_evals)?;
    if manifest_num_vars != source_num_vars {
        return None;
    }

    let manifest_root =
        whir_initial_root_digest(&pk.seed, root_policy, manifest_num_vars, manifest_evals)?;
    let batch_manifest_root = native_batch_manifest_root(
        manifest_layout_digest,
        manifest_root,
        native_oracle_root_policy_digest(root_policy),
    );
    let specs = build_n2_native_manifest_source_oracle_specs(
        manifest_layout_digest,
        source_layout_digest,
        manifest_num_vars,
        source_num_vars,
        batch_manifest_root,
        root_policy,
    )?;
    let requests = native_manifest_source_membership_eval_requests();
    let native_proof = whir_commit_and_prove_oracles_with_root_policy(
        pk,
        root_policy,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &specs,
        &[manifest_evals.to_vec(), source_evals.to_vec()],
        &requests,
    )?;
    let manifest_claim = native_proof.eval_claims.first()?;
    let source_claim = native_proof.eval_claims.get(1)?;
    if manifest_claim.claim_kind != WhirNativeEvalClaimKind::EqualitySide
        || source_claim.claim_kind != WhirNativeEvalClaimKind::EqualitySide
        || manifest_claim.value != source_claim.value
    {
        return None;
    }

    Some(NativeManifestSourceMembershipProof {
        batch_manifest_root,
        native_proof,
    })
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn verify_native_manifest_source_membership(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    manifest_layout_digest: Digest32,
    source_layout_digest: Digest32,
    batch_manifest_root: Digest32,
    manifest_policy: ManifestCommitmentPolicy,
    source_policy: SourceCommitmentPolicy,
    expected_root_policy: NativeOracleRootPolicy,
    descriptors: &[WhirNativeOracleDescriptor],
    proof: &WhirNativeMultiOracleProof,
) -> WhirNativeOracleVerifyReport {
    if !native_manifest_source_semantics_ok(
        manifest_layout_digest,
        source_layout_digest,
        batch_manifest_root,
        manifest_policy,
        source_policy,
        expected_root_policy,
        descriptors,
        proof,
    ) {
        return native_manifest_source_fail_report(proof);
    }

    whir_verify_oracle_openings_with_counters_for_profile(
        vk,
        NativeOracleVerificationProfile::NativeManifestAuthority,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptors,
        proof,
        &proof.eval_claims,
    )
}

pub fn prove_committed_private_manifest_membership(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    whir_param_digest: Digest32,
    zk_status: Symbt3ZkStatus,
    components: &[Symbt3ManifestSourceComponentValues],
) -> Option<Symbt3CommittedPrivateManifestMembershipProof> {
    let prepared = prepare_committed_private_manifest_witness(components)?;
    let root_policy = NativeOracleRootPolicy::CanonicalWhirRootV1;
    let manifest_policy = ManifestCommitmentPolicy::NativeManifestOracleOpeningV1;
    let source_policy = SourceCommitmentPolicy::NativeSourceOracleOpeningV1;
    if prepared.committed_private_component_count == 0 {
        return None;
    }
    for component in &prepared.public_views {
        if !symbt3_manifest_visibility_allowed_for_policies(
            component.visibility,
            zk_status,
            manifest_policy,
            source_policy,
        ) {
            return None;
        }
    }

    let manifest_num_vars = num_vars_for_evals(&prepared.manifest_evals)?;
    let source_num_vars = num_vars_for_evals(&prepared.source_evals)?;
    if manifest_num_vars != source_num_vars {
        return None;
    }
    let manifest_oracle_root = whir_initial_root_digest(
        &pk.seed,
        root_policy,
        manifest_num_vars,
        &prepared.manifest_evals,
    )?;
    let source_oracle_root = whir_initial_root_digest(
        &pk.seed,
        root_policy,
        source_num_vars,
        &prepared.source_evals,
    )?;
    let batch_manifest_root = native_batch_manifest_root(
        prepared.manifest_layout_digest,
        manifest_oracle_root,
        native_oracle_root_policy_digest(root_policy),
    );
    let public_statement = Symbt3CommittedPrivateManifestPublicStatement {
        manifest_policy,
        source_policy,
        zk_status,
        root_policy,
        manifest_layout_digest: prepared.manifest_layout_digest,
        source_layout_digest: prepared.source_layout_digest,
        manifest_oracle_root,
        source_oracle_root,
        batch_manifest_root,
        components: prepared.public_views,
    };
    if !committed_private_manifest_public_statement_ok(&public_statement) {
        return None;
    }
    let public_statement_digest = public_statement.digest();
    let specs = build_n2_native_manifest_source_oracle_specs(
        public_statement.manifest_layout_digest,
        public_statement.source_layout_digest,
        manifest_num_vars,
        source_num_vars,
        public_statement.batch_manifest_root,
        root_policy,
    )?;
    let native_proof = whir_commit_and_prove_oracles_with_root_policy(
        pk,
        root_policy,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &specs,
        &[prepared.manifest_evals, prepared.source_evals],
        &native_manifest_source_membership_eval_requests(),
    )?;
    let manifest_claim = native_proof.eval_claims.first()?;
    let source_claim = native_proof.eval_claims.get(1)?;
    if manifest_claim.claim_kind != WhirNativeEvalClaimKind::EqualitySide
        || source_claim.claim_kind != WhirNativeEvalClaimKind::EqualitySide
        || manifest_claim.value != source_claim.value
    {
        return None;
    }

    Some(Symbt3CommittedPrivateManifestMembershipProof {
        public_statement,
        membership_proof: NativeManifestSourceMembershipProof {
            batch_manifest_root,
            native_proof,
        },
    })
}

#[must_use]
pub fn verify_committed_private_manifest_membership(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    whir_param_digest: Digest32,
    proof: &Symbt3CommittedPrivateManifestMembershipProof,
) -> Symbt3CommittedPrivateManifestVerifyReport {
    let public_statement = &proof.public_statement;
    let native_proof = &proof.membership_proof.native_proof;
    let public_statement_digest = public_statement.digest();
    if !committed_private_manifest_public_statement_ok(public_statement)
        || proof.membership_proof.batch_manifest_root != public_statement.batch_manifest_root
        || native_proof.public_statement_digest != public_statement_digest
        || native_proof.descriptors.len() != 2
        || native_proof.descriptors[0].root != public_statement.manifest_oracle_root
        || native_proof.descriptors[1].root != public_statement.source_oracle_root
    {
        return committed_private_manifest_fail_report(proof);
    }

    let native_report = verify_native_manifest_source_membership(
        vk,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        public_statement.manifest_layout_digest,
        public_statement.source_layout_digest,
        public_statement.batch_manifest_root,
        public_statement.manifest_policy,
        public_statement.source_policy,
        public_statement.root_policy,
        &native_proof.descriptors,
        native_proof,
    );
    Symbt3CommittedPrivateManifestVerifyReport {
        ok: native_report.ok,
        native_report,
        committed_private_component_count: public_statement.committed_private_component_count(),
        committed_private_public_bytes: public_statement.committed_private_public_bytes(),
        public_statement_bytes: public_statement.public_statement_bytes(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prove_native_round_message_oracle_views(
    pk: &WhirProvingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    challenge_context: &Symbt3NativeRoundChallengeContext,
    batch_log_size: usize,
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    message_oracle_evaluations: &[Vec<BabyBear>],
    eval_requests: &[WhirNativeEvalRequest],
) -> Option<Symbt3NativeRoundMessageOracleProof> {
    let root_policy = NativeOracleRootPolicy::CanonicalWhirRootV1;
    let specs = build_native_message_oracle_specs(round_layouts, batch_log_size)?;
    if specs.len() != message_oracle_evaluations.len()
        || eval_requests.len() != round_layouts.len()
        || eval_requests != native_round_message_view_eval_requests(round_layouts)
    {
        return None;
    }

    let native_proof = whir_commit_and_prove_oracles_with_root_policy(
        pk,
        root_policy,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &specs,
        message_oracle_evaluations,
        eval_requests,
    )?;
    let message_oracle_roots_digest = native_message_roots_digest(&native_proof.descriptors);
    let message_round_layouts_digest = native_message_round_layouts_digest(round_layouts);
    let message_oracle_policy = Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1;
    let message_oracle_policy_digest = symbt3_message_oracle_policy_digest(message_oracle_policy);
    let round_challenges = derive_native_round_challenges(
        &native_proof.descriptors,
        round_layouts,
        challenge_context,
    )?;

    Some(Symbt3NativeRoundMessageOracleProof {
        message_oracle_policy,
        message_oracle_roots_digest,
        message_round_layouts_digest,
        message_oracle_policy_digest,
        round_challenges,
        native_proof,
    })
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn verify_native_round_message_oracle_views(
    vk: &WhirVerifyingKey,
    proof_relation_id: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
    challenge_context: &Symbt3NativeRoundChallengeContext,
    batch_log_size: usize,
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    expected_message_oracle_roots_digest: Digest32,
    expected_message_round_layouts_digest: Digest32,
    expected_message_oracle_policy_digest: Digest32,
    expected_policy: Symbt3MessageOraclePolicy,
    expected_root_policy: NativeOracleRootPolicy,
    proof: &Symbt3NativeRoundMessageOracleProof,
) -> Symbt3NativeRoundMessageOracleVerifyReport {
    let Some(round_challenges) = native_round_message_semantics_challenges(
        challenge_context,
        batch_log_size,
        round_layouts,
        expected_message_oracle_roots_digest,
        expected_message_round_layouts_digest,
        expected_message_oracle_policy_digest,
        expected_policy,
        expected_root_policy,
        proof,
    ) else {
        return native_round_message_fail_report(proof, Vec::new());
    };

    let native_report = whir_verify_oracle_openings_with_counters_for_profile(
        vk,
        NativeOracleVerificationProfile::NativeMessageAuthority,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        &proof.native_proof.descriptors,
        &proof.native_proof,
        &proof.native_proof.eval_claims,
    );
    Symbt3NativeRoundMessageOracleVerifyReport {
        ok: native_report.ok,
        native_report,
        native_message_round_count: round_layouts.len(),
        message_to_trace_binding_count: 0,
        round_challenges,
    }
}

#[must_use]
pub fn symbt3_native_folding_integrity_challenge_context(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    batch_manifest_root: Digest32,
) -> Symbt3NativeRoundChallengeContext {
    Symbt3NativeRoundChallengeContext {
        folding_protocol_id: instance.folding_protocol_id,
        input_public_boundary_digest: instance.input_public_boundary_digest,
        batch_manifest_root,
        source_roots_digest: instance.source_roots_digest,
        active_count: instance.active_count,
        batch_size: instance.batch_size,
        folded_output_digest: instance.folded_output_digest,
    }
}

#[must_use]
pub fn symbt3_native_folding_integrity_profile_metadata(
    instance: &Symbt3NativeFoldingIntegrityInstance,
    counters: &Symbt3NativeFoldingIntegrityCounters,
) -> Symbt3NonZkFoldingIntegrityProfileMetadata {
    Symbt3NonZkFoldingIntegrityProfileMetadata {
        native_profile: instance.native_profile,
        manifest_policy: Some(instance.manifest_policy),
        source_policy: Some(instance.source_policy),
        message_oracle_policy: Some(instance.message_oracle_policy),
        root_policy: instance.root_policy,
        zk_status: instance.zk_status,
        committed_private_component_count: instance.committed_private_component_count,
        manifest_source_native_oracle_count: counters.native_manifest_source_oracle_count,
        manifest_source_native_pcs_opening_count: counters
            .native_oracle_pcs_opening_count
            .saturating_sub(counters.native_message_oracle_count),
        native_message_round_count: instance.round_layouts.len(),
        native_message_oracle_count: counters.native_message_oracle_count,
        native_message_pcs_opening_count: counters
            .native_oracle_pcs_opening_count
            .saturating_sub(2),
        batch_size: usize::try_from(instance.batch_size).unwrap_or(usize::MAX),
        batch_axis_log_size: instance.batch_axis_log_size,
        message_round_layouts: instance.round_layouts.clone(),
        logical_native_envelope_count: 1,
        top_level_whir_proof_count: counters.top_level_whir_proof_count,
        family_columnar_subproof_count: counters.family_columnar_subproof_count,
        message_to_trace_binding_count: counters.message_to_trace_binding_count,
        semantic_profile_version: instance.semantic_profile_version,
        required_semantic_families: instance.required_semantic_families,
        k5_masking_available: instance.k5_masking_available,
        monolithic_fallback: instance.monolithic_fallback,
        product_default_route_attempted: instance.product_default_route_attempted,
        product_eligible: instance.product_eligible,
        native_product_route_version_exists: instance.native_product_route_version_exists,
    }
}

pub fn prove_symbt3_native_folding_integrity_non_zk(
    pk: &WhirProvingKey,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    witness: &Symbt3NativeFoldingIntegrityWitness,
) -> Option<Symbt3NativeFoldingIntegrityProof> {
    if !symbt3_native_folding_integrity_instance_shape_ok(instance)
        || instance.root_policy != NativeOracleRootPolicy::CanonicalWhirRootV1
    {
        return None;
    }

    let manifest_num_vars = num_vars_for_evals(&witness.manifest_evals)?;
    let source_num_vars = num_vars_for_evals(&witness.source_evals)?;
    if manifest_num_vars != source_num_vars {
        return None;
    }
    let manifest_oracle_root = whir_initial_root_digest(
        &pk.seed,
        instance.root_policy,
        manifest_num_vars,
        &witness.manifest_evals,
    )?;
    let source_oracle_root = whir_initial_root_digest(
        &pk.seed,
        instance.root_policy,
        source_num_vars,
        &witness.source_evals,
    )?;
    let batch_manifest_root = native_batch_manifest_root(
        instance.manifest_layout_digest,
        manifest_oracle_root,
        native_oracle_root_policy_digest(instance.root_policy),
    );

    let mut oracle_specs = build_n2_native_manifest_source_oracle_specs(
        instance.manifest_layout_digest,
        instance.source_layout_digest,
        manifest_num_vars,
        source_num_vars,
        batch_manifest_root,
        instance.root_policy,
    )?;
    let message_specs =
        build_native_message_oracle_specs(&instance.round_layouts, instance.batch_axis_log_size)?;
    oracle_specs.extend(message_specs);
    validate_specs(&oracle_specs).ok()?;

    let mut oracle_evaluations = Vec::with_capacity(2 + witness.message_oracle_evaluations.len());
    oracle_evaluations.push(witness.manifest_evals.clone());
    oracle_evaluations.push(witness.source_evals.clone());
    oracle_evaluations.extend_from_slice(&witness.message_oracle_evaluations);
    if oracle_specs.len() != oracle_evaluations.len() {
        return None;
    }

    let mut eval_requests = native_manifest_source_membership_eval_requests();
    eval_requests.extend(native_round_message_view_eval_requests(
        &instance.round_layouts,
    ));

    let public_statement_digest = instance.public_statement_digest();
    let native_oracle_proof = whir_commit_and_prove_oracles_with_root_policy(
        pk,
        instance.root_policy,
        instance.symbt3_relation_id,
        public_statement_digest,
        instance.whir_param_digest,
        &oracle_specs,
        &oracle_evaluations,
        &eval_requests,
    )?;

    let symbt3_proof =
        <WhirSnark as BackendSnark>::prove(pk, &instance.main_instance, &witness.main_witness);

    let message_descriptors = native_folding_message_descriptors(&native_oracle_proof)?;
    let native_message_roots_digest = native_message_roots_digest(message_descriptors);
    let challenge_context =
        symbt3_native_folding_integrity_challenge_context(instance, batch_manifest_root);
    let round_challenges = derive_native_round_challenges(
        message_descriptors,
        &instance.round_layouts,
        &challenge_context,
    )?;
    let counters = native_folding_integrity_counters(instance, &native_oracle_proof)?;
    let metadata = symbt3_native_folding_integrity_profile_metadata(instance, &counters);
    if !profile_meets_native_non_zk_folding_integrity(&metadata) {
        return None;
    }

    let profile_digest =
        symbt3_native_oracle_profile_digest(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1);
    let message_oracle_policy_digest =
        symbt3_message_oracle_policy_digest(instance.message_oracle_policy);
    let manifest_policy_digest = manifest_commitment_policy_digest(instance.manifest_policy);
    let binding_digest = native_folding_integrity_binding_digest(
        instance.symbt3_relation_id,
        public_statement_digest,
        profile_digest,
        instance.whir_param_digest,
        native_oracle_proof.native_oracle_descriptor_digest,
        native_message_roots_digest,
        manifest_oracle_root,
        source_oracle_root,
        batch_manifest_root,
        instance.source_column_layout_digest,
        message_oracle_policy_digest,
        manifest_policy_digest,
        instance.active_count,
        instance.batch_size,
    );

    let proof = Symbt3NativeFoldingIntegrityProof {
        version: SYMBT3_NATIVE_FOLDING_INTEGRITY_PROOF_VERSION,
        proof_kind: Symbt3NativeFoldingProofKind::NativeNonZkFoldingIntegrityV1,
        profile_digest,
        public_statement_digest,
        whir_param_digest: instance.whir_param_digest,
        symbt3_relation_id: instance.symbt3_relation_id,
        native_oracle_descriptor_digest: native_oracle_proof.native_oracle_descriptor_digest,
        native_message_roots_digest,
        manifest_oracle_root,
        source_oracle_root,
        batch_manifest_root,
        source_column_layout_digest: instance.source_column_layout_digest,
        message_oracle_policy_digest,
        manifest_commitment_policy_digest: manifest_policy_digest,
        binding_digest,
        round_challenges,
        symbt3_proof,
        native_oracle_proof,
        counters,
    };

    if symbt3_native_folding_integrity_semantics_ok(instance, &proof) {
        Some(proof)
    } else {
        None
    }
}

#[must_use]
pub fn verify_symbt3_native_folding_integrity_non_zk(
    vk: &WhirVerifyingKey,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    verify_symbt3_native_folding_integrity_non_zk_for_kind(
        vk,
        instance,
        proof,
        Symbt3NativeFoldingProofKind::NativeNonZkFoldingIntegrityV1,
    )
}

#[must_use]
pub fn prove_public_symbt3_native_folding_integrity_non_zk(
    pk: &WhirProvingKey,
    public_profile: &Symbt3NativeFoldingIntegrityPublicProfile,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    witness: &Symbt3NativeFoldingIntegrityWitness,
) -> Option<Symbt3NativeFoldingIntegrityProof> {
    if !symbt3_native_folding_integrity_public_route_ok(public_profile, instance) {
        return None;
    }
    let mut proof = prove_symbt3_native_folding_integrity_non_zk(pk, instance, witness)?;
    proof.proof_kind = Symbt3NativeFoldingProofKind::Symbt3NativeNonZkFoldingIntegrityV1;
    Some(proof)
}

#[must_use]
pub fn verify_public_symbt3_native_folding_integrity_non_zk(
    vk: &WhirVerifyingKey,
    public_profile: &Symbt3NativeFoldingIntegrityPublicProfile,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> bool {
    symbt3_native_folding_integrity_public_route_ok(public_profile, instance)
        && verify_symbt3_native_folding_integrity_non_zk_for_kind(
            vk,
            instance,
            proof,
            Symbt3NativeFoldingProofKind::Symbt3NativeNonZkFoldingIntegrityV1,
        )
}

#[must_use]
pub const fn symbt3_k6a_public_canonical_route_accepts_proof_kind(
    proof_kind: Symbt3NativeFoldingProofKind,
) -> bool {
    matches!(
        proof_kind,
        Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1
    )
}

#[must_use]
pub const fn symbt3_monolithic_typed_cp_route_accepts_proof_kind(
    proof_kind: Symbt3NativeFoldingProofKind,
) -> bool {
    matches!(
        proof_kind,
        Symbt3NativeFoldingProofKind::MonolithicTypedCpV1
    )
}

#[must_use]
pub const fn symbt3_native_folding_integrity_public_route_selected(
    public_profile: &Symbt3NativeFoldingIntegrityPublicProfile,
) -> bool {
    matches!(
        public_profile.route_status,
        Symbt3NativeFoldingIntegrityRouteStatus::ExplicitNativeNonZk
            | Symbt3NativeFoldingIntegrityRouteStatus::ResearchOnlyNativeNonZk
    )
}

#[must_use]
pub const fn symbt3_native_folding_integrity_monolithic_fallback_used(
    instance: &Symbt3NativeFoldingIntegrityInstance,
) -> bool {
    instance.monolithic_fallback
}

#[must_use]
fn verify_symbt3_native_folding_integrity_non_zk_for_kind(
    vk: &WhirVerifyingKey,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeFoldingIntegrityProof,
    expected_proof_kind: Symbt3NativeFoldingProofKind,
) -> bool {
    if proof.version != SYMBT3_NATIVE_FOLDING_INTEGRITY_PROOF_VERSION
        || proof.proof_kind != expected_proof_kind
        || !symbt3_native_folding_integrity_instance_shape_ok(instance)
        || proof.public_statement_digest != instance.public_statement_digest()
        || proof.whir_param_digest != instance.whir_param_digest
        || proof.symbt3_relation_id != instance.symbt3_relation_id
        || proof.profile_digest
            != symbt3_native_oracle_profile_digest(
                Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1,
            )
        || proof.native_oracle_descriptor_digest
            != proof.native_oracle_proof.native_oracle_descriptor_digest
        || proof.native_oracle_descriptor_digest
            != native_oracle_descriptor_digest(&proof.native_oracle_proof.descriptors)
        || proof.source_column_layout_digest != instance.source_column_layout_digest
        || proof.message_oracle_policy_digest
            != symbt3_message_oracle_policy_digest(instance.message_oracle_policy)
        || proof.manifest_commitment_policy_digest
            != manifest_commitment_policy_digest(instance.manifest_policy)
        || proof.native_oracle_proof.root_policy != NativeOracleRootPolicy::CanonicalWhirRootV1
    {
        return false;
    }

    let Some(expected_counters) =
        native_folding_integrity_counters(instance, &proof.native_oracle_proof)
    else {
        return false;
    };
    if proof.counters != expected_counters {
        return false;
    }
    let metadata = symbt3_native_folding_integrity_profile_metadata(instance, &proof.counters);
    if !profile_meets_native_non_zk_folding_integrity(&metadata) {
        return false;
    }
    if !symbt3_native_folding_integrity_semantics_ok(instance, proof) {
        return false;
    }

    let native_report = whir_verify_oracle_openings_with_counters_for_profile(
        vk,
        NativeOracleVerificationProfile::ProductAuthority,
        instance.symbt3_relation_id,
        proof.public_statement_digest,
        instance.whir_param_digest,
        &proof.native_oracle_proof.descriptors,
        &proof.native_oracle_proof,
        &proof.native_oracle_proof.eval_claims,
    );
    if !native_report.ok {
        return false;
    }

    <WhirSnark as BackendSnark>::verify(vk, &instance.main_instance, &proof.symbt3_proof)
}

pub fn prove_symbt3_native_accumulator_authority_non_zk(
    pk: &WhirProvingKey,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    witness: &Symbt3NativeFoldingIntegrityWitness,
) -> Option<Symbt3NativeAccumulatorAuthorityProof> {
    if !symbt3_native_folding_integrity_instance_shape_ok(instance)
        || instance.root_policy != NativeOracleRootPolicy::CanonicalWhirRootV1
    {
        return None;
    }

    let public_statement_digest = instance.public_statement_digest();
    let tuple_inputs =
        build_symbt3_native_accumulator_authority_tuple_leaf_inputs(&pk.seed, instance, witness)?;
    let rlc_tuple_leaf_multi_oracle_proof = whir_commit_and_prove_same_domain_multi_oracle(
        pk,
        instance.symbt3_relation_id,
        public_statement_digest,
        instance.whir_param_digest,
        &tuple_inputs.specs,
        &tuple_inputs.evaluations,
        &tuple_inputs.eval_requests,
    )?;
    if rlc_tuple_leaf_multi_oracle_proof.packed_root != tuple_inputs.packed_root {
        return None;
    }

    let main_symbt3_whir_proof =
        <WhirSnark as BackendSnark>::prove(pk, &instance.main_instance, &witness.main_witness);
    let main_symbt3_proof_digest = symbt3_main_whir_proof_digest(&main_symbt3_whir_proof);
    let counters = native_accumulator_authority_counters(
        instance,
        &rlc_tuple_leaf_multi_oracle_proof,
        &main_symbt3_whir_proof,
        Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1,
    )?;
    let metadata = symbt3_native_accumulator_authority_profile_metadata(instance, &counters);
    if !profile_meets_native_accumulator_authority(&metadata) {
        return None;
    }

    let profile_digest =
        symbt3_native_oracle_profile_digest(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1);
    let accumulator_instance_digest = symbt3_native_accumulator_authority_instance_digest(instance);
    let old_accumulator_digest = symbt3_native_accumulator_old_digest(instance);
    let new_accumulator_digest = symbt3_native_accumulator_new_digest(
        instance,
        old_accumulator_digest,
        tuple_inputs.batch_manifest_root,
    );
    let challenge_context = symbt3_native_folding_integrity_challenge_context(
        instance,
        tuple_inputs.batch_manifest_root,
    );
    let round_challenges = derive_native_round_challenges(
        &tuple_inputs.message_descriptors,
        &instance.round_layouts,
        &challenge_context,
    )?;
    let native_binding_digest = native_accumulator_authority_binding_digest(
        Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1,
        profile_digest,
        accumulator_instance_digest,
        public_statement_digest,
        instance.whir_param_digest,
        instance.symbt3_relation_id,
        main_symbt3_proof_digest,
        rlc_tuple_leaf_multi_oracle_proof.packed_root,
        rlc_tuple_leaf_multi_oracle_proof.tuple_leaf_layout_digest,
        tuple_inputs.native_oracle_descriptor_digest,
        tuple_inputs.native_message_roots_digest,
        tuple_inputs.manifest_oracle_root,
        tuple_inputs.source_oracle_root,
        tuple_inputs.batch_manifest_root,
        old_accumulator_digest,
        new_accumulator_digest,
        instance.batch_size,
        instance.active_count,
    );

    let proof = Symbt3NativeAccumulatorAuthorityProof {
        version: SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_PROOF_VERSION,
        proof_kind: Symbt3NativeFoldingProofKind::Symbt3NativeAccumulatorAuthorityV1,
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1,
        profile_digest,
        accumulator_instance_digest,
        public_statement_digest,
        whir_param_digest: instance.whir_param_digest,
        native_binding_digest,
        main_symbt3_relation_id: instance.symbt3_relation_id,
        main_symbt3_proof_digest,
        rlc_tuple_leaf_root: rlc_tuple_leaf_multi_oracle_proof.packed_root,
        rlc_tuple_leaf_layout_digest: rlc_tuple_leaf_multi_oracle_proof.tuple_leaf_layout_digest,
        native_oracle_descriptor_digest: tuple_inputs.native_oracle_descriptor_digest,
        native_message_roots_digest: tuple_inputs.native_message_roots_digest,
        native_message_roots: tuple_inputs.native_message_roots,
        manifest_oracle_root: tuple_inputs.manifest_oracle_root,
        source_oracle_root: tuple_inputs.source_oracle_root,
        batch_manifest_root: tuple_inputs.batch_manifest_root,
        old_accumulator_digest,
        new_accumulator_digest,
        round_challenges,
        main_symbt3_whir_proof,
        rlc_tuple_leaf_multi_oracle_proof,
        counters,
    };

    if symbt3_native_accumulator_authority_semantics_ok(instance, &proof) {
        Some(proof)
    } else {
        None
    }
}
