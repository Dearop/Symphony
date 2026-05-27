#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestCommitmentPolicy {
    PublicCanonicalManifestViewV1,
    NativeManifestOracleOpeningV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCommitmentPolicy {
    NativeSourceOracleOpeningV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ManifestVisibility {
    PublicBoundary,
    CommittedPrivateNonZk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ZkStatus {
    NonZkIntegrityOnly,
    ExplicitNonZkResearch,
    ZkRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ManifestComponentKind {
    PublicBoundary,
    CommittedPrivateWitness,
    Auxiliary(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageOraclePolicy {
    DigestOnlyMessageRootsV1,
    NativeRoundMessageOraclesV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3NativeOracleProfile {
    NonZkFoldingIntegrityV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3NativeFoldingProofKind {
    NativeNonZkFoldingIntegrityV1,
    PublicCanonicalK6aV1,
    MonolithicTypedCpV1,
    Symbt3NativeNonZkFoldingIntegrityV1,
    Symbt3NativeAccumulatorAuthorityV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3NativeAccumulatorAuthorityWorkload {
    N7SmokeProfileV1,
    FullK6aAccumulatorV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3NativeFoldingIntegrityRouteStatus {
    Disabled,
    PublicCanonicalK6a,
    ExplicitNativeNonZk,
    ResearchOnlyNativeNonZk,
    DefaultVerifyPublic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOracleRootPolicy {
    DebugDevelopmentOnly,
    CanonicalWhirRootV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOracleVerificationProfile {
    Development,
    Infrastructure,
    ProductAuthority,
    NativeManifestAuthority,
    NativeMessageAuthority,
}

impl NativeOracleRootPolicy {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"NATIVE_ORACLE_ROOT_POLICY_V1");
        encode_root_policy(&mut out, *self);
        out
    }
}

impl ManifestCommitmentPolicy {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"MANIFEST_COMMITMENT_POLICY_V1");
        encode_manifest_commitment_policy(&mut out, *self);
        out
    }
}

impl SourceCommitmentPolicy {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SOURCE_COMMITMENT_POLICY_V1");
        encode_source_commitment_policy(&mut out, *self);
        out
    }
}

impl Symbt3ManifestVisibility {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_MANIFEST_VISIBILITY_V1");
        encode_symbt3_manifest_visibility(&mut out, self);
        out
    }
}

impl Symbt3ZkStatus {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_ZK_STATUS_V1");
        encode_symbt3_zk_status(&mut out, self);
        out
    }
}

impl Symbt3ManifestComponentKind {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_MANIFEST_COMPONENT_KIND_V1");
        encode_symbt3_manifest_component_kind(&mut out, self);
        out
    }
}

impl Symbt3MessageOraclePolicy {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_MESSAGE_ORACLE_POLICY_V1");
        encode_symbt3_message_oracle_policy(&mut out, self);
        out
    }
}

impl Symbt3NativeOracleProfile {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_ORACLE_PROFILE_V1");
        encode_symbt3_native_oracle_profile(&mut out, self);
        out
    }
}

impl Symbt3NativeFoldingProofKind {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_FOLDING_PROOF_KIND_V1");
        encode_symbt3_native_folding_proof_kind(&mut out, self);
        out
    }
}

impl Symbt3NativeAccumulatorAuthorityWorkload {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_WORKLOAD_V1");
        encode_symbt3_native_accumulator_authority_workload(&mut out, self);
        out
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::N7SmokeProfileV1 => "N7SmokeProfileV1",
            Self::FullK6aAccumulatorV1 => "FullK6aAccumulatorV1",
        }
    }
}

impl Symbt3NativeFoldingIntegrityRouteStatus {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_FOLDING_INTEGRITY_ROUTE_STATUS_V1");
        encode_symbt3_native_folding_integrity_route_status(&mut out, self);
        out
    }
}

impl Symbt3FoldingIntegritySemanticFamilies {
    #[must_use]
    pub const fn production_non_zk() -> Self {
        Self {
            manifest_evaluation_claim: true,
            accumulator_transition_consistency: true,
            k1_semantic_family: true,
            k2_semantic_family: true,
            k3_semantic_family: true,
            k4_semantic_family: true,
            production_norm_range_bundle: true,
        }
    }

    #[must_use]
    pub const fn all_required_ok(&self) -> bool {
        self.manifest_evaluation_claim
            && self.accumulator_transition_consistency
            && self.k1_semantic_family
            && self.k2_semantic_family
            && self.k3_semantic_family
            && self.k4_semantic_family
            && self.production_norm_range_bundle
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_FOLDING_INTEGRITY_SEMANTIC_FAMILIES_V1");
        push_bool(&mut out, self.manifest_evaluation_claim);
        push_bool(&mut out, self.accumulator_transition_consistency);
        push_bool(&mut out, self.k1_semantic_family);
        push_bool(&mut out, self.k2_semantic_family);
        push_bool(&mut out, self.k3_semantic_family);
        push_bool(&mut out, self.k4_semantic_family);
        push_bool(&mut out, self.production_norm_range_bundle);
        out
    }
}

impl Symbt3NativeFoldingIntegrityCounters {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_FOLDING_INTEGRITY_COUNTERS_V1");
        push_u64(&mut out, self.top_level_whir_proof_count as u64);
        push_u64(&mut out, self.family_columnar_subproof_count as u64);
        push_u64(&mut out, self.backend_table_count as u64);
        push_u64(&mut out, self.native_oracle_count as u64);
        push_u64(&mut out, self.native_manifest_source_oracle_count as u64);
        push_u64(&mut out, self.native_message_oracle_count as u64);
        push_u64(&mut out, self.native_oracle_eval_claim_count as u64);
        push_u64(&mut out, self.native_oracle_pcs_opening_count as u64);
        push_u64(&mut out, self.native_oracle_descriptor_bytes as u64);
        push_u64(&mut out, self.message_to_trace_binding_count as u64);
        push_u64(&mut out, self.accumulator_transition_claims as u64);
        out
    }
}

impl Symbt3NativeFoldingIntegrityPublicProfile {
    #[must_use]
    pub const fn explicit_non_zk() -> Self {
        Self {
            route_status: Symbt3NativeFoldingIntegrityRouteStatus::ExplicitNativeNonZk,
            zk_status: Symbt3ZkStatus::NonZkIntegrityOnly,
            product_accepts_native_non_zk_folding_integrity: true,
            k5_masking_required: false,
            allow_monolithic_fallback: false,
        }
    }

    #[must_use]
    pub const fn research_only_non_zk() -> Self {
        Self {
            route_status: Symbt3NativeFoldingIntegrityRouteStatus::ResearchOnlyNativeNonZk,
            zk_status: Symbt3ZkStatus::ExplicitNonZkResearch,
            product_accepts_native_non_zk_folding_integrity: true,
            k5_masking_required: false,
            allow_monolithic_fallback: false,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_NATIVE_FOLDING_INTEGRITY_PUBLIC_PROFILE_V1",
        );
        push_bytes(&mut out, &self.route_status.canonical_bytes());
        push_bytes(&mut out, &self.zk_status.canonical_bytes());
        push_bool(
            &mut out,
            self.product_accepts_native_non_zk_folding_integrity,
        );
        push_bool(&mut out, self.k5_masking_required);
        push_bool(&mut out, self.allow_monolithic_fallback);
        out
    }
}

impl Symbt3NativeFoldingIntegrityInstance {
    #[must_use]
    pub fn canonical_public_statement_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_NATIVE_FOLDING_INTEGRITY_PUBLIC_STATEMENT_V1",
        );
        match self.native_profile {
            Some(profile) => {
                push_bool(&mut out, true);
                push_bytes(&mut out, &profile.canonical_bytes());
            }
            None => push_bool(&mut out, false),
        }
        push_bytes(&mut out, &self.manifest_policy.canonical_bytes());
        push_bytes(&mut out, &self.source_policy.canonical_bytes());
        push_bytes(&mut out, &self.message_oracle_policy.canonical_bytes());
        push_bytes(&mut out, &self.root_policy.canonical_bytes());
        push_bytes(&mut out, &self.zk_status.canonical_bytes());
        push_digest(&mut out, &self.symbt3_relation_id);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.manifest_layout_digest);
        push_digest(&mut out, &self.source_layout_digest);
        push_digest(&mut out, &self.source_column_layout_digest);
        push_digest(&mut out, &self.folding_protocol_id);
        push_digest(&mut out, &self.input_public_boundary_digest);
        push_digest(&mut out, &self.source_roots_digest);
        push_u64(&mut out, self.active_count);
        push_u64(&mut out, self.batch_size);
        push_digest(&mut out, &self.folded_output_digest);
        push_u64(&mut out, self.batch_axis_log_size as u64);
        push_u64(&mut out, self.round_layouts.len() as u64);
        for layout in &self.round_layouts {
            push_bytes(&mut out, &layout.canonical_bytes());
        }
        push_u64(&mut out, self.committed_private_component_count as u64);
        push_u32(&mut out, self.semantic_profile_version);
        push_bytes(&mut out, &self.required_semantic_families.canonical_bytes());
        push_bool(&mut out, self.k5_masking_available);
        push_bool(&mut out, self.monolithic_fallback);
        push_bool(&mut out, self.product_default_route_attempted);
        push_bool(&mut out, self.product_eligible);
        push_bool(&mut out, self.native_product_route_version_exists);
        push_u64(&mut out, self.backend_table_count as u64);
        push_u64(&mut out, self.accumulator_transition_claims as u64);
        push_bytes(&mut out, &self.main_instance);
        out
    }

    #[must_use]
    pub fn public_statement_digest(&self) -> Digest32 {
        digest_bytes(&self.canonical_public_statement_bytes())
    }

    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        self.canonical_public_statement_bytes().len()
    }
}

impl Symbt3NativeFoldingIntegrityProof {
    #[must_use]
    pub fn metadata_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_NATIVE_FOLDING_INTEGRITY_PROOF_METADATA_V1",
        );
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.proof_kind.canonical_bytes());
        push_digest(&mut out, &self.profile_digest);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.symbt3_relation_id);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_message_roots_digest);
        push_digest(&mut out, &self.manifest_oracle_root);
        push_digest(&mut out, &self.source_oracle_root);
        push_digest(&mut out, &self.batch_manifest_root);
        push_digest(&mut out, &self.source_column_layout_digest);
        push_digest(&mut out, &self.message_oracle_policy_digest);
        push_digest(&mut out, &self.manifest_commitment_policy_digest);
        push_digest(&mut out, &self.binding_digest);
        push_babybear_vec(&mut out, &self.round_challenges);
        push_digest(
            &mut out,
            &self.native_oracle_proof.native_multi_oracle_envelope_digest,
        );
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn metadata_digest(&self) -> Digest32 {
        digest_bytes(&self.metadata_canonical_bytes())
    }
}

impl Symbt3NativeAccumulatorAuthorityCounters {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_COUNTERS_V1");
        push_bool(&mut out, self.full_accumulator_workload);
        push_bool(&mut out, self.smoke_profile);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_u64(&mut out, self.main_whir_num_vars as u64);
        push_u64(&mut out, self.main_oracle_len as u64);
        push_u64(&mut out, self.top_level_whir_proof_count as u64);
        push_u64(&mut out, self.family_columnar_subproof_count as u64);
        push_u64(&mut out, self.backend_table_count as u64);
        push_bool(&mut out, self.native_multi_oracle);
        push_bytes(&mut out, self.tuple_leaf_layout.as_bytes());
        push_u64(&mut out, self.whir_instance_count as u64);
        push_u64(&mut out, self.root_count as u64);
        push_u64(&mut out, self.query_schedule_count as u64);
        push_u64(&mut out, self.transcript_count as u64);
        push_u64(&mut out, self.native_oracle_pcs_opening_count as u64);
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.native_manifest_source_oracle_count as u64);
        push_u64(&mut out, self.native_message_oracle_count as u64);
        push_u64(&mut out, self.accumulator_transition_claims as u64);
        push_u64(
            &mut out,
            self.source_r1cs_residual_verifier_evaluations as u64,
        );
        push_u64(&mut out, self.rlc_batching_bits as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_u64(&mut out, self.native_oracle_eval_claim_count as u64);
        push_bool(&mut out, self.fallback_used);
        out
    }
}

impl Symbt3NativeAccumulatorAuthorityProof {
    #[must_use]
    pub fn metadata_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_PROOF_METADATA_V1",
        );
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.proof_kind.canonical_bytes());
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.profile_digest);
        push_digest(&mut out, &self.accumulator_instance_digest);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.native_binding_digest);
        push_digest(&mut out, &self.main_symbt3_relation_id);
        push_digest(&mut out, &self.main_symbt3_proof_digest);
        push_digest(&mut out, &self.rlc_tuple_leaf_root);
        push_digest(&mut out, &self.rlc_tuple_leaf_layout_digest);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_message_roots_digest);
        push_u64(&mut out, self.native_message_roots.len() as u64);
        for root in &self.native_message_roots {
            push_digest(&mut out, root);
        }
        push_digest(&mut out, &self.manifest_oracle_root);
        push_digest(&mut out, &self.source_oracle_root);
        push_digest(&mut out, &self.batch_manifest_root);
        push_digest(&mut out, &self.old_accumulator_digest);
        push_digest(&mut out, &self.new_accumulator_digest);
        push_babybear_vec(&mut out, &self.round_challenges);
        push_digest(
            &mut out,
            &self
                .rlc_tuple_leaf_multi_oracle_proof
                .tuple_leaf_layout_digest,
        );
        push_digest(
            &mut out,
            &self.rlc_tuple_leaf_multi_oracle_proof.packed_root,
        );
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn metadata_digest(&self) -> Digest32 {
        digest_bytes(&self.metadata_canonical_bytes())
    }
}

impl Symbt3ManifestSourceComponentValues {
    #[must_use]
    pub fn public_view(&self) -> Option<Symbt3ManifestComponentPublicView> {
        if self.manifest_values.is_empty() || self.manifest_values.len() != self.source_values.len()
        {
            return None;
        }
        let public_manifest_values = match self.visibility {
            Symbt3ManifestVisibility::PublicBoundary => self.manifest_values.clone(),
            Symbt3ManifestVisibility::CommittedPrivateNonZk => Vec::new(),
        };
        let public_source_values = match self.visibility {
            Symbt3ManifestVisibility::PublicBoundary => self.source_values.clone(),
            Symbt3ManifestVisibility::CommittedPrivateNonZk => Vec::new(),
        };

        Some(Symbt3ManifestComponentPublicView {
            component_id: self.component_id,
            kind: self.kind,
            visibility: self.visibility,
            layout_digest: self.layout_digest,
            value_count: self.manifest_values.len(),
            manifest_component_root: symbt3_manifest_component_values_root(
                WhirNativeOracleRole::Manifest,
                self.component_id,
                self.kind,
                self.visibility,
                self.layout_digest,
                &self.manifest_values,
            ),
            source_component_root: symbt3_manifest_component_values_root(
                WhirNativeOracleRole::Source,
                self.component_id,
                self.kind,
                self.visibility,
                self.layout_digest,
                &self.source_values,
            ),
            public_manifest_values,
            public_source_values,
        })
    }
}

impl Symbt3NativeRoundMessageOracleLayoutV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_ROUND_MESSAGE_ORACLE_LAYOUT_V1");
        push_u32(&mut out, self.round_index);
        push_u32(&mut out, self.oracle_id);
        push_u64(&mut out, self.batch_axis_log_size as u64);
        push_u64(&mut out, self.message_axis_log_size as u64);
        push_u64(&mut out, self.total_num_vars as u64);
        push_digest(&mut out, &self.layout_digest);
        push_digest(&mut out, &self.section_layout_digest);
        push_digest(&mut out, &self.view_map_digest);
        out
    }
}

impl Symbt3NativeRoundChallengeContext {
    #[must_use]
    pub fn canonical_bytes_without_folded_output(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_ROUND_CHALLENGE_CONTEXT_V1");
        push_digest(&mut out, &self.folding_protocol_id);
        push_digest(&mut out, &self.input_public_boundary_digest);
        push_digest(&mut out, &self.batch_manifest_root);
        push_digest(&mut out, &self.source_roots_digest);
        push_u64(&mut out, self.active_count);
        push_u64(&mut out, self.batch_size);
        out
    }
}

impl Symbt3NativeMessageOraclePublicBoundary {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_MESSAGE_ORACLE_PUBLIC_BOUNDARY_V1");
        push_bytes(&mut out, &self.message_oracle_policy.canonical_bytes());
        push_digest(&mut out, &self.message_oracle_roots_digest);
        push_digest(&mut out, &self.message_round_layouts_digest);
        push_digest(&mut out, &self.message_oracle_policy_digest);
        out
    }
}

impl Symbt3ManifestComponentPublicView {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_MANIFEST_COMPONENT_PUBLIC_VIEW_V1");
        push_u32(&mut out, self.component_id);
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_bytes(&mut out, &self.visibility.canonical_bytes());
        push_digest(&mut out, &self.layout_digest);
        push_u64(&mut out, self.value_count as u64);
        push_digest(&mut out, &self.manifest_component_root);
        push_digest(&mut out, &self.source_component_root);
        push_babybear_vec(&mut out, &self.public_manifest_values);
        push_babybear_vec(&mut out, &self.public_source_values);
        out
    }
}

impl Symbt3CommittedPrivateManifestPublicStatement {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_COMMITTED_PRIVATE_MANIFEST_PUBLIC_STATEMENT_V1",
        );
        push_bytes(&mut out, &self.manifest_policy.canonical_bytes());
        push_bytes(&mut out, &self.source_policy.canonical_bytes());
        push_bytes(&mut out, &self.zk_status.canonical_bytes());
        push_bytes(&mut out, &self.root_policy.canonical_bytes());
        push_digest(&mut out, &self.manifest_layout_digest);
        push_digest(&mut out, &self.source_layout_digest);
        push_digest(&mut out, &self.manifest_oracle_root);
        push_digest(&mut out, &self.source_oracle_root);
        push_digest(&mut out, &self.batch_manifest_root);
        push_u64(&mut out, self.components.len() as u64);
        for component in &self.components {
            push_bytes(&mut out, &component.canonical_bytes());
        }
        out
    }

    #[must_use]
    pub fn digest(&self) -> Digest32 {
        digest_bytes(&self.canonical_bytes())
    }

    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        self.canonical_bytes().len()
    }

    #[must_use]
    pub fn committed_private_component_count(&self) -> usize {
        self.components
            .iter()
            .filter(|component| {
                component.visibility == Symbt3ManifestVisibility::CommittedPrivateNonZk
            })
            .count()
    }

    #[must_use]
    pub fn committed_private_public_bytes(&self) -> usize {
        self.components
            .iter()
            .filter(|component| {
                component.visibility == Symbt3ManifestVisibility::CommittedPrivateNonZk
            })
            .map(|component| {
                component.public_manifest_values.len() * std::mem::size_of::<u64>()
                    + component.public_source_values.len() * std::mem::size_of::<u64>()
            })
            .sum()
    }
}

#[must_use]
pub const fn native_oracle_root_policy_allowed_for_profile(
    policy: NativeOracleRootPolicy,
    profile: NativeOracleVerificationProfile,
) -> bool {
    match profile {
        NativeOracleVerificationProfile::Development => true,
        NativeOracleVerificationProfile::Infrastructure
        | NativeOracleVerificationProfile::ProductAuthority
        | NativeOracleVerificationProfile::NativeManifestAuthority
        | NativeOracleVerificationProfile::NativeMessageAuthority => {
            matches!(policy, NativeOracleRootPolicy::CanonicalWhirRootV1)
        }
    }
}

#[must_use]
pub const fn manifest_commitment_policy_allowed_for_native_manifest_membership(
    policy: ManifestCommitmentPolicy,
) -> bool {
    matches!(
        policy,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1
    )
}

#[must_use]
pub const fn source_commitment_policy_allowed_for_native_manifest_membership(
    policy: SourceCommitmentPolicy,
) -> bool {
    matches!(policy, SourceCommitmentPolicy::NativeSourceOracleOpeningV1)
}

#[must_use]
pub const fn symbt3_manifest_visibility_allowed_for_policies(
    visibility: Symbt3ManifestVisibility,
    zk_status: Symbt3ZkStatus,
    manifest_policy: ManifestCommitmentPolicy,
    source_policy: SourceCommitmentPolicy,
) -> bool {
    match visibility {
        Symbt3ManifestVisibility::PublicBoundary => true,
        Symbt3ManifestVisibility::CommittedPrivateNonZk => {
            matches!(
                manifest_policy,
                ManifestCommitmentPolicy::NativeManifestOracleOpeningV1
            ) && matches!(
                source_policy,
                SourceCommitmentPolicy::NativeSourceOracleOpeningV1
            ) && matches!(
                zk_status,
                Symbt3ZkStatus::NonZkIntegrityOnly | Symbt3ZkStatus::ExplicitNonZkResearch
            )
        }
    }
}

#[must_use]
pub const fn symbt3_message_oracle_policy_allowed_for_native_message_oracles(
    policy: Symbt3MessageOraclePolicy,
) -> bool {
    matches!(
        policy,
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1
    )
}

#[must_use]
pub fn profile_meets_native_non_zk_folding_integrity(
    metadata: &Symbt3NonZkFoldingIntegrityProfileMetadata,
) -> bool {
    symbt3_non_zk_folding_integrity_profile_report(metadata).ok
}

#[must_use]
pub fn symbt3_non_zk_folding_integrity_profile_report(
    metadata: &Symbt3NonZkFoldingIntegrityProfileMetadata,
) -> Symbt3NonZkFoldingIntegrityProfileReport {
    let native_profile_ok = matches!(
        metadata.native_profile,
        Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1)
    );
    let native_manifest_policy_ok = matches!(
        metadata.manifest_policy,
        Some(ManifestCommitmentPolicy::NativeManifestOracleOpeningV1)
    );
    let native_source_policy_ok = matches!(
        metadata.source_policy,
        Some(SourceCommitmentPolicy::NativeSourceOracleOpeningV1)
    );
    let native_message_policy_ok = matches!(
        metadata.message_oracle_policy,
        Some(Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1)
    );
    let canonical_root_policy_ok =
        metadata.root_policy == NativeOracleRootPolicy::CanonicalWhirRootV1;
    let non_zk_status_ok = matches!(
        metadata.zk_status,
        Symbt3ZkStatus::NonZkIntegrityOnly | Symbt3ZkStatus::ExplicitNonZkResearch
    );
    let committed_private_policy_ok = if metadata.committed_private_component_count == 0 {
        non_zk_status_ok
    } else {
        non_zk_status_ok && native_manifest_policy_ok && native_source_policy_ok
    };
    let message_layouts_ok = metadata.message_round_layouts.len()
        == metadata.native_message_round_count
        && build_native_message_oracle_specs(
            &metadata.message_round_layouts,
            metadata.batch_axis_log_size,
        )
        .is_some();
    let native_message_oracle_count_is_round_count =
        metadata.native_message_oracle_count == metadata.native_message_round_count;
    let message_oracle_count_ok = metadata.native_message_round_count > 0
        && native_message_oracle_count_is_round_count
        && metadata.native_message_pcs_opening_count == metadata.native_message_round_count
        && message_layouts_ok;
    let manifest_source_oracle_count_ok = metadata.manifest_source_native_oracle_count == 2
        && metadata.manifest_source_native_pcs_opening_count == 2;
    let proof_shape_ok = metadata.logical_native_envelope_count == 1
        && metadata.top_level_whir_proof_count == 1
        && metadata.family_columnar_subproof_count == 0
        && metadata.message_to_trace_binding_count == 0
        && !metadata.monolithic_fallback;
    let required_families_ok = metadata.required_semantic_families.all_required_ok();
    let semantic_profile_version_ok = metadata.semantic_profile_version
        >= SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION;
    let no_monolithic_fallback = !metadata.monolithic_fallback;
    let product_routing_unchanged = !metadata.product_default_route_attempted
        && !metadata.product_eligible
        && !metadata.native_product_route_version_exists;
    let ok = native_profile_ok
        && native_manifest_policy_ok
        && native_source_policy_ok
        && native_message_policy_ok
        && canonical_root_policy_ok
        && committed_private_policy_ok
        && non_zk_status_ok
        && message_oracle_count_ok
        && manifest_source_oracle_count_ok
        && proof_shape_ok
        && required_families_ok
        && semantic_profile_version_ok
        && no_monolithic_fallback
        && product_routing_unchanged;

    Symbt3NonZkFoldingIntegrityProfileReport {
        ok,
        native_profile_ok,
        native_manifest_policy_ok,
        native_source_policy_ok,
        native_message_policy_ok,
        canonical_root_policy_ok,
        committed_private_policy_ok,
        non_zk_status_ok,
        message_oracle_count_ok,
        manifest_source_oracle_count_ok,
        proof_shape_ok,
        required_families_ok,
        semantic_profile_version_ok,
        no_monolithic_fallback,
        product_routing_unchanged,
        native_oracle_count_manifest_source: metadata.manifest_source_native_oracle_count,
        native_oracle_count_messages: metadata.native_message_oracle_count,
        native_message_round_count: metadata.native_message_round_count,
        native_message_oracle_count: metadata.native_message_oracle_count,
        native_message_oracle_count_is_round_count,
        family_columnar_subproof_count: metadata.family_columnar_subproof_count,
        gate_ok: ok,
    }
}

#[must_use]
pub fn profile_meets_native_accumulator_authority(
    metadata: &Symbt3NativeAccumulatorAuthorityProfileMetadata,
) -> bool {
    symbt3_native_accumulator_authority_profile_report(metadata).ok
}

#[must_use]
pub fn profile_meets_native_accumulator_authority_full(
    metadata: &Symbt3NativeAccumulatorAuthorityProfileMetadata,
) -> bool {
    symbt3_native_accumulator_authority_profile_report(metadata).full_ok
}

#[must_use]
pub fn symbt3_native_accumulator_authority_profile_report(
    metadata: &Symbt3NativeAccumulatorAuthorityProfileMetadata,
) -> Symbt3NativeAccumulatorAuthorityProfileReport {
    let workload_kind_ok = metadata.workload_kind
        == Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        && metadata.full_accumulator_workload
        && !metadata.smoke_profile;
    let native_profile_ok = matches!(
        metadata.native_profile,
        Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1)
    );
    let native_manifest_policy_ok = matches!(
        metadata.manifest_policy,
        Some(ManifestCommitmentPolicy::NativeManifestOracleOpeningV1)
    );
    let native_source_policy_ok = matches!(
        metadata.source_policy,
        Some(SourceCommitmentPolicy::NativeSourceOracleOpeningV1)
    );
    let native_message_policy_ok = matches!(
        metadata.message_oracle_policy,
        Some(Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1)
    );
    let canonical_root_policy_ok =
        metadata.root_policy == NativeOracleRootPolicy::CanonicalWhirRootV1;
    let non_zk_status_ok = matches!(
        metadata.zk_status,
        Symbt3ZkStatus::NonZkIntegrityOnly | Symbt3ZkStatus::ExplicitNonZkResearch
    );
    let tuple_leaf_mode_ok = metadata.multi_oracle_mode
        == Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1
        && metadata.tuple_leaf_layout == SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT;
    let rlc_bits_present = metadata.rlc_batching_bits.is_some_and(|bits| bits > 0);
    let rlc_soundness_ok = rlc_bits_present
        && metadata.total_rlc_batching_bits >= metadata.target_soundness_bits
        && metadata
            .rlc_batching_bits
            .is_some_and(|bits| bits == metadata.total_rlc_batching_bits)
        && metadata.effective_soundness_bits >= metadata.target_soundness_bits;
    let full_rlc_soundness_ok = rlc_soundness_ok
        && metadata.rlc_repetition_count
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        && metadata.rlc_batching_bits_per_repetition > 0
        && metadata.total_rlc_batching_bits
            >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS
        && metadata.effective_soundness_bits >= metadata.soundness_bound_bits;
    let committed_private_policy_ok = if metadata.committed_private_component_count == 0 {
        non_zk_status_ok
    } else {
        non_zk_status_ok && native_manifest_policy_ok && native_source_policy_ok
    };
    let message_layouts_ok = metadata.message_round_layouts.len()
        == metadata.native_message_round_count
        && build_native_message_oracle_specs(
            &metadata.message_round_layouts,
            metadata.batch_axis_log_size,
        )
        .is_some();
    let message_oracle_count_ok = metadata.native_message_round_count > 0
        && metadata.native_message_oracle_count == metadata.native_message_round_count
        && message_layouts_ok;
    let tuple_leaf_shape_ok = metadata.whir_instance_count == 1
        && metadata.root_count == 1
        && metadata.query_schedule_count == 1
        && metadata.transcript_count == 1
        && metadata.native_oracle_pcs_opening_count == 1
        && metadata.logical_oracle_count == 2 + metadata.native_message_round_count
        && metadata.native_manifest_source_oracle_count == 2
        && metadata.top_level_whir_proof_count == 1
        && metadata.family_columnar_subproof_count == 0
        && metadata.message_to_trace_binding_count == 0;
    let required_families_ok = metadata.required_semantic_families.all_required_ok();
    let semantic_profile_version_ok = metadata.semantic_profile_version
        >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_MIN_SEMANTIC_PROFILE_VERSION;
    let full_semantic_profile_version_ok = metadata.semantic_profile_version
        >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_MIN_SEMANTIC_PROFILE_VERSION;
    let no_monolithic_fallback = !metadata.monolithic_fallback;
    let product_routing_unchanged = !metadata.product_default_route_attempted
        && !metadata.product_eligible
        && !metadata.native_product_route_version_exists;
    let ok = native_profile_ok
        && native_manifest_policy_ok
        && native_source_policy_ok
        && native_message_policy_ok
        && canonical_root_policy_ok
        && non_zk_status_ok
        && tuple_leaf_mode_ok
        && tuple_leaf_shape_ok
        && rlc_soundness_ok
        && committed_private_policy_ok
        && message_oracle_count_ok
        && required_families_ok
        && semantic_profile_version_ok
        && no_monolithic_fallback
        && product_routing_unchanged;
    let full_ok =
        ok && workload_kind_ok && full_rlc_soundness_ok && full_semantic_profile_version_ok;

    Symbt3NativeAccumulatorAuthorityProfileReport {
        ok,
        full_ok,
        workload_kind_ok,
        full_accumulator_workload: metadata.full_accumulator_workload,
        smoke_profile: metadata.smoke_profile,
        native_profile_ok,
        native_manifest_policy_ok,
        native_source_policy_ok,
        native_message_policy_ok,
        canonical_root_policy_ok,
        non_zk_status_ok,
        tuple_leaf_mode_ok,
        tuple_leaf_shape_ok,
        rlc_soundness_ok,
        committed_private_policy_ok,
        message_oracle_count_ok,
        required_families_ok,
        semantic_profile_version_ok,
        no_monolithic_fallback,
        product_routing_unchanged,
        family_columnar_subproof_count: metadata.family_columnar_subproof_count,
        native_multi_oracle: tuple_leaf_mode_ok && tuple_leaf_shape_ok,
        tuple_leaf_layout: metadata.tuple_leaf_layout.clone(),
        logical_oracle_count: metadata.logical_oracle_count,
        native_message_round_count: metadata.native_message_round_count,
        native_message_oracle_count: metadata.native_message_oracle_count,
        native_oracle_pcs_opening_count: metadata.native_oracle_pcs_opening_count,
        rlc_batching_bits: metadata.rlc_batching_bits,
        rlc_repetition_count: metadata.rlc_repetition_count,
        rlc_batching_bits_per_repetition: metadata.rlc_batching_bits_per_repetition,
        total_rlc_batching_bits: metadata.total_rlc_batching_bits,
        effective_soundness_bits: metadata.effective_soundness_bits,
        gate_ok: ok,
    }
}
