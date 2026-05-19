#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symbt3FoldingIntegritySemanticFamilies {
    pub manifest_evaluation_claim: bool,
    pub accumulator_transition_consistency: bool,
    pub k1_semantic_family: bool,
    pub k2_semantic_family: bool,
    pub k3_semantic_family: bool,
    pub k4_semantic_family: bool,
    pub production_norm_range_bundle: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NonZkFoldingIntegrityProfileMetadata {
    pub native_profile: Option<Symbt3NativeOracleProfile>,
    pub manifest_policy: Option<ManifestCommitmentPolicy>,
    pub source_policy: Option<SourceCommitmentPolicy>,
    pub message_oracle_policy: Option<Symbt3MessageOraclePolicy>,
    pub root_policy: NativeOracleRootPolicy,
    pub zk_status: Symbt3ZkStatus,
    pub committed_private_component_count: usize,
    pub manifest_source_native_oracle_count: usize,
    pub manifest_source_native_pcs_opening_count: usize,
    pub native_message_round_count: usize,
    pub native_message_oracle_count: usize,
    pub native_message_pcs_opening_count: usize,
    pub batch_size: usize,
    pub batch_axis_log_size: usize,
    pub message_round_layouts: Vec<Symbt3NativeRoundMessageOracleLayoutV1>,
    pub logical_native_envelope_count: usize,
    pub top_level_whir_proof_count: usize,
    pub family_columnar_subproof_count: usize,
    pub message_to_trace_binding_count: usize,
    pub semantic_profile_version: u32,
    pub required_semantic_families: Symbt3FoldingIntegritySemanticFamilies,
    pub k5_masking_available: bool,
    pub monolithic_fallback: bool,
    pub product_default_route_attempted: bool,
    pub product_eligible: bool,
    pub native_product_route_version_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NonZkFoldingIntegrityProfileReport {
    pub ok: bool,
    pub native_profile_ok: bool,
    pub native_manifest_policy_ok: bool,
    pub native_source_policy_ok: bool,
    pub native_message_policy_ok: bool,
    pub canonical_root_policy_ok: bool,
    pub committed_private_policy_ok: bool,
    pub non_zk_status_ok: bool,
    pub message_oracle_count_ok: bool,
    pub manifest_source_oracle_count_ok: bool,
    pub proof_shape_ok: bool,
    pub required_families_ok: bool,
    pub semantic_profile_version_ok: bool,
    pub no_monolithic_fallback: bool,
    pub product_routing_unchanged: bool,
    pub native_oracle_count_manifest_source: usize,
    pub native_oracle_count_messages: usize,
    pub native_message_round_count: usize,
    pub native_message_oracle_count: usize,
    pub native_message_oracle_count_is_round_count: bool,
    pub family_columnar_subproof_count: usize,
    pub gate_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeFoldingIntegrityCounters {
    pub top_level_whir_proof_count: usize,
    pub family_columnar_subproof_count: usize,
    pub backend_table_count: usize,
    pub native_oracle_count: usize,
    pub native_manifest_source_oracle_count: usize,
    pub native_message_oracle_count: usize,
    pub native_oracle_eval_claim_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub native_oracle_descriptor_bytes: usize,
    pub message_to_trace_binding_count: usize,
    pub accumulator_transition_claims: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeFoldingIntegrityPublicProfile {
    pub route_status: Symbt3NativeFoldingIntegrityRouteStatus,
    pub zk_status: Symbt3ZkStatus,
    pub product_accepts_native_non_zk_folding_integrity: bool,
    pub k5_masking_required: bool,
    pub allow_monolithic_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeFoldingIntegrityInstance {
    pub native_profile: Option<Symbt3NativeOracleProfile>,
    pub manifest_policy: ManifestCommitmentPolicy,
    pub source_policy: SourceCommitmentPolicy,
    pub message_oracle_policy: Symbt3MessageOraclePolicy,
    pub root_policy: NativeOracleRootPolicy,
    pub zk_status: Symbt3ZkStatus,
    pub symbt3_relation_id: Digest32,
    pub whir_param_digest: Digest32,
    pub manifest_layout_digest: Digest32,
    pub source_layout_digest: Digest32,
    pub source_column_layout_digest: Digest32,
    pub folding_protocol_id: Digest32,
    pub input_public_boundary_digest: Digest32,
    pub source_roots_digest: Digest32,
    pub active_count: u64,
    pub batch_size: u64,
    pub folded_output_digest: Digest32,
    pub batch_axis_log_size: usize,
    pub round_layouts: Vec<Symbt3NativeRoundMessageOracleLayoutV1>,
    pub committed_private_component_count: usize,
    pub semantic_profile_version: u32,
    pub required_semantic_families: Symbt3FoldingIntegritySemanticFamilies,
    pub k5_masking_available: bool,
    pub monolithic_fallback: bool,
    pub product_default_route_attempted: bool,
    pub product_eligible: bool,
    pub native_product_route_version_exists: bool,
    pub backend_table_count: usize,
    pub accumulator_transition_claims: usize,
    pub main_instance: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeFoldingIntegrityWitness {
    pub main_witness: Vec<u8>,
    pub manifest_evals: Vec<BabyBear>,
    pub source_evals: Vec<BabyBear>,
    pub message_oracle_evaluations: Vec<Vec<BabyBear>>,
}

#[derive(Debug, Clone)]
pub struct Symbt3NativeFoldingIntegrityProof {
    pub version: u64,
    pub proof_kind: Symbt3NativeFoldingProofKind,
    pub profile_digest: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub symbt3_relation_id: Digest32,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_message_roots_digest: Digest32,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
    pub batch_manifest_root: Digest32,
    pub source_column_layout_digest: Digest32,
    pub message_oracle_policy_digest: Digest32,
    pub manifest_commitment_policy_digest: Digest32,
    pub binding_digest: Digest32,
    pub round_challenges: Vec<BabyBear>,
    pub symbt3_proof: WhirProof,
    pub native_oracle_proof: WhirNativeMultiOracleProof,
    pub counters: Symbt3NativeFoldingIntegrityCounters,
}

#[must_use]
pub fn symbt3_native_folding_integrity_proof_size_hint(
    proof: &Symbt3NativeFoldingIntegrityProof,
) -> usize {
    let main_sumcheck_bytes = proof.symbt3_proof.sumcheck_rounds_3.len() * 3 * 8
        + proof.symbt3_proof.sumcheck_rounds_4.len() * 4 * 8
        + proof.symbt3_proof.linear_checks.len() * 64
        + proof.symbt3_proof.whir_pcs_proof.rounds.len() * 256
        + 128;
    proof.metadata_canonical_bytes().len()
        + proof.native_oracle_proof.metadata_canonical_bytes().len()
        + proof.native_oracle_proof.pcs_openings.len() * 256
        + main_sumcheck_bytes
}

