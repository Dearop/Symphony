#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3N8IntegratedConstraintKind {
    K6aAccumulatorMainV1,
    NativeTupleLeafRepeatedRlcV1,
    AccumulatorTransitionBindingV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3N8IntegratedConstraintDescriptor {
    pub kind: Symbt3N8IntegratedConstraintKind,
    pub num_vars: usize,
    pub oracle_len: usize,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegratedK6aNativeK6aPaddingModeV1 {
    NoPadding,
    ZeroExtendRowsToIntegratedNumVars,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeK6aPaddingPolicyV1 {
    pub mode: IntegratedK6aNativeK6aPaddingModeV1,
    pub source_num_vars: usize,
    pub target_num_vars: usize,
    pub source_oracle_len: usize,
    pub target_oracle_len: usize,
    pub added_num_vars: usize,
    pub padded_row_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegratedK6aNativeTupleRepetitionAxisPlacementV1 {
    AppendedAfterLogicalAxes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeTupleRepetitionAxisMappingV1 {
    pub placement: IntegratedK6aNativeTupleRepetitionAxisPlacementV1,
    pub logical_num_vars: usize,
    pub repetition_axis_start: usize,
    pub repetition_axis_len: usize,
    pub rlc_repetition_count: usize,
    pub packed_num_vars: usize,
    pub integrated_num_vars: usize,
    pub integrated_padding_num_vars: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegratedK6aNativeLogicalOracleKindV1 {
    K6aAccumulatorMainV1,
    NativeTupleLeafPackedV1,
    NativeTupleLeafLogicalV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeLogicalOracleDescriptorV1 {
    pub kind: IntegratedK6aNativeLogicalOracleKindV1,
    pub oracle_id: Option<u32>,
    pub role: Option<WhirNativeOracleRole>,
    pub layout_digest: Digest32,
    pub root_digest: Option<Digest32>,
    pub source_num_vars: usize,
    pub integrated_num_vars: usize,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegratedK6aNativeClaimDescriptorKindV1 {
    K6aAccumulatorMainClaimsV1,
    NativeTupleLeafPackedClaimsV1,
    NativeTupleLeafLogicalClaimsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeClaimDescriptorV1 {
    pub kind: IntegratedK6aNativeClaimDescriptorKindV1,
    pub claim_count: usize,
    pub num_vars: usize,
    pub claims_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeClaimPlanV1 {
    pub version: u64,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub k6a_relation_id: Digest32,
    pub k6a_public_statement_digest: Digest32,
    pub k6a_semantic_descriptor_digest: Digest32,
    pub tuple_leaf_descriptor_digest: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub k6a_num_vars: usize,
    pub k6a_oracle_len: usize,
    pub tuple_logical_oracle_count: usize,
    pub tuple_logical_num_vars: usize,
    pub tuple_packed_num_vars: usize,
    pub tuple_packed_oracle_len: usize,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub k6a_padding_policy: IntegratedK6aNativeK6aPaddingPolicyV1,
    pub tuple_repetition_axis: IntegratedK6aNativeTupleRepetitionAxisMappingV1,
    pub logical_oracle_descriptors: Vec<IntegratedK6aNativeLogicalOracleDescriptorV1>,
    pub constraint_descriptors: Vec<Symbt3N8IntegratedConstraintDescriptor>,
    pub claim_descriptors: Vec<IntegratedK6aNativeClaimDescriptorV1>,
    pub combined_logical_oracle_descriptor_digest: Digest32,
    pub combined_constraint_descriptor_digest: Digest32,
    pub combined_claim_descriptor_digest: Digest32,
    pub claim_plan_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8IntegratedK6aSemanticConstraintRowKindV1 {
    VerifierOpeningClaimV1,
    FinalResidualZeroV1,
    ZEvalBindingV1,
    ProductSumcheckAcceptedV1,
    K6aPaddingZeroV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedK6aSemanticConstraintRowV1 {
    pub kind: N8IntegratedK6aSemanticConstraintRowKindV1,
    pub source_index: usize,
    pub integrated_row: usize,
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub aux_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedK6aSemanticConstraintsV1 {
    pub version: u64,
    pub complete: bool,
    pub k6a_relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub k6a_num_vars: usize,
    pub k6a_oracle_len: usize,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub verifier_point_count: usize,
    pub verifier_claim_count: usize,
    pub final_residual_count: usize,
    pub product_sumcheck_round_count: usize,
    pub padding_row_count: usize,
    pub verifier_points_digest: Digest32,
    pub verifier_claims_digest: Digest32,
    pub final_residual_digest: Digest32,
    pub product_sumcheck_digest: Digest32,
    pub rows: Vec<N8IntegratedK6aSemanticConstraintRowV1>,
    pub rows_digest: Digest32,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8IntegratedTupleRlcSemanticConstraintRowKindV1 {
    PackedOpeningClaimV1,
    LogicalOpeningClaimV1,
    RlcResidualZeroV1,
    TuplePaddingZeroV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedTupleRlcSemanticConstraintRowV1 {
    pub kind: N8IntegratedTupleRlcSemanticConstraintRowKindV1,
    pub source_index: usize,
    pub integrated_row: usize,
    pub repetition_index: Option<usize>,
    pub oracle_id: Option<u32>,
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub aux_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedTupleRlcSemanticConstraintsV1 {
    pub version: u64,
    pub complete: bool,
    pub proof_relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub tuple_leaf_descriptor_digest: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub packed_root: Digest32,
    pub logical_oracle_count: usize,
    pub logical_num_vars: usize,
    pub packed_num_vars: usize,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub tuple_leaf_layout: String,
    pub same_domain: bool,
    pub same_field: bool,
    pub same_rate: bool,
    pub same_folding_parameter: bool,
    pub claim_kind: WhirNativeEvalClaimKind,
    pub packing_challenge_digest: Digest32,
    pub derived_packing_challenge_digest: Digest32,
    pub packed_claims_digest: Digest32,
    pub logical_claims_digest: Digest32,
    pub opening_points_digest: Digest32,
    pub residuals_digest: Digest32,
    pub packed_row_count: usize,
    pub logical_row_count: usize,
    pub residual_row_count: usize,
    pub padding_row_count: usize,
    pub rows: Vec<N8IntegratedTupleRlcSemanticConstraintRowV1>,
    pub rows_digest: Digest32,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8IntegratedTransitionBindingSemanticConstraintRowKindV1 {
    AccumulatorBoundaryDigestV1,
    PublicStatementAndK6aProofV1,
    TupleLeafRootAndLayoutV1,
    NativeDescriptorAndMessageRootsV1,
    ManifestSourceBatchRootsV1,
    BatchShapeV1,
    WorkloadKindV1,
    N8PlanTableLayoutV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedTransitionBindingSemanticConstraintRowV1 {
    pub kind: N8IntegratedTransitionBindingSemanticConstraintRowKindV1,
    pub source_index: usize,
    pub integrated_row: usize,
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub aux_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedTransitionBindingSemanticConstraintsV1 {
    pub version: u64,
    pub complete: bool,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub profile_digest: Digest32,
    pub accumulator_instance_digest: Digest32,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub main_symbt3_relation_id: Digest32,
    pub k6a_proof_digest: Digest32,
    pub tuple_leaf_root: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub tuple_leaf_descriptor_digest: Digest32,
    pub tuple_leaf_packing_challenge_digest: Digest32,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_message_roots_digest: Digest32,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
    pub batch_manifest_root: Digest32,
    pub batch_size: u64,
    pub active_count: u64,
    pub k6a_num_vars: usize,
    pub k6a_oracle_len: usize,
    pub tuple_logical_oracle_count: usize,
    pub tuple_logical_num_vars: usize,
    pub tuple_packed_num_vars: usize,
    pub tuple_packed_oracle_len: usize,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub k6a_semantic_descriptor_digest: Digest32,
    pub tuple_rlc_semantic_descriptor_digest: Digest32,
    pub n8_claim_plan_digest: Digest32,
    pub n8_committed_table_layout_digest: Digest32,
    pub n8_committed_table_digest: Digest32,
    pub n8_combined_constraint_descriptor_digest: Digest32,
    pub n8_combined_claim_descriptor_digest: Digest32,
    pub k6a_constraint_descriptor_digest: Digest32,
    pub tuple_constraint_descriptor_digest: Digest32,
    pub transition_constraint_descriptor_digest: Digest32,
    pub transition_binding_digest: Digest32,
    pub rows: Vec<N8IntegratedTransitionBindingSemanticConstraintRowV1>,
    pub rows_digest: Digest32,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N8IntegratedSemanticCompletionFlagsV1 {
    pub version: u64,
    pub k6a_semantics_complete: bool,
    pub tuple_rlc_semantics_complete: bool,
    pub transition_semantics_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8SemanticBatchingFamilyV1 {
    K6aSourceRowsV1,
    K6aSemanticRowsV1,
    TupleRlcSemanticRowsV1,
    TransitionBindingSemanticRowsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N8SemanticBatchingFamilyDescriptorV1 {
    pub family: N8SemanticBatchingFamilyV1,
    pub source_row_count: usize,
    pub batched_query_count: usize,
    pub row_digest: Digest32,
    pub challenge_point_digest: Digest32,
    pub soundness_bits: usize,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N8K6aSourceRowBatchingV1 {
    pub version: u64,
    pub enabled: bool,
    pub descriptor: N8SemanticBatchingFamilyDescriptorV1,
    pub unbatched_source_opening_count: usize,
    pub batched_source_opening_count: usize,
    pub effective_soundness_bits: usize,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N8SemanticBatchingV1 {
    pub version: u64,
    pub enabled: bool,
    pub descriptor_binding_digest: Digest32,
    pub k6a_source: N8K6aSourceRowBatchingV1,
    pub k6a: N8SemanticBatchingFamilyDescriptorV1,
    pub tuple_rlc: N8SemanticBatchingFamilyDescriptorV1,
    pub transition_binding: N8SemanticBatchingFamilyDescriptorV1,
    pub unbatched_semantic_opening_count: usize,
    pub batched_semantic_opening_count: usize,
    pub effective_soundness_bits: usize,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegratedK6aNativeCommittedTableRowOwnerV1 {
    K6aAccumulatorMainRows,
    K6aZeroPaddingRows,
    NativeTupleLeafRepeatedRlcRows,
    NativeTupleLeafIntegratedPaddingRows,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeCommittedTableRowRangeV1 {
    pub owner: IntegratedK6aNativeCommittedTableRowOwnerV1,
    pub integrated_start: usize,
    pub row_count: usize,
    pub source_start: usize,
    pub source_row_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegratedK6aNativeCommittedTableAxisOwnerV1 {
    K6aSourceAxes,
    K6aPaddingAxes,
    TupleLeafLogicalAxes,
    TupleLeafRepetitionAxes,
    TupleLeafIntegratedPaddingAxes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeCommittedTableAxisRangeV1 {
    pub owner: IntegratedK6aNativeCommittedTableAxisOwnerV1,
    pub axis_start: usize,
    pub axis_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeCommittedTableCountersV1 {
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub k6a_padded_rows: usize,
    pub tuple_rows: usize,
    pub combined_constraint_count: usize,
    pub table_digest: Digest32,
    pub layout_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegratedK6aNativeCommittedTableV1 {
    pub version: u64,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub plan_digest: Digest32,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub k6a_padding_policy: IntegratedK6aNativeK6aPaddingPolicyV1,
    pub tuple_repetition_axis: IntegratedK6aNativeTupleRepetitionAxisMappingV1,
    pub row_ownership: Vec<IntegratedK6aNativeCommittedTableRowRangeV1>,
    pub axis_ownership: Vec<IntegratedK6aNativeCommittedTableAxisRangeV1>,
    pub logical_integrated_oracle_count: usize,
    pub one_oracle_per_batch_item_layout: bool,
    pub introduced_whir_root_count: usize,
    pub introduced_whir_proof_count: usize,
    pub counters: IntegratedK6aNativeCommittedTableCountersV1,
    pub layout_digest: Digest32,
    pub table_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealIntegratedK6aNativeEvaluatorRowKindV1 {
    K6aAccumulatorOpeningClaimV1,
    K6aAccumulatorResidualClaimV1,
    K6aAccumulatorZEvalClaimV1,
    K6aProductSumcheckRoundClaimV1,
    K6aZeroPaddingClaimV1,
    K6aSemanticVerifierOpeningClaimV1,
    K6aSemanticFinalResidualZeroV1,
    K6aSemanticZEvalBindingV1,
    K6aSemanticProductSumcheckAcceptedV1,
    K6aSemanticPaddingZeroV1,
    NativeTupleLeafPackedRlcClaimV1,
    NativeTupleLeafLogicalRlcClaimV1,
    NativeTupleLeafRlcBindingResidualV1,
    NativeTupleLeafIntegratedPaddingClaimV1,
    AccumulatorTransitionBindingClaimV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealIntegratedK6aNativeLogicalColumnV1 {
    K6aAccumulatorMain,
    NativeTupleLeafPacked,
    NativeTupleLeafLogical,
    AccumulatorTransitionBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealIntegratedK6aNativeEvaluatorRowV1 {
    pub kind: RealIntegratedK6aNativeEvaluatorRowKindV1,
    pub logical_column: RealIntegratedK6aNativeLogicalColumnV1,
    pub source_index: usize,
    pub integrated_row: usize,
    pub repetition_index: Option<usize>,
    pub oracle_id: Option<u32>,
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub aux_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealIntegratedK6aNativeEvaluatorCountersV1 {
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub k6a_claim_rows: usize,
    pub k6a_semantic_rows: usize,
    pub tuple_claim_rows: usize,
    pub padding_rows: usize,
    pub transition_binding_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealIntegratedK6aNativeEvaluatorV1 {
    pub version: u64,
    pub plan_digest: Digest32,
    pub committed_table_layout_digest: Digest32,
    pub committed_table_digest: Digest32,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub rows: Vec<RealIntegratedK6aNativeEvaluatorRowV1>,
    pub counters: RealIntegratedK6aNativeEvaluatorCountersV1,
    pub rows_digest: Digest32,
    pub table_digest: Digest32,
    pub evaluator_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3IntegratedK6aNativeWhirRelationV1 {
    pub version: u64,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub main_symbt3_relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub tuple_leaf_descriptor_digest: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub same_field: bool,
    pub same_rate: bool,
    pub same_folding_parameter: bool,
    pub claim_plan: IntegratedK6aNativeClaimPlanV1,
    pub committed_table: IntegratedK6aNativeCommittedTableV1,
    pub k6a_semantic_constraints: N8IntegratedK6aSemanticConstraintsV1,
    pub tuple_rlc_semantic_constraints: N8IntegratedTupleRlcSemanticConstraintsV1,
    pub transition_binding_semantic_constraints: N8IntegratedTransitionBindingSemanticConstraintsV1,
    pub semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    pub real_evaluator: RealIntegratedK6aNativeEvaluatorV1,
    pub transcript_binding_digest: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8IntegratedWhirTableRepresentationV1 {
    SameDomainMultipleLogicalColumns,
    ScalarOracleSelectorGatedRegions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8IntegratedWhirClaimBridgeKindV1 {
    K6aAccumulatorConstraintsV1,
    NativeTupleLeafRepeatedRlcConstraintsV1,
    AccumulatorTransitionBindingConstraintsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedWhirClaimBridgeDescriptorV1 {
    pub kind: N8IntegratedWhirClaimBridgeKindV1,
    pub claim_count: usize,
    pub source_num_vars: usize,
    pub integrated_num_vars: usize,
    pub source_constraint_digest: Digest32,
    pub source_claim_digest: Digest32,
    pub table_layout_digest: Digest32,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, Copy)]
pub struct N8IntegratedWhirProofInputs<'a> {
    pub version: u64,
    pub descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1,
    pub table_representation: N8IntegratedWhirTableRepresentationV1,
    pub integrated_whir_root: Option<Digest32>,
    pub integrated_whir_proof: Option<&'a WhirProof>,
    pub extra_whir_root_count: usize,
    pub extra_whir_proof_count: usize,
    pub legacy_k6a_proof: Option<&'a WhirProof>,
    pub legacy_tuple_leaf_proof: Option<&'a Symbt3TupleLeafMultiOracleProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedWhirProofPlan {
    pub version: u64,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub table_representation: N8IntegratedWhirTableRepresentationV1,
    pub descriptor_transcript_digest: Digest32,
    pub claim_plan_digest: Digest32,
    pub committed_table_layout_digest: Digest32,
    pub committed_table_digest: Digest32,
    pub integrated_num_vars: usize,
    pub integrated_oracle_len: usize,
    pub integrated_whir_root_count: usize,
    pub integrated_whir_proof_count: usize,
    pub delegated_split_proof_material_present: bool,
    pub semantic_batching: N8SemanticBatchingV1,
    pub bridge_claim_descriptors: Vec<N8IntegratedWhirClaimBridgeDescriptorV1>,
    pub combined_bridge_claim_descriptor_digest: Digest32,
    pub transcript_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedWhirQueryClaimV1 {
    pub bridge_kind: N8IntegratedWhirClaimBridgeKindV1,
    pub point: Vec<BabyBear>,
    pub point_digest: Digest32,
    pub value: BabyBear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedWhirQueryScheduleV1 {
    pub version: u64,
    pub integrated_num_vars: usize,
    pub transcript_digest: Digest32,
    pub combined_bridge_claim_descriptor_digest: Digest32,
    pub query_claims: Vec<N8IntegratedWhirQueryClaimV1>,
    pub query_claims_digest: Digest32,
    pub query_schedule_digest: Digest32,
}

#[derive(Debug, Clone, Copy)]
pub struct N8IntegratedWhirVerifierInput<'a> {
    pub version: u64,
    pub prover_mode: N8IntegratedWhirProverModeV1,
    pub descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1,
    pub proof_plan: &'a N8IntegratedWhirProofPlan,
    pub claim_plan: &'a IntegratedK6aNativeClaimPlanV1,
    pub committed_table_layout_digest: Digest32,
    pub committed_table_digest: Digest32,
    pub combined_claim_descriptors: &'a [N8IntegratedWhirClaimBridgeDescriptorV1],
    pub combined_claim_descriptor_digest: Digest32,
    pub integrated_whir_root: Option<Digest32>,
    pub integrated_whir_proof: Option<&'a WhirProof>,
    pub query_schedule: Option<&'a N8IntegratedWhirQueryScheduleV1>,
    pub whir_instance_count: usize,
    pub root_count: usize,
    pub extra_whir_root_count: usize,
    pub extra_whir_proof_count: usize,
    pub legacy_k6a_proof: Option<&'a WhirProof>,
    pub legacy_tuple_leaf_proof: Option<&'a Symbt3TupleLeafMultiOracleProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N8IntegratedWhirProverModeV1 {
    SyntheticNonAuthoritativeV1,
    RealIntegratedK6aNativeEvaluatorV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N8IntegratedWhirPrototypeCounters {
    pub whir_instance_count: usize,
    pub root_count: usize,
    pub query_schedule_count: usize,
    pub tuple_pcs_proof_count: usize,
    pub delegated_split_proof_material_present: bool,
    pub synthetic_non_authoritative: bool,
}

#[derive(Debug, Clone)]
pub struct N8IntegratedWhirProverOutput {
    pub version: u64,
    pub mode: N8IntegratedWhirProverModeV1,
    pub proof_plan: N8IntegratedWhirProofPlan,
    pub integrated_whir_root: Digest32,
    pub integrated_whir_proof: WhirProof,
    pub query_schedule: N8IntegratedWhirQueryScheduleV1,
    pub counters: N8IntegratedWhirPrototypeCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3AccumulationAuthorityProfile {
    N8NonZkSameShapeV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AccumulatorPublicInstance {
    pub profile_digest: Digest32,
    pub shape_id: Digest32,
    pub accumulator_digest: Digest32,
    pub accumulator_coordinates: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AccumulationBatch {
    pub profile: Symbt3AuthorityProfile,
    pub public_statement: BatchedCpSymbt3PublicStatement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AccumulatorObject {
    pub public_instance: Symbt3AccumulatorPublicInstance,
}

#[derive(Debug, Clone)]
pub struct Symbt3AccumulationProof {
    pub version: u64,
    pub public_statement_digest: Digest32,
    pub accumulator_instance_digest: Digest32,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub batch_size: u64,
    pub active_count: u64,
    pub k6a_relation_id: Digest32,
    pub whir_param_digest: Digest32,
    pub tuple_leaf_root: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub tuple_leaf_descriptor_digest: Digest32,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_message_roots_digest: Digest32,
    pub n8_transcript_binding_digest: Digest32,
    pub n8_claim_plan_digest: Digest32,
    pub n8_committed_table_layout_digest: Digest32,
    pub n8_committed_table_digest: Digest32,
    pub semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    pub descriptor: Symbt3IntegratedK6aNativeWhirRelationV1,
    pub output: N8IntegratedWhirProverOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AccumulationVerificationReport {
    pub ok: bool,
    pub blocked: bool,
    pub blocker: Option<Symbt3N8IntegratedPrototypeBlocker>,
    pub semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct N8IntegratedDescriptorBuildProfileV1 {
    pub k6a_semantic_descriptor_ms: f64,
    pub claim_plan_ms: f64,
    pub descriptor_digest_construction_ms: f64,
    pub integrated_table_construction_ms: f64,
    pub k6a_semantic_rows_ms: f64,
    pub tuple_rlc_semantic_rows_ms: f64,
    pub transition_binding_semantic_rows_ms: f64,
    pub semantic_row_construction_ms: f64,
    pub real_evaluator_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct N8DirectSemanticInputBuildProfileV1 {
    pub relation_statement_ms: f64,
    pub k6a_relation_construction_ms: f64,
    pub k6a_public_statement_construction_ms: f64,
    pub k6a_witness_conversion_ms: f64,
    pub k6a_claim_extraction_ms: f64,
    pub adapter_construction_ms: f64,
    pub digest_canonical_serialization_ms: f64,
    pub tuple_rlc_input_ms: f64,
    pub tuple_rlc_raw_values_ms: f64,
    pub tuple_rlc_descriptor_ms: f64,
    pub tuple_rlc_claims_ms: f64,
    pub tuple_rlc_packed_root_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3N8K6aSemanticSourceV1 {
    pub source_digest: Digest32,
    pub relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub num_vars: usize,
    pub oracle_len: usize,
    pub verifier_points: Vec<Vec<BabyBear>>,
    pub verifier_claims: Vec<BabyBear>,
    pub final_residuals: [BabyBear; 3],
    pub z_eval: BabyBear,
    pub product_sumcheck_rounds: Vec<[BabyBear; 4]>,
}

#[derive(Debug, Clone)]
pub struct N8DirectSemanticInputsV1 {
    pub relation: BatchedCpSymbt3RelationDescription,
    pub statement: crate::batched_cp::BatchedCpSymbt3PublicStatement,
    pub k6a_semantic_source: Symbt3N8K6aSemanticSourceV1,
    pub k6a_adapter: Symbt3NativeAccumulatorK6aWorkloadAdapter,
    pub native_tuple_leaf: Symbt3N7bNativeTupleLeafProofParts,
    pub profile: N8DirectSemanticInputBuildProfileV1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct N8IntegratedWhirProveProfileV1 {
    pub proof_plan_validation_ms: f64,
    pub committed_table_rebuild_ms: f64,
    pub query_claim_construction_ms: f64,
    pub integrated_table_values_ms: f64,
    pub whir_prove_ms: f64,
    pub query_schedule_ms: f64,
    pub serialization_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct N8IntegratedProofPlanBuildProfileV1 {
    pub bridge_descriptor_ms: f64,
    pub semantic_batching_ms: f64,
    pub transcript_digest_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3N8IntegratedPrototypeBlocker {
    MissingK6aAdapter,
    MissingNativeTupleLeafProof,
    WorkloadKindMismatch,
    SmokeProfile,
    K6aNotFullWorkload,
    TupleLeafProfileIncompatible,
    RepeatedRlcSoundnessMissingOrWeak,
    ShapeMismatch,
    CombinedConstraintEvaluatorMissing,
    ClaimPlanDigestMismatch,
    PaddingPolicyMismatch,
    RepetitionAxisMismatch,
    IntegratedNumVarsMismatch,
    DescriptorPlanMismatch,
    CommittedTableDigestMismatch,
    CommittedTableLayoutMismatch,
    AmbiguousIntegratedLayout,
    ExtraWhirProofOrRoot,
    SplitK6aTupleDelegationAttempt,
    OneOraclePerBatchItemLayout,
    SyntheticNonAuthoritativeOutput,
    IntegratedSemanticChecksIncomplete,
    K6aSemanticConstraintViolation,
    TupleRlcSemanticConstraintViolation,
    TransitionBindingSemanticConstraintViolation,
    IntegratedWhirProofApiMissing,
    IntegratedWhirRootMismatch,
    IntegratedWhirQueryScheduleMismatch,
    IntegratedWhirProofRejected,
}
