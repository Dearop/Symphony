//! Native multi-oracle WHIR evaluation envelope.
//!
//! N1 is an infrastructure layer: it keeps one logical proof envelope while
//! allowing multiple named WHIR/PCS oracles to be opened and checked under a
//! shared descriptor transcript. The current whir-p3 integration commits one
//! polynomial per PCS payload, so this envelope contains one internal PCS
//! opening payload per native oracle. These payloads are not SYMBT2F family
//! subproofs and are accounted for separately.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

use crate::batched_cp::{
    derive_symbt3_public_statement_digest, BatchedCpSymbt3RelationDescription, ProductProofKind,
    Symbt3AccumulatorInstance, Symbt3AccumulatorWitness, Symbt3AuthorityProfile,
    Symbt3TypedMessageOracle,
};
use crate::folding::digest::Digest32;
use crate::snark::BackendSnark;

use super::{
    canonical_whir_proof_bytes, derive_challenge, mle_eval_bb, whir_commit_and_prove_multi,
    whir_commit_initial_root_only, whir_verify_opening_multi, WhirMmcs, WhirPcsProof, WhirProof,
    WhirProvingKey, WhirSnark, WhirVerifyingKey, EF, F,
};

pub const WHIR_NATIVE_MULTI_ORACLE_PROOF_VERSION: u64 = 1;
pub const WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION: u64 = 1;
pub const SYMBT3_N2_MANIFEST_ORACLE_ID: u32 = 1;
pub const SYMBT3_N2_SOURCE_ORACLE_ID: u32 = 2;
pub const SYMBT3_N2_MANIFEST_SOURCE_EQUALITY_DOMAIN: &str = "SYMBT3_N2_MANIFEST_SOURCE_EQUALITY";
pub const SYMBT3_N4_MESSAGE_ORACLE_ID_BASE: u32 = 1000;
pub const SYMBT3_N4_ROUND_MESSAGE_VIEW_DOMAIN: &str = "SYMBT3_N4_ROUND_MESSAGE_VIEW";
pub const SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION: u32 = 5;
pub const SYMBT3_NATIVE_FOLDING_INTEGRITY_PROOF_VERSION: u64 = 1;
pub const SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION: u64 = 1;
pub const SYMBT3_TUPLE_LEAF_LAYOUT_VERSION: u64 = 1;
pub const SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT: &str = "same_domain_rlc_tuple_leaf_v1";
pub const SYMBT3_SAME_DOMAIN_VECTOR_TUPLE_LEAF_LAYOUT: &str = "same_domain_tuple_leaf_v1";
pub const SYMBT3_RLC_TUPLE_LEAF_PACKING_DOMAIN: &str = "SYMBT3_RLC_TUPLE_LEAF_PACKING_V1";
pub const SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS: usize = 31;
pub const SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT: usize = 4;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT: usize = 4;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_BATCHING_BITS_PER_REPETITION: usize =
    SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS: usize = 120;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS: usize = 100;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_PROOF_VERSION: u64 = 1;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_WRAPPER_VERSION: u64 = 1;
pub const SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION: u64 = 1;
pub const INTEGRATED_K6A_NATIVE_CLAIM_PLAN_VERSION: u64 = 1;
pub const INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_VERSION: u64 = 1;
pub const N8_INTEGRATED_WHIR_PROOF_INPUTS_VERSION: u64 = 1;
pub const N8_INTEGRATED_WHIR_PROOF_PLAN_VERSION: u64 = 1;
pub const N8_INTEGRATED_WHIR_VERIFIER_INPUT_VERSION: u64 = 1;
pub const N8_INTEGRATED_WHIR_QUERY_SCHEDULE_VERSION: u64 = 1;
pub const N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION: u64 = 1;
pub const REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_VERSION: u64 = 1;
pub const N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_VERSION: u64 = 1;
pub const N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINTS_VERSION: u64 = 1;
pub const N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_CONSTRAINTS_VERSION: u64 = 1;
pub const N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION: u64 = 1;
pub const N8_SEMANTIC_BATCHING_VERSION: u64 = 1;
pub const N8_SEMANTIC_BATCHING_CHALLENGE_SOUNDNESS_BITS: usize = 31;
pub const SYMBT3_N8_INTEGRATED_K6A_NATIVE_TRANSCRIPT_DOMAIN: &str =
    "SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_V1";
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_MIN_SEMANTIC_PROFILE_VERSION: u32 = 7;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_MIN_SEMANTIC_PROFILE_VERSION: u32 = 8;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_TARGET_SOUNDNESS_BITS: usize =
    SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
pub const SYMBT3_N7_TUPLE_LEAF_OPENING_DOMAIN: &str =
    "SYMBT3_N7_NATIVE_ACCUMULATOR_AUTHORITY_TUPLE_LEAF";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhirNativeOracleRole {
    Manifest,
    Source,
    MessageRound { round: u32 },
    Accumulator,
    FoldedBoundary,
    Auxiliary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhirNativeOpeningSchedule {
    /// All claims under this schedule share a fixed N1 point domain.
    SamePoint,
    /// Claims are opened at descriptor-specific points.
    PerOraclePoint,
    /// Claims with the same claim kind and domain separator are opened at the
    /// same point derived from the ordered descriptor/root digest.
    ///
    /// Use this with [`WhirNativeEvalClaimKind::EqualitySide`] for equality
    /// checks such as `ManifestOracle(zeta) = SourceOracle(zeta)`.
    TranscriptDerived { domain_separator: &'static str },
    /// Transcript-derived schedule with an additional policy-specific binding
    /// digest. N2 uses this to bind the equality point to the native manifest
    /// batch root while preserving the N1 logical envelope.
    TranscriptDerivedWithBinding {
        domain_separator: &'static str,
        binding_digest: Digest32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirNativeOracleSpec {
    pub version: u64,
    pub oracle_id: u32,
    pub role: WhirNativeOracleRole,
    pub layout_digest: Digest32,
    pub num_vars: usize,
    pub opening_schedule: WhirNativeOpeningSchedule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirNativeOracleDescriptor {
    pub version: u64,
    pub oracle_id: u32,
    pub role: WhirNativeOracleRole,
    pub layout_digest: Digest32,
    pub num_vars: usize,
    pub root: Digest32,
    pub opening_schedule: WhirNativeOpeningSchedule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WhirNativeEvalClaimKind {
    DirectOpening,
    EqualitySide,
    MessageView,
    ManifestView,
    SourceView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirNativeEvalRequest {
    pub oracle_id: u32,
    pub claim_kind: WhirNativeEvalClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirNativeOracleEvalClaim {
    pub oracle_id: u32,
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub claim_kind: WhirNativeEvalClaimKind,
}

#[derive(Debug, Clone)]
pub struct WhirNativeOraclePcsOpening {
    pub oracle_id: u32,
    pub proof: WhirPcsProof<F, EF, WhirMmcs>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirNativeOracleCounters {
    pub native_oracle_count: usize,
    pub native_oracle_descriptor_bytes: usize,
    pub native_oracle_eval_claim_count: usize,
    pub native_oracle_opening_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub native_oracle_transcript_squeezes: usize,
}

#[derive(Debug, Clone)]
pub struct WhirNativeMultiOracleProof {
    pub version: u64,
    pub root_policy: NativeOracleRootPolicy,
    pub proof_relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_oracle_eval_claims_digest: Digest32,
    pub native_multi_oracle_envelope_digest: Digest32,
    pub descriptors: Vec<WhirNativeOracleDescriptor>,
    pub eval_claims: Vec<WhirNativeOracleEvalClaim>,
    pub pcs_openings: Vec<WhirNativeOraclePcsOpening>,
    pub counters: WhirNativeOracleCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3NativeMultiOracleMode {
    CompatibilityEnvelopeV1,
    SameDomainRlcTupleLeafV1,
    SameDomainVectorTupleLeafV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TupleLeafLayoutV1 {
    pub version: u64,
    pub mode: Symbt3NativeMultiOracleMode,
    pub logical_oracle_count: usize,
    pub num_vars: usize,
    pub packing_challenge_digest: Digest32,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TupleLeafPackedEvalClaim {
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub claim_kind: WhirNativeEvalClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TupleLeafMultiOracleCounters {
    pub logical_oracle_count: usize,
    pub whir_instance_count: usize,
    pub query_schedule_count: usize,
    pub transcript_count: usize,
    pub root_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub logical_eval_claim_count: usize,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub tuple_leaf_layout: String,
    pub same_domain: bool,
    pub same_field: bool,
    pub same_rate: bool,
    pub same_folding_parameter: bool,
    pub merkle_path_proxy: usize,
    pub hash_estimate: usize,
    pub field_op_estimate: usize,
}

#[derive(Debug, Clone)]
pub struct Symbt3TupleLeafMultiOracleProof {
    pub version: u64,
    pub mode: Symbt3NativeMultiOracleMode,
    pub proof_relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub logical_descriptors: Vec<WhirNativeOracleSpec>,
    pub descriptor_digest: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub packing_challenge_digest: Digest32,
    pub packed_root: Digest32,
    pub packed_eval_claims: Vec<Symbt3TupleLeafPackedEvalClaim>,
    pub logical_eval_claims: Vec<WhirNativeOracleEvalClaim>,
    pub whir_pcs_proof: WhirPcsProof<F, EF, WhirMmcs>,
    pub counters: Symbt3TupleLeafMultiOracleCounters,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbt3TupleLeafProofByteSections {
    pub descriptor_layout_profile_metadata_bytes: usize,
    pub duplicated_main_k6a_context_bytes: usize,
    pub logical_eval_claim_bytes: usize,
    pub repeated_rlc_claim_bytes: usize,
    pub pcs_payload_length_prefix_bytes: usize,
    pub pcs_compact_canonical_payload_bytes: usize,
    pub pcs_legacy_json_payload_bytes: usize,
    pub pcs_merkle_root_path_payload_bytes: usize,
    pub pcs_query_value_payload_bytes: usize,
    pub pcs_transcript_payload_bytes: usize,
    pub pcs_json_framing_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbt3N7bFullAuthorityProofByteSections {
    pub proof_header_bytes: usize,
    pub main_k6a_whir_proof_bytes: usize,
    pub k6a_adapter_bytes: usize,
    pub tuple_leaf_native_proof_bytes: usize,
    pub native_tuple_leaf_part_metadata_bytes: usize,
    pub binding_digest_profile_metadata_bytes: usize,
    pub wrapper_counters_bytes: usize,
    pub serialization_framing_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct WhirNativeOracleVerifyReport {
    pub ok: bool,
    pub counters: WhirNativeOracleCounters,
    pub native_oracle_verify_ms: f64,
}

#[derive(Debug, Clone)]
pub struct NativeManifestSourceMembershipProof {
    pub batch_manifest_root: Digest32,
    pub native_proof: WhirNativeMultiOracleProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ManifestSourceComponentValues {
    pub component_id: u32,
    pub kind: Symbt3ManifestComponentKind,
    pub visibility: Symbt3ManifestVisibility,
    pub layout_digest: Digest32,
    pub manifest_values: Vec<BabyBear>,
    pub source_values: Vec<BabyBear>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ManifestComponentPublicView {
    pub component_id: u32,
    pub kind: Symbt3ManifestComponentKind,
    pub visibility: Symbt3ManifestVisibility,
    pub layout_digest: Digest32,
    pub value_count: usize,
    pub manifest_component_root: Digest32,
    pub source_component_root: Digest32,
    pub public_manifest_values: Vec<BabyBear>,
    pub public_source_values: Vec<BabyBear>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3CommittedPrivateManifestPublicStatement {
    pub manifest_policy: ManifestCommitmentPolicy,
    pub source_policy: SourceCommitmentPolicy,
    pub zk_status: Symbt3ZkStatus,
    pub root_policy: NativeOracleRootPolicy,
    pub manifest_layout_digest: Digest32,
    pub source_layout_digest: Digest32,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
    pub batch_manifest_root: Digest32,
    pub components: Vec<Symbt3ManifestComponentPublicView>,
}

#[derive(Debug, Clone)]
pub struct Symbt3CommittedPrivateManifestMembershipProof {
    pub public_statement: Symbt3CommittedPrivateManifestPublicStatement,
    pub membership_proof: NativeManifestSourceMembershipProof,
}

#[derive(Debug, Clone)]
pub struct Symbt3CommittedPrivateManifestVerifyReport {
    pub ok: bool,
    pub native_report: WhirNativeOracleVerifyReport,
    pub committed_private_component_count: usize,
    pub committed_private_public_bytes: usize,
    pub public_statement_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeRoundMessageOracleLayoutV1 {
    pub round_index: u32,
    pub oracle_id: u32,
    pub batch_axis_log_size: usize,
    pub message_axis_log_size: usize,
    pub total_num_vars: usize,
    pub layout_digest: Digest32,
    pub section_layout_digest: Digest32,
    pub view_map_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeRoundChallengeContext {
    pub folding_protocol_id: Digest32,
    pub input_public_boundary_digest: Digest32,
    pub batch_manifest_root: Digest32,
    pub source_roots_digest: Digest32,
    pub active_count: u64,
    pub batch_size: u64,
    pub folded_output_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeMessageOraclePublicBoundary {
    pub message_oracle_policy: Symbt3MessageOraclePolicy,
    pub message_oracle_roots_digest: Digest32,
    pub message_round_layouts_digest: Digest32,
    pub message_oracle_policy_digest: Digest32,
}

#[derive(Debug, Clone)]
pub struct Symbt3NativeRoundMessageOracleProof {
    pub message_oracle_policy: Symbt3MessageOraclePolicy,
    pub message_oracle_roots_digest: Digest32,
    pub message_round_layouts_digest: Digest32,
    pub message_oracle_policy_digest: Digest32,
    pub round_challenges: Vec<BabyBear>,
    pub native_proof: WhirNativeMultiOracleProof,
}

#[derive(Debug, Clone)]
pub struct Symbt3NativeRoundMessageOracleVerifyReport {
    pub ok: bool,
    pub native_report: WhirNativeOracleVerifyReport,
    pub native_message_round_count: usize,
    pub message_to_trace_binding_count: usize,
    pub round_challenges: Vec<BabyBear>,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeAccumulatorAuthorityCounters {
    pub full_accumulator_workload: bool,
    pub smoke_profile: bool,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub main_whir_num_vars: usize,
    pub main_oracle_len: usize,
    pub top_level_whir_proof_count: usize,
    pub family_columnar_subproof_count: usize,
    pub backend_table_count: usize,
    pub native_multi_oracle: bool,
    pub tuple_leaf_layout: String,
    pub whir_instance_count: usize,
    pub root_count: usize,
    pub query_schedule_count: usize,
    pub transcript_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub logical_oracle_count: usize,
    pub native_manifest_source_oracle_count: usize,
    pub native_message_oracle_count: usize,
    pub accumulator_transition_claims: usize,
    pub source_r1cs_residual_verifier_evaluations: usize,
    pub rlc_batching_bits: usize,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub native_oracle_eval_claim_count: usize,
    pub fallback_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeAccumulatorAuthorityProfileMetadata {
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub full_accumulator_workload: bool,
    pub smoke_profile: bool,
    pub native_profile: Option<Symbt3NativeOracleProfile>,
    pub manifest_policy: Option<ManifestCommitmentPolicy>,
    pub source_policy: Option<SourceCommitmentPolicy>,
    pub message_oracle_policy: Option<Symbt3MessageOraclePolicy>,
    pub root_policy: NativeOracleRootPolicy,
    pub zk_status: Symbt3ZkStatus,
    pub multi_oracle_mode: Symbt3NativeMultiOracleMode,
    pub tuple_leaf_layout: String,
    pub rlc_batching_bits: Option<usize>,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub target_soundness_bits: usize,
    pub soundness_bound_bits: usize,
    pub committed_private_component_count: usize,
    pub native_manifest_source_oracle_count: usize,
    pub native_message_round_count: usize,
    pub native_message_oracle_count: usize,
    pub logical_oracle_count: usize,
    pub whir_instance_count: usize,
    pub root_count: usize,
    pub query_schedule_count: usize,
    pub transcript_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub batch_size: usize,
    pub batch_axis_log_size: usize,
    pub message_round_layouts: Vec<Symbt3NativeRoundMessageOracleLayoutV1>,
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
pub struct Symbt3NativeAccumulatorAuthorityProfileReport {
    pub ok: bool,
    pub full_ok: bool,
    pub workload_kind_ok: bool,
    pub full_accumulator_workload: bool,
    pub smoke_profile: bool,
    pub native_profile_ok: bool,
    pub native_manifest_policy_ok: bool,
    pub native_source_policy_ok: bool,
    pub native_message_policy_ok: bool,
    pub canonical_root_policy_ok: bool,
    pub non_zk_status_ok: bool,
    pub tuple_leaf_mode_ok: bool,
    pub tuple_leaf_shape_ok: bool,
    pub rlc_soundness_ok: bool,
    pub committed_private_policy_ok: bool,
    pub message_oracle_count_ok: bool,
    pub required_families_ok: bool,
    pub semantic_profile_version_ok: bool,
    pub no_monolithic_fallback: bool,
    pub product_routing_unchanged: bool,
    pub family_columnar_subproof_count: usize,
    pub native_multi_oracle: bool,
    pub tuple_leaf_layout: String,
    pub logical_oracle_count: usize,
    pub native_message_round_count: usize,
    pub native_message_oracle_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub rlc_batching_bits: Option<usize>,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub gate_ok: bool,
}

#[derive(Debug, Clone)]
pub struct Symbt3NativeAccumulatorAuthorityProof {
    pub version: u64,
    pub proof_kind: Symbt3NativeFoldingProofKind,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub profile_digest: Digest32,
    pub accumulator_instance_digest: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub native_binding_digest: Digest32,
    pub main_symbt3_relation_id: Digest32,
    pub main_symbt3_proof_digest: Digest32,
    pub rlc_tuple_leaf_root: Digest32,
    pub rlc_tuple_leaf_layout_digest: Digest32,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_message_roots_digest: Digest32,
    pub native_message_roots: Vec<Digest32>,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
    pub batch_manifest_root: Digest32,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub round_challenges: Vec<BabyBear>,
    pub main_symbt3_whir_proof: WhirProof,
    pub rlc_tuple_leaf_multi_oracle_proof: Symbt3TupleLeafMultiOracleProof,
    pub counters: Symbt3NativeAccumulatorAuthorityCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3N7bFullAuthorityBlocker {
    MissingK6aAdapter,
    MissingNativeTupleLeafProof,
    MissingBindingDigest,
    WorkloadKindMismatch,
    SmokeProfile,
    AdapterNotFullWorkload,
    K6aProofMismatch,
    TupleLeafProfileIncompatible,
    TupleLeafVerificationFailed,
    BindingDigestMismatch,
    FallbackUsed,
    FamilySubproofsPresent,
    RepeatedRlcSoundnessMissingOrWeak,
    PublicCanonicalOrMonolithicAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3N7bFullAuthorityBindingInputs {
    pub profile_digest: Digest32,
    pub accumulator_instance_digest: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub main_symbt3_relation_id: Digest32,
    pub main_symbt3_proof_digest: Digest32,
    pub tuple_leaf_root: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_message_roots_digest: Digest32,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
    pub batch_manifest_root: Digest32,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub batch_size: u64,
    pub active_count: u64,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
}

#[derive(Debug, Clone)]
pub struct Symbt3N7bNativeTupleLeafProofParts {
    pub proof: Symbt3TupleLeafMultiOracleProof,
    pub native_oracle_descriptor_digest: Digest32,
    pub native_message_roots_digest: Digest32,
    pub manifest_oracle_root: Digest32,
    pub source_oracle_root: Digest32,
}

#[derive(Debug, Clone, Default)]
pub struct Symbt3N7bFullAuthorityWrapperParts {
    pub workload_kind: Option<Symbt3NativeAccumulatorAuthorityWorkload>,
    pub k6a_adapter: Option<Symbt3NativeAccumulatorK6aWorkloadAdapter>,
    pub native_tuple_leaf: Option<Symbt3N7bNativeTupleLeafProofParts>,
    pub binding_digest: Option<Digest32>,
    pub fallback_used: bool,
}

#[derive(Debug, Clone)]
pub struct Symbt3N7bFullAuthorityWrapperProof {
    pub version: u64,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub k6a_adapter: Symbt3NativeAccumulatorK6aWorkloadAdapter,
    pub native_tuple_leaf: Symbt3N7bNativeTupleLeafProofParts,
    pub binding_digest: Digest32,
    pub counters: Symbt3NativeAccumulatorAuthorityCounters,
}

#[derive(Debug, Clone)]
pub struct Symbt3N7bFullAuthorityProof {
    pub version: u64,
    pub proof_kind: ProductProofKind,
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub k6a_main_proof: WhirProof,
    pub wrapper: Symbt3N7bFullAuthorityWrapperProof,
}

pub struct Symbt3N7bFullAuthorityVerificationContext<'a> {
    pub k6a_vk: &'a WhirVerifyingKey,
    pub tuple_leaf_vk: &'a WhirVerifyingKey,
    pub profile: &'a Symbt3AuthorityProfile,
    pub accumulator_instance: &'a Symbt3AccumulatorInstance,
    pub proof_kind: ProductProofKind,
    pub k6a_proof: &'a WhirProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3N7bFullAuthorityVerificationReport {
    pub ok: bool,
    pub blocked: bool,
    pub blocker: Option<Symbt3N7bFullAuthorityBlocker>,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3N8IntegratedPrototypeGateReport {
    pub ok: bool,
    pub blocked: bool,
    pub blocker: Option<Symbt3N8IntegratedPrototypeBlocker>,
    pub semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3NativeAccumulatorK6aWorkloadAdapter {
    pub workload_kind: Symbt3NativeAccumulatorAuthorityWorkload,
    pub full_accumulator_workload: bool,
    pub smoke_profile: bool,
    pub proof_kind: ProductProofKind,
    pub profile_digest: Digest32,
    pub accumulator_instance_digest: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub main_symbt3_relation_id: Digest32,
    pub main_symbt3_proof_digest: Digest32,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub batch_manifest_root: Digest32,
    pub manifest_oracle_root: Digest32,
    pub native_message_roots_digest: Digest32,
    pub batch_size: u64,
    pub active_count: u64,
    pub main_whir_num_vars: usize,
    pub main_oracle_len: usize,
    pub top_level_whir_proof_count: usize,
    pub family_columnar_subproof_count: usize,
    pub backend_table_count: usize,
    pub accumulator_transition_claims: usize,
    pub source_r1cs_residual_verifier_evaluations: usize,
}

impl Symbt3NativeAccumulatorK6aWorkloadAdapter {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_N7B_K6A_WORKLOAD_ADAPTER_V1");
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        out.push(u8::from(self.full_accumulator_workload));
        out.push(u8::from(self.smoke_profile));
        let proof_kind = match self.proof_kind {
            ProductProofKind::MonolithicTypedCp => b"MonolithicTypedCp".as_slice(),
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity => {
                b"Symbt3AccumulatorNonZkIntegrity".as_slice()
            }
            ProductProofKind::Symbt2F => b"Symbt2F".as_slice(),
            ProductProofKind::Symbt2C => b"Symbt2C".as_slice(),
            ProductProofKind::Symbtc => b"Symbtc".as_slice(),
        };
        push_bytes(&mut out, proof_kind);
        push_digest(&mut out, &self.profile_digest);
        push_digest(&mut out, &self.accumulator_instance_digest);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.main_symbt3_relation_id);
        push_digest(&mut out, &self.main_symbt3_proof_digest);
        push_digest(&mut out, &self.old_accumulator_digest);
        push_digest(&mut out, &self.new_accumulator_digest);
        push_digest(&mut out, &self.batch_manifest_root);
        push_digest(&mut out, &self.manifest_oracle_root);
        push_digest(&mut out, &self.native_message_roots_digest);
        push_u64(&mut out, self.batch_size);
        push_u64(&mut out, self.active_count);
        push_u64(&mut out, self.main_whir_num_vars as u64);
        push_u64(&mut out, self.main_oracle_len as u64);
        push_u64(&mut out, self.top_level_whir_proof_count as u64);
        push_u64(&mut out, self.family_columnar_subproof_count as u64);
        push_u64(&mut out, self.backend_table_count as u64);
        push_u64(&mut out, self.accumulator_transition_claims as u64);
        push_u64(
            &mut out,
            self.source_r1cs_residual_verifier_evaluations as u64,
        );
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Symbt3NativeAccumulatorK6aWorkloadAdapterParts {
    workload_kind: Option<Symbt3NativeAccumulatorAuthorityWorkload>,
    full_accumulator_workload: Option<bool>,
    smoke_profile: Option<bool>,
    proof_kind: Option<ProductProofKind>,
    profile_digest: Option<Digest32>,
    accumulator_instance_digest: Option<Digest32>,
    public_statement_digest: Option<Digest32>,
    whir_param_digest: Option<Digest32>,
    main_symbt3_relation_id: Option<Digest32>,
    main_symbt3_proof_digest: Option<Digest32>,
    old_accumulator_digest: Option<Digest32>,
    new_accumulator_digest: Option<Digest32>,
    batch_manifest_root: Option<Digest32>,
    manifest_oracle_root: Option<Digest32>,
    native_message_roots_digest: Option<Digest32>,
    batch_size: Option<u64>,
    active_count: Option<u64>,
    main_whir_num_vars: Option<usize>,
    main_oracle_len: Option<usize>,
    top_level_whir_proof_count: Option<usize>,
    family_columnar_subproof_count: Option<usize>,
    backend_table_count: Option<usize>,
    accumulator_transition_claims: Option<usize>,
    source_r1cs_residual_verifier_evaluations: Option<usize>,
}

pub enum Symbt3NativeAccumulatorK6aWorkloadAdapterInput<'a> {
    FullK6a {
        vk: &'a WhirVerifyingKey,
        profile: &'a Symbt3AuthorityProfile,
        accumulator_instance: &'a Symbt3AccumulatorInstance,
        proof_kind: ProductProofKind,
        proof: &'a WhirProof,
    },
    NativeN7Smoke {
        instance: &'a Symbt3NativeFoldingIntegrityInstance,
        proof: &'a Symbt3NativeAccumulatorAuthorityProof,
    },
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

impl WhirNativeMultiOracleProof {
    #[must_use]
    pub const fn top_level_whir_proof_count(&self) -> usize {
        1
    }

    #[must_use]
    pub const fn family_columnar_subproof_count(&self) -> usize {
        0
    }

    #[must_use]
    pub const fn native_oracle_pcs_opening_count(&self) -> usize {
        self.pcs_openings.len()
    }

    #[must_use]
    pub fn metadata_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_MULTI_ORACLE_ENVELOPE_METADATA_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.root_policy.canonical_bytes());
        push_digest(&mut out, &self.proof_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_oracle_eval_claims_digest);
        push_u64(&mut out, self.descriptors.len() as u64);
        for descriptor in &self.descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_u64(&mut out, self.eval_claims.len() as u64);
        for claim in &self.eval_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_u64(&mut out, self.pcs_openings.len() as u64);
        for opening in &self.pcs_openings {
            push_u32(&mut out, opening.oracle_id);
        }
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }
}

impl Symbt3NativeMultiOracleMode {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_MULTI_ORACLE_MODE_V1");
        encode_native_multi_oracle_mode(&mut out, self);
        out
    }
}

impl Symbt3TupleLeafLayoutV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_TUPLE_LEAF_LAYOUT_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.num_vars as u64);
        push_digest(&mut out, &self.packing_challenge_digest);
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl Symbt3TupleLeafPackedEvalClaim {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_TUPLE_LEAF_PACKED_EVAL_CLAIM_V1");
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_bytes(&mut out, &self.claim_kind.canonical_bytes());
        out
    }
}

impl Symbt3TupleLeafMultiOracleCounters {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_TUPLE_LEAF_MULTI_ORACLE_COUNTERS_V1");
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.whir_instance_count as u64);
        push_u64(&mut out, self.query_schedule_count as u64);
        push_u64(&mut out, self.transcript_count as u64);
        push_u64(&mut out, self.root_count as u64);
        push_u64(&mut out, self.native_oracle_pcs_opening_count as u64);
        push_u64(&mut out, self.logical_eval_claim_count as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_bytes(&mut out, self.tuple_leaf_layout.as_bytes());
        out.push(u8::from(self.same_domain));
        out.push(u8::from(self.same_field));
        out.push(u8::from(self.same_rate));
        out.push(u8::from(self.same_folding_parameter));
        push_u64(&mut out, self.merkle_path_proxy as u64);
        push_u64(&mut out, self.hash_estimate as u64);
        push_u64(&mut out, self.field_op_estimate as u64);
        out
    }
}

impl Symbt3TupleLeafMultiOracleProof {
    #[must_use]
    pub const fn top_level_whir_proof_count(&self) -> usize {
        1
    }

    #[must_use]
    pub const fn family_columnar_subproof_count(&self) -> usize {
        0
    }

    #[must_use]
    pub const fn native_oracle_pcs_opening_count(&self) -> usize {
        1
    }

    #[must_use]
    pub fn metadata_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_METADATA_V1",
        );
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_digest(&mut out, &self.proof_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_u64(&mut out, self.logical_descriptors.len() as u64);
        for descriptor in &self.logical_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_digest(&mut out, &self.descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.packing_challenge_digest);
        push_digest(&mut out, &self.packed_root);
        push_u64(&mut out, self.packed_eval_claims.len() as u64);
        for claim in &self.packed_eval_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_u64(&mut out, self.logical_eval_claims.len() as u64);
        for claim in &self.logical_eval_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn accounting_byte_sections(&self) -> Symbt3TupleLeafProofByteSections {
        let descriptor_layout_profile_metadata_bytes = encoded_len(|out| {
            push_bytes(out, b"SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_METADATA_V1");
            push_u64(out, self.version);
            push_bytes(out, &self.mode.canonical_bytes());
            push_u64(out, self.logical_descriptors.len() as u64);
            for descriptor in &self.logical_descriptors {
                push_bytes(out, &descriptor.canonical_bytes());
            }
            push_digest(out, &self.descriptor_digest);
            push_digest(out, &self.tuple_leaf_layout_digest);
            push_digest(out, &self.packing_challenge_digest);
            push_digest(out, &self.packed_root);
            push_bytes(out, &self.counters.canonical_bytes());
        });
        let duplicated_main_k6a_context_bytes = encoded_len(|out| {
            push_digest(out, &self.proof_relation_id);
            push_digest(out, &self.public_statement_digest);
            push_digest(out, &self.whir_param_digest);
        });
        let repeated_rlc_claim_bytes = encoded_len(|out| {
            push_u64(out, self.packed_eval_claims.len() as u64);
            for claim in &self.packed_eval_claims {
                push_bytes(out, &claim.canonical_bytes());
            }
        });
        let logical_eval_claim_bytes = encoded_len(|out| {
            push_u64(out, self.logical_eval_claims.len() as u64);
            for claim in &self.logical_eval_claims {
                push_bytes(out, &claim.canonical_bytes());
            }
        });
        debug_assert_eq!(
            self.metadata_canonical_bytes().len(),
            descriptor_layout_profile_metadata_bytes
                + duplicated_main_k6a_context_bytes
                + repeated_rlc_claim_bytes
                + logical_eval_claim_bytes
        );

        let pcs_legacy_json_bytes = serde_json::to_vec(&self.whir_pcs_proof)
            .expect("tuple-leaf WHIR PCS proof must serialize for byte accounting");
        let pcs_compact_canonical_bytes = whir_pcs_compact_canonical_bytes(&self.whir_pcs_proof)
            .expect("tuple-leaf WHIR PCS proof must compact-serialize for byte accounting");
        let pcs_json = serde_json::to_value(&self.whir_pcs_proof)
            .expect("tuple-leaf WHIR PCS proof must convert to JSON for byte accounting");
        let (
            pcs_merkle_root_path_payload_bytes,
            pcs_query_value_payload_bytes,
            pcs_transcript_payload_bytes,
        ) = whir_pcs_json_payload_sections(&pcs_json);
        let accounted_pcs_bytes = pcs_merkle_root_path_payload_bytes
            + pcs_query_value_payload_bytes
            + pcs_transcript_payload_bytes;
        let pcs_json_framing_bytes = pcs_legacy_json_bytes
            .len()
            .saturating_sub(accounted_pcs_bytes);
        let pcs_payload_length_prefix_bytes = 8;
        let total_bytes = descriptor_layout_profile_metadata_bytes
            + duplicated_main_k6a_context_bytes
            + logical_eval_claim_bytes
            + repeated_rlc_claim_bytes
            + pcs_payload_length_prefix_bytes
            + pcs_compact_canonical_bytes.len();

        Symbt3TupleLeafProofByteSections {
            descriptor_layout_profile_metadata_bytes,
            duplicated_main_k6a_context_bytes,
            logical_eval_claim_bytes,
            repeated_rlc_claim_bytes,
            pcs_payload_length_prefix_bytes,
            pcs_compact_canonical_payload_bytes: pcs_compact_canonical_bytes.len(),
            pcs_legacy_json_payload_bytes: pcs_legacy_json_bytes.len(),
            pcs_merkle_root_path_payload_bytes,
            pcs_query_value_payload_bytes,
            pcs_transcript_payload_bytes,
            pcs_json_framing_bytes,
            total_bytes,
        }
    }

    #[must_use]
    pub fn accounting_serialized_bytes_len(&self) -> usize {
        self.accounting_byte_sections().total_bytes
    }
}

#[must_use]
pub fn whir_pcs_compact_canonical_bytes(proof: &WhirPcsProof<F, EF, WhirMmcs>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(b"WHIR_PCS_COMPACT_JSON_CBOR_V1");
    let value = serde_json::to_value(proof).ok()?;
    ciborium::into_writer(&value, &mut out).ok()?;
    Some(out)
}

pub fn whir_pcs_from_compact_canonical_bytes(
    bytes: &[u8],
) -> Option<WhirPcsProof<F, EF, WhirMmcs>> {
    let magic = b"WHIR_PCS_COMPACT_JSON_CBOR_V1";
    let payload = bytes.strip_prefix(magic)?;
    let value: serde_json::Value = ciborium::from_reader(std::io::Cursor::new(payload)).ok()?;
    serde_json::from_value(value).ok()
}

#[must_use]
pub fn symbt3_tuple_leaf_multi_oracle_proof_canonical_bytes_compact(
    proof: &Symbt3TupleLeafMultiOracleProof,
) -> Option<Vec<u8>> {
    let mut out = proof.metadata_canonical_bytes();
    let pcs_bytes = whir_pcs_compact_canonical_bytes(&proof.whir_pcs_proof)?;
    push_bytes(&mut out, &pcs_bytes);
    Some(out)
}

fn encoded_len(encode: impl FnOnce(&mut Vec<u8>)) -> usize {
    let mut out = Vec::new();
    encode(&mut out);
    out.len()
}

fn json_value_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value)
        .expect("JSON value must serialize for byte accounting")
        .len()
}

fn json_object_field_len(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> usize {
    object.get(key).map_or(0, json_value_len)
}

fn whir_pcs_query_opening_json_sections(query: &serde_json::Value) -> (usize, usize, usize) {
    let Some(object) = query.as_object() else {
        return (0, 0, json_value_len(query));
    };
    let merkle_root_path_payload_bytes = json_object_field_len(object, "proof");
    let query_value_payload_bytes = json_object_field_len(object, "values");
    let accounted = merkle_root_path_payload_bytes + query_value_payload_bytes;
    let transcript_payload_bytes = json_value_len(query).saturating_sub(accounted);
    (
        merkle_root_path_payload_bytes,
        query_value_payload_bytes,
        transcript_payload_bytes,
    )
}

fn whir_pcs_query_array_json_sections(queries: &serde_json::Value) -> (usize, usize, usize) {
    let Some(queries) = queries.as_array() else {
        return (0, 0, json_value_len(queries));
    };
    queries.iter().fold((0, 0, 0), |mut acc, query| {
        let sections = whir_pcs_query_opening_json_sections(query);
        acc.0 += sections.0;
        acc.1 += sections.1;
        acc.2 += sections.2;
        acc
    })
}

fn whir_pcs_json_payload_sections(pcs_json: &serde_json::Value) -> (usize, usize, usize) {
    let Some(object) = pcs_json.as_object() else {
        return (0, 0, json_value_len(pcs_json));
    };
    let mut merkle_root_path_payload_bytes = json_object_field_len(object, "initial_commitment");
    let mut query_value_payload_bytes = 0;
    let mut transcript_payload_bytes = json_object_field_len(object, "initial_ood_answers")
        + json_object_field_len(object, "initial_sumcheck")
        + json_object_field_len(object, "final_poly")
        + json_object_field_len(object, "final_pow_witness")
        + json_object_field_len(object, "final_sumcheck");

    if let Some(rounds) = object.get("rounds").and_then(serde_json::Value::as_array) {
        for round in rounds {
            let Some(round_object) = round.as_object() else {
                transcript_payload_bytes += json_value_len(round);
                continue;
            };
            merkle_root_path_payload_bytes += json_object_field_len(round_object, "commitment");
            transcript_payload_bytes += json_object_field_len(round_object, "ood_answers")
                + json_object_field_len(round_object, "pow_witness")
                + json_object_field_len(round_object, "sumcheck");
            if let Some(queries) = round_object.get("queries") {
                let query_sections = whir_pcs_query_array_json_sections(queries);
                merkle_root_path_payload_bytes += query_sections.0;
                query_value_payload_bytes += query_sections.1;
                transcript_payload_bytes += query_sections.2;
            }
        }
    }

    if let Some(final_queries) = object.get("final_queries") {
        let query_sections = whir_pcs_query_array_json_sections(final_queries);
        merkle_root_path_payload_bytes += query_sections.0;
        query_value_payload_bytes += query_sections.1;
        transcript_payload_bytes += query_sections.2;
    }

    (
        merkle_root_path_payload_bytes,
        query_value_payload_bytes,
        transcript_payload_bytes,
    )
}

#[must_use]
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
pub fn build_native_oracle_benchmark_specs(
    oracle_count: usize,
    num_vars_per_oracle: usize,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if oracle_count == 0 || num_vars_per_oracle == 0 {
        return None;
    }
    Some(
        (0..oracle_count)
            .map(|oracle_index| {
                let oracle_id = 10_000u32.checked_add(oracle_index as u32)?;
                let mut layout_bytes = Vec::new();
                push_bytes(&mut layout_bytes, b"SYMBT3_N1BENCH_NATIVE_ORACLE_LAYOUT_V1");
                push_u32(&mut layout_bytes, oracle_id);
                push_u64(&mut layout_bytes, num_vars_per_oracle as u64);
                Some(WhirNativeOracleSpec {
                    version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                    oracle_id,
                    role: WhirNativeOracleRole::Auxiliary,
                    layout_digest: digest_bytes(&layout_bytes),
                    num_vars: num_vars_per_oracle,
                    opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                        domain_separator: "SYMBT3_N1BENCH_NATIVE_MULTI_ORACLE",
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?,
    )
}

#[must_use]
pub fn build_native_oracle_batch_axis_benchmark_specs(
    round_count: usize,
    batch_log_size: usize,
    message_axis_log_size: usize,
) -> Option<Vec<WhirNativeOracleSpec>> {
    if round_count == 0 || message_axis_log_size == 0 {
        return None;
    }
    let total_num_vars = batch_log_size.checked_add(message_axis_log_size)?;
    if total_num_vars == 0 {
        return None;
    }
    Some(
        (0..round_count)
            .map(|round| {
                let round_u32 = u32::try_from(round).ok()?;
                let oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE.checked_add(round_u32)?;
                let mut layout_bytes = Vec::new();
                push_bytes(
                    &mut layout_bytes,
                    b"SYMBT3_N1BENCH_BATCH_AXIS_ORACLE_LAYOUT_V1",
                );
                push_u32(&mut layout_bytes, round_u32);
                push_u32(&mut layout_bytes, oracle_id);
                push_u64(&mut layout_bytes, batch_log_size as u64);
                push_u64(&mut layout_bytes, message_axis_log_size as u64);
                Some(WhirNativeOracleSpec {
                    version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                    oracle_id,
                    role: WhirNativeOracleRole::MessageRound { round: round_u32 },
                    layout_digest: digest_bytes(&layout_bytes),
                    num_vars: total_num_vars,
                    opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                        domain_separator: "SYMBT3_N1BENCH_BATCH_AXIS_MESSAGE_VIEW",
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?,
    )
}

#[must_use]
pub fn build_native_oracle_benchmark_eval_requests(
    specs: &[WhirNativeOracleSpec],
    claim_kind: WhirNativeEvalClaimKind,
) -> Vec<WhirNativeEvalRequest> {
    specs
        .iter()
        .map(|spec| WhirNativeEvalRequest {
            oracle_id: spec.oracle_id,
            claim_kind,
        })
        .collect()
}

#[must_use]
pub fn build_native_oracle_benchmark_evals(
    specs: &[WhirNativeOracleSpec],
    seed: u64,
) -> Option<Vec<Vec<BabyBear>>> {
    specs
        .iter()
        .enumerate()
        .map(|(oracle_index, spec)| {
            let shift = u32::try_from(spec.num_vars).ok()?;
            let len = 1usize.checked_shl(shift)?;
            Some(
                (0..len)
                    .map(|eval_index| {
                        BabyBear::from_u32(
                            ((seed + oracle_index as u64 * 1_000_003 + eval_index as u64 * 65_537)
                                % 2_000_000_000) as u32,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

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

#[must_use]
pub fn build_symbt3_n7b_full_authority_binding_digest(
    inputs: &Symbt3N7bFullAuthorityBindingInputs,
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        b"SYMBT3_N7B_FULL_NATIVE_ACCUMULATOR_AUTHORITY_BINDING_V1",
    );
    push_bytes(&mut bytes, &inputs.workload_kind.canonical_bytes());
    push_digest(&mut bytes, &inputs.profile_digest);
    push_digest(&mut bytes, &inputs.accumulator_instance_digest);
    push_digest(&mut bytes, &inputs.public_statement_digest);
    push_digest(&mut bytes, &inputs.whir_param_digest);
    push_digest(&mut bytes, &inputs.main_symbt3_relation_id);
    push_digest(&mut bytes, &inputs.main_symbt3_proof_digest);
    push_digest(&mut bytes, &inputs.tuple_leaf_root);
    push_digest(&mut bytes, &inputs.tuple_leaf_layout_digest);
    push_digest(&mut bytes, &inputs.native_oracle_descriptor_digest);
    push_digest(&mut bytes, &inputs.native_message_roots_digest);
    push_digest(&mut bytes, &inputs.manifest_oracle_root);
    push_digest(&mut bytes, &inputs.source_oracle_root);
    push_digest(&mut bytes, &inputs.batch_manifest_root);
    push_digest(&mut bytes, &inputs.old_accumulator_digest);
    push_digest(&mut bytes, &inputs.new_accumulator_digest);
    push_u64(&mut bytes, inputs.batch_size);
    push_u64(&mut bytes, inputs.active_count);
    digest_bytes(&bytes)
}

impl Symbt3N8IntegratedConstraintKind {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_N8_INTEGRATED_CONSTRAINT_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorMainV1 => 1,
            Self::NativeTupleLeafRepeatedRlcV1 => 2,
            Self::AccumulatorTransitionBindingV1 => 3,
        });
        out
    }
}

impl Symbt3N8IntegratedConstraintDescriptor {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_N8_INTEGRATED_CONSTRAINT_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.num_vars as u64);
        push_u64(&mut out, self.oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl IntegratedK6aNativeK6aPaddingModeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_K6A_PADDING_MODE_V1");
        out.push(match self {
            Self::NoPadding => 1,
            Self::ZeroExtendRowsToIntegratedNumVars => 2,
        });
        out
    }
}

impl IntegratedK6aNativeK6aPaddingPolicyV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_K6A_PADDING_POLICY_V1");
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_u64(&mut out, self.source_num_vars as u64);
        push_u64(&mut out, self.target_num_vars as u64);
        push_u64(&mut out, self.source_oracle_len as u64);
        push_u64(&mut out, self.target_oracle_len as u64);
        push_u64(&mut out, self.added_num_vars as u64);
        push_u64(&mut out, self.padded_row_count as u64);
        out
    }
}

impl IntegratedK6aNativeTupleRepetitionAxisPlacementV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_TUPLE_REPETITION_AXIS_PLACEMENT_V1",
        );
        out.push(match self {
            Self::AppendedAfterLogicalAxes => 1,
        });
        out
    }
}

impl IntegratedK6aNativeTupleRepetitionAxisMappingV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_TUPLE_REPETITION_AXIS_MAPPING_V1",
        );
        push_bytes(&mut out, &self.placement.canonical_bytes());
        push_u64(&mut out, self.logical_num_vars as u64);
        push_u64(&mut out, self.repetition_axis_start as u64);
        push_u64(&mut out, self.repetition_axis_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.packed_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_padding_num_vars as u64);
        out
    }
}

impl IntegratedK6aNativeLogicalOracleKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_LOGICAL_ORACLE_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorMainV1 => 1,
            Self::NativeTupleLeafPackedV1 => 2,
            Self::NativeTupleLeafLogicalV1 => 3,
        });
        out
    }
}

impl IntegratedK6aNativeLogicalOracleDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_LOGICAL_ORACLE_DESCRIPTOR_V1",
        );
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_optional_u32(&mut out, self.oracle_id);
        push_optional_role(&mut out, self.role.as_ref());
        push_digest(&mut out, &self.layout_digest);
        push_optional_digest(&mut out, self.root_digest.as_ref());
        push_u64(&mut out, self.source_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl IntegratedK6aNativeClaimDescriptorKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_CLAIM_DESCRIPTOR_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorMainClaimsV1 => 1,
            Self::NativeTupleLeafPackedClaimsV1 => 2,
            Self::NativeTupleLeafLogicalClaimsV1 => 3,
        });
        out
    }
}

impl IntegratedK6aNativeClaimDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_CLAIM_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.claim_count as u64);
        push_u64(&mut out, self.num_vars as u64);
        push_digest(&mut out, &self.claims_digest);
        out
    }
}

impl IntegratedK6aNativeClaimPlanV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_CLAIM_PLAN_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.k6a_relation_id);
        push_digest(&mut out, &self.k6a_public_statement_digest);
        push_digest(&mut out, &self.k6a_semantic_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_u64(&mut out, self.k6a_num_vars as u64);
        push_u64(&mut out, self.k6a_oracle_len as u64);
        push_u64(&mut out, self.tuple_logical_oracle_count as u64);
        push_u64(&mut out, self.tuple_logical_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_bytes(&mut out, &self.k6a_padding_policy.canonical_bytes());
        push_bytes(&mut out, &self.tuple_repetition_axis.canonical_bytes());
        push_u64(&mut out, self.logical_oracle_descriptors.len() as u64);
        for descriptor in &self.logical_oracle_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_u64(&mut out, self.constraint_descriptors.len() as u64);
        for descriptor in &self.constraint_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_u64(&mut out, self.claim_descriptors.len() as u64);
        for descriptor in &self.claim_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_digest(&mut out, &self.combined_logical_oracle_descriptor_digest);
        push_digest(&mut out, &self.combined_constraint_descriptor_digest);
        push_digest(&mut out, &self.combined_claim_descriptor_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.claim_plan_digest);
        out
    }
}

impl N8IntegratedK6aSemanticConstraintRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINT_ROW_KIND_V1",
        );
        out.push(match self {
            Self::VerifierOpeningClaimV1 => 1,
            Self::FinalResidualZeroV1 => 2,
            Self::ZEvalBindingV1 => 3,
            Self::ProductSumcheckAcceptedV1 => 4,
            Self::K6aPaddingZeroV1 => 5,
        });
        out
    }
}

impl N8IntegratedK6aSemanticConstraintRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINT_ROW_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl N8IntegratedK6aSemanticConstraintsV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.complete);
        push_digest(&mut out, &self.k6a_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_u64(&mut out, self.k6a_num_vars as u64);
        push_u64(&mut out, self.k6a_oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.verifier_point_count as u64);
        push_u64(&mut out, self.verifier_claim_count as u64);
        push_u64(&mut out, self.final_residual_count as u64);
        push_u64(&mut out, self.product_sumcheck_round_count as u64);
        push_u64(&mut out, self.padding_row_count as u64);
        push_digest(&mut out, &self.verifier_points_digest);
        push_digest(&mut out, &self.verifier_claims_digest);
        push_digest(&mut out, &self.final_residual_digest);
        push_digest(&mut out, &self.product_sumcheck_digest);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_digest(&mut out, &self.rows_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8IntegratedTupleRlcSemanticConstraintRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINT_ROW_KIND_V1",
        );
        out.push(match self {
            Self::PackedOpeningClaimV1 => 1,
            Self::LogicalOpeningClaimV1 => 2,
            Self::RlcResidualZeroV1 => 3,
            Self::TuplePaddingZeroV1 => 4,
        });
        out
    }
}

impl N8IntegratedTupleRlcSemanticConstraintRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINT_ROW_V1",
        );
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        match self.repetition_index {
            Some(index) => {
                push_bool(&mut out, true);
                push_u64(&mut out, index as u64);
            }
            None => push_bool(&mut out, false),
        }
        push_optional_u32(&mut out, self.oracle_id);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl N8IntegratedTupleRlcSemanticConstraintsV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINTS_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.complete);
        push_digest(&mut out, &self.proof_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.packed_root);
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.logical_num_vars as u64);
        push_u64(&mut out, self.packed_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_bytes(&mut out, self.tuple_leaf_layout.as_bytes());
        push_bool(&mut out, self.same_domain);
        push_bool(&mut out, self.same_field);
        push_bool(&mut out, self.same_rate);
        push_bool(&mut out, self.same_folding_parameter);
        encode_claim_kind(&mut out, self.claim_kind);
        push_digest(&mut out, &self.packing_challenge_digest);
        push_digest(&mut out, &self.derived_packing_challenge_digest);
        push_digest(&mut out, &self.packed_claims_digest);
        push_digest(&mut out, &self.logical_claims_digest);
        push_digest(&mut out, &self.opening_points_digest);
        push_digest(&mut out, &self.residuals_digest);
        push_u64(&mut out, self.packed_row_count as u64);
        push_u64(&mut out, self.logical_row_count as u64);
        push_u64(&mut out, self.residual_row_count as u64);
        push_u64(&mut out, self.padding_row_count as u64);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_digest(&mut out, &self.rows_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8IntegratedTransitionBindingSemanticConstraintRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_ROW_KIND_V1",
        );
        out.push(match self {
            Self::AccumulatorBoundaryDigestV1 => 1,
            Self::PublicStatementAndK6aProofV1 => 2,
            Self::TupleLeafRootAndLayoutV1 => 3,
            Self::NativeDescriptorAndMessageRootsV1 => 4,
            Self::ManifestSourceBatchRootsV1 => 5,
            Self::BatchShapeV1 => 6,
            Self::WorkloadKindV1 => 7,
            Self::N8PlanTableLayoutV1 => 8,
        });
        out
    }
}

impl N8IntegratedTransitionBindingSemanticConstraintRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_ROW_V1",
        );
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl N8IntegratedTransitionBindingSemanticConstraintsV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_CONSTRAINTS_V1",
        );
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.complete);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.profile_digest);
        push_digest(&mut out, &self.accumulator_instance_digest);
        push_digest(&mut out, &self.old_accumulator_digest);
        push_digest(&mut out, &self.new_accumulator_digest);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.main_symbt3_relation_id);
        push_digest(&mut out, &self.k6a_proof_digest);
        push_digest(&mut out, &self.tuple_leaf_root);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_packing_challenge_digest);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_message_roots_digest);
        push_digest(&mut out, &self.manifest_oracle_root);
        push_digest(&mut out, &self.source_oracle_root);
        push_digest(&mut out, &self.batch_manifest_root);
        push_u64(&mut out, self.batch_size);
        push_u64(&mut out, self.active_count);
        push_u64(&mut out, self.k6a_num_vars as u64);
        push_u64(&mut out, self.k6a_oracle_len as u64);
        push_u64(&mut out, self.tuple_logical_oracle_count as u64);
        push_u64(&mut out, self.tuple_logical_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_digest(&mut out, &self.k6a_semantic_descriptor_digest);
        push_digest(&mut out, &self.tuple_rlc_semantic_descriptor_digest);
        push_digest(&mut out, &self.n8_claim_plan_digest);
        push_digest(&mut out, &self.n8_committed_table_layout_digest);
        push_digest(&mut out, &self.n8_committed_table_digest);
        push_digest(&mut out, &self.n8_combined_constraint_descriptor_digest);
        push_digest(&mut out, &self.n8_combined_claim_descriptor_digest);
        push_digest(&mut out, &self.k6a_constraint_descriptor_digest);
        push_digest(&mut out, &self.tuple_constraint_descriptor_digest);
        push_digest(&mut out, &self.transition_constraint_descriptor_digest);
        push_digest(&mut out, &self.transition_binding_digest);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_digest(&mut out, &self.rows_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8IntegratedSemanticCompletionFlagsV1 {
    #[must_use]
    pub const fn none_complete() -> Self {
        Self {
            version: N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION,
            k6a_semantics_complete: false,
            tuple_rlc_semantics_complete: false,
            transition_semantics_complete: false,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.k6a_semantics_complete);
        push_bool(&mut out, self.tuple_rlc_semantics_complete);
        push_bool(&mut out, self.transition_semantics_complete);
        out
    }

    #[must_use]
    pub const fn all_complete(&self) -> bool {
        self.k6a_semantics_complete
            && self.tuple_rlc_semantics_complete
            && self.transition_semantics_complete
    }
}

impl N8SemanticBatchingFamilyV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_SEMANTIC_BATCHING_FAMILY_V1");
        out.push(match self {
            Self::K6aSemanticRowsV1 => 1,
            Self::TupleRlcSemanticRowsV1 => 2,
            Self::TransitionBindingSemanticRowsV1 => 3,
            Self::K6aSourceRowsV1 => 4,
        });
        out
    }
}

impl N8SemanticBatchingFamilyDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_SEMANTIC_BATCHING_FAMILY_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.family.canonical_bytes());
        push_u64(&mut out, self.source_row_count as u64);
        push_u64(&mut out, self.batched_query_count as u64);
        push_digest(&mut out, &self.row_digest);
        push_digest(&mut out, &self.challenge_point_digest);
        push_u64(&mut out, self.soundness_bits as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8K6aSourceRowBatchingV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_K6A_SOURCE_ROW_BATCHING_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.enabled);
        push_bytes(&mut out, &self.descriptor.canonical_bytes());
        push_u64(&mut out, self.unbatched_source_opening_count as u64);
        push_u64(&mut out, self.batched_source_opening_count as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8SemanticBatchingV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_SEMANTIC_BATCHING_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.enabled);
        push_digest(&mut out, &self.descriptor_binding_digest);
        push_bytes(&mut out, &self.k6a_source.canonical_bytes());
        push_bytes(&mut out, &self.k6a.canonical_bytes());
        push_bytes(&mut out, &self.tuple_rlc.canonical_bytes());
        push_bytes(&mut out, &self.transition_binding.canonical_bytes());
        push_u64(&mut out, self.unbatched_semantic_opening_count as u64);
        push_u64(&mut out, self.batched_semantic_opening_count as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl IntegratedK6aNativeCommittedTableRowOwnerV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_ROW_OWNER_V1",
        );
        out.push(match self {
            Self::K6aAccumulatorMainRows => 1,
            Self::K6aZeroPaddingRows => 2,
            Self::NativeTupleLeafRepeatedRlcRows => 3,
            Self::NativeTupleLeafIntegratedPaddingRows => 4,
        });
        out
    }
}

impl IntegratedK6aNativeCommittedTableRowRangeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_ROW_RANGE_V1",
        );
        push_bytes(&mut out, &self.owner.canonical_bytes());
        push_u64(&mut out, self.integrated_start as u64);
        push_u64(&mut out, self.row_count as u64);
        push_u64(&mut out, self.source_start as u64);
        push_u64(&mut out, self.source_row_count as u64);
        out
    }
}

impl IntegratedK6aNativeCommittedTableAxisOwnerV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_AXIS_OWNER_V1",
        );
        out.push(match self {
            Self::K6aSourceAxes => 1,
            Self::K6aPaddingAxes => 2,
            Self::TupleLeafLogicalAxes => 3,
            Self::TupleLeafRepetitionAxes => 4,
            Self::TupleLeafIntegratedPaddingAxes => 5,
        });
        out
    }
}

impl IntegratedK6aNativeCommittedTableAxisRangeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_AXIS_RANGE_V1",
        );
        push_bytes(&mut out, &self.owner.canonical_bytes());
        push_u64(&mut out, self.axis_start as u64);
        push_u64(&mut out, self.axis_len as u64);
        out
    }
}

impl IntegratedK6aNativeCommittedTableCountersV1 {
    #[must_use]
    pub fn canonical_bytes_without_digests(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_COUNTERS_V1",
        );
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.k6a_padded_rows as u64);
        push_u64(&mut out, self.tuple_rows as u64);
        push_u64(&mut out, self.combined_constraint_count as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digests();
        push_digest(&mut out, &self.table_digest);
        push_digest(&mut out, &self.layout_digest);
        out
    }
}

impl IntegratedK6aNativeCommittedTableV1 {
    #[must_use]
    pub fn canonical_layout_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_LAYOUT_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.plan_digest);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_bytes(&mut out, &self.k6a_padding_policy.canonical_bytes());
        push_bytes(&mut out, &self.tuple_repetition_axis.canonical_bytes());
        push_u64(&mut out, self.row_ownership.len() as u64);
        for range in &self.row_ownership {
            push_bytes(&mut out, &range.canonical_bytes());
        }
        push_u64(&mut out, self.axis_ownership.len() as u64);
        for range in &self.axis_ownership {
            push_bytes(&mut out, &range.canonical_bytes());
        }
        push_u64(&mut out, self.logical_integrated_oracle_count as u64);
        push_bool(&mut out, self.one_oracle_per_batch_item_layout);
        push_u64(&mut out, self.introduced_whir_root_count as u64);
        push_u64(&mut out, self.introduced_whir_proof_count as u64);
        out
    }

    #[must_use]
    pub fn canonical_table_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_V1");
        push_bytes(&mut out, &self.canonical_layout_bytes_without_digest());
        push_digest(&mut out, &self.layout_digest);
        push_bytes(&mut out, &self.counters.canonical_bytes_without_digests());
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_table_bytes_without_digest();
        push_digest(&mut out, &self.table_digest);
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_ROW_KIND_V1",
        );
        out.push(match self {
            Self::K6aAccumulatorOpeningClaimV1 => 1,
            Self::K6aAccumulatorResidualClaimV1 => 2,
            Self::K6aAccumulatorZEvalClaimV1 => 3,
            Self::K6aProductSumcheckRoundClaimV1 => 4,
            Self::K6aZeroPaddingClaimV1 => 5,
            Self::K6aSemanticVerifierOpeningClaimV1 => 6,
            Self::K6aSemanticFinalResidualZeroV1 => 7,
            Self::K6aSemanticZEvalBindingV1 => 8,
            Self::K6aSemanticProductSumcheckAcceptedV1 => 9,
            Self::K6aSemanticPaddingZeroV1 => 10,
            Self::NativeTupleLeafPackedRlcClaimV1 => 11,
            Self::NativeTupleLeafLogicalRlcClaimV1 => 12,
            Self::NativeTupleLeafRlcBindingResidualV1 => 13,
            Self::NativeTupleLeafIntegratedPaddingClaimV1 => 14,
            Self::AccumulatorTransitionBindingClaimV1 => 15,
        });
        out
    }
}

impl RealIntegratedK6aNativeLogicalColumnV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"REAL_INTEGRATED_K6A_NATIVE_LOGICAL_COLUMN_V1");
        out.push(match self {
            Self::K6aAccumulatorMain => 1,
            Self::NativeTupleLeafPacked => 2,
            Self::NativeTupleLeafLogical => 3,
            Self::AccumulatorTransitionBinding => 4,
        });
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_ROW_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_bytes(&mut out, &self.logical_column.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        match self.repetition_index {
            Some(index) => {
                push_bool(&mut out, true);
                push_u64(&mut out, index as u64);
            }
            None => push_bool(&mut out, false),
        }
        push_optional_u32(&mut out, self.oracle_id);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorCountersV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_COUNTERS_V1",
        );
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.k6a_claim_rows as u64);
        push_u64(&mut out, self.k6a_semantic_rows as u64);
        push_u64(&mut out, self.tuple_claim_rows as u64);
        push_u64(&mut out, self.padding_rows as u64);
        push_u64(&mut out, self.transition_binding_rows as u64);
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorV1 {
    #[must_use]
    pub fn canonical_bytes_without_digests(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_V1");
        push_u64(&mut out, self.version);
        push_digest(&mut out, &self.plan_digest);
        push_digest(&mut out, &self.committed_table_layout_digest);
        push_digest(&mut out, &self.committed_table_digest);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digests();
        push_digest(&mut out, &self.rows_digest);
        push_digest(&mut out, &self.table_digest);
        push_digest(&mut out, &self.evaluator_digest);
        out
    }
}

impl Symbt3IntegratedK6aNativeWhirRelationV1 {
    #[must_use]
    pub fn canonical_bytes_without_transcript_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_V1",
        );
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.main_symbt3_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_bool(&mut out, self.same_field);
        push_bool(&mut out, self.same_rate);
        push_bool(&mut out, self.same_folding_parameter);
        push_bytes(&mut out, &self.claim_plan.canonical_bytes());
        push_bytes(&mut out, &self.committed_table.canonical_bytes());
        push_bytes(&mut out, &self.k6a_semantic_constraints.canonical_bytes());
        push_bytes(
            &mut out,
            &self.tuple_rlc_semantic_constraints.canonical_bytes(),
        );
        push_bytes(
            &mut out,
            &self
                .transition_binding_semantic_constraints
                .canonical_bytes(),
        );
        push_bytes(&mut out, &self.semantic_completion.canonical_bytes());
        push_bytes(&mut out, &self.real_evaluator.canonical_bytes());
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_transcript_digest();
        push_digest(&mut out, &self.transcript_binding_digest);
        out
    }
}

impl N8IntegratedWhirTableRepresentationV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_TABLE_REPRESENTATION_V1");
        out.push(match self {
            Self::SameDomainMultipleLogicalColumns => 1,
            Self::ScalarOracleSelectorGatedRegions => 2,
        });
        out
    }
}

impl N8IntegratedWhirClaimBridgeKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_CLAIM_BRIDGE_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorConstraintsV1 => 1,
            Self::NativeTupleLeafRepeatedRlcConstraintsV1 => 2,
            Self::AccumulatorTransitionBindingConstraintsV1 => 3,
        });
        out
    }
}

impl N8IntegratedWhirClaimBridgeDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_CLAIM_BRIDGE_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.claim_count as u64);
        push_u64(&mut out, self.source_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_digest(&mut out, &self.source_constraint_digest);
        push_digest(&mut out, &self.source_claim_digest);
        push_digest(&mut out, &self.table_layout_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl<'a> N8IntegratedWhirProofInputs<'a> {
    #[must_use]
    pub const fn from_descriptor(descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1) -> Self {
        Self {
            version: N8_INTEGRATED_WHIR_PROOF_INPUTS_VERSION,
            descriptor,
            table_representation:
                N8IntegratedWhirTableRepresentationV1::SameDomainMultipleLogicalColumns,
            integrated_whir_root: None,
            integrated_whir_proof: None,
            extra_whir_root_count: 0,
            extra_whir_proof_count: 0,
            legacy_k6a_proof: None,
            legacy_tuple_leaf_proof: None,
        }
    }
}

impl N8IntegratedWhirProofPlan {
    #[must_use]
    pub fn canonical_bytes_without_transcript_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_PROOF_PLAN_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_bytes(&mut out, &self.table_representation.canonical_bytes());
        push_digest(&mut out, &self.descriptor_transcript_digest);
        push_digest(&mut out, &self.claim_plan_digest);
        push_digest(&mut out, &self.committed_table_layout_digest);
        push_digest(&mut out, &self.committed_table_digest);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.integrated_whir_root_count as u64);
        push_u64(&mut out, self.integrated_whir_proof_count as u64);
        push_bool(&mut out, self.delegated_split_proof_material_present);
        push_bytes(&mut out, &self.semantic_batching.canonical_bytes());
        push_u64(&mut out, self.bridge_claim_descriptors.len() as u64);
        for descriptor in &self.bridge_claim_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_digest(&mut out, &self.combined_bridge_claim_descriptor_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_transcript_digest();
        push_digest(&mut out, &self.transcript_digest);
        out
    }
}

impl N8IntegratedWhirQueryClaimV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_QUERY_CLAIM_V1");
        push_bytes(&mut out, &self.bridge_kind.canonical_bytes());
        push_babybear_vec(&mut out, &self.point);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        out
    }
}

impl N8IntegratedWhirQueryScheduleV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_QUERY_SCHEDULE_V1");
        push_u64(&mut out, self.version);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_digest(&mut out, &self.transcript_digest);
        push_digest(&mut out, &self.combined_bridge_claim_descriptor_digest);
        push_u64(&mut out, self.query_claims.len() as u64);
        for claim in &self.query_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_digest(&mut out, &self.query_claims_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.query_schedule_digest);
        out
    }
}

impl<'a> N8IntegratedWhirVerifierInput<'a> {
    #[must_use]
    pub fn from_descriptor_and_plan(
        descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1,
        proof_plan: &'a N8IntegratedWhirProofPlan,
        integrated_whir_root: Option<Digest32>,
        integrated_whir_proof: Option<&'a WhirProof>,
        query_schedule: Option<&'a N8IntegratedWhirQueryScheduleV1>,
    ) -> Self {
        Self {
            version: N8_INTEGRATED_WHIR_VERIFIER_INPUT_VERSION,
            prover_mode: N8IntegratedWhirProverModeV1::RealIntegratedK6aNativeEvaluatorV1,
            descriptor,
            proof_plan,
            claim_plan: &descriptor.claim_plan,
            committed_table_layout_digest: descriptor.committed_table.layout_digest,
            committed_table_digest: descriptor.committed_table.table_digest,
            combined_claim_descriptors: &proof_plan.bridge_claim_descriptors,
            combined_claim_descriptor_digest: proof_plan.combined_bridge_claim_descriptor_digest,
            integrated_whir_root,
            integrated_whir_proof,
            query_schedule,
            whir_instance_count: usize::from(integrated_whir_proof.is_some()),
            root_count: usize::from(integrated_whir_root.is_some()),
            extra_whir_root_count: 0,
            extra_whir_proof_count: 0,
            legacy_k6a_proof: None,
            legacy_tuple_leaf_proof: None,
        }
    }
}

impl N8IntegratedWhirProverModeV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_PROVER_MODE_V1");
        out.push(match self {
            Self::SyntheticNonAuthoritativeV1 => 1,
            Self::RealIntegratedK6aNativeEvaluatorV1 => 2,
        });
        out
    }
}

impl N8IntegratedWhirProverOutput {
    #[must_use]
    pub fn verifier_input<'a>(
        &'a self,
        descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1,
    ) -> N8IntegratedWhirVerifierInput<'a> {
        let mut input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            descriptor,
            &self.proof_plan,
            Some(self.integrated_whir_root),
            Some(&self.integrated_whir_proof),
            Some(&self.query_schedule),
        );
        input.whir_instance_count = self.counters.whir_instance_count;
        input.root_count = self.counters.root_count;
        input.prover_mode = self.mode;
        input
    }
}

impl Symbt3N8IntegratedPrototypeGateReport {
    fn ok() -> Self {
        Self {
            ok: true,
            blocked: false,
            blocker: None,
            semantic_completion: N8IntegratedSemanticCompletionFlagsV1::none_complete(),
        }
    }

    fn ok_with_semantic_completion(
        semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    ) -> Self {
        Self {
            ok: true,
            blocked: false,
            blocker: None,
            semantic_completion,
        }
    }

    fn blocked(blocker: Symbt3N8IntegratedPrototypeBlocker) -> Self {
        Self {
            ok: false,
            blocked: true,
            blocker: Some(blocker),
            semantic_completion: N8IntegratedSemanticCompletionFlagsV1::none_complete(),
        }
    }

    fn blocked_with_semantic_completion(
        blocker: Symbt3N8IntegratedPrototypeBlocker,
        semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    ) -> Self {
        Self {
            ok: false,
            blocked: true,
            blocker: Some(blocker),
            semantic_completion,
        }
    }
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
pub fn build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness(
    pk: &WhirProvingKey,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
) -> Option<Symbt3N7bNativeTupleLeafProofParts> {
    build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
        pk,
        accumulator_instance,
        witness,
        adapter,
        None,
    )
}

fn build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
    pk: &WhirProvingKey,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    mut profile: Option<&mut N8DirectSemanticInputBuildProfileV1>,
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

    let section_start = Instant::now();
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
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_raw_values_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
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
    validate_same_domain_tuple_leaf_inputs(&specs, &evaluations, &eval_requests).ok()?;

    let mode = Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1;
    let logical_oracle_count = specs.len();
    let descriptor_digest = native_oracle_spec_digest(&specs);
    let repetition_log_size =
        symbt3_tuple_leaf_repetition_log_size(SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT)?;
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest_for_repeated_rlc(
        mode,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    );
    let repeated_packing_challenges = symbt3_tuple_leaf_packing_challenges_for_repetitions(
        mode,
        adapter.main_symbt3_relation_id,
        adapter.public_statement_digest,
        adapter.whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        logical_oracle_count,
        num_vars,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
    )?;
    let packing_challenge_digest =
        symbt3_tuple_leaf_repeated_packing_challenge_digest(&repeated_packing_challenges);
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_descriptor_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
    let claim_kind = WhirNativeEvalClaimKind::DirectOpening;
    let evals_by_id = specs
        .iter()
        .zip(evaluations.iter())
        .map(|(spec, evaluations)| (spec.oracle_id, evaluations.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let packed_num_vars = num_vars.checked_add(repetition_log_size)?;
    let mut logical_claims =
        Vec::with_capacity(eval_requests.len() * SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT);
    let mut packed_eval_claims = Vec::with_capacity(SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT);
    let mut packed_evaluations = Vec::new();
    for (repetition_index, packing_challenges) in repeated_packing_challenges.iter().enumerate() {
        let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
            repetition_index,
            adapter.main_symbt3_relation_id,
            adapter.public_statement_digest,
            adapter.whir_param_digest,
            descriptor_digest,
            tuple_leaf_layout_digest,
            claim_kind,
            num_vars,
        );
        let point_digest = native_oracle_point_digest(&point);
        let mut repetition_claims = Vec::with_capacity(eval_requests.len());
        for request in &eval_requests {
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
            symbt3_tuple_leaf_pack_evaluations(packing_challenges, &evaluations)?;
        let mut packed_point = point;
        packed_point.extend(tuple_leaf_boolean_point_for_index(
            repetition_index,
            repetition_log_size,
        ));
        let packed_point_digest = native_oracle_point_digest(&packed_point);
        packed_eval_claims.push(Symbt3TupleLeafPackedEvalClaim {
            point_digest: packed_point_digest,
            value: packed_value,
            claim_kind,
        });
        packed_evaluations.extend(repetition_packed_evaluations);
        logical_claims.extend(repetition_claims);
    }
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_claims_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }

    let section_start = Instant::now();
    let packed_root = whir_initial_root_digest(
        &pk.seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        packed_num_vars,
        &packed_evaluations,
    )?;
    if let Some(profile) = profile.as_deref_mut() {
        profile.tuple_rlc_packed_root_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    }
    let counters = tuple_leaf_counters_for(
        logical_oracle_count,
        logical_claims.len(),
        num_vars,
        SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
        SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
    );
    let proof = Symbt3TupleLeafMultiOracleProof {
        version: SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_VERSION,
        mode,
        proof_relation_id: adapter.main_symbt3_relation_id,
        public_statement_digest: adapter.public_statement_digest,
        whir_param_digest: adapter.whir_param_digest,
        logical_descriptors: specs,
        descriptor_digest,
        tuple_leaf_layout_digest,
        packing_challenge_digest,
        packed_root,
        packed_eval_claims,
        logical_eval_claims: logical_claims,
        whir_pcs_proof: WhirPcsProof::<F, EF, WhirMmcs>::default(),
        counters,
    };
    let source_oracle_root = accumulator_instance.source_assignment_roots_digest;
    let descriptors = proof
        .logical_descriptors
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

#[derive(Debug, Clone, Copy)]
struct N8DirectValidatedK6aSetupMaterialV1 {
    relation_id: Digest32,
    profile_digest: Digest32,
    accumulator_instance_digest: Digest32,
    public_statement_digest: Digest32,
    whir_param_digest: Digest32,
}

fn n8_direct_timed_digest<T>(
    digest_canonical_serialization_ms: &mut f64,
    build: impl FnOnce() -> T,
) -> T {
    let start = Instant::now();
    let value = build();
    *digest_canonical_serialization_ms += start.elapsed().as_secs_f64() * 1_000.0;
    value
}

fn n8_direct_product_non_zk_profile_ok(
    profile: &Symbt3AuthorityProfile,
    relation: &BatchedCpSymbt3RelationDescription,
) -> bool {
    profile.routing_status == crate::batched_cp::Symbt3RoutingStatus::ProductAuthority
        && profile.product_eligible
        && !profile.research_only
        && profile.zk_status == crate::batched_cp::Symbt3ZkStatus::NonZkIntegrityOnly
        && crate::batched_cp::product_policy_accepts_non_zk(profile)
        && crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        && profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
}

fn n8_direct_accumulator_instance_matches_prebuilt_statement(
    profile_digest: Digest32,
    accumulator_instance: &Symbt3AccumulatorInstance,
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    digest_canonical_serialization_ms: &mut f64,
) -> bool {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let expected_source_assignment_roots_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-assignment-roots",
                &accumulator_instance.source_assignment_roots,
            )
        });
    let expected_source_ajtai_opening_roots_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-ajtai-opening-roots",
                &accumulator_instance.source_ajtai_opening_roots,
            )
        });
    let expected_message_oracle_roots_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-message-oracle-roots",
                &accumulator_instance.message_oracle_roots,
            )
        });
    let expected_batch_items_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_batch_items_digest(
                scheme,
                &accumulator_instance.input_public_values,
                &accumulator_instance.input_commitment_values,
                &accumulator_instance.input_evaluation_values,
                &accumulator_instance.input_accumulator_values,
                &accumulator_instance.source_assignment_roots,
                &accumulator_instance.message_oracle_roots,
            )
        });
    let expected_public_source_boundary_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            crate::batched_cp::symbt3_public_source_boundary_digest(
                scheme,
                &expected_source_assignment_roots_digest,
                &accumulator_instance.source_assignment_boundary_digest,
                &expected_source_ajtai_opening_roots_digest,
                &accumulator_instance.source_ajtai_commitment_boundary_digest,
            )
        });
    let statement_bytes_len = n8_direct_timed_digest(digest_canonical_serialization_ms, || {
        statement.canonical_bytes().len()
    });

    accumulator_instance.profile_digest == profile_digest
        && accumulator_instance.shape_id == relation.shape.shape_id
        && accumulator_instance.batch_capacity == relation.shape.batch_capacity
        && accumulator_instance.active_count == relation.shape.active_count
        && accumulator_instance.batch_items_digest == expected_batch_items_digest
        && accumulator_instance.public_source_boundary_digest
            == expected_public_source_boundary_digest
        && accumulator_instance.source_assignment_roots_digest
            == expected_source_assignment_roots_digest
        && accumulator_instance.source_ajtai_opening_roots_digest
            == expected_source_ajtai_opening_roots_digest
        && accumulator_instance.message_oracle_roots_digest == expected_message_oracle_roots_digest
        && statement.matches_relation(relation)
        && statement_bytes_len == relation.public_statement_bytes()
}

fn n8_direct_validated_k6a_setup_material(
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    relation: &BatchedCpSymbt3RelationDescription,
    digest_canonical_serialization_ms: &mut f64,
) -> Option<(
    crate::batched_cp::BatchedCpSymbt3PublicStatement,
    N8DirectValidatedK6aSetupMaterialV1,
)> {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let relation_id =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || relation.relation_id());
    let profile_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || profile.digest(scheme));
    if !n8_direct_product_non_zk_profile_ok(profile, relation)
        || profile.semantic_profile_version < 1
    {
        return None;
    }
    let statement = accumulator_instance.to_public_statement();
    if !n8_direct_accumulator_instance_matches_prebuilt_statement(
        profile_digest,
        accumulator_instance,
        relation,
        &statement,
        digest_canonical_serialization_ms,
    ) {
        return None;
    }
    let public_statement_digest = n8_direct_timed_digest(digest_canonical_serialization_ms, || {
        derive_symbt3_public_statement_digest(relation, &statement)
    });
    let accumulator_instance_digest =
        n8_direct_timed_digest(digest_canonical_serialization_ms, || {
            accumulator_instance.digest(scheme)
        });
    let whir_param_digest = statement.whir_parameter_digest;
    Some((
        statement,
        N8DirectValidatedK6aSetupMaterialV1 {
            relation_id,
            profile_digest,
            accumulator_instance_digest,
            public_statement_digest,
            whir_param_digest,
        },
    ))
}

fn symbt3_k6a_relation_from_context(context: &[u8]) -> Option<BatchedCpSymbt3RelationDescription> {
    BatchedCpSymbt3RelationDescription::from_context_bytes(context).ok()
}

fn symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_proof(
    relation: &BatchedCpSymbt3RelationDescription,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    proof: &WhirProof,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || proof.is_output
        || !proof.sumcheck_rounds_3.is_empty()
        || !proof.linear_checks.is_empty()
        || !proof.family_columnar_subproofs.is_empty()
        || !crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        || !crate::batched_cp::product_policy_accepts_non_zk(profile)
        || !profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
        || !accumulator_instance.matches_profile_and_relation(profile, relation)
    {
        return None;
    }
    let statement = accumulator_instance.to_public_statement();
    if !profile.accepts_statement_for_non_zk_integrity_product_authority(relation, &statement) {
        return None;
    }
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        full_accumulator_workload: true,
        smoke_profile: false,
        proof_kind,
        profile_digest: profile.digest(scheme),
        accumulator_instance_digest: accumulator_instance.digest(scheme),
        public_statement_digest: derive_symbt3_public_statement_digest(relation, &statement),
        whir_param_digest: statement.whir_parameter_digest,
        main_symbt3_relation_id: relation.relation_id(),
        main_symbt3_proof_digest: symbt3_main_whir_proof_digest(proof),
        old_accumulator_digest: statement.old_accumulator_digest,
        new_accumulator_digest: statement.new_accumulator_digest,
        batch_manifest_root: statement.batch_manifest_root,
        manifest_oracle_root: statement.manifest_oracle_root,
        native_message_roots_digest: accumulator_instance.message_oracle_roots_digest,
        batch_size: statement.batch_capacity as u64,
        active_count: statement.active_count as u64,
        main_whir_num_vars: proof.num_vars,
        main_oracle_len: 1usize.checked_shl(proof.num_vars as u32).unwrap_or(0),
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: proof.family_columnar_subproofs.len(),
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        source_r1cs_residual_verifier_evaluations: 1,
    };
    symbt3_native_accumulator_k6a_workload_adapter_from_parts((&adapter).into())
}

#[cfg(test)]
fn symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_semantic_source(
    relation: &BatchedCpSymbt3RelationDescription,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    source: &Symbt3N8K6aSemanticSourceV1,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    let statement = super::symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
        profile,
        accumulator_instance,
        relation,
    )?;
    symbt3_native_accumulator_k6a_workload_adapter_from_relation_statement_and_semantic_source(
        relation,
        profile,
        accumulator_instance,
        &statement,
        proof_kind,
        source,
    )
}

#[cfg(test)]
fn symbt3_native_accumulator_k6a_workload_adapter_from_relation_statement_and_semantic_source(
    relation: &BatchedCpSymbt3RelationDescription,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    proof_kind: ProductProofKind,
    source: &Symbt3N8K6aSemanticSourceV1,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || source.source_digest == [0u8; 32]
        || source.relation_id != relation.relation_id()
        || source.num_vars == 0
        || source.oracle_len != symbt3_n8_oracle_len(source.num_vars)?
        || source.verifier_claims.is_empty()
        || source.verifier_points.len() != source.verifier_claims.len()
        || source
            .final_residuals
            .iter()
            .any(|&value| value != BabyBear::ZERO)
        || !crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        || !crate::batched_cp::product_policy_accepts_non_zk(profile)
        || !profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
        || !accumulator_instance.matches_profile_and_relation(profile, relation)
    {
        return None;
    }
    let public_statement_digest = derive_symbt3_public_statement_digest(relation, statement);
    if source.public_statement_digest != public_statement_digest
        || source.whir_param_digest != statement.whir_parameter_digest
        || !profile.accepts_statement_for_non_zk_integrity_product_authority(relation, statement)
    {
        return None;
    }
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        full_accumulator_workload: true,
        smoke_profile: false,
        proof_kind,
        profile_digest: profile.digest(scheme),
        accumulator_instance_digest: accumulator_instance.digest(scheme),
        public_statement_digest,
        whir_param_digest: statement.whir_parameter_digest,
        main_symbt3_relation_id: relation.relation_id(),
        main_symbt3_proof_digest: source.source_digest,
        old_accumulator_digest: statement.old_accumulator_digest,
        new_accumulator_digest: statement.new_accumulator_digest,
        batch_manifest_root: statement.batch_manifest_root,
        manifest_oracle_root: statement.manifest_oracle_root,
        native_message_roots_digest: accumulator_instance.message_oracle_roots_digest,
        batch_size: statement.batch_capacity as u64,
        active_count: statement.active_count as u64,
        main_whir_num_vars: source.num_vars,
        main_oracle_len: source.oracle_len,
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        source_r1cs_residual_verifier_evaluations: 1,
    };
    symbt3_native_accumulator_k6a_workload_adapter_from_parts((&adapter).into())
}

fn symbt3_native_accumulator_k6a_workload_adapter_from_validated_direct_material(
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    accumulator_instance: &Symbt3AccumulatorInstance,
    proof_kind: ProductProofKind,
    source: &Symbt3N8K6aSemanticSourceV1,
    material: N8DirectValidatedK6aSetupMaterialV1,
) -> Option<Symbt3NativeAccumulatorK6aWorkloadAdapter> {
    if proof_kind != ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        || source.source_digest == [0u8; 32]
        || source.relation_id != material.relation_id
        || source.public_statement_digest != material.public_statement_digest
        || source.whir_param_digest != material.whir_param_digest
        || source.num_vars == 0
        || source.oracle_len != symbt3_n8_oracle_len(source.num_vars)?
        || source.verifier_claims.is_empty()
        || source.verifier_points.len() != source.verifier_claims.len()
        || source
            .final_residuals
            .iter()
            .any(|&value| value != BabyBear::ZERO)
        || statement.whir_parameter_digest != material.whir_param_digest
    {
        return None;
    }
    let adapter = Symbt3NativeAccumulatorK6aWorkloadAdapter {
        workload_kind: Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
        full_accumulator_workload: true,
        smoke_profile: false,
        proof_kind,
        profile_digest: material.profile_digest,
        accumulator_instance_digest: material.accumulator_instance_digest,
        public_statement_digest: material.public_statement_digest,
        whir_param_digest: material.whir_param_digest,
        main_symbt3_relation_id: material.relation_id,
        main_symbt3_proof_digest: source.source_digest,
        old_accumulator_digest: statement.old_accumulator_digest,
        new_accumulator_digest: statement.new_accumulator_digest,
        batch_manifest_root: statement.batch_manifest_root,
        manifest_oracle_root: statement.manifest_oracle_root,
        native_message_roots_digest: accumulator_instance.message_oracle_roots_digest,
        batch_size: statement.batch_capacity as u64,
        active_count: statement.active_count as u64,
        main_whir_num_vars: source.num_vars,
        main_oracle_len: source.oracle_len,
        top_level_whir_proof_count: 1,
        family_columnar_subproof_count: 0,
        backend_table_count: 1,
        accumulator_transition_claims: 1,
        source_r1cs_residual_verifier_evaluations: 1,
    };
    symbt3_native_accumulator_k6a_workload_adapter_from_parts((&adapter).into())
}

#[must_use]
pub fn build_n8_semantic_inputs_from_k6a_witness(
    pk: &WhirProvingKey,
    profile: &Symbt3AuthorityProfile,
    accumulator_instance: &Symbt3AccumulatorInstance,
    witness: &Symbt3AccumulatorWitness,
) -> Option<N8DirectSemanticInputsV1> {
    let total_start = Instant::now();
    let mut build_profile = N8DirectSemanticInputBuildProfileV1::default();

    let relation_statement_start = Instant::now();
    let section_start = Instant::now();
    let relation = symbt3_k6a_relation_from_context(pk.relation.context.as_ref()?)?;
    build_profile.k6a_relation_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let (statement, setup_material) = n8_direct_validated_k6a_setup_material(
        profile,
        accumulator_instance,
        &relation,
        &mut build_profile.digest_canonical_serialization_ms,
    )?;
    build_profile.k6a_public_statement_construction_ms =
        section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let symbt3_witness = witness.to_symbt3_witness(&relation)?;
    build_profile.k6a_witness_conversion_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    build_profile.relation_statement_ms =
        relation_statement_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let k6a_semantic_source = symbt3_n8_k6a_semantic_source_from_witness_with_public_digest(
        &pk.seed,
        &relation,
        &statement,
        &symbt3_witness,
        Some(setup_material.public_statement_digest),
        Some(setup_material.relation_id),
        Some(&mut build_profile.digest_canonical_serialization_ms),
    )?;
    build_profile.k6a_claim_extraction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let k6a_adapter =
        symbt3_native_accumulator_k6a_workload_adapter_from_validated_direct_material(
            &statement,
            accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &k6a_semantic_source,
            setup_material,
        )?;
    build_profile.adapter_construction_ms = section_start.elapsed().as_secs_f64() * 1_000.0;

    let section_start = Instant::now();
    let native_tuple_leaf = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
        pk,
        accumulator_instance,
        witness,
        &k6a_adapter,
        Some(&mut build_profile),
    )?;
    build_profile.tuple_rlc_input_ms = section_start.elapsed().as_secs_f64() * 1_000.0;
    build_profile.total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;

    Some(N8DirectSemanticInputsV1 {
        relation,
        statement,
        k6a_semantic_source,
        k6a_adapter,
        native_tuple_leaf,
        profile: build_profile,
    })
}

#[must_use]
pub fn symbt3_manifest_component_values_root(
    role: WhirNativeOracleRole,
    component_id: u32,
    kind: Symbt3ManifestComponentKind,
    visibility: Symbt3ManifestVisibility,
    layout_digest: Digest32,
    values: &[BabyBear],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_MANIFEST_COMPONENT_VALUES_ROOT_V1");
    push_bytes(&mut bytes, &role.canonical_bytes());
    push_u32(&mut bytes, component_id);
    push_bytes(&mut bytes, &kind.canonical_bytes());
    push_bytes(&mut bytes, &visibility.canonical_bytes());
    push_digest(&mut bytes, &layout_digest);
    push_babybear_vec(&mut bytes, values);
    digest_bytes(&bytes)
}

#[must_use]
pub fn symbt3_manifest_oracle_layout_digest(
    role: WhirNativeOracleRole,
    components: &[Symbt3ManifestComponentPublicView],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_MANIFEST_ORACLE_LAYOUT_DIGEST_V1");
    push_bytes(&mut bytes, &role.canonical_bytes());
    push_u64(&mut bytes, components.len() as u64);
    for component in components {
        push_u32(&mut bytes, component.component_id);
        push_bytes(&mut bytes, &component.kind.canonical_bytes());
        push_bytes(&mut bytes, &component.visibility.canonical_bytes());
        push_digest(&mut bytes, &component.layout_digest);
        push_u64(&mut bytes, component.value_count as u64);
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_message_round_layouts_digest(
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_MESSAGE_ROUND_LAYOUTS_V1");
    push_u64(&mut bytes, round_layouts.len() as u64);
    for layout in round_layouts {
        push_bytes(&mut bytes, &layout.canonical_bytes());
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn native_message_roots_digest(descriptors: &[WhirNativeOracleDescriptor]) -> Digest32 {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_NATIVE_MESSAGE_ORACLE_ROOTS_V1");
    push_u64(&mut bytes, descriptors.len() as u64);
    for descriptor in descriptors {
        let round = match &descriptor.role {
            WhirNativeOracleRole::MessageRound { round } => *round,
            _ => {
                return digest_bytes(b"SYMBT3_NATIVE_MESSAGE_ORACLE_ROOTS_INVALID_ROLE_V1");
            }
        };
        push_u32(&mut bytes, round);
        push_u32(&mut bytes, descriptor.oracle_id);
        push_digest(&mut bytes, &descriptor.root);
        push_digest(&mut bytes, &descriptor.layout_digest);
        push_u64(&mut bytes, descriptor.num_vars as u64);
    }
    digest_bytes(&bytes)
}

#[must_use]
pub fn derive_native_round_challenge(
    round_index: u32,
    prefix_roots: &[Digest32],
    round_layout_digest: Digest32,
    context: &Symbt3NativeRoundChallengeContext,
) -> BabyBear {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"SYMBT3_ROUND_CHALLENGE_V1");
    push_bytes(&mut bytes, &context.canonical_bytes_without_folded_output());
    push_u64(&mut bytes, prefix_roots.len() as u64);
    for root in prefix_roots {
        push_digest(&mut bytes, root);
    }
    push_u32(&mut bytes, round_index);
    push_digest(&mut bytes, &round_layout_digest);
    derive_challenge(&bytes, 0, b"symbt3-native-round-challenge")
}

#[must_use]
pub fn derive_native_round_challenges(
    descriptors: &[WhirNativeOracleDescriptor],
    round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    context: &Symbt3NativeRoundChallengeContext,
) -> Option<Vec<BabyBear>> {
    if descriptors.len() != round_layouts.len() {
        return None;
    }
    let mut roots = Vec::with_capacity(descriptors.len());
    let mut challenges = Vec::with_capacity(descriptors.len());
    for (descriptor, layout) in descriptors.iter().zip(round_layouts.iter()) {
        roots.push(descriptor.root);
        challenges.push(derive_native_round_challenge(
            layout.round_index,
            &roots,
            layout.layout_digest,
            context,
        ));
    }
    Some(challenges)
}

impl WhirNativeOracleRole {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_ORACLE_ROLE_V1");
        encode_role(&mut out, self);
        out
    }
}

impl WhirNativeOpeningSchedule {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_OPENING_SCHEDULE_V1");
        encode_schedule(&mut out, self);
        out
    }
}

impl WhirNativeOracleSpec {
    #[must_use]
    pub fn descriptor_with_root(&self, root: Digest32) -> WhirNativeOracleDescriptor {
        WhirNativeOracleDescriptor {
            version: self.version,
            oracle_id: self.oracle_id,
            role: self.role.clone(),
            layout_digest: self.layout_digest,
            num_vars: self.num_vars,
            root,
            opening_schedule: self.opening_schedule.clone(),
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_ORACLE_SPEC_V1");
        push_u64(&mut out, self.version);
        push_u32(&mut out, self.oracle_id);
        push_bytes(&mut out, &self.role.canonical_bytes());
        push_digest(&mut out, &self.layout_digest);
        push_u64(&mut out, self.num_vars as u64);
        push_bytes(&mut out, &self.opening_schedule.canonical_bytes());
        out
    }
}

impl WhirNativeOracleDescriptor {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_ORACLE_DESCRIPTOR_V1");
        push_u64(&mut out, self.version);
        push_u32(&mut out, self.oracle_id);
        push_bytes(&mut out, &self.role.canonical_bytes());
        push_digest(&mut out, &self.layout_digest);
        push_u64(&mut out, self.num_vars as u64);
        push_digest(&mut out, &self.root);
        push_bytes(&mut out, &self.opening_schedule.canonical_bytes());
        out
    }
}

impl WhirNativeEvalClaimKind {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_EVAL_CLAIM_KIND_V1");
        encode_claim_kind(&mut out, self);
        out
    }
}

impl WhirNativeEvalRequest {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_EVAL_REQUEST_V1");
        push_u32(&mut out, self.oracle_id);
        push_bytes(&mut out, &self.claim_kind.canonical_bytes());
        out
    }
}

impl WhirNativeOracleEvalClaim {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_ORACLE_EVAL_CLAIM_V1");
        push_u32(&mut out, self.oracle_id);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_bytes(&mut out, &self.claim_kind.canonical_bytes());
        out
    }
}

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

#[allow(clippy::too_many_arguments)]
#[must_use]
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

fn whir_initial_root_digest(
    seed: &[u8; 32],
    root_policy: NativeOracleRootPolicy,
    num_variables: usize,
    evaluations: &[BabyBear],
) -> Option<Digest32> {
    let proof = whir_commit_initial_root_only(seed, num_variables, evaluations)?;
    whir_pcs_initial_root_digest(&proof, root_policy)
}

fn whir_pcs_initial_root_digest(
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    root_policy: NativeOracleRootPolicy,
) -> Option<Digest32> {
    match root_policy {
        NativeOracleRootPolicy::DebugDevelopmentOnly => {
            whir_pcs_initial_root_debug_development_digest(proof)
        }
        NativeOracleRootPolicy::CanonicalWhirRootV1 => {
            whir_pcs_initial_root_canonical_digest(proof)
        }
    }
}

#[must_use]
pub fn whir_pcs_initial_root_canonical_digest(
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
) -> Option<Digest32> {
    let root = proof.initial_commitment.as_ref()?;
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"WHIR_NATIVE_ORACLE_PCS_ROOT_CANONICAL_V1");
    push_u64(&mut bytes, root.num_roots() as u64);
    for digest_words in root.roots() {
        push_u64(&mut bytes, digest_words.len() as u64);
        for &word in digest_words {
            push_babybear(&mut bytes, word);
        }
    }
    Some(digest_bytes(&bytes))
}

fn whir_pcs_initial_root_debug_development_digest(
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
) -> Option<Digest32> {
    let root = proof.initial_commitment.as_ref()?;
    let mut hasher = Sha256::new();
    hasher.update(b"WHIR_NATIVE_ORACLE_PCS_ROOT_DEBUG_V1");
    // Quarantined compatibility path for development-only N1 fixtures. Product,
    // authority, native-manifest, and native-message verification profiles reject
    // NativeOracleRootPolicy::DebugDevelopmentOnly.
    hasher.update(format!("{root:?}").as_bytes());
    Some(hasher.finalize().into())
}

fn digest_bytes(bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_role(out: &mut Vec<u8>, role: &WhirNativeOracleRole) {
    match role {
        WhirNativeOracleRole::Manifest => out.push(1),
        WhirNativeOracleRole::Source => out.push(2),
        WhirNativeOracleRole::MessageRound { round } => {
            out.push(3);
            push_u32(out, *round);
        }
        WhirNativeOracleRole::Accumulator => out.push(4),
        WhirNativeOracleRole::FoldedBoundary => out.push(5),
        WhirNativeOracleRole::Auxiliary => out.push(6),
    }
}

fn encode_schedule(out: &mut Vec<u8>, schedule: &WhirNativeOpeningSchedule) {
    match schedule {
        WhirNativeOpeningSchedule::SamePoint => out.push(1),
        WhirNativeOpeningSchedule::PerOraclePoint => out.push(2),
        WhirNativeOpeningSchedule::TranscriptDerived { domain_separator } => {
            out.push(3);
            push_bytes(out, domain_separator.as_bytes());
        }
        WhirNativeOpeningSchedule::TranscriptDerivedWithBinding {
            domain_separator,
            binding_digest,
        } => {
            out.push(4);
            push_bytes(out, domain_separator.as_bytes());
            push_digest(out, binding_digest);
        }
    }
}

fn encode_claim_kind(out: &mut Vec<u8>, claim_kind: WhirNativeEvalClaimKind) {
    out.push(match claim_kind {
        WhirNativeEvalClaimKind::DirectOpening => 1,
        WhirNativeEvalClaimKind::EqualitySide => 2,
        WhirNativeEvalClaimKind::MessageView => 3,
        WhirNativeEvalClaimKind::ManifestView => 4,
        WhirNativeEvalClaimKind::SourceView => 5,
    });
}

fn encode_native_multi_oracle_mode(out: &mut Vec<u8>, mode: Symbt3NativeMultiOracleMode) {
    out.push(match mode {
        Symbt3NativeMultiOracleMode::CompatibilityEnvelopeV1 => 1,
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1 => 2,
        Symbt3NativeMultiOracleMode::SameDomainVectorTupleLeafV1 => 3,
    });
}

fn symbt3_tuple_leaf_layout_name(mode: Symbt3NativeMultiOracleMode) -> &'static str {
    match mode {
        Symbt3NativeMultiOracleMode::CompatibilityEnvelopeV1 => "none",
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1 => {
            SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
        }
        Symbt3NativeMultiOracleMode::SameDomainVectorTupleLeafV1 => {
            SYMBT3_SAME_DOMAIN_VECTOR_TUPLE_LEAF_LAYOUT
        }
    }
}

fn encode_root_policy(out: &mut Vec<u8>, root_policy: NativeOracleRootPolicy) {
    out.push(match root_policy {
        NativeOracleRootPolicy::DebugDevelopmentOnly => 1,
        NativeOracleRootPolicy::CanonicalWhirRootV1 => 2,
    });
}

fn encode_manifest_commitment_policy(out: &mut Vec<u8>, policy: ManifestCommitmentPolicy) {
    out.push(match policy {
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1 => 1,
        ManifestCommitmentPolicy::NativeManifestOracleOpeningV1 => 2,
    });
}

fn encode_source_commitment_policy(out: &mut Vec<u8>, policy: SourceCommitmentPolicy) {
    out.push(match policy {
        SourceCommitmentPolicy::NativeSourceOracleOpeningV1 => 1,
    });
}

fn encode_symbt3_manifest_visibility(out: &mut Vec<u8>, visibility: Symbt3ManifestVisibility) {
    out.push(match visibility {
        Symbt3ManifestVisibility::PublicBoundary => 1,
        Symbt3ManifestVisibility::CommittedPrivateNonZk => 2,
    });
}

fn encode_symbt3_zk_status(out: &mut Vec<u8>, zk_status: Symbt3ZkStatus) {
    out.push(match zk_status {
        Symbt3ZkStatus::NonZkIntegrityOnly => 1,
        Symbt3ZkStatus::ExplicitNonZkResearch => 2,
        Symbt3ZkStatus::ZkRequired => 3,
    });
}

fn encode_symbt3_manifest_component_kind(out: &mut Vec<u8>, kind: Symbt3ManifestComponentKind) {
    match kind {
        Symbt3ManifestComponentKind::PublicBoundary => out.push(1),
        Symbt3ManifestComponentKind::CommittedPrivateWitness => out.push(2),
        Symbt3ManifestComponentKind::Auxiliary(tag) => {
            out.push(3);
            push_u32(out, tag);
        }
    }
}

fn encode_symbt3_message_oracle_policy(out: &mut Vec<u8>, policy: Symbt3MessageOraclePolicy) {
    out.push(match policy {
        Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1 => 1,
        Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1 => 2,
    });
}

fn encode_symbt3_native_oracle_profile(out: &mut Vec<u8>, profile: Symbt3NativeOracleProfile) {
    out.push(match profile {
        Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1 => 1,
    });
}

fn encode_symbt3_native_folding_proof_kind(
    out: &mut Vec<u8>,
    proof_kind: Symbt3NativeFoldingProofKind,
) {
    out.push(match proof_kind {
        Symbt3NativeFoldingProofKind::NativeNonZkFoldingIntegrityV1 => 1,
        Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1 => 2,
        Symbt3NativeFoldingProofKind::MonolithicTypedCpV1 => 3,
        Symbt3NativeFoldingProofKind::Symbt3NativeNonZkFoldingIntegrityV1 => 4,
        Symbt3NativeFoldingProofKind::Symbt3NativeAccumulatorAuthorityV1 => 5,
    });
}

fn encode_symbt3_native_accumulator_authority_workload(
    out: &mut Vec<u8>,
    workload: Symbt3NativeAccumulatorAuthorityWorkload,
) {
    out.push(match workload {
        Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1 => 1,
        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1 => 2,
    });
}

fn encode_symbt3_native_folding_integrity_route_status(
    out: &mut Vec<u8>,
    route_status: Symbt3NativeFoldingIntegrityRouteStatus,
) {
    out.push(match route_status {
        Symbt3NativeFoldingIntegrityRouteStatus::Disabled => 1,
        Symbt3NativeFoldingIntegrityRouteStatus::PublicCanonicalK6a => 2,
        Symbt3NativeFoldingIntegrityRouteStatus::ExplicitNativeNonZk => 3,
        Symbt3NativeFoldingIntegrityRouteStatus::ResearchOnlyNativeNonZk => 4,
        Symbt3NativeFoldingIntegrityRouteStatus::DefaultVerifyPublic => 5,
    });
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn push_digest(out: &mut Vec<u8>, digest: &Digest32) {
    out.extend_from_slice(digest);
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn push_optional_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            push_bool(out, true);
            push_u32(out, value);
        }
        None => push_bool(out, false),
    }
}

fn push_optional_digest(out: &mut Vec<u8>, value: Option<&Digest32>) {
    match value {
        Some(value) => {
            push_bool(out, true);
            push_digest(out, value);
        }
        None => push_bool(out, false),
    }
}

fn push_optional_role(out: &mut Vec<u8>, value: Option<&WhirNativeOracleRole>) {
    match value {
        Some(value) => {
            push_bool(out, true);
            push_bytes(out, &value.canonical_bytes());
        }
        None => push_bool(out, false),
    }
}

fn push_babybear(out: &mut Vec<u8>, value: BabyBear) {
    out.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
}

fn push_babybear_vec(out: &mut Vec<u8>, values: &[BabyBear]) {
    push_u64(out, values.len() as u64);
    for &value in values {
        push_babybear(out, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batched_cp::{
        BatchedCpBucket, BatchedCpItem, BatchedCpSymbt3RelationDescription,
        BatchedCpSymbt3SetupDescriptor,
    };
    use crate::commitment::Commitment;
    use crate::cp_relation_core::CpPublicStatement;
    use crate::digest_core::PublicDigestScheme;
    use crate::params::{SymphonyParams, D};
    use crate::proof_orchestrator::{ProofBundle, Prover};
    use crate::r1cs::R1CSMatrices;
    use crate::ring::{RingElement, RingVector};
    use crate::snark::whir::WhirSnark;
    use crate::snark::{BackendSnark, RelationDescription};
    use crate::SumcheckSnark;
    use p3_field::PrimeCharacteristicRing;

    fn digest(label: &[u8]) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.finalize().into()
    }

    fn relation() -> RelationDescription {
        RelationDescription {
            num_instance_vars: 1,
            num_witness_vars: 1,
            num_constraints: 1,
            context: None,
        }
    }

    fn native_oracle_fixture() -> (
        WhirProvingKey,
        WhirVerifyingKey,
        Digest32,
        Digest32,
        Digest32,
        Vec<WhirNativeOracleSpec>,
        Vec<Vec<BabyBear>>,
        Vec<WhirNativeEvalRequest>,
        WhirNativeMultiOracleProof,
    ) {
        native_oracle_fixture_with_source(None)
    }

    fn native_oracle_fixture_with_source(
        source_override: Option<Vec<BabyBear>>,
    ) -> (
        WhirProvingKey,
        WhirVerifyingKey,
        Digest32,
        Digest32,
        Digest32,
        Vec<WhirNativeOracleSpec>,
        Vec<Vec<BabyBear>>,
        Vec<WhirNativeEvalRequest>,
        WhirNativeMultiOracleProof,
    ) {
        let (pk, vk) = WhirSnark::setup(&relation());
        let proof_relation_id = digest(b"n1-proof-relation");
        let public_statement_digest = digest(b"n1-public-statement");
        let whir_param_digest = digest(b"n1-whir-params");
        let specs = vec![
            WhirNativeOracleSpec {
                version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                oracle_id: 1,
                role: WhirNativeOracleRole::Manifest,
                layout_digest: digest(b"manifest-layout"),
                num_vars: 2,
                opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                    domain_separator: "N1_MANIFEST_SOURCE_EQUALITY",
                },
            },
            WhirNativeOracleSpec {
                version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                oracle_id: 2,
                role: WhirNativeOracleRole::Source,
                layout_digest: digest(b"source-layout"),
                num_vars: 2,
                opening_schedule: WhirNativeOpeningSchedule::TranscriptDerived {
                    domain_separator: "N1_MANIFEST_SOURCE_EQUALITY",
                },
            },
        ];
        let manifest = vec![
            BabyBear::from_u32(3),
            BabyBear::from_u32(5),
            BabyBear::from_u32(8),
            BabyBear::from_u32(13),
        ];
        let source = source_override.unwrap_or_else(|| manifest.clone());
        let requests = vec![
            WhirNativeEvalRequest {
                oracle_id: 1,
                claim_kind: WhirNativeEvalClaimKind::EqualitySide,
            },
            WhirNativeEvalRequest {
                oracle_id: 2,
                claim_kind: WhirNativeEvalClaimKind::EqualitySide,
            },
        ];
        let proof = whir_commit_and_prove_oracles(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &specs,
            &[manifest.clone(), source.clone()],
            &requests,
        )
        .expect("native oracle proof");
        (
            pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            specs,
            vec![manifest, source],
            requests,
            proof,
        )
    }

    fn verify_fixture(
        vk: &WhirVerifyingKey,
        proof_relation_id: Digest32,
        public_statement_digest: Digest32,
        whir_param_digest: Digest32,
        proof: &WhirNativeMultiOracleProof,
    ) -> bool {
        whir_verify_oracle_openings(
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &proof.descriptors,
            proof,
            &proof.eval_claims,
        )
    }

    fn refresh_envelope_digest(proof: &mut WhirNativeMultiOracleProof) {
        proof.native_multi_oracle_envelope_digest = native_multi_oracle_envelope_digest(proof);
    }

    struct N2Fixture {
        pk: WhirProvingKey,
        vk: WhirVerifyingKey,
        proof_relation_id: Digest32,
        public_statement_digest: Digest32,
        whir_param_digest: Digest32,
        manifest_layout_digest: Digest32,
        source_layout_digest: Digest32,
        manifest_evals: Vec<BabyBear>,
        proof: NativeManifestSourceMembershipProof,
    }

    fn n2_fixture() -> N2Fixture {
        n2_fixture_with_source_and_policy(None, NativeOracleRootPolicy::CanonicalWhirRootV1, true)
    }

    fn n2_fixture_with_source_and_policy(
        source_override: Option<Vec<BabyBear>>,
        root_policy: NativeOracleRootPolicy,
        require_equal: bool,
    ) -> N2Fixture {
        let (pk, vk) = WhirSnark::setup(&relation());
        let proof_relation_id = digest(b"n2-proof-relation");
        let public_statement_digest = digest(b"n2-public-statement");
        let whir_param_digest = digest(b"n2-whir-params");
        let manifest_layout_digest = digest(b"n2-manifest-layout");
        let source_layout_digest = digest(b"n2-source-layout");
        let manifest_evals = vec![
            BabyBear::from_u32(3),
            BabyBear::from_u32(5),
            BabyBear::from_u32(8),
            BabyBear::from_u32(13),
        ];
        let source_evals = source_override.unwrap_or_else(|| manifest_evals.clone());
        let manifest_num_vars = num_vars_for_evals(&manifest_evals).expect("manifest num vars");
        let source_num_vars = num_vars_for_evals(&source_evals).expect("source num vars");

        let proof = if require_equal && root_policy == NativeOracleRootPolicy::CanonicalWhirRootV1 {
            prove_native_manifest_source_membership(
                &pk,
                proof_relation_id,
                public_statement_digest,
                whir_param_digest,
                manifest_layout_digest,
                source_layout_digest,
                &manifest_evals,
                &source_evals,
            )
            .expect("N2 native manifest/source membership proof")
        } else {
            let manifest_root =
                whir_initial_root_digest(&pk.seed, root_policy, manifest_num_vars, &manifest_evals)
                    .expect("manifest root");
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
            )
            .expect("N2 specs");
            let requests = native_manifest_source_membership_eval_requests();
            let native_proof = whir_commit_and_prove_oracles_with_root_policy(
                &pk,
                root_policy,
                proof_relation_id,
                public_statement_digest,
                whir_param_digest,
                &specs,
                &[manifest_evals.clone(), source_evals.clone()],
                &requests,
            )
            .expect("N2 native oracle proof");
            NativeManifestSourceMembershipProof {
                batch_manifest_root,
                native_proof,
            }
        };

        N2Fixture {
            pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            manifest_layout_digest,
            source_layout_digest,
            manifest_evals,
            proof,
        }
    }

    fn verify_n2_fixture(
        fixture: &N2Fixture,
        proof: &NativeManifestSourceMembershipProof,
    ) -> WhirNativeOracleVerifyReport {
        verify_n2_fixture_with_batch(fixture, proof.batch_manifest_root, &proof.native_proof)
    }

    fn verify_n2_fixture_with_batch(
        fixture: &N2Fixture,
        batch_manifest_root: Digest32,
        proof: &WhirNativeMultiOracleProof,
    ) -> WhirNativeOracleVerifyReport {
        verify_native_manifest_source_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            batch_manifest_root,
            ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &proof.descriptors,
            proof,
        )
    }

    struct N3Fixture {
        pk: WhirProvingKey,
        vk: WhirVerifyingKey,
        proof_relation_id: Digest32,
        whir_param_digest: Digest32,
        components: Vec<Symbt3ManifestSourceComponentValues>,
        proof: Symbt3CommittedPrivateManifestMembershipProof,
    }

    fn n3_components() -> Vec<Symbt3ManifestSourceComponentValues> {
        vec![
            Symbt3ManifestSourceComponentValues {
                component_id: 1,
                kind: Symbt3ManifestComponentKind::PublicBoundary,
                visibility: Symbt3ManifestVisibility::PublicBoundary,
                layout_digest: digest(b"n3-public-component-layout"),
                manifest_values: vec![BabyBear::from_u32(17), BabyBear::from_u32(19)],
                source_values: vec![BabyBear::from_u32(17), BabyBear::from_u32(19)],
            },
            Symbt3ManifestSourceComponentValues {
                component_id: 2,
                kind: Symbt3ManifestComponentKind::CommittedPrivateWitness,
                visibility: Symbt3ManifestVisibility::CommittedPrivateNonZk,
                layout_digest: digest(b"n3-committed-private-component-layout"),
                manifest_values: vec![BabyBear::from_u32(1_234_567), BabyBear::from_u32(7_654_321)],
                source_values: vec![BabyBear::from_u32(1_234_567), BabyBear::from_u32(7_654_321)],
            },
        ]
    }

    fn n3_fixture() -> N3Fixture {
        n3_fixture_with_components(n3_components(), Symbt3ZkStatus::NonZkIntegrityOnly)
    }

    fn n3_fixture_with_components(
        components: Vec<Symbt3ManifestSourceComponentValues>,
        zk_status: Symbt3ZkStatus,
    ) -> N3Fixture {
        let (pk, vk) = WhirSnark::setup(&relation());
        let proof_relation_id = digest(b"n3-proof-relation");
        let whir_param_digest = digest(b"n3-whir-params");
        let proof = prove_committed_private_manifest_membership(
            &pk,
            proof_relation_id,
            whir_param_digest,
            zk_status,
            &components,
        )
        .expect("N3 committed-private manifest membership proof");
        N3Fixture {
            pk,
            vk,
            proof_relation_id,
            whir_param_digest,
            components,
            proof,
        }
    }

    fn verify_n3_fixture(
        fixture: &N3Fixture,
        proof: &Symbt3CommittedPrivateManifestMembershipProof,
    ) -> Symbt3CommittedPrivateManifestVerifyReport {
        verify_committed_private_manifest_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.whir_param_digest,
            proof,
        )
    }

    fn flatten_n3_components(
        components: &[Symbt3ManifestSourceComponentValues],
    ) -> (Vec<BabyBear>, Vec<BabyBear>) {
        let mut manifest_evals = Vec::new();
        let mut source_evals = Vec::new();
        for component in components {
            manifest_evals.extend_from_slice(&component.manifest_values);
            source_evals.extend_from_slice(&component.source_values);
        }
        (manifest_evals, source_evals)
    }

    fn low_level_n3_membership_proof_with_statement(
        pk: &WhirProvingKey,
        proof_relation_id: Digest32,
        whir_param_digest: Digest32,
        public_statement: &Symbt3CommittedPrivateManifestPublicStatement,
        manifest_evals: &[BabyBear],
        source_evals: &[BabyBear],
    ) -> NativeManifestSourceMembershipProof {
        let manifest_num_vars = num_vars_for_evals(manifest_evals).expect("manifest num vars");
        let source_num_vars = num_vars_for_evals(source_evals).expect("source num vars");
        let specs = build_n2_native_manifest_source_oracle_specs(
            public_statement.manifest_layout_digest,
            public_statement.source_layout_digest,
            manifest_num_vars,
            source_num_vars,
            public_statement.batch_manifest_root,
            public_statement.root_policy,
        )
        .expect("N3 native specs");
        let native_proof = whir_commit_and_prove_oracles_with_root_policy(
            pk,
            public_statement.root_policy,
            proof_relation_id,
            public_statement.digest(),
            whir_param_digest,
            &specs,
            &[manifest_evals.to_vec(), source_evals.to_vec()],
            &native_manifest_source_membership_eval_requests(),
        )
        .expect("N3 low-level native proof");
        NativeManifestSourceMembershipProof {
            batch_manifest_root: public_statement.batch_manifest_root,
            native_proof,
        }
    }

    struct N4Fixture {
        pk: WhirProvingKey,
        vk: WhirVerifyingKey,
        proof_relation_id: Digest32,
        public_statement_digest: Digest32,
        whir_param_digest: Digest32,
        challenge_context: Symbt3NativeRoundChallengeContext,
        batch_log_size: usize,
        round_layouts: Vec<Symbt3NativeRoundMessageOracleLayoutV1>,
        message_evals: Vec<Vec<BabyBear>>,
        proof: Symbt3NativeRoundMessageOracleProof,
    }

    fn n4_batch_size(batch_log_size: usize) -> u64 {
        1u64 << batch_log_size
    }

    fn n4_context(
        folded_output_digest: Digest32,
        batch_log_size: usize,
    ) -> Symbt3NativeRoundChallengeContext {
        Symbt3NativeRoundChallengeContext {
            folding_protocol_id: digest(b"n4-folding-protocol"),
            input_public_boundary_digest: digest(b"n4-input-public-boundary"),
            batch_manifest_root: digest(b"n4-batch-manifest-root"),
            source_roots_digest: digest(b"n4-source-roots"),
            active_count: 7,
            batch_size: n4_batch_size(batch_log_size),
            folded_output_digest,
        }
    }

    fn n4_layouts(
        round_count: usize,
        batch_log_size: usize,
    ) -> Vec<Symbt3NativeRoundMessageOracleLayoutV1> {
        (0..round_count)
            .map(|round| {
                let message_axis_log_size = if round % 2 == 0 { 1 } else { 2 };
                Symbt3NativeRoundMessageOracleLayoutV1 {
                    round_index: round as u32,
                    oracle_id: SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + round as u32,
                    batch_axis_log_size: batch_log_size,
                    message_axis_log_size,
                    total_num_vars: batch_log_size + message_axis_log_size,
                    layout_digest: digest(format!("n4-round-layout-{round}").as_bytes()),
                    section_layout_digest: digest(format!("n4-section-layout-{round}").as_bytes()),
                    view_map_digest: digest(format!("n4-view-map-{round}").as_bytes()),
                }
            })
            .collect()
    }

    fn n4_message_evals(
        round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
    ) -> Vec<Vec<BabyBear>> {
        round_layouts
            .iter()
            .map(|layout| {
                let len = 1usize << layout.total_num_vars;
                (0..len)
                    .map(|i| {
                        BabyBear::from_u32(
                            ((layout.round_index as usize * 37 + i * 13 + 5) % 251) as u32,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn n4_fixture(round_count: usize) -> N4Fixture {
        n4_fixture_with_batch_log_size(round_count, 1)
    }

    fn n4_fixture_with_batch_log_size(round_count: usize, batch_log_size: usize) -> N4Fixture {
        let (pk, vk) = WhirSnark::setup(&relation());
        let proof_relation_id = digest(b"n4-proof-relation");
        let public_statement_digest = digest(b"n4-public-statement");
        let whir_param_digest = digest(b"n4-whir-params");
        let challenge_context = n4_context(digest(b"n4-folded-output"), batch_log_size);
        let round_layouts = n4_layouts(round_count, batch_log_size);
        let message_evals = n4_message_evals(&round_layouts);
        let proof = prove_native_round_message_oracle_views(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &challenge_context,
            batch_log_size,
            &round_layouts,
            &message_evals,
            &native_round_message_view_eval_requests(&round_layouts),
        )
        .expect("N4 native round-message proof");
        N4Fixture {
            pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            challenge_context,
            batch_log_size,
            round_layouts,
            message_evals,
            proof,
        }
    }

    fn verify_n4_fixture(
        fixture: &N4Fixture,
        proof: &Symbt3NativeRoundMessageOracleProof,
    ) -> Symbt3NativeRoundMessageOracleVerifyReport {
        verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            proof.message_oracle_roots_digest,
            proof.message_round_layouts_digest,
            proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            proof,
        )
    }

    fn low_level_n4_proof_with_root_policy(
        pk: &WhirProvingKey,
        proof_relation_id: Digest32,
        public_statement_digest: Digest32,
        whir_param_digest: Digest32,
        challenge_context: &Symbt3NativeRoundChallengeContext,
        batch_log_size: usize,
        round_layouts: &[Symbt3NativeRoundMessageOracleLayoutV1],
        message_evals: &[Vec<BabyBear>],
        root_policy: NativeOracleRootPolicy,
    ) -> Symbt3NativeRoundMessageOracleProof {
        let specs =
            build_native_message_oracle_specs(round_layouts, batch_log_size).expect("N4 specs");
        let native_proof = whir_commit_and_prove_oracles_with_root_policy(
            pk,
            root_policy,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &specs,
            message_evals,
            &native_round_message_view_eval_requests(round_layouts),
        )
        .expect("N4 low-level native proof");
        let message_oracle_policy = Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1;
        let round_challenges = derive_native_round_challenges(
            &native_proof.descriptors,
            round_layouts,
            challenge_context,
        )
        .expect("round challenges");
        Symbt3NativeRoundMessageOracleProof {
            message_oracle_policy,
            message_oracle_roots_digest: native_message_roots_digest(&native_proof.descriptors),
            message_round_layouts_digest: native_message_round_layouts_digest(round_layouts),
            message_oracle_policy_digest: symbt3_message_oracle_policy_digest(
                message_oracle_policy,
            ),
            round_challenges,
            native_proof,
        }
    }

    fn n4_round_challenge_for(fixture: &N4Fixture, roots: &[Digest32], round: usize) -> BabyBear {
        derive_native_round_challenge(
            fixture.round_layouts[round].round_index,
            &roots[..=round],
            fixture.round_layouts[round].layout_digest,
            &fixture.challenge_context,
        )
    }

    fn n5_valid_metadata() -> Symbt3NonZkFoldingIntegrityProfileMetadata {
        let n3 = n3_fixture();
        let n3_report = verify_n3_fixture(&n3, &n3.proof);
        assert!(n3_report.ok);

        let n4 = n4_fixture_with_batch_log_size(2, 2);
        let n4_report = verify_n4_fixture(&n4, &n4.proof);
        assert!(n4_report.ok);

        Symbt3NonZkFoldingIntegrityProfileMetadata {
            native_profile: Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1),
            manifest_policy: Some(n3.proof.public_statement.manifest_policy),
            source_policy: Some(n3.proof.public_statement.source_policy),
            message_oracle_policy: Some(n4.proof.message_oracle_policy),
            root_policy: NativeOracleRootPolicy::CanonicalWhirRootV1,
            zk_status: n3.proof.public_statement.zk_status,
            committed_private_component_count: n3_report.committed_private_component_count,
            manifest_source_native_oracle_count: n3_report
                .native_report
                .counters
                .native_oracle_count,
            manifest_source_native_pcs_opening_count: n3_report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            native_message_round_count: n4_report.native_message_round_count,
            native_message_oracle_count: n4_report.native_report.counters.native_oracle_count,
            native_message_pcs_opening_count: n4_report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            batch_size: n4.challenge_context.batch_size as usize,
            batch_axis_log_size: n4.batch_log_size,
            message_round_layouts: n4.round_layouts,
            logical_native_envelope_count: 1,
            top_level_whir_proof_count: 1,
            family_columnar_subproof_count: 0,
            message_to_trace_binding_count: n4_report.message_to_trace_binding_count,
            semantic_profile_version: SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION,
            required_semantic_families: Symbt3FoldingIntegritySemanticFamilies::production_non_zk(),
            k5_masking_available: false,
            monolithic_fallback: false,
            product_default_route_attempted: false,
            product_eligible: false,
            native_product_route_version_exists: false,
        }
    }

    fn n5_report(
        metadata: &Symbt3NonZkFoldingIntegrityProfileMetadata,
    ) -> Symbt3NonZkFoldingIntegrityProfileReport {
        symbt3_non_zk_folding_integrity_profile_report(metadata)
    }

    struct N6aFixture {
        vk: WhirVerifyingKey,
        instance: Symbt3NativeFoldingIntegrityInstance,
        proof: Symbt3NativeFoldingIntegrityProof,
    }

    struct N6bFixture {
        vk: WhirVerifyingKey,
        public_profile: Symbt3NativeFoldingIntegrityPublicProfile,
        instance: Symbt3NativeFoldingIntegrityInstance,
        proof: Symbt3NativeFoldingIntegrityProof,
    }

    fn n6a_instance_witness(
        batch_log_size: usize,
        round_count: usize,
    ) -> (
        Symbt3NativeFoldingIntegrityInstance,
        Symbt3NativeFoldingIntegrityWitness,
    ) {
        let components = n3_components();
        let prepared =
            prepare_committed_private_manifest_witness(&components).expect("N6a manifest witness");
        let round_layouts = n4_layouts(round_count, batch_log_size);
        let witness = Symbt3NativeFoldingIntegrityWitness {
            main_witness: vec![11, 13, 17, 19, batch_log_size as u8, round_count as u8],
            manifest_evals: prepared.manifest_evals,
            source_evals: prepared.source_evals,
            message_oracle_evaluations: n4_message_evals(&round_layouts),
        };
        let batch_size = 1u64 << batch_log_size;
        let instance = Symbt3NativeFoldingIntegrityInstance {
            native_profile: Some(Symbt3NativeOracleProfile::NonZkFoldingIntegrityV1),
            manifest_policy: ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
            source_policy: SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            message_oracle_policy: Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            root_policy: NativeOracleRootPolicy::CanonicalWhirRootV1,
            zk_status: Symbt3ZkStatus::NonZkIntegrityOnly,
            symbt3_relation_id: digest(b"n6a-symbt3-relation"),
            whir_param_digest: digest(b"n6a-whir-params"),
            manifest_layout_digest: prepared.manifest_layout_digest,
            source_layout_digest: prepared.source_layout_digest,
            source_column_layout_digest: digest(b"n6a-source-column-layout"),
            folding_protocol_id: digest(b"n6a-folding-protocol"),
            input_public_boundary_digest: digest(b"n6a-input-public-boundary"),
            source_roots_digest: digest(b"n6a-source-roots"),
            active_count: batch_size,
            batch_size,
            folded_output_digest: digest(b"n6a-folded-output"),
            batch_axis_log_size: batch_log_size,
            round_layouts,
            committed_private_component_count: prepared.committed_private_component_count,
            semantic_profile_version: SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION,
            required_semantic_families: Symbt3FoldingIntegritySemanticFamilies::production_non_zk(),
            k5_masking_available: false,
            monolithic_fallback: false,
            product_default_route_attempted: false,
            product_eligible: false,
            native_product_route_version_exists: false,
            backend_table_count: 1,
            accumulator_transition_claims: 1,
            main_instance: vec![3, 5, 7, 9, batch_log_size as u8, round_count as u8],
        };
        (instance, witness)
    }

    fn n6a_fixture(batch_log_size: usize, round_count: usize) -> N6aFixture {
        let (pk, vk) = WhirSnark::setup(&relation());
        let (instance, witness) = n6a_instance_witness(batch_log_size, round_count);
        let proof = prove_symbt3_native_folding_integrity_non_zk(&pk, &instance, &witness)
            .expect("N6a native folding-integrity proof");
        N6aFixture {
            vk,
            instance,
            proof,
        }
    }

    fn verify_n6a_fixture(
        fixture: &N6aFixture,
        instance: &Symbt3NativeFoldingIntegrityInstance,
        proof: &Symbt3NativeFoldingIntegrityProof,
    ) -> bool {
        verify_symbt3_native_folding_integrity_non_zk(&fixture.vk, instance, proof)
    }

    fn n6b_public_profile() -> Symbt3NativeFoldingIntegrityPublicProfile {
        Symbt3NativeFoldingIntegrityPublicProfile::explicit_non_zk()
    }

    fn n6b_fixture(batch_log_size: usize, round_count: usize) -> N6bFixture {
        let (pk, vk) = WhirSnark::setup(&relation());
        let (instance, witness) = n6a_instance_witness(batch_log_size, round_count);
        let public_profile = n6b_public_profile();
        let proof = prove_public_symbt3_native_folding_integrity_non_zk(
            &pk,
            &public_profile,
            &instance,
            &witness,
        )
        .expect("N6b public native folding-integrity proof");
        N6bFixture {
            vk,
            public_profile,
            instance,
            proof,
        }
    }

    fn verify_n6b_fixture(
        fixture: &N6bFixture,
        public_profile: &Symbt3NativeFoldingIntegrityPublicProfile,
        instance: &Symbt3NativeFoldingIntegrityInstance,
        proof: &Symbt3NativeFoldingIntegrityProof,
    ) -> bool {
        verify_public_symbt3_native_folding_integrity_non_zk(
            &fixture.vk,
            public_profile,
            instance,
            proof,
        )
    }

    struct N7Fixture {
        vk: WhirVerifyingKey,
        instance: Symbt3NativeFoldingIntegrityInstance,
        proof: Symbt3NativeAccumulatorAuthorityProof,
    }

    struct K6aAdapterFixture {
        pk: WhirProvingKey,
        vk: WhirVerifyingKey,
        profile: Symbt3AuthorityProfile,
        accumulator_instance: Symbt3AccumulatorInstance,
        accumulator_witness: Symbt3AccumulatorWitness,
        proof: WhirProof,
        adapter: Symbt3NativeAccumulatorK6aWorkloadAdapter,
    }

    fn k6a_params() -> SymphonyParams {
        SymphonyParams {
            q: 257,
            d: D,
            kappa: 1,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(257, D),
        }
    }

    fn k6a_r1cs() -> (R1CSMatrices, Vec<i64>) {
        let mut r1cs = R1CSMatrices::new(4, 4, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 3, 1);
        r1cs.a.insert(1, 1, 1);
        r1cs.b.insert(1, 0, 1);
        r1cs.c.insert(1, 1, 1);
        (r1cs, vec![1, 3, 5, 15])
    }

    fn k6a_statement(
        prover: &Prover<SumcheckSnark, SumcheckSnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z
                .iter()
                .map(|&value| RingElement::from_constant(value))
                .collect(),
        };
        let (commitment, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&value| RingElement::from_constant(value))
                .collect(),
        };
        (commitment, z[..n_in].to_vec(), witness_part)
    }

    fn k6a_batched_item(
        prover: &Prover<SumcheckSnark, SumcheckSnark>,
        r1cs: &R1CSMatrices,
        z: &[i64],
        tag: u8,
    ) -> BatchedCpItem {
        let statements = vec![
            k6a_statement(prover, z, r1cs.num_public),
            k6a_statement(prover, z, r1cs.num_public),
        ];
        let public_inputs = statements
            .iter()
            .map(|(_, public_input, _)| public_input.clone())
            .collect::<Vec<_>>();
        let proof: ProofBundle<SumcheckSnark, SumcheckSnark> = prover.prove(&statements, r1cs);
        let public = CpPublicStatement::new(
            proof.cp_public_instance.clone(),
            public_inputs,
            r1cs,
            PublicDigestScheme::Sha256,
        );
        BatchedCpItem {
            item_tag: [tag; 32],
            public,
            witness: proof.witness_bundle,
        }
    }

    fn k6a_adapter_fixture() -> K6aAdapterFixture {
        k6a_adapter_fixture_with_batch_size(1)
    }

    fn k6a_adapter_fixture_with_batch_size(batch_size: usize) -> K6aAdapterFixture {
        let params = k6a_params();
        let (prover, _) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
        let (r1cs, z) = k6a_r1cs();
        let items = (0..batch_size)
            .map(|idx| k6a_batched_item(&prover, &r1cs, &z, idx as u8 + 1))
            .collect::<Vec<_>>();
        let bucket = BatchedCpBucket::new(items, digest(b"k6a-native-adapter-whir-params"))
            .expect("K6a adapter bucket");
        let descriptor = BatchedCpSymbt3SetupDescriptor::new(
            bucket.shape.clone(),
            &prover.ajtai,
            &r1cs,
            prover.params.b_input(),
        );
        let relation =
            <WhirSnark as crate::cp_backend_api::CpBackend>::symbt3_relation_description(
                &descriptor,
            )
            .expect("WHIR exposes SYMBT3 relation");
        let decoded_relation = BatchedCpSymbt3RelationDescription::from_context_bytes(
            relation.context.as_ref().unwrap(),
        )
        .expect("SYMBT3 relation context decodes");
        let (pk, vk) = <WhirSnark as crate::cp_backend_api::CpBackend>::setup(&relation);
        let public = bucket.symbt3_public_statement_for_relation(&decoded_relation);
        let witness = bucket.symbt3_witness_for_relation(&decoded_relation);
        let profile =
            Symbt3AuthorityProfile::accumulator_non_zk_integrity_product_authority_from_relation(
                &decoded_relation,
                64,
            );
        let profile_digest = profile.digest(bucket.shape.accumulator_shape.digest_scheme);
        let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
            bucket.shape.accumulator_shape.digest_scheme,
            profile_digest,
            public.old_accumulator_digest,
            public.new_accumulator_digest,
            &public,
        );
        let accumulator_witness =
            Symbt3AccumulatorWitness::from_symbt3_witness(&decoded_relation, &witness);
        let (proof, adapter) = prove_symbt3_native_accumulator_k6a_workload_adapter(
            &pk,
            &profile,
            &accumulator_instance,
            &accumulator_witness,
        )
        .expect("K6a native workload adapter proof");
        K6aAdapterFixture {
            pk,
            vk,
            profile,
            accumulator_instance,
            accumulator_witness,
            proof,
            adapter,
        }
    }

    fn k6a_compatible_n7b_tuple_leaf_parts(
        adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    ) -> (WhirVerifyingKey, Symbt3N7bNativeTupleLeafProofParts) {
        k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
            adapter,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT,
            SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS,
        )
    }

    fn k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
        adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
        rlc_repetition_count: usize,
        rlc_batching_bits_per_repetition: usize,
    ) -> (WhirVerifyingKey, Symbt3N7bNativeTupleLeafProofParts) {
        let (pk, vk) = WhirSnark::setup(&relation());
        let num_vars = 1;
        let opening_schedule = WhirNativeOpeningSchedule::TranscriptDerived {
            domain_separator: SYMBT3_N7_TUPLE_LEAF_OPENING_DOMAIN,
        };
        let specs = vec![
            WhirNativeOracleSpec {
                version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                oracle_id: SYMBT3_N2_MANIFEST_ORACLE_ID,
                role: WhirNativeOracleRole::Manifest,
                layout_digest: digest(b"n7b-full-manifest-layout"),
                num_vars,
                opening_schedule: opening_schedule.clone(),
            },
            WhirNativeOracleSpec {
                version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                oracle_id: SYMBT3_N2_SOURCE_ORACLE_ID,
                role: WhirNativeOracleRole::Source,
                layout_digest: digest(b"n7b-full-source-layout"),
                num_vars,
                opening_schedule: opening_schedule.clone(),
            },
            WhirNativeOracleSpec {
                version: WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION,
                oracle_id: SYMBT3_N4_MESSAGE_ORACLE_ID_BASE,
                role: WhirNativeOracleRole::MessageRound { round: 0 },
                layout_digest: digest(b"n7b-full-message-layout"),
                num_vars,
                opening_schedule,
            },
        ];
        let evaluations = vec![
            vec![BabyBear::from_u32(3), BabyBear::from_u32(5)],
            vec![BabyBear::from_u32(3), BabyBear::from_u32(7)],
            vec![BabyBear::from_u32(11), BabyBear::from_u32(13)],
        ];
        let eval_requests = specs
            .iter()
            .map(|spec| WhirNativeEvalRequest {
                oracle_id: spec.oracle_id,
                claim_kind: WhirNativeEvalClaimKind::DirectOpening,
            })
            .collect::<Vec<_>>();
        let proof = whir_commit_and_prove_same_domain_multi_oracle_with_repetitions(
            &pk,
            adapter.main_symbt3_relation_id,
            adapter.public_statement_digest,
            adapter.whir_param_digest,
            &specs,
            &evaluations,
            &eval_requests,
            rlc_repetition_count,
            rlc_batching_bits_per_repetition,
        )
        .expect("K6a-compatible tuple-leaf proof");
        let manifest_oracle_root = adapter.manifest_oracle_root;
        let source_oracle_root = digest(b"n7b-full-source-oracle-root");
        let message_oracle_root = digest(b"n7b-full-message-oracle-root");
        let descriptors = specs
            .iter()
            .zip([
                manifest_oracle_root,
                source_oracle_root,
                message_oracle_root,
            ])
            .map(|(spec, root)| spec.descriptor_with_root(root))
            .collect::<Vec<_>>();
        (
            vk,
            Symbt3N7bNativeTupleLeafProofParts {
                proof,
                native_oracle_descriptor_digest: native_oracle_descriptor_digest(&descriptors),
                native_message_roots_digest: adapter.native_message_roots_digest,
                manifest_oracle_root,
                source_oracle_root,
            },
        )
    }

    fn n7_instance_witness(
        batch_log_size: usize,
        round_count: usize,
    ) -> (
        Symbt3NativeFoldingIntegrityInstance,
        Symbt3NativeFoldingIntegrityWitness,
    ) {
        let (mut instance, witness) = n6a_instance_witness(batch_log_size, round_count);
        instance.semantic_profile_version =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_MIN_SEMANTIC_PROFILE_VERSION;
        (instance, witness)
    }

    fn n7_fixture(batch_log_size: usize, round_count: usize) -> N7Fixture {
        let (pk, vk) = WhirSnark::setup(&relation());
        let (instance, witness) = n7_instance_witness(batch_log_size, round_count);
        let proof = prove_symbt3_native_accumulator_authority_non_zk(&pk, &instance, &witness)
            .expect("N7 native accumulator authority proof");
        N7Fixture {
            vk,
            instance,
            proof,
        }
    }

    fn verify_n7_fixture(
        fixture: &N7Fixture,
        instance: &Symbt3NativeFoldingIntegrityInstance,
        proof: &Symbt3NativeAccumulatorAuthorityProof,
    ) -> bool {
        verify_symbt3_native_accumulator_authority_non_zk(&fixture.vk, instance, proof)
    }

    #[test]
    fn native_oracle_two_oracle_roundtrip_and_counters() {
        let (
            _pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            _specs,
            _evals,
            _requests,
            proof,
        ) = native_oracle_fixture();

        let report = whir_verify_oracle_openings_with_counters(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &proof.descriptors,
            &proof,
            &proof.eval_claims,
        );
        assert!(report.ok);
        assert_eq!(proof.top_level_whir_proof_count(), 1);
        assert_eq!(proof.family_columnar_subproof_count(), 0);
        assert_eq!(proof.native_oracle_pcs_opening_count(), 2);
        assert_eq!(report.counters.native_oracle_count, 2);
        assert_eq!(report.counters.native_oracle_eval_claim_count, 2);
        assert_eq!(report.counters.native_oracle_pcs_opening_count, 2);
        assert_eq!(
            proof.root_policy,
            NativeOracleRootPolicy::CanonicalWhirRootV1
        );
        assert!(report.counters.native_oracle_descriptor_bytes > 0);
        assert!(report.native_oracle_verify_ms >= 0.0);
        assert_eq!(
            proof.native_oracle_descriptor_digest,
            native_oracle_descriptor_digest(&proof.descriptors)
        );
        assert_eq!(
            proof.native_oracle_eval_claims_digest,
            native_oracle_eval_claims_digest(&proof.eval_claims)
        );
        assert_eq!(
            proof.native_multi_oracle_envelope_digest,
            native_multi_oracle_envelope_digest(&proof)
        );
    }

    #[test]
    fn symbt3_native_oracle_manifest_source_equality_smoke() {
        let (
            _pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            _specs,
            _evals,
            _requests,
            proof,
        ) = native_oracle_fixture();

        assert!(verify_fixture(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &proof
        ));
        assert_eq!(proof.eval_claims.len(), 2);
        assert_eq!(proof.descriptors[0].role, WhirNativeOracleRole::Manifest);
        assert_eq!(proof.descriptors[1].role, WhirNativeOracleRole::Source);
        assert_eq!(
            proof.eval_claims[0].claim_kind,
            WhirNativeEvalClaimKind::EqualitySide
        );
        assert_eq!(
            proof.eval_claims[1].claim_kind,
            WhirNativeEvalClaimKind::EqualitySide
        );
        assert_eq!(proof.eval_claims[0].value, proof.eval_claims[1].value);
    }

    #[test]
    fn symbt3_n2_native_manifest_source_membership_roundtrip_and_counters() {
        let fixture = n2_fixture();
        let report = verify_n2_fixture(&fixture, &fixture.proof);
        assert!(report.ok);
        assert_eq!(
            fixture.proof.native_proof.root_policy,
            NativeOracleRootPolicy::CanonicalWhirRootV1
        );
        assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
        assert_eq!(
            fixture.proof.native_proof.family_columnar_subproof_count(),
            0
        );
        assert_eq!(
            fixture.proof.native_proof.native_oracle_pcs_opening_count(),
            2
        );
        assert_eq!(report.counters.native_oracle_count, 2);
        assert_eq!(report.counters.native_oracle_eval_claim_count, 2);
        assert_eq!(report.counters.native_oracle_opening_count, 2);
        assert_eq!(report.counters.native_oracle_pcs_opening_count, 2);
        assert!(report.counters.native_oracle_descriptor_bytes > 0);
        assert!(report.native_oracle_verify_ms >= 0.0);
        assert_eq!(
            fixture.proof.batch_manifest_root,
            native_batch_manifest_root(
                fixture.manifest_layout_digest,
                fixture.proof.native_proof.descriptors[0].root,
                native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
            )
        );
        assert_eq!(
            fixture.proof.native_proof.eval_claims[0].claim_kind,
            WhirNativeEvalClaimKind::EqualitySide
        );
        assert_eq!(
            fixture.proof.native_proof.eval_claims[1].claim_kind,
            WhirNativeEvalClaimKind::EqualitySide
        );
        assert_eq!(
            fixture.proof.native_proof.eval_claims[0].point_digest,
            fixture.proof.native_proof.eval_claims[1].point_digest
        );
        assert_eq!(
            fixture.proof.native_proof.eval_claims[0].value,
            fixture.proof.native_proof.eval_claims[1].value
        );
    }

    #[test]
    fn symbt3_n2_build_specs_rejects_num_vars_mismatch() {
        let fixture = n2_fixture();
        assert!(build_n2_native_manifest_source_oracle_specs(
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            2,
            3,
            fixture.proof.batch_manifest_root,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
        )
        .is_none());
        assert!(prove_native_manifest_source_membership(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            &fixture.manifest_evals,
            &[
                BabyBear::from_u32(3),
                BabyBear::from_u32(5),
                BabyBear::from_u32(8),
                BabyBear::from_u32(13),
                BabyBear::from_u32(21),
                BabyBear::from_u32(34),
                BabyBear::from_u32(55),
                BabyBear::from_u32(89),
            ],
        )
        .is_none());
    }

    #[test]
    fn symbt3_n2_unequal_manifest_source_eval_rejects() {
        let honest = n2_fixture();
        let unequal_source = honest
            .manifest_evals
            .iter()
            .map(|&value| value + BabyBear::ONE)
            .collect::<Vec<_>>();
        assert!(prove_native_manifest_source_membership(
            &honest.pk,
            honest.proof_relation_id,
            honest.public_statement_digest,
            honest.whir_param_digest,
            honest.manifest_layout_digest,
            honest.source_layout_digest,
            &honest.manifest_evals,
            &unequal_source,
        )
        .is_none());

        let fixture = n2_fixture_with_source_and_policy(
            Some(unequal_source),
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            false,
        );
        assert_ne!(
            fixture.proof.native_proof.eval_claims[0].value,
            fixture.proof.native_proof.eval_claims[1].value
        );
        assert!(!verify_n2_fixture(&fixture, &fixture.proof).ok);
    }

    #[test]
    fn symbt3_n2_manifest_root_swap_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[0].root = digest(b"wrong-n2-manifest-root");
        proof.batch_manifest_root = native_batch_manifest_root(
            fixture.manifest_layout_digest,
            proof.native_proof.descriptors[0].root,
            native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
        );
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_source_root_swap_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[1].root = digest(b"wrong-n2-source-root");
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_oracle_id_swap_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[0].oracle_id = SYMBT3_N2_SOURCE_ORACLE_ID;
        proof.native_proof.descriptors[1].oracle_id = SYMBT3_N2_MANIFEST_ORACLE_ID;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_role_swap_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[0].role = WhirNativeOracleRole::Source;
        proof.native_proof.descriptors[1].role = WhirNativeOracleRole::Manifest;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_layout_digest_swap_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[0].layout_digest = fixture.source_layout_digest;
        proof.native_proof.descriptors[1].layout_digest = fixture.manifest_layout_digest;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_num_vars_mismatch_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[1].num_vars += 1;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_debug_root_policy_rejects() {
        let fixture = n2_fixture_with_source_and_policy(
            None,
            NativeOracleRootPolicy::DebugDevelopmentOnly,
            false,
        );
        let report = verify_native_manifest_source_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            fixture.proof.batch_manifest_root,
            ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            NativeOracleRootPolicy::DebugDevelopmentOnly,
            &fixture.proof.native_proof.descriptors,
            &fixture.proof.native_proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n2_public_canonical_policy_rejects() {
        let fixture = n2_fixture();
        let report = verify_native_manifest_source_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            fixture.proof.batch_manifest_root,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof.native_proof.descriptors,
            &fixture.proof.native_proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n2_batch_manifest_root_mismatch_rejects() {
        let fixture = n2_fixture();
        assert!(
            !verify_n2_fixture_with_batch(
                &fixture,
                digest(b"wrong-n2-batch-manifest-root"),
                &fixture.proof.native_proof,
            )
            .ok
        );
    }

    #[test]
    fn symbt3_n2_stale_public_statement_digest_rejects() {
        let fixture = n2_fixture();
        let report = verify_native_manifest_source_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            digest(b"changed-n2-public-statement"),
            fixture.whir_param_digest,
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            fixture.proof.batch_manifest_root,
            ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof.native_proof.descriptors,
            &fixture.proof.native_proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n2_stale_whir_param_digest_rejects() {
        let fixture = n2_fixture();
        let report = verify_native_manifest_source_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            digest(b"changed-n2-whir-params"),
            fixture.manifest_layout_digest,
            fixture.source_layout_digest,
            fixture.proof.batch_manifest_root,
            ManifestCommitmentPolicy::NativeManifestOracleOpeningV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof.native_proof.descriptors,
            &fixture.proof.native_proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n2_descriptors_out_of_order_reject() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors.reverse();
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_duplicate_oracle_id_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[1].oracle_id = proof.native_proof.descriptors[0].oracle_id;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_extra_oracle_descriptor_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        let mut extra = proof.native_proof.descriptors[1].clone();
        extra.oracle_id = 3;
        proof.native_proof.descriptors.push(extra);
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_missing_oracle_descriptor_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors.pop();
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_wrong_claim_kind_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].claim_kind = WhirNativeEvalClaimKind::ManifestView;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_point_digest_mutation_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].point_digest = digest(b"wrong-n2-point");
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n2_value_mutation_rejects() {
        let fixture = n2_fixture();
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_n2_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_committed_private_manifest_membership_roundtrip_and_counters() {
        let fixture = n3_fixture();
        let report = verify_n3_fixture(&fixture, &fixture.proof);
        assert!(report.ok);
        assert_eq!(
            fixture.proof.public_statement.manifest_policy,
            ManifestCommitmentPolicy::NativeManifestOracleOpeningV1
        );
        assert_eq!(
            fixture.proof.public_statement.source_policy,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1
        );
        assert_eq!(
            fixture.proof.public_statement.zk_status,
            Symbt3ZkStatus::NonZkIntegrityOnly
        );
        assert_eq!(report.committed_private_component_count, 1);
        assert_eq!(report.committed_private_public_bytes, 0);
        assert!(report.public_statement_bytes > 0);
        assert_eq!(report.native_report.counters.native_oracle_count, 2);
        assert_eq!(
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            2
        );
        assert_eq!(
            fixture
                .proof
                .membership_proof
                .native_proof
                .top_level_whir_proof_count(),
            1
        );
        assert_eq!(
            fixture
                .proof
                .membership_proof
                .native_proof
                .family_columnar_subproof_count(),
            0
        );
        assert_eq!(
            fixture.proof.membership_proof.native_proof.eval_claims[0].value,
            fixture.proof.membership_proof.native_proof.eval_claims[1].value
        );
        assert_eq!(
            fixture.proof.public_statement.batch_manifest_root,
            native_batch_manifest_root(
                fixture.proof.public_statement.manifest_layout_digest,
                fixture.proof.public_statement.manifest_oracle_root,
                native_oracle_root_policy_digest(NativeOracleRootPolicy::CanonicalWhirRootV1),
            )
        );
    }

    #[test]
    fn symbt3_n3_public_boundary_excludes_committed_private_values() {
        let fixture = n3_fixture();
        let statement = &fixture.proof.public_statement;
        let private_component = &fixture.components[1];
        let mut private_value_bytes = Vec::new();
        push_babybear_vec(&mut private_value_bytes, &private_component.manifest_values);
        push_babybear_vec(&mut private_value_bytes, &private_component.source_values);

        assert_eq!(statement.committed_private_public_bytes(), 0);
        assert!(statement.components[1].public_manifest_values.is_empty());
        assert!(statement.components[1].public_source_values.is_empty());
        assert!(!statement
            .canonical_bytes()
            .windows(private_value_bytes.len())
            .any(|window| window == private_value_bytes.as_slice()));
        assert_eq!(
            statement.components[0].public_manifest_values,
            fixture.components[0].manifest_values
        );
    }

    #[test]
    fn symbt3_n3_explicit_nonzk_research_policy_verifies() {
        let fixture =
            n3_fixture_with_components(n3_components(), Symbt3ZkStatus::ExplicitNonZkResearch);
        assert!(verify_n3_fixture(&fixture, &fixture.proof).ok);
    }

    #[test]
    fn symbt3_n3_public_canonical_manifest_policy_rejects_committed_private() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.manifest_policy =
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_zk_required_profile_rejects_without_k5() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.zk_status = Symbt3ZkStatus::ZkRequired;
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
        assert!(prove_committed_private_manifest_membership(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.whir_param_digest,
            Symbt3ZkStatus::ZkRequired,
            &fixture.components,
        )
        .is_none());
    }

    #[test]
    fn symbt3_n3_mutating_committed_private_manifest_value_rejects() {
        let fixture = n3_fixture();
        let mut components = fixture.components.clone();
        components[1].manifest_values[0] += BabyBear::ONE;
        let (manifest_evals, source_evals) = flatten_n3_components(&components);
        let membership_proof = low_level_n3_membership_proof_with_statement(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.whir_param_digest,
            &fixture.proof.public_statement,
            &manifest_evals,
            &source_evals,
        );
        let proof = Symbt3CommittedPrivateManifestMembershipProof {
            public_statement: fixture.proof.public_statement.clone(),
            membership_proof,
        };
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_mutating_committed_private_source_value_rejects() {
        let fixture = n3_fixture();
        let mut components = fixture.components.clone();
        components[1].source_values[1] += BabyBear::ONE;
        let (manifest_evals, source_evals) = flatten_n3_components(&components);
        let membership_proof = low_level_n3_membership_proof_with_statement(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.whir_param_digest,
            &fixture.proof.public_statement,
            &manifest_evals,
            &source_evals,
        );
        let proof = Symbt3CommittedPrivateManifestMembershipProof {
            public_statement: fixture.proof.public_statement.clone(),
            membership_proof,
        };
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_committed_private_component_layout_digest_mutation_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.components[1].layout_digest = digest(b"wrong-n3-private-layout");
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_stale_private_component_root_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.components[1].manifest_component_root =
            digest(b"wrong-n3-private-component-root");
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_debug_root_policy_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_num_vars_mismatch_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.membership_proof.native_proof.descriptors[1].num_vars += 1;
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_wrong_visibility_tag_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.components[1].visibility = Symbt3ManifestVisibility::PublicBoundary;
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_wrong_component_kind_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.components[1].kind = Symbt3ManifestComponentKind::Auxiliary(99);
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_wrong_component_order_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.public_statement.components.reverse();
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_stale_public_statement_digest_rejects() {
        let fixture = n3_fixture();
        let mut proof = fixture.proof.clone();
        proof.membership_proof.native_proof.public_statement_digest =
            digest(b"changed-n3-public-statement-digest");
        assert!(!verify_n3_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n3_stale_whir_param_digest_rejects() {
        let fixture = n3_fixture();
        let report = verify_committed_private_manifest_membership(
            &fixture.vk,
            fixture.proof_relation_id,
            digest(b"changed-n3-whir-params"),
            &fixture.proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4_one_round_message_oracle_verifies() {
        let fixture = n4_fixture(1);
        let report = verify_n4_fixture(&fixture, &fixture.proof);
        assert!(report.ok);
        assert_eq!(report.native_message_round_count, 1);
        assert_eq!(report.native_report.counters.native_oracle_count, 1);
        assert_eq!(
            report.native_report.counters.native_oracle_eval_claim_count,
            1
        );
        assert_eq!(
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            1
        );
        assert_eq!(report.message_to_trace_binding_count, 0);
        assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
        assert_eq!(
            fixture.proof.native_proof.family_columnar_subproof_count(),
            0
        );
        assert_eq!(
            fixture.proof.native_proof.eval_claims[0].claim_kind,
            WhirNativeEvalClaimKind::MessageView
        );
    }

    #[test]
    fn symbt3_n4_two_round_message_oracles_verify_with_counters() {
        let fixture = n4_fixture(2);
        let report = verify_n4_fixture(&fixture, &fixture.proof);
        assert!(report.ok);
        assert_eq!(report.native_message_round_count, 2);
        assert_eq!(report.native_report.counters.native_oracle_count, 2);
        assert_eq!(
            report.native_report.counters.native_oracle_eval_claim_count,
            2
        );
        assert_eq!(
            report
                .native_report
                .counters
                .native_oracle_pcs_opening_count,
            2
        );
        assert_eq!(report.message_to_trace_binding_count, 0);
        assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
        assert_eq!(
            fixture.proof.native_proof.family_columnar_subproof_count(),
            0
        );
        assert_ne!(
            fixture.proof.native_proof.descriptors[0].num_vars,
            fixture.proof.native_proof.descriptors[1].num_vars
        );
        assert_eq!(report.round_challenges, fixture.proof.round_challenges);
    }

    #[test]
    fn symbt3_n4b_one_round_batch_axis_keeps_oracle_count_constant() {
        let mut observed_num_vars = Vec::new();
        for (batch_size, batch_log_size) in [(1usize, 0usize), (2, 1), (4, 2), (8, 3)] {
            let fixture = n4_fixture_with_batch_log_size(1, batch_log_size);
            let report = verify_n4_fixture(&fixture, &fixture.proof);
            assert!(report.ok);
            assert_eq!(fixture.challenge_context.batch_size, batch_size as u64);
            assert_eq!(report.native_message_round_count, 1);
            assert_eq!(report.native_report.counters.native_oracle_count, 1);
            assert_eq!(
                report
                    .native_report
                    .counters
                    .native_oracle_pcs_opening_count,
                1
            );
            assert_eq!(report.message_to_trace_binding_count, 0);
            assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
            assert_eq!(
                fixture.proof.native_proof.family_columnar_subproof_count(),
                0
            );
            assert_eq!(
                fixture.proof.native_proof.descriptors[0].num_vars,
                batch_log_size + fixture.round_layouts[0].message_axis_log_size
            );
            observed_num_vars.push(fixture.proof.native_proof.descriptors[0].num_vars);
        }
        assert_eq!(observed_num_vars, vec![1, 2, 3, 4]);
    }

    #[test]
    fn symbt3_n4b_two_round_batch_axis_keeps_oracle_count_constant() {
        for batch_log_size in [0usize, 1, 2] {
            let fixture = n4_fixture_with_batch_log_size(2, batch_log_size);
            let report = verify_n4_fixture(&fixture, &fixture.proof);
            assert!(report.ok);
            assert_eq!(report.native_message_round_count, 2);
            assert_eq!(report.native_report.counters.native_oracle_count, 2);
            assert_eq!(
                report
                    .native_report
                    .counters
                    .native_oracle_pcs_opening_count,
                2
            );
            assert_eq!(report.message_to_trace_binding_count, 0);
            assert_eq!(
                fixture.proof.native_proof.family_columnar_subproof_count(),
                0
            );
            assert_eq!(fixture.proof.native_proof.top_level_whir_proof_count(), 1);
            assert_eq!(
                fixture.proof.native_proof.descriptors[0].num_vars,
                batch_log_size + fixture.round_layouts[0].message_axis_log_size
            );
            assert_eq!(
                fixture.proof.native_proof.descriptors[1].num_vars,
                batch_log_size + fixture.round_layouts[1].message_axis_log_size
            );
        }
    }

    #[test]
    fn symbt3_n4_prefix_challenges_bind_ordered_prefix_roots() {
        let fixture = n4_fixture(3);
        let mut roots = fixture
            .proof
            .native_proof
            .descriptors
            .iter()
            .map(|descriptor| descriptor.root)
            .collect::<Vec<_>>();
        let challenge_0 = n4_round_challenge_for(&fixture, &roots, 0);
        let challenge_1 = n4_round_challenge_for(&fixture, &roots, 1);

        roots[0] = digest(b"n4-mutated-root-0");
        assert_ne!(challenge_0, n4_round_challenge_for(&fixture, &roots, 0));
        assert_ne!(challenge_1, n4_round_challenge_for(&fixture, &roots, 1));

        roots = fixture
            .proof
            .native_proof
            .descriptors
            .iter()
            .map(|descriptor| descriptor.root)
            .collect::<Vec<_>>();
        roots[1] = digest(b"n4-mutated-root-1");
        assert_eq!(challenge_0, n4_round_challenge_for(&fixture, &roots, 0));
        assert_ne!(challenge_1, n4_round_challenge_for(&fixture, &roots, 1));

        roots = fixture
            .proof
            .native_proof
            .descriptors
            .iter()
            .map(|descriptor| descriptor.root)
            .collect::<Vec<_>>();
        roots[2] = digest(b"n4-mutated-later-root");
        assert_eq!(challenge_0, n4_round_challenge_for(&fixture, &roots, 0));
        assert_eq!(challenge_1, n4_round_challenge_for(&fixture, &roots, 1));
    }

    #[test]
    fn symbt3_n4_prefix_challenges_bind_layout_counts_and_ignore_folded_output() {
        let fixture = n4_fixture(2);
        let roots = fixture
            .proof
            .native_proof
            .descriptors
            .iter()
            .map(|descriptor| descriptor.root)
            .collect::<Vec<_>>();
        let challenge = n4_round_challenge_for(&fixture, &roots, 1);

        let mut mutated_layouts = fixture.round_layouts.clone();
        mutated_layouts[1].layout_digest = digest(b"n4-mutated-round-layout");
        assert_ne!(
            challenge,
            derive_native_round_challenge(
                mutated_layouts[1].round_index,
                &roots[..=1],
                mutated_layouts[1].layout_digest,
                &fixture.challenge_context,
            )
        );

        let mut count_context = fixture.challenge_context.clone();
        count_context.active_count += 1;
        assert_ne!(
            challenge,
            derive_native_round_challenge(
                fixture.round_layouts[1].round_index,
                &roots[..=1],
                fixture.round_layouts[1].layout_digest,
                &count_context,
            )
        );

        let mut batch_context = fixture.challenge_context.clone();
        batch_context.batch_size += 1;
        assert_ne!(
            challenge,
            derive_native_round_challenge(
                fixture.round_layouts[1].round_index,
                &roots[..=1],
                fixture.round_layouts[1].layout_digest,
                &batch_context,
            )
        );

        let mut folded_context = fixture.challenge_context.clone();
        folded_context.folded_output_digest = digest(b"n4-mutated-folded-output");
        assert_eq!(
            challenge,
            derive_native_round_challenge(
                fixture.round_layouts[1].round_index,
                &roots[..=1],
                fixture.round_layouts[1].layout_digest,
                &folded_context,
            )
        );
    }

    #[test]
    fn symbt3_n4_public_boundary_omits_message_values_and_challenges_ignore_opening_payloads() {
        let fixture = n4_fixture(2);
        let public_boundary = Symbt3NativeMessageOraclePublicBoundary {
            message_oracle_policy: Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            message_oracle_roots_digest: fixture.proof.message_oracle_roots_digest,
            message_round_layouts_digest: fixture.proof.message_round_layouts_digest,
            message_oracle_policy_digest: fixture.proof.message_oracle_policy_digest,
        };
        let mut first_message_bytes = Vec::new();
        push_babybear_vec(&mut first_message_bytes, &fixture.message_evals[0]);
        assert!(!public_boundary
            .canonical_bytes()
            .windows(first_message_bytes.len())
            .any(|window| window == first_message_bytes.as_slice()));

        let before = derive_native_round_challenges(
            &fixture.proof.native_proof.descriptors,
            &fixture.round_layouts,
            &fixture.challenge_context,
        )
        .expect("round challenges");
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].value += BabyBear::ONE;
        assert_eq!(
            before,
            derive_native_round_challenges(
                &proof.native_proof.descriptors,
                &fixture.round_layouts,
                &fixture.challenge_context,
            )
            .expect("round challenges")
        );
    }

    #[test]
    fn symbt3_n4_root_swap_between_rounds_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        let root_0 = proof.native_proof.descriptors[0].root;
        proof.native_proof.descriptors[0].root = proof.native_proof.descriptors[1].root;
        proof.native_proof.descriptors[1].root = root_0;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_oracle_id_swap_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[0].oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + 1;
        proof.native_proof.descriptors[1].oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_role_round_index_swap_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[0].role = WhirNativeOracleRole::MessageRound { round: 1 };
        proof.native_proof.descriptors[1].role = WhirNativeOracleRole::MessageRound { round: 0 };
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_wrong_round_count_rejects() {
        let fixture = n4_fixture(2);
        let mut layouts = fixture.round_layouts.clone();
        layouts.pop();
        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &layouts,
            fixture.proof.message_oracle_roots_digest,
            native_message_round_layouts_digest(&layouts),
            fixture.proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4_wrong_round_layout_digest_rejects() {
        let fixture = n4_fixture(2);
        let mut layouts = fixture.round_layouts.clone();
        layouts[1].layout_digest = digest(b"n4-wrong-layout");
        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &layouts,
            fixture.proof.message_oracle_roots_digest,
            fixture.proof.message_round_layouts_digest,
            fixture.proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4_wrong_num_vars_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[1].num_vars += 1;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4b_one_oracle_per_batch_item_under_fixed_round_count_rejects() {
        let fixture = n4_fixture_with_batch_log_size(1, 2);
        let item_style_round_layouts = n4_layouts(4, fixture.batch_log_size);
        let item_style_evals = n4_message_evals(&item_style_round_layouts);
        let proof = low_level_n4_proof_with_root_policy(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &item_style_round_layouts,
            &item_style_evals,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
        );
        assert_eq!(proof.native_proof.descriptors.len(), 4);

        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            proof.message_oracle_roots_digest,
            proof.message_round_layouts_digest,
            proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4b_wrong_batch_axis_log_size_rejects() {
        let fixture = n4_fixture_with_batch_log_size(1, 2);
        let mut layouts = fixture.round_layouts.clone();
        layouts[0].batch_axis_log_size += 1;
        assert!(build_native_message_oracle_specs(&layouts, fixture.batch_log_size).is_none());
        assert!(prove_native_round_message_oracle_views(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &layouts,
            &fixture.message_evals,
            &native_round_message_view_eval_requests(&layouts),
        )
        .is_none());
    }

    #[test]
    fn symbt3_n4b_wrong_message_axis_log_size_rejects() {
        let fixture = n4_fixture_with_batch_log_size(1, 2);
        let mut layouts = fixture.round_layouts.clone();
        layouts[0].message_axis_log_size += 1;
        assert!(build_native_message_oracle_specs(&layouts, fixture.batch_log_size).is_none());
        assert!(prove_native_round_message_oracle_views(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &layouts,
            &fixture.message_evals,
            &native_round_message_view_eval_requests(&layouts),
        )
        .is_none());
    }

    #[test]
    fn symbt3_n4b_item_root_style_replay_rejects() {
        let fixture = n4_fixture_with_batch_log_size(1, 2);
        let item_style_round_layouts = n4_layouts(4, fixture.batch_log_size);
        let item_style_evals = n4_message_evals(&item_style_round_layouts);
        let proof = low_level_n4_proof_with_root_policy(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &item_style_round_layouts,
            &item_style_evals,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
        );
        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            proof.message_oracle_roots_digest,
            fixture.proof.message_round_layouts_digest,
            proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4b_stale_challenge_prefix_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.round_challenges[1] += BabyBear::ONE;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_wrong_message_value_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_wrong_point_digest_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].point_digest = digest(b"n4-wrong-point");
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_wrong_claim_kind_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.eval_claims[0].claim_kind = WhirNativeEvalClaimKind::DirectOpening;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_descriptor_truncation_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors.pop();
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_descriptor_append_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        let mut extra = proof.native_proof.descriptors[1].clone();
        extra.oracle_id = SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + 2;
        proof.native_proof.descriptors.push(extra);
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_duplicate_oracle_id_rejects() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors[1].oracle_id = proof.native_proof.descriptors[0].oracle_id;
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_unsorted_descriptors_reject() {
        let fixture = n4_fixture(2);
        let mut proof = fixture.proof.clone();
        proof.native_proof.descriptors.reverse();
        assert!(!verify_n4_fixture(&fixture, &proof).ok);
    }

    #[test]
    fn symbt3_n4_stale_public_statement_digest_rejects() {
        let fixture = n4_fixture(2);
        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            digest(b"changed-n4-public-statement"),
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            fixture.proof.message_oracle_roots_digest,
            fixture.proof.message_round_layouts_digest,
            fixture.proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4_stale_whir_param_digest_rejects() {
        let fixture = n4_fixture(2);
        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            digest(b"changed-n4-whir-params"),
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            fixture.proof.message_oracle_roots_digest,
            fixture.proof.message_round_layouts_digest,
            fixture.proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            &fixture.proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n4_debug_root_policy_rejects() {
        let fixture = n4_fixture(2);
        let proof = low_level_n4_proof_with_root_policy(
            &fixture.pk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            &fixture.message_evals,
            NativeOracleRootPolicy::DebugDevelopmentOnly,
        );
        let report = verify_native_round_message_oracle_views(
            &fixture.vk,
            fixture.proof_relation_id,
            fixture.public_statement_digest,
            fixture.whir_param_digest,
            &fixture.challenge_context,
            fixture.batch_log_size,
            &fixture.round_layouts,
            proof.message_oracle_roots_digest,
            proof.message_round_layouts_digest,
            proof.message_oracle_policy_digest,
            Symbt3MessageOraclePolicy::NativeRoundMessageOraclesV1,
            NativeOracleRootPolicy::DebugDevelopmentOnly,
            &proof,
        );
        assert!(!report.ok);
    }

    #[test]
    fn symbt3_n5_native_nonzk_folding_integrity_gate_accepts_valid_profile() {
        let metadata = n5_valid_metadata();
        let report = n5_report(&metadata);

        assert!(report.ok);
        assert!(profile_meets_native_non_zk_folding_integrity(&metadata));
        assert!(report.native_profile_ok);
        assert!(report.native_manifest_policy_ok);
        assert!(report.native_source_policy_ok);
        assert!(report.native_message_policy_ok);
        assert!(report.canonical_root_policy_ok);
        assert!(report.committed_private_policy_ok);
        assert!(report.non_zk_status_ok);
        assert!(report.message_oracle_count_ok);
        assert!(report.manifest_source_oracle_count_ok);
        assert!(report.proof_shape_ok);
        assert!(report.required_families_ok);
        assert!(report.semantic_profile_version_ok);
        assert!(report.no_monolithic_fallback);
        assert!(report.product_routing_unchanged);
        assert_eq!(report.native_oracle_count_manifest_source, 2);
        assert_eq!(report.native_oracle_count_messages, 2);
        assert_eq!(report.native_message_round_count, 2);
        assert_eq!(report.native_message_oracle_count, 2);
        assert!(report.native_message_oracle_count_is_round_count);
        assert_eq!(report.family_columnar_subproof_count, 0);
    }

    #[test]
    fn symbt3_n5_k6a_public_canonical_route_is_not_native_gate() {
        assert!(symbt3_manifest_visibility_allowed_for_policies(
            Symbt3ManifestVisibility::PublicBoundary,
            Symbt3ZkStatus::NonZkIntegrityOnly,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        ));

        let mut metadata = n5_valid_metadata();
        metadata.manifest_policy = Some(ManifestCommitmentPolicy::PublicCanonicalManifestViewV1);
        metadata.committed_private_component_count = 0;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.native_manifest_policy_ok);
    }

    #[test]
    fn symbt3_n5_rejects_missing_native_policies_and_legacy_message_roots() {
        let mut metadata = n5_valid_metadata();
        metadata.manifest_policy = None;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.native_manifest_policy_ok);

        let mut metadata = n5_valid_metadata();
        metadata.source_policy = None;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.native_source_policy_ok);

        let mut metadata = n5_valid_metadata();
        metadata.message_oracle_policy = None;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.native_message_policy_ok);

        let mut metadata = n5_valid_metadata();
        metadata.message_oracle_policy = Some(Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1);
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.native_message_policy_ok);
    }

    #[test]
    fn symbt3_n5_rejects_debug_roots_and_zk_required_committed_private() {
        let mut metadata = n5_valid_metadata();
        metadata.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.canonical_root_policy_ok);

        let mut metadata = n5_valid_metadata();
        metadata.zk_status = Symbt3ZkStatus::ZkRequired;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.non_zk_status_ok);
        assert!(!report.committed_private_policy_ok);
    }

    #[test]
    fn symbt3_n5_rejects_one_oracle_per_batch_and_bad_message_layouts() {
        let mut metadata = n5_valid_metadata();
        metadata.native_message_round_count = 1;
        metadata.native_message_oracle_count = metadata.batch_size;
        metadata.native_message_pcs_opening_count = metadata.batch_size;
        metadata.message_round_layouts = n4_layouts(1, metadata.batch_axis_log_size);
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.message_oracle_count_ok);
        assert!(!report.native_message_oracle_count_is_round_count);

        let mut metadata = n5_valid_metadata();
        metadata.message_round_layouts[0].batch_axis_log_size += 1;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.message_oracle_count_ok);
    }

    #[test]
    fn symbt3_n5_rejects_old_semantic_profile_and_missing_families() {
        let mut metadata = n5_valid_metadata();
        metadata.semantic_profile_version =
            SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.semantic_profile_version_ok);

        let mut metadata = n5_valid_metadata();
        metadata
            .required_semantic_families
            .manifest_evaluation_claim = false;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.required_families_ok);

        let mut metadata = n5_valid_metadata();
        metadata
            .required_semantic_families
            .accumulator_transition_consistency = false;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.required_families_ok);

        let mut metadata = n5_valid_metadata();
        metadata.required_semantic_families.k3_semantic_family = false;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.required_families_ok);

        let mut metadata = n5_valid_metadata();
        metadata
            .required_semantic_families
            .production_norm_range_bundle = false;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.required_families_ok);
    }

    #[test]
    fn symbt3_n5_rejects_bad_proof_shape_monolithic_and_product_route() {
        let mut metadata = n5_valid_metadata();
        metadata.family_columnar_subproof_count = 1;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.proof_shape_ok);
        assert_eq!(report.family_columnar_subproof_count, 1);

        let mut metadata = n5_valid_metadata();
        metadata.logical_native_envelope_count = 2;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.proof_shape_ok);

        let mut metadata = n5_valid_metadata();
        metadata.monolithic_fallback = true;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.no_monolithic_fallback);
        assert!(!report.proof_shape_ok);

        let mut metadata = n5_valid_metadata();
        metadata.product_default_route_attempted = true;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.product_routing_unchanged);

        let mut metadata = n5_valid_metadata();
        metadata.product_eligible = true;
        let report = n5_report(&metadata);
        assert!(!report.ok);
        assert!(!report.product_routing_unchanged);
    }

    #[test]
    fn symbt3_n6a_honest_profiles_verify_and_report_expected_counters() {
        for (batch_log_size, round_count) in [(0usize, 1usize), (1, 1), (1, 2)] {
            let fixture = n6a_fixture(batch_log_size, round_count);
            assert!(verify_n6a_fixture(
                &fixture,
                &fixture.instance,
                &fixture.proof
            ));
            assert_eq!(fixture.proof.version, 1);
            assert_eq!(
                fixture.proof.proof_kind,
                Symbt3NativeFoldingProofKind::NativeNonZkFoldingIntegrityV1
            );
            assert_eq!(fixture.proof.counters.top_level_whir_proof_count, 1);
            assert_eq!(fixture.proof.counters.family_columnar_subproof_count, 0);
            assert_eq!(fixture.proof.counters.backend_table_count, 1);
            assert_eq!(
                fixture.proof.counters.native_manifest_source_oracle_count,
                2
            );
            assert_eq!(
                fixture.proof.counters.native_message_oracle_count,
                round_count
            );
            assert_eq!(fixture.proof.counters.native_oracle_count, 2 + round_count);
            assert_eq!(
                fixture.proof.counters.native_oracle_pcs_opening_count,
                2 + round_count
            );
            assert_eq!(fixture.proof.counters.message_to_trace_binding_count, 0);
            assert_eq!(fixture.proof.counters.accumulator_transition_claims, 1);
            assert_eq!(
                fixture.proof.native_oracle_proof.descriptors.len(),
                2 + round_count
            );
            assert_eq!(
                fixture.proof.native_oracle_proof.pcs_openings.len(),
                2 + round_count
            );
            assert_eq!(
                fixture.proof.native_oracle_descriptor_digest,
                native_oracle_descriptor_digest(&fixture.proof.native_oracle_proof.descriptors)
            );
            assert_eq!(
                fixture.proof.native_message_roots_digest,
                native_message_roots_digest(&fixture.proof.native_oracle_proof.descriptors[2..])
            );
            assert_eq!(
                fixture.proof.binding_digest,
                native_folding_integrity_binding_digest(
                    fixture.instance.symbt3_relation_id,
                    fixture.instance.public_statement_digest(),
                    fixture.proof.profile_digest,
                    fixture.instance.whir_param_digest,
                    fixture.proof.native_oracle_descriptor_digest,
                    fixture.proof.native_message_roots_digest,
                    fixture.proof.manifest_oracle_root,
                    fixture.proof.source_oracle_root,
                    fixture.proof.batch_manifest_root,
                    fixture.instance.source_column_layout_digest,
                    fixture.proof.message_oracle_policy_digest,
                    fixture.proof.manifest_commitment_policy_digest,
                    fixture.instance.active_count,
                    fixture.instance.batch_size,
                )
            );

            let metadata = symbt3_native_folding_integrity_profile_metadata(
                &fixture.instance,
                &fixture.proof.counters,
            );
            assert!(profile_meets_native_non_zk_folding_integrity(&metadata));
        }
    }

    #[test]
    fn symbt3_n6a_single_native_envelope_contains_n2_and_n4_claims() {
        let fixture = n6a_fixture(1, 2);
        let proof = &fixture.proof.native_oracle_proof;
        assert_eq!(proof.top_level_whir_proof_count(), 1);
        assert_eq!(proof.family_columnar_subproof_count(), 0);
        assert_eq!(proof.descriptors[0].oracle_id, SYMBT3_N2_MANIFEST_ORACLE_ID);
        assert_eq!(proof.descriptors[1].oracle_id, SYMBT3_N2_SOURCE_ORACLE_ID);
        assert_eq!(
            proof.descriptors[2].oracle_id,
            SYMBT3_N4_MESSAGE_ORACLE_ID_BASE
        );
        assert_eq!(
            proof.descriptors[3].oracle_id,
            SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + 1
        );
        assert_eq!(
            proof.eval_claims[0].claim_kind,
            WhirNativeEvalClaimKind::EqualitySide
        );
        assert_eq!(
            proof.eval_claims[1].claim_kind,
            WhirNativeEvalClaimKind::EqualitySide
        );
        assert_eq!(
            proof.eval_claims[2].claim_kind,
            WhirNativeEvalClaimKind::MessageView
        );
        assert_eq!(
            proof.eval_claims[3].claim_kind,
            WhirNativeEvalClaimKind::MessageView
        );
    }

    #[test]
    fn symbt3_n6a_k6a_public_canonical_route_stays_separate() {
        assert!(symbt3_manifest_visibility_allowed_for_policies(
            Symbt3ManifestVisibility::PublicBoundary,
            Symbt3ZkStatus::NonZkIntegrityOnly,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            SourceCommitmentPolicy::NativeSourceOracleOpeningV1,
        ));

        let fixture = n6a_fixture(1, 1);
        let mut instance = fixture.instance.clone();
        instance.manifest_policy = ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
        instance.committed_private_component_count = 0;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));
    }

    #[test]
    fn symbt3_n6a_rejects_binding_and_metadata_mismatches() {
        let fixture = n6a_fixture(1, 2);

        let mut proof = fixture.proof.clone();
        proof.binding_digest = digest(b"n6a-wrong-binding");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.profile_digest = digest(b"n6a-wrong-profile");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.public_statement_digest = digest(b"n6a-wrong-public-statement");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.whir_param_digest = digest(b"n6a-wrong-whir-params");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.native_oracle_descriptor_digest = digest(b"n6a-wrong-descriptor-digest");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.manifest_oracle_root = digest(b"n6a-wrong-manifest-root");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.source_oracle_root = digest(b"n6a-wrong-source-root");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.native_message_roots_digest = digest(b"n6a-wrong-message-roots");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));
    }

    #[test]
    fn symbt3_n6a_rejects_stale_main_or_native_proof_components() {
        let fixture = n6a_fixture(1, 1);

        let mut proof = fixture.proof.clone();
        proof.symbt3_proof.z_eval += BabyBear::ONE;
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.native_oracle_proof.eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.native_oracle_proof.eval_claims[2].point_digest = digest(b"n6a-wrong-point");
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));
    }

    #[test]
    fn symbt3_n6a_rejects_route_profile_and_proof_kind_mismatches() {
        let fixture = n6a_fixture(1, 1);

        let mut proof = fixture.proof.clone();
        proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut instance = fixture.instance.clone();
        instance.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.message_oracle_policy = Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.semantic_profile_version =
            SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.zk_status = Symbt3ZkStatus::ZkRequired;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.monolithic_fallback = true;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let mut proof = fixture.proof.clone();
        proof.counters.family_columnar_subproof_count = 1;
        assert!(!verify_n6a_fixture(&fixture, &fixture.instance, &proof));

        let mut instance = fixture.instance.clone();
        instance.product_default_route_attempted = true;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));
    }

    #[test]
    fn symbt3_n6a_rejects_message_shape_and_challenge_mutations() {
        let fixture = n6a_fixture(2, 1);
        let item_style = n6a_fixture(2, 4);
        assert_eq!(fixture.proof.counters.native_message_oracle_count, 1);
        assert_eq!(item_style.proof.counters.native_message_oracle_count, 4);
        assert!(!verify_n6a_fixture(
            &fixture,
            &fixture.instance,
            &item_style.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.round_layouts[0].batch_axis_log_size += 1;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.round_layouts[0].message_axis_log_size += 1;
        assert!(!verify_n6a_fixture(&fixture, &instance, &fixture.proof));

        let two_round = n6a_fixture(1, 2);
        let mut proof = two_round.proof.clone();
        proof.native_oracle_proof.descriptors.swap(2, 3);
        assert!(!verify_n6a_fixture(&two_round, &two_round.instance, &proof));

        let mut proof = two_round.proof.clone();
        proof.round_challenges[1] += BabyBear::ONE;
        assert!(!verify_n6a_fixture(&two_round, &two_round.instance, &proof));
    }

    #[test]
    fn symbt3_n6b_public_route_verifies_for_k1_and_k2() {
        for batch_log_size in [0usize, 1usize] {
            let fixture = n6b_fixture(batch_log_size, 1);
            assert!(verify_n6b_fixture(
                &fixture,
                &fixture.public_profile,
                &fixture.instance,
                &fixture.proof
            ));
            assert_eq!(
                fixture.proof.proof_kind,
                Symbt3NativeFoldingProofKind::Symbt3NativeNonZkFoldingIntegrityV1
            );
            assert_eq!(fixture.proof.counters.native_oracle_count, 3);
            assert_eq!(fixture.proof.counters.native_oracle_pcs_opening_count, 3);
            assert_eq!(fixture.proof.counters.top_level_whir_proof_count, 1);
            assert_eq!(fixture.proof.counters.family_columnar_subproof_count, 0);
            assert_eq!(fixture.proof.counters.backend_table_count, 1);
            assert_eq!(fixture.proof.counters.message_to_trace_binding_count, 0);
            assert!(symbt3_native_folding_integrity_public_route_selected(
                &fixture.public_profile
            ));
            assert!(!symbt3_native_folding_integrity_monolithic_fallback_used(
                &fixture.instance
            ));
        }
    }

    #[test]
    fn symbt3_n6b_route_discriminator_separates_k6a_native_and_monolithic() {
        let fixture = n6b_fixture(1, 1);
        assert!(!verify_n6a_fixture(
            &n6a_fixture(1, 1),
            &fixture.instance,
            &fixture.proof
        ));
        assert!(!symbt3_k6a_public_canonical_route_accepts_proof_kind(
            fixture.proof.proof_kind
        ));
        assert!(!symbt3_monolithic_typed_cp_route_accepts_proof_kind(
            fixture.proof.proof_kind
        ));

        let mut proof = fixture.proof.clone();
        proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));
        assert!(symbt3_k6a_public_canonical_route_accepts_proof_kind(
            proof.proof_kind
        ));

        let mut proof = fixture.proof.clone();
        proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));
        assert!(symbt3_monolithic_typed_cp_route_accepts_proof_kind(
            proof.proof_kind
        ));
    }

    #[test]
    fn symbt3_n6b_rejects_route_profile_gate_failures() {
        let fixture = n6b_fixture(1, 1);

        let mut profile = fixture.public_profile.clone();
        profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::Disabled;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));

        let mut profile = fixture.public_profile.clone();
        profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::PublicCanonicalK6a;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));

        let mut profile = fixture.public_profile.clone();
        profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::DefaultVerifyPublic;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));

        let mut profile = fixture.public_profile.clone();
        profile.product_accepts_native_non_zk_folding_integrity = false;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));

        let mut profile = fixture.public_profile.clone();
        profile.k5_masking_required = true;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));

        let mut profile = fixture.public_profile.clone();
        profile.allow_monolithic_fallback = true;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));
    }

    #[test]
    fn symbt3_n6b_rejects_native_profile_failures() {
        let fixture = n6b_fixture(1, 1);

        let mut instance = fixture.instance.clone();
        instance
            .required_semantic_families
            .accumulator_transition_consistency = false;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.manifest_policy = ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
        instance.committed_private_component_count = 0;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.message_oracle_policy = Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.semantic_profile_version =
            SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.zk_status = Symbt3ZkStatus::ZkRequired;
        let mut profile = fixture.public_profile.clone();
        profile.zk_status = Symbt3ZkStatus::ZkRequired;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.monolithic_fallback = true;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));
    }

    #[test]
    fn symbt3_n6b_rejects_binding_digest_and_stale_proofs() {
        let fixture = n6b_fixture(1, 1);

        let mut proof = fixture.proof.clone();
        proof.binding_digest = digest(b"n6b-wrong-binding");
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));

        let mut proof = fixture.proof.clone();
        proof.native_oracle_descriptor_digest = digest(b"n6b-wrong-descriptor");
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));

        let mut proof = fixture.proof.clone();
        proof.native_message_roots_digest = digest(b"n6b-wrong-message-roots");
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));

        let mut proof = fixture.proof.clone();
        proof.native_oracle_proof.eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));

        let mut proof = fixture.proof.clone();
        proof.symbt3_proof.z_eval += BabyBear::ONE;
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &proof
        ));
    }

    #[test]
    fn symbt3_n6b_rejects_one_oracle_per_batch_item_layout() {
        let fixed_round = n6b_fixture(2, 1);
        let item_style = n6b_fixture(2, 4);
        assert_eq!(fixed_round.proof.counters.native_message_oracle_count, 1);
        assert_eq!(item_style.proof.counters.native_message_oracle_count, 4);
        assert!(!verify_n6b_fixture(
            &fixed_round,
            &fixed_round.public_profile,
            &fixed_round.instance,
            &item_style.proof
        ));
    }

    #[test]
    fn symbt3_n6c_route_matrix_separation_invariants() {
        let fixture = n6b_fixture(1, 1);
        assert!(verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &fixture.proof
        ));
        assert!(symbt3_native_folding_integrity_public_route_selected(
            &fixture.public_profile
        ));
        assert!(!symbt3_k6a_public_canonical_route_accepts_proof_kind(
            fixture.proof.proof_kind
        ));
        assert!(!symbt3_monolithic_typed_cp_route_accepts_proof_kind(
            fixture.proof.proof_kind
        ));

        let mut k6a_proof = fixture.proof.clone();
        k6a_proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
        assert!(symbt3_k6a_public_canonical_route_accepts_proof_kind(
            k6a_proof.proof_kind
        ));
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &k6a_proof
        ));

        let mut monolithic_proof = fixture.proof.clone();
        monolithic_proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
        assert!(symbt3_monolithic_typed_cp_route_accepts_proof_kind(
            monolithic_proof.proof_kind
        ));
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &fixture.instance,
            &monolithic_proof
        ));

        let mut profile = fixture.public_profile.clone();
        profile.route_status = Symbt3NativeFoldingIntegrityRouteStatus::Disabled;
        assert!(!verify_n6b_fixture(
            &fixture,
            &profile,
            &fixture.instance,
            &fixture.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.monolithic_fallback = true;
        assert!(symbt3_native_folding_integrity_monolithic_fallback_used(
            &instance
        ));
        assert!(!verify_n6b_fixture(
            &fixture,
            &fixture.public_profile,
            &instance,
            &fixture.proof
        ));
    }

    #[test]
    fn symbt3_n7_honest_native_accumulator_authority_verifies() {
        for batch_log_size in [0usize, 1, 2] {
            let fixture = n7_fixture(batch_log_size, 1);
            assert!(verify_n7_fixture(
                &fixture,
                &fixture.instance,
                &fixture.proof
            ));
            assert_eq!(
                fixture.proof.proof_kind,
                Symbt3NativeFoldingProofKind::Symbt3NativeAccumulatorAuthorityV1
            );
            assert_eq!(
                fixture.proof.workload_kind,
                Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1
            );
            assert!(!fixture.proof.counters.full_accumulator_workload);
            assert!(fixture.proof.counters.smoke_profile);
            assert_eq!(fixture.proof.counters.main_whir_num_vars, 2);
            assert_eq!(fixture.proof.counters.main_oracle_len, 4);
            assert!(fixture.proof.counters.native_multi_oracle);
            assert_eq!(
                fixture.proof.counters.tuple_leaf_layout,
                SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
            );
            assert_eq!(fixture.proof.counters.whir_instance_count, 1);
            assert_eq!(fixture.proof.counters.root_count, 1);
            assert_eq!(fixture.proof.counters.query_schedule_count, 1);
            assert_eq!(fixture.proof.counters.transcript_count, 1);
            assert_eq!(fixture.proof.counters.native_oracle_pcs_opening_count, 1);
            assert_eq!(fixture.proof.counters.logical_oracle_count, 3);
            assert_eq!(
                fixture.proof.counters.native_manifest_source_oracle_count,
                2
            );
            assert_eq!(fixture.proof.counters.native_message_oracle_count, 1);
            assert_eq!(fixture.proof.counters.family_columnar_subproof_count, 0);
            assert_eq!(fixture.proof.counters.accumulator_transition_claims, 1);
            assert_eq!(
                fixture.proof.counters.rlc_batching_bits,
                SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(
                fixture.proof.counters.rlc_repetition_count,
                SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
            );
            assert_eq!(
                fixture.proof.counters.rlc_batching_bits_per_repetition,
                SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(
                fixture.proof.counters.total_rlc_batching_bits,
                SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(
                fixture.proof.counters.effective_soundness_bits,
                SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(
                fixture
                    .proof
                    .rlc_tuple_leaf_multi_oracle_proof
                    .counters
                    .root_count,
                1
            );
        }
    }

    #[test]
    fn symbt3_n7_profile_gate_accepts_tuple_leaf_authority_shape() {
        let fixture = n7_fixture(1, 1);
        let metadata = symbt3_native_accumulator_authority_profile_metadata(
            &fixture.instance,
            &fixture.proof.counters,
        );
        let report = symbt3_native_accumulator_authority_profile_report(&metadata);
        assert!(report.ok);
        assert!(profile_meets_native_accumulator_authority(&metadata));
        assert!(report.tuple_leaf_mode_ok);
        assert!(report.tuple_leaf_shape_ok);
        assert!(report.rlc_soundness_ok);
        assert!(!report.full_ok);
        assert!(!profile_meets_native_accumulator_authority_full(&metadata));
        assert!(!report.full_accumulator_workload);
        assert!(report.smoke_profile);
        assert_eq!(report.logical_oracle_count, 3);
        assert_eq!(report.native_oracle_pcs_opening_count, 1);
        assert_eq!(
            report.rlc_batching_bits,
            Some(SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS)
        );
    }

    #[test]
    fn symbt3_n7_full_authority_gate_rejects_smoke_profile() {
        let fixture = n7_fixture(1, 1);
        assert!(
            symbt3_native_accumulator_k6a_workload_adapter(
                Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
                    instance: &fixture.instance,
                    proof: &fixture.proof,
                },
            )
            .is_none(),
            "N7 smoke proofs must not enter the full K6a N7b helper boundary"
        );

        let mut metadata = symbt3_native_accumulator_authority_profile_metadata(
            &fixture.instance,
            &fixture.proof.counters,
        );
        metadata.workload_kind = Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1;
        metadata.full_accumulator_workload = true;
        metadata.smoke_profile = false;
        metadata.semantic_profile_version =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_MIN_SEMANTIC_PROFILE_VERSION;
        metadata.target_soundness_bits =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS;
        metadata.soundness_bound_bits =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS;
        metadata.rlc_repetition_count = 1;
        metadata.rlc_batching_bits_per_repetition = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
        metadata.total_rlc_batching_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
        metadata.rlc_batching_bits = Some(SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS);
        metadata.effective_soundness_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
        let report = symbt3_native_accumulator_authority_profile_report(&metadata);
        assert!(!report.full_ok);
        assert!(!profile_meets_native_accumulator_authority_full(&metadata));
        assert!(!report.rlc_soundness_ok);

        metadata.rlc_repetition_count =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT;
        metadata.rlc_batching_bits_per_repetition =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_BATCHING_BITS_PER_REPETITION;
        metadata.total_rlc_batching_bits = metadata
            .rlc_repetition_count
            .saturating_mul(metadata.rlc_batching_bits_per_repetition);
        metadata.rlc_batching_bits = Some(metadata.total_rlc_batching_bits);
        metadata.effective_soundness_bits = metadata.total_rlc_batching_bits;
        let report = symbt3_native_accumulator_authority_profile_report(&metadata);
        assert!(report.rlc_soundness_ok);
        assert!(report.workload_kind_ok);
        assert!(report.full_ok);
    }

    #[test]
    fn symbt3_n7b_k6a_adapter_extracts_full_workload() {
        let fixture = k6a_adapter_fixture();
        let adapter = &fixture.adapter;
        assert_eq!(
            adapter.workload_kind,
            Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        );
        assert!(adapter.full_accumulator_workload);
        assert!(!adapter.smoke_profile);
        assert_eq!(
            adapter.proof_kind,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity
        );
        assert_eq!(
            adapter.old_accumulator_digest,
            fixture.accumulator_instance.old_accumulator_digest
        );
        assert_eq!(
            adapter.new_accumulator_digest,
            fixture.accumulator_instance.new_accumulator_digest
        );
        assert_eq!(
            adapter.batch_size,
            fixture.accumulator_instance.batch_capacity as u64
        );
        assert_eq!(
            adapter.active_count,
            fixture.accumulator_instance.active_count as u64
        );
        assert_eq!(
            adapter.main_symbt3_proof_digest,
            symbt3_main_whir_proof_digest(&fixture.proof)
        );
        assert_eq!(adapter.main_whir_num_vars, fixture.proof.num_vars);
        assert_eq!(adapter.main_oracle_len, 1usize << fixture.proof.num_vars);
        assert_eq!(adapter.top_level_whir_proof_count, 1);
        assert_eq!(adapter.family_columnar_subproof_count, 0);
        assert_eq!(adapter.backend_table_count, 1);
        assert_eq!(adapter.accumulator_transition_claims, 1);
        assert!(symbt3_native_accumulator_k6a_workload_adapter_matches(
            adapter,
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &fixture.proof,
        ));

        let from_input = symbt3_native_accumulator_k6a_workload_adapter(
            Symbt3NativeAccumulatorK6aWorkloadAdapterInput::FullK6a {
                vk: &fixture.vk,
                profile: &fixture.profile,
                accumulator_instance: &fixture.accumulator_instance,
                proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                proof: &fixture.proof,
            },
        )
        .expect("verified K6a adapter input");
        assert_eq!(from_input, *adapter);

        let smoke = n7_fixture(1, 1);
        assert!(
            symbt3_native_accumulator_k6a_workload_adapter(
                Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
                    instance: &smoke.instance,
                    proof: &smoke.proof,
                },
            )
            .is_none(),
            "synthetic N7 smoke inputs must not be coerced into K6a workload metadata"
        );

        let mut stale_adapter = adapter.clone();
        stale_adapter.main_symbt3_proof_digest = digest(b"stale-k6a-proof-digest");
        assert!(!symbt3_native_accumulator_k6a_workload_adapter_matches(
            &stale_adapter,
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &fixture.proof,
        ));

        let mut stale_adapter = adapter.clone();
        stale_adapter.old_accumulator_digest = digest(b"stale-k6a-old-accumulator");
        assert!(!symbt3_native_accumulator_k6a_workload_adapter_matches(
            &stale_adapter,
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
            &fixture.proof,
        ));

        let mut stale_instance = fixture.accumulator_instance.clone();
        stale_instance.new_accumulator_digest = digest(b"stale-k6a-new-accumulator");
        assert!(
            symbt3_native_accumulator_k6a_workload_adapter(
                Symbt3NativeAccumulatorK6aWorkloadAdapterInput::FullK6a {
                    vk: &fixture.vk,
                    profile: &fixture.profile,
                    accumulator_instance: &stale_instance,
                    proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                    proof: &fixture.proof,
                },
            )
            .is_none(),
            "mismatched accumulator instance digests must reject"
        );

        let mut missing = Symbt3NativeAccumulatorK6aWorkloadAdapterParts::from(adapter);
        missing.main_symbt3_proof_digest = None;
        assert!(symbt3_native_accumulator_k6a_workload_adapter_from_parts(missing).is_none());
    }

    fn assert_honest_full_n7b_verifies(batch_size: usize) -> Symbt3N7bFullAuthorityProof {
        let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
        let proof = prove_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("full N7b proof");
        assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &proof,
        ));
        let counters = &proof.wrapper.counters;
        assert!(counters.full_accumulator_workload);
        assert!(!counters.smoke_profile);
        assert!(counters.native_multi_oracle);
        assert_eq!(counters.whir_instance_count, 1);
        assert_eq!(counters.root_count, 1);
        assert_eq!(counters.query_schedule_count, 1);
        assert_eq!(counters.transcript_count, 1);
        assert_eq!(counters.native_oracle_pcs_opening_count, 1);
        assert_eq!(
            counters.logical_oracle_count,
            2 + fixture.accumulator_instance.message_oracle_roots.len()
        );
        assert_eq!(counters.family_columnar_subproof_count, 0);
        assert_eq!(
            counters.rlc_repetition_count,
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        );
        assert!(
            counters.effective_soundness_bits
                >= SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS
        );
        assert!(!counters.fallback_used);
        proof
    }

    #[test]
    fn symbt3_n7b_full_helper_honest_k1_round1_verifies() {
        assert_honest_full_n7b_verifies(1);
    }

    #[test]
    fn symbt3_n7b_full_helper_honest_k2_round1_verifies() {
        assert_honest_full_n7b_verifies(2);
    }

    #[test]
    fn symbt3_n7b_actual_serialized_bytes_use_compact_pcs_and_match_accounting() {
        let fixture = k6a_adapter_fixture_with_batch_size(1);
        let mut proof = prove_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("full N7b proof");
        assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &proof,
        ));

        let serialized = symbt3_n7b_full_authority_proof_canonical_bytes(&proof)
            .expect("N7b proof canonical bytes");
        let sections = symbt3_n7b_full_authority_proof_byte_sections(&proof);
        assert_eq!(serialized.len(), sections.total_bytes);
        assert_eq!(
            serialized.len(),
            symbt3_n7b_full_authority_proof_size_hint(&proof)
        );

        let compact_pcs =
            whir_pcs_compact_canonical_bytes(&proof.wrapper.native_tuple_leaf.proof.whir_pcs_proof)
                .expect("compact tuple PCS payload");
        assert!(
            serialized
                .windows(compact_pcs.len())
                .any(|window| window == compact_pcs.as_slice()),
            "actual N7b serialized bytes must contain the compact PCS payload"
        );

        let decoded_pcs =
            whir_pcs_from_compact_canonical_bytes(&compact_pcs).expect("decode compact PCS");
        assert_eq!(
            serde_json::to_value(&decoded_pcs).expect("decoded PCS JSON"),
            serde_json::to_value(&proof.wrapper.native_tuple_leaf.proof.whir_pcs_proof)
                .expect("original PCS JSON")
        );
        proof.wrapper.native_tuple_leaf.proof.whir_pcs_proof = decoded_pcs;
        assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &proof,
        ));
    }

    fn refresh_symbt3_n8_claim_plan_for_test(plan: &mut IntegratedK6aNativeClaimPlanV1) {
        plan.combined_logical_oracle_descriptor_digest =
            symbt3_n8_integrated_logical_oracle_descriptors_digest(
                &plan.logical_oracle_descriptors,
            );
        plan.combined_constraint_descriptor_digest =
            symbt3_n8_integrated_constraint_descriptors_digest(&plan.constraint_descriptors);
        plan.combined_claim_descriptor_digest =
            symbt3_n8_integrated_claim_descriptors_digest(&plan.claim_descriptors);
        plan.claim_plan_digest = symbt3_n8_integrated_claim_plan_digest(plan);
    }

    fn refresh_symbt3_n8_committed_table_for_test(table: &mut IntegratedK6aNativeCommittedTableV1) {
        table.layout_digest = symbt3_n8_integrated_committed_table_layout_digest(table);
        table.table_digest = symbt3_n8_integrated_committed_table_digest(table);
        table.counters.layout_digest = table.layout_digest;
        table.counters.table_digest = table.table_digest;
    }

    fn refresh_symbt3_n8_real_evaluator_for_test(
        evaluator: &mut RealIntegratedK6aNativeEvaluatorV1,
    ) {
        evaluator.rows_digest = n8_integrated_evaluator_rows_digest(&evaluator.rows);
        evaluator.table_digest =
            n8_integrated_evaluator_table_digest(evaluator).expect("real evaluator table digest");
        evaluator.evaluator_digest = n8_integrated_evaluator_digest(evaluator);
    }

    fn refresh_symbt3_n8_k6a_semantic_constraints_for_test(
        constraints: &mut N8IntegratedK6aSemanticConstraintsV1,
    ) {
        constraints.rows_digest = n8_integrated_k6a_semantic_rows_digest(&constraints.rows);
    }

    fn refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
        constraints: &mut N8IntegratedTupleRlcSemanticConstraintsV1,
    ) {
        constraints.rows_digest = n8_integrated_tuple_rlc_semantic_rows_digest(&constraints.rows);
        constraints.descriptor_digest =
            n8_integrated_tuple_rlc_semantic_descriptor_digest(constraints);
    }

    fn refresh_symbt3_n8_descriptor_for_test(
        descriptor: &mut Symbt3IntegratedK6aNativeWhirRelationV1,
    ) {
        refresh_symbt3_n8_claim_plan_for_test(&mut descriptor.claim_plan);
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(descriptor);
    }

    fn semantic_n8_descriptor_fixture_for_test() -> (
        K6aAdapterFixture,
        Symbt3N7bFullAuthorityProof,
        Symbt3IntegratedK6aNativeWhirRelationV1,
    ) {
        let fixture = k6a_adapter_fixture_with_batch_size(1);
        let proof = prove_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("full N7b proof");
        assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &proof,
        ));
        let relation = symbt3_k6a_relation_from_context(
            fixture
                .vk
                .relation
                .context
                .as_ref()
                .expect("K6a relation context"),
        )
        .expect("K6a relation decodes");
        let statement = fixture.accumulator_instance.to_public_statement();
        let descriptor =
            build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics(
                &fixture.pk.seed,
                &relation,
                &statement,
                &proof.wrapper.k6a_adapter,
                &proof.wrapper.native_tuple_leaf,
                &proof.k6a_main_proof,
            )
            .expect("N8 descriptor with K6a semantics builds");
        (fixture, proof, descriptor)
    }

    fn direct_semantic_n8_descriptor_for_test(
        batch_size: usize,
    ) -> (
        K6aAdapterFixture,
        N8DirectSemanticInputsV1,
        Symbt3IntegratedK6aNativeWhirRelationV1,
    ) {
        let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
        let inputs = build_n8_semantic_inputs_from_k6a_witness(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("direct N8 semantic inputs");
        let descriptor =
            build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs(
                &inputs,
            )
            .expect("direct N8 descriptor");
        (fixture, inputs, descriptor)
    }

    fn reference_n8_semantic_inputs_from_k6a_witness_for_test(
        pk: &WhirProvingKey,
        profile: &Symbt3AuthorityProfile,
        accumulator_instance: &Symbt3AccumulatorInstance,
        witness: &Symbt3AccumulatorWitness,
    ) -> Option<N8DirectSemanticInputsV1> {
        let relation = symbt3_k6a_relation_from_context(pk.relation.context.as_ref()?)?;
        let statement =
            super::super::symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
                profile,
                accumulator_instance,
                &relation,
            )?;
        let symbt3_witness = witness.to_symbt3_witness(&relation)?;
        let k6a_semantic_source = symbt3_n8_k6a_semantic_source_from_witness(
            &pk.seed,
            &relation,
            &statement,
            &symbt3_witness,
        )?;
        let k6a_adapter =
            symbt3_native_accumulator_k6a_workload_adapter_from_relation_statement_and_semantic_source(
                &relation,
                profile,
                accumulator_instance,
                &statement,
                ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                &k6a_semantic_source,
            )?;
        let native_tuple_leaf = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness(
            pk,
            accumulator_instance,
            witness,
            &k6a_adapter,
        )?;
        Some(N8DirectSemanticInputsV1 {
            relation,
            statement,
            k6a_semantic_source,
            k6a_adapter,
            native_tuple_leaf,
            profile: N8DirectSemanticInputBuildProfileV1::default(),
        })
    }

    #[test]
    fn symbt3_n8_optimized_direct_setup_matches_reference_direct_setup() {
        for batch_size in [1usize, 2] {
            let fixture = k6a_adapter_fixture_with_batch_size(batch_size);
            let optimized = build_n8_semantic_inputs_from_k6a_witness(
                &fixture.pk,
                &fixture.profile,
                &fixture.accumulator_instance,
                &fixture.accumulator_witness,
            )
            .expect("optimized direct N8 semantic inputs");
            let reference = reference_n8_semantic_inputs_from_k6a_witness_for_test(
                &fixture.pk,
                &fixture.profile,
                &fixture.accumulator_instance,
                &fixture.accumulator_witness,
            )
            .expect("reference direct N8 semantic inputs");

            assert_eq!(optimized.relation, reference.relation);
            assert_eq!(optimized.statement, reference.statement);
            assert_eq!(optimized.k6a_semantic_source, reference.k6a_semantic_source);
            assert_eq!(optimized.k6a_adapter, reference.k6a_adapter);
            assert_eq!(
                optimized.native_tuple_leaf.proof.packed_root,
                reference.native_tuple_leaf.proof.packed_root
            );
            assert_eq!(
                optimized.native_tuple_leaf.proof.logical_eval_claims,
                reference.native_tuple_leaf.proof.logical_eval_claims
            );
            assert_eq!(
                optimized.native_tuple_leaf.proof.packed_eval_claims,
                reference.native_tuple_leaf.proof.packed_eval_claims
            );
            assert_eq!(
                optimized.native_tuple_leaf.native_oracle_descriptor_digest,
                reference.native_tuple_leaf.native_oracle_descriptor_digest
            );
        }
    }

    fn assert_direct_n8_rows_match_source_proof_extraction(batch_size: usize) {
        let (fixture, direct_inputs, direct_descriptor) =
            direct_semantic_n8_descriptor_for_test(batch_size);
        let source_proof = prove_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("reference N7b source proof");
        let source = symbt3_n8_k6a_semantic_source_from_proof(
            &fixture.pk.seed,
            &direct_inputs.relation,
            &direct_inputs.statement,
            &source_proof.k6a_main_proof,
        )
        .expect("source-proof-extracted K6a semantic material");
        assert_eq!(source, direct_inputs.k6a_semantic_source);
        let adapter =
            symbt3_native_accumulator_k6a_workload_adapter_from_relation_and_semantic_source(
                &direct_inputs.relation,
                &fixture.profile,
                &fixture.accumulator_instance,
                ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                &source,
            )
            .expect("source-material adapter");
        let reference_inputs = N8DirectSemanticInputsV1 {
            relation: direct_inputs.relation.clone(),
            statement: direct_inputs.statement.clone(),
            k6a_semantic_source: source,
            k6a_adapter: adapter,
            native_tuple_leaf: source_proof.wrapper.native_tuple_leaf,
            profile: N8DirectSemanticInputBuildProfileV1::default(),
        };
        assert_eq!(
            reference_inputs.native_tuple_leaf.proof.packed_root,
            direct_inputs.native_tuple_leaf.proof.packed_root,
            "direct tuple root must match source-proof tuple root"
        );
        let reference_descriptor =
            build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_from_semantic_inputs(
                &reference_inputs,
            )
            .expect("reference descriptor from source proof material");
        assert_eq!(
            direct_descriptor.k6a_semantic_constraints.rows,
            reference_descriptor.k6a_semantic_constraints.rows
        );
        assert_eq!(
            direct_descriptor.tuple_rlc_semantic_constraints.rows,
            reference_descriptor.tuple_rlc_semantic_constraints.rows
        );
        assert_eq!(
            direct_descriptor
                .transition_binding_semantic_constraints
                .rows,
            reference_descriptor
                .transition_binding_semantic_constraints
                .rows
        );
        assert_eq!(
            direct_descriptor.real_evaluator.rows,
            reference_descriptor.real_evaluator.rows
        );
        assert_eq!(
            direct_descriptor.transcript_binding_digest,
            reference_descriptor.transcript_binding_digest
        );
    }

    #[test]
    fn symbt3_n8_direct_builder_rows_match_source_proof_extracted_rows_k1() {
        assert_direct_n8_rows_match_source_proof_extraction(1);
    }

    #[test]
    fn symbt3_n8_direct_builder_rows_match_source_proof_extracted_rows_k2() {
        assert_direct_n8_rows_match_source_proof_extraction(2);
    }

    #[test]
    fn symbt3_n8_direct_builder_uses_claim_material_digest_not_k6a_proof_digest() {
        let (fixture, inputs, _descriptor) = direct_semantic_n8_descriptor_for_test(1);
        assert_eq!(
            inputs.k6a_adapter.main_symbt3_proof_digest,
            inputs.k6a_semantic_source.source_digest
        );
        assert_ne!(
            inputs.k6a_adapter.main_symbt3_proof_digest,
            symbt3_main_whir_proof_digest(&fixture.proof),
            "direct N8 must not bind the harness-built K6a proof digest"
        );
        assert_eq!(
            serde_json::to_value(&inputs.native_tuple_leaf.proof.whir_pcs_proof)
                .expect("direct tuple PCS placeholder serializes"),
            serde_json::to_value(WhirPcsProof::<F, EF, WhirMmcs>::default())
                .expect("default tuple PCS placeholder serializes")
        );
    }

    #[test]
    fn symbt3_n8_direct_tuple_leaf_profiled_matches_unprofiled() {
        let (fixture, inputs, _descriptor) = direct_semantic_n8_descriptor_for_test(1);
        let unprofiled = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness(
            &fixture.pk,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
            &inputs.k6a_adapter,
        )
        .expect("unprofiled direct tuple leaf");
        let mut profile = N8DirectSemanticInputBuildProfileV1::default();
        let profiled = build_symbt3_n8_direct_native_tuple_leaf_from_k6a_witness_profiled(
            &fixture.pk,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
            &inputs.k6a_adapter,
            Some(&mut profile),
        )
        .expect("profiled direct tuple leaf");

        assert_eq!(profiled.proof.packed_root, unprofiled.proof.packed_root);
        assert_eq!(
            profiled.proof.packed_root,
            inputs.native_tuple_leaf.proof.packed_root
        );
        assert_eq!(
            profiled.proof.packed_eval_claims,
            unprofiled.proof.packed_eval_claims
        );
        assert_eq!(
            profiled.proof.logical_eval_claims,
            unprofiled.proof.logical_eval_claims
        );
        assert_eq!(
            profiled.native_oracle_descriptor_digest,
            unprofiled.native_oracle_descriptor_digest
        );
        assert!(profile.tuple_rlc_input_ms == 0.0);
        assert!(profile.tuple_rlc_raw_values_ms >= 0.0);
        assert!(profile.tuple_rlc_descriptor_ms >= 0.0);
        assert!(profile.tuple_rlc_claims_ms >= 0.0);
        assert!(profile.tuple_rlc_packed_root_ms >= 0.0);
    }

    #[test]
    fn symbt3_n8_root_only_commit_matches_full_empty_opening_proof_root() {
        let seed = [0x42u8; 32];
        let num_variables = 4;
        let evaluations = (0..(1usize << num_variables))
            .map(|value| BabyBear::from_u32((value as u32).wrapping_mul(17).wrapping_add(3)))
            .collect::<Vec<_>>();
        let root_only = whir_initial_root_digest(
            &seed,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            num_variables,
            &evaluations,
        )
        .expect("root-only WHIR commitment digest");
        let (proof, openings) =
            whir_commit_and_prove_multi(&seed, num_variables, &evaluations, &[]);
        assert!(openings.is_empty());
        let full_proof_root =
            whir_pcs_initial_root_digest(&proof, NativeOracleRootPolicy::CanonicalWhirRootV1)
                .expect("full WHIR proof root");
        assert_eq!(root_only, full_proof_root);
    }

    #[test]
    fn symbt3_n8_root_only_tuple_leaf_is_not_standalone_verifier_authoritative() {
        let fixture = k6a_adapter_fixture_with_batch_size(1);
        let inputs = build_n8_semantic_inputs_from_k6a_witness(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("direct N8 semantic inputs");
        assert_eq!(
            serde_json::to_value(&inputs.native_tuple_leaf.proof.whir_pcs_proof)
                .expect("direct tuple PCS placeholder serializes"),
            serde_json::to_value(WhirPcsProof::<F, EF, WhirMmcs>::default())
                .expect("default tuple PCS placeholder serializes")
        );
        assert!(
            !whir_verify_same_domain_multi_oracle(
                &fixture.vk,
                inputs.k6a_adapter.main_symbt3_relation_id,
                inputs.k6a_adapter.public_statement_digest,
                inputs.k6a_adapter.whir_param_digest,
                &inputs.native_tuple_leaf.proof,
                &inputs.native_tuple_leaf.proof.logical_eval_claims,
            ),
            "N8's root-only tuple leaf is prover material for the integrated proof, not a standalone verifier proof"
        );
    }

    #[test]
    fn symbt3_n8_direct_builder_authority_candidate_verifies() {
        let (fixture, _inputs, descriptor) = direct_semantic_n8_descriptor_for_test(1);
        let plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("direct N8 proof plan builds");
        let output = prove_symbt3_integrated_whir_from_claim_plan(&fixture.pk, &descriptor, &plan)
            .expect("direct N8 integrated output");
        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &fixture.vk,
            &output.verifier_input(&descriptor),
        );
        assert!(backend_report.ok);
        let authority_report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
        assert!(authority_report.ok);
    }

    fn semantic_n8_output_fixture_for_test() -> (
        K6aAdapterFixture,
        Symbt3N7bFullAuthorityProof,
        Symbt3IntegratedK6aNativeWhirRelationV1,
        WhirVerifyingKey,
        N8IntegratedWhirProverOutput,
    ) {
        let (fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("semantic N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());
        let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
            .expect("semantic integrated output");
        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &output.verifier_input(&descriptor),
        );
        assert!(backend_report.ok);
        let authority_report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
        assert!(authority_report.ok);
        (fixture, proof, descriptor, vk, output)
    }

    fn assert_n8_transition_binding_semantic_mutation_rejects(
        mutate: impl FnOnce(&mut N8IntegratedTransitionBindingSemanticConstraintsV1),
    ) {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        mutate(&mut descriptor.transition_binding_semantic_constraints);
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation)
        );
    }

    fn refresh_symbt3_n8_table_descriptor_for_test(
        descriptor: &mut Symbt3IntegratedK6aNativeWhirRelationV1,
    ) {
        refresh_symbt3_n8_committed_table_for_test(&mut descriptor.committed_table);
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(descriptor);
    }

    fn refresh_symbt3_n8_evaluator_descriptor_for_test(
        descriptor: &mut Symbt3IntegratedK6aNativeWhirRelationV1,
    ) {
        refresh_symbt3_n8_real_evaluator_for_test(&mut descriptor.real_evaluator);
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(descriptor);
    }

    fn n8_integrated_plan_for_existing_proof_for_test(
        descriptor: &Symbt3IntegratedK6aNativeWhirRelationV1,
        integrated_proof: &WhirProof,
    ) -> (Digest32, N8IntegratedWhirProofPlan) {
        let root = whir_pcs_initial_root_digest(
            &integrated_proof.whir_pcs_proof,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
        )
        .expect("canonical integrated WHIR root");
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(descriptor);
        inputs.integrated_whir_root = Some(root);
        inputs.integrated_whir_proof = Some(integrated_proof);
        let plan = build_n8_integrated_whir_proof_plan(&inputs)
            .expect("N8 proof plan records integrated proof material");
        (root, plan)
    }

    fn assert_n8_real_evaluator_row_mutation_rejects(
        row_kind: RealIntegratedK6aNativeEvaluatorRowKindV1,
    ) {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());
        let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
            .expect("real integrated output");

        let mut mutated_descriptor = descriptor.clone();
        let row = mutated_descriptor
            .real_evaluator
            .rows
            .iter_mut()
            .find(|row| row.kind == row_kind)
            .expect("requested real evaluator row exists");
        row.value += BabyBear::ONE;
        refresh_symbt3_n8_evaluator_descriptor_for_test(&mut mutated_descriptor);

        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&mutated_descriptor);
        inputs.integrated_whir_root = Some(output.integrated_whir_root);
        inputs.integrated_whir_proof = Some(&output.integrated_whir_proof);
        let mutated_plan = build_n8_integrated_whir_proof_plan(&inputs)
            .expect("mutated descriptor proof plan builds");
        let mutated_schedule = build_n8_integrated_whir_query_schedule_for_claims(
            &mutated_plan,
            output.query_schedule.query_claims.clone(),
        );
        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
                &mutated_descriptor,
                &mutated_plan,
                Some(output.integrated_whir_root),
                Some(&output.integrated_whir_proof),
                Some(&mutated_schedule),
            ),
        );

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
        );
    }

    #[test]
    fn symbt3_n8_claim_plan_records_shapes_and_padding() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds from full N7b parts");
        let plan = &descriptor.claim_plan;
        let table = &descriptor.committed_table;

        assert_eq!(
            descriptor.version,
            SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION
        );
        assert_eq!(
            descriptor.workload_kind,
            Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        );
        assert_eq!(
            plan.k6a_num_vars,
            proof.wrapper.k6a_adapter.main_whir_num_vars
        );
        assert_eq!(plan.k6a_oracle_len, 1usize << plan.k6a_num_vars);
        assert_eq!(
            plan.tuple_packed_oracle_len,
            1usize << plan.tuple_packed_num_vars
        );
        assert_eq!(
            plan.integrated_num_vars,
            plan.k6a_num_vars.max(plan.tuple_packed_num_vars)
        );
        assert_eq!(
            plan.integrated_oracle_len,
            1usize << plan.integrated_num_vars
        );
        assert_eq!(
            plan.k6a_padding_policy,
            symbt3_n8_k6a_padding_policy(plan.k6a_num_vars, plan.integrated_num_vars)
                .expect("deterministic K6a padding policy")
        );
        assert_eq!(
            plan.k6a_padding_policy.mode,
            if plan.k6a_num_vars == plan.integrated_num_vars {
                IntegratedK6aNativeK6aPaddingModeV1::NoPadding
            } else {
                IntegratedK6aNativeK6aPaddingModeV1::ZeroExtendRowsToIntegratedNumVars
            }
        );
        assert_eq!(
            plan.tuple_repetition_axis.repetition_axis_start,
            plan.tuple_logical_num_vars
        );
        assert_eq!(
            plan.tuple_repetition_axis.packed_num_vars,
            plan.tuple_packed_num_vars
        );
        assert_eq!(
            plan.tuple_repetition_axis.integrated_num_vars,
            plan.integrated_num_vars
        );
        assert!(descriptor.same_field);
        assert!(descriptor.same_rate);
        assert!(descriptor.same_folding_parameter);
        assert_eq!(plan.constraint_descriptors.len(), 3);
        assert_eq!(
            plan.constraint_descriptors[0].kind,
            Symbt3N8IntegratedConstraintKind::K6aAccumulatorMainV1
        );
        assert_eq!(
            plan.constraint_descriptors[1].kind,
            Symbt3N8IntegratedConstraintKind::NativeTupleLeafRepeatedRlcV1
        );
        assert_eq!(
            plan.constraint_descriptors[2].kind,
            Symbt3N8IntegratedConstraintKind::AccumulatorTransitionBindingV1
        );
        assert_eq!(
            plan.logical_oracle_descriptors.len(),
            2 + plan.tuple_logical_oracle_count
        );
        assert_eq!(plan.claim_descriptors.len(), 3);
        assert_eq!(table.plan_digest, plan.claim_plan_digest);
        assert_eq!(table.integrated_num_vars, plan.integrated_num_vars);
        assert_eq!(table.integrated_oracle_len, plan.integrated_oracle_len);
        assert_eq!(
            table.counters.k6a_padded_rows,
            plan.k6a_padding_policy.padded_row_count
        );
        assert_eq!(table.counters.tuple_rows, plan.tuple_packed_oracle_len);
        assert_eq!(
            table.counters.combined_constraint_count,
            plan.constraint_descriptors.len()
        );
        assert_eq!(table.logical_integrated_oracle_count, 1);
        assert!(!table.one_oracle_per_batch_item_layout);
        assert_eq!(table.introduced_whir_root_count, 0);
        assert_eq!(table.introduced_whir_proof_count, 0);
        assert_eq!(
            table.layout_digest,
            symbt3_n8_integrated_committed_table_layout_digest(table)
        );
        assert_eq!(
            table.table_digest,
            symbt3_n8_integrated_committed_table_digest(table)
        );
        assert_ne!(descriptor.transcript_binding_digest, [0u8; 32]);
        assert_eq!(
            descriptor.transcript_binding_digest,
            symbt3_n8_integrated_transcript_binding_digest(&descriptor)
        );

        let rebuilt = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor rebuild");
        assert_eq!(
            plan.k6a_padding_policy,
            rebuilt.claim_plan.k6a_padding_policy
        );
        assert_eq!(plan.claim_plan_digest, rebuilt.claim_plan.claim_plan_digest);
        assert_eq!(table.table_digest, rebuilt.committed_table.table_digest);
        assert_eq!(table.layout_digest, rebuilt.committed_table.layout_digest);
        assert_eq!(
            descriptor.transcript_binding_digest,
            rebuilt.transcript_binding_digest
        );
    }

    #[test]
    fn symbt3_n8_committed_table_mutations_reject() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let original_table_digest = descriptor.committed_table.table_digest;

        let rebuilt = build_integrated_k6a_native_committed_table_v1(&descriptor.claim_plan)
            .expect("N8 committed table rebuild");
        assert_eq!(descriptor.committed_table, rebuilt);

        let mut bad_padding = descriptor.clone();
        bad_padding
            .committed_table
            .k6a_padding_policy
            .padded_row_count += 1;
        refresh_symbt3_n8_table_descriptor_for_test(&mut bad_padding);
        assert_ne!(
            original_table_digest,
            bad_padding.committed_table.table_digest
        );
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_padding);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::PaddingPolicyMismatch)
        );

        let mut bad_row_order = descriptor.clone();
        bad_row_order.committed_table.row_ownership.reverse();
        refresh_symbt3_n8_table_descriptor_for_test(&mut bad_row_order);
        assert_ne!(
            original_table_digest,
            bad_row_order.committed_table.table_digest
        );
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_row_order);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::CommittedTableLayoutMismatch)
        );

        let mut bad_axis = descriptor.clone();
        bad_axis
            .committed_table
            .tuple_repetition_axis
            .repetition_axis_start += 1;
        refresh_symbt3_n8_table_descriptor_for_test(&mut bad_axis);
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_axis);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)
        );

        let mut bad_integrated = descriptor.clone();
        bad_integrated.committed_table.integrated_num_vars += 1;
        bad_integrated.committed_table.integrated_oracle_len =
            1usize << bad_integrated.committed_table.integrated_num_vars;
        bad_integrated.committed_table.counters.integrated_num_vars =
            bad_integrated.committed_table.integrated_num_vars;
        bad_integrated
            .committed_table
            .counters
            .integrated_oracle_len = bad_integrated.committed_table.integrated_oracle_len;
        refresh_symbt3_n8_table_descriptor_for_test(&mut bad_integrated);
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_integrated);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
        );
    }

    #[test]
    fn symbt3_n8_descriptor_axis_and_integrated_shape_mutations_reject() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");

        let original_plan_digest = descriptor.claim_plan.claim_plan_digest;
        let mut mutated_descriptor = descriptor.clone();
        mutated_descriptor.claim_plan.constraint_descriptors[1].descriptor_digest =
            digest(b"symbt3-n8-mutated-tuple-constraint-descriptor");
        refresh_symbt3_n8_claim_plan_for_test(&mut mutated_descriptor.claim_plan);
        assert_ne!(
            original_plan_digest,
            mutated_descriptor.claim_plan.claim_plan_digest
        );

        let mut bad_axis = descriptor.clone();
        bad_axis
            .claim_plan
            .tuple_repetition_axis
            .repetition_axis_start += 1;
        refresh_symbt3_n8_descriptor_for_test(&mut bad_axis);
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_axis);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::RepetitionAxisMismatch)
        );

        let mut bad_integrated = descriptor.clone();
        bad_integrated.claim_plan.integrated_num_vars += 1;
        bad_integrated.claim_plan.integrated_oracle_len =
            1usize << bad_integrated.claim_plan.integrated_num_vars;
        bad_integrated.claim_plan.k6a_padding_policy = symbt3_n8_k6a_padding_policy(
            bad_integrated.claim_plan.k6a_num_vars,
            bad_integrated.claim_plan.integrated_num_vars,
        )
        .expect("mutated padding policy");
        bad_integrated.claim_plan.tuple_repetition_axis = symbt3_n8_tuple_repetition_axis_mapping(
            bad_integrated.claim_plan.tuple_logical_num_vars,
            bad_integrated.claim_plan.rlc_repetition_count,
            bad_integrated.claim_plan.integrated_num_vars,
        )
        .expect("mutated repetition axis");
        for logical_descriptor in &mut bad_integrated.claim_plan.logical_oracle_descriptors {
            logical_descriptor.integrated_num_vars = bad_integrated.claim_plan.integrated_num_vars;
        }
        for constraint_descriptor in &mut bad_integrated.claim_plan.constraint_descriptors {
            constraint_descriptor.integrated_num_vars =
                bad_integrated.claim_plan.integrated_num_vars;
            constraint_descriptor.integrated_oracle_len =
                bad_integrated.claim_plan.integrated_oracle_len;
        }
        refresh_symbt3_n8_descriptor_for_test(&mut bad_integrated);
        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&bad_integrated);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
        );
    }

    #[test]
    fn symbt3_n8_integrated_whir_plan_records_claim_bridge() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);

        let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");

        assert_eq!(plan.version, N8_INTEGRATED_WHIR_PROOF_PLAN_VERSION);
        assert_eq!(
            plan.table_representation,
            N8IntegratedWhirTableRepresentationV1::SameDomainMultipleLogicalColumns
        );
        assert_eq!(plan.workload_kind, descriptor.workload_kind);
        assert_eq!(
            plan.descriptor_transcript_digest,
            descriptor.transcript_binding_digest
        );
        assert_eq!(
            plan.claim_plan_digest,
            descriptor.claim_plan.claim_plan_digest
        );
        assert_eq!(
            plan.committed_table_layout_digest,
            descriptor.committed_table.layout_digest
        );
        assert_eq!(
            plan.committed_table_digest,
            descriptor.committed_table.table_digest
        );
        assert_eq!(
            plan.integrated_num_vars,
            descriptor.claim_plan.integrated_num_vars
        );
        assert_eq!(
            plan.integrated_oracle_len,
            descriptor.claim_plan.integrated_oracle_len
        );
        assert_eq!(plan.integrated_whir_root_count, 0);
        assert_eq!(plan.integrated_whir_proof_count, 0);
        assert!(!plan.delegated_split_proof_material_present);
        assert_eq!(plan.bridge_claim_descriptors.len(), 3);
        assert_eq!(
            plan.bridge_claim_descriptors[0].kind,
            N8IntegratedWhirClaimBridgeKindV1::K6aAccumulatorConstraintsV1
        );
        assert_eq!(
            plan.bridge_claim_descriptors[1].kind,
            N8IntegratedWhirClaimBridgeKindV1::NativeTupleLeafRepeatedRlcConstraintsV1
        );
        assert_eq!(
            plan.bridge_claim_descriptors[2].kind,
            N8IntegratedWhirClaimBridgeKindV1::AccumulatorTransitionBindingConstraintsV1
        );
        assert_eq!(
            plan.combined_bridge_claim_descriptor_digest,
            n8_integrated_whir_claim_bridge_descriptors_digest(&plan.bridge_claim_descriptors)
        );
        assert_eq!(plan.semantic_batching.version, N8_SEMANTIC_BATCHING_VERSION);
        assert!(plan.semantic_batching.enabled);
        assert_eq!(
            plan.semantic_batching.descriptor_binding_digest,
            n8_semantic_batching_binding_digest(&descriptor)
        );
        assert_eq!(
            plan.semantic_batching.descriptor_digest,
            n8_semantic_batching_descriptor_digest(&plan.semantic_batching)
        );
        assert_ne!(plan.transcript_digest, [0u8; 32]);
        assert_eq!(
            plan.transcript_digest,
            n8_integrated_whir_proof_plan_transcript_digest(&plan)
        );
    }

    #[test]
    fn symbt3_n8_real_evaluator_rows_are_deterministic() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let rebuilt = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor rebuilds");

        assert_eq!(descriptor.real_evaluator, rebuilt.real_evaluator);
        assert_eq!(
            descriptor.real_evaluator.counters.k6a_claim_rows,
            symbt3_n8_k6a_claim_row_count(&proof.k6a_main_proof)
        );
        assert_eq!(
            descriptor.real_evaluator.counters.tuple_claim_rows,
            proof
                .wrapper
                .native_tuple_leaf
                .proof
                .packed_eval_claims
                .len()
                + proof
                    .wrapper
                    .native_tuple_leaf
                    .proof
                    .logical_eval_claims
                    .len()
                + proof
                    .wrapper
                    .native_tuple_leaf
                    .proof
                    .counters
                    .rlc_repetition_count
        );
        assert_eq!(
            descriptor.real_evaluator.rows_digest,
            n8_integrated_evaluator_rows_digest(&descriptor.real_evaluator.rows)
        );
        assert_eq!(
            descriptor.real_evaluator.table_digest,
            n8_integrated_evaluator_table_digest(&descriptor.real_evaluator)
                .expect("real evaluator table digest")
        );
    }

    #[test]
    fn symbt3_n8_semantic_rows_honest_pass_and_reach_authority_candidate() {
        let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();

        assert!(descriptor.k6a_semantic_constraints.complete);
        assert!(descriptor.tuple_rlc_semantic_constraints.complete);
        assert!(descriptor.transition_binding_semantic_constraints.complete);
        assert!(descriptor.semantic_completion.k6a_semantics_complete);
        assert!(descriptor.semantic_completion.tuple_rlc_semantics_complete);
        assert!(descriptor.semantic_completion.transition_semantics_complete);
        assert_eq!(
            descriptor.real_evaluator.counters.k6a_semantic_rows,
            descriptor.k6a_semantic_constraints.rows.len()
        );
        assert!(
            descriptor
                .k6a_semantic_constraints
                .rows
                .iter()
                .any(|row| row.kind
                    == N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1)
        );
        assert_eq!(
            descriptor.tuple_rlc_semantic_constraints.residual_row_count,
            descriptor.claim_plan.rlc_repetition_count
        );
        assert!(descriptor
            .tuple_rlc_semantic_constraints
            .rows
            .iter()
            .filter(|row| row.kind
                == N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1)
            .all(|row| row.value == BabyBear::ZERO));
        assert_eq!(
            descriptor.real_evaluator.counters.transition_binding_rows,
            descriptor
                .transition_binding_semantic_constraints
                .rows
                .len()
        );
        assert!(descriptor
            .transition_binding_semantic_constraints
            .rows
            .iter()
            .all(|row| row.value == BabyBear::ZERO));

        let relation_report =
            verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(relation_report.ok);
        assert_eq!(relation_report.blocker, None);
        assert!(relation_report.semantic_completion.k6a_semantics_complete);
        assert!(
            relation_report
                .semantic_completion
                .tuple_rlc_semantics_complete
        );
        assert!(
            relation_report
                .semantic_completion
                .transition_semantics_complete
        );

        let plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("semantic N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());
        let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
            .expect("semantic integrated output");
        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &output.verifier_input(&descriptor),
        );
        assert!(backend_report.ok);

        let authority_report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
        assert!(authority_report.ok);
        assert_eq!(authority_report.blocker, None);
        assert!(authority_report.semantic_completion.k6a_semantics_complete);
        assert!(
            authority_report
                .semantic_completion
                .tuple_rlc_semantics_complete
        );
        assert!(
            authority_report
                .semantic_completion
                .transition_semantics_complete
        );
    }

    #[test]
    fn symbt3_n8_audit_semantic_output_is_one_proof_non_delegating() {
        let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
        let verifier_input = output.verifier_input(&descriptor);

        assert_eq!(output.counters.whir_instance_count, 1);
        assert_eq!(output.counters.root_count, 1);
        assert_eq!(output.counters.query_schedule_count, 1);
        assert_eq!(output.counters.tuple_pcs_proof_count, 0);
        assert!(!output.counters.delegated_split_proof_material_present);
        assert!(!output.counters.synthetic_non_authoritative);
        assert_eq!(output.proof_plan.integrated_whir_root_count, 1);
        assert_eq!(output.proof_plan.integrated_whir_proof_count, 1);
        assert_eq!(
            output.integrated_whir_proof.num_vars,
            output.proof_plan.integrated_num_vars
        );
        assert!(!output.integrated_whir_proof.is_output);
        assert!(output
            .integrated_whir_proof
            .family_columnar_subproofs
            .is_empty());
        assert!(verifier_input.legacy_k6a_proof.is_none());
        assert!(verifier_input.legacy_tuple_leaf_proof.is_none());
        assert_eq!(verifier_input.extra_whir_root_count, 0);
        assert_eq!(verifier_input.extra_whir_proof_count, 0);
        assert_eq!(
            output.query_schedule.transcript_digest,
            output.proof_plan.transcript_digest
        );
        assert_eq!(
            output.query_schedule.query_claims,
            n8_integrated_whir_real_query_claims(
                &descriptor.real_evaluator,
                &output.proof_plan.semantic_batching,
            )
            .expect("real query claims derive from integrated evaluator")
        );
    }

    #[test]
    fn symbt3_n8_semantic_batching_challenges_are_domain_separated() {
        let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
        let batching = output.proof_plan.semantic_batching;

        assert_eq!(
            batching.descriptor_binding_digest,
            n8_semantic_batching_binding_digest(&descriptor)
        );
        assert!(batching.k6a_source.enabled);
        assert_ne!(
            batching.k6a_source.descriptor.challenge_point_digest,
            [0u8; 32]
        );
        assert_ne!(batching.k6a.challenge_point_digest, [0u8; 32]);
        assert_ne!(batching.tuple_rlc.challenge_point_digest, [0u8; 32]);
        assert_ne!(
            batching.transition_binding.challenge_point_digest,
            [0u8; 32]
        );
        assert_ne!(
            batching.k6a_source.descriptor.challenge_point_digest,
            batching.k6a.challenge_point_digest
        );
        assert_ne!(
            batching.k6a_source.descriptor.challenge_point_digest,
            batching.tuple_rlc.challenge_point_digest
        );
        assert_ne!(
            batching.k6a_source.descriptor.challenge_point_digest,
            batching.transition_binding.challenge_point_digest
        );
        assert_ne!(
            batching.k6a.challenge_point_digest,
            batching.tuple_rlc.challenge_point_digest
        );
        assert_ne!(
            batching.k6a.challenge_point_digest,
            batching.transition_binding.challenge_point_digest
        );
        assert_ne!(
            batching.tuple_rlc.challenge_point_digest,
            batching.transition_binding.challenge_point_digest
        );
        assert_eq!(
            batching.effective_soundness_bits,
            N8_SEMANTIC_BATCHING_CHALLENGE_SOUNDNESS_BITS
        );
    }

    #[test]
    fn symbt3_n8_semantic_batching_reduces_opening_count() {
        let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
        let k6a_source_rows = descriptor
            .real_evaluator
            .rows
            .iter()
            .filter(|row| n8_integrated_evaluator_row_is_k6a_source(row))
            .count();
        let batching = output.proof_plan.semantic_batching;
        assert_eq!(
            batching.k6a_source.unbatched_source_opening_count,
            k6a_source_rows
        );
        assert_eq!(batching.k6a_source.batched_source_opening_count, 1);
        let expected_openings = batching
            .k6a_source
            .batched_source_opening_count
            .saturating_add(batching.k6a.batched_query_count)
            .saturating_add(batching.tuple_rlc.batched_query_count)
            .saturating_add(batching.transition_binding.batched_query_count);

        assert_eq!(output.query_schedule.query_claims.len(), expected_openings);
        assert_eq!(output.query_schedule.query_claims.len(), 4);
        assert!(output.query_schedule.query_claims.len() < descriptor.real_evaluator.rows.len());
        assert_eq!(
            batching.unbatched_semantic_opening_count,
            batching
                .k6a
                .source_row_count
                .saturating_add(batching.tuple_rlc.source_row_count)
                .saturating_add(batching.transition_binding.source_row_count)
        );
        assert_eq!(
            batching.batched_semantic_opening_count,
            batching
                .k6a
                .batched_query_count
                .saturating_add(batching.tuple_rlc.batched_query_count)
                .saturating_add(batching.transition_binding.batched_query_count)
        );
    }

    #[test]
    fn symbt3_n8_semantic_batching_descriptor_mutation_rejects() {
        let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
        let mut bad_output = output.clone();
        bad_output
            .proof_plan
            .semantic_batching
            .k6a
            .challenge_point_digest[0] ^= 0x01;
        bad_output
            .proof_plan
            .semantic_batching
            .k6a
            .descriptor_digest = n8_semantic_batching_family_descriptor_digest(
            &bad_output.proof_plan.semantic_batching.k6a,
        );
        bad_output.proof_plan.semantic_batching.descriptor_digest =
            n8_semantic_batching_descriptor_digest(&bad_output.proof_plan.semantic_batching);
        bad_output.proof_plan.transcript_digest =
            n8_integrated_whir_proof_plan_transcript_digest(&bad_output.proof_plan);

        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
        );
    }

    #[test]
    fn symbt3_n8_k6a_source_row_batching_descriptor_mutation_rejects() {
        let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
        let mut bad_output = output.clone();
        bad_output
            .proof_plan
            .semantic_batching
            .k6a_source
            .descriptor
            .row_digest[0] ^= 0x01;
        bad_output
            .proof_plan
            .semantic_batching
            .k6a_source
            .descriptor
            .descriptor_digest = n8_semantic_batching_family_descriptor_digest(
            &bad_output
                .proof_plan
                .semantic_batching
                .k6a_source
                .descriptor,
        );
        bad_output
            .proof_plan
            .semantic_batching
            .k6a_source
            .descriptor_digest = n8_k6a_source_row_batching_descriptor_digest(
            &bad_output.proof_plan.semantic_batching.k6a_source,
        );
        bad_output.proof_plan.semantic_batching.descriptor_digest =
            n8_semantic_batching_descriptor_digest(&bad_output.proof_plan.semantic_batching);
        bad_output.proof_plan.transcript_digest =
            n8_integrated_whir_proof_plan_transcript_digest(&bad_output.proof_plan);

        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
        );
    }

    #[test]
    fn symbt3_n8_semantic_batching_row_mutations_still_reject() {
        let (_fixture, _proof, descriptor, _vk, output) = semantic_n8_output_fixture_for_test();
        for row_kind in [
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1,
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1,
            RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1,
            RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
        ] {
            let mut bad_descriptor = descriptor.clone();
            bad_descriptor
                .real_evaluator
                .rows
                .iter_mut()
                .find(|row| row.kind == row_kind)
                .expect("batched semantic row exists")
                .value += BabyBear::ONE;
            let report =
                verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
            assert!(matches!(
                report.blocker,
                Some(
                    Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                        | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
                )
            ));
        }
    }

    #[test]
    fn symbt3_n8_audit_coherent_k6a_opening_row_replay_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        let semantic_row = descriptor
            .k6a_semantic_constraints
            .rows
            .iter_mut()
            .find(|row| {
                row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::VerifierOpeningClaimV1
            })
            .expect("K6a verifier-opening semantic row exists");
        let source_index = semantic_row.source_index;
        semantic_row.value += BabyBear::ONE;
        refresh_symbt3_n8_k6a_semantic_constraints_for_test(
            &mut descriptor.k6a_semantic_constraints,
        );

        let evaluator_row = descriptor
            .real_evaluator
            .rows
            .iter_mut()
            .find(|row| {
                row.kind
                    == RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticVerifierOpeningClaimV1
                    && row.source_index == source_index
            })
            .expect("matching integrated K6a semantic evaluator row exists");
        evaluator_row.value += BabyBear::ONE;
        refresh_symbt3_n8_evaluator_descriptor_for_test(&mut descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_audit_authority_candidate_output_mutations_reject() {
        let (_fixture, _proof, descriptor, vk, output) = semantic_n8_output_fixture_for_test();

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .real_evaluator
            .rows
            .iter_mut()
            .find(|row| {
                row.kind
                    == RealIntegratedK6aNativeEvaluatorRowKindV1::K6aSemanticFinalResidualZeroV1
            })
            .expect("integrated K6a semantic row exists")
            .value += BabyBear::ONE;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(matches!(
            report.blocker,
            Some(
                Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
            )
        ));

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .real_evaluator
            .rows
            .iter_mut()
            .find(|row| {
                row.kind
                    == RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafRlcBindingResidualV1
            })
            .expect("integrated tuple-RLC semantic row exists")
            .value += BabyBear::ONE;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(matches!(
            report.blocker,
            Some(
                Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
            )
        ));

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .real_evaluator
            .rows
            .iter_mut()
            .find(|row| {
                row.kind
                    == RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1
            })
            .expect("integrated transition semantic row exists")
            .value += BabyBear::ONE;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(matches!(
            report.blocker,
            Some(
                Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
            )
        ));

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor.public_statement_digest[0] ^= 0x01;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(report.blocked);

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .transition_binding_semantic_constraints
            .old_accumulator_digest[0] ^= 0x02;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(report.blocked);

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .transition_binding_semantic_constraints
            .new_accumulator_digest[0] ^= 0x04;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(report.blocked);

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor
            .transition_binding_semantic_constraints
            .tuple_leaf_root[0] ^= 0x08;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(report.blocked);

        let mut bad_descriptor = descriptor.clone();
        bad_descriptor.tuple_leaf_layout_digest[0] ^= 0x10;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(report.blocked);

        let mut bad_output = output.clone();
        bad_output.proof_plan.claim_plan_digest[0] ^= 0x20;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
        );

        let mut bad_output = output.clone();
        bad_output.proof_plan.committed_table_digest[0] ^= 0x40;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
        );

        let mut bad_output = output.clone();
        bad_output.integrated_whir_root[0] ^= 0x80;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)
        );
        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &bad_output.verifier_input(&descriptor),
        );
        assert_eq!(
            backend_report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)
        );

        let mut bad_output = output.clone();
        bad_output.query_schedule.query_claims[0].value += BabyBear::ONE;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &bad_output);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
        );
        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &bad_output.verifier_input(&descriptor),
        );
        assert_eq!(
            backend_report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
        );

        let mut bad_descriptor = descriptor;
        bad_descriptor
            .semantic_completion
            .transition_semantics_complete = false;
        let report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&bad_descriptor, &output);
        assert!(report.blocked);
    }

    #[test]
    fn symbt3_n8_audit_synthetic_semantic_output_authority_rejects() {
        let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("semantic N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());
        let output =
            prove_symbt3_synthetic_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
                .expect("synthetic semantic backend plumbing output");

        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &output.verifier_input(&descriptor),
        );
        assert!(backend_report.ok);
        let authority_report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
        assert_eq!(
            authority_report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput)
        );
    }

    #[test]
    fn symbt3_n8_audit_n7b_full_proof_rejected_as_n8_candidate() {
        let (_fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let (root, plan) =
            n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
        let empty_schedule = build_n8_integrated_whir_query_schedule_for_claims(&plan, Vec::new());
        let (_, vk) = WhirSnark::setup(&relation());

        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
                &descriptor,
                &plan,
                Some(root),
                Some(&proof.k6a_main_proof),
                Some(&empty_schedule),
            ),
        );

        assert!(!report.ok);
        assert!(report.blocked);
        assert!(matches!(
            report.blocker,
            Some(
                Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected
            )
        ));
    }

    #[test]
    fn symbt3_n8_transition_binding_semantic_rows_honest_pass() {
        let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let constraints = &descriptor.transition_binding_semantic_constraints;
        assert!(constraints.complete);
        assert_eq!(constraints.rows.len(), 8);
        assert_eq!(
            constraints.rows_digest,
            n8_integrated_transition_binding_semantic_rows_digest(&constraints.rows)
        );
        assert_eq!(
            constraints.transition_binding_digest,
            n8_integrated_transition_binding_semantic_digest(constraints)
        );
        assert_eq!(
            constraints.descriptor_digest,
            n8_integrated_transition_binding_semantic_descriptor_digest(constraints)
        );
        assert!(constraints
            .rows
            .iter()
            .all(|row| row.value == BabyBear::ZERO));
        assert_eq!(
            descriptor.real_evaluator.counters.transition_binding_rows,
            constraints.rows.len()
        );
        assert!(verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor).ok);
    }

    #[test]
    fn symbt3_n8_transition_old_accumulator_digest_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.old_accumulator_digest[0] ^= 0x01;
        });
    }

    #[test]
    fn symbt3_n8_transition_new_accumulator_digest_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.new_accumulator_digest[0] ^= 0x02;
        });
    }

    #[test]
    fn symbt3_n8_transition_public_statement_digest_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.public_statement_digest[0] ^= 0x04;
        });
    }

    #[test]
    fn symbt3_n8_transition_k6a_proof_digest_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.k6a_proof_digest[0] ^= 0x08;
        });
    }

    #[test]
    fn symbt3_n8_transition_tuple_root_layout_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.tuple_leaf_root[0] ^= 0x10;
        });
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.tuple_leaf_layout_digest[0] ^= 0x20;
        });
    }

    #[test]
    fn symbt3_n8_transition_native_message_roots_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.native_oracle_descriptor_digest[0] ^= 0x40;
        });
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.native_message_roots_digest[0] ^= 0x80;
        });
    }

    #[test]
    fn symbt3_n8_transition_batch_size_active_count_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.batch_size += 1;
        });
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.active_count += 1;
        });
    }

    #[test]
    fn symbt3_n8_transition_plan_table_digest_mutation_rejects() {
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.n8_claim_plan_digest[0] ^= 0x01;
        });
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.n8_committed_table_layout_digest[0] ^= 0x02;
        });
        assert_n8_transition_binding_semantic_mutation_rejects(|constraints| {
            constraints.n8_committed_table_digest[0] ^= 0x04;
        });
    }

    #[test]
    fn symbt3_n8_authority_gate_rejects_unless_all_semantic_flags_true() {
        for mutate in [
            |flags: &mut N8IntegratedSemanticCompletionFlagsV1| {
                flags.k6a_semantics_complete = false;
            },
            |flags: &mut N8IntegratedSemanticCompletionFlagsV1| {
                flags.tuple_rlc_semantics_complete = false;
            },
            |flags: &mut N8IntegratedSemanticCompletionFlagsV1| {
                flags.transition_semantics_complete = false;
            },
        ] {
            let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
            mutate(&mut descriptor.semantic_completion);
            descriptor.transcript_binding_digest =
                symbt3_n8_integrated_transcript_binding_digest(&descriptor);
            let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
            assert!(!report.ok);
            assert_eq!(
                report.blocker,
                Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
            );
        }
    }

    #[test]
    fn symbt3_n8_keeps_default_verify_public_routing_unchanged() {
        assert!(WhirSnark::has_authoritative_typed_cp());
        let smoke = n7_fixture(1, 1);
        assert!(verify_symbt3_native_accumulator_authority_non_zk(
            &smoke.vk,
            &smoke.instance,
            &smoke.proof,
        ));
        assert!(symbt3_native_accumulator_k6a_workload_adapter(
            Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
                instance: &smoke.instance,
                proof: &smoke.proof,
            },
        )
        .is_none());
    }

    #[test]
    fn symbt3_n8_k6a_semantic_constraint_row_mutation_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        let row = descriptor
            .k6a_semantic_constraints
            .rows
            .iter_mut()
            .find(|row| row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::FinalResidualZeroV1)
            .expect("K6a final residual semantic row exists");
        row.value += BabyBear::ONE;
        refresh_symbt3_n8_k6a_semantic_constraints_for_test(
            &mut descriptor.k6a_semantic_constraints,
        );
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_k6a_semantic_padding_mutation_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        let row = descriptor
            .k6a_semantic_constraints
            .rows
            .iter_mut()
            .find(|row| row.kind == N8IntegratedK6aSemanticConstraintRowKindV1::K6aPaddingZeroV1)
            .expect("K6a semantic padding row exists");
        row.value += BabyBear::ONE;
        refresh_symbt3_n8_k6a_semantic_constraints_for_test(
            &mut descriptor.k6a_semantic_constraints,
        );
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_k6a_semantic_descriptor_mutation_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        descriptor.k6a_semantic_constraints.descriptor_digest[0] ^= 0x40;
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::K6aSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_tuple_rlc_semantic_weak_repetition_or_bits_reject() {
        let fixture = k6a_adapter_fixture_with_batch_size(1);
        let relation = symbt3_k6a_relation_from_context(
            fixture
                .vk
                .relation
                .context
                .as_ref()
                .expect("K6a relation context"),
        )
        .expect("K6a relation decodes");
        let statement = fixture.accumulator_instance.to_public_statement();

        for (repetition_count, bits_per_repetition) in [(1usize, 31usize), (4, 0), (4, 20)] {
            let (_tuple_leaf_vk, native_tuple_leaf) =
                k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
                    &fixture.adapter,
                    repetition_count,
                    bits_per_repetition,
                );
            let err =
                build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor_with_k6a_semantics(
                    &fixture.pk.seed,
                    &relation,
                    &statement,
                    &fixture.adapter,
                    &native_tuple_leaf,
                    &fixture.proof,
                )
                .expect_err("weak tuple-RLC semantic evidence must reject");
            assert_eq!(
                err,
                Symbt3N8IntegratedPrototypeBlocker::RepeatedRlcSoundnessMissingOrWeak
            );
        }
    }

    #[test]
    fn symbt3_n8_tuple_rlc_semantic_domain_mutation_rejects() {
        let (_fixture, _proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let mut gamma_descriptor = descriptor.clone();
        gamma_descriptor
            .tuple_rlc_semantic_constraints
            .packing_challenge_digest = digest(b"n8-mutated-tuple-rlc-gamma-domain");
        refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
            &mut gamma_descriptor.tuple_rlc_semantic_constraints,
        );
        gamma_descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&gamma_descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&gamma_descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
        );

        let mut zeta_descriptor = descriptor;
        zeta_descriptor
            .tuple_rlc_semantic_constraints
            .opening_points_digest = digest(b"n8-mutated-tuple-rlc-zeta-domain");
        refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
            &mut zeta_descriptor.tuple_rlc_semantic_constraints,
        );
        zeta_descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&zeta_descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&zeta_descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_tuple_rlc_semantic_repetition_swap_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        descriptor.tuple_rlc_semantic_constraints.rows.swap(0, 1);
        refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
            &mut descriptor.tuple_rlc_semantic_constraints,
        );
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_tuple_rlc_semantic_logical_oracle_order_mutation_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        let logical_base = descriptor
            .tuple_rlc_semantic_constraints
            .rlc_repetition_count;
        descriptor
            .tuple_rlc_semantic_constraints
            .rows
            .swap(logical_base, logical_base + 1);
        refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
            &mut descriptor.tuple_rlc_semantic_constraints,
        );
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_tuple_rlc_semantic_residual_mutation_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        let row = descriptor
            .tuple_rlc_semantic_constraints
            .rows
            .iter_mut()
            .find(|row| {
                row.kind == N8IntegratedTupleRlcSemanticConstraintRowKindV1::RlcResidualZeroV1
            })
            .expect("tuple RLC residual semantic row exists");
        row.value += BabyBear::ONE;
        refresh_symbt3_n8_tuple_rlc_semantic_constraints_for_test(
            &mut descriptor.tuple_rlc_semantic_constraints,
        );
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_tuple_rlc_semantic_descriptor_mutation_rejects() {
        let (_fixture, _proof, mut descriptor) = semantic_n8_descriptor_fixture_for_test();
        descriptor.tuple_rlc_semantic_constraints.descriptor_digest[0] ^= 0x20;
        descriptor.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&descriptor);

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::TupleRlcSemanticConstraintViolation)
        );
    }

    #[test]
    fn symbt3_n8_tuple_pcs_proof_material_rejects() {
        let (_fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let (_, vk) = WhirSnark::setup(&relation());
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);

        let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
        );
    }

    #[test]
    fn symbt3_n8_k6a_semantic_split_delegation_still_rejects() {
        let (_fixture, proof, descriptor) = semantic_n8_descriptor_fixture_for_test();
        let (_, vk) = WhirSnark::setup(&relation());
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        inputs.legacy_k6a_proof = Some(&proof.k6a_main_proof);
        inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);

        let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
        );
    }

    #[test]
    fn symbt3_n8_integrated_prover_output_verifies_through_backend() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());

        let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
            .expect("real integrated WHIR prover output");

        assert_eq!(output.version, N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION);
        assert_eq!(
            output.mode,
            N8IntegratedWhirProverModeV1::RealIntegratedK6aNativeEvaluatorV1
        );
        assert_eq!(output.counters.whir_instance_count, 1);
        assert_eq!(output.counters.root_count, 1);
        assert_eq!(output.counters.query_schedule_count, 1);
        assert_eq!(output.counters.tuple_pcs_proof_count, 0);
        assert!(!output.counters.delegated_split_proof_material_present);
        assert!(!output.counters.synthetic_non_authoritative);
        assert_eq!(output.proof_plan.integrated_whir_root_count, 1);
        assert_eq!(output.proof_plan.integrated_whir_proof_count, 1);
        assert_eq!(
            output.integrated_whir_proof.num_vars,
            output.proof_plan.integrated_num_vars
        );
        assert_eq!(
            output.query_schedule.integrated_num_vars,
            output.proof_plan.integrated_num_vars
        );
        let expected_claim_count: usize = output
            .proof_plan
            .bridge_claim_descriptors
            .iter()
            .map(|descriptor| descriptor.claim_count)
            .sum();
        assert_eq!(
            output.query_schedule.query_claims.len(),
            expected_claim_count
        );

        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &output.verifier_input(&descriptor),
        );
        assert!(report.ok);
        assert!(!report.blocked);
        let authority_report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
        assert_eq!(
            authority_report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
        );
    }

    #[test]
    fn symbt3_n8_integrated_prover_output_mutations_reject() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());
        let output = prove_symbt3_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
            .expect("real integrated WHIR prover output");

        let mut bad_num_vars = output.integrated_whir_proof.clone();
        bad_num_vars.num_vars += 1;
        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
                &descriptor,
                &output.proof_plan,
                Some(output.integrated_whir_root),
                Some(&bad_num_vars),
                Some(&output.query_schedule),
            ),
        );
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
        );

        let mut bad_root = output.integrated_whir_root;
        bad_root[0] ^= 0x80;
        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
                &descriptor,
                &output.proof_plan,
                Some(bad_root),
                Some(&output.integrated_whir_proof),
                Some(&output.query_schedule),
            ),
        );
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirRootMismatch)
        );

        let mut bad_schedule = output.query_schedule.clone();
        bad_schedule.transcript_digest[0] ^= 0x40;
        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
                &descriptor,
                &output.proof_plan,
                Some(output.integrated_whir_root),
                Some(&output.integrated_whir_proof),
                Some(&bad_schedule),
            ),
        );
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch)
        );

        let mut mutated_bridge_descriptors = output.proof_plan.bridge_claim_descriptors.clone();
        mutated_bridge_descriptors[0].claim_count += 1;
        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &N8IntegratedWhirVerifierInput {
                combined_claim_descriptors: &mutated_bridge_descriptors,
                ..output.verifier_input(&descriptor)
            },
        );
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
        );

        let mut split_input = output.verifier_input(&descriptor);
        split_input.legacy_k6a_proof = Some(&proof.k6a_main_proof);
        split_input.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);
        let report = verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &split_input);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
        );
    }

    #[test]
    fn symbt3_n8_real_evaluator_k6a_row_mutation_rejects() {
        assert_n8_real_evaluator_row_mutation_rejects(
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aAccumulatorOpeningClaimV1,
        );
    }

    #[test]
    fn symbt3_n8_real_evaluator_tuple_rlc_row_mutation_rejects() {
        assert_n8_real_evaluator_row_mutation_rejects(
            RealIntegratedK6aNativeEvaluatorRowKindV1::NativeTupleLeafLogicalRlcClaimV1,
        );
    }

    #[test]
    fn symbt3_n8_real_evaluator_padding_row_mutation_rejects() {
        assert_n8_real_evaluator_row_mutation_rejects(
            RealIntegratedK6aNativeEvaluatorRowKindV1::K6aZeroPaddingClaimV1,
        );
    }

    #[test]
    fn symbt3_n8_real_evaluator_transition_binding_row_mutation_rejects() {
        assert_n8_real_evaluator_row_mutation_rejects(
            RealIntegratedK6aNativeEvaluatorRowKindV1::AccumulatorTransitionBindingClaimV1,
        );
    }

    #[test]
    fn symbt3_n8_synthetic_output_verifies_only_backend_plumbing_and_authority_rejects() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("N8 proof plan builds");
        let (pk, vk) = WhirSnark::setup(&relation());
        let output =
            prove_symbt3_synthetic_integrated_whir_from_claim_plan(&pk, &descriptor, &plan)
                .expect("synthetic backend plumbing output");

        assert_eq!(
            output.mode,
            N8IntegratedWhirProverModeV1::SyntheticNonAuthoritativeV1
        );
        assert!(output.counters.synthetic_non_authoritative);
        let backend_report = verify_symbt3_integrated_whir_backend_from_verifier_input(
            &vk,
            &output.verifier_input(&descriptor),
        );
        assert!(backend_report.ok);
        let authority_report =
            verify_symbt3_n8_integrated_prover_output_authority_gate(&descriptor, &output);
        assert_eq!(
            authority_report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SyntheticNonAuthoritativeOutput)
        );
    }

    #[test]
    fn symbt3_n8_integrated_backend_rejects_missing_integrated_proof() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        let plan = build_n8_integrated_whir_proof_plan(&inputs).expect("N8 proof plan builds");
        let (_, vk) = WhirSnark::setup(&relation());
        let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            None,
            None,
            None,
        );

        let report =
            verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofApiMissing)
        );
    }

    #[test]
    fn symbt3_n8_integrated_backend_rejects_proof_num_vars_mismatch() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let mut bad_integrated_proof = proof.k6a_main_proof.clone();
        bad_integrated_proof.num_vars = descriptor.claim_plan.integrated_num_vars + 1;
        let (root, plan) =
            n8_integrated_plan_for_existing_proof_for_test(&descriptor, &bad_integrated_proof);
        let (_, vk) = WhirSnark::setup(&relation());
        let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            Some(root),
            Some(&bad_integrated_proof),
            None,
        );

        let report =
            verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch)
        );
    }

    #[test]
    fn symbt3_n8_integrated_backend_rejects_second_root_or_proof() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let (root, plan) =
            n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
        let (_, vk) = WhirSnark::setup(&relation());
        let mut verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            Some(root),
            Some(&proof.k6a_main_proof),
            None,
        );
        verifier_input.extra_whir_root_count = 1;
        verifier_input.extra_whir_proof_count = 1;

        let report =
            verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot)
        );
    }

    #[test]
    fn symbt3_n8_integrated_backend_rejects_split_k6a_tuple_delegation() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let (root, plan) =
            n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
        let (_, vk) = WhirSnark::setup(&relation());
        let mut verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            Some(root),
            Some(&proof.k6a_main_proof),
            None,
        );
        verifier_input.legacy_k6a_proof = Some(&proof.k6a_main_proof);
        verifier_input.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);

        let report =
            verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
        );
    }

    #[test]
    fn symbt3_n8_integrated_backend_rejects_claim_descriptor_mutation() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let (root, plan) =
            n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
        let (_, vk) = WhirSnark::setup(&relation());
        let mut mutated_bridge_descriptors = plan.bridge_claim_descriptors.clone();
        mutated_bridge_descriptors[1].claim_count += 1;
        let verifier_input = N8IntegratedWhirVerifierInput {
            combined_claim_descriptors: &mutated_bridge_descriptors,
            ..N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
                &descriptor,
                &plan,
                Some(root),
                Some(&proof.k6a_main_proof),
                None,
            )
        };

        let report =
            verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::DescriptorPlanMismatch)
        );
    }

    #[test]
    fn symbt3_n8_integrated_backend_rejects_current_n7b_as_integrated_proof() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let (root, plan) =
            n8_integrated_plan_for_existing_proof_for_test(&descriptor, &proof.k6a_main_proof);
        let empty_schedule = build_n8_integrated_whir_query_schedule_for_claims(&plan, Vec::new());
        let (_, vk) = WhirSnark::setup(&relation());
        let verifier_input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            &descriptor,
            &plan,
            Some(root),
            Some(&proof.k6a_main_proof),
            Some(&empty_schedule),
        );

        let report =
            verify_symbt3_integrated_whir_backend_from_verifier_input(&vk, &verifier_input);

        assert!(!report.ok);
        assert!(report.blocked);
        assert!(matches!(
            report.blocker,
            Some(
                Symbt3N8IntegratedPrototypeBlocker::IntegratedNumVarsMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirQueryScheduleMismatch
                    | Symbt3N8IntegratedPrototypeBlocker::IntegratedWhirProofRejected
            )
        ));
    }

    #[test]
    fn symbt3_n8_rejects_ambiguous_selector_gated_overlap() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        inputs.table_representation =
            N8IntegratedWhirTableRepresentationV1::ScalarOracleSelectorGatedRegions;

        let err = build_n8_integrated_whir_proof_plan(&inputs)
            .expect_err("overlapping current layout cannot be selector-gated");

        assert_eq!(
            err,
            Symbt3N8IntegratedPrototypeBlocker::AmbiguousIntegratedLayout
        );
    }

    #[test]
    fn symbt3_n8_rejects_second_whir_root_or_proof() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let (_, vk) = WhirSnark::setup(&relation());
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        inputs.integrated_whir_root = Some(digest(b"n8-integrated-root-placeholder"));
        inputs.integrated_whir_proof = Some(&proof.k6a_main_proof);
        inputs.extra_whir_root_count = 1;
        inputs.extra_whir_proof_count = 1;

        let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::ExtraWhirProofOrRoot)
        );
    }

    #[test]
    fn symbt3_n8_rejects_split_k6a_tuple_delegation_attempt() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let (_, vk) = WhirSnark::setup(&relation());
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        inputs.legacy_k6a_proof = Some(&proof.k6a_main_proof);
        inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);
        let plan = build_n8_integrated_whir_proof_plan(&inputs)
            .expect("legacy material is recorded but not accepted");
        assert!(plan.delegated_split_proof_material_present);

        let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);

        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
        );
    }

    #[test]
    fn symbt3_n8_descriptor_mutation_changes_proof_plan_transcript() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds");
        let original_plan = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&descriptor),
        )
        .expect("original N8 proof plan builds");

        let mut mutated = descriptor.clone();
        mutated
            .transition_binding_semantic_constraints
            .descriptor_digest[0] ^= 0x10;
        mutated.transcript_binding_digest =
            symbt3_n8_integrated_transcript_binding_digest(&mutated);
        let mutated_err = build_n8_integrated_whir_proof_plan(
            &N8IntegratedWhirProofInputs::from_descriptor(&mutated),
        )
        .expect_err("transition semantic descriptor mutation rejects");

        assert_ne!(
            original_plan.descriptor_transcript_digest,
            mutated.transcript_binding_digest
        );
        assert_eq!(
            mutated_err,
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation
        );
    }

    #[test]
    fn symbt3_n8_current_n7b_object_fails_closed_before_authority() {
        let proof = assert_honest_full_n7b_verifies(1);
        let descriptor = build_symbt3_n8_integrated_k6a_native_whir_relation_descriptor(
            &proof.wrapper.k6a_adapter,
            &proof.wrapper.native_tuple_leaf,
            &proof.k6a_main_proof,
        )
        .expect("N8 descriptor builds from current N7b object");

        let report = verify_symbt3_n8_integrated_k6a_native_whir_relation_gate(&descriptor);
        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::IntegratedSemanticChecksIncomplete)
        );

        let (pk, vk) = WhirSnark::setup(&relation());
        let mut inputs = N8IntegratedWhirProofInputs::from_descriptor(&descriptor);
        inputs.legacy_k6a_proof = Some(&proof.k6a_main_proof);
        inputs.legacy_tuple_leaf_proof = Some(&proof.wrapper.native_tuple_leaf.proof);
        let proof_err = prove_symbt3_n8_integrated_whir_non_zk(&pk, &inputs)
            .expect_err("N8 prover skeleton remains fail-closed");
        assert_eq!(
            proof_err,
            Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt
        );
        let report = verify_symbt3_n8_integrated_whir_non_zk(&vk, &inputs);
        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N8IntegratedPrototypeBlocker::SplitK6aTupleDelegationAttempt)
        );
    }

    #[test]
    fn symbt3_n7b_full_helper_rejects_stale_components_and_mutations() {
        let fixture = k6a_adapter_fixture_with_batch_size(1);
        let other = k6a_adapter_fixture_with_batch_size(2);
        let proof = prove_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.pk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &fixture.accumulator_witness,
        )
        .expect("full N7b proof");
        assert!(verify_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &proof,
        ));

        let mut stale_k6a = proof.clone();
        stale_k6a.k6a_main_proof = other.proof;
        let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &stale_k6a,
        );
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N7bFullAuthorityBlocker::K6aProofMismatch)
        );

        let other_proof = prove_symbt3_native_accumulator_authority_full_non_zk(
            &other.pk,
            &other.profile,
            &other.accumulator_instance,
            &other.accumulator_witness,
        )
        .expect("other full N7b proof");
        let mut stale_native = proof.clone();
        stale_native.wrapper.native_tuple_leaf = other_proof.wrapper.native_tuple_leaf;
        stale_native.wrapper.binding_digest = build_symbt3_n7b_full_authority_binding_digest(
            &symbt3_n7b_full_authority_binding_inputs(
                &stale_native.wrapper.k6a_adapter,
                &stale_native.wrapper.native_tuple_leaf,
            ),
        );
        let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &stale_native,
        );
        assert!(!report.ok);

        let mut bad_binding = proof.clone();
        bad_binding.wrapper.binding_digest = digest(b"n7b-full-helper-bad-binding");
        let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &bad_binding,
        );
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N7bFullAuthorityBlocker::BindingDigestMismatch)
        );

        let mut weak_rlc = proof.clone();
        weak_rlc.wrapper.counters.rlc_repetition_count = 1;
        weak_rlc.wrapper.counters.total_rlc_batching_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
        weak_rlc.wrapper.counters.effective_soundness_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
        weak_rlc.wrapper.counters.rlc_batching_bits = SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
        let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &weak_rlc,
        );
        assert!(!report.ok);

        let mut public_canonical = proof;
        public_canonical.proof_kind = ProductProofKind::MonolithicTypedCp;
        let report = verify_symbt3_native_accumulator_authority_full_non_zk_report(
            &fixture.vk,
            &fixture.profile,
            &fixture.accumulator_instance,
            &public_canonical,
        );
        assert!(!report.ok);
        assert_eq!(
            report.blocker,
            Some(Symbt3N7bFullAuthorityBlocker::PublicCanonicalOrMonolithicAuthority)
        );
    }

    #[test]
    fn symbt3_n7b_full_binding_digest_is_deterministic_and_field_bound() {
        let fixture = k6a_adapter_fixture();
        let (_, native_tuple_leaf) = k6a_compatible_n7b_tuple_leaf_parts(&fixture.adapter);
        let inputs = symbt3_n7b_full_authority_binding_inputs(&fixture.adapter, &native_tuple_leaf);
        let binding_digest = build_symbt3_n7b_full_authority_binding_digest(&inputs);
        assert_eq!(
            binding_digest,
            build_symbt3_n7b_full_authority_binding_digest(&inputs)
        );

        let mut changed = inputs.clone();
        changed.main_symbt3_proof_digest = digest(b"n7b-changed-k6a-proof-digest");
        assert_ne!(
            binding_digest,
            build_symbt3_n7b_full_authority_binding_digest(&changed)
        );

        let mut changed = inputs.clone();
        changed.tuple_leaf_root = digest(b"n7b-changed-tuple-leaf-root");
        assert_ne!(
            binding_digest,
            build_symbt3_n7b_full_authority_binding_digest(&changed)
        );

        let mut changed = inputs.clone();
        changed.old_accumulator_digest = digest(b"n7b-changed-old-accumulator");
        assert_ne!(
            binding_digest,
            build_symbt3_n7b_full_authority_binding_digest(&changed)
        );

        let mut changed = inputs;
        changed.new_accumulator_digest = digest(b"n7b-changed-new-accumulator");
        assert_ne!(
            binding_digest,
            build_symbt3_n7b_full_authority_binding_digest(&changed)
        );
    }

    #[test]
    fn symbt3_n7b_full_wrapper_advances_past_repeated_rlc_blocker_when_evidence_verifies() {
        let fixture = k6a_adapter_fixture();
        let (tuple_leaf_vk, native_tuple_leaf) =
            k6a_compatible_n7b_tuple_leaf_parts(&fixture.adapter);
        let wrapper =
            compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
                workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
                k6a_adapter: Some(fixture.adapter.clone()),
                native_tuple_leaf: Some(native_tuple_leaf),
                binding_digest: None,
                fallback_used: false,
            })
            .expect("N7b full wrapper has all typed components");
        assert_eq!(
            wrapper.binding_digest,
            build_symbt3_n7b_full_authority_binding_digest(
                &symbt3_n7b_full_authority_binding_inputs(
                    &wrapper.k6a_adapter,
                    &wrapper.native_tuple_leaf,
                )
            )
        );
        assert!(wrapper.counters.full_accumulator_workload);
        assert!(!wrapper.counters.smoke_profile);
        assert_eq!(wrapper.counters.whir_instance_count, 1);
        assert_eq!(wrapper.counters.root_count, 1);
        assert_eq!(wrapper.counters.family_columnar_subproof_count, 0);
        assert_eq!(
            wrapper.counters.rlc_repetition_count,
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        );
        let report = verify_symbt3_n7b_full_authority_wrapper_non_zk(
            &Symbt3N7bFullAuthorityVerificationContext {
                k6a_vk: &fixture.vk,
                tuple_leaf_vk: &tuple_leaf_vk,
                profile: &fixture.profile,
                accumulator_instance: &fixture.accumulator_instance,
                proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                k6a_proof: &fixture.proof,
            },
            &wrapper,
        );
        assert!(report.ok);
        assert!(!report.blocked);
        assert_eq!(report.blocker, None);
    }

    #[test]
    fn symbt3_n7b_full_wrapper_rejects_weak_or_missing_repeated_rlc_evidence() {
        let fixture = k6a_adapter_fixture();
        for (repetition_count, bits_per_repetition) in [(1usize, 31usize), (4, 0), (4, 20)] {
            let (tuple_leaf_vk, native_tuple_leaf) =
                k6a_compatible_n7b_tuple_leaf_parts_with_repetitions(
                    &fixture.adapter,
                    repetition_count,
                    bits_per_repetition,
                );
            let wrapper =
                compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
                    workload_kind: Some(
                        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1,
                    ),
                    k6a_adapter: Some(fixture.adapter.clone()),
                    native_tuple_leaf: Some(native_tuple_leaf),
                    binding_digest: None,
                    fallback_used: false,
                })
                .expect("weak-RLC wrapper is structurally composed");
            let report = verify_symbt3_n7b_full_authority_wrapper_non_zk(
                &Symbt3N7bFullAuthorityVerificationContext {
                    k6a_vk: &fixture.vk,
                    tuple_leaf_vk: &tuple_leaf_vk,
                    profile: &fixture.profile,
                    accumulator_instance: &fixture.accumulator_instance,
                    proof_kind: ProductProofKind::Symbt3AccumulatorNonZkIntegrity,
                    k6a_proof: &fixture.proof,
                },
                &wrapper,
            );
            assert!(!report.ok);
            assert!(report.blocked);
            assert_eq!(
                report.blocker,
                Some(Symbt3N7bFullAuthorityBlocker::RepeatedRlcSoundnessMissingOrWeak)
            );
        }
    }

    #[test]
    fn symbt3_n7b_full_wrapper_rejects_missing_tuple_smoke_and_bad_binding() {
        let fixture = k6a_adapter_fixture();
        assert_eq!(
            compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
                workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
                k6a_adapter: Some(fixture.adapter.clone()),
                native_tuple_leaf: None,
                binding_digest: None,
                fallback_used: false,
            })
            .unwrap_err(),
            Symbt3N7bFullAuthorityBlocker::MissingNativeTupleLeafProof
        );

        let (_, native_tuple_leaf) = k6a_compatible_n7b_tuple_leaf_parts(&fixture.adapter);
        let mut smoke_adapter = fixture.adapter.clone();
        smoke_adapter.full_accumulator_workload = false;
        smoke_adapter.smoke_profile = true;
        assert_eq!(
            compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
                workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
                k6a_adapter: Some(smoke_adapter),
                native_tuple_leaf: Some(native_tuple_leaf.clone()),
                binding_digest: None,
                fallback_used: false,
            })
            .unwrap_err(),
            Symbt3N7bFullAuthorityBlocker::SmokeProfile
        );

        assert_eq!(
            compose_symbt3_n7b_full_authority_wrapper(Symbt3N7bFullAuthorityWrapperParts {
                workload_kind: Some(Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1),
                k6a_adapter: Some(fixture.adapter.clone()),
                native_tuple_leaf: Some(native_tuple_leaf),
                binding_digest: Some(digest(b"n7b-wrong-binding")),
                fallback_used: false,
            })
            .unwrap_err(),
            Symbt3N7bFullAuthorityBlocker::BindingDigestMismatch
        );
    }

    #[test]
    fn symbt3_n7b_full_wrapper_keeps_default_verify_public_routing_unchanged() {
        assert!(WhirSnark::has_authoritative_typed_cp());
        let smoke = n7_fixture(1, 1);
        assert!(verify_symbt3_native_accumulator_authority_non_zk(
            &smoke.vk,
            &smoke.instance,
            &smoke.proof,
        ));
        assert!(symbt3_native_accumulator_k6a_workload_adapter(
            Symbt3NativeAccumulatorK6aWorkloadAdapterInput::NativeN7Smoke {
                instance: &smoke.instance,
                proof: &smoke.proof,
            },
        )
        .is_none());
    }

    #[test]
    fn symbt3_n7_rejects_k6a_monolithic_and_compatibility_routes() {
        let fixture = n7_fixture(1, 1);

        let mut proof = fixture.proof.clone();
        proof.proof_kind = Symbt3NativeFoldingProofKind::PublicCanonicalK6aV1;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
        assert!(symbt3_k6a_public_canonical_route_accepts_proof_kind(
            proof.proof_kind
        ));

        let mut proof = fixture.proof.clone();
        proof.proof_kind = Symbt3NativeFoldingProofKind::MonolithicTypedCpV1;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
        assert!(symbt3_monolithic_typed_cp_route_accepts_proof_kind(
            proof.proof_kind
        ));

        let n6a = n6a_fixture(1, 1);
        assert!(!symbt3_k6a_public_canonical_route_accepts_proof_kind(
            fixture.proof.proof_kind
        ));
        assert!(!verify_n6a_fixture(&n6a, &fixture.instance, &n6a.proof));

        let mut proof = fixture.proof.clone();
        proof.counters.whir_instance_count = 2;
        proof.counters.native_multi_oracle = false;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
    }

    #[test]
    fn symbt3_n7_rejects_profile_gate_failures() {
        let fixture = n7_fixture(1, 1);

        let mut instance = fixture.instance.clone();
        instance.manifest_policy = ManifestCommitmentPolicy::PublicCanonicalManifestViewV1;
        instance.committed_private_component_count = 0;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.message_oracle_policy = Symbt3MessageOraclePolicy::DigestOnlyMessageRootsV1;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.zk_status = Symbt3ZkStatus::ZkRequired;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.semantic_profile_version =
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_MIN_SEMANTIC_PROFILE_VERSION - 1;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance
            .required_semantic_families
            .production_norm_range_bundle = false;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut instance = fixture.instance.clone();
        instance.monolithic_fallback = true;
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut proof = fixture.proof.clone();
        proof.counters.family_columnar_subproof_count = 1;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut metadata = symbt3_native_accumulator_authority_profile_metadata(
            &fixture.instance,
            &fixture.proof.counters,
        );
        metadata.rlc_batching_bits = None;
        let report = symbt3_native_accumulator_authority_profile_report(&metadata);
        assert!(!report.ok);
        assert!(!report.rlc_soundness_ok);
    }

    #[test]
    fn symbt3_n7_rejects_binding_and_digest_mutations() {
        let fixture = n7_fixture(1, 1);

        let mut proof = fixture.proof.clone();
        proof.native_binding_digest = digest(b"n7-wrong-binding");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.profile_digest = digest(b"n7-wrong-profile");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.accumulator_instance_digest = digest(b"n7-wrong-instance");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.public_statement_digest = digest(b"n7-wrong-public-statement");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.whir_param_digest = digest(b"n7-wrong-whir-params");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.native_oracle_descriptor_digest = digest(b"n7-wrong-descriptor");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.rlc_tuple_leaf_root = digest(b"n7-wrong-rlc-root");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.native_message_roots_digest = digest(b"n7-wrong-message-roots");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.old_accumulator_digest = digest(b"n7-wrong-old-acc");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.new_accumulator_digest = digest(b"n7-wrong-new-acc");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
    }

    #[test]
    fn symbt3_n7_rejects_tuple_leaf_native_and_accumulator_mutations() {
        let fixture = n7_fixture(2, 1);

        let mut proof = fixture.proof.clone();
        proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[2].value += BabyBear::ONE;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.rlc_tuple_leaf_multi_oracle_proof.packed_eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof
            .rlc_tuple_leaf_multi_oracle_proof
            .packing_challenge_digest = digest(b"n7-wrong-packing-domain");
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof
            .rlc_tuple_leaf_multi_oracle_proof
            .logical_descriptors
            .swap(1, 2);
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[0].claim_kind =
            WhirNativeEvalClaimKind::EqualitySide;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let two_round = n7_fixture(1, 2);
        let mut proof = two_round.proof.clone();
        proof.native_message_roots.swap(0, 1);
        assert!(!verify_n7_fixture(&two_round, &two_round.instance, &proof));

        let item_style = n7_fixture(2, 4);
        assert_eq!(fixture.proof.counters.native_message_oracle_count, 1);
        assert_eq!(item_style.proof.counters.native_message_oracle_count, 4);
        assert!(!verify_n7_fixture(
            &fixture,
            &fixture.instance,
            &item_style.proof
        ));

        let mut instance = fixture.instance.clone();
        instance.folded_output_digest = digest(b"n7-mutated-folded-output");
        assert!(!verify_n7_fixture(&fixture, &instance, &fixture.proof));

        let mut proof = fixture.proof.clone();
        proof.main_symbt3_whir_proof.z_eval += BabyBear::ONE;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
    }

    #[test]
    fn symbt3_n7_rejects_stale_main_or_native_components() {
        let fixture = n7_fixture(1, 1);
        let stale = n7_fixture(2, 1);

        let mut proof = fixture.proof.clone();
        proof.main_symbt3_whir_proof = stale.proof.main_symbt3_whir_proof.clone();
        proof.main_symbt3_proof_digest =
            symbt3_main_whir_proof_digest(&proof.main_symbt3_whir_proof);
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));

        let mut proof = fixture.proof.clone();
        proof.rlc_tuple_leaf_multi_oracle_proof =
            stale.proof.rlc_tuple_leaf_multi_oracle_proof.clone();
        proof.rlc_tuple_leaf_root = proof.rlc_tuple_leaf_multi_oracle_proof.packed_root;
        proof.rlc_tuple_leaf_layout_digest = proof
            .rlc_tuple_leaf_multi_oracle_proof
            .tuple_leaf_layout_digest;
        assert!(!verify_n7_fixture(&fixture, &fixture.instance, &proof));
    }

    #[test]
    fn symbt3_n1bench_helpers_build_sorted_specs_and_evals() {
        let specs = build_native_oracle_benchmark_specs(4, 5).expect("N1bench specs");
        assert_eq!(specs.len(), 4);
        assert!(specs
            .windows(2)
            .all(|pair| pair[0].oracle_id < pair[1].oracle_id));
        assert!(specs
            .iter()
            .all(|spec| spec.num_vars == 5 && spec.role == WhirNativeOracleRole::Auxiliary));

        let requests = build_native_oracle_benchmark_eval_requests(
            &specs,
            WhirNativeEvalClaimKind::DirectOpening,
        );
        assert_eq!(requests.len(), specs.len());
        assert!(requests
            .iter()
            .zip(specs.iter())
            .all(|(request, spec)| request.oracle_id == spec.oracle_id
                && request.claim_kind == WhirNativeEvalClaimKind::DirectOpening));

        let evals = build_native_oracle_benchmark_evals(&specs, 17).expect("N1bench evals");
        assert_eq!(evals.len(), specs.len());
        assert!(evals.iter().all(|oracle| oracle.len() == 32));
    }

    #[test]
    fn symbt3_n1bench_batch_axis_keeps_oracle_count_fixed() {
        let round_count = 2usize;
        let message_axis_log_size = 3usize;
        for k in [1usize, 2, 4, 8] {
            let batch_log_size = k.trailing_zeros() as usize;
            let specs = build_native_oracle_batch_axis_benchmark_specs(
                round_count,
                batch_log_size,
                message_axis_log_size,
            )
            .expect("N1bench batch-axis specs");
            assert_eq!(specs.len(), round_count);
            assert!(specs.iter().enumerate().all(|(round, spec)| spec.oracle_id
                == SYMBT3_N4_MESSAGE_ORACLE_ID_BASE + round as u32
                && spec.num_vars == batch_log_size + message_axis_log_size
                && spec.role
                    == WhirNativeOracleRole::MessageRound {
                        round: round as u32
                    }));
        }
    }

    fn tuple_leaf_fixture(
        logical_oracle_count: usize,
    ) -> (
        WhirProvingKey,
        WhirVerifyingKey,
        Digest32,
        Digest32,
        Digest32,
        Vec<WhirNativeOracleSpec>,
        Vec<Vec<BabyBear>>,
        Vec<WhirNativeEvalRequest>,
        Symbt3TupleLeafMultiOracleProof,
    ) {
        let (pk, vk) = WhirSnark::setup(&relation());
        let proof_relation_id = digest(b"m1b-proof-relation");
        let public_statement_digest = digest(b"m1b-public-statement");
        let whir_param_digest = digest(b"m1b-whir-params");
        let specs =
            build_native_oracle_benchmark_specs(logical_oracle_count, 3).expect("M1b specs");
        let evaluations = build_native_oracle_benchmark_evals(&specs, 77).expect("M1b evals");
        let requests = build_native_oracle_benchmark_eval_requests(
            &specs,
            WhirNativeEvalClaimKind::DirectOpening,
        );
        let proof = whir_commit_and_prove_same_domain_multi_oracle(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &specs,
            &evaluations,
            &requests,
        )
        .expect("M1b tuple-leaf proof");
        (
            pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            specs,
            evaluations,
            requests,
            proof,
        )
    }

    #[test]
    fn same_domain_tuple_leaf_two_oracles_verifies() {
        let (
            _pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            _specs,
            _evaluations,
            _requests,
            proof,
        ) = tuple_leaf_fixture(2);
        assert!(whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &proof,
            &proof.logical_eval_claims,
        ));
        assert_eq!(proof.counters.logical_oracle_count, 2);
        assert_eq!(proof.counters.whir_instance_count, 1);
        assert_eq!(proof.counters.root_count, 1);
        assert_eq!(proof.counters.query_schedule_count, 1);
        assert_eq!(proof.counters.transcript_count, 1);
        assert_eq!(proof.counters.native_oracle_pcs_opening_count, 1);
        assert_eq!(
            proof.counters.rlc_repetition_count,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
        );
        assert_eq!(
            proof.counters.rlc_batching_bits_per_repetition,
            SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        );
        assert_eq!(
            proof.counters.total_rlc_batching_bits,
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT * SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        );
        assert_eq!(
            proof.counters.effective_soundness_bits,
            proof.counters.total_rlc_batching_bits
        );
        assert_eq!(
            proof.counters.tuple_leaf_layout,
            SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT
        );
    }

    #[test]
    fn same_domain_tuple_leaf_four_oracles_exposes_logical_claims_and_packed_value() {
        let (
            _pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            specs,
            evaluations,
            _requests,
            proof,
        ) = tuple_leaf_fixture(4);
        assert!(whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &proof,
            &proof.logical_eval_claims,
        ));
        assert_eq!(
            proof.packed_eval_claims.len(),
            SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
        );
        assert_eq!(
            proof.logical_eval_claims.len(),
            specs.len() * SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT
        );
        for repetition_index in 0..SYMBT3_RLC_TUPLE_LEAF_REPETITION_COUNT {
            let point = derive_same_domain_tuple_leaf_opening_point_for_repetition(
                repetition_index,
                proof_relation_id,
                public_statement_digest,
                whir_param_digest,
                proof.descriptor_digest,
                proof.tuple_leaf_layout_digest,
                WhirNativeEvalClaimKind::DirectOpening,
                specs[0].num_vars,
            );
            let start = repetition_index * specs.len();
            let claims = &proof.logical_eval_claims[start..start + specs.len()];
            for (claim, evaluations) in claims.iter().zip(evaluations.iter()) {
                assert_eq!(claim.value, mle_eval_bb(evaluations, &point));
            }
            let challenges = symbt3_tuple_leaf_packing_challenges_for_repetition(
                proof.mode,
                repetition_index,
                proof_relation_id,
                public_statement_digest,
                whir_param_digest,
                proof.descriptor_digest,
                proof.tuple_leaf_layout_digest,
                proof.logical_descriptors.len(),
                specs[0].num_vars,
            )
            .expect("M1b repetition packing challenges");
            let logical_values = claims.iter().map(|claim| claim.value).collect::<Vec<_>>();
            assert_eq!(
                proof.packed_eval_claims[repetition_index].value,
                symbt3_tuple_leaf_pack_values(&challenges, &logical_values).unwrap()
            );
        }
    }

    #[test]
    fn same_domain_tuple_leaf_byte_accounting_sections_sum_to_total() {
        let (_, _, _, _, _, _, _, _, proof) = tuple_leaf_fixture(4);
        let sections = proof.accounting_byte_sections();
        let pcs_json_bytes =
            serde_json::to_vec(&proof.whir_pcs_proof).expect("tuple PCS proof serializes");
        let pcs_compact_bytes = whir_pcs_compact_canonical_bytes(&proof.whir_pcs_proof)
            .expect("tuple PCS proof compact-serializes");
        let expected_total = proof.metadata_canonical_bytes().len() + 8 + pcs_compact_bytes.len();
        assert_eq!(sections.total_bytes, expected_total);
        assert_eq!(
            sections.total_bytes,
            sections.descriptor_layout_profile_metadata_bytes
                + sections.duplicated_main_k6a_context_bytes
                + sections.logical_eval_claim_bytes
                + sections.repeated_rlc_claim_bytes
                + sections.pcs_payload_length_prefix_bytes
                + sections.pcs_compact_canonical_payload_bytes
        );
        assert_eq!(sections.pcs_legacy_json_payload_bytes, pcs_json_bytes.len());
        assert_eq!(
            sections.pcs_legacy_json_payload_bytes,
            sections.pcs_merkle_root_path_payload_bytes
                + sections.pcs_query_value_payload_bytes
                + sections.pcs_transcript_payload_bytes
                + sections.pcs_json_framing_bytes
        );
        assert!(sections.pcs_merkle_root_path_payload_bytes > 0);
        assert!(sections.pcs_query_value_payload_bytes > 0);
        assert!(sections.repeated_rlc_claim_bytes > 0);
        assert_eq!(proof.counters.whir_instance_count, 1);
        assert_eq!(proof.counters.root_count, 1);
        assert_eq!(proof.counters.query_schedule_count, 1);
        assert_eq!(proof.counters.native_oracle_pcs_opening_count, 1);
    }

    fn mutate_first_json_number(value: &mut serde_json::Value) -> bool {
        match value {
            serde_json::Value::Number(number) => {
                let next = number.as_u64().unwrap_or(0).wrapping_add(1);
                *value = serde_json::Value::from(next);
                true
            }
            serde_json::Value::Array(values) => values.iter_mut().any(mutate_first_json_number),
            serde_json::Value::Object(fields) => fields.values_mut().any(mutate_first_json_number),
            _ => false,
        }
    }

    fn mutate_first_query_field_number(
        proof: &WhirPcsProof<F, EF, WhirMmcs>,
        field: &str,
    ) -> WhirPcsProof<F, EF, WhirMmcs> {
        let mut value = serde_json::to_value(proof).expect("PCS proof JSON value");
        let mut mutated = false;
        if let Some(rounds) = value
            .get_mut("rounds")
            .and_then(serde_json::Value::as_array_mut)
        {
            for round in rounds {
                if let Some(queries) = round
                    .get_mut("queries")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for query in queries {
                        if let Some(target) = query.get_mut(field) {
                            mutated = mutate_first_json_number(target);
                            if mutated {
                                break;
                            }
                        }
                    }
                }
                if mutated {
                    break;
                }
            }
        }
        if !mutated {
            if let Some(queries) = value
                .get_mut("final_queries")
                .and_then(serde_json::Value::as_array_mut)
            {
                for query in queries {
                    if let Some(target) = query.get_mut(field) {
                        mutated = mutate_first_json_number(target);
                        if mutated {
                            break;
                        }
                    }
                }
            }
        }
        assert!(mutated, "expected to mutate query field {field}");
        serde_json::from_value(value).expect("mutated PCS proof remains structurally valid")
    }

    #[test]
    fn same_domain_tuple_leaf_compact_pcs_encoding_roundtrips_and_mutations_reject() {
        let (
            _pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            _specs,
            _evaluations,
            _requests,
            proof,
        ) = tuple_leaf_fixture(4);
        let compact =
            whir_pcs_compact_canonical_bytes(&proof.whir_pcs_proof).expect("compact PCS encoding");
        let decoded =
            whir_pcs_from_compact_canonical_bytes(&compact).expect("compact PCS decoding");
        assert_eq!(
            serde_json::to_value(&decoded).expect("decoded PCS JSON"),
            serde_json::to_value(&proof.whir_pcs_proof).expect("original PCS JSON")
        );
        let mut compact_roundtrip = proof.clone();
        compact_roundtrip.whir_pcs_proof = decoded;
        assert!(whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &compact_roundtrip,
            &compact_roundtrip.logical_eval_claims,
        ));

        let mut sibling_mutation = proof.clone();
        sibling_mutation.whir_pcs_proof =
            mutate_first_query_field_number(&sibling_mutation.whir_pcs_proof, "proof");
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &sibling_mutation,
            &sibling_mutation.logical_eval_claims,
        ));

        let mut opened_value_mutation = proof;
        opened_value_mutation.whir_pcs_proof =
            mutate_first_query_field_number(&opened_value_mutation.whir_pcs_proof, "values");
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &opened_value_mutation,
            &opened_value_mutation.logical_eval_claims,
        ));
    }

    #[test]
    fn same_domain_tuple_leaf_rejects_mixed_domains_duplicate_ids_and_schedule_mix() {
        let (pk, _vk) = WhirSnark::setup(&relation());
        let proof_relation_id = digest(b"m1b-bad-relation");
        let public_statement_digest = digest(b"m1b-bad-public");
        let whir_param_digest = digest(b"m1b-bad-whir");
        let specs = build_native_oracle_benchmark_specs(2, 3).expect("M1b specs");
        let evaluations = build_native_oracle_benchmark_evals(&specs, 91).expect("M1b evals");
        let requests = build_native_oracle_benchmark_eval_requests(
            &specs,
            WhirNativeEvalClaimKind::DirectOpening,
        );

        let mut mixed_num_vars = specs.clone();
        mixed_num_vars[1].num_vars = 4;
        assert!(whir_commit_and_prove_same_domain_multi_oracle(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &mixed_num_vars,
            &evaluations,
            &requests,
        )
        .is_none());

        let mut duplicate_id = specs.clone();
        duplicate_id[1].oracle_id = duplicate_id[0].oracle_id;
        assert!(whir_commit_and_prove_same_domain_multi_oracle(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &duplicate_id,
            &evaluations,
            &requests,
        )
        .is_none());

        let mut schedule_mix = specs.clone();
        schedule_mix[1].opening_schedule = WhirNativeOpeningSchedule::SamePoint;
        assert!(whir_commit_and_prove_same_domain_multi_oracle(
            &pk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &schedule_mix,
            &evaluations,
            &requests,
        )
        .is_none());
    }

    #[test]
    fn same_domain_tuple_leaf_rejects_replays_and_mutations() {
        let (
            _pk,
            vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            _specs,
            _evaluations,
            _requests,
            proof,
        ) = tuple_leaf_fixture(4);
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            digest(b"m1b-stale-public"),
            whir_param_digest,
            &proof,
            &proof.logical_eval_claims,
        ));
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            digest(b"m1b-stale-whir"),
            &proof,
            &proof.logical_eval_claims,
        ));

        let mut descriptor_swap = proof.clone();
        descriptor_swap.logical_descriptors.swap(0, 1);
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &descriptor_swap,
            &descriptor_swap.logical_eval_claims,
        ));

        let mut logical_value_mutation = proof.clone();
        logical_value_mutation.logical_eval_claims[0].value += BabyBear::ONE;
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &logical_value_mutation,
            &logical_value_mutation.logical_eval_claims,
        ));

        let mut packed_value_mutation = proof.clone();
        packed_value_mutation.packed_eval_claims[0].value += BabyBear::ONE;
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &packed_value_mutation,
            &packed_value_mutation.logical_eval_claims,
        ));

        let mut domain_mutation = proof.clone();
        domain_mutation.packing_challenge_digest = digest(b"m1b-wrong-rlc-domain");
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &domain_mutation,
            &domain_mutation.logical_eval_claims,
        ));

        let mut layout_domain_mutation = proof.clone();
        layout_domain_mutation.tuple_leaf_layout_digest = digest(b"m1b-wrong-layout-domain");
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &layout_domain_mutation,
            &layout_domain_mutation.logical_eval_claims,
        ));

        let mut packed_repetition_swap = proof.clone();
        packed_repetition_swap.packed_eval_claims.swap(0, 1);
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &packed_repetition_swap,
            &packed_repetition_swap.logical_eval_claims,
        ));

        let mut logical_repetition_swap = proof.clone();
        let width = logical_repetition_swap.logical_descriptors.len();
        for offset in 0..width {
            logical_repetition_swap
                .logical_eval_claims
                .swap(offset, width + offset);
        }
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &logical_repetition_swap,
            &logical_repetition_swap.logical_eval_claims,
        ));

        let mut point_mutation = proof.clone();
        point_mutation.logical_eval_claims[0].point_digest = digest(b"m1b-wrong-point");
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &point_mutation,
            &point_mutation.logical_eval_claims,
        ));

        let mut claim_kind_mutation = proof.clone();
        claim_kind_mutation.logical_eval_claims[0].claim_kind =
            WhirNativeEvalClaimKind::MessageView;
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &claim_kind_mutation,
            &claim_kind_mutation.logical_eval_claims,
        ));

        let mut whir_instance_count_mutation = proof.clone();
        whir_instance_count_mutation.counters.whir_instance_count = 2;
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &whir_instance_count_mutation,
            &whir_instance_count_mutation.logical_eval_claims,
        ));

        let mut root_count_mutation = proof;
        root_count_mutation.counters.root_count = 2;
        assert!(!whir_verify_same_domain_multi_oracle(
            &vk,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            &root_count_mutation,
            &root_count_mutation.logical_eval_claims,
        ));
    }

    #[test]
    fn native_oracle_descriptor_digest_stability() {
        let (_, _, _, _, _, _, _, _, proof) = native_oracle_fixture();
        let digest_a = native_oracle_descriptor_digest(&proof.descriptors);
        let digest_b = native_oracle_descriptor_digest(&proof.descriptors);
        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn native_oracle_descriptor_canonical_bytes_are_stable() {
        let (_, _, _, _, _, specs, _, _, proof) = native_oracle_fixture();
        assert_eq!(
            native_oracle_spec_digest(&specs),
            native_oracle_spec_digest(&specs)
        );
        assert_eq!(
            proof.descriptors[0].canonical_bytes(),
            proof.descriptors[0].canonical_bytes()
        );
        assert_ne!(proof.descriptors[0].canonical_bytes(), Vec::<u8>::new());
        assert_eq!(
            proof.descriptors[0].role.canonical_bytes(),
            WhirNativeOracleRole::Manifest.canonical_bytes()
        );
        assert_eq!(
            proof.descriptors[0].opening_schedule.canonical_bytes(),
            specs[0].opening_schedule.canonical_bytes()
        );
    }

    #[test]
    fn native_oracle_eval_claim_canonical_bytes_are_stable() {
        let (_, _, _, _, _, _, _, requests, proof) = native_oracle_fixture();
        assert_eq!(
            requests[0].canonical_bytes(),
            WhirNativeEvalRequest {
                oracle_id: 1,
                claim_kind: WhirNativeEvalClaimKind::EqualitySide,
            }
            .canonical_bytes()
        );
        assert_eq!(
            proof.eval_claims[0].canonical_bytes(),
            proof.eval_claims[0].canonical_bytes()
        );
        assert_eq!(
            proof.eval_claims[0].claim_kind.canonical_bytes(),
            WhirNativeEvalClaimKind::EqualitySide.canonical_bytes()
        );
        assert_eq!(
            proof.native_oracle_eval_claims_digest,
            native_oracle_eval_claims_digest(&proof.eval_claims)
        );
    }

    #[test]
    fn native_oracle_envelope_metadata_digest_is_stable() {
        let (_, _, _, _, _, _, _, _, proof) = native_oracle_fixture();
        let digest_a = native_multi_oracle_envelope_digest(&proof);
        let digest_b = native_multi_oracle_envelope_digest(&proof);
        assert_eq!(digest_a, digest_b);
        assert_eq!(digest_a, proof.native_multi_oracle_envelope_digest);
        assert_eq!(
            proof.metadata_canonical_bytes(),
            proof.metadata_canonical_bytes()
        );
    }

    #[test]
    fn native_oracle_root_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture_with_source(Some(vec![
                BabyBear::from_u32(4),
                BabyBear::from_u32(6),
                BabyBear::from_u32(9),
                BabyBear::from_u32(14),
            ]));
        assert_ne!(proof.descriptors[0].root, proof.descriptors[1].root);
        let lhs_root = proof.descriptors[0].root;
        proof.descriptors[0].root = proof.descriptors[1].root;
        proof.descriptors[1].root = lhs_root;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_oracle_id_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors[0].oracle_id = 9;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_role_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors[0].role = WhirNativeOracleRole::Source;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_layout_digest_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors[0].layout_digest = digest(b"wrong-layout");
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_num_vars_mismatch_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors[0].num_vars = 3;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_opening_point_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.eval_claims[0].point_digest = digest(b"wrong-point");
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_claimed_value_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.eval_claims[0].value += BabyBear::ONE;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_claim_kind_swap_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.eval_claims[0].claim_kind = WhirNativeEvalClaimKind::DirectOpening;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_mutating_descriptor_canonical_bytes_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        let before = proof.descriptors[0].canonical_bytes();
        proof.descriptors[0].layout_digest[0] ^= 0x5a;
        assert_ne!(before, proof.descriptors[0].canonical_bytes());
        proof.native_oracle_descriptor_digest = native_oracle_descriptor_digest(&proof.descriptors);
        refresh_envelope_digest(&mut proof);
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_mutating_eval_claim_canonical_bytes_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        let before = proof.eval_claims[0].canonical_bytes();
        proof.eval_claims[0].value += BabyBear::ONE;
        assert_ne!(before, proof.eval_claims[0].canonical_bytes());
        proof.native_oracle_eval_claims_digest =
            native_oracle_eval_claims_digest(&proof.eval_claims);
        refresh_envelope_digest(&mut proof);
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_root_policy_mismatch_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, proof) =
            native_oracle_fixture();
        assert!(whir_verify_oracle_openings_with_root_policy(
            &vk,
            NativeOracleRootPolicy::CanonicalWhirRootV1,
            relation_id,
            statement_digest,
            whir_digest,
            &proof.descriptors,
            &proof,
            &proof.eval_claims,
        ));
        assert!(!whir_verify_oracle_openings_with_root_policy(
            &vk,
            NativeOracleRootPolicy::DebugDevelopmentOnly,
            relation_id,
            statement_digest,
            whir_digest,
            &proof.descriptors,
            &proof,
            &proof.eval_claims,
        ));
    }

    #[test]
    fn native_oracle_debug_root_policy_rejected_by_authority_profiles() {
        let (pk, vk, relation_id, statement_digest, whir_digest, specs, evals, requests, _) =
            native_oracle_fixture();
        let debug_proof = whir_commit_and_prove_oracles_with_root_policy(
            &pk,
            NativeOracleRootPolicy::DebugDevelopmentOnly,
            relation_id,
            statement_digest,
            whir_digest,
            &specs,
            &evals,
            &requests,
        )
        .expect("debug native oracle proof");

        assert!(whir_verify_oracle_openings_for_profile(
            &vk,
            NativeOracleVerificationProfile::Development,
            relation_id,
            statement_digest,
            whir_digest,
            &debug_proof.descriptors,
            &debug_proof,
            &debug_proof.eval_claims,
        ));
        assert!(!whir_verify_oracle_openings_for_profile(
            &vk,
            NativeOracleVerificationProfile::ProductAuthority,
            relation_id,
            statement_digest,
            whir_digest,
            &debug_proof.descriptors,
            &debug_proof,
            &debug_proof.eval_claims,
        ));
        assert!(!whir_verify_oracle_openings_for_profile(
            &vk,
            NativeOracleVerificationProfile::NativeManifestAuthority,
            relation_id,
            statement_digest,
            whir_digest,
            &debug_proof.descriptors,
            &debug_proof,
            &debug_proof.eval_claims,
        ));
        assert!(!whir_verify_oracle_openings_for_profile(
            &vk,
            NativeOracleVerificationProfile::NativeMessageAuthority,
            relation_id,
            statement_digest,
            whir_digest,
            &debug_proof.descriptors,
            &debug_proof,
            &debug_proof.eval_claims,
        ));
    }

    #[test]
    fn native_oracle_replay_under_different_root_policy_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.root_policy = NativeOracleRootPolicy::DebugDevelopmentOnly;
        refresh_envelope_digest(&mut proof);
        assert!(!whir_verify_oracle_openings_for_profile(
            &vk,
            NativeOracleVerificationProfile::Development,
            relation_id,
            statement_digest,
            whir_digest,
            &proof.descriptors,
            &proof,
            &proof.eval_claims,
        ));
    }

    #[test]
    fn native_oracle_truncated_descriptors_reject() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors.pop();
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_appended_descriptor_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        let mut extra = proof.descriptors[1].clone();
        extra.oracle_id = 3;
        proof.descriptors.push(extra);
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_replay_under_different_public_statement_digest_rejects() {
        let (_, vk, relation_id, _statement_digest, whir_digest, _, _, _, proof) =
            native_oracle_fixture();
        assert!(!verify_fixture(
            &vk,
            relation_id,
            digest(b"different-public-statement"),
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_replay_under_different_whir_param_digest_rejects() {
        let (_, vk, relation_id, statement_digest, _whir_digest, _, _, _, proof) =
            native_oracle_fixture();
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            digest(b"different-whir-params"),
            &proof
        ));
    }

    #[test]
    fn native_oracle_duplicate_oracle_id_rejects() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors[1].oracle_id = proof.descriptors[0].oracle_id;
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }

    #[test]
    fn native_oracle_unsorted_descriptors_reject() {
        let (_, vk, relation_id, statement_digest, whir_digest, _, _, _, mut proof) =
            native_oracle_fixture();
        proof.descriptors.reverse();
        assert!(!verify_fixture(
            &vk,
            relation_id,
            statement_digest,
            whir_digest,
            &proof
        ));
    }
}
