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
};
use crate::folding::digest::Digest32;
use crate::snark::BackendSnark;

use super::{
    canonical_whir_proof_bytes, derive_challenge, mle_eval_bb, whir_commit_and_prove_multi,
    whir_verify_opening_multi, WhirMmcs, WhirPcsProof, WhirProof, WhirProvingKey, WhirSnark,
    WhirVerifyingKey, EF, F,
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
pub const SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS: usize = 31;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT: usize = 4;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_BATCHING_BITS_PER_REPETITION: usize =
    SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_TARGET_SOUNDNESS_BITS: usize = 120;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_SOUNDNESS_BOUND_BITS: usize = 100;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_PROOF_VERSION: u64 = 1;
pub const SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_WRAPPER_VERSION: u64 = 1;
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
    if logical_oracle_count == 0 || num_vars == 0 {
        return None;
    }
    let mut transcript = Vec::new();
    push_bytes(&mut transcript, b"SYMBT3_NATIVE_MULTI_ORACLE_PACKING_V1");
    push_digest(&mut transcript, &proof_relation_id);
    push_digest(&mut transcript, &public_statement_digest);
    push_digest(&mut transcript, &whir_param_digest);
    push_digest(&mut transcript, &descriptor_digest);
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
    let mut transcript = Vec::new();
    push_bytes(
        &mut transcript,
        b"SYMBT3_NATIVE_MULTI_ORACLE_TUPLE_LEAF_OPENING_POINT_V1",
    );
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
    ) == proof.counters
}

fn symbt3_n7b_full_authority_counters(
    adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
    native_tuple_leaf: &Symbt3N7bNativeTupleLeafProofParts,
    fallback_used: bool,
) -> Option<Symbt3NativeAccumulatorAuthorityCounters> {
    let proof = &native_tuple_leaf.proof;
    let native_message_oracle_count = proof.logical_descriptors.len().checked_sub(2)?;
    let rlc_repetition_count = SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT;
    let rlc_batching_bits_per_repetition =
        SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_BATCHING_BITS_PER_REPETITION;
    let total_rlc_batching_bits =
        rlc_repetition_count.saturating_mul(rlc_batching_bits_per_repetition);
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
        effective_soundness_bits: total_rlc_batching_bits,
        native_oracle_eval_claim_count: proof.counters.logical_eval_claim_count,
        fallback_used,
    })
}

fn symbt3_n7b_full_authority_repeated_rlc_evidence_ok(
    proof: &Symbt3N7bFullAuthorityWrapperProof,
) -> bool {
    let counters = &proof.counters;
    counters.rlc_batching_bits > 0
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
    validate_same_domain_tuple_leaf_inputs(logical_specs, logical_evaluations, eval_requests)
        .ok()?;
    let mode = Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1;
    let logical_oracle_count = logical_specs.len();
    let num_vars = logical_specs.first()?.num_vars;
    let descriptor_digest = native_oracle_spec_digest(logical_specs);
    let packing_challenges = symbt3_tuple_leaf_packing_challenges(
        mode,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
    )?;
    let packing_challenge_digest = symbt3_tuple_leaf_packing_challenge_digest(&packing_challenges);
    let layout = Symbt3TupleLeafLayoutV1 {
        version: SYMBT3_TUPLE_LEAF_LAYOUT_VERSION,
        mode,
        logical_oracle_count,
        num_vars,
        packing_challenge_digest,
        descriptor_digest,
    };
    let tuple_leaf_layout_digest = symbt3_tuple_leaf_layout_digest(&layout);
    let claim_kind = eval_requests.first()?.claim_kind;
    let point = derive_same_domain_tuple_leaf_opening_point(
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        tuple_leaf_layout_digest,
        claim_kind,
        num_vars,
    );
    let point_digest = native_oracle_point_digest(&point);

    let evals_by_id = logical_specs
        .iter()
        .zip(logical_evaluations.iter())
        .map(|(spec, evaluations)| (spec.oracle_id, evaluations.as_slice()))
        .collect::<BTreeMap<_, _>>();
    let mut logical_claims = Vec::with_capacity(eval_requests.len());
    for request in eval_requests {
        let evaluations = *evals_by_id.get(&request.oracle_id)?;
        logical_claims.push(WhirNativeOracleEvalClaim {
            oracle_id: request.oracle_id,
            point_digest,
            value: mle_eval_bb(evaluations, &point),
            claim_kind: request.claim_kind,
        });
    }

    let logical_values = logical_claims
        .iter()
        .map(|claim| claim.value)
        .collect::<Vec<_>>();
    let packed_value = symbt3_tuple_leaf_pack_values(&packing_challenges, &logical_values)?;
    let packed_evaluations =
        symbt3_tuple_leaf_pack_evaluations(&packing_challenges, logical_evaluations)?;
    let (whir_pcs_proof, opened_values) =
        whir_commit_and_prove_multi(&pk.seed, num_vars, &packed_evaluations, &[point.clone()]);
    if opened_values != [packed_value] {
        return None;
    }
    let packed_root =
        whir_pcs_initial_root_digest(&whir_pcs_proof, NativeOracleRootPolicy::CanonicalWhirRootV1)?;
    let packed_eval_claims = vec![Symbt3TupleLeafPackedEvalClaim {
        point_digest,
        value: packed_value,
        claim_kind: WhirNativeEvalClaimKind::DirectOpening,
    }];
    let counters = tuple_leaf_counters_for(logical_oracle_count, logical_claims.len(), num_vars);

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
    let descriptor_digest = native_oracle_spec_digest(&proof.logical_descriptors);
    if descriptor_digest != proof.descriptor_digest {
        return false;
    }
    let Some(packing_challenges) = symbt3_tuple_leaf_packing_challenges(
        proof.mode,
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        logical_oracle_count,
        num_vars,
    ) else {
        return false;
    };
    let packing_challenge_digest = symbt3_tuple_leaf_packing_challenge_digest(&packing_challenges);
    if packing_challenge_digest != proof.packing_challenge_digest {
        return false;
    }
    let expected_layout = Symbt3TupleLeafLayoutV1 {
        version: SYMBT3_TUPLE_LEAF_LAYOUT_VERSION,
        mode: proof.mode,
        logical_oracle_count,
        num_vars,
        packing_challenge_digest,
        descriptor_digest,
    };
    if symbt3_tuple_leaf_layout_digest(&expected_layout) != proof.tuple_leaf_layout_digest
        || tuple_leaf_counters_for(
            logical_oracle_count,
            expected_logical_claims.len(),
            num_vars,
        ) != proof.counters
    {
        return false;
    }

    let claim_kind = expected_logical_claims[0].claim_kind;
    let point = derive_same_domain_tuple_leaf_opening_point(
        proof_relation_id,
        public_statement_digest,
        whir_param_digest,
        descriptor_digest,
        proof.tuple_leaf_layout_digest,
        claim_kind,
        num_vars,
    );
    let point_digest = native_oracle_point_digest(&point);
    if expected_logical_claims
        .iter()
        .any(|claim| claim.point_digest != point_digest)
    {
        return false;
    }

    let logical_values = expected_logical_claims
        .iter()
        .map(|claim| claim.value)
        .collect::<Vec<_>>();
    let Some(packed_value) = symbt3_tuple_leaf_pack_values(&packing_challenges, &logical_values)
    else {
        return false;
    };
    let expected_packed_claim = Symbt3TupleLeafPackedEvalClaim {
        point_digest,
        value: packed_value,
        claim_kind: WhirNativeEvalClaimKind::DirectOpening,
    };
    if proof.packed_eval_claims != [expected_packed_claim] {
        return false;
    }
    if whir_pcs_initial_root_digest(
        &proof.whir_pcs_proof,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
    ) != Some(proof.packed_root)
    {
        return false;
    }

    whir_verify_opening_multi(
        &vk.seed,
        num_vars,
        &proof.whir_pcs_proof,
        &[point],
        &[packed_value],
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

/// Fail-closed placeholder for SYMBT3-N7b full-workload native authority.
///
/// The current N7 proof is a smoke profile over a tiny native-oracle fixture
/// relation. It is intentionally not accepted by this full-workload helper
/// until a real adapter wires the K6a accumulator relation and repeated RLC
/// tuple-leaf openings into this proof object.
pub fn prove_symbt3_native_accumulator_authority_full_non_zk(
    _pk: &WhirProvingKey,
    _instance: &Symbt3NativeFoldingIntegrityInstance,
    _witness: &Symbt3NativeFoldingIntegrityWitness,
) -> Option<Symbt3NativeAccumulatorAuthorityProof> {
    None
}

#[must_use]
pub fn verify_symbt3_native_accumulator_authority_full_non_zk(
    vk: &WhirVerifyingKey,
    instance: &Symbt3NativeFoldingIntegrityInstance,
    proof: &Symbt3NativeAccumulatorAuthorityProof,
) -> bool {
    if proof.workload_kind != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || !proof.counters.full_accumulator_workload
        || proof.counters.smoke_profile
    {
        return false;
    }
    let metadata = symbt3_native_accumulator_authority_profile_metadata(instance, &proof.counters);
    profile_meets_native_accumulator_authority_full(&metadata)
        && verify_symbt3_native_accumulator_authority_non_zk(vk, instance, proof)
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
    let packing_challenges = symbt3_tuple_leaf_packing_challenges(
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1,
        instance.symbt3_relation_id,
        instance.public_statement_digest(),
        instance.whir_param_digest,
        descriptor_digest,
        specs.len(),
        common_num_vars,
    )?;
    let packed_evaluations = symbt3_tuple_leaf_pack_evaluations(&packing_challenges, &evaluations)?;
    let packed_root = whir_initial_root_digest(
        seed,
        NativeOracleRootPolicy::CanonicalWhirRootV1,
        common_num_vars,
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
        )
    {
        return None;
    }
    let rlc_repetition_count = match workload_kind {
        Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1 => 1,
        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1 => {
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_REPETITION_COUNT
        }
    };
    let rlc_batching_bits_per_repetition = match workload_kind {
        Symbt3NativeAccumulatorAuthorityWorkload::N7SmokeProfileV1 => {
            SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
        }
        Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1 => {
            SYMBT3_NATIVE_ACCUMULATOR_AUTHORITY_FULL_RLC_BATCHING_BITS_PER_REPETITION
        }
    };
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
        || tuple_proof.logical_eval_claims.len() != tuple_proof.logical_descriptors.len()
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
    for ((descriptor, layout), claim) in message_descriptors
        .iter()
        .zip(instance.round_layouts.iter())
        .zip(proof.rlc_tuple_leaf_multi_oracle_proof.logical_eval_claims[2..].iter())
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
    if specs.len() != claims.len() {
        return Err(());
    }
    let claim_kind = claims.first().ok_or(())?.claim_kind;
    for (spec, claim) in specs.iter().zip(claims.iter()) {
        if claim.oracle_id != spec.oracle_id || claim.claim_kind != claim_kind {
            return Err(());
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
) -> Symbt3TupleLeafMultiOracleCounters {
    let oracle_len = 1usize.checked_shl(num_vars as u32).unwrap_or(0);
    Symbt3TupleLeafMultiOracleCounters {
        logical_oracle_count,
        whir_instance_count: 1,
        query_schedule_count: 1,
        transcript_count: 1,
        root_count: 1,
        native_oracle_pcs_opening_count: 1,
        logical_eval_claim_count,
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
    let (proof, _) = whir_commit_and_prove_multi(seed, num_variables, evaluations, &[]);
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
        vk: WhirVerifyingKey,
        profile: Symbt3AuthorityProfile,
        accumulator_instance: Symbt3AccumulatorInstance,
        proof: WhirProof,
        adapter: Symbt3NativeAccumulatorK6aWorkloadAdapter,
    }

    fn k6a_params() -> SymphonyParams {
        SymphonyParams {
            q: 257,
            d: D,
            kappa: 2,
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
        let params = k6a_params();
        let (prover, _) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params);
        let (r1cs, z) = k6a_r1cs();
        let item = k6a_batched_item(&prover, &r1cs, &z, 1);
        let bucket = BatchedCpBucket::new(vec![item], digest(b"k6a-native-adapter-whir-params"))
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
            vk,
            profile,
            accumulator_instance,
            proof,
            adapter,
        }
    }

    fn k6a_compatible_n7b_tuple_leaf_parts(
        adapter: &Symbt3NativeAccumulatorK6aWorkloadAdapter,
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
        let proof = whir_commit_and_prove_same_domain_multi_oracle(
            &pk,
            adapter.main_symbt3_relation_id,
            adapter.public_statement_digest,
            adapter.whir_param_digest,
            &specs,
            &evaluations,
            &eval_requests,
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
                SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(fixture.proof.counters.rlc_repetition_count, 1);
            assert_eq!(
                fixture.proof.counters.rlc_batching_bits_per_repetition,
                SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(
                fixture.proof.counters.total_rlc_batching_bits,
                SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
            );
            assert_eq!(
                fixture.proof.counters.effective_soundness_bits,
                SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS
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
            Some(SYMBT3_RLC_TUPLE_LEAF_BATCHING_BITS)
        );
    }

    #[test]
    fn symbt3_n7_full_authority_gate_rejects_smoke_profile() {
        let fixture = n7_fixture(1, 1);
        let (pk, _) = WhirSnark::setup(&relation());
        let (_, witness) = n7_instance_witness(1, 1);
        assert!(prove_symbt3_native_accumulator_authority_full_non_zk(
            &pk,
            &fixture.instance,
            &witness
        )
        .is_none());
        assert!(!verify_symbt3_native_accumulator_authority_full_non_zk(
            &fixture.vk,
            &fixture.instance,
            &fixture.proof
        ));

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
    fn symbt3_n7b_k6a_adapter_extracts_full_workload_and_stays_fail_closed() {
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

        let (pk, _) = WhirSnark::setup(&relation());
        let (_, smoke_witness) = n7_instance_witness(1, 1);
        assert!(
            prove_symbt3_native_accumulator_authority_full_non_zk(
                &pk,
                &smoke.instance,
                &smoke_witness,
            )
            .is_none(),
            "N7b full route remains blocked until the K6a adapter is wired into the wrapper"
        );
        assert!(!verify_symbt3_native_accumulator_authority_full_non_zk(
            &smoke.vk,
            &smoke.instance,
            &smoke.proof,
        ));
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
    fn symbt3_n7b_full_wrapper_composes_and_remains_blocked_on_repeated_rlc() {
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
        assert!(!report.ok);
        assert!(report.blocked);
        assert_eq!(
            report.blocker,
            Some(Symbt3N7bFullAuthorityBlocker::RepeatedRlcSoundnessMissingOrWeak)
        );
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
        assert!(!verify_symbt3_native_accumulator_authority_full_non_zk(
            &smoke.vk,
            &smoke.instance,
            &smoke.proof,
        ));
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
        let point = derive_same_domain_tuple_leaf_opening_point(
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            proof.descriptor_digest,
            proof.tuple_leaf_layout_digest,
            WhirNativeEvalClaimKind::DirectOpening,
            specs[0].num_vars,
        );
        for (claim, evaluations) in proof.logical_eval_claims.iter().zip(evaluations.iter()) {
            assert_eq!(claim.value, mle_eval_bb(evaluations, &point));
        }
        let challenges = symbt3_tuple_leaf_packing_challenges(
            proof.mode,
            proof_relation_id,
            public_statement_digest,
            whir_param_digest,
            proof.descriptor_digest,
            proof.logical_descriptors.len(),
            specs[0].num_vars,
        )
        .expect("M1b packing challenges");
        let logical_values = proof
            .logical_eval_claims
            .iter()
            .map(|claim| claim.value)
            .collect::<Vec<_>>();
        assert_eq!(
            proof.packed_eval_claims[0].value,
            symbt3_tuple_leaf_pack_values(&challenges, &logical_values).unwrap()
        );
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
