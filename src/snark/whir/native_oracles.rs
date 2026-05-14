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
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

use crate::folding::digest::Digest32;

use super::{
    derive_challenge, mle_eval_bb, whir_commit_and_prove_multi, whir_verify_opening_multi,
    WhirMmcs, WhirPcsProof, WhirProvingKey, WhirVerifyingKey, EF, F,
};

pub const WHIR_NATIVE_MULTI_ORACLE_PROOF_VERSION: u64 = 1;
pub const WHIR_NATIVE_ORACLE_DESCRIPTOR_VERSION: u64 = 1;
pub const SYMBT3_N2_MANIFEST_ORACLE_ID: u32 = 1;
pub const SYMBT3_N2_SOURCE_ORACLE_ID: u32 = 2;
pub const SYMBT3_N2_MANIFEST_SOURCE_EQUALITY_DOMAIN: &str = "SYMBT3_N2_MANIFEST_SOURCE_EQUALITY";
pub const SYMBT3_N4_MESSAGE_ORACLE_ID_BASE: u32 = 1000;
pub const SYMBT3_N4_ROUND_MESSAGE_VIEW_DOMAIN: &str = "SYMBT3_N4_ROUND_MESSAGE_VIEW";
pub const SYMBT3_NON_ZK_FOLDING_INTEGRITY_MIN_SEMANTIC_PROFILE_VERSION: u32 = 5;

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
pub fn native_oracle_descriptor_bytes_len(descriptors: &[WhirNativeOracleDescriptor]) -> usize {
    descriptors
        .iter()
        .map(|descriptor| descriptor.canonical_bytes().len())
        .sum()
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
    use crate::snark::whir::WhirSnark;
    use crate::snark::{BackendSnark, RelationDescription};
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
