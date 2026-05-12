//! Structured same-shape batched CP relation foundation.
//!
//! This module is deliberately non-authoritative today. It defines the product
//! domain objects P3/P4 needs without changing the current monolithic typed CP
//! public verifier route.

use std::collections::{BTreeMap, BTreeSet};

use crate::commitment::AjtaiParams;
use crate::cp_relation_core::{
    CpFieldRelation, CpPublicStatement, CpRelationError, CpWitnessBundle,
};
use crate::digest_core::{digest_domain_with_scheme, Digest32, PublicDigestScheme};
use crate::params::{D, T};
use crate::r1cs::R1CSMatrices;
use crate::ring::{RingElement, RingVector};
use crate::snark::RelationDescription;

const STRUCTURED_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBTC1\0";
const SEMANTIC_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBTCS1";
const SEMANTIC_V2_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBTC2\0";
const SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBT2C\0";
const SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBT2F\0";
const SYMBT3_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBT3\0\0";
const SEMANTIC_COLUMNAR_V2_LAYOUT_VERSION: u64 = 1;
const SYMBT3_LAYOUT_VERSION: u64 = 10;
const SYMBT3_CHALLENGE_SCHEDULE_VERSION: u64 = 2;
const SYMBT3_RING_ACTION_VERSION: u64 = 1;
const SYMBT3_AJTAI_COMMIT_LAYOUT_VERSION: u64 = 1;
const SYMBT3_R1CS_EVALUATOR_LAYOUT_VERSION: u64 = 1;
const SYMBT3_GR1CS_RESIDUAL_LAYOUT_VERSION: u64 = 1;
const SYMBT3_FOLDED_GR1CS_PRODUCT_RESIDUAL_LAYOUT_VERSION: u64 = 1;
const SYMBT3_ALGEBRA_LAW_VERSION: u64 = 1;
const SYMBT3_AJTAI_LINEAR_ALGEBRA_LAYOUT_VERSION: u64 = 1;
const SYMBT3_AJTAI_NORM_RANGE_LAYOUT_VERSION: u64 = 2;
const SYMBT3_PROJECTION_LAYOUT_VERSION: u64 = 2;
const SYMBT3_RANGE_LAYOUT_VERSION: u64 = 2;
const SYMBT3_MONOMIAL_EMBEDDING_LAYOUT_VERSION: u64 = 1;
const SYMBT3_REPRESENTATIVE_LAYOUT_VERSION: u64 = 1;
const SYMBT3_BATCH_MANIFEST_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MANIFEST_ORACLE_LAYOUT_VERSION: u64 = 1;
const SYMBT3_SOURCE_COLUMN_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_SEMANTIC_LAYOUT_VERSION: u64 = 2;
const SYMBT3_ROUND_MESSAGE_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_SECTION_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_VIEW_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_COORDINATE_MAP_VERSION: u64 = 1;
const SYMBT3_AUTHORITY_PROFILE_VERSION: u64 = 2;
const SYMBT2F_MAX_SECTION_EQUALITY_ROWS: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchedCpError {
    EmptyBatch,
    ShapeMismatch,
    InvalidShape,
    InvalidBatchSize,
    DuplicateItemTag,
    ManifestMismatch,
    WitnessOracleMismatch,
    RoundMessageOracleMismatch,
    RoundMessageCommitmentMismatch,
    ChallengeDigestMismatch,
    InvalidStructuredRelationContext,
    InvalidSemanticRelationContext,
    ItemRelationFailed(usize, CpRelationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchedCpGr1csMessageSectionKind {
    Header,
    HadamardEvals,
    RangePayload,
    MonomialPayload,
    SquareEvals,
    ProjectedValues,
    TrailingFrame,
}

impl BatchedCpGr1csMessageSectionKind {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::HadamardEvals => "hadamard-evals",
            Self::RangePayload => "range-payload",
            Self::MonomialPayload => "monomial-payload",
            Self::SquareEvals => "square-evals",
            Self::ProjectedValues => "projected-values",
            Self::TrailingFrame => "trailing-frame",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpGr1csMessageSection {
    pub kind: BatchedCpGr1csMessageSectionKind,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpAccumulatorShape {
    pub digest_scheme: PublicDigestScheme,
    pub r1cs_num_constraints: usize,
    pub r1cs_num_variables: usize,
    pub r1cs_num_public: usize,
    pub local_public_input_count: usize,
    pub public_statement_len: usize,
    pub num_rounds: usize,
    pub fs_message_lens: Vec<usize>,
    pub fs_commitment_len: usize,
    pub fs_opening_len: usize,
    pub fold_input_commitment_lens: Vec<usize>,
    pub fold_input_public_input_lens: Vec<usize>,
    pub fold_input_eval_message_lens: Vec<usize>,
    pub gr1cs_hadamard_eval_offsets: Vec<Vec<usize>>,
    pub gr1cs_message_sections: Vec<Vec<BatchedCpGr1csMessageSection>>,
    pub original_witness_lens: Vec<usize>,
    pub commitment_kappa: usize,
    pub commitment_d: usize,
    pub folded_public_input_len: usize,
    pub folded_evaluation_count: usize,
    pub folded_output_contribution_len: usize,
    pub whir_parameter_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpStatementShape {
    pub accumulator_shape: CpAccumulatorShape,
    pub shape_id: Digest32,
    pub batch_log_size: usize,
    pub batch_capacity: usize,
    pub active_count: usize,
    pub witness_row_len: usize,
    pub round_message_lens: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpStructuredRelationDescription {
    pub shape: BatchedCpStatementShape,
    pub public_statement_bytes: usize,
    pub product_domain_size: usize,
    pub witness_oracle_row_len: usize,
    pub round_message_oracle_lens: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchedCpOracleByteRange {
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpProductOracleLayout {
    pub byte_len: usize,
    pub packed_field_len: usize,
    pub witness_rows: Vec<BatchedCpOracleByteRange>,
    pub witness_item_tags: Vec<BatchedCpOracleByteRange>,
    pub witness_public_statements: Vec<BatchedCpOracleByteRange>,
    pub witness_folded_output_contributions: Vec<BatchedCpOracleByteRange>,
    pub witness_local_betas: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_fs_commitments: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_fold_input_commitments: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_fold_input_public_inputs: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_fold_input_eval_messages: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_original_witnesses: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_fs_messages: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_fs_openings: Vec<Vec<BatchedCpOracleByteRange>>,
    pub witness_active_markers: Vec<usize>,
    pub round_message_rows: Vec<Vec<BatchedCpOracleByteRange>>,
    pub round_message_active_markers: Vec<Vec<usize>>,
    pub round_message_digest_bodies: Vec<Vec<BatchedCpOracleByteRange>>,
    pub round_message_digest_body_active_markers: Vec<Vec<usize>>,
    pub fs_commitment_bodies: Vec<Vec<BatchedCpOracleByteRange>>,
    pub fs_commitment_body_messages: Vec<Vec<BatchedCpOracleByteRange>>,
    pub fs_commitment_body_openings: Vec<Vec<BatchedCpOracleByteRange>>,
    pub fs_commitment_body_active_markers: Vec<Vec<usize>>,
    pub poseidon_fs_commitment_trace_outputs: Vec<Vec<BatchedCpOracleByteRange>>,
    pub poseidon_fs_commitment_trace_inputs: Vec<Vec<BatchedCpOracleByteRange>>,
    pub poseidon_fs_commitment_trace_aux: Vec<Vec<BatchedCpOracleByteRange>>,
    pub poseidon_fs_commitment_trace_active_markers: Vec<Vec<usize>>,
    pub manifest_active_markers: Vec<usize>,
    pub manifest_item_tags: Vec<BatchedCpOracleByteRange>,
    pub manifest_public_statements: Vec<BatchedCpOracleByteRange>,
    pub manifest_body: BatchedCpOracleByteRange,
    pub batch_challenge_body: BatchedCpOracleByteRange,
    pub challenge_to_beta_body: BatchedCpOracleByteRange,
    pub challenge_to_beta_digest: BatchedCpOracleByteRange,
    pub challenge_to_beta_beta: BatchedCpOracleByteRange,
    pub folded_output_accumulator_body: BatchedCpOracleByteRange,
    pub folded_output_accumulator_root: BatchedCpOracleByteRange,
    pub folded_output_contributions: Vec<BatchedCpOracleByteRange>,
    pub fold_input_reconstruction_body: BatchedCpOracleByteRange,
    pub fold_input_commitments: Vec<Vec<BatchedCpOracleByteRange>>,
    pub fold_input_public_inputs: Vec<Vec<BatchedCpOracleByteRange>>,
    pub fold_input_eval_messages: Vec<Vec<BatchedCpOracleByteRange>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchedCpSemanticConstraintFamily {
    PoseidonDigestCorrectness,
    ManifestMembership,
    RoundMessageBinding,
    ChallengeDerivation,
    ChallengeToBetaBinding,
    FoldedOutputDerivation,
    AjtaiOpeningValidity,
    OriginalR1csValidity,
    ActiveOrDummyPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticRelationDescription {
    pub shape: BatchedCpStatementShape,
    pub oracle_layout: BatchedCpProductOracleLayout,
    pub ajtai_params_digest: Digest32,
    pub ajtai_matrix: Vec<Vec<RingElement>>,
    pub r1cs_matrices_digest: Digest32,
    pub r1cs_matrices: R1CSMatrices,
    pub input_bound: u64,
    pub constraint_families: Vec<BatchedCpSemanticConstraintFamily>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticOracleV2Layout {
    pub byte_len: usize,
    pub packed_field_len: usize,
    pub product_rows: usize,
    pub semantic_column_count: usize,
    pub residual_family_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticRelationV2Description {
    pub semantic: BatchedCpSemanticRelationDescription,
    pub v2_layout: BatchedCpSemanticOracleV2Layout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchedCpSemanticColumnV2Kind {
    ActiveMask,
    InactivePadding,
    ManifestItemTag,
    ManifestPublicStatement,
    RoundMessage,
    DigestBodyMessage,
    ChallengeBodyPackedValue,
    ChallengeToBetaPackedValue,
    PublicPackedValue,
    PoseidonR1csA,
    PoseidonR1csB,
    PoseidonR1csC,
    FoldedOutputExpected,
    FoldedOutputActual,
    AjtaiOpeningExpected,
    AjtaiOpeningActual,
    OriginalR1csA,
    OriginalR1csB,
    OriginalR1csC,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticColumnV2 {
    pub id: usize,
    pub kind: BatchedCpSemanticColumnV2Kind,
    pub label: String,
    pub row_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchedCpSemanticResidualV2Kind {
    Equality,
    Product,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticResidualV2 {
    pub family: BatchedCpSemanticConstraintFamily,
    pub kind: BatchedCpSemanticResidualV2Kind,
    pub label: String,
    pub transcript_label: Vec<u8>,
    pub left_column: usize,
    pub right_column: usize,
    pub aux_columns: Vec<usize>,
    pub row_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticColumnarV2Layout {
    pub layout_version: u64,
    pub column_row_count: usize,
    pub columns: Vec<BatchedCpSemanticColumnV2>,
    pub residuals: Vec<BatchedCpSemanticResidualV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticColumnarV2Description {
    pub semantic: BatchedCpSemanticRelationDescription,
    pub v2_layout: BatchedCpSemanticOracleV2Layout,
    pub columnar_layout: BatchedCpSemanticColumnarV2Layout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticFamilyColumnarV2Table {
    pub family: BatchedCpSemanticConstraintFamily,
    pub kind: BatchedCpSemanticResidualV2Kind,
    pub label: String,
    pub transcript_label: Vec<u8>,
    pub column_kinds: Vec<BatchedCpSemanticColumnV2Kind>,
    pub column_labels: Vec<String>,
    pub row_count: usize,
    pub padded_row_count: usize,
    pub table_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticFamilyColumnarV2Layout {
    pub layout_version: u64,
    pub tables: Vec<BatchedCpSemanticFamilyColumnarV2Table>,
    pub total_field_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticFamilyColumnarV2Description {
    pub semantic: BatchedCpSemanticRelationDescription,
    pub v2_layout: BatchedCpSemanticOracleV2Layout,
    pub family_layout: BatchedCpSemanticFamilyColumnarV2Layout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchedCpSymbt3AlgebraicColumnKind {
    ActiveMask,
    BetaCoefficient,
    FoldedPublicInput,
    FoldedCommitment,
    FoldedEvaluation,
    AjtaiLinearCombination,
    OriginalR1csResidual,
    Gr1csResidual,
    FoldedGr1csProductLeft,
    FoldedGr1csProductRight,
    FoldedGr1csProductOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchedCpSymbt3ConstraintFamily {
    ChallengeToBeta,
    FoldedPublicInputLinearIdentity,
    FoldedCommitmentLinearIdentity,
    FoldedEvaluationLinearIdentity,
    FoldedAccumulatorBoundaryIdentity,
    RingBetaAction,
    FoldedAjtaiOpeningIdentity,
    FoldedAjtaiCommitmentIdentity,
    AjtaiFoldedResidualZero,
    FoldedAjtaiOpeningLinearIdentity,
    FoldedAjtaiCommitmentLinearIdentity,
    FoldedAjtaiMapConsistency,
    FoldedAjtaiProjectionConsistency,
    FoldedAjtaiProjectedRangeBound,
    FoldedAjtaiMonomialEmbeddingConsistency,
    FoldedAjtaiStructuredProjectionConsistency,
    ProjectedOpeningMonomialEmbedding,
    ProjectedOpeningRangeConstantTerm,
    ProjectedOpeningRepresentativeValidity,
    CommittedSourceR1csResidualValidity,
    FoldedGr1csResidualValidity,
    FoldedGr1csProductResidualZeroCheck,
    BatchManifestRootBinding,
    SourceManifestColumnMembership,
    ManifestEvaluationClaim,
    SourceAssignmentRootManifestBinding,
    SourceMessageRootManifestBinding,
    RoundMessageLayoutValidity,
    RoundChallengePrefixBinding,
    NativeMessageOracleViews,
    MessageToTraceColumnBinding,
    SumcheckRoundClaimTransition,
    SumcheckFinalLocalClaimBinding,
    FoldingMessageBoundaryConsistency,
    AccumulatorTransitionConsistency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3RingActionSide {
    Left,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ActivePolicy {
    PrefixActiveCountV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Symbt3ManifestComponentKind {
    PublicInput,
    SourceCommitmentCoordinate,
    SourceEvaluationCoordinate,
    SourceAccumulatorBoundaryCoordinate,
    SourceAjtaiCommitmentCoordinate,
    SourceAssignmentRootCoordinate,
    SourceMessageRootCoordinate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ManifestVisibility {
    PublicBoundaryCoordinate,
    CommittedPrivateRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MembershipMode {
    CoordinateEquality,
    RootDigestEquality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3CommitmentSchemeId {
    WhirDevOracleRootV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ManifestRootPolicy {
    TypedDigestRootV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestCommitmentPolicy {
    DigestOfLayoutAndOracleRootV1,
    PublicCanonicalManifestViewV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageSectionKind {
    SumcheckRoundPolynomial,
    SumcheckClaimValue,
    EvaluationPoint,
    EvaluationValue,
    FoldedOutputCoordinate,
    FoldedGr1csCoordinate,
    AjtaiOpeningCoordinate,
    AjtaiCommitmentCoordinate,
    ProjectionCoordinate,
    RangeWitnessCoordinate,
    BoundaryDigestCoordinate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageAlgebraType {
    BabyBearFieldElement,
    RingCoefficient,
    DigestByteCoordinate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageVisibility {
    CommittedOracleValue,
    PublicChallengeConstant,
    PublicBoundaryCoordinate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageBindingMode {
    OracleToTraceEquality,
    VerifierChallengeConstant,
    SumcheckTransition,
    FinalLocalClaim,
    BoundaryCoordinateEquality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageSemanticMode {
    TypedAlgebraicOracleV1,
    NativeOracleViewV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3TraceKind {
    SumcheckRoundPolynomial,
    SumcheckClaimValue,
    EvaluationPoint,
    EvaluationValue,
    FoldedOutputCoordinate,
    FoldedGr1csCoordinate,
    AjtaiOpeningCoordinate,
    AjtaiCommitmentCoordinate,
    ProjectionCoordinate,
    RangeWitnessCoordinate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MessageCoordinateMapMode {
    ContiguousOffsetV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3FieldExtensionPolicy {
    BaseFieldSingleCheckDevelopment,
    ExtensionFieldAuthorityRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3SumcheckChallengePolicy {
    BaseFieldSingleChallengeDevelopment,
    AuthorityRepetitionOrExtensionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ZkStatus {
    NonZkDevelopment,
    NonZkIntegrityOnly,
    ZkRequiredForProductRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3AuthorityStatus {
    NonAuthoritativeDevelopment,
    AuthorityCandidateV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3SemanticProfile {
    Symbt3J2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3SoundnessStatus {
    DevelopmentOnly,
    SoundnessCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3RoutingStatus {
    ResearchOnly,
    ProductAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ProductPolicy {
    MonolithicTypedCpOnly,
    Symbt3NonZkIntegrityOptIn,
    Symbt3ZkRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductProofKind {
    MonolithicTypedCp,
    Symbt3AccumulatorNonZkIntegrity,
    Symbt2F,
    Symbt2C,
    Symbtc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AuthorityProfile {
    pub version_marker: &'static [u8; 8],
    pub profile_version: u64,
    pub semantic_profile_version: u32,
    pub semantic_version: &'static str,
    pub semantic_profile: Symbt3SemanticProfile,
    pub enabled_families: Vec<BatchedCpSymbt3ConstraintFamily>,
    pub whir_parameter_digest: Digest32,
    pub relation_id: Digest32,
    pub folding_protocol_id: Digest32,
    pub proof_public_statement_schedule: &'static str,
    pub challenge_schedule_digest: Digest32,
    pub fiat_shamir_domain_digest: Digest32,
    pub ring_module_layout_digest: Digest32,
    pub ring_module_law_digest: Digest32,
    pub algebra_law_digest: Digest32,
    pub folded_gr1cs_product_residual_layout_digest: Digest32,
    pub ajtai_policy_digest: Digest32,
    pub norm_range_policy_digest: Digest32,
    pub ajtai_linear_algebra_layout_digest: Digest32,
    pub ajtai_norm_range_layout_digest: Digest32,
    pub batch_manifest_layout_digest: Digest32,
    pub manifest_commitment_policy_digest: Digest32,
    pub message_oracle_policy_digest: Digest32,
    pub accumulator_transition_policy_digest: Digest32,
    pub accumulator_transition_profile_digest: Digest32,
    pub message_semantic_layout_digest: Digest32,
    pub projection_layout_digest: Digest32,
    pub range_layout_digest: Digest32,
    pub monomial_embedding_layout_digest: Digest32,
    pub representative_layout_digest: Digest32,
    pub field_policy: Symbt3FieldExtensionPolicy,
    pub sumcheck_challenge_policy: Symbt3SumcheckChallengePolicy,
    pub repetition_count: usize,
    pub fs_domain_separators: Vec<&'static str>,
    pub soundness_target_bits: u32,
    pub soundness_bound_bits: u32,
    pub whir_proximity_soundness_bits: u32,
    pub sumcheck_identity_check_bits: u32,
    pub rlc_batching_bits: u32,
    pub manifest_membership_bits: u32,
    pub message_view_bits: u32,
    pub norm_range_projection_bits: u32,
    pub ajtai_binding_bits: u32,
    pub bcs_rom_bits: u32,
    pub union_bound_overhead_bits: u32,
    pub union_bound_family_count: usize,
    pub accepted_shape_id: Digest32,
    pub accepted_batch_capacity: usize,
    pub accepted_active_policy: Symbt3ActivePolicy,
    pub soundness_status: Symbt3SoundnessStatus,
    pub zk_status: Symbt3ZkStatus,
    pub routing_status: Symbt3RoutingStatus,
    pub product_policy: Symbt3ProductPolicy,
    pub product_eligible: bool,
    pub research_only: bool,
    pub authority_status: Symbt3AuthorityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3RingModuleLayout {
    pub ring_degree: usize,
    pub modulus: u64,
    pub basis_order: &'static str,
    pub negacyclic_sign_convention: &'static str,
    pub action_side: Symbt3RingActionSide,
    pub opening_module_dimension: usize,
    pub commitment_module_dimension: usize,
    pub coordinate_encoding: &'static str,
    pub beta_encoding: &'static str,
    pub ring_action_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AjtaiCommitLayout {
    pub layout_version: u64,
    pub commitment_module_dimension: usize,
    pub opening_module_dimension: usize,
    pub ring_degree: usize,
    pub modulus: u64,
    pub indexed_evaluator_id: Digest32,
    pub separated_message_randomness: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3AjtaiOpeningMode {
    StrictAfEqualsC,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3AjtaiMatrixVectorEvaluatorId {
    DirectDevMatrixVectorV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AjtaiLinearAlgebraLayout {
    pub version_marker: &'static [u8; 8],
    pub layout_version: u64,
    pub algebra_law_digest: Digest32,
    pub ajtai_matrix_digest: Digest32,
    pub ajtai_commit_layout_digest: Digest32,
    pub kappa: usize,
    pub opening_len: usize,
    pub ring_degree: usize,
    pub source_opening_column: usize,
    pub source_commitment_column: usize,
    pub folded_opening_column: usize,
    pub folded_commitment_column: usize,
    pub beta_action: Symbt3BetaActionId,
    pub product_law: Symbt3ProductLawId,
    pub matrix_vector_evaluator: Symbt3AjtaiMatrixVectorEvaluatorId,
    pub padding_policy: &'static str,
    pub selector_evaluator: &'static str,
    pub opening_mode: Symbt3AjtaiOpeningMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ProjectionMode {
    DirectDevDenseProjectionV1,
    StructuredBlockProjectionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ProjectionSeedPolicy {
    ProofBoundDeterministicV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3RangeMode {
    DirectSignedRangeDevV1,
    MonomialEmbeddingRangeV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3SignedEncoding {
    CheckFieldSignedRepresentativeV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3CoefficientEncoding {
    CenteredI64LeV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ProjectionEntryDistribution {
    ZeroPlusMinusOneV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3MonomialityMode {
    OneHotCoefficientVectorV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ConstantTermPolicy {
    SignedRangeTableV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3SignedConvention {
    CenteredExponentV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3CanonicalRepPolicy {
    CenteredModQRepresentativeV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ProjectionLayout {
    pub layout_version: u64,
    pub projection_mode: Symbt3ProjectionMode,
    pub projection_seed_policy: Symbt3ProjectionSeedPolicy,
    pub projection_matrix_digest: Digest32,
    pub input_len: usize,
    pub output_len: usize,
    pub block_len: usize,
    pub rows_per_block: usize,
    pub entry_distribution: Symbt3ProjectionEntryDistribution,
    pub coefficient_domain: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3MonomialEmbeddingLayout {
    pub layout_version: u64,
    pub ring_degree: usize,
    pub bound_b: usize,
    pub table_polynomial_digest: Digest32,
    pub monomiality_mode: Symbt3MonomialityMode,
    pub constant_term_policy: Symbt3ConstantTermPolicy,
    pub signed_convention: Symbt3SignedConvention,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3RepresentativeLayout {
    pub layout_version: u64,
    pub modulus_digest: Digest32,
    pub signed_range: i64,
    pub canonical_rep_policy: Symbt3CanonicalRepPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3RangeLayout {
    pub layout_version: u64,
    pub range_mode: Symbt3RangeMode,
    pub bound_b: i64,
    pub signed_encoding: Symbt3SignedEncoding,
    pub table_digest: Option<Digest32>,
    pub monomial_embedding_layout_digest: Option<Digest32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AjtaiNormRangeLayout {
    pub version_marker: &'static [u8; 8],
    pub layout_version: u64,
    pub algebra_law_digest: Digest32,
    pub ajtai_linear_algebra_layout_digest: Digest32,
    pub folded_opening_column: usize,
    pub projected_opening_column: usize,
    pub monomial_witness_column: usize,
    pub projection_layout: Symbt3ProjectionLayout,
    pub range_layout: Symbt3RangeLayout,
    pub monomial_embedding_layout: Symbt3MonomialEmbeddingLayout,
    pub representative_layout: Symbt3RepresentativeLayout,
    pub norm_bound: i64,
    pub coefficient_encoding: Symbt3CoefficientEncoding,
    pub reduction_policy: &'static str,
    pub selector_evaluator: &'static str,
    pub padding_policy: &'static str,
    pub range_mode: Symbt3RangeMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ManifestOracleLayout {
    pub layout_version: u64,
    pub row_count: usize,
    pub component_count: usize,
    pub coordinate_count: usize,
    pub coordinate_ordering: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3SourceColumnLayout {
    pub layout_version: u64,
    pub component_count: usize,
    pub coordinate_count: usize,
    pub source_column_ordering: &'static str,
    pub root_binding_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3ManifestComponentLayout {
    pub kind: Symbt3ManifestComponentKind,
    pub coordinate_len: usize,
    pub source_column_id: usize,
    pub manifest_column_id: usize,
    pub visibility: Symbt3ManifestVisibility,
    pub membership_mode: Symbt3MembershipMode,
    pub padding_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3BatchManifestLayout {
    pub version_marker: &'static [u8; 8],
    pub layout_version: u64,
    pub batch_size: usize,
    pub active_count: usize,
    pub active_policy: Symbt3ActivePolicy,
    pub manifest_oracle_layout: Symbt3ManifestOracleLayout,
    pub source_column_layout: Symbt3SourceColumnLayout,
    pub component_kinds: Vec<Symbt3ManifestComponentLayout>,
    pub commitment_scheme_id: Symbt3CommitmentSchemeId,
    pub manifest_root_policy: Symbt3ManifestRootPolicy,
    pub selector_evaluator: &'static str,
    pub padding_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3MessageSectionLayout {
    pub layout_version: u64,
    pub section_kind: Symbt3MessageSectionKind,
    pub coordinate_offset: usize,
    pub coordinate_len: usize,
    pub algebra_type: Symbt3MessageAlgebraType,
    pub visibility: Symbt3MessageVisibility,
    pub binding_mode: Symbt3MessageBindingMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3MessageColumnBinding {
    pub layout_version: u64,
    pub round_index: usize,
    pub message_coordinate_offset: usize,
    pub trace_column_id: usize,
    pub trace_coordinate_offset: usize,
    pub coordinate_len: usize,
    pub binding_mode: Symbt3MessageBindingMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3MessageCoordinateMap {
    pub layout_version: u64,
    pub mode: Symbt3MessageCoordinateMapMode,
    pub message_coordinate_offset: usize,
    pub coordinate_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3MessageViewLayout {
    pub layout_version: u64,
    pub round: usize,
    pub trace_kind: Symbt3TraceKind,
    pub trace_coordinate_axis: &'static str,
    pub message_coordinate_map: Symbt3MessageCoordinateMap,
    pub algebra_type: Symbt3MessageAlgebraType,
    pub padding_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3RoundMessageLayout {
    pub layout_version: u64,
    pub round_index: usize,
    pub row_count: usize,
    pub message_len: usize,
    pub packed_field_len: usize,
    pub coordinate_axis: &'static str,
    pub section_axis: &'static str,
    pub sections: Vec<Symbt3MessageSectionLayout>,
    pub source_column_bindings: Vec<Symbt3MessageColumnBinding>,
    pub trace_column_bindings: Vec<Symbt3MessageColumnBinding>,
    pub message_views: Vec<Symbt3MessageViewLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3MessageSemanticLayout {
    pub version_marker: &'static [u8; 8],
    pub layout_version: u64,
    pub round_count: usize,
    pub round_layouts: Vec<Symbt3RoundMessageLayout>,
    pub challenge_schedule_version: u64,
    pub message_oracle_layout_digest: Digest32,
    pub algebra_law_digest: Digest32,
    pub gr1cs_layout_digest: Digest32,
    pub ajtai_layout_digest: Digest32,
    pub norm_range_layout_digest: Digest32,
    pub manifest_layout_digest: Digest32,
    pub selector_evaluator: &'static str,
    pub padding_policy: &'static str,
    pub semantic_mode: Symbt3MessageSemanticMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3R1csEvaluatorLayout {
    pub layout_version: u64,
    pub field_id: &'static str,
    pub modulus: u64,
    pub num_constraints: usize,
    pub num_variables: usize,
    pub num_public: usize,
    pub num_witness: usize,
    pub constant_one_wire_index: Option<usize>,
    pub public_input_wire_layout: &'static str,
    pub witness_wire_layout: &'static str,
    pub sparse_encoding_format: &'static str,
    pub row_ordering: &'static str,
    pub column_ordering: &'static str,
    pub padding_policy: &'static str,
    pub coefficient_encoding: &'static str,
    pub term_encoding: &'static str,
    pub evaluator_algorithm_id: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3Gr1csResidualLayout {
    pub layout_version: u64,
    pub folded_evaluation_coordinate_count: usize,
    pub tensor_rows: usize,
    pub ring_degree: usize,
    pub grouping: &'static str,
    pub coordinate_ordering: &'static str,
    pub padding_policy: &'static str,
    pub component_kind_tags: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3ProductLawId {
    FieldCoordinateMulV1,
    RqNegacyclicConvolutionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3BetaActionId {
    ScalarFieldCoordinateV1,
    RingCoefficientActionV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AlgebraLaw {
    pub version_marker: &'static [u8; 8],
    pub law_version: u64,
    pub check_field_id: &'static str,
    pub coefficient_domain: &'static str,
    pub ring_degree: usize,
    pub ring_relation: &'static str,
    pub coefficient_basis: &'static str,
    pub coefficient_order: &'static str,
    pub reduction_policy: &'static str,
    pub beta_action: Symbt3BetaActionId,
    pub product_law: Symbt3ProductLawId,
    pub module_layout: &'static str,
    pub soundness_profile: &'static str,
    pub zk_profile: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3FoldedGr1csProductResidualLayout {
    pub layout_version: u64,
    pub product_domain_log_size: usize,
    pub equation_kind_axis: &'static str,
    pub row_axis: &'static str,
    pub l_fold_column: usize,
    pub r_fold_column: usize,
    pub o_fold_column: usize,
    pub selector_evaluator: &'static str,
    pub product_law: Symbt3ProductLawId,
    pub beta_action: Symbt3BetaActionId,
    pub padding_policy: &'static str,
    pub check_field: &'static str,
    pub soundness_profile: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3MessageOracleLayout {
    pub round: usize,
    pub row_count: usize,
    pub message_len: usize,
    pub packed_field_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3AlgebraicColumn {
    pub id: usize,
    pub kind: BatchedCpSymbt3AlgebraicColumnKind,
    pub row_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3OracleLayout {
    pub layout_version: u64,
    pub challenge_schedule_version: u64,
    pub batch_capacity: usize,
    pub active_count: usize,
    pub message_oracles: Vec<BatchedCpSymbt3MessageOracleLayout>,
    pub algebraic_columns: Vec<BatchedCpSymbt3AlgebraicColumn>,
    pub constraint_families: Vec<BatchedCpSymbt3ConstraintFamily>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3RelationDescription {
    pub shape: BatchedCpStatementShape,
    pub oracle_layout: BatchedCpSymbt3OracleLayout,
    pub ring_module_layout: Symbt3RingModuleLayout,
    pub ajtai_commit_layout: Symbt3AjtaiCommitLayout,
    pub r1cs_evaluator_layout: Symbt3R1csEvaluatorLayout,
    pub gr1cs_residual_layout: Symbt3Gr1csResidualLayout,
    pub algebra_law: Symbt3AlgebraLaw,
    pub ajtai_linear_algebra_layout: Symbt3AjtaiLinearAlgebraLayout,
    pub ajtai_norm_range_layout: Symbt3AjtaiNormRangeLayout,
    pub batch_manifest_layout: Symbt3BatchManifestLayout,
    pub message_semantic_layout: Symbt3MessageSemanticLayout,
    pub folded_gr1cs_product_residual_layout: Symbt3FoldedGr1csProductResidualLayout,
    pub ajtai_matrix: Vec<Vec<RingElement>>,
    pub r1cs_matrices: R1CSMatrices,
    pub ajtai_params_digest: Digest32,
    pub r1cs_matrices_digest: Digest32,
    pub input_bound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3SetupDescriptor {
    pub shape: BatchedCpStatementShape,
    pub ring_module_layout: Symbt3RingModuleLayout,
    pub ajtai_commit_layout: Symbt3AjtaiCommitLayout,
    pub r1cs_evaluator_layout: Symbt3R1csEvaluatorLayout,
    pub gr1cs_residual_layout: Symbt3Gr1csResidualLayout,
    pub algebra_law: Symbt3AlgebraLaw,
    pub ajtai_linear_algebra_layout: Symbt3AjtaiLinearAlgebraLayout,
    pub ajtai_norm_range_layout: Symbt3AjtaiNormRangeLayout,
    pub batch_manifest_layout: Symbt3BatchManifestLayout,
    pub message_semantic_layout: Symbt3MessageSemanticLayout,
    pub folded_gr1cs_product_residual_layout: Symbt3FoldedGr1csProductResidualLayout,
    pub ajtai_matrix: Vec<Vec<RingElement>>,
    pub r1cs_matrices: R1CSMatrices,
    pub ajtai_params_digest: Digest32,
    pub r1cs_matrices_digest: Digest32,
    pub input_bound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TypedMessageSection {
    pub section_kind: Symbt3MessageSectionKind,
    pub offset: usize,
    pub values: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TypedMessageRow {
    pub row_index: usize,
    pub sections: Vec<Symbt3TypedMessageSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TypedMessageOracle {
    pub round: usize,
    pub rows: Vec<Symbt3TypedMessageRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AccumulatorInstance {
    pub profile_digest: Digest32,
    pub shape_id: Digest32,
    pub batch_capacity: usize,
    pub active_count: usize,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub old_accumulator_coordinates: Vec<i64>,
    pub new_accumulator_coordinates: Vec<i64>,
    pub input_public_boundary_digest: Digest32,
    pub manifest_root: Digest32,
    pub manifest_oracle_root: Digest32,
    pub manifest_eval_claim: u32,
    pub manifest_layout_digest: Digest32,
    pub source_column_layout_digest: Digest32,
    pub message_semantic_layout_digest: Digest32,
    pub production_norm_range_layout_digest: Digest32,
    pub structured_projection_layout_digest: Digest32,
    pub monomial_embedding_layout_digest: Digest32,
    pub representative_layout_digest: Digest32,
    pub norm_range_public_digest: Digest32,
    pub batch_items_digest: Digest32,
    pub public_source_boundary_digest: Digest32,
    pub source_assignment_roots_digest: Digest32,
    pub source_ajtai_opening_roots_digest: Digest32,
    pub message_oracle_roots_digest: Digest32,
    pub input_public_values: Vec<Vec<i64>>,
    pub input_commitment_values: Vec<Vec<i64>>,
    pub input_evaluation_values: Vec<Vec<i64>>,
    pub input_accumulator_values: Vec<Vec<i64>>,
    pub source_assignment_roots: Vec<Digest32>,
    pub source_assignment_boundary_digest: Digest32,
    pub source_ajtai_opening_roots: Vec<Digest32>,
    pub source_ajtai_commitment_boundary_digest: Digest32,
    pub message_oracle_roots: Vec<Digest32>,
    pub folded_public_input: Vec<i64>,
    pub folded_commitment: Vec<i64>,
    pub folded_evaluation: Vec<i64>,
    pub folded_batch_accumulator_coordinates: Vec<i64>,
    pub folded_ajtai_opening_root: Digest32,
    pub folded_ajtai_commitment: Vec<i64>,
    pub folded_gr1cs_boundary_digest: Digest32,
    pub ring_module_layout_digest: Digest32,
    pub ajtai_commit_layout_digest: Digest32,
    pub r1cs_evaluator_layout_digest: Digest32,
    pub gr1cs_residual_layout_digest: Digest32,
    pub algebra_law_digest: Digest32,
    pub ajtai_linear_algebra_layout_digest: Digest32,
    pub ajtai_norm_range_layout_digest: Digest32,
    pub projection_layout_digest: Digest32,
    pub range_layout_digest: Digest32,
    pub folded_gr1cs_product_residual_layout_digest: Digest32,
    pub folded_output_boundary_digest: Digest32,
    pub whir_params_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3AccumulatorWitness {
    pub manifest_oracle: Vec<Vec<i64>>,
    pub source_columns: Vec<Vec<i64>>,
    pub message_oracles: Vec<Symbt3TypedMessageOracle>,
    pub folded_witness_columns: Vec<Vec<i64>>,
    pub ajtai_openings: Vec<Vec<i64>>,
    pub old_accumulator_coordinates: Vec<i64>,
    pub new_accumulator_coordinates: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3PublicStatement {
    pub shape_id: Digest32,
    pub batch_capacity: usize,
    pub active_count: usize,
    pub old_accumulator_digest: Digest32,
    pub new_accumulator_digest: Digest32,
    pub old_accumulator_coordinates: Vec<i64>,
    pub new_accumulator_coordinates: Vec<i64>,
    pub input_public_boundary_digest: Digest32,
    pub batch_manifest_root: Digest32,
    pub manifest_oracle_root: Digest32,
    pub manifest_eval_claim: u32,
    pub batch_manifest_layout_digest: Digest32,
    pub source_column_layout_digest: Digest32,
    pub message_semantic_layout_digest: Digest32,
    pub production_norm_range_layout_digest: Digest32,
    pub structured_projection_layout_digest: Digest32,
    pub monomial_embedding_layout_digest: Digest32,
    pub representative_layout_digest: Digest32,
    pub norm_range_public_digest: Digest32,
    pub input_public_values: Vec<Vec<i64>>,
    pub input_commitment_values: Vec<Vec<i64>>,
    pub input_evaluation_values: Vec<Vec<i64>>,
    pub input_accumulator_values: Vec<Vec<i64>>,
    pub source_assignment_roots: Vec<Digest32>,
    pub source_assignment_boundary_digest: Digest32,
    pub source_ajtai_opening_roots: Vec<Digest32>,
    pub source_ajtai_commitment_boundary_digest: Digest32,
    pub message_oracle_roots: Vec<Digest32>,
    pub folded_public_input: Vec<i64>,
    pub folded_commitment: Vec<i64>,
    pub folded_evaluation: Vec<i64>,
    pub folded_accumulator_coordinates: Vec<i64>,
    pub folded_ajtai_opening_root: Digest32,
    pub folded_ajtai_commitment: Vec<i64>,
    pub folded_gr1cs_boundary_digest: Digest32,
    pub ring_module_layout_digest: Digest32,
    pub ajtai_commit_layout_digest: Digest32,
    pub r1cs_evaluator_layout_digest: Digest32,
    pub gr1cs_residual_layout_digest: Digest32,
    pub algebra_law_digest: Digest32,
    pub ajtai_linear_algebra_layout_digest: Digest32,
    pub ajtai_norm_range_layout_digest: Digest32,
    pub projection_layout_digest: Digest32,
    pub range_layout_digest: Digest32,
    pub folded_gr1cs_product_residual_layout_digest: Digest32,
    pub folded_output_accumulator_root: Digest32,
    pub whir_parameter_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSymbt3Witness {
    pub message_oracles: Vec<Vec<Vec<u8>>>,
    pub algebraic_trace_columns: Vec<Vec<u32>>,
    pub source_ajtai_opening_values: Vec<Vec<i64>>,
    pub folded_ajtai_opening_values: Vec<i64>,
    pub source_r1cs_assignment_values: Vec<Vec<i64>>,
    pub manifest_source_values: Vec<Vec<i64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticTraceV2 {
    pub layout: BatchedCpSemanticColumnarV2Layout,
    pub columns: Vec<Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticFamilyTraceV2 {
    pub layout: BatchedCpSemanticFamilyColumnarV2Layout,
    pub tables: Vec<Vec<Vec<u32>>>,
}

#[derive(Debug, Clone)]
enum BatchedCpFamilyColumnarV2TableSource {
    Equality(Vec<BatchedCpOracleByteEquality>),
    PackedValue(BatchedCpSemanticConstraintFamily),
    PoseidonR1cs(Vec<BatchedCpPoseidonR1csRowConstraint>),
    FoldedPublicInputLinear(Vec<BatchedCpFoldedPublicInputLinearConstraint>),
    FoldedCommitmentRingMul(Vec<BatchedCpFoldedCommitmentRingMulConstraint>),
    FoldedEvaluationRingMul(Vec<BatchedCpFoldedEvaluationRingMulConstraint>),
    AjtaiOpeningLinear(Vec<BatchedCpAjtaiOpeningLinearConstraint>),
    OriginalR1cs(Vec<BatchedCpOriginalR1csConstraint>),
}

#[derive(Debug, Clone)]
struct BatchedCpFamilyColumnarV2TableSpec {
    family: BatchedCpSemanticConstraintFamily,
    kind: BatchedCpSemanticResidualV2Kind,
    label: String,
    transcript_label: Vec<u8>,
    column_kinds: Vec<BatchedCpSemanticColumnV2Kind>,
    column_labels: Vec<String>,
    row_count: usize,
    source: BatchedCpFamilyColumnarV2TableSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchedCpOracleByteEquality {
    pub left_offset: usize,
    pub right_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchedCpOraclePackedValue {
    pub packed_index: usize,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpFoldedPublicInputLinearConstraint {
    pub beta_coeff_offsets: Vec<usize>,
    pub input_scalar_offsets: Vec<usize>,
    pub output_coeff_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpFoldedCommitmentRingMulConstraint {
    pub beta_coeff_offsets: Vec<Vec<usize>>,
    pub commitment_coeff_offsets: Vec<Vec<usize>>,
    pub output_coeff_index: usize,
    pub output_coeff_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpFoldedEvaluationRingMulConstraint {
    pub beta_coeff_offsets: Vec<Vec<usize>>,
    pub evaluation_coeff_offsets: Vec<Vec<usize>>,
    pub output_coeff_index: usize,
    pub output_coeff_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpPoseidonR1csRowConstraint {
    pub round: usize,
    pub item: usize,
    pub row: usize,
    pub input_len: usize,
    pub output_offsets: Vec<usize>,
    pub input_offsets: Vec<usize>,
    pub aux_offsets: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpPoseidonR1csSurface {
    pub round: usize,
    pub item: usize,
    pub input_len: usize,
    pub num_rows: usize,
    pub output_offsets: Vec<usize>,
    pub input_offsets: Vec<usize>,
    pub aux_offsets: Vec<usize>,
}

impl BatchedCpPoseidonR1csSurface {
    #[must_use]
    pub fn row_constraint(&self, row: usize) -> Option<BatchedCpPoseidonR1csRowConstraint> {
        (row < self.num_rows).then(|| BatchedCpPoseidonR1csRowConstraint {
            round: self.round,
            item: self.item,
            row,
            input_len: self.input_len,
            output_offsets: self.output_offsets.clone(),
            input_offsets: self.input_offsets.clone(),
            aux_offsets: self.aux_offsets.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpAjtaiOpeningLinearConstraint {
    pub item: usize,
    pub round: usize,
    pub row: usize,
    pub coeff: usize,
    pub matrix_row: Vec<RingElement>,
    pub public_input_offsets: Vec<usize>,
    pub witness_coeff_offsets: Vec<Vec<usize>>,
    pub commitment_coeff_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpOriginalR1csConstraint {
    pub item: usize,
    pub original_index: usize,
    pub row: usize,
    pub coeff: usize,
    pub a_terms: Vec<(i64, usize)>,
    pub b_terms: Vec<(i64, usize)>,
    pub c_terms: Vec<(i64, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchedCpSemanticConstraint {
    ByteEquality(BatchedCpOracleByteEquality),
    PackedValue(BatchedCpOraclePackedValue),
    FoldedPublicInputLinear(BatchedCpFoldedPublicInputLinearConstraint),
    FoldedCommitmentRingMul(BatchedCpFoldedCommitmentRingMulConstraint),
    FoldedEvaluationRingMul(BatchedCpFoldedEvaluationRingMulConstraint),
    PoseidonR1csRow(BatchedCpPoseidonR1csRowConstraint),
    AjtaiOpeningLinear(BatchedCpAjtaiOpeningLinearConstraint),
    OriginalR1cs(BatchedCpOriginalR1csConstraint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpSemanticConstraintBlock {
    pub family: BatchedCpSemanticConstraintFamily,
    pub label: &'static str,
    pub constraints: Vec<BatchedCpSemanticConstraint>,
}

#[derive(Debug, Clone)]
pub struct BatchedCpItem {
    pub item_tag: Digest32,
    pub public: CpPublicStatement,
    pub witness: CpWitnessBundle,
}

#[derive(Debug, Clone)]
pub struct BatchedCpBucket {
    pub shape: BatchedCpStatementShape,
    pub items: Vec<BatchedCpItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchManifest {
    pub digest: Digest32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRoundMessageCommitments {
    pub commitments: Vec<Digest32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedCpPublicStatement {
    pub shape: BatchedCpStatementShape,
    pub manifest_digest: Digest32,
    pub round_message_commitments: Vec<Digest32>,
    pub batch_challenge_digest: Digest32,
    pub folded_output_accumulator_root: Digest32,
    pub whir_parameter_digest: Digest32,
}

#[derive(Debug, Clone)]
pub struct BatchedCpWitnessBundle {
    pub items: Vec<BatchedCpItem>,
    pub witness_oracle_rows: Vec<Vec<u8>>,
    pub round_message_oracles: Vec<Vec<Vec<u8>>>,
}

pub struct BatchedCpEvaluator;

impl CpAccumulatorShape {
    pub fn from_item(
        public: &CpPublicStatement,
        witness: &CpWitnessBundle,
        whir_parameter_digest: Digest32,
    ) -> Result<Self, BatchedCpError> {
        if witness.fs_messages.is_empty()
            || witness.fs_messages.len() != witness.fs_commitments.len()
            || witness.fs_messages.len() != witness.fs_openings.len()
            || witness.fs_messages.len() != witness.fold_inputs.len()
            || witness.fs_messages.len() != witness.folding_proof.gr1cs_proofs.len()
            || witness.fs_messages.len() != witness.folding_proof.beta.len()
            || public.public_inputs.len() != witness.original_witnesses.len()
        {
            return Err(BatchedCpError::InvalidShape);
        }
        let first_commitment = witness
            .folding_proof
            .commitments
            .first()
            .ok_or(BatchedCpError::InvalidShape)?;
        let commitment_kappa = first_commitment.value.elements.len();
        let commitment_d = first_commitment
            .value
            .elements
            .first()
            .map(|elem| elem.coeffs.len())
            .ok_or(BatchedCpError::InvalidShape)?;
        let folded_evaluation_count = public.instance.x_folded.evaluation_values.len();
        let gr1cs_hadamard_eval_offsets: Vec<Vec<usize>> = witness
            .fold_inputs
            .iter()
            .map(|input| {
                gr1cs_hadamard_evaluation_offsets(&input.eval_values_bytes, folded_evaluation_count)
            })
            .collect::<Option<_>>()
            .ok_or(BatchedCpError::InvalidShape)?;
        let gr1cs_message_sections: Vec<Vec<BatchedCpGr1csMessageSection>> = witness
            .folding_proof
            .gr1cs_proofs
            .iter()
            .zip(witness.fs_messages.iter())
            .map(|(proof, message)| gr1cs_message_sections(proof, message.len()))
            .collect::<Option<_>>()
            .ok_or(BatchedCpError::InvalidShape)?;

        Ok(Self {
            digest_scheme: public.digest_scheme,
            r1cs_num_constraints: public.r1cs_num_constraints,
            r1cs_num_variables: public.r1cs_num_variables,
            r1cs_num_public: public.r1cs_num_public,
            local_public_input_count: public.public_inputs.len(),
            public_statement_len: encode_public_statement(public).len(),
            num_rounds: witness.fs_messages.len(),
            fs_message_lens: witness.fs_messages.iter().map(Vec::len).collect(),
            fs_commitment_len: witness.fs_commitments[0].len(),
            fs_opening_len: witness.fs_openings[0].len(),
            fold_input_commitment_lens: witness
                .fold_inputs
                .iter()
                .map(|input| input.commitment_bytes.len())
                .collect(),
            fold_input_public_input_lens: witness
                .fold_inputs
                .iter()
                .map(|input| input.public_input.len())
                .collect(),
            fold_input_eval_message_lens: witness
                .fold_inputs
                .iter()
                .map(|input| input.eval_values_bytes.len())
                .collect(),
            gr1cs_hadamard_eval_offsets,
            gr1cs_message_sections,
            original_witness_lens: witness
                .original_witnesses
                .iter()
                .map(RingVector::len)
                .collect(),
            commitment_kappa,
            commitment_d,
            folded_public_input_len: public.instance.x_folded.public_input.len(),
            folded_evaluation_count,
            folded_output_contribution_len: encode_folded_output_contribution_parts(public, None)
                .len(),
            whir_parameter_digest,
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"symphony-cp-accumulator-shape-v1");
        push_digest_scheme(&mut out, self.digest_scheme);
        push_usize(&mut out, self.r1cs_num_constraints);
        push_usize(&mut out, self.r1cs_num_variables);
        push_usize(&mut out, self.r1cs_num_public);
        push_usize(&mut out, self.local_public_input_count);
        push_usize(&mut out, self.public_statement_len);
        push_usize(&mut out, self.num_rounds);
        push_usize_vec(&mut out, &self.fs_message_lens);
        push_usize(&mut out, self.fs_commitment_len);
        push_usize(&mut out, self.fs_opening_len);
        push_usize_vec(&mut out, &self.fold_input_commitment_lens);
        push_usize_vec(&mut out, &self.fold_input_public_input_lens);
        push_usize_vec(&mut out, &self.fold_input_eval_message_lens);
        push_nested_usize_vec(&mut out, &self.gr1cs_hadamard_eval_offsets);
        push_gr1cs_message_sections(&mut out, &self.gr1cs_message_sections);
        push_usize_vec(&mut out, &self.original_witness_lens);
        push_usize(&mut out, self.commitment_kappa);
        push_usize(&mut out, self.commitment_d);
        push_usize(&mut out, self.folded_public_input_len);
        push_usize(&mut out, self.folded_evaluation_count);
        push_usize(&mut out, self.folded_output_contribution_len);
        out.extend_from_slice(&self.whir_parameter_digest);
        out
    }

    #[must_use]
    pub fn shape_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.digest_scheme,
            b"batched-cp-shape-id",
            &self.canonical_bytes(),
        )
    }
}

impl BatchedCpStatementShape {
    pub fn new(
        accumulator_shape: CpAccumulatorShape,
        active_count: usize,
    ) -> Result<Self, BatchedCpError> {
        if active_count == 0 {
            return Err(BatchedCpError::EmptyBatch);
        }
        let batch_capacity = active_count.next_power_of_two();
        let batch_log_size = batch_capacity.trailing_zeros() as usize;
        let witness_row_len = estimate_witness_row_len(&accumulator_shape);
        let shape_id = accumulator_shape.shape_id();
        let round_message_lens = accumulator_shape.fs_message_lens.clone();
        Ok(Self {
            accumulator_shape,
            shape_id,
            batch_log_size,
            batch_capacity,
            active_count,
            witness_row_len,
            round_message_lens,
        })
    }

    #[must_use]
    pub fn product_domain_size(&self) -> usize {
        self.batch_capacity * self.witness_row_len
    }

    #[must_use]
    pub fn canonical_product_oracle_byte_len(&self) -> usize {
        self.canonical_product_oracle_public_byte_template().0.len()
    }

    #[must_use]
    pub fn canonical_product_oracle_public_byte_template(&self) -> (Vec<u8>, Vec<bool>) {
        self.canonical_product_oracle_public_byte_template_inner(None)
    }

    pub fn canonical_product_oracle_public_byte_template_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<(Vec<u8>, Vec<bool>)> {
        if statement.shape != *self
            || statement.round_message_commitments.len() != self.round_message_lens.len()
        {
            return None;
        }
        Some(self.canonical_product_oracle_public_byte_template_inner(Some(statement)))
    }

    fn canonical_product_oracle_public_byte_template_inner(
        &self,
        statement: Option<&BatchedCpPublicStatement>,
    ) -> (Vec<u8>, Vec<bool>) {
        let mut bytes = Vec::new();
        let mut known = Vec::new();
        push_known_bytes(
            &mut bytes,
            &mut known,
            b"symphony-batched-cp-product-oracle-v1",
        );
        push_known_statement_shape(&mut bytes, &mut known, self);
        push_known_usize(&mut bytes, &mut known, self.batch_capacity);
        for idx in 0..self.batch_capacity {
            push_known_usize(&mut bytes, &mut known, idx);
            push_known_u8(&mut bytes, &mut known, u8::from(idx < self.active_count));
            if idx < self.active_count {
                push_private_bytes(&mut bytes, &mut known, self.witness_row_len);
            } else {
                push_known_bytes(&mut bytes, &mut known, &[]);
            }
        }
        push_known_usize(&mut bytes, &mut known, self.round_message_lens.len());
        for (round, &message_len) in self.round_message_lens.iter().enumerate() {
            push_known_usize(&mut bytes, &mut known, round);
            push_known_usize(&mut bytes, &mut known, self.batch_capacity);
            for idx in 0..self.batch_capacity {
                push_known_usize(&mut bytes, &mut known, idx);
                push_known_u8(&mut bytes, &mut known, u8::from(idx < self.active_count));
                if idx < self.active_count {
                    push_private_bytes(&mut bytes, &mut known, message_len);
                } else {
                    push_known_bytes(&mut bytes, &mut known, &[]);
                }
            }
        }
        push_known_usize(&mut bytes, &mut known, self.round_message_lens.len());
        for (round, &message_len) in self.round_message_lens.iter().enumerate() {
            push_known_bytes(
                &mut bytes,
                &mut known,
                b"symphony-batched-cp-round-message-v1",
            );
            push_known_raw(&mut bytes, &mut known, &self.shape_id);
            push_known_usize(&mut bytes, &mut known, round);
            push_known_usize(&mut bytes, &mut known, self.batch_capacity);
            for idx in 0..self.batch_capacity {
                push_known_usize(&mut bytes, &mut known, idx);
                push_known_u8(&mut bytes, &mut known, u8::from(idx < self.active_count));
                if idx < self.active_count {
                    push_private_bytes(&mut bytes, &mut known, message_len);
                } else {
                    push_known_bytes(&mut bytes, &mut known, &[]);
                }
            }
        }
        push_known_manifest_body_template(&mut bytes, &mut known, self);
        push_known_fs_commitment_body_template(&mut bytes, &mut known, self);
        push_known_poseidon_fs_commitment_trace_template(&mut bytes, &mut known, self);
        push_known_batch_challenge_body_template(&mut bytes, &mut known, self, statement);
        push_known_challenge_to_beta_body_template(&mut bytes, &mut known, self, statement);
        push_known_fold_input_reconstruction_body_template(&mut bytes, &mut known, self);
        push_known_folded_output_accumulator_body_template(&mut bytes, &mut known, self, statement);
        debug_assert_eq!(bytes.len(), known.len());
        (bytes, known)
    }

    #[must_use]
    pub fn canonical_product_oracle_public_packed_claim_count(&self) -> usize {
        let (bytes, known) = self.canonical_product_oracle_public_byte_template();
        count_fully_known_packed_chunks(&bytes, &known)
    }

    pub fn canonical_product_oracle_public_packed_claim_count_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<usize> {
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(count_fully_known_packed_chunks(&bytes, &known))
    }

    pub fn challenge_derivation_packed_values_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<Vec<BatchedCpOraclePackedValue>> {
        let layout = self.product_oracle_layout();
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(packed_values_for_known_range(
            &bytes,
            &known,
            layout.batch_challenge_body,
        ))
    }

    pub fn challenge_to_beta_packed_values_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<Vec<BatchedCpOraclePackedValue>> {
        let layout = self.product_oracle_layout();
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(packed_values_for_known_range(
            &bytes,
            &known,
            layout.challenge_to_beta_body,
        ))
    }

    pub fn folded_output_packed_values_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<Vec<BatchedCpOraclePackedValue>> {
        let layout = self.product_oracle_layout();
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(packed_values_for_known_range(
            &bytes,
            &known,
            layout.folded_output_accumulator_body,
        ))
    }

    #[must_use]
    pub fn structured_oracle_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities: Vec<_> = layout
            .round_message_rows
            .iter()
            .zip(layout.round_message_digest_bodies.iter())
            .flat_map(|(message_rows, digest_rows)| {
                message_rows
                    .iter()
                    .zip(digest_rows.iter())
                    .flat_map(|(message, digest)| {
                        let len = message.len.min(digest.len);
                        (0..len).map(move |offset| BatchedCpOracleByteEquality {
                            left_offset: message.offset + offset,
                            right_offset: digest.offset + offset,
                        })
                    })
            })
            .collect();
        for round in 0..self.accumulator_shape.num_rounds {
            for idx in 0..self.active_count {
                push_range_equalities(
                    &mut equalities,
                    layout.witness_fs_messages[round][idx],
                    layout.round_message_rows[round][idx],
                );
            }
        }
        equalities
    }

    #[must_use]
    pub fn fs_commitment_body_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for round in 0..self.accumulator_shape.num_rounds {
            for idx in 0..self.active_count {
                push_range_equalities(
                    &mut equalities,
                    layout.fs_commitment_body_messages[round][idx],
                    layout.witness_fs_messages[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.fs_commitment_body_openings[round][idx],
                    layout.witness_fs_openings[round][idx],
                );
                if poseidon_fs_commitment_traces_enabled(self) {
                    for limb in 0..8 {
                        for byte in 0..4 {
                            equalities.push(BatchedCpOracleByteEquality {
                                left_offset: layout.poseidon_fs_commitment_trace_outputs[round]
                                    [idx]
                                    .offset
                                    + limb * 4
                                    + byte,
                                right_offset: layout.witness_fs_commitments[round][idx].offset
                                    + limb * 4
                                    + byte,
                            });
                        }
                    }
                }
            }
        }
        equalities
    }

    #[must_use]
    pub fn poseidon_fs_commitment_r1cs_constraints(
        &self,
    ) -> Vec<BatchedCpPoseidonR1csRowConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let mut constraints = Vec::new();
            for surface in self.poseidon_fs_commitment_r1cs_surfaces() {
                let row_candidates = sampled_poseidon_row_candidates(surface.num_rows);
                for row in row_candidates {
                    if let Some(constraint) = surface.row_constraint(row) {
                        constraints.push(constraint);
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn poseidon_fs_commitment_r1cs_surfaces(&self) -> Vec<BatchedCpPoseidonR1csSurface> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut surfaces = Vec::new();
            for round in 0..self.accumulator_shape.num_rounds {
                let input_len = poseidon_fs_commitment_input_len(
                    self.accumulator_shape.fs_message_lens[round],
                    self.accumulator_shape.fs_opening_len,
                );
                let (r1cs, _) = crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
                    b"fs-commit",
                    input_len,
                );
                for item in 0..self.active_count {
                    surfaces.push(BatchedCpPoseidonR1csSurface {
                        round,
                        item,
                        input_len,
                        num_rows: r1cs.num_constraints,
                        output_offsets: field_offsets(
                            layout.poseidon_fs_commitment_trace_outputs[round][item],
                            8,
                        ),
                        input_offsets: field_offsets(
                            layout.poseidon_fs_commitment_trace_inputs[round][item],
                            input_len,
                        ),
                        aux_offsets: field_offsets(
                            layout.poseidon_fs_commitment_trace_aux[round][item],
                            poseidon_fs_commitment_aux_len(input_len),
                        ),
                    });
                }
            }
            surfaces
        }
    }

    #[must_use]
    pub fn active_marker_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for idx in 0..self.batch_capacity {
            let manifest_marker = layout.manifest_active_markers[idx];
            equalities.push(BatchedCpOracleByteEquality {
                left_offset: manifest_marker,
                right_offset: layout.witness_active_markers[idx],
            });
            for round_markers in &layout.round_message_active_markers {
                equalities.push(BatchedCpOracleByteEquality {
                    left_offset: manifest_marker,
                    right_offset: round_markers[idx],
                });
            }
            for round_markers in &layout.round_message_digest_body_active_markers {
                equalities.push(BatchedCpOracleByteEquality {
                    left_offset: manifest_marker,
                    right_offset: round_markers[idx],
                });
            }
            if idx < self.active_count {
                for round_markers in &layout.fs_commitment_body_active_markers {
                    equalities.push(BatchedCpOracleByteEquality {
                        left_offset: manifest_marker,
                        right_offset: round_markers[idx],
                    });
                }
                if poseidon_fs_commitment_traces_enabled(self) {
                    for round_markers in &layout.poseidon_fs_commitment_trace_active_markers {
                        equalities.push(BatchedCpOracleByteEquality {
                            left_offset: manifest_marker,
                            right_offset: round_markers[idx],
                        });
                    }
                }
            }
        }
        equalities
    }

    #[must_use]
    pub fn manifest_membership_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for idx in 0..self.active_count {
            push_range_equalities(
                &mut equalities,
                layout.manifest_item_tags[idx],
                layout.witness_item_tags[idx],
            );
            push_range_equalities(
                &mut equalities,
                layout.manifest_public_statements[idx],
                layout.witness_public_statements[idx],
            );
        }
        equalities
    }

    #[must_use]
    pub fn folded_output_contribution_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for idx in 0..self.active_count {
            push_range_equalities(
                &mut equalities,
                layout.folded_output_contributions[idx],
                layout.witness_folded_output_contributions[idx],
            );
        }
        equalities
    }

    #[must_use]
    pub fn folded_output_self_consistency_byte_equalities(
        &self,
    ) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let folded_instance_len = folded_instance_encoding_len(&self.accumulator_shape);
        let mut equalities = Vec::new();
        for idx in 0..self.active_count {
            let contribution = layout.folded_output_contributions[idx];
            let x_folded = BatchedCpOracleByteRange {
                offset: contribution.offset + 32,
                len: folded_instance_len,
            };
            let folded_output_instance = BatchedCpOracleByteRange {
                offset: contribution.offset + 32 + folded_instance_len,
                len: folded_instance_len,
            };
            push_range_equalities(&mut equalities, x_folded, folded_output_instance);
        }
        equalities
    }

    #[must_use]
    pub fn fold_input_reconstruction_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for round in 0..self.accumulator_shape.num_rounds {
            for idx in 0..self.active_count {
                push_range_equalities(
                    &mut equalities,
                    layout.fold_input_commitments[round][idx],
                    layout.witness_fold_input_commitments[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.fold_input_public_inputs[round][idx],
                    layout.witness_fold_input_public_inputs[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.fold_input_eval_messages[round][idx],
                    layout.witness_fold_input_eval_messages[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.witness_fold_input_eval_messages[round][idx],
                    layout.round_message_rows[round][idx],
                );
            }
        }
        equalities
    }

    #[must_use]
    pub fn folded_public_input_linear_constraints(
        &self,
    ) -> Vec<BatchedCpFoldedPublicInputLinearConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut constraints = Vec::new();
            for idx in 0..self.active_count {
                for public_idx in 0..self.accumulator_shape.folded_public_input_len {
                    for coeff_idx in 0..D {
                        constraints.push(BatchedCpFoldedPublicInputLinearConstraint {
                            beta_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    layout.witness_local_betas[round][idx].offset + coeff_idx * 8
                                })
                                .collect(),
                            input_scalar_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    layout.fold_input_public_inputs[round][idx].offset
                                        + public_idx * 8
                                })
                                .collect(),
                            output_coeff_offset:
                                folded_output_contribution_public_input_coeff_offset(
                                    &self.accumulator_shape,
                                    layout.folded_output_contributions[idx],
                                    public_idx,
                                    coeff_idx,
                                ),
                        });
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn folded_commitment_ring_mul_constraints(
        &self,
    ) -> Vec<BatchedCpFoldedCommitmentRingMulConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut constraints = Vec::new();
            for idx in 0..self.active_count {
                for commitment_idx in 0..self.accumulator_shape.commitment_kappa {
                    for coeff_idx in 0..D {
                        constraints.push(BatchedCpFoldedCommitmentRingMulConstraint {
                            beta_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    (0..D)
                                        .map(|beta_coeff_idx| {
                                            layout.witness_local_betas[round][idx].offset
                                                + beta_coeff_idx * 8
                                        })
                                        .collect()
                                })
                                .collect(),
                            commitment_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    let commitment = layout.fold_input_commitments[round][idx];
                                    (0..D)
                                        .map(|commitment_coeff_idx| {
                                            commitment.offset
                                                + 8
                                                + commitment_idx * D * 8
                                                + commitment_coeff_idx * 8
                                        })
                                        .collect()
                                })
                                .collect(),
                            output_coeff_index: coeff_idx,
                            output_coeff_offset: folded_output_contribution_commitment_coeff_offset(
                                layout.folded_output_contributions[idx],
                                commitment_idx,
                                coeff_idx,
                            ),
                        });
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn folded_evaluation_ring_mul_constraints(
        &self,
    ) -> Vec<BatchedCpFoldedEvaluationRingMulConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut constraints = Vec::new();
            for idx in 0..self.active_count {
                for eval_idx in 0..self.accumulator_shape.folded_evaluation_count {
                    for tensor_row in 0..T {
                        for coeff_idx in 0..D {
                            constraints.push(BatchedCpFoldedEvaluationRingMulConstraint {
                                beta_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                    .map(|round| {
                                        (0..D)
                                            .map(|beta_coeff_idx| {
                                                layout.witness_local_betas[round][idx].offset
                                                    + beta_coeff_idx * 8
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                evaluation_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                    .map(|round| {
                                        let eval_offset = self
                                            .accumulator_shape
                                            .gr1cs_hadamard_eval_offsets[round][eval_idx];
                                        (0..D)
                                            .map(|input_coeff_idx| {
                                                layout.fold_input_eval_messages[round][idx].offset
                                                    + eval_offset
                                                    + tensor_row * D * 8
                                                    + input_coeff_idx * 8
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                output_coeff_index: coeff_idx,
                                output_coeff_offset:
                                    folded_output_contribution_evaluation_coeff_offset(
                                        &self.accumulator_shape,
                                        layout.folded_output_contributions[idx],
                                        eval_idx,
                                        tensor_row,
                                        coeff_idx,
                                    ),
                            });
                        }
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn product_oracle_layout(&self) -> BatchedCpProductOracleLayout {
        let mut cursor = ProductOracleCursor::new();
        cursor.push_bytes(b"symphony-batched-cp-product-oracle-v1");
        cursor.push_raw_len(encoded_statement_shape(self).len());
        cursor.push_usize();
        let mut witness_rows = Vec::with_capacity(self.batch_capacity);
        let mut witness_item_tags = Vec::with_capacity(self.batch_capacity);
        let mut witness_public_statements = Vec::with_capacity(self.batch_capacity);
        let mut witness_folded_output_contributions = Vec::with_capacity(self.batch_capacity);
        let mut witness_local_betas: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fs_commitments: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fs_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fs_openings: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fold_input_commitments: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fold_input_public_inputs: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fold_input_eval_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_original_witnesses: Vec<Vec<BatchedCpOracleByteRange>> = self
            .accumulator_shape
            .original_witness_lens
            .iter()
            .map(|_| Vec::with_capacity(self.batch_capacity))
            .collect();
        let mut witness_active_markers = Vec::with_capacity(self.batch_capacity);
        for idx in 0..self.batch_capacity {
            cursor.push_usize();
            witness_active_markers.push(cursor.offset);
            cursor.push_u8();
            if idx < self.active_count {
                let row_offset = cursor.offset + 8;
                witness_rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(self.witness_row_len),
                    len: self.witness_row_len,
                });
                witness_item_tags.push(BatchedCpOracleByteRange {
                    offset: row_offset,
                    len: 32,
                });
                witness_public_statements.push(BatchedCpOracleByteRange {
                    offset: row_offset + 32,
                    len: self.accumulator_shape.public_statement_len,
                });
                witness_folded_output_contributions.push(BatchedCpOracleByteRange {
                    offset: row_offset + 32 + self.accumulator_shape.public_statement_len,
                    len: self.accumulator_shape.folded_output_contribution_len,
                });
                let mut inner = row_offset
                    + 32
                    + self.accumulator_shape.public_statement_len
                    + self.accumulator_shape.folded_output_contribution_len;
                for betas in witness_local_betas
                    .iter_mut()
                    .take(self.accumulator_shape.num_rounds)
                {
                    betas.push(BatchedCpOracleByteRange {
                        offset: inner,
                        len: D * 8,
                    });
                    inner += D * 8;
                }
                for (round, &message_len) in
                    self.accumulator_shape.fs_message_lens.iter().enumerate()
                {
                    witness_fs_messages[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: message_len,
                    });
                    inner += 8 + message_len;
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    let commitment_len = self.accumulator_shape.fs_commitment_len;
                    witness_fs_commitments[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: commitment_len,
                    });
                    inner += 8 + commitment_len;
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    witness_fs_openings[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: self.accumulator_shape.fs_opening_len,
                    });
                    inner += 8 + self.accumulator_shape.fs_opening_len;
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    let commitment_len = self.accumulator_shape.fold_input_commitment_lens[round];
                    witness_fold_input_commitments[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: commitment_len,
                    });
                    inner += 8 + commitment_len;

                    let public_input_len =
                        self.accumulator_shape.fold_input_public_input_lens[round] * 8;
                    witness_fold_input_public_inputs[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: public_input_len,
                    });
                    inner += 8 + public_input_len;

                    let eval_message_len =
                        self.accumulator_shape.fold_input_eval_message_lens[round];
                    witness_fold_input_eval_messages[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: eval_message_len,
                    });
                    inner += 8 + eval_message_len;
                }
                for (witness_idx, &witness_len) in self
                    .accumulator_shape
                    .original_witness_lens
                    .iter()
                    .enumerate()
                {
                    witness_original_witnesses[witness_idx].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: witness_len * D * 8,
                    });
                    inner += 8 + witness_len * D * 8;
                }
            } else {
                witness_rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(0),
                    len: 0,
                });
                witness_item_tags.push(BatchedCpOracleByteRange {
                    offset: cursor.offset,
                    len: 0,
                });
                witness_public_statements.push(BatchedCpOracleByteRange {
                    offset: cursor.offset,
                    len: 0,
                });
                witness_folded_output_contributions.push(BatchedCpOracleByteRange {
                    offset: cursor.offset,
                    len: 0,
                });
                for betas in witness_local_betas
                    .iter_mut()
                    .take(self.accumulator_shape.num_rounds)
                {
                    betas.push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    witness_fs_messages[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fs_commitments[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fs_openings[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fold_input_commitments[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fold_input_public_inputs[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fold_input_eval_messages[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
                for witness_ranges in witness_original_witnesses.iter_mut() {
                    witness_ranges.push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
            }
        }

        cursor.push_usize();
        let mut round_message_rows = Vec::with_capacity(self.round_message_lens.len());
        let mut round_message_active_markers = Vec::with_capacity(self.round_message_lens.len());
        for &message_len in &self.round_message_lens {
            cursor.push_usize();
            cursor.push_usize();
            let mut rows = Vec::with_capacity(self.batch_capacity);
            let mut markers = Vec::with_capacity(self.batch_capacity);
            for idx in 0..self.batch_capacity {
                cursor.push_usize();
                markers.push(cursor.offset);
                cursor.push_u8();
                let len = if idx < self.active_count {
                    message_len
                } else {
                    0
                };
                rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(len),
                    len,
                });
            }
            round_message_rows.push(rows);
            round_message_active_markers.push(markers);
        }

        cursor.push_usize();
        let mut round_message_digest_bodies = Vec::with_capacity(self.round_message_lens.len());
        let mut round_message_digest_body_active_markers =
            Vec::with_capacity(self.round_message_lens.len());
        for &message_len in &self.round_message_lens {
            cursor.push_bytes(b"symphony-batched-cp-round-message-v1");
            cursor.push_raw_len(32);
            cursor.push_usize();
            cursor.push_usize();
            let mut rows = Vec::with_capacity(self.batch_capacity);
            let mut markers = Vec::with_capacity(self.batch_capacity);
            for idx in 0..self.batch_capacity {
                cursor.push_usize();
                markers.push(cursor.offset);
                cursor.push_u8();
                let len = if idx < self.active_count {
                    message_len
                } else {
                    0
                };
                rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(len),
                    len,
                });
            }
            round_message_digest_bodies.push(rows);
            round_message_digest_body_active_markers.push(markers);
        }

        let manifest_start = cursor.offset;
        let mut manifest_active_markers = Vec::with_capacity(self.batch_capacity);
        let mut manifest_item_tags = Vec::with_capacity(self.batch_capacity);
        let mut manifest_public_statements = Vec::with_capacity(self.batch_capacity);
        cursor.push_bytes(b"symphony-batched-cp-manifest-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        for idx in 0..self.batch_capacity {
            cursor.push_usize();
            manifest_active_markers.push(cursor.offset);
            cursor.push_u8();
            manifest_item_tags.push(BatchedCpOracleByteRange {
                offset: cursor.push_raw_len(32),
                len: 32,
            });
            if idx < self.active_count {
                manifest_public_statements.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(self.accumulator_shape.public_statement_len),
                    len: self.accumulator_shape.public_statement_len,
                });
            } else {
                manifest_public_statements.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(0),
                    len: 0,
                });
            }
        }
        let manifest_body = BatchedCpOracleByteRange {
            offset: manifest_start,
            len: cursor.offset - manifest_start,
        };
        debug_assert_eq!(manifest_body.len, manifest_body_len(self));
        let fs_commitment_body_start = cursor.offset;
        let mut fs_commitment_bodies: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fs_commitment_body_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fs_commitment_body_openings: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fs_commitment_body_active_markers: Vec<Vec<usize>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut poseidon_fs_commitment_trace_outputs: Vec<Vec<BatchedCpOracleByteRange>> = (0
            ..self.accumulator_shape.num_rounds)
            .map(|_| Vec::with_capacity(self.active_count))
            .collect();
        let mut poseidon_fs_commitment_trace_inputs: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut poseidon_fs_commitment_trace_aux: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut poseidon_fs_commitment_trace_active_markers: Vec<Vec<usize>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        cursor.push_bytes(b"symphony-batched-cp-fs-commitment-bodies-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        for round in 0..self.accumulator_shape.num_rounds {
            cursor.push_usize();
            for _idx in 0..self.active_count {
                cursor.push_usize();
                fs_commitment_body_active_markers[round].push(cursor.offset);
                cursor.push_u8();
                let body_start = cursor.offset;
                cursor.push_usize();
                let message_len = self.accumulator_shape.fs_message_lens[round];
                fs_commitment_body_messages[round].push(BatchedCpOracleByteRange {
                    offset: cursor.push_raw_len(message_len),
                    len: message_len,
                });
                let opening_len = self.accumulator_shape.fs_opening_len;
                fs_commitment_body_openings[round].push(BatchedCpOracleByteRange {
                    offset: cursor.push_raw_len(opening_len),
                    len: opening_len,
                });
                fs_commitment_bodies[round].push(BatchedCpOracleByteRange {
                    offset: body_start,
                    len: cursor.offset - body_start,
                });
            }
        }
        let fs_commitment_body = BatchedCpOracleByteRange {
            offset: fs_commitment_body_start,
            len: cursor.offset - fs_commitment_body_start,
        };
        debug_assert_eq!(fs_commitment_body.len, fs_commitment_bodies_body_len(self));
        if poseidon_fs_commitment_traces_enabled(self) {
            let poseidon_trace_start = cursor.offset;
            cursor.push_bytes(b"symphony-batched-cp-poseidon-fs-commitment-traces-v1");
            cursor.push_raw_len(32);
            cursor.push_usize();
            cursor.push_usize();
            for round in 0..self.accumulator_shape.num_rounds {
                cursor.push_usize();
                let input_len = poseidon_fs_commitment_input_len(
                    self.accumulator_shape.fs_message_lens[round],
                    self.accumulator_shape.fs_opening_len,
                );
                let aux_len = poseidon_fs_commitment_aux_len(input_len);
                for _idx in 0..self.active_count {
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_active_markers[round].push(cursor.offset);
                    cursor.push_u8();
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_outputs[round].push(BatchedCpOracleByteRange {
                        offset: cursor.push_raw_len(8 * 4),
                        len: 8 * 4,
                    });
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_inputs[round].push(BatchedCpOracleByteRange {
                        offset: cursor.push_raw_len(input_len * 4),
                        len: input_len * 4,
                    });
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_aux[round].push(BatchedCpOracleByteRange {
                        offset: cursor.push_raw_len(aux_len * 4),
                        len: aux_len * 4,
                    });
                }
            }
            let poseidon_trace_body = BatchedCpOracleByteRange {
                offset: poseidon_trace_start,
                len: cursor.offset - poseidon_trace_start,
            };
            debug_assert_eq!(
                poseidon_trace_body.len,
                poseidon_fs_commitment_traces_body_len(self)
            );
        }
        let batch_challenge_body = BatchedCpOracleByteRange {
            offset: cursor.offset,
            len: batch_challenge_body_len(self),
        };
        cursor.push_raw_len(batch_challenge_body.len);
        let challenge_to_beta_start = cursor.offset;
        cursor.push_bytes(b"symphony-batched-cp-challenge-to-beta-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        let challenge_to_beta_digest = BatchedCpOracleByteRange {
            offset: cursor.push_raw_len(32),
            len: 32,
        };
        let challenge_to_beta_beta = BatchedCpOracleByteRange {
            offset: cursor.push_raw_len(D * 8),
            len: D * 8,
        };
        let challenge_to_beta_body = BatchedCpOracleByteRange {
            offset: challenge_to_beta_start,
            len: cursor.offset - challenge_to_beta_start,
        };
        debug_assert_eq!(challenge_to_beta_body.len, challenge_to_beta_body_len(self));
        let fold_input_start = cursor.offset;
        let mut fold_input_commitments: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fold_input_public_inputs: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fold_input_eval_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        cursor.push_bytes(b"symphony-batched-cp-fold-input-reconstruction-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        for _idx in 0..self.active_count {
            cursor.push_usize();
            for round in 0..self.accumulator_shape.num_rounds {
                cursor.push_usize();
                fold_input_commitments[round].push(BatchedCpOracleByteRange {
                    offset: cursor
                        .push_bytes_len(self.accumulator_shape.fold_input_commitment_lens[round]),
                    len: self.accumulator_shape.fold_input_commitment_lens[round],
                });
                let public_input_len =
                    self.accumulator_shape.fold_input_public_input_lens[round] * 8;
                cursor.push_usize();
                fold_input_public_inputs[round].push(BatchedCpOracleByteRange {
                    offset: cursor.push_raw_len(public_input_len),
                    len: public_input_len,
                });
                fold_input_eval_messages[round].push(BatchedCpOracleByteRange {
                    offset: cursor
                        .push_bytes_len(self.accumulator_shape.fold_input_eval_message_lens[round]),
                    len: self.accumulator_shape.fold_input_eval_message_lens[round],
                });
            }
        }
        let fold_input_reconstruction_body = BatchedCpOracleByteRange {
            offset: fold_input_start,
            len: cursor.offset - fold_input_start,
        };
        debug_assert_eq!(
            fold_input_reconstruction_body.len,
            fold_input_reconstruction_body_len(self)
        );
        let folded_output_start = cursor.offset;
        let mut folded_output_contributions = Vec::with_capacity(self.active_count);
        cursor.push_bytes(b"symphony-batched-cp-folded-output-accumulator-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        let folded_output_accumulator_root = BatchedCpOracleByteRange {
            offset: cursor.push_raw_len(32),
            len: 32,
        };
        cursor.push_usize();
        for _ in 0..self.active_count {
            folded_output_contributions.push(BatchedCpOracleByteRange {
                offset: cursor.push_raw_len(self.accumulator_shape.folded_output_contribution_len),
                len: self.accumulator_shape.folded_output_contribution_len,
            });
        }
        let folded_output_accumulator_body = BatchedCpOracleByteRange {
            offset: folded_output_start,
            len: cursor.offset - folded_output_start,
        };
        debug_assert_eq!(
            folded_output_accumulator_body.len,
            folded_output_accumulator_body_len(self)
        );
        let byte_len = cursor.offset;
        BatchedCpProductOracleLayout {
            byte_len,
            packed_field_len: byte_len.div_ceil(3) + 1,
            witness_rows,
            witness_item_tags,
            witness_public_statements,
            witness_folded_output_contributions,
            witness_local_betas,
            witness_fs_commitments,
            witness_fold_input_commitments,
            witness_fold_input_public_inputs,
            witness_fold_input_eval_messages,
            witness_original_witnesses,
            witness_fs_messages,
            witness_fs_openings,
            witness_active_markers,
            round_message_rows,
            round_message_active_markers,
            round_message_digest_bodies,
            round_message_digest_body_active_markers,
            fs_commitment_bodies,
            fs_commitment_body_messages,
            fs_commitment_body_openings,
            fs_commitment_body_active_markers,
            poseidon_fs_commitment_trace_outputs,
            poseidon_fs_commitment_trace_inputs,
            poseidon_fs_commitment_trace_aux,
            poseidon_fs_commitment_trace_active_markers,
            manifest_active_markers,
            manifest_item_tags,
            manifest_public_statements,
            manifest_body,
            batch_challenge_body,
            challenge_to_beta_body,
            challenge_to_beta_digest,
            challenge_to_beta_beta,
            folded_output_accumulator_body,
            folded_output_accumulator_root,
            folded_output_contributions,
            fold_input_reconstruction_body,
            fold_input_commitments,
            fold_input_public_inputs,
            fold_input_eval_messages,
        }
    }

    #[must_use]
    pub fn structured_relation_description(&self) -> BatchedCpStructuredRelationDescription {
        BatchedCpStructuredRelationDescription {
            shape: self.clone(),
            public_statement_bytes: estimate_public_statement_bytes(self),
            product_domain_size: self.product_domain_size(),
            witness_oracle_row_len: self.witness_row_len,
            round_message_oracle_lens: self.round_message_lens.clone(),
        }
    }

    #[must_use]
    pub fn semantic_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticRelationDescription {
        BatchedCpSemanticRelationDescription {
            shape: self.clone(),
            oracle_layout: self.product_oracle_layout(),
            ajtai_params_digest: digest_ajtai_params(self.accumulator_shape.digest_scheme, ajtai),
            ajtai_matrix: ajtai.a.clone(),
            r1cs_matrices_digest: digest_r1cs_matrices(self.accumulator_shape.digest_scheme, r1cs),
            r1cs_matrices: r1cs.clone(),
            input_bound,
            constraint_families: vec![
                BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                BatchedCpSemanticConstraintFamily::ManifestMembership,
                BatchedCpSemanticConstraintFamily::RoundMessageBinding,
                BatchedCpSemanticConstraintFamily::ChallengeDerivation,
                BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
                BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
                BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
                BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
                BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            ],
        }
    }

    #[must_use]
    pub fn semantic_v2_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticRelationV2Description {
        let semantic = self.semantic_relation_description(ajtai, r1cs, input_bound);
        BatchedCpSemanticRelationV2Description {
            v2_layout: BatchedCpSemanticOracleV2Layout::from_semantic(&semantic),
            semantic,
        }
    }

    #[must_use]
    pub fn semantic_columnar_v2_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticColumnarV2Description {
        let semantic = self.semantic_relation_description(ajtai, r1cs, input_bound);
        BatchedCpSemanticColumnarV2Description {
            v2_layout: BatchedCpSemanticOracleV2Layout::from_semantic(&semantic),
            columnar_layout: BatchedCpSemanticColumnarV2Layout::from_semantic(&semantic),
            semantic,
        }
    }

    #[must_use]
    pub fn semantic_family_columnar_v2_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticFamilyColumnarV2Description {
        let semantic = self.semantic_relation_description(ajtai, r1cs, input_bound);
        BatchedCpSemanticFamilyColumnarV2Description {
            v2_layout: BatchedCpSemanticOracleV2Layout::from_semantic(&semantic),
            family_layout: BatchedCpSemanticFamilyColumnarV2Layout::from_semantic(&semantic),
            semantic,
        }
    }

    #[must_use]
    pub fn symbt3_setup_descriptor(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSymbt3SetupDescriptor {
        let ajtai_params_digest = digest_ajtai_params(self.accumulator_shape.digest_scheme, ajtai);
        let ring_module_layout = Symbt3RingModuleLayout::from_shape_and_ajtai(self, ajtai);
        let ajtai_commit_layout =
            Symbt3AjtaiCommitLayout::from_shape_and_ajtai(self, ajtai, ajtai_params_digest);
        let r1cs_matrices_digest = digest_r1cs_matrices(self.accumulator_shape.digest_scheme, r1cs);
        let r1cs_evaluator_layout =
            Symbt3R1csEvaluatorLayout::from_shape_and_r1cs(self, r1cs, r1cs_matrices_digest);
        let gr1cs_residual_layout = Symbt3Gr1csResidualLayout::from_shape(self);
        let algebra_law = Symbt3AlgebraLaw::from_shape(self);
        let ajtai_linear_algebra_layout = Symbt3AjtaiLinearAlgebraLayout::from_shape_and_layouts(
            self,
            &algebra_law,
            &ajtai_commit_layout,
            ajtai_params_digest,
            self.accumulator_shape.digest_scheme,
        );
        let ajtai_norm_range_layout = Symbt3AjtaiNormRangeLayout::from_shape_and_layouts(
            self,
            &algebra_law,
            &ajtai_linear_algebra_layout,
            input_bound,
            self.accumulator_shape.digest_scheme,
        );
        let batch_manifest_layout = Symbt3BatchManifestLayout::from_shape(self);
        let message_semantic_layout = Symbt3MessageSemanticLayout::from_shape_and_layouts(
            self,
            &BatchedCpSymbt3OracleLayout::from_shape(self),
            &algebra_law,
            &gr1cs_residual_layout,
            &ajtai_linear_algebra_layout,
            &ajtai_norm_range_layout,
            &batch_manifest_layout,
            self.accumulator_shape.digest_scheme,
        );
        let folded_gr1cs_product_residual_layout =
            Symbt3FoldedGr1csProductResidualLayout::from_shape(self);
        BatchedCpSymbt3SetupDescriptor {
            shape: self.clone(),
            ring_module_layout,
            ajtai_commit_layout,
            r1cs_evaluator_layout,
            gr1cs_residual_layout,
            algebra_law,
            ajtai_linear_algebra_layout,
            ajtai_norm_range_layout,
            batch_manifest_layout,
            message_semantic_layout,
            folded_gr1cs_product_residual_layout,
            ajtai_matrix: ajtai.a.clone(),
            r1cs_matrices: r1cs.clone(),
            ajtai_params_digest,
            r1cs_matrices_digest,
            input_bound,
        }
    }
}

impl Symbt3RingModuleLayout {
    #[must_use]
    pub fn from_shape_and_ajtai(_shape: &BatchedCpStatementShape, ajtai: &AjtaiParams) -> Self {
        Self {
            ring_degree: D,
            modulus: ajtai.q,
            basis_order: "coefficient-ascending",
            negacyclic_sign_convention: "x^D=-1",
            action_side: Symbt3RingActionSide::Left,
            opening_module_dimension: ajtai.n,
            commitment_module_dimension: ajtai.kappa,
            coordinate_encoding: "centered-i64-le",
            beta_encoding: "digest-base5-ring-coefficients",
            ring_action_version: SYMBT3_RING_ACTION_VERSION,
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        push_usize(&mut body, self.ring_degree);
        body.extend_from_slice(&self.modulus.to_le_bytes());
        push_bytes(&mut body, self.basis_order.as_bytes());
        push_bytes(&mut body, self.negacyclic_sign_convention.as_bytes());
        body.push(match self.action_side {
            Symbt3RingActionSide::Left => 1,
        });
        push_usize(&mut body, self.opening_module_dimension);
        push_usize(&mut body, self.commitment_module_dimension);
        push_bytes(&mut body, self.coordinate_encoding.as_bytes());
        push_bytes(&mut body, self.beta_encoding.as_bytes());
        body.extend_from_slice(&self.ring_action_version.to_le_bytes());
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ring-module-layout", &body)
    }
}

impl Symbt3AjtaiCommitLayout {
    #[must_use]
    pub fn from_shape_and_ajtai(
        shape: &BatchedCpStatementShape,
        ajtai: &AjtaiParams,
        ajtai_params_digest: Digest32,
    ) -> Self {
        let mut evaluator_body = Vec::new();
        evaluator_body.extend_from_slice(&ajtai_params_digest);
        push_usize(&mut evaluator_body, ajtai.kappa);
        push_usize(&mut evaluator_body, ajtai.n);
        evaluator_body.extend_from_slice(&ajtai.q.to_le_bytes());
        let indexed_evaluator_id = digest_domain_with_scheme(
            shape.accumulator_shape.digest_scheme,
            b"batched-cp-symbt3-ajtai-indexed-evaluator",
            &evaluator_body,
        );
        Self {
            layout_version: SYMBT3_AJTAI_COMMIT_LAYOUT_VERSION,
            commitment_module_dimension: ajtai.kappa,
            opening_module_dimension: ajtai.n,
            ring_degree: D,
            modulus: ajtai.q,
            indexed_evaluator_id,
            separated_message_randomness: false,
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        body.extend_from_slice(&self.layout_version.to_le_bytes());
        push_usize(&mut body, self.commitment_module_dimension);
        push_usize(&mut body, self.opening_module_dimension);
        push_usize(&mut body, self.ring_degree);
        body.extend_from_slice(&self.modulus.to_le_bytes());
        body.extend_from_slice(&self.indexed_evaluator_id);
        body.push(u8::from(self.separated_message_randomness));
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ajtai-commit-layout", &body)
    }
}

impl Symbt3AjtaiLinearAlgebraLayout {
    #[must_use]
    pub fn from_shape_and_layouts(
        _shape: &BatchedCpStatementShape,
        algebra_law: &Symbt3AlgebraLaw,
        ajtai_commit_layout: &Symbt3AjtaiCommitLayout,
        ajtai_matrix_digest: Digest32,
        scheme: PublicDigestScheme,
    ) -> Self {
        let algebra_law_digest = algebra_law.digest(scheme);
        let ajtai_commit_layout_digest = ajtai_commit_layout.digest(scheme);
        Self {
            version_marker: b"SYMBT3F\0",
            layout_version: SYMBT3_AJTAI_LINEAR_ALGEBRA_LAYOUT_VERSION,
            algebra_law_digest,
            ajtai_matrix_digest,
            ajtai_commit_layout_digest,
            kappa: ajtai_commit_layout.commitment_module_dimension,
            opening_len: ajtai_commit_layout.opening_module_dimension,
            ring_degree: D,
            source_opening_column: 0,
            source_commitment_column: 1,
            folded_opening_column: 2,
            folded_commitment_column: 3,
            beta_action: algebra_law.beta_action,
            product_law: algebra_law.product_law,
            matrix_vector_evaluator: Symbt3AjtaiMatrixVectorEvaluatorId::DirectDevMatrixVectorV1,
            padding_policy: "selector-zero-padded-tail",
            selector_evaluator: "prefix-active-item-selector-v1",
            opening_mode: Symbt3AjtaiOpeningMode::StrictAfEqualsC,
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_ajtai_linear_algebra_layout(&mut body, self);
        digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-ajtai-linear-algebra-layout",
            &body,
        )
    }
}

impl Symbt3ProjectionLayout {
    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_projection_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-projection-layout", &body)
    }
}

impl Symbt3RangeLayout {
    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_range_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-range-layout", &body)
    }
}

impl Symbt3MonomialEmbeddingLayout {
    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_monomial_embedding_layout(&mut body, self);
        digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-monomial-embedding-layout",
            &body,
        )
    }
}

impl Symbt3RepresentativeLayout {
    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_representative_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-representative-layout", &body)
    }
}

impl Symbt3AjtaiNormRangeLayout {
    #[must_use]
    pub fn from_shape_and_layouts(
        shape: &BatchedCpStatementShape,
        algebra_law: &Symbt3AlgebraLaw,
        ajtai_linear_algebra_layout: &Symbt3AjtaiLinearAlgebraLayout,
        input_bound: u64,
        scheme: PublicDigestScheme,
    ) -> Self {
        let input_len =
            ajtai_linear_algebra_layout.opening_len * ajtai_linear_algebra_layout.ring_degree;
        let mut projection_body = Vec::new();
        projection_body.extend_from_slice(&shape.shape_id);
        projection_body.extend_from_slice(&ajtai_linear_algebra_layout.digest(scheme));
        push_usize(&mut projection_body, input_len);
        let block_len = D.min(input_len.max(1));
        let rows_per_block = 1usize;
        let output_len = input_len.div_ceil(block_len) * rows_per_block;
        push_usize(&mut projection_body, block_len);
        push_usize(&mut projection_body, output_len);
        let projection_matrix_digest = digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-j-structured-block-projection",
            &projection_body,
        );
        let projection_layout = Symbt3ProjectionLayout {
            layout_version: SYMBT3_PROJECTION_LAYOUT_VERSION,
            projection_mode: Symbt3ProjectionMode::StructuredBlockProjectionV1,
            projection_seed_policy: Symbt3ProjectionSeedPolicy::ProofBoundDeterministicV1,
            projection_matrix_digest,
            input_len,
            output_len,
            block_len,
            rows_per_block,
            entry_distribution: Symbt3ProjectionEntryDistribution::ZeroPlusMinusOneV1,
            coefficient_domain: "check-field-native-ring-coefficients",
        };
        let max_beta_coeff = 2i64;
        let active = shape.active_count.max(1) as i128;
        let bound = (input_bound as i128)
            .saturating_mul(max_beta_coeff as i128)
            .saturating_mul(D as i128)
            .saturating_mul(block_len as i128)
            .saturating_mul(active)
            .min(i64::MAX as i128) as i64;
        let mut table_body = Vec::new();
        table_body.extend_from_slice(&shape.shape_id);
        table_body.extend_from_slice(&projection_matrix_digest);
        table_body.extend_from_slice(&bound.max(1).to_le_bytes());
        let table_polynomial_digest = digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-j-monomial-range-table",
            &table_body,
        );
        let monomial_embedding_layout = Symbt3MonomialEmbeddingLayout {
            layout_version: SYMBT3_MONOMIAL_EMBEDDING_LAYOUT_VERSION,
            ring_degree: D,
            bound_b: bound.max(1) as usize,
            table_polynomial_digest,
            monomiality_mode: Symbt3MonomialityMode::OneHotCoefficientVectorV1,
            constant_term_policy: Symbt3ConstantTermPolicy::SignedRangeTableV1,
            signed_convention: Symbt3SignedConvention::CenteredExponentV1,
        };
        let mut modulus_body = Vec::new();
        encode_symbt3_algebra_law(&mut modulus_body, algebra_law);
        let modulus_digest = digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-j-representative-modulus",
            &modulus_body,
        );
        let representative_layout = Symbt3RepresentativeLayout {
            layout_version: SYMBT3_REPRESENTATIVE_LAYOUT_VERSION,
            modulus_digest,
            signed_range: bound.max(1),
            canonical_rep_policy: Symbt3CanonicalRepPolicy::CenteredModQRepresentativeV1,
        };
        let monomial_embedding_layout_digest = monomial_embedding_layout.digest(scheme);
        let range_layout = Symbt3RangeLayout {
            layout_version: SYMBT3_RANGE_LAYOUT_VERSION,
            range_mode: Symbt3RangeMode::MonomialEmbeddingRangeV1,
            bound_b: bound.max(1),
            signed_encoding: Symbt3SignedEncoding::CheckFieldSignedRepresentativeV1,
            table_digest: Some(table_polynomial_digest),
            monomial_embedding_layout_digest: Some(monomial_embedding_layout_digest),
        };
        Self {
            version_marker: b"SYMBT3J\0",
            layout_version: SYMBT3_AJTAI_NORM_RANGE_LAYOUT_VERSION,
            algebra_law_digest: algebra_law.digest(scheme),
            ajtai_linear_algebra_layout_digest: ajtai_linear_algebra_layout.digest(scheme),
            folded_opening_column: 0,
            projected_opening_column: 1,
            monomial_witness_column: 2,
            projection_layout,
            range_layout,
            monomial_embedding_layout,
            representative_layout,
            norm_bound: bound.max(1),
            coefficient_encoding: Symbt3CoefficientEncoding::CenteredI64LeV1,
            reduction_policy: "CheckFieldNativeV1",
            selector_evaluator: "valid-folded-opening-coordinate-selector-v1",
            padding_policy: "selector-zero-padded-tail",
            range_mode: Symbt3RangeMode::MonomialEmbeddingRangeV1,
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_ajtai_norm_range_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ajtai-norm-range-layout", &body)
    }
}

impl Symbt3ManifestOracleLayout {
    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_manifest_oracle_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-manifest-oracle-layout", &body)
    }
}

impl Symbt3SourceColumnLayout {
    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_source_column_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-source-column-layout", &body)
    }
}

impl Symbt3BatchManifestLayout {
    #[must_use]
    pub fn from_shape(shape: &BatchedCpStatementShape) -> Self {
        let mut next_column = 0usize;
        let mut component = |kind, coordinate_len, visibility, membership_mode| {
            let layout = Symbt3ManifestComponentLayout {
                kind,
                coordinate_len,
                source_column_id: next_column,
                manifest_column_id: next_column + 1,
                visibility,
                membership_mode,
                padding_policy: "selector-zero-padded-tail",
            };
            next_column += 2;
            layout
        };
        let public_len = shape.accumulator_shape.local_public_input_count
            * shape.accumulator_shape.r1cs_num_public;
        let commitment_len =
            shape.accumulator_shape.commitment_kappa * shape.accumulator_shape.commitment_d;
        let evaluation_len = shape.accumulator_shape.folded_evaluation_count * T * D;
        let accumulator_len = public_len + commitment_len + evaluation_len;
        let assignment_root_len = shape.accumulator_shape.local_public_input_count * 32;
        let message_root_len = shape.accumulator_shape.num_rounds * 32;
        let component_kinds = vec![
            component(
                Symbt3ManifestComponentKind::PublicInput,
                public_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::CoordinateEquality,
            ),
            component(
                Symbt3ManifestComponentKind::SourceCommitmentCoordinate,
                commitment_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::CoordinateEquality,
            ),
            component(
                Symbt3ManifestComponentKind::SourceEvaluationCoordinate,
                evaluation_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::CoordinateEquality,
            ),
            component(
                Symbt3ManifestComponentKind::SourceAccumulatorBoundaryCoordinate,
                accumulator_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::CoordinateEquality,
            ),
            component(
                Symbt3ManifestComponentKind::SourceAjtaiCommitmentCoordinate,
                commitment_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::CoordinateEquality,
            ),
            component(
                Symbt3ManifestComponentKind::SourceAssignmentRootCoordinate,
                assignment_root_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::RootDigestEquality,
            ),
            component(
                Symbt3ManifestComponentKind::SourceMessageRootCoordinate,
                message_root_len,
                Symbt3ManifestVisibility::PublicBoundaryCoordinate,
                Symbt3MembershipMode::RootDigestEquality,
            ),
        ];
        let coordinate_count = component_kinds
            .iter()
            .map(|component| component.coordinate_len)
            .sum::<usize>();
        let manifest_oracle_layout = Symbt3ManifestOracleLayout {
            layout_version: SYMBT3_MANIFEST_ORACLE_LAYOUT_VERSION,
            row_count: shape.batch_capacity,
            component_count: component_kinds.len(),
            coordinate_count,
            coordinate_ordering: "item-component-coordinate",
        };
        let source_column_layout = Symbt3SourceColumnLayout {
            layout_version: SYMBT3_SOURCE_COLUMN_LAYOUT_VERSION,
            component_count: component_kinds.len(),
            coordinate_count,
            source_column_ordering: "item-component-coordinate",
            root_binding_policy: "digest-coordinate-boundary-v1",
        };
        Self {
            version_marker: b"SYMBT3H\0",
            layout_version: SYMBT3_BATCH_MANIFEST_LAYOUT_VERSION,
            batch_size: shape.batch_capacity,
            active_count: shape.active_count,
            active_policy: Symbt3ActivePolicy::PrefixActiveCountV1,
            manifest_oracle_layout,
            source_column_layout,
            component_kinds,
            commitment_scheme_id: Symbt3CommitmentSchemeId::WhirDevOracleRootV1,
            manifest_root_policy: Symbt3ManifestRootPolicy::TypedDigestRootV1,
            selector_evaluator: "prefix-active-valid-component-selector-v1",
            padding_policy: "selector-zero-padded-tail",
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_batch_manifest_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-batch-manifest-layout", &body)
    }
}

impl Symbt3MessageSemanticLayout {
    #[must_use]
    pub fn from_shape_and_layouts(
        shape: &BatchedCpStatementShape,
        oracle_layout: &BatchedCpSymbt3OracleLayout,
        algebra_law: &Symbt3AlgebraLaw,
        gr1cs_residual_layout: &Symbt3Gr1csResidualLayout,
        ajtai_linear_algebra_layout: &Symbt3AjtaiLinearAlgebraLayout,
        ajtai_norm_range_layout: &Symbt3AjtaiNormRangeLayout,
        batch_manifest_layout: &Symbt3BatchManifestLayout,
        scheme: PublicDigestScheme,
    ) -> Self {
        let round_layouts = oracle_layout
            .message_oracles
            .iter()
            .map(|oracle| {
                let polynomial_len = oracle.packed_field_len.min(2);
                let claim_len = oracle
                    .packed_field_len
                    .saturating_sub(polynomial_len)
                    .min(2);
                let eval_point_len = oracle
                    .packed_field_len
                    .saturating_sub(polynomial_len + claim_len)
                    .min(1);
                let eval_value_len = oracle
                    .packed_field_len
                    .saturating_sub(polynomial_len + claim_len + eval_point_len)
                    .min(1);
                let mut offset = 0usize;
                let mut sections = Vec::new();
                let mut push_section =
                    |section_kind, coordinate_len, algebra_type, visibility, binding_mode| {
                        if coordinate_len == 0 {
                            return;
                        }
                        sections.push(Symbt3MessageSectionLayout {
                            layout_version: SYMBT3_MESSAGE_SECTION_LAYOUT_VERSION,
                            section_kind,
                            coordinate_offset: offset,
                            coordinate_len,
                            algebra_type,
                            visibility,
                            binding_mode,
                        });
                        offset += coordinate_len;
                    };
                push_section(
                    Symbt3MessageSectionKind::SumcheckRoundPolynomial,
                    polynomial_len,
                    Symbt3MessageAlgebraType::BabyBearFieldElement,
                    Symbt3MessageVisibility::CommittedOracleValue,
                    Symbt3MessageBindingMode::SumcheckTransition,
                );
                push_section(
                    Symbt3MessageSectionKind::SumcheckClaimValue,
                    claim_len,
                    Symbt3MessageAlgebraType::BabyBearFieldElement,
                    Symbt3MessageVisibility::CommittedOracleValue,
                    Symbt3MessageBindingMode::SumcheckTransition,
                );
                push_section(
                    Symbt3MessageSectionKind::EvaluationPoint,
                    eval_point_len,
                    Symbt3MessageAlgebraType::BabyBearFieldElement,
                    Symbt3MessageVisibility::PublicChallengeConstant,
                    Symbt3MessageBindingMode::VerifierChallengeConstant,
                );
                push_section(
                    Symbt3MessageSectionKind::EvaluationValue,
                    eval_value_len,
                    Symbt3MessageAlgebraType::BabyBearFieldElement,
                    Symbt3MessageVisibility::CommittedOracleValue,
                    Symbt3MessageBindingMode::FinalLocalClaim,
                );
                let message_views = sections
                    .iter()
                    .filter_map(|section| {
                        let trace_kind =
                            symbt3_trace_kind_for_message_section(section.section_kind)?;
                        Some(Symbt3MessageViewLayout {
                            layout_version: SYMBT3_MESSAGE_VIEW_LAYOUT_VERSION,
                            round: oracle.round,
                            trace_kind,
                            trace_coordinate_axis: "item-packed-message-coordinate",
                            message_coordinate_map: Symbt3MessageCoordinateMap {
                                layout_version: SYMBT3_MESSAGE_COORDINATE_MAP_VERSION,
                                mode: Symbt3MessageCoordinateMapMode::ContiguousOffsetV1,
                                message_coordinate_offset: section.coordinate_offset,
                                coordinate_len: section.coordinate_len,
                            },
                            algebra_type: section.algebra_type,
                            padding_policy: "selector-zero-padded-tail",
                        })
                    })
                    .collect::<Vec<_>>();
                Symbt3RoundMessageLayout {
                    layout_version: SYMBT3_ROUND_MESSAGE_LAYOUT_VERSION,
                    round_index: oracle.round,
                    row_count: oracle.row_count,
                    message_len: oracle.message_len,
                    packed_field_len: oracle.packed_field_len,
                    coordinate_axis: "item-packed-message-coordinate",
                    section_axis: "typed-round-message-section",
                    sections,
                    source_column_bindings: Vec::new(),
                    trace_column_bindings: Vec::new(),
                    message_views,
                }
            })
            .collect::<Vec<_>>();
        let mut message_oracle_body = Vec::new();
        push_usize(
            &mut message_oracle_body,
            oracle_layout.message_oracles.len(),
        );
        for oracle in &oracle_layout.message_oracles {
            push_usize(&mut message_oracle_body, oracle.round);
            push_usize(&mut message_oracle_body, oracle.row_count);
            push_usize(&mut message_oracle_body, oracle.message_len);
            push_usize(&mut message_oracle_body, oracle.packed_field_len);
        }
        let message_oracle_layout_digest = digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-message-oracle-layout",
            &message_oracle_body,
        );
        Self {
            version_marker: b"SYMBT3I\0",
            layout_version: SYMBT3_MESSAGE_SEMANTIC_LAYOUT_VERSION,
            round_count: shape.accumulator_shape.num_rounds,
            round_layouts,
            challenge_schedule_version: SYMBT3_CHALLENGE_SCHEDULE_VERSION,
            message_oracle_layout_digest,
            algebra_law_digest: algebra_law.digest(scheme),
            gr1cs_layout_digest: gr1cs_residual_layout.digest(scheme),
            ajtai_layout_digest: ajtai_linear_algebra_layout.digest(scheme),
            norm_range_layout_digest: ajtai_norm_range_layout.digest(scheme),
            manifest_layout_digest: batch_manifest_layout.digest(scheme),
            selector_evaluator: "prefix-active-message-coordinate-selector-v1",
            padding_policy: "selector-zero-padded-tail",
            semantic_mode: Symbt3MessageSemanticMode::NativeOracleViewV1,
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_message_semantic_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-message-semantic-layout", &body)
    }

    #[must_use]
    pub fn coordinate_count(&self) -> usize {
        self.round_layouts
            .iter()
            .map(|round| round.row_count * round.packed_field_len)
            .sum()
    }

    #[must_use]
    pub fn view_coordinate_count(&self, active_count: usize) -> usize {
        self.round_layouts
            .iter()
            .map(|round| {
                round
                    .message_views
                    .iter()
                    .map(|view| view.message_coordinate_map.coordinate_len * active_count)
                    .sum::<usize>()
            })
            .sum()
    }

    #[must_use]
    pub fn message_to_trace_binding_count(&self) -> usize {
        self.round_layouts
            .iter()
            .map(|round| {
                round
                    .trace_column_bindings
                    .iter()
                    .map(|binding| binding.coordinate_len * round.row_count)
                    .sum::<usize>()
            })
            .sum()
    }

    #[must_use]
    pub fn semantic_sumcheck_transition_count(&self) -> usize {
        self.round_layouts
            .iter()
            .map(|round| {
                round
                    .sections
                    .iter()
                    .filter(|section| {
                        section.binding_mode == Symbt3MessageBindingMode::SumcheckTransition
                    })
                    .count()
            })
            .sum()
    }
}

fn symbt3_trace_kind_for_message_section(
    section_kind: Symbt3MessageSectionKind,
) -> Option<Symbt3TraceKind> {
    match section_kind {
        Symbt3MessageSectionKind::SumcheckRoundPolynomial => {
            Some(Symbt3TraceKind::SumcheckRoundPolynomial)
        }
        Symbt3MessageSectionKind::SumcheckClaimValue => Some(Symbt3TraceKind::SumcheckClaimValue),
        Symbt3MessageSectionKind::EvaluationPoint => Some(Symbt3TraceKind::EvaluationPoint),
        Symbt3MessageSectionKind::EvaluationValue => Some(Symbt3TraceKind::EvaluationValue),
        Symbt3MessageSectionKind::FoldedOutputCoordinate => {
            Some(Symbt3TraceKind::FoldedOutputCoordinate)
        }
        Symbt3MessageSectionKind::FoldedGr1csCoordinate => {
            Some(Symbt3TraceKind::FoldedGr1csCoordinate)
        }
        Symbt3MessageSectionKind::AjtaiOpeningCoordinate => {
            Some(Symbt3TraceKind::AjtaiOpeningCoordinate)
        }
        Symbt3MessageSectionKind::AjtaiCommitmentCoordinate => {
            Some(Symbt3TraceKind::AjtaiCommitmentCoordinate)
        }
        Symbt3MessageSectionKind::ProjectionCoordinate => {
            Some(Symbt3TraceKind::ProjectionCoordinate)
        }
        Symbt3MessageSectionKind::RangeWitnessCoordinate => {
            Some(Symbt3TraceKind::RangeWitnessCoordinate)
        }
        Symbt3MessageSectionKind::BoundaryDigestCoordinate => None,
    }
}

impl Symbt3R1csEvaluatorLayout {
    #[must_use]
    pub fn from_shape_and_r1cs(
        shape: &BatchedCpStatementShape,
        r1cs: &R1CSMatrices,
        r1cs_matrices_digest: Digest32,
    ) -> Self {
        let mut evaluator_body = Vec::new();
        evaluator_body.extend_from_slice(&r1cs_matrices_digest);
        push_usize(&mut evaluator_body, r1cs.num_constraints);
        push_usize(&mut evaluator_body, r1cs.num_variables);
        push_usize(&mut evaluator_body, r1cs.num_public);
        let evaluator_algorithm_id = digest_domain_with_scheme(
            shape.accumulator_shape.digest_scheme,
            b"batched-cp-symbt3-r1cs-sparse-evaluator",
            &evaluator_body,
        );
        Self {
            layout_version: SYMBT3_R1CS_EVALUATOR_LAYOUT_VERSION,
            field_id: "BabyBear",
            modulus: 2_013_265_921,
            num_constraints: r1cs.num_constraints,
            num_variables: r1cs.num_variables,
            num_public: r1cs.num_public,
            num_witness: r1cs.num_variables.saturating_sub(r1cs.num_public),
            constant_one_wire_index: None,
            public_input_wire_layout: "public-prefix-constant-ring",
            witness_wire_layout: "witness-suffix-ring-coefficients",
            sparse_encoding_format: "coo-row-col-i64-v1",
            row_ordering: "ascending-row-index",
            column_ordering: "ascending-column-index",
            padding_policy: "zero-pad-to-power-of-two",
            coefficient_encoding: "centered-i64-le",
            term_encoding: "babybear-linear-form-v1",
            evaluator_algorithm_id,
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_r1cs_evaluator_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-r1cs-evaluator-layout", &body)
    }
}

impl Symbt3Gr1csResidualLayout {
    #[must_use]
    pub fn from_shape(shape: &BatchedCpStatementShape) -> Self {
        Self {
            layout_version: SYMBT3_GR1CS_RESIDUAL_LAYOUT_VERSION,
            folded_evaluation_coordinate_count: shape.accumulator_shape.folded_evaluation_count
                * T
                * D,
            tensor_rows: T,
            ring_degree: D,
            grouping: "triples-left-right-output",
            coordinate_ordering: "evaluation-index-tensor-row-coeff",
            padding_policy: "ignore-incomplete-trailing-triple",
            component_kind_tags: vec!["left", "right", "output"],
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_gr1cs_residual_layout(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-gr1cs-residual-layout", &body)
    }
}

impl Symbt3AlgebraLaw {
    #[must_use]
    pub fn from_shape(_shape: &BatchedCpStatementShape) -> Self {
        Self {
            version_marker: b"SYMBT3E\0",
            law_version: SYMBT3_ALGEBRA_LAW_VERSION,
            check_field_id: "BabyBear",
            coefficient_domain: "check-field-native-ring",
            ring_degree: D,
            ring_relation: "X^D+1",
            coefficient_basis: "coefficient-ascending",
            coefficient_order: "little-endian",
            reduction_policy: "CheckFieldNativeV1",
            beta_action: Symbt3BetaActionId::RingCoefficientActionV1,
            product_law: Symbt3ProductLawId::RqNegacyclicConvolutionV1,
            module_layout: "coordinatewise-ring-module",
            soundness_profile: "NonAuthoritativeDevelopmentBaseFieldSingleCheck",
            zk_profile: "NonZkDevelopment",
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_algebra_law(&mut body, self);
        digest_domain_with_scheme(scheme, b"batched-cp-symbt3-algebra-law-v1", &body)
    }
}

impl Symbt3FoldedGr1csProductResidualLayout {
    #[must_use]
    pub fn from_shape(shape: &BatchedCpStatementShape) -> Self {
        let product_coordinate_count = shape.accumulator_shape.folded_evaluation_count * T * D / 3;
        Self {
            layout_version: SYMBT3_FOLDED_GR1CS_PRODUCT_RESIDUAL_LAYOUT_VERSION,
            product_domain_log_size: product_coordinate_count
                .max(1)
                .next_power_of_two()
                .trailing_zeros() as usize,
            equation_kind_axis: "folded-gr1cs-left-right-output",
            row_axis: "evaluation-index-tensor-row-coeff",
            l_fold_column: 0,
            r_fold_column: 1,
            o_fold_column: 2,
            selector_evaluator: "prefix-valid-coordinate-selector-v1",
            product_law: Symbt3ProductLawId::RqNegacyclicConvolutionV1,
            beta_action: Symbt3BetaActionId::RingCoefficientActionV1,
            padding_policy: "selector-zero-padded-tail",
            check_field: "BabyBear",
            soundness_profile: "NonAuthoritativeDevelopmentBaseFieldSingleCheck",
        }
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        let mut body = Vec::new();
        encode_symbt3_folded_gr1cs_product_residual_layout(&mut body, self);
        digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-folded-gr1cs-product-residual-layout",
            &body,
        )
    }
}

impl BatchedCpSymbt3OracleLayout {
    #[must_use]
    pub fn from_shape(shape: &BatchedCpStatementShape) -> Self {
        let message_oracles = shape
            .round_message_lens
            .iter()
            .enumerate()
            .map(|(round, &message_len)| BatchedCpSymbt3MessageOracleLayout {
                round,
                row_count: shape.batch_capacity,
                message_len,
                packed_field_len: message_len.div_ceil(4),
            })
            .collect();
        let column_kinds = [
            BatchedCpSymbt3AlgebraicColumnKind::ActiveMask,
            BatchedCpSymbt3AlgebraicColumnKind::BetaCoefficient,
            BatchedCpSymbt3AlgebraicColumnKind::FoldedPublicInput,
            BatchedCpSymbt3AlgebraicColumnKind::FoldedCommitment,
            BatchedCpSymbt3AlgebraicColumnKind::FoldedEvaluation,
            BatchedCpSymbt3AlgebraicColumnKind::AjtaiLinearCombination,
            BatchedCpSymbt3AlgebraicColumnKind::OriginalR1csResidual,
            BatchedCpSymbt3AlgebraicColumnKind::Gr1csResidual,
            BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductLeft,
            BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductRight,
            BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductOutput,
        ];
        let algebraic_columns = column_kinds
            .iter()
            .copied()
            .enumerate()
            .map(|(id, kind)| BatchedCpSymbt3AlgebraicColumn {
                id,
                kind,
                row_count: shape.batch_capacity,
            })
            .collect();
        Self {
            layout_version: SYMBT3_LAYOUT_VERSION,
            challenge_schedule_version: SYMBT3_CHALLENGE_SCHEDULE_VERSION,
            batch_capacity: shape.batch_capacity,
            active_count: shape.active_count,
            message_oracles,
            algebraic_columns,
            constraint_families: vec![
                BatchedCpSymbt3ConstraintFamily::BatchManifestRootBinding,
                BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership,
                BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim,
                BatchedCpSymbt3ConstraintFamily::SourceAssignmentRootManifestBinding,
                BatchedCpSymbt3ConstraintFamily::SourceMessageRootManifestBinding,
                BatchedCpSymbt3ConstraintFamily::RoundMessageLayoutValidity,
                BatchedCpSymbt3ConstraintFamily::RoundChallengePrefixBinding,
                BatchedCpSymbt3ConstraintFamily::NativeMessageOracleViews,
                BatchedCpSymbt3ConstraintFamily::SumcheckRoundClaimTransition,
                BatchedCpSymbt3ConstraintFamily::SumcheckFinalLocalClaimBinding,
                BatchedCpSymbt3ConstraintFamily::FoldingMessageBoundaryConsistency,
                BatchedCpSymbt3ConstraintFamily::ChallengeToBeta,
                BatchedCpSymbt3ConstraintFamily::FoldedPublicInputLinearIdentity,
                BatchedCpSymbt3ConstraintFamily::FoldedCommitmentLinearIdentity,
                BatchedCpSymbt3ConstraintFamily::FoldedEvaluationLinearIdentity,
                BatchedCpSymbt3ConstraintFamily::FoldedAccumulatorBoundaryIdentity,
                BatchedCpSymbt3ConstraintFamily::RingBetaAction,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningIdentity,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentIdentity,
                BatchedCpSymbt3ConstraintFamily::AjtaiFoldedResidualZero,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningLinearIdentity,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentLinearIdentity,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiMapConsistency,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectionConsistency,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectedRangeBound,
                BatchedCpSymbt3ConstraintFamily::CommittedSourceR1csResidualValidity,
                BatchedCpSymbt3ConstraintFamily::FoldedGr1csResidualValidity,
                BatchedCpSymbt3ConstraintFamily::FoldedGr1csProductResidualZeroCheck,
                BatchedCpSymbt3ConstraintFamily::FoldedAjtaiStructuredProjectionConsistency,
                BatchedCpSymbt3ConstraintFamily::ProjectedOpeningMonomialEmbedding,
                BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRangeConstantTerm,
                BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRepresentativeValidity,
                BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency,
            ],
        }
    }

    #[must_use]
    pub fn total_witness_fields(&self) -> usize {
        let message_fields = self
            .message_oracles
            .iter()
            .map(|oracle| oracle.row_count * oracle.packed_field_len.max(1))
            .sum::<usize>();
        let algebraic_fields = self
            .algebraic_columns
            .iter()
            .map(|column| column.row_count)
            .sum::<usize>();
        message_fields + algebraic_fields
    }
}

impl BatchedCpSymbt3SetupDescriptor {
    #[must_use]
    pub fn new(
        shape: BatchedCpStatementShape,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> Self {
        shape.symbt3_setup_descriptor(ajtai, r1cs, input_bound)
    }

    #[must_use]
    pub fn relation_description(&self) -> BatchedCpSymbt3RelationDescription {
        BatchedCpSymbt3RelationDescription {
            shape: self.shape.clone(),
            oracle_layout: BatchedCpSymbt3OracleLayout::from_shape(&self.shape),
            ring_module_layout: self.ring_module_layout.clone(),
            ajtai_commit_layout: self.ajtai_commit_layout.clone(),
            r1cs_evaluator_layout: self.r1cs_evaluator_layout.clone(),
            gr1cs_residual_layout: self.gr1cs_residual_layout.clone(),
            algebra_law: self.algebra_law.clone(),
            ajtai_linear_algebra_layout: self.ajtai_linear_algebra_layout.clone(),
            ajtai_norm_range_layout: self.ajtai_norm_range_layout.clone(),
            batch_manifest_layout: self.batch_manifest_layout.clone(),
            message_semantic_layout: self.message_semantic_layout.clone(),
            folded_gr1cs_product_residual_layout: self.folded_gr1cs_product_residual_layout.clone(),
            ajtai_matrix: self.ajtai_matrix.clone(),
            r1cs_matrices: self.r1cs_matrices.clone(),
            ajtai_params_digest: self.ajtai_params_digest,
            r1cs_matrices_digest: self.r1cs_matrices_digest,
            input_bound: self.input_bound,
        }
    }
}

impl BatchedCpSemanticOracleV2Layout {
    #[must_use]
    pub fn from_semantic(semantic: &BatchedCpSemanticRelationDescription) -> Self {
        let oracle_layout = &semantic.oracle_layout;
        Self {
            byte_len: oracle_layout.byte_len,
            packed_field_len: oracle_layout.packed_field_len,
            product_rows: semantic.shape.batch_capacity,
            // SYMBTC2 currently maps typed semantic columns onto the canonical
            // product-oracle packed columns plus one active-mask family. This
            // keeps the v2 context explicit while the WHIR path evaluates full
            // residual families rather than sampled subsets.
            semantic_column_count: oracle_layout.packed_field_len + 1,
            residual_family_count: semantic.constraint_families.len(),
        }
    }
}

impl BatchedCpSemanticRelationV2Description {
    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        self.semantic.public_statement_bytes()
    }

    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEMANTIC_V2_RELATION_CONTEXT_MAGIC);
        let semantic_context = self.semantic.canonical_context_bytes();
        push_usize(&mut out, semantic_context.len());
        out.extend_from_slice(&semantic_context);
        push_usize(&mut out, self.v2_layout.byte_len);
        push_usize(&mut out, self.v2_layout.packed_field_len);
        push_usize(&mut out, self.v2_layout.product_rows);
        push_usize(&mut out, self.v2_layout.semantic_column_count);
        push_usize(&mut out, self.v2_layout.residual_family_count);
        out
    }

    #[must_use]
    pub fn semantic_relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.semantic.shape.accumulator_shape.digest_scheme,
            b"batched-cp-semantic-v2-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes(),
            num_witness_vars: self.v2_layout.packed_field_len,
            // SYMBTC2 is a structured product-domain relation context, not a
            // lowered/appended typed CP R1CS.
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < SEMANTIC_V2_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..SEMANTIC_V2_RELATION_CONTEXT_MAGIC.len()]
                != SEMANTIC_V2_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut pos = SEMANTIC_V2_RELATION_CONTEXT_MAGIC.len();
        let semantic_context_len = read_usize(bytes, &mut pos)?;
        let semantic_context_end = pos
            .checked_add(semantic_context_len)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let semantic_context = bytes
            .get(pos..semantic_context_end)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let semantic = BatchedCpSemanticRelationDescription::from_context_bytes(semantic_context)?;
        pos = semantic_context_end;
        let v2_layout = BatchedCpSemanticOracleV2Layout {
            byte_len: read_usize(bytes, &mut pos)?,
            packed_field_len: read_usize(bytes, &mut pos)?,
            product_rows: read_usize(bytes, &mut pos)?,
            semantic_column_count: read_usize(bytes, &mut pos)?,
            residual_family_count: read_usize(bytes, &mut pos)?,
        };
        if pos != bytes.len()
            || v2_layout != BatchedCpSemanticOracleV2Layout::from_semantic(&semantic)
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        Ok(Self {
            semantic,
            v2_layout,
        })
    }

    #[must_use]
    pub fn supported_constraint_blocks(&self) -> Vec<BatchedCpSemanticConstraintBlock> {
        self.semantic.supported_constraint_blocks()
    }

    #[must_use]
    pub fn supported_constraint_blocks_for_statement(
        &self,
        statement: Option<&BatchedCpPublicStatement>,
    ) -> Vec<BatchedCpSemanticConstraintBlock> {
        self.semantic
            .supported_constraint_blocks_for_statement(statement)
    }
}

impl BatchedCpSymbt3RelationDescription {
    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        estimate_symbt3_public_statement_bytes(&self.shape)
    }

    #[must_use]
    pub fn symbt3_public_input_coordinate_len(&self) -> usize {
        self.shape.accumulator_shape.local_public_input_count
            * self.shape.accumulator_shape.r1cs_num_public
    }

    #[must_use]
    pub fn symbt3_commitment_coordinate_len(&self) -> usize {
        self.shape.accumulator_shape.commitment_kappa * self.shape.accumulator_shape.commitment_d
    }

    #[must_use]
    pub fn symbt3_evaluation_coordinate_len(&self) -> usize {
        self.shape.accumulator_shape.folded_evaluation_count * T * D
    }

    #[must_use]
    pub fn symbt3_accumulator_coordinate_len(&self) -> usize {
        self.symbt3_public_input_coordinate_len()
            + self.symbt3_commitment_coordinate_len()
            + self.symbt3_evaluation_coordinate_len()
    }

    #[must_use]
    pub fn symbt3_folded_output_coordinate_len(&self) -> usize {
        self.symbt3_accumulator_coordinate_len() * 2
    }

    #[must_use]
    pub fn has_symbt3_a_families(&self) -> bool {
        self.oracle_layout
            .constraint_families
            .contains(&BatchedCpSymbt3ConstraintFamily::ChallengeToBeta)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedPublicInputLinearIdentity)
    }

    #[must_use]
    pub fn has_symbt3_b_families(&self) -> bool {
        self.has_symbt3_a_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedCommitmentLinearIdentity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedEvaluationLinearIdentity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAccumulatorBoundaryIdentity)
    }

    #[must_use]
    pub fn has_symbt3_c_families(&self) -> bool {
        self.has_symbt3_b_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::RingBetaAction)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningIdentity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentIdentity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::AjtaiFoldedResidualZero)
    }

    #[must_use]
    pub fn has_symbt3_f_families(&self) -> bool {
        self.has_symbt3_c_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningLinearIdentity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentLinearIdentity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiMapConsistency)
    }

    #[must_use]
    pub fn has_symbt3_d_families(&self) -> bool {
        self.has_symbt3_f_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::CommittedSourceR1csResidualValidity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedGr1csResidualValidity)
    }

    #[must_use]
    pub fn has_symbt3_d2_families(&self) -> bool {
        self.has_symbt3_d_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedGr1csProductResidualZeroCheck)
    }

    #[must_use]
    pub fn has_symbt3_g_families(&self) -> bool {
        self.has_symbt3_d2_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectionConsistency)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectedRangeBound)
    }

    #[must_use]
    pub fn has_symbt3_j_families(&self) -> bool {
        self.has_symbt3_i_families()
            && self.oracle_layout.constraint_families.contains(
                &BatchedCpSymbt3ConstraintFamily::FoldedAjtaiStructuredProjectionConsistency,
            )
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::ProjectedOpeningMonomialEmbedding)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRangeConstantTerm)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRepresentativeValidity)
    }

    #[must_use]
    pub fn has_symbt3_k2_families(&self) -> bool {
        self.has_symbt3_j_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency)
    }

    #[must_use]
    pub fn has_symbt3_h_families(&self) -> bool {
        self.has_symbt3_g_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::BatchManifestRootBinding)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::SourceAssignmentRootManifestBinding)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::SourceMessageRootManifestBinding)
    }

    #[must_use]
    pub fn has_symbt3_i_families(&self) -> bool {
        self.has_symbt3_h_families()
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::RoundMessageLayoutValidity)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::RoundChallengePrefixBinding)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::NativeMessageOracleViews)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::SumcheckRoundClaimTransition)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::SumcheckFinalLocalClaimBinding)
            && self
                .oracle_layout
                .constraint_families
                .contains(&BatchedCpSymbt3ConstraintFamily::FoldingMessageBoundaryConsistency)
    }

    #[must_use]
    pub fn derive_folded_public_input_boundary(
        &self,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Vec<i64> {
        symbt3_linear_fold_values(
            self,
            statement,
            &statement.input_public_values,
            self.symbt3_public_input_coordinate_len(),
        )
    }

    #[must_use]
    pub fn derive_folded_commitment_boundary(
        &self,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Vec<i64> {
        symbt3_linear_fold_values(
            self,
            statement,
            &statement.input_commitment_values,
            self.symbt3_commitment_coordinate_len(),
        )
    }

    #[must_use]
    pub fn derive_ring_folded_commitment_boundary(
        &self,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Vec<i64> {
        symbt3_ring_fold_values(
            self,
            statement,
            &statement.input_commitment_values,
            self.ring_module_layout.commitment_module_dimension,
        )
    }

    #[must_use]
    pub fn derive_ring_folded_opening_boundary(
        &self,
        statement: &BatchedCpSymbt3PublicStatement,
        rows: &[Vec<i64>],
    ) -> Vec<i64> {
        symbt3_ring_fold_values(
            self,
            statement,
            rows,
            self.ring_module_layout.opening_module_dimension,
        )
    }

    #[must_use]
    pub fn derive_folded_evaluation_boundary(
        &self,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Vec<i64> {
        let mut folded = match self.algebra_law.beta_action {
            Symbt3BetaActionId::ScalarFieldCoordinateV1 => symbt3_linear_fold_values(
                self,
                statement,
                &statement.input_evaluation_values,
                self.symbt3_evaluation_coordinate_len(),
            ),
            Symbt3BetaActionId::RingCoefficientActionV1 => symbt3_ring_fold_values(
                self,
                statement,
                &statement.input_evaluation_values,
                self.symbt3_evaluation_coordinate_len() / D,
            ),
        };
        if self.has_symbt3_d2_families() {
            let product_len = self
                .gr1cs_residual_layout
                .folded_evaluation_coordinate_count
                / 3;
            if folded.len() >= product_len * 3 {
                match self.folded_gr1cs_product_residual_layout.product_law {
                    Symbt3ProductLawId::FieldCoordinateMulV1 => {
                        for idx in 0..product_len {
                            folded[2 * product_len + idx] =
                                folded[idx].saturating_mul(folded[product_len + idx]);
                        }
                    }
                    Symbt3ProductLawId::RqNegacyclicConvolutionV1 => {
                        for chunk_start in (0..product_len).step_by(D) {
                            if chunk_start + D > product_len {
                                break;
                            }
                            let product = symbt3_negacyclic_mul_i64(
                                &folded[chunk_start..chunk_start + D],
                                &folded[product_len + chunk_start..product_len + chunk_start + D],
                                BABYBEAR_MODULUS_U64,
                            );
                            folded
                                [2 * product_len + chunk_start..2 * product_len + chunk_start + D]
                                .copy_from_slice(&product);
                        }
                    }
                }
            }
        }
        folded
    }

    #[must_use]
    pub fn derive_folded_accumulator_boundary(
        &self,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Vec<i64> {
        symbt3_linear_fold_values(
            self,
            statement,
            &statement.input_accumulator_values,
            self.symbt3_accumulator_coordinate_len(),
        )
    }

    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SYMBT3_RELATION_CONTEXT_MAGIC);
        encode_statement_shape(&mut out, &self.shape);
        push_usize(&mut out, self.oracle_layout.layout_version as usize);
        push_usize(
            &mut out,
            self.oracle_layout.challenge_schedule_version as usize,
        );
        push_usize(&mut out, self.oracle_layout.batch_capacity);
        push_usize(&mut out, self.oracle_layout.active_count);
        push_usize(&mut out, self.oracle_layout.message_oracles.len());
        for oracle in &self.oracle_layout.message_oracles {
            push_usize(&mut out, oracle.round);
            push_usize(&mut out, oracle.row_count);
            push_usize(&mut out, oracle.message_len);
            push_usize(&mut out, oracle.packed_field_len);
        }
        push_usize(&mut out, self.oracle_layout.algebraic_columns.len());
        for column in &self.oracle_layout.algebraic_columns {
            push_usize(&mut out, column.id);
            out.push(symbt3_algebraic_column_kind_code(column.kind));
            push_usize(&mut out, column.row_count);
        }
        push_usize(&mut out, self.oracle_layout.constraint_families.len());
        for family in &self.oracle_layout.constraint_families {
            out.push(symbt3_constraint_family_code(*family));
        }
        encode_symbt3_ring_module_layout(&mut out, &self.ring_module_layout);
        encode_symbt3_ajtai_commit_layout(&mut out, &self.ajtai_commit_layout);
        encode_symbt3_r1cs_evaluator_layout(&mut out, &self.r1cs_evaluator_layout);
        encode_symbt3_gr1cs_residual_layout(&mut out, &self.gr1cs_residual_layout);
        encode_symbt3_algebra_law(&mut out, &self.algebra_law);
        encode_symbt3_ajtai_linear_algebra_layout(&mut out, &self.ajtai_linear_algebra_layout);
        encode_symbt3_ajtai_norm_range_layout(&mut out, &self.ajtai_norm_range_layout);
        encode_symbt3_batch_manifest_layout(&mut out, &self.batch_manifest_layout);
        encode_symbt3_message_semantic_layout(&mut out, &self.message_semantic_layout);
        encode_symbt3_folded_gr1cs_product_residual_layout(
            &mut out,
            &self.folded_gr1cs_product_residual_layout,
        );
        encode_ring_matrix(&mut out, &self.ajtai_matrix);
        encode_r1cs_matrices(&mut out, &self.r1cs_matrices);
        out.extend_from_slice(&self.ajtai_params_digest);
        out.extend_from_slice(&self.r1cs_matrices_digest);
        out.extend_from_slice(&self.input_bound.to_le_bytes());
        out
    }

    #[must_use]
    pub fn relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-symbt3-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn folding_protocol_id(&self) -> Digest32 {
        let mut body = Vec::new();
        body.extend_from_slice(b"symphony-symbt3-folding-protocol-v1");
        body.extend_from_slice(&self.shape.shape_id);
        push_usize(&mut body, self.shape.batch_capacity);
        push_usize(&mut body, self.shape.active_count);
        push_usize(&mut body, self.oracle_layout.message_oracles.len());
        for oracle in &self.oracle_layout.message_oracles {
            push_usize(&mut body, oracle.round);
            push_usize(&mut body, oracle.row_count);
            push_usize(&mut body, oracle.message_len);
            push_usize(&mut body, oracle.packed_field_len);
        }
        body.extend_from_slice(&self.shape.accumulator_shape.whir_parameter_digest);
        body.extend_from_slice(&self.ajtai_params_digest);
        body.extend_from_slice(&self.r1cs_matrices_digest);
        body.extend_from_slice(
            &self
                .ring_module_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .ajtai_commit_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .r1cs_evaluator_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .gr1cs_residual_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .algebra_law
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .ajtai_linear_algebra_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .ajtai_norm_range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .batch_manifest_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .batch_manifest_layout
                .source_column_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(
            &self
                .message_semantic_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
        );
        body.extend_from_slice(&(SYMBT3_CHALLENGE_SCHEDULE_VERSION).to_le_bytes());
        digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-symbt3-folding-protocol-id",
            &body,
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes(),
            num_witness_vars: self.oracle_layout.total_witness_fields(),
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < SYMBT3_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..SYMBT3_RELATION_CONTEXT_MAGIC.len()] != SYMBT3_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut pos = SYMBT3_RELATION_CONTEXT_MAGIC.len();
        let shape = decode_statement_shape(bytes, &mut pos)?;
        let layout_version = read_usize(bytes, &mut pos)? as u64;
        let challenge_schedule_version = read_usize(bytes, &mut pos)? as u64;
        let batch_capacity = read_usize(bytes, &mut pos)?;
        let active_count = read_usize(bytes, &mut pos)?;
        let message_count = read_usize(bytes, &mut pos)?;
        let mut message_oracles = Vec::with_capacity(message_count);
        for _ in 0..message_count {
            message_oracles.push(BatchedCpSymbt3MessageOracleLayout {
                round: read_usize(bytes, &mut pos)?,
                row_count: read_usize(bytes, &mut pos)?,
                message_len: read_usize(bytes, &mut pos)?,
                packed_field_len: read_usize(bytes, &mut pos)?,
            });
        }
        let column_count = read_usize(bytes, &mut pos)?;
        let mut algebraic_columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let id = read_usize(bytes, &mut pos)?;
            let Some(&code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            let kind = symbt3_algebraic_column_kind_from_code(code)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            algebraic_columns.push(BatchedCpSymbt3AlgebraicColumn {
                id,
                kind,
                row_count: read_usize(bytes, &mut pos)?,
            });
        }
        let family_count = read_usize(bytes, &mut pos)?;
        let mut constraint_families = Vec::with_capacity(family_count);
        for _ in 0..family_count {
            let Some(&code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            constraint_families.push(
                symbt3_constraint_family_from_code(code)
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
            );
        }
        let ring_module_layout = read_symbt3_ring_module_layout(bytes, &mut pos)?;
        let ajtai_commit_layout = read_symbt3_ajtai_commit_layout(bytes, &mut pos)?;
        let r1cs_evaluator_layout = read_symbt3_r1cs_evaluator_layout(bytes, &mut pos)?;
        let gr1cs_residual_layout = read_symbt3_gr1cs_residual_layout(bytes, &mut pos)?;
        let algebra_law = read_symbt3_algebra_law(bytes, &mut pos)?;
        let ajtai_linear_algebra_layout = read_symbt3_ajtai_linear_algebra_layout(bytes, &mut pos)?;
        let ajtai_norm_range_layout = read_symbt3_ajtai_norm_range_layout(bytes, &mut pos)?;
        let batch_manifest_layout = read_symbt3_batch_manifest_layout(bytes, &mut pos)?;
        let message_semantic_layout = read_symbt3_message_semantic_layout(bytes, &mut pos)?;
        let folded_gr1cs_product_residual_layout =
            read_symbt3_folded_gr1cs_product_residual_layout(bytes, &mut pos)?;
        let ajtai_matrix = read_ring_matrix(bytes, &mut pos)?;
        let r1cs_matrices = read_r1cs_matrices(bytes, &mut pos)?;
        let ajtai_params_digest = read_digest(bytes, &mut pos)?;
        let r1cs_matrices_digest = read_digest(bytes, &mut pos)?;
        let end = pos
            .checked_add(8)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let input_bound = u64::from_le_bytes(
            bytes
                .get(pos..end)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?
                .try_into()
                .map_err(|_| BatchedCpError::InvalidSemanticRelationContext)?,
        );
        pos = end;
        let oracle_layout = BatchedCpSymbt3OracleLayout {
            layout_version,
            challenge_schedule_version,
            batch_capacity,
            active_count,
            message_oracles,
            algebraic_columns,
            constraint_families,
        };
        if pos != bytes.len()
            || oracle_layout != BatchedCpSymbt3OracleLayout::from_shape(&shape)
            || layout_version != SYMBT3_LAYOUT_VERSION
            || challenge_schedule_version != SYMBT3_CHALLENGE_SCHEDULE_VERSION
            || ring_module_layout.ring_degree != D
            || ring_module_layout.ring_action_version != SYMBT3_RING_ACTION_VERSION
            || ajtai_commit_layout.layout_version != SYMBT3_AJTAI_COMMIT_LAYOUT_VERSION
            || r1cs_evaluator_layout.layout_version != SYMBT3_R1CS_EVALUATOR_LAYOUT_VERSION
            || gr1cs_residual_layout.layout_version != SYMBT3_GR1CS_RESIDUAL_LAYOUT_VERSION
            || algebra_law != Symbt3AlgebraLaw::from_shape(&shape)
            || ajtai_linear_algebra_layout.layout_version
                != SYMBT3_AJTAI_LINEAR_ALGEBRA_LAYOUT_VERSION
            || ajtai_norm_range_layout.layout_version != SYMBT3_AJTAI_NORM_RANGE_LAYOUT_VERSION
            || batch_manifest_layout.layout_version != SYMBT3_BATCH_MANIFEST_LAYOUT_VERSION
            || message_semantic_layout.layout_version != SYMBT3_MESSAGE_SEMANTIC_LAYOUT_VERSION
            || folded_gr1cs_product_residual_layout.layout_version
                != SYMBT3_FOLDED_GR1CS_PRODUCT_RESIDUAL_LAYOUT_VERSION
            || ajtai_matrix.len() != ajtai_commit_layout.commitment_module_dimension
            || ajtai_matrix
                .iter()
                .any(|row| row.len() != ajtai_commit_layout.opening_module_dimension)
            || r1cs_matrices.num_constraints != shape.accumulator_shape.r1cs_num_constraints
            || r1cs_matrices.num_variables != shape.accumulator_shape.r1cs_num_variables
            || r1cs_matrices.num_public != shape.accumulator_shape.r1cs_num_public
            || r1cs_evaluator_layout
                != Symbt3R1csEvaluatorLayout::from_shape_and_r1cs(
                    &shape,
                    &r1cs_matrices,
                    r1cs_matrices_digest,
                )
            || gr1cs_residual_layout != Symbt3Gr1csResidualLayout::from_shape(&shape)
            || ajtai_linear_algebra_layout
                != Symbt3AjtaiLinearAlgebraLayout::from_shape_and_layouts(
                    &shape,
                    &algebra_law,
                    &ajtai_commit_layout,
                    ajtai_params_digest,
                    shape.accumulator_shape.digest_scheme,
                )
            || batch_manifest_layout != Symbt3BatchManifestLayout::from_shape(&shape)
            || folded_gr1cs_product_residual_layout
                != Symbt3FoldedGr1csProductResidualLayout::from_shape(&shape)
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        Ok(Self {
            shape,
            oracle_layout,
            ring_module_layout,
            ajtai_commit_layout,
            r1cs_evaluator_layout,
            gr1cs_residual_layout,
            algebra_law,
            ajtai_linear_algebra_layout,
            ajtai_norm_range_layout,
            batch_manifest_layout,
            message_semantic_layout,
            folded_gr1cs_product_residual_layout,
            ajtai_matrix,
            r1cs_matrices,
            ajtai_params_digest,
            r1cs_matrices_digest,
            input_bound,
        })
    }
}

impl Symbt3AuthorityProfile {
    #[must_use]
    pub fn development_from_relation(relation: &BatchedCpSymbt3RelationDescription) -> Self {
        Self::from_relation(
            relation,
            Symbt3FieldExtensionPolicy::BaseFieldSingleCheckDevelopment,
            Symbt3SumcheckChallengePolicy::BaseFieldSingleChallengeDevelopment,
            1,
            0,
            0,
            Symbt3SoundnessStatus::DevelopmentOnly,
            Symbt3ZkStatus::NonZkDevelopment,
            Symbt3RoutingStatus::ResearchOnly,
            Symbt3ProductPolicy::MonolithicTypedCpOnly,
            false,
            true,
            Symbt3AuthorityStatus::NonAuthoritativeDevelopment,
        )
    }

    #[must_use]
    pub fn research_authority_candidate_from_relation(
        relation: &BatchedCpSymbt3RelationDescription,
        soundness_target_bits: u32,
    ) -> Self {
        Self::from_relation(
            relation,
            Symbt3FieldExtensionPolicy::BaseFieldSingleCheckDevelopment,
            Symbt3SumcheckChallengePolicy::BaseFieldSingleChallengeDevelopment,
            1,
            0,
            soundness_target_bits,
            Symbt3SoundnessStatus::SoundnessCandidate,
            Symbt3ZkStatus::NonZkDevelopment,
            Symbt3RoutingStatus::ResearchOnly,
            Symbt3ProductPolicy::MonolithicTypedCpOnly,
            false,
            true,
            Symbt3AuthorityStatus::AuthorityCandidateV1,
        )
    }

    #[must_use]
    pub fn accumulator_soundness_authority_candidate_from_relation(
        relation: &BatchedCpSymbt3RelationDescription,
        soundness_bound_bits: u32,
    ) -> Self {
        Self::from_relation(
            relation,
            Symbt3FieldExtensionPolicy::BaseFieldSingleCheckDevelopment,
            Symbt3SumcheckChallengePolicy::BaseFieldSingleChallengeDevelopment,
            1,
            1,
            soundness_bound_bits,
            Symbt3SoundnessStatus::SoundnessCandidate,
            Symbt3ZkStatus::NonZkDevelopment,
            Symbt3RoutingStatus::ResearchOnly,
            Symbt3ProductPolicy::MonolithicTypedCpOnly,
            false,
            true,
            Symbt3AuthorityStatus::AuthorityCandidateV1,
        )
    }

    #[must_use]
    pub fn accumulator_non_zk_integrity_product_authority_from_relation(
        relation: &BatchedCpSymbt3RelationDescription,
        soundness_bound_bits: u32,
    ) -> Self {
        Self::from_relation(
            relation,
            Symbt3FieldExtensionPolicy::BaseFieldSingleCheckDevelopment,
            Symbt3SumcheckChallengePolicy::BaseFieldSingleChallengeDevelopment,
            1,
            1,
            soundness_bound_bits,
            Symbt3SoundnessStatus::SoundnessCandidate,
            Symbt3ZkStatus::NonZkIntegrityOnly,
            Symbt3RoutingStatus::ProductAuthority,
            Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn,
            true,
            false,
            Symbt3AuthorityStatus::AuthorityCandidateV1,
        )
    }

    #[must_use]
    pub fn authority_candidate_from_relation(
        relation: &BatchedCpSymbt3RelationDescription,
        soundness_target_bits: u32,
    ) -> Self {
        Self::from_relation(
            relation,
            Symbt3FieldExtensionPolicy::ExtensionFieldAuthorityRequired,
            Symbt3SumcheckChallengePolicy::AuthorityRepetitionOrExtensionV1,
            2,
            0,
            soundness_target_bits,
            Symbt3SoundnessStatus::SoundnessCandidate,
            Symbt3ZkStatus::ZkRequiredForProductRoute,
            Symbt3RoutingStatus::ProductAuthority,
            Symbt3ProductPolicy::Symbt3ZkRequired,
            true,
            false,
            Symbt3AuthorityStatus::AuthorityCandidateV1,
        )
    }

    fn from_relation(
        relation: &BatchedCpSymbt3RelationDescription,
        field_policy: Symbt3FieldExtensionPolicy,
        sumcheck_challenge_policy: Symbt3SumcheckChallengePolicy,
        repetition_count: usize,
        semantic_profile_version: u32,
        soundness_target_bits: u32,
        soundness_status: Symbt3SoundnessStatus,
        zk_status: Symbt3ZkStatus,
        routing_status: Symbt3RoutingStatus,
        product_policy: Symbt3ProductPolicy,
        product_eligible: bool,
        research_only: bool,
        authority_status: Symbt3AuthorityStatus,
    ) -> Self {
        let scheme = relation.shape.accumulator_shape.digest_scheme;
        let fs_domain_separators = vec![
            "SYMBT3-A-BETA",
            "SYMBT3_ACC_TRANSITION",
            "batched-cp-symbt3-proof-public-statement",
            "SYMBT3-J-PROJECTION",
            "batched-cp-symbt3-round-challenge",
        ];
        let proof_public_statement_schedule =
            "relation/folding-protocol/public-statement split; beta input-side only";
        let accumulator_transition_policy_digest =
            symbt3_accumulator_transition_profile_digest(scheme, relation);
        let soundness_bits = if semantic_profile_version >= 1 {
            96
        } else {
            soundness_target_bits
        };
        Self {
            version_marker: b"SYMBT3K\0",
            profile_version: SYMBT3_AUTHORITY_PROFILE_VERSION,
            semantic_profile_version,
            semantic_version: "SYMBT3-K-authority-profile-v1",
            semantic_profile: Symbt3SemanticProfile::Symbt3J2,
            enabled_families: relation.oracle_layout.constraint_families.clone(),
            whir_parameter_digest: relation.shape.accumulator_shape.whir_parameter_digest,
            relation_id: relation.relation_id(),
            folding_protocol_id: relation.folding_protocol_id(),
            proof_public_statement_schedule,
            challenge_schedule_digest: symbt3_challenge_schedule_policy_digest(
                scheme,
                relation,
                field_policy,
                sumcheck_challenge_policy,
                repetition_count,
            ),
            fiat_shamir_domain_digest: symbt3_fiat_shamir_domain_digest(
                scheme,
                &fs_domain_separators,
                proof_public_statement_schedule,
            ),
            ring_module_layout_digest: relation.ring_module_layout.digest(scheme),
            ring_module_law_digest: symbt3_ring_module_law_policy_digest(scheme, relation),
            algebra_law_digest: relation.algebra_law.digest(scheme),
            folded_gr1cs_product_residual_layout_digest: relation
                .folded_gr1cs_product_residual_layout
                .digest(scheme),
            ajtai_policy_digest: symbt3_ajtai_policy_digest(scheme, relation),
            norm_range_policy_digest: symbt3_norm_range_policy_digest(scheme, relation),
            ajtai_linear_algebra_layout_digest: relation.ajtai_linear_algebra_layout.digest(scheme),
            ajtai_norm_range_layout_digest: relation.ajtai_norm_range_layout.digest(scheme),
            batch_manifest_layout_digest: relation.batch_manifest_layout.digest(scheme),
            manifest_commitment_policy_digest: symbt3_manifest_commitment_policy_digest(
                scheme,
                ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            ),
            message_oracle_policy_digest: symbt3_message_oracle_policy_digest(scheme, relation),
            accumulator_transition_policy_digest,
            accumulator_transition_profile_digest: accumulator_transition_policy_digest,
            message_semantic_layout_digest: relation.message_semantic_layout.digest(scheme),
            projection_layout_digest: relation
                .ajtai_norm_range_layout
                .projection_layout
                .digest(scheme),
            range_layout_digest: relation.ajtai_norm_range_layout.range_layout.digest(scheme),
            monomial_embedding_layout_digest: relation
                .ajtai_norm_range_layout
                .monomial_embedding_layout
                .digest(scheme),
            representative_layout_digest: relation
                .ajtai_norm_range_layout
                .representative_layout
                .digest(scheme),
            field_policy,
            sumcheck_challenge_policy,
            repetition_count,
            fs_domain_separators,
            soundness_target_bits,
            soundness_bound_bits: soundness_target_bits,
            whir_proximity_soundness_bits: soundness_bits,
            sumcheck_identity_check_bits: soundness_bits,
            rlc_batching_bits: soundness_bits,
            manifest_membership_bits: soundness_bits,
            message_view_bits: soundness_bits,
            norm_range_projection_bits: soundness_bits,
            ajtai_binding_bits: soundness_bits,
            bcs_rom_bits: soundness_bits,
            union_bound_overhead_bits: relation
                .oracle_layout
                .constraint_families
                .len()
                .next_power_of_two()
                .trailing_zeros(),
            union_bound_family_count: relation.oracle_layout.constraint_families.len(),
            accepted_shape_id: relation.shape.shape_id,
            accepted_batch_capacity: relation.shape.batch_capacity,
            accepted_active_policy: relation.batch_manifest_layout.active_policy,
            soundness_status,
            zk_status,
            routing_status,
            product_policy,
            product_eligible,
            research_only,
            authority_status,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.version_marker);
        out.extend_from_slice(&self.profile_version.to_le_bytes());
        out.extend_from_slice(&self.semantic_profile_version.to_le_bytes());
        push_bytes(&mut out, self.semantic_version.as_bytes());
        out.push(symbt3_semantic_profile_code(self.semantic_profile));
        push_usize(&mut out, self.enabled_families.len());
        for family in &self.enabled_families {
            out.push(symbt3_constraint_family_code(*family));
        }
        out.extend_from_slice(&self.whir_parameter_digest);
        out.extend_from_slice(&self.relation_id);
        out.extend_from_slice(&self.folding_protocol_id);
        push_bytes(&mut out, self.proof_public_statement_schedule.as_bytes());
        out.extend_from_slice(&self.challenge_schedule_digest);
        out.extend_from_slice(&self.fiat_shamir_domain_digest);
        out.extend_from_slice(&self.ring_module_layout_digest);
        out.extend_from_slice(&self.ring_module_law_digest);
        out.extend_from_slice(&self.algebra_law_digest);
        out.extend_from_slice(&self.folded_gr1cs_product_residual_layout_digest);
        out.extend_from_slice(&self.ajtai_policy_digest);
        out.extend_from_slice(&self.norm_range_policy_digest);
        out.extend_from_slice(&self.ajtai_linear_algebra_layout_digest);
        out.extend_from_slice(&self.ajtai_norm_range_layout_digest);
        out.extend_from_slice(&self.batch_manifest_layout_digest);
        out.extend_from_slice(&self.manifest_commitment_policy_digest);
        out.extend_from_slice(&self.message_oracle_policy_digest);
        out.extend_from_slice(&self.accumulator_transition_policy_digest);
        out.extend_from_slice(&self.accumulator_transition_profile_digest);
        out.extend_from_slice(&self.message_semantic_layout_digest);
        out.extend_from_slice(&self.projection_layout_digest);
        out.extend_from_slice(&self.range_layout_digest);
        out.extend_from_slice(&self.monomial_embedding_layout_digest);
        out.extend_from_slice(&self.representative_layout_digest);
        out.push(symbt3_field_extension_policy_code(self.field_policy));
        out.push(symbt3_sumcheck_challenge_policy_code(
            self.sumcheck_challenge_policy,
        ));
        push_usize(&mut out, self.repetition_count);
        push_usize(&mut out, self.fs_domain_separators.len());
        for separator in &self.fs_domain_separators {
            push_bytes(&mut out, separator.as_bytes());
        }
        out.extend_from_slice(&self.soundness_target_bits.to_le_bytes());
        out.extend_from_slice(&self.soundness_bound_bits.to_le_bytes());
        out.extend_from_slice(&self.whir_proximity_soundness_bits.to_le_bytes());
        out.extend_from_slice(&self.sumcheck_identity_check_bits.to_le_bytes());
        out.extend_from_slice(&self.rlc_batching_bits.to_le_bytes());
        out.extend_from_slice(&self.manifest_membership_bits.to_le_bytes());
        out.extend_from_slice(&self.message_view_bits.to_le_bytes());
        out.extend_from_slice(&self.norm_range_projection_bits.to_le_bytes());
        out.extend_from_slice(&self.ajtai_binding_bits.to_le_bytes());
        out.extend_from_slice(&self.bcs_rom_bits.to_le_bytes());
        out.extend_from_slice(&self.union_bound_overhead_bits.to_le_bytes());
        push_usize(&mut out, self.union_bound_family_count);
        out.extend_from_slice(&self.accepted_shape_id);
        push_usize(&mut out, self.accepted_batch_capacity);
        out.push(symbt3_active_policy_code(self.accepted_active_policy));
        out.push(symbt3_soundness_status_code(self.soundness_status));
        out.push(symbt3_zk_status_code(self.zk_status));
        out.push(symbt3_routing_status_code(self.routing_status));
        out.push(symbt3_product_policy_code(self.product_policy));
        out.push(u8::from(self.product_eligible));
        out.push(u8::from(self.research_only));
        out.push(symbt3_authority_status_code(self.authority_status));
        out
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        digest_domain_with_scheme(
            scheme,
            b"batched-cp-symbt3-authority-profile-v1",
            &self.canonical_bytes(),
        )
    }

    #[must_use]
    pub fn matches_relation_metadata(&self, relation: &BatchedCpSymbt3RelationDescription) -> bool {
        let scheme = relation.shape.accumulator_shape.digest_scheme;
        self.profile_version == SYMBT3_AUTHORITY_PROFILE_VERSION
            && self.enabled_families == relation.oracle_layout.constraint_families
            && self.whir_parameter_digest == relation.shape.accumulator_shape.whir_parameter_digest
            && self.relation_id == relation.relation_id()
            && self.folding_protocol_id == relation.folding_protocol_id()
            && self.challenge_schedule_digest
                == symbt3_challenge_schedule_policy_digest(
                    scheme,
                    relation,
                    self.field_policy,
                    self.sumcheck_challenge_policy,
                    self.repetition_count,
                )
            && self.fiat_shamir_domain_digest
                == symbt3_fiat_shamir_domain_digest(
                    scheme,
                    &self.fs_domain_separators,
                    self.proof_public_statement_schedule,
                )
            && self.ring_module_layout_digest == relation.ring_module_layout.digest(scheme)
            && self.ring_module_law_digest == symbt3_ring_module_law_policy_digest(scheme, relation)
            && self.algebra_law_digest == relation.algebra_law.digest(scheme)
            && self.folded_gr1cs_product_residual_layout_digest
                == relation.folded_gr1cs_product_residual_layout.digest(scheme)
            && self.ajtai_policy_digest == symbt3_ajtai_policy_digest(scheme, relation)
            && self.norm_range_policy_digest == symbt3_norm_range_policy_digest(scheme, relation)
            && self.ajtai_linear_algebra_layout_digest
                == relation.ajtai_linear_algebra_layout.digest(scheme)
            && self.ajtai_norm_range_layout_digest
                == relation.ajtai_norm_range_layout.digest(scheme)
            && self.batch_manifest_layout_digest == relation.batch_manifest_layout.digest(scheme)
            && self.manifest_commitment_policy_digest
                == symbt3_manifest_commitment_policy_digest(
                    scheme,
                    ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
                )
            && self.accumulator_transition_profile_digest
                == symbt3_accumulator_transition_profile_digest(scheme, relation)
            && self.accumulator_transition_policy_digest
                == symbt3_accumulator_transition_profile_digest(scheme, relation)
            && self.message_oracle_policy_digest
                == symbt3_message_oracle_policy_digest(scheme, relation)
            && relation
                .batch_manifest_layout
                .component_kinds
                .iter()
                .all(|component| {
                    component.visibility != Symbt3ManifestVisibility::CommittedPrivateRoot
                })
            && self.message_semantic_layout_digest
                == relation.message_semantic_layout.digest(scheme)
            && self.projection_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .projection_layout
                    .digest(scheme)
            && self.range_layout_digest
                == relation.ajtai_norm_range_layout.range_layout.digest(scheme)
            && self.monomial_embedding_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .monomial_embedding_layout
                    .digest(scheme)
            && self.representative_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .representative_layout
                    .digest(scheme)
            && self.union_bound_family_count == relation.oracle_layout.constraint_families.len()
            && self.accepted_shape_id == relation.shape.shape_id
            && self.accepted_batch_capacity == relation.shape.batch_capacity
            && self.accepted_active_policy == relation.batch_manifest_layout.active_policy
    }

    #[must_use]
    pub fn effective_soundness_bits(&self) -> u32 {
        let bits = [
            self.whir_proximity_soundness_bits,
            self.sumcheck_identity_check_bits,
            self.rlc_batching_bits,
            self.manifest_membership_bits,
            self.message_view_bits,
            self.norm_range_projection_bits,
            self.ajtai_binding_bits,
            self.bcs_rom_bits,
        ];
        let failure_probability = bits
            .iter()
            .map(|&bits| 2.0f64.powi(-(bits as i32)))
            .sum::<f64>();
        if !failure_probability.is_finite() || failure_probability <= 0.0 {
            return u32::MAX;
        }
        let effective = -failure_probability.log2();
        if effective <= 0.0 {
            0
        } else {
            effective.floor() as u32
        }
    }

    #[must_use]
    pub fn accepts_relation_for_accumulator_soundness_authority_candidate(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> bool {
        profile_meets_accumulator_soundness_authority_for_relation(self, relation)
    }

    #[must_use]
    pub fn accepts_relation_for_research_authority_candidate(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> bool {
        self.matches_relation_metadata(relation)
            && self.semantic_profile == Symbt3SemanticProfile::Symbt3J2
            && self.semantic_profile_version == 0
            && self.soundness_status == Symbt3SoundnessStatus::SoundnessCandidate
            && self.authority_status == Symbt3AuthorityStatus::AuthorityCandidateV1
            && self.zk_status == Symbt3ZkStatus::NonZkDevelopment
            && self.routing_status == Symbt3RoutingStatus::ResearchOnly
            && !self.product_eligible
            && self.research_only
            && relation.has_symbt3_k2_families()
            && relation
                .message_semantic_layout
                .message_to_trace_binding_count()
                == 0
            && relation.algebra_law.product_law == Symbt3ProductLawId::RqNegacyclicConvolutionV1
            && relation.algebra_law.beta_action == Symbt3BetaActionId::RingCoefficientActionV1
            && relation
                .ajtai_norm_range_layout
                .projection_layout
                .projection_mode
                != Symbt3ProjectionMode::DirectDevDenseProjectionV1
            && relation.ajtai_norm_range_layout.range_mode
                != Symbt3RangeMode::DirectSignedRangeDevV1
    }

    #[must_use]
    pub fn accepts_relation_for_product_authority(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> bool {
        self.matches_relation_metadata(relation)
            && self.semantic_profile == Symbt3SemanticProfile::Symbt3J2
            && self.soundness_status == Symbt3SoundnessStatus::SoundnessCandidate
            && self.authority_status == Symbt3AuthorityStatus::AuthorityCandidateV1
            && self.routing_status == Symbt3RoutingStatus::ProductAuthority
            && self.product_eligible
            && !self.research_only
            && self.field_policy == Symbt3FieldExtensionPolicy::ExtensionFieldAuthorityRequired
            && self.sumcheck_challenge_policy
                == Symbt3SumcheckChallengePolicy::AuthorityRepetitionOrExtensionV1
            && self.repetition_count >= 2
            && self.soundness_target_bits >= 80
            && self.zk_status == Symbt3ZkStatus::ZkRequiredForProductRoute
            && relation.has_symbt3_k2_families()
            && relation
                .message_semantic_layout
                .message_to_trace_binding_count()
                == 0
            && relation.algebra_law.product_law == Symbt3ProductLawId::RqNegacyclicConvolutionV1
            && relation.algebra_law.beta_action == Symbt3BetaActionId::RingCoefficientActionV1
            && relation
                .ajtai_norm_range_layout
                .projection_layout
                .projection_mode
                != Symbt3ProjectionMode::DirectDevDenseProjectionV1
            && relation.ajtai_norm_range_layout.range_mode
                != Symbt3RangeMode::DirectSignedRangeDevV1
            && !relation
                .algebra_law
                .soundness_profile
                .contains("NonAuthoritativeDevelopment")
            && relation.algebra_law.zk_profile != "NonZkDevelopment"
    }

    #[must_use]
    pub fn accepts_relation_for_non_zk_integrity_product_authority(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> bool {
        profile_meets_accumulator_soundness_non_zk_integrity_product_for_relation(self, relation)
    }

    #[must_use]
    pub fn accepts_statement_for_product_authority(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> bool {
        self.accepts_relation_for_product_authority(relation)
            && statement.matches_relation(relation)
            && derive_symbt3_batch_challenge_digest(relation, statement)
                == derive_symbt3_batch_challenge_digest(relation, statement)
    }

    #[must_use]
    pub fn accepts_statement_for_non_zk_integrity_product_authority(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> bool {
        self.accepts_relation_for_non_zk_integrity_product_authority(relation)
            && statement.matches_relation(relation)
    }

    #[must_use]
    pub fn accepts_statement_for_research_authority_candidate(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> bool {
        self.accepts_relation_for_research_authority_candidate(relation)
            && statement.matches_relation(relation)
            && derive_symbt3_batch_challenge_digest(relation, statement)
                == derive_symbt3_batch_challenge_digest(relation, statement)
    }

    #[must_use]
    pub fn accepts_statement_for_accumulator_soundness_authority_candidate(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> bool {
        self.accepts_relation_for_accumulator_soundness_authority_candidate(relation)
            && statement.matches_relation(relation)
    }
}

#[must_use]
pub fn profile_meets_accumulator_soundness_authority(profile: &Symbt3AuthorityProfile) -> bool {
    profile_meets_accumulator_soundness_authority_core(profile)
        && profile.routing_status == Symbt3RoutingStatus::ResearchOnly
        && profile.research_only
        && !profile.product_eligible
        && profile.product_policy == Symbt3ProductPolicy::MonolithicTypedCpOnly
}

#[must_use]
pub fn profile_meets_accumulator_soundness_authority_for_relation(
    profile: &Symbt3AuthorityProfile,
    relation: &BatchedCpSymbt3RelationDescription,
) -> bool {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    profile_meets_accumulator_soundness_authority(profile)
        && profile.matches_relation_metadata(relation)
        && profile.semantic_profile == Symbt3SemanticProfile::Symbt3J2
        && relation.has_symbt3_k2_families()
        && relation
            .oracle_layout
            .constraint_families
            .contains(&BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim)
        && relation
            .oracle_layout
            .constraint_families
            .contains(&BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency)
        && profile.manifest_commitment_policy_digest
            == symbt3_manifest_commitment_policy_digest(
                scheme,
                ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            )
        && relation
            .batch_manifest_layout
            .component_kinds
            .iter()
            .all(|component| component.visibility != Symbt3ManifestVisibility::CommittedPrivateRoot)
        && relation
            .message_semantic_layout
            .message_to_trace_binding_count()
            == 0
        && relation.algebra_law.product_law == Symbt3ProductLawId::RqNegacyclicConvolutionV1
        && relation.algebra_law.beta_action == Symbt3BetaActionId::RingCoefficientActionV1
        && relation
            .ajtai_norm_range_layout
            .projection_layout
            .projection_mode
            == Symbt3ProjectionMode::StructuredBlockProjectionV1
        && relation.ajtai_norm_range_layout.projection_layout.block_len > 1
        && relation
            .ajtai_norm_range_layout
            .projection_layout
            .output_len
            < relation
                .ajtai_norm_range_layout
                .projection_layout
                .input_len
                .max(1)
        && relation.ajtai_norm_range_layout.range_mode == Symbt3RangeMode::MonomialEmbeddingRangeV1
        && relation.ajtai_norm_range_layout.range_layout.range_mode
            == Symbt3RangeMode::MonomialEmbeddingRangeV1
        && relation
            .ajtai_norm_range_layout
            .range_layout
            .table_digest
            .is_some()
        && relation
            .ajtai_norm_range_layout
            .range_layout
            .monomial_embedding_layout_digest
            .is_some()
        && relation
            .ajtai_norm_range_layout
            .representative_layout
            .modulus_digest
            != [0u8; 32]
        && relation
            .ajtai_norm_range_layout
            .representative_layout
            .signed_range
            > 0
        && relation
            .ajtai_norm_range_layout
            .monomial_embedding_layout
            .table_polynomial_digest
            != [0u8; 32]
        && relation.has_symbt3_j_families()
}

#[must_use]
pub fn product_policy_accepts_non_zk(profile: &Symbt3AuthorityProfile) -> bool {
    profile.product_policy == Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn
}

#[must_use]
pub fn profile_meets_accumulator_soundness_non_zk_integrity_product(
    profile: &Symbt3AuthorityProfile,
) -> bool {
    profile_meets_accumulator_soundness_authority_core(profile)
        && profile.routing_status == Symbt3RoutingStatus::ProductAuthority
        && profile.product_eligible
        && !profile.research_only
        && profile.zk_status == Symbt3ZkStatus::NonZkIntegrityOnly
        && product_policy_accepts_non_zk(profile)
}

#[must_use]
pub fn profile_meets_accumulator_soundness_non_zk_integrity_product_for_relation(
    profile: &Symbt3AuthorityProfile,
    relation: &BatchedCpSymbt3RelationDescription,
) -> bool {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        && profile.matches_relation_metadata(relation)
        && profile.semantic_profile == Symbt3SemanticProfile::Symbt3J2
        && relation.has_symbt3_k2_families()
        && relation
            .oracle_layout
            .constraint_families
            .contains(&BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim)
        && relation
            .oracle_layout
            .constraint_families
            .contains(&BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency)
        && profile.manifest_commitment_policy_digest
            == symbt3_manifest_commitment_policy_digest(
                scheme,
                ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            )
        && relation
            .batch_manifest_layout
            .component_kinds
            .iter()
            .all(|component| component.visibility != Symbt3ManifestVisibility::CommittedPrivateRoot)
        && relation
            .message_semantic_layout
            .message_to_trace_binding_count()
            == 0
        && relation.algebra_law.product_law == Symbt3ProductLawId::RqNegacyclicConvolutionV1
        && relation.algebra_law.beta_action == Symbt3BetaActionId::RingCoefficientActionV1
        && relation
            .ajtai_norm_range_layout
            .projection_layout
            .projection_mode
            == Symbt3ProjectionMode::StructuredBlockProjectionV1
        && relation.ajtai_norm_range_layout.projection_layout.block_len > 1
        && relation
            .ajtai_norm_range_layout
            .projection_layout
            .output_len
            < relation
                .ajtai_norm_range_layout
                .projection_layout
                .input_len
                .max(1)
        && relation.ajtai_norm_range_layout.range_mode == Symbt3RangeMode::MonomialEmbeddingRangeV1
        && relation.ajtai_norm_range_layout.range_layout.range_mode
            == Symbt3RangeMode::MonomialEmbeddingRangeV1
        && relation
            .ajtai_norm_range_layout
            .range_layout
            .table_digest
            .is_some()
        && relation
            .ajtai_norm_range_layout
            .range_layout
            .monomial_embedding_layout_digest
            .is_some()
        && relation
            .ajtai_norm_range_layout
            .representative_layout
            .modulus_digest
            != [0u8; 32]
        && relation
            .ajtai_norm_range_layout
            .representative_layout
            .signed_range
            > 0
        && relation
            .ajtai_norm_range_layout
            .monomial_embedding_layout
            .table_polynomial_digest
            != [0u8; 32]
        && relation.has_symbt3_j_families()
}

fn profile_meets_accumulator_soundness_authority_core(profile: &Symbt3AuthorityProfile) -> bool {
    profile.semantic_profile_version >= 1
        && profile.soundness_status != Symbt3SoundnessStatus::DevelopmentOnly
        && profile.authority_status == Symbt3AuthorityStatus::AuthorityCandidateV1
        && profile
            .enabled_families
            .contains(&BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim)
        && profile
            .enabled_families
            .contains(&BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency)
        && profile.policy_digests_are_populated()
        && profile.effective_soundness_bits() >= profile.soundness_bound_bits
}

impl Symbt3AuthorityProfile {
    #[must_use]
    fn policy_digests_are_populated(&self) -> bool {
        [
            self.challenge_schedule_digest,
            self.fiat_shamir_domain_digest,
            self.ring_module_law_digest,
            self.ajtai_policy_digest,
            self.norm_range_policy_digest,
            self.manifest_commitment_policy_digest,
            self.message_oracle_policy_digest,
            self.accumulator_transition_policy_digest,
            self.accumulator_transition_profile_digest,
        ]
        .iter()
        .all(|digest| *digest != [0u8; 32])
    }
}

impl BatchedCpSemanticColumnarV2Layout {
    #[must_use]
    pub fn from_semantic(semantic: &BatchedCpSemanticRelationDescription) -> Self {
        let mut columns = Vec::new();
        let mut residuals = Vec::new();
        push_columnar_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            "active-or-dummy-policy",
            b"symbtc2-columnar-active-or-dummy-v1",
            BatchedCpSemanticColumnV2Kind::ActiveMask,
            BatchedCpSemanticColumnV2Kind::InactivePadding,
            semantic.shape.active_marker_byte_equalities(),
        );
        push_columnar_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::ManifestMembership,
            "manifest-membership",
            b"symbtc2-columnar-manifest-membership-v1",
            BatchedCpSemanticColumnV2Kind::ManifestItemTag,
            BatchedCpSemanticColumnV2Kind::ManifestPublicStatement,
            semantic.shape.manifest_membership_byte_equalities(),
        );
        push_columnar_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            "round-message-binding",
            b"symbtc2-columnar-round-message-binding-v1",
            BatchedCpSemanticColumnV2Kind::RoundMessage,
            BatchedCpSemanticColumnV2Kind::DigestBodyMessage,
            semantic.shape.structured_oracle_byte_equalities(),
        );
        push_columnar_public_value_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::ChallengeDerivation,
            "challenge-derivation-public-packed-values",
            b"symbtc2-columnar-challenge-derivation-v1",
            BatchedCpSemanticColumnV2Kind::ChallengeBodyPackedValue,
            count_packed_chunks_in_range(
                semantic.oracle_layout.byte_len,
                semantic.oracle_layout.batch_challenge_body,
            ),
        );
        push_columnar_public_value_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
            "challenge-to-beta-public-packed-values",
            b"symbtc2-columnar-challenge-to-beta-v1",
            BatchedCpSemanticColumnV2Kind::ChallengeToBetaPackedValue,
            count_packed_chunks_in_range(
                semantic.oracle_layout.byte_len,
                semantic.oracle_layout.challenge_to_beta_body,
            ),
        );
        push_columnar_product_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
            "poseidon-fs-commitment-r1cs-rows",
            b"symbtc2-columnar-poseidon-r1cs-v1",
            BatchedCpSemanticColumnV2Kind::PoseidonR1csA,
            BatchedCpSemanticColumnV2Kind::PoseidonR1csB,
            BatchedCpSemanticColumnV2Kind::PoseidonR1csC,
            semantic
                .shape
                .poseidon_fs_commitment_r1cs_constraints()
                .len(),
        );
        let folded_output_row_count = semantic
            .shape
            .folded_output_contribution_byte_equalities()
            .len()
            + semantic
                .shape
                .folded_output_self_consistency_byte_equalities()
                .len()
            + semantic
                .shape
                .fold_input_reconstruction_byte_equalities()
                .len()
            + semantic
                .shape
                .folded_public_input_linear_constraints()
                .len()
            + semantic
                .shape
                .folded_commitment_ring_mul_constraints()
                .len()
            + semantic
                .shape
                .folded_evaluation_ring_mul_constraints()
                .len();
        push_columnar_equality_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            "folded-output-derivation-equations",
            b"symbtc2-columnar-folded-output-v1",
            BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
            BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
            folded_output_row_count,
        );
        push_columnar_equality_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
            "ajtai-opening-linear-equations",
            b"symbtc2-columnar-ajtai-opening-v1",
            BatchedCpSemanticColumnV2Kind::AjtaiOpeningExpected,
            BatchedCpSemanticColumnV2Kind::AjtaiOpeningActual,
            semantic.ajtai_opening_linear_constraints().len(),
        );
        push_columnar_product_residual_columns(
            &mut columns,
            &mut residuals,
            BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
            "original-r1cs-residual-equations",
            b"symbtc2-columnar-original-r1cs-v1",
            BatchedCpSemanticColumnV2Kind::OriginalR1csA,
            BatchedCpSemanticColumnV2Kind::OriginalR1csB,
            BatchedCpSemanticColumnV2Kind::OriginalR1csC,
            semantic.original_r1cs_constraints().len(),
        );
        let column_row_count = columns
            .iter()
            .map(|column| column.row_count)
            .max()
            .unwrap_or(0)
            .next_power_of_two()
            .max(1);
        Self {
            layout_version: SEMANTIC_COLUMNAR_V2_LAYOUT_VERSION,
            column_row_count,
            columns,
            residuals,
        }
    }
}

impl BatchedCpSemanticFamilyColumnarV2Layout {
    #[must_use]
    pub fn from_semantic(semantic: &BatchedCpSemanticRelationDescription) -> Self {
        let mut tables = Vec::new();
        let mut table_offset = 0usize;
        for spec in family_columnar_v2_table_specs(semantic) {
            if spec.row_count == 0 {
                continue;
            }
            let padded_row_count = spec.row_count.next_power_of_two().max(1);
            let table_len = spec.column_kinds.len() * padded_row_count;
            tables.push(BatchedCpSemanticFamilyColumnarV2Table {
                family: spec.family,
                kind: spec.kind,
                label: spec.label,
                transcript_label: spec.transcript_label,
                column_kinds: spec.column_kinds,
                column_labels: spec.column_labels,
                row_count: spec.row_count,
                padded_row_count,
                table_offset,
            });
            table_offset += table_len;
        }
        Self {
            layout_version: SEMANTIC_COLUMNAR_V2_LAYOUT_VERSION,
            tables,
            total_field_len: table_offset,
        }
    }
}

fn family_columnar_v2_table_specs(
    semantic: &BatchedCpSemanticRelationDescription,
) -> Vec<BatchedCpFamilyColumnarV2TableSpec> {
    let shape = &semantic.shape;
    let mut specs = Vec::new();
    push_family_equality_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        "active-or-dummy-policy",
        b"symbt2f-active-or-dummy-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::ActiveMask,
        BatchedCpSemanticColumnV2Kind::InactivePadding,
        shape.active_marker_byte_equalities(),
    );
    push_family_equality_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::ManifestMembership,
        "manifest-membership",
        b"symbt2f-manifest-membership-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::ManifestItemTag,
        BatchedCpSemanticColumnV2Kind::ManifestPublicStatement,
        shape.manifest_membership_byte_equalities(),
    );

    for round in 0..shape.accumulator_shape.num_rounds {
        push_sectioned_message_equality_table_specs(
            &mut specs,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            "round-message-digest-body-byte-equality",
            b"symbt2f-round-message-digest-body-v2",
            shape,
            round,
            BatchedCpSemanticColumnV2Kind::RoundMessage,
            BatchedCpSemanticColumnV2Kind::DigestBodyMessage,
            round_message_digest_body_equalities_for_section,
        );
        push_sectioned_message_equality_table_specs(
            &mut specs,
            BatchedCpSemanticConstraintFamily::RoundMessageBinding,
            "round-message-witness-byte-equality",
            b"symbt2f-round-message-witness-v2",
            shape,
            round,
            BatchedCpSemanticColumnV2Kind::RoundMessage,
            BatchedCpSemanticColumnV2Kind::DigestBodyMessage,
            round_message_witness_equalities_for_section,
        );
    }

    push_family_packed_value_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::ChallengeDerivation,
        "challenge-derivation-public-packed-values",
        b"symbt2f-challenge-derivation-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::ChallengeBodyPackedValue,
        count_packed_chunks_in_range(
            semantic.oracle_layout.byte_len,
            semantic.oracle_layout.batch_challenge_body,
        ),
    );
    push_family_packed_value_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
        "challenge-to-beta-public-packed-values",
        b"symbt2f-challenge-to-beta-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::ChallengeToBetaPackedValue,
        count_packed_chunks_in_range(
            semantic.oracle_layout.byte_len,
            semantic.oracle_layout.challenge_to_beta_body,
        ),
    );

    push_family_product_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
        "poseidon-fs-commitment-r1cs-rows",
        b"symbt2f-poseidon-r1cs-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::PoseidonR1csA,
        BatchedCpSemanticColumnV2Kind::PoseidonR1csB,
        BatchedCpSemanticColumnV2Kind::PoseidonR1csC,
        BatchedCpFamilyColumnarV2TableSource::PoseidonR1cs(
            shape.poseidon_fs_commitment_r1cs_constraints(),
        ),
    );

    push_family_equality_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        "folded-output-contribution-byte-equality",
        b"symbt2f-folded-output-contribution-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
        BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
        shape.folded_output_contribution_byte_equalities(),
    );
    push_family_equality_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        "folded-output-self-consistency-byte-equality",
        b"symbt2f-folded-output-self-consistency-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
        BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
        shape.folded_output_self_consistency_byte_equalities(),
    );
    for round in 0..shape.accumulator_shape.num_rounds {
        push_family_equality_table_spec(
            &mut specs,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            &format!("fold-input-commitment-reconstruction-round-{round}"),
            family_transcript_label(b"symbt2f-fold-input-commitment-v1", round),
            BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
            BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
            fold_input_commitment_reconstruction_equalities(shape, round),
        );
        push_family_equality_table_spec(
            &mut specs,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            &format!("fold-input-public-input-reconstruction-round-{round}"),
            family_transcript_label(b"symbt2f-fold-input-public-input-v1", round),
            BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
            BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
            fold_input_public_input_reconstruction_equalities(shape, round),
        );
        push_sectioned_message_equality_table_specs(
            &mut specs,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            "fold-input-eval-message-reconstruction",
            b"symbt2f-fold-input-eval-message-v2",
            shape,
            round,
            BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
            BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
            fold_input_eval_message_reconstruction_equalities_for_section,
        );
        push_sectioned_message_equality_table_specs(
            &mut specs,
            BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
            "fold-input-round-message-reconstruction",
            b"symbt2f-fold-input-round-message-v2",
            shape,
            round,
            BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
            BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
            fold_input_round_message_reconstruction_equalities_for_section,
        );
    }
    push_family_equality_equation_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        "folded-public-input-linear-equations",
        b"symbt2f-folded-public-input-linear-v1".to_vec(),
        BatchedCpFamilyColumnarV2TableSource::FoldedPublicInputLinear(
            shape.folded_public_input_linear_constraints(),
        ),
    );
    push_family_equality_equation_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        "folded-commitment-ring-mul-equations",
        b"symbt2f-folded-commitment-ring-mul-v1".to_vec(),
        BatchedCpFamilyColumnarV2TableSource::FoldedCommitmentRingMul(
            shape.folded_commitment_ring_mul_constraints(),
        ),
    );
    push_family_equality_equation_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        "folded-evaluation-ring-mul-equations",
        b"symbt2f-folded-evaluation-ring-mul-v1".to_vec(),
        BatchedCpFamilyColumnarV2TableSource::FoldedEvaluationRingMul(
            shape.folded_evaluation_ring_mul_constraints(),
        ),
    );

    push_family_equality_equation_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
        "ajtai-opening-linear-equations",
        b"symbt2f-ajtai-opening-v1".to_vec(),
        BatchedCpFamilyColumnarV2TableSource::AjtaiOpeningLinear(
            semantic.ajtai_opening_linear_constraints(),
        ),
    );
    push_family_product_table_spec(
        &mut specs,
        BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
        "original-r1cs-residual-equations",
        b"symbt2f-original-r1cs-v1".to_vec(),
        BatchedCpSemanticColumnV2Kind::OriginalR1csA,
        BatchedCpSemanticColumnV2Kind::OriginalR1csB,
        BatchedCpSemanticColumnV2Kind::OriginalR1csC,
        BatchedCpFamilyColumnarV2TableSource::OriginalR1cs(semantic.original_r1cs_constraints()),
    );
    specs
}

fn push_family_equality_table_spec(
    specs: &mut Vec<BatchedCpFamilyColumnarV2TableSpec>,
    family: BatchedCpSemanticConstraintFamily,
    label: &str,
    transcript_label: Vec<u8>,
    left_kind: BatchedCpSemanticColumnV2Kind,
    right_kind: BatchedCpSemanticColumnV2Kind,
    equalities: Vec<BatchedCpOracleByteEquality>,
) {
    if equalities.is_empty() {
        return;
    }
    specs.push(BatchedCpFamilyColumnarV2TableSpec {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Equality,
        label: label.to_string(),
        transcript_label,
        column_kinds: vec![left_kind, right_kind],
        column_labels: vec![format!("{label}-left"), format!("{label}-right")],
        row_count: equalities.len(),
        source: BatchedCpFamilyColumnarV2TableSource::Equality(equalities),
    });
}

fn push_sectioned_message_equality_table_specs(
    specs: &mut Vec<BatchedCpFamilyColumnarV2TableSpec>,
    family: BatchedCpSemanticConstraintFamily,
    label_prefix: &str,
    transcript_prefix: &[u8],
    shape: &BatchedCpStatementShape,
    round: usize,
    left_kind: BatchedCpSemanticColumnV2Kind,
    right_kind: BatchedCpSemanticColumnV2Kind,
    equalities_for_section: fn(
        &BatchedCpStatementShape,
        usize,
        &BatchedCpGr1csMessageSection,
    ) -> Vec<BatchedCpOracleByteEquality>,
) {
    let Some(sections) = shape.accumulator_shape.gr1cs_message_sections.get(round) else {
        return;
    };
    for section in sections {
        if section.len == 0 {
            continue;
        }
        let equalities = equalities_for_section(shape, round, section);
        for (chunk_idx, chunk) in equalities
            .chunks(SYMBT2F_MAX_SECTION_EQUALITY_ROWS)
            .enumerate()
        {
            if chunk.is_empty() {
                continue;
            }
            let label = format!(
                "{label_prefix}-round-{round}-section-{}-chunk-{chunk_idx}",
                section.kind.label()
            );
            let transcript_label =
                family_section_transcript_label(transcript_prefix, round, &section.kind, chunk_idx);
            push_family_equality_table_spec(
                specs,
                family,
                &label,
                transcript_label,
                left_kind,
                right_kind,
                chunk.to_vec(),
            );
        }
    }
}

fn family_section_transcript_label(
    prefix: &[u8],
    round: usize,
    section: &BatchedCpGr1csMessageSectionKind,
    chunk_idx: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 24);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&(round as u64).to_le_bytes());
    out.push(gr1cs_message_section_kind_code(section));
    out.extend_from_slice(&(chunk_idx as u64).to_le_bytes());
    out
}

fn push_family_packed_value_table_spec(
    specs: &mut Vec<BatchedCpFamilyColumnarV2TableSpec>,
    family: BatchedCpSemanticConstraintFamily,
    label: &str,
    transcript_label: Vec<u8>,
    oracle_kind: BatchedCpSemanticColumnV2Kind,
    row_count: usize,
) {
    if row_count == 0 {
        return;
    }
    specs.push(BatchedCpFamilyColumnarV2TableSpec {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Equality,
        label: label.to_string(),
        transcript_label,
        column_kinds: vec![
            oracle_kind,
            BatchedCpSemanticColumnV2Kind::PublicPackedValue,
        ],
        column_labels: vec![format!("{label}-oracle"), format!("{label}-public")],
        row_count,
        source: BatchedCpFamilyColumnarV2TableSource::PackedValue(family),
    });
}

fn push_family_equality_equation_table_spec(
    specs: &mut Vec<BatchedCpFamilyColumnarV2TableSpec>,
    family: BatchedCpSemanticConstraintFamily,
    label: &str,
    transcript_label: Vec<u8>,
    source: BatchedCpFamilyColumnarV2TableSource,
) {
    let row_count = family_table_source_row_count(&source);
    if row_count == 0 {
        return;
    }
    specs.push(BatchedCpFamilyColumnarV2TableSpec {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Equality,
        label: label.to_string(),
        transcript_label,
        column_kinds: vec![
            BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
            BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
        ],
        column_labels: vec![format!("{label}-left"), format!("{label}-right")],
        row_count,
        source,
    });
}

fn push_family_product_table_spec(
    specs: &mut Vec<BatchedCpFamilyColumnarV2TableSpec>,
    family: BatchedCpSemanticConstraintFamily,
    label: &str,
    transcript_label: Vec<u8>,
    left_kind: BatchedCpSemanticColumnV2Kind,
    aux_kind: BatchedCpSemanticColumnV2Kind,
    right_kind: BatchedCpSemanticColumnV2Kind,
    source: BatchedCpFamilyColumnarV2TableSource,
) {
    let row_count = family_table_source_row_count(&source);
    if row_count == 0 {
        return;
    }
    specs.push(BatchedCpFamilyColumnarV2TableSpec {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Product,
        label: label.to_string(),
        transcript_label,
        column_kinds: vec![left_kind, aux_kind, right_kind],
        column_labels: vec![
            format!("{label}-a"),
            format!("{label}-b"),
            format!("{label}-c"),
        ],
        row_count,
        source,
    });
}

fn family_table_source_row_count(source: &BatchedCpFamilyColumnarV2TableSource) -> usize {
    match source {
        BatchedCpFamilyColumnarV2TableSource::Equality(rows) => rows.len(),
        BatchedCpFamilyColumnarV2TableSource::PackedValue(_) => 0,
        BatchedCpFamilyColumnarV2TableSource::PoseidonR1cs(rows) => rows.len(),
        BatchedCpFamilyColumnarV2TableSource::FoldedPublicInputLinear(rows) => rows.len(),
        BatchedCpFamilyColumnarV2TableSource::FoldedCommitmentRingMul(rows) => rows.len(),
        BatchedCpFamilyColumnarV2TableSource::FoldedEvaluationRingMul(rows) => rows.len(),
        BatchedCpFamilyColumnarV2TableSource::AjtaiOpeningLinear(rows) => rows.len(),
        BatchedCpFamilyColumnarV2TableSource::OriginalR1cs(rows) => rows.len(),
    }
}

fn family_transcript_label(prefix: &[u8], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 8);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out
}

fn push_columnar_residual_columns(
    columns: &mut Vec<BatchedCpSemanticColumnV2>,
    residuals: &mut Vec<BatchedCpSemanticResidualV2>,
    family: BatchedCpSemanticConstraintFamily,
    label: &'static str,
    transcript_label: &'static [u8],
    left_kind: BatchedCpSemanticColumnV2Kind,
    right_kind: BatchedCpSemanticColumnV2Kind,
    equalities: Vec<BatchedCpOracleByteEquality>,
) {
    if equalities.is_empty() {
        return;
    }
    let left_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: left_column,
        kind: left_kind,
        label: format!("{label}-left"),
        row_count: equalities.len(),
    });
    let right_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: right_column,
        kind: right_kind,
        label: format!("{label}-right"),
        row_count: equalities.len(),
    });
    residuals.push(BatchedCpSemanticResidualV2 {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Equality,
        label: label.to_string(),
        transcript_label: transcript_label.to_vec(),
        left_column,
        right_column,
        aux_columns: Vec::new(),
        row_count: equalities.len(),
    });
}

fn push_columnar_equality_residual_columns(
    columns: &mut Vec<BatchedCpSemanticColumnV2>,
    residuals: &mut Vec<BatchedCpSemanticResidualV2>,
    family: BatchedCpSemanticConstraintFamily,
    label: &'static str,
    transcript_label: &'static [u8],
    left_kind: BatchedCpSemanticColumnV2Kind,
    right_kind: BatchedCpSemanticColumnV2Kind,
    row_count: usize,
) {
    if row_count == 0 {
        return;
    }
    let left_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: left_column,
        kind: left_kind,
        label: format!("{label}-left"),
        row_count,
    });
    let right_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: right_column,
        kind: right_kind,
        label: format!("{label}-right"),
        row_count,
    });
    residuals.push(BatchedCpSemanticResidualV2 {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Equality,
        label: label.to_string(),
        transcript_label: transcript_label.to_vec(),
        left_column,
        right_column,
        aux_columns: Vec::new(),
        row_count,
    });
}

fn push_columnar_product_residual_columns(
    columns: &mut Vec<BatchedCpSemanticColumnV2>,
    residuals: &mut Vec<BatchedCpSemanticResidualV2>,
    family: BatchedCpSemanticConstraintFamily,
    label: &'static str,
    transcript_label: &'static [u8],
    left_kind: BatchedCpSemanticColumnV2Kind,
    aux_kind: BatchedCpSemanticColumnV2Kind,
    right_kind: BatchedCpSemanticColumnV2Kind,
    row_count: usize,
) {
    if row_count == 0 {
        return;
    }
    let left_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: left_column,
        kind: left_kind,
        label: format!("{label}-a"),
        row_count,
    });
    let aux_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: aux_column,
        kind: aux_kind,
        label: format!("{label}-b"),
        row_count,
    });
    let right_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: right_column,
        kind: right_kind,
        label: format!("{label}-c"),
        row_count,
    });
    residuals.push(BatchedCpSemanticResidualV2 {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Product,
        label: label.to_string(),
        transcript_label: transcript_label.to_vec(),
        left_column,
        right_column,
        aux_columns: vec![aux_column],
        row_count,
    });
}

fn push_columnar_public_value_residual_columns(
    columns: &mut Vec<BatchedCpSemanticColumnV2>,
    residuals: &mut Vec<BatchedCpSemanticResidualV2>,
    family: BatchedCpSemanticConstraintFamily,
    label: &'static str,
    transcript_label: &'static [u8],
    oracle_kind: BatchedCpSemanticColumnV2Kind,
    row_count: usize,
) {
    if row_count == 0 {
        return;
    }
    let left_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: left_column,
        kind: oracle_kind,
        label: format!("{label}-oracle"),
        row_count,
    });
    let right_column = columns.len();
    columns.push(BatchedCpSemanticColumnV2 {
        id: right_column,
        kind: BatchedCpSemanticColumnV2Kind::PublicPackedValue,
        label: format!("{label}-public"),
        row_count,
    });
    residuals.push(BatchedCpSemanticResidualV2 {
        family,
        kind: BatchedCpSemanticResidualV2Kind::Equality,
        label: label.to_string(),
        transcript_label: transcript_label.to_vec(),
        left_column,
        right_column,
        aux_columns: Vec::new(),
        row_count,
    });
}

fn count_packed_chunks_in_range(byte_len: usize, range: BatchedCpOracleByteRange) -> usize {
    let range_end = range.offset.saturating_add(range.len);
    (0..byte_len.div_ceil(3))
        .filter(|chunk_index| {
            let start = chunk_index * 3;
            let end = byte_len.min(start + 3);
            start >= range.offset && end <= range_end
        })
        .count()
}

impl BatchedCpSemanticColumnarV2Description {
    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        self.semantic.public_statement_bytes()
    }

    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC);
        let semantic_context = self.semantic.canonical_context_bytes();
        push_usize(&mut out, semantic_context.len());
        out.extend_from_slice(&semantic_context);
        push_usize(&mut out, self.v2_layout.byte_len);
        push_usize(&mut out, self.v2_layout.packed_field_len);
        push_usize(&mut out, self.v2_layout.product_rows);
        push_usize(&mut out, self.v2_layout.semantic_column_count);
        push_usize(&mut out, self.v2_layout.residual_family_count);
        out.extend_from_slice(&self.columnar_layout.layout_version.to_le_bytes());
        push_usize(&mut out, self.columnar_layout.column_row_count);
        push_usize(&mut out, self.columnar_layout.columns.len());
        for column in &self.columnar_layout.columns {
            push_usize(&mut out, column.id);
            out.push(semantic_column_v2_kind_code(column.kind));
            push_bytes(&mut out, column.label.as_bytes());
            push_usize(&mut out, column.row_count);
        }
        push_usize(&mut out, self.columnar_layout.residuals.len());
        for residual in &self.columnar_layout.residuals {
            out.push(semantic_constraint_family_code(residual.family));
            out.push(semantic_residual_v2_kind_code(residual.kind));
            push_bytes(&mut out, residual.label.as_bytes());
            push_bytes(&mut out, &residual.transcript_label);
            push_usize(&mut out, residual.left_column);
            push_usize(&mut out, residual.right_column);
            push_usize_vec(&mut out, &residual.aux_columns);
            push_usize(&mut out, residual.row_count);
        }
        out
    }

    #[must_use]
    pub fn semantic_relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.semantic.shape.accumulator_shape.digest_scheme,
            b"batched-cp-semantic-columnar-v2-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes(),
            num_witness_vars: self.columnar_layout.columns.len()
                * self.columnar_layout.column_row_count,
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC.len()]
                != SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut pos = SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC.len();
        let semantic_context_len = read_usize(bytes, &mut pos)?;
        let semantic_context_end = pos
            .checked_add(semantic_context_len)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let semantic_context = bytes
            .get(pos..semantic_context_end)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let semantic = BatchedCpSemanticRelationDescription::from_context_bytes(semantic_context)?;
        pos = semantic_context_end;
        let v2_layout = BatchedCpSemanticOracleV2Layout {
            byte_len: read_usize(bytes, &mut pos)?,
            packed_field_len: read_usize(bytes, &mut pos)?,
            product_rows: read_usize(bytes, &mut pos)?,
            semantic_column_count: read_usize(bytes, &mut pos)?,
            residual_family_count: read_usize(bytes, &mut pos)?,
        };
        let layout_version = read_u64(bytes, &mut pos)?;
        let column_row_count = read_usize(bytes, &mut pos)?;
        let column_count = read_usize(bytes, &mut pos)?;
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let id = read_usize(bytes, &mut pos)?;
            let Some(&kind_code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            let kind = semantic_column_v2_kind_from_code(kind_code)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            let label = String::from_utf8(read_bytes(bytes, &mut pos)?)
                .map_err(|_| BatchedCpError::InvalidSemanticRelationContext)?;
            let row_count = read_usize(bytes, &mut pos)?;
            columns.push(BatchedCpSemanticColumnV2 {
                id,
                kind,
                label,
                row_count,
            });
        }
        let residual_count = read_usize(bytes, &mut pos)?;
        let mut residuals = Vec::with_capacity(residual_count);
        for _ in 0..residual_count {
            let Some(&family_code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            let family = semantic_constraint_family_from_code(family_code)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            let Some(&kind_code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            let kind = semantic_residual_v2_kind_from_code(kind_code)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            let label = String::from_utf8(read_bytes(bytes, &mut pos)?)
                .map_err(|_| BatchedCpError::InvalidSemanticRelationContext)?;
            let transcript_label = read_bytes(bytes, &mut pos)?;
            let left_column = read_usize(bytes, &mut pos)?;
            let right_column = read_usize(bytes, &mut pos)?;
            let aux_columns = read_usize_vec(bytes, &mut pos)?;
            let row_count = read_usize(bytes, &mut pos)?;
            residuals.push(BatchedCpSemanticResidualV2 {
                family,
                kind,
                label,
                transcript_label,
                left_column,
                right_column,
                aux_columns,
                row_count,
            });
        }
        let columnar_layout = BatchedCpSemanticColumnarV2Layout {
            layout_version,
            column_row_count,
            columns,
            residuals,
        };
        let expected_columnar_layout = BatchedCpSemanticColumnarV2Layout::from_semantic(&semantic);
        if pos != bytes.len()
            || v2_layout != BatchedCpSemanticOracleV2Layout::from_semantic(&semantic)
            || columnar_layout != expected_columnar_layout
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        Ok(Self {
            semantic,
            v2_layout,
            columnar_layout,
        })
    }
}

impl BatchedCpSemanticFamilyColumnarV2Description {
    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        self.semantic.public_statement_bytes()
    }

    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC);
        let semantic_context = self.semantic.canonical_context_bytes();
        push_usize(&mut out, semantic_context.len());
        out.extend_from_slice(&semantic_context);
        push_usize(&mut out, self.v2_layout.byte_len);
        push_usize(&mut out, self.v2_layout.packed_field_len);
        push_usize(&mut out, self.v2_layout.product_rows);
        push_usize(&mut out, self.v2_layout.semantic_column_count);
        push_usize(&mut out, self.v2_layout.residual_family_count);
        out.extend_from_slice(&self.family_layout.layout_version.to_le_bytes());
        push_usize(&mut out, self.family_layout.total_field_len);
        push_usize(&mut out, self.family_layout.tables.len());
        for table in &self.family_layout.tables {
            out.push(semantic_constraint_family_code(table.family));
            out.push(semantic_residual_v2_kind_code(table.kind));
            push_bytes(&mut out, table.label.as_bytes());
            push_bytes(&mut out, &table.transcript_label);
            push_usize(&mut out, table.column_kinds.len());
            for (&kind, label) in table.column_kinds.iter().zip(&table.column_labels) {
                out.push(semantic_column_v2_kind_code(kind));
                push_bytes(&mut out, label.as_bytes());
            }
            push_usize(&mut out, table.row_count);
            push_usize(&mut out, table.padded_row_count);
            push_usize(&mut out, table.table_offset);
        }
        out
    }

    #[must_use]
    pub fn semantic_relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.semantic.shape.accumulator_shape.digest_scheme,
            b"batched-cp-semantic-family-columnar-v2-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes(),
            num_witness_vars: self.family_layout.total_field_len,
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC.len()]
                != SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut pos = SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC.len();
        let semantic_context_len = read_usize(bytes, &mut pos)?;
        let semantic_context_end = pos
            .checked_add(semantic_context_len)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let semantic_context = bytes
            .get(pos..semantic_context_end)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        let semantic = BatchedCpSemanticRelationDescription::from_context_bytes(semantic_context)?;
        pos = semantic_context_end;
        let v2_layout = BatchedCpSemanticOracleV2Layout {
            byte_len: read_usize(bytes, &mut pos)?,
            packed_field_len: read_usize(bytes, &mut pos)?,
            product_rows: read_usize(bytes, &mut pos)?,
            semantic_column_count: read_usize(bytes, &mut pos)?,
            residual_family_count: read_usize(bytes, &mut pos)?,
        };
        let layout_version = read_u64(bytes, &mut pos)?;
        let total_field_len = read_usize(bytes, &mut pos)?;
        let table_count = read_usize(bytes, &mut pos)?;
        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            let Some(&family_code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            let family = semantic_constraint_family_from_code(family_code)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            let Some(&kind_code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            let kind = semantic_residual_v2_kind_from_code(kind_code)
                .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            let label = String::from_utf8(read_bytes(bytes, &mut pos)?)
                .map_err(|_| BatchedCpError::InvalidSemanticRelationContext)?;
            let transcript_label = read_bytes(bytes, &mut pos)?;
            let column_count = read_usize(bytes, &mut pos)?;
            let mut column_kinds = Vec::with_capacity(column_count);
            let mut column_labels = Vec::with_capacity(column_count);
            for _ in 0..column_count {
                let Some(&column_kind_code) = bytes.get(pos) else {
                    return Err(BatchedCpError::InvalidSemanticRelationContext);
                };
                pos += 1;
                column_kinds.push(
                    semantic_column_v2_kind_from_code(column_kind_code)
                        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
                );
                column_labels.push(
                    String::from_utf8(read_bytes(bytes, &mut pos)?)
                        .map_err(|_| BatchedCpError::InvalidSemanticRelationContext)?,
                );
            }
            let row_count = read_usize(bytes, &mut pos)?;
            let padded_row_count = read_usize(bytes, &mut pos)?;
            let table_offset = read_usize(bytes, &mut pos)?;
            tables.push(BatchedCpSemanticFamilyColumnarV2Table {
                family,
                kind,
                label,
                transcript_label,
                column_kinds,
                column_labels,
                row_count,
                padded_row_count,
                table_offset,
            });
        }
        let family_layout = BatchedCpSemanticFamilyColumnarV2Layout {
            layout_version,
            tables,
            total_field_len,
        };
        let expected_family_layout =
            BatchedCpSemanticFamilyColumnarV2Layout::from_semantic(&semantic);
        if pos != bytes.len()
            || v2_layout != BatchedCpSemanticOracleV2Layout::from_semantic(&semantic)
            || family_layout != expected_family_layout
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        Ok(Self {
            semantic,
            v2_layout,
            family_layout,
        })
    }
}

fn semantic_column_v2_kind_code(kind: BatchedCpSemanticColumnV2Kind) -> u8 {
    match kind {
        BatchedCpSemanticColumnV2Kind::ActiveMask => 1,
        BatchedCpSemanticColumnV2Kind::InactivePadding => 2,
        BatchedCpSemanticColumnV2Kind::ManifestItemTag => 3,
        BatchedCpSemanticColumnV2Kind::ManifestPublicStatement => 4,
        BatchedCpSemanticColumnV2Kind::RoundMessage => 5,
        BatchedCpSemanticColumnV2Kind::DigestBodyMessage => 6,
        BatchedCpSemanticColumnV2Kind::ChallengeBodyPackedValue => 7,
        BatchedCpSemanticColumnV2Kind::ChallengeToBetaPackedValue => 8,
        BatchedCpSemanticColumnV2Kind::PublicPackedValue => 9,
        BatchedCpSemanticColumnV2Kind::PoseidonR1csA => 10,
        BatchedCpSemanticColumnV2Kind::PoseidonR1csB => 11,
        BatchedCpSemanticColumnV2Kind::PoseidonR1csC => 12,
        BatchedCpSemanticColumnV2Kind::FoldedOutputExpected => 13,
        BatchedCpSemanticColumnV2Kind::FoldedOutputActual => 14,
        BatchedCpSemanticColumnV2Kind::AjtaiOpeningExpected => 15,
        BatchedCpSemanticColumnV2Kind::AjtaiOpeningActual => 16,
        BatchedCpSemanticColumnV2Kind::OriginalR1csA => 17,
        BatchedCpSemanticColumnV2Kind::OriginalR1csB => 18,
        BatchedCpSemanticColumnV2Kind::OriginalR1csC => 19,
    }
}

fn semantic_column_v2_kind_from_code(code: u8) -> Option<BatchedCpSemanticColumnV2Kind> {
    Some(match code {
        1 => BatchedCpSemanticColumnV2Kind::ActiveMask,
        2 => BatchedCpSemanticColumnV2Kind::InactivePadding,
        3 => BatchedCpSemanticColumnV2Kind::ManifestItemTag,
        4 => BatchedCpSemanticColumnV2Kind::ManifestPublicStatement,
        5 => BatchedCpSemanticColumnV2Kind::RoundMessage,
        6 => BatchedCpSemanticColumnV2Kind::DigestBodyMessage,
        7 => BatchedCpSemanticColumnV2Kind::ChallengeBodyPackedValue,
        8 => BatchedCpSemanticColumnV2Kind::ChallengeToBetaPackedValue,
        9 => BatchedCpSemanticColumnV2Kind::PublicPackedValue,
        10 => BatchedCpSemanticColumnV2Kind::PoseidonR1csA,
        11 => BatchedCpSemanticColumnV2Kind::PoseidonR1csB,
        12 => BatchedCpSemanticColumnV2Kind::PoseidonR1csC,
        13 => BatchedCpSemanticColumnV2Kind::FoldedOutputExpected,
        14 => BatchedCpSemanticColumnV2Kind::FoldedOutputActual,
        15 => BatchedCpSemanticColumnV2Kind::AjtaiOpeningExpected,
        16 => BatchedCpSemanticColumnV2Kind::AjtaiOpeningActual,
        17 => BatchedCpSemanticColumnV2Kind::OriginalR1csA,
        18 => BatchedCpSemanticColumnV2Kind::OriginalR1csB,
        19 => BatchedCpSemanticColumnV2Kind::OriginalR1csC,
        _ => return None,
    })
}

fn semantic_residual_v2_kind_code(kind: BatchedCpSemanticResidualV2Kind) -> u8 {
    match kind {
        BatchedCpSemanticResidualV2Kind::Equality => 1,
        BatchedCpSemanticResidualV2Kind::Product => 2,
    }
}

fn semantic_residual_v2_kind_from_code(code: u8) -> Option<BatchedCpSemanticResidualV2Kind> {
    Some(match code {
        1 => BatchedCpSemanticResidualV2Kind::Equality,
        2 => BatchedCpSemanticResidualV2Kind::Product,
        _ => return None,
    })
}

fn count_fully_known_packed_chunks(bytes: &[u8], known: &[bool]) -> usize {
    if bytes.len() != known.len() {
        return 0;
    }
    let chunk_claims = bytes
        .chunks(3)
        .enumerate()
        .filter(|(idx, chunk)| {
            let start = idx * 3;
            let end = start + chunk.len();
            known[start..end].iter().all(|&value| value)
        })
        .count();
    chunk_claims + 1 // final length sentinel
}

fn packed_values_for_known_range(
    bytes: &[u8],
    known: &[bool],
    range: BatchedCpOracleByteRange,
) -> Vec<BatchedCpOraclePackedValue> {
    if bytes.len() != known.len() {
        return Vec::new();
    }
    let range_end = range.offset.saturating_add(range.len);
    bytes
        .chunks(3)
        .enumerate()
        .filter_map(|(packed_index, chunk)| {
            let start = packed_index * 3;
            let end = start + chunk.len();
            if start < range.offset
                || end > range_end
                || !known.get(start..end)?.iter().all(|&value| value)
            {
                return None;
            }
            let mut value = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u32) << (8 * i);
            }
            Some(BatchedCpOraclePackedValue {
                packed_index,
                value,
            })
        })
        .collect()
}

fn push_range_equalities(
    equalities: &mut Vec<BatchedCpOracleByteEquality>,
    left: BatchedCpOracleByteRange,
    right: BatchedCpOracleByteRange,
) {
    if left.len != right.len {
        return;
    }
    equalities.extend((0..left.len).map(|offset| BatchedCpOracleByteEquality {
        left_offset: left.offset + offset,
        right_offset: right.offset + offset,
    }));
}

struct ProductOracleCursor {
    offset: usize,
}

impl ProductOracleCursor {
    fn new() -> Self {
        Self { offset: 0 }
    }

    fn push_u8(&mut self) {
        self.offset += 1;
    }

    fn push_usize(&mut self) {
        self.offset += 8;
    }

    fn push_raw_len(&mut self, len: usize) -> usize {
        let start = self.offset;
        self.offset += len;
        start
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> usize {
        self.push_bytes_len(bytes.len())
    }

    fn push_bytes_len(&mut self, len: usize) -> usize {
        self.push_usize();
        self.push_raw_len(len)
    }
}

fn encoded_statement_shape(shape: &BatchedCpStatementShape) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_statement_shape(&mut encoded, shape);
    encoded
}

impl BatchedCpStructuredRelationDescription {
    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STRUCTURED_RELATION_CONTEXT_MAGIC);
        encode_statement_shape(&mut out, &self.shape);
        push_usize(&mut out, self.public_statement_bytes);
        push_usize(&mut out, self.product_domain_size);
        push_usize(&mut out, self.witness_oracle_row_len);
        push_usize_vec(&mut out, &self.round_message_oracle_lens);
        out
    }

    #[must_use]
    pub fn relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-structured-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes,
            num_witness_vars: self.product_domain_size,
            // This is intentionally not a flattened/appended R1CS. The real
            // structured WHIR path consumes the context metadata directly.
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < STRUCTURED_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..STRUCTURED_RELATION_CONTEXT_MAGIC.len()]
                != STRUCTURED_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidStructuredRelationContext);
        }
        let mut pos = STRUCTURED_RELATION_CONTEXT_MAGIC.len();
        let shape = decode_statement_shape(bytes, &mut pos)?;
        let public_statement_bytes = read_usize(bytes, &mut pos)?;
        let product_domain_size = read_usize(bytes, &mut pos)?;
        let witness_oracle_row_len = read_usize(bytes, &mut pos)?;
        let round_message_oracle_lens = read_usize_vec(bytes, &mut pos)?;
        if pos != bytes.len()
            || product_domain_size != shape.product_domain_size()
            || witness_oracle_row_len != shape.witness_row_len
            || round_message_oracle_lens != shape.round_message_lens
        {
            return Err(BatchedCpError::InvalidStructuredRelationContext);
        }
        Ok(Self {
            shape,
            public_statement_bytes,
            product_domain_size,
            witness_oracle_row_len,
            round_message_oracle_lens,
        })
    }
}

impl BatchedCpSemanticRelationDescription {
    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        estimate_public_statement_bytes(&self.shape)
    }

    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEMANTIC_RELATION_CONTEXT_MAGIC);
        encode_statement_shape(&mut out, &self.shape);
        push_usize(&mut out, self.oracle_layout.byte_len);
        push_usize(&mut out, self.oracle_layout.packed_field_len);
        out.extend_from_slice(&self.ajtai_params_digest);
        encode_ring_matrix(&mut out, &self.ajtai_matrix);
        out.extend_from_slice(&self.r1cs_matrices_digest);
        encode_r1cs_matrices(&mut out, &self.r1cs_matrices);
        out.extend_from_slice(&self.input_bound.to_le_bytes());
        push_usize(&mut out, self.constraint_families.len());
        for family in &self.constraint_families {
            out.push(semantic_constraint_family_code(*family));
        }
        out
    }

    #[must_use]
    pub fn semantic_relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-semantic-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes(),
            num_witness_vars: self.oracle_layout.packed_field_len,
            // The semantic context is intentionally not an appended R1CS. A
            // later WHIR structured-constraint interface must consume these
            // families directly before this route can become authoritative.
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < SEMANTIC_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..SEMANTIC_RELATION_CONTEXT_MAGIC.len()] != SEMANTIC_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut pos = SEMANTIC_RELATION_CONTEXT_MAGIC.len();
        let shape = decode_statement_shape(bytes, &mut pos)?;
        let byte_len = read_usize(bytes, &mut pos)?;
        let packed_field_len = read_usize(bytes, &mut pos)?;
        let ajtai_params_digest = read_digest(bytes, &mut pos)?;
        let ajtai_matrix = read_ring_matrix(bytes, &mut pos)?;
        let r1cs_matrices_digest = read_digest(bytes, &mut pos)?;
        let r1cs_matrices = read_r1cs_matrices(bytes, &mut pos)?;
        let input_bound = read_u64(bytes, &mut pos)?;
        let family_count = read_usize(bytes, &mut pos)?;
        let mut constraint_families = Vec::with_capacity(family_count);
        for _ in 0..family_count {
            let Some(&code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            constraint_families.push(
                semantic_constraint_family_from_code(code)
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
            );
        }
        if pos != bytes.len() {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let oracle_layout = shape.product_oracle_layout();
        if byte_len != oracle_layout.byte_len
            || packed_field_len != oracle_layout.packed_field_len
            || ajtai_matrix.len() != shape.accumulator_shape.commitment_kappa
            || ajtai_matrix
                .iter()
                .any(|row| row.len() != shape.accumulator_shape.r1cs_num_variables)
            || r1cs_matrices.num_constraints != shape.accumulator_shape.r1cs_num_constraints
            || r1cs_matrices.num_variables != shape.accumulator_shape.r1cs_num_variables
            || r1cs_matrices.num_public != shape.accumulator_shape.r1cs_num_public
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        Ok(Self {
            shape,
            oracle_layout,
            ajtai_params_digest,
            ajtai_matrix,
            r1cs_matrices_digest,
            r1cs_matrices,
            input_bound,
            constraint_families,
        })
    }

    #[must_use]
    pub fn supported_constraint_blocks(&self) -> Vec<BatchedCpSemanticConstraintBlock> {
        self.supported_constraint_blocks_for_statement(None)
    }

    #[must_use]
    pub fn supported_constraint_blocks_for_statement(
        &self,
        statement: Option<&BatchedCpPublicStatement>,
    ) -> Vec<BatchedCpSemanticConstraintBlock> {
        let mut blocks = Vec::new();
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                label: "fs-commitment-body-message-opening-byte-equality",
                constraints: self
                    .shape
                    .fs_commitment_body_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .chain(
                        self.shape
                            .poseidon_fs_commitment_r1cs_constraints()
                            .into_iter()
                            .map(BatchedCpSemanticConstraint::PoseidonR1csRow),
                    )
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::RoundMessageBinding)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::RoundMessageBinding,
                label: "round-message-oracle-to-digest-body-byte-equality",
                constraints: self
                    .shape
                    .structured_oracle_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ManifestMembership)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::ManifestMembership,
                label: "manifest-item-to-witness-row-byte-equality",
                constraints: self
                    .shape
                    .manifest_membership_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ChallengeDerivation)
        {
            if let Some(statement) = statement {
                let constraints = self
                    .shape
                    .challenge_derivation_packed_values_for_statement(statement)
                    .unwrap_or_default()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::PackedValue)
                    .collect();
                blocks.push(BatchedCpSemanticConstraintBlock {
                    family: BatchedCpSemanticConstraintFamily::ChallengeDerivation,
                    label: "batch-challenge-body-public-packed-values",
                    constraints,
                });
            }
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding)
        {
            if let Some(statement) = statement {
                let constraints = self
                    .shape
                    .challenge_to_beta_packed_values_for_statement(statement)
                    .unwrap_or_default()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::PackedValue)
                    .collect();
                blocks.push(BatchedCpSemanticConstraintBlock {
                    family: BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
                    label: "batch-challenge-digest-to-beta-packed-values",
                    constraints,
                });
            }
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::FoldedOutputDerivation)
        {
            let mut constraints = Vec::new();
            constraints.extend(
                self.shape
                    .folded_output_contribution_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality),
            );
            constraints.extend(
                self.shape
                    .folded_output_self_consistency_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality),
            );
            constraints.extend(
                self.shape
                    .fold_input_reconstruction_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality),
            );
            constraints.extend(
                self.shape
                    .folded_public_input_linear_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::FoldedPublicInputLinear),
            );
            constraints.extend(
                self.shape
                    .folded_commitment_ring_mul_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::FoldedCommitmentRingMul),
            );
            constraints.extend(
                self.shape
                    .folded_evaluation_ring_mul_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::FoldedEvaluationRingMul),
            );
            if let Some(statement) = statement {
                constraints.extend(
                    self.shape
                        .folded_output_packed_values_for_statement(statement)
                        .unwrap_or_default()
                        .into_iter()
                        .map(BatchedCpSemanticConstraint::PackedValue),
                );
            }
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
                label: "folded-output-accumulator-body-binding",
                constraints,
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
                label: "original-commitment-ajtai-opening-linear-equations",
                constraints: self
                    .ajtai_opening_linear_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::AjtaiOpeningLinear)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::OriginalR1csValidity)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
                label: "original-r1cs-row-hadamard-equations",
                constraints: self
                    .original_r1cs_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::OriginalR1cs)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
                label: "active-marker-consistency",
                constraints: self
                    .shape
                    .active_marker_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .collect(),
            });
        }
        blocks
    }

    #[must_use]
    pub fn ajtai_opening_linear_constraints(&self) -> Vec<BatchedCpAjtaiOpeningLinearConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.shape.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            if self.ajtai_matrix.len() != self.shape.accumulator_shape.commitment_kappa
                || self
                    .ajtai_matrix
                    .iter()
                    .any(|row| row.len() != self.shape.accumulator_shape.r1cs_num_variables)
            {
                return Vec::new();
            }

            let layout = self.shape.product_oracle_layout();
            let mut constraints = Vec::new();
            for item in 0..self.shape.active_count {
                for round in 0..self.shape.accumulator_shape.num_rounds {
                    let public_inputs = layout.fold_input_public_inputs[round][item];
                    let original_witness = layout.witness_original_witnesses[round][item];
                    if original_witness.len
                        != self.shape.accumulator_shape.original_witness_lens[round] * D * 8
                    {
                        continue;
                    }
                    for (row, matrix_row) in self.ajtai_matrix.iter().enumerate() {
                        for coeff in 0..D {
                            constraints.push(BatchedCpAjtaiOpeningLinearConstraint {
                                item,
                                round,
                                row,
                                coeff,
                                matrix_row: matrix_row.clone(),
                                public_input_offsets: (0..self
                                    .shape
                                    .accumulator_shape
                                    .r1cs_num_public)
                                    .map(|public_idx| public_inputs.offset + public_idx * 8)
                                    .collect(),
                                witness_coeff_offsets: (0..self
                                    .shape
                                    .accumulator_shape
                                    .original_witness_lens[round])
                                    .map(|witness_idx| {
                                        (0..D)
                                            .map(|witness_coeff| {
                                                original_witness.offset
                                                    + witness_idx * D * 8
                                                    + witness_coeff * 8
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                commitment_coeff_offset: layout.fold_input_commitments[round][item]
                                    .offset
                                    + 8
                                    + row * D * 8
                                    + coeff * 8,
                            });
                        }
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn original_r1cs_constraints(&self) -> Vec<BatchedCpOriginalR1csConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.shape.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            if self.r1cs_matrices.num_constraints
                != self.shape.accumulator_shape.r1cs_num_constraints
                || self.r1cs_matrices.num_variables
                    != self.shape.accumulator_shape.r1cs_num_variables
                || self.r1cs_matrices.num_public != self.shape.accumulator_shape.r1cs_num_public
            {
                return Vec::new();
            }
            let layout = self.shape.product_oracle_layout();
            let mut constraints = Vec::new();
            for item in 0..self.shape.active_count {
                for original_index in 0..self.shape.accumulator_shape.local_public_input_count {
                    let public_inputs = layout.fold_input_public_inputs[original_index][item];
                    let original_witness = layout.witness_original_witnesses[original_index][item];
                    for row in 0..self.r1cs_matrices.num_constraints {
                        for coeff in 0..D {
                            constraints.push(BatchedCpOriginalR1csConstraint {
                                item,
                                original_index,
                                row,
                                coeff,
                                a_terms: r1cs_row_terms(
                                    &self.r1cs_matrices.a,
                                    row,
                                    coeff,
                                    public_inputs,
                                    original_witness,
                                    self.r1cs_matrices.num_public,
                                ),
                                b_terms: r1cs_row_terms(
                                    &self.r1cs_matrices.b,
                                    row,
                                    coeff,
                                    public_inputs,
                                    original_witness,
                                    self.r1cs_matrices.num_public,
                                ),
                                c_terms: r1cs_row_terms(
                                    &self.r1cs_matrices.c,
                                    row,
                                    coeff,
                                    public_inputs,
                                    original_witness,
                                    self.r1cs_matrices.num_public,
                                ),
                            });
                        }
                    }
                }
            }
            constraints
        }
    }
}

impl BatchedCpBucket {
    pub fn new(
        items: Vec<BatchedCpItem>,
        whir_parameter_digest: Digest32,
    ) -> Result<Self, BatchedCpError> {
        if items.is_empty() {
            return Err(BatchedCpError::EmptyBatch);
        }
        let mut tags = BTreeSet::new();
        for item in &items {
            if !tags.insert(item.item_tag) {
                return Err(BatchedCpError::DuplicateItemTag);
            }
        }
        let first_shape = CpAccumulatorShape::from_item(
            &items[0].public,
            &items[0].witness,
            whir_parameter_digest,
        )?;
        for item in &items[1..] {
            let shape =
                CpAccumulatorShape::from_item(&item.public, &item.witness, whir_parameter_digest)?;
            if shape != first_shape {
                return Err(BatchedCpError::ShapeMismatch);
            }
        }
        let shape = BatchedCpStatementShape::new(first_shape, items.len())?;
        Ok(Self { shape, items })
    }

    #[must_use]
    pub fn manifest(&self) -> BatchManifest {
        let body = encode_manifest_body(&self.shape, &self.items);
        let digest = digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-manifest",
            &body,
        );
        BatchManifest { digest, body }
    }

    #[must_use]
    pub fn round_message_commitments(&self) -> BatchRoundMessageCommitments {
        let commitments = (0..self.shape.accumulator_shape.num_rounds)
            .map(|round| {
                let body = encode_round_message_body(&self.shape, &self.items, round);
                digest_domain_with_scheme(
                    self.shape.accumulator_shape.digest_scheme,
                    b"batched-cp-round-message",
                    &body,
                )
            })
            .collect();
        BatchRoundMessageCommitments { commitments }
    }

    #[must_use]
    pub fn public_statement(&self) -> BatchedCpPublicStatement {
        let manifest = self.manifest();
        let round_commitments = self.round_message_commitments();
        let challenge_digest =
            derive_batch_challenge_digest(&self.shape, manifest.digest, &round_commitments);
        let folded_output_accumulator_root = digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-folded-output-accumulator-root",
            &encode_folded_output_accumulator_body(&self.items),
        );
        BatchedCpPublicStatement {
            shape: self.shape.clone(),
            manifest_digest: manifest.digest,
            round_message_commitments: round_commitments.commitments,
            batch_challenge_digest: challenge_digest,
            folded_output_accumulator_root,
            whir_parameter_digest: self.shape.accumulator_shape.whir_parameter_digest,
        }
    }

    #[must_use]
    pub fn symbt3_public_statement_for_relation(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> BatchedCpSymbt3PublicStatement {
        let witness = self.witness_bundle();
        let message_oracle_roots: Vec<Digest32> = witness
            .round_message_oracles
            .iter()
            .enumerate()
            .map(|(round, rows)| {
                symbt3_message_oracle_root(
                    self.shape.accumulator_shape.digest_scheme,
                    &self.shape,
                    round,
                    rows,
                )
            })
            .collect();
        let folded_output_accumulator_root = digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-folded-output-accumulator-root",
            &encode_folded_output_accumulator_body(&self.items),
        );
        let input_public_values = self
            .items
            .iter()
            .map(|item| flatten_symbt3_public_inputs(&item.public.public_inputs))
            .collect::<Vec<_>>();
        let input_commitment_values = self
            .items
            .iter()
            .map(|item| flatten_symbt3_commitment(&item.public.instance.x_folded.commitment))
            .collect::<Vec<_>>();
        let input_evaluation_values = self
            .items
            .iter()
            .map(|item| {
                flatten_symbt3_evaluations(&item.public.instance.x_folded.evaluation_values)
            })
            .collect::<Vec<_>>();
        let input_accumulator_values = input_public_values
            .iter()
            .zip(input_commitment_values.iter())
            .zip(input_evaluation_values.iter())
            .map(|((public, commitment), evaluation)| {
                let mut out = Vec::with_capacity(relation.symbt3_accumulator_coordinate_len());
                out.extend_from_slice(public);
                out.extend_from_slice(commitment);
                out.extend_from_slice(evaluation);
                out
            })
            .collect::<Vec<_>>();
        let source_ajtai_opening_values = self
            .items
            .iter()
            .map(flatten_symbt3_full_ajtai_opening)
            .collect::<Vec<_>>();
        let source_r1cs_assignment_values = self
            .items
            .iter()
            .flat_map(|item| {
                (0..relation.shape.accumulator_shape.local_public_input_count).map(
                    move |original_index| {
                        flatten_symbt3_source_r1cs_assignment(item, original_index, relation)
                    },
                )
            })
            .collect::<Vec<_>>();
        let source_assignment_roots = source_r1cs_assignment_values
            .iter()
            .map(|row| {
                symbt3_source_assignment_root(
                    self.shape.accumulator_shape.digest_scheme,
                    relation,
                    row,
                )
            })
            .collect::<Vec<_>>();
        let source_ajtai_opening_roots = source_ajtai_opening_values
            .iter()
            .map(|row| {
                symbt3_ajtai_opening_root(
                    self.shape.accumulator_shape.digest_scheme,
                    &relation.ring_module_layout,
                    row,
                )
            })
            .collect::<Vec<_>>();
        let input_public_boundary_digest = symbt3_input_public_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            &input_public_values,
            &input_commitment_values,
            &input_evaluation_values,
            &input_accumulator_values,
        );
        let source_ajtai_commitment_boundary_digest =
            symbt3_source_ajtai_commitment_boundary_digest(
                self.shape.accumulator_shape.digest_scheme,
                &input_commitment_values,
            );
        let source_assignment_boundary_digest = symbt3_source_assignment_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &source_assignment_roots,
        );
        let manifest_rows = symbt3_manifest_rows_from_statement_parts(
            relation,
            &input_public_values,
            &input_commitment_values,
            &input_evaluation_values,
            &input_accumulator_values,
            &source_assignment_roots,
            &message_oracle_roots,
        );
        let manifest_oracle_root = symbt3_manifest_oracle_root_from_rows(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &manifest_rows,
        );
        let batch_manifest_layout_digest = relation
            .batch_manifest_layout
            .digest(self.shape.accumulator_shape.digest_scheme);
        let batch_manifest_root = symbt3_batch_manifest_root_from_oracle_root(
            self.shape.accumulator_shape.digest_scheme,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            &batch_manifest_layout_digest,
            &manifest_oracle_root,
        );
        let folded_gr1cs_boundary_digest = symbt3_folded_gr1cs_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &input_evaluation_values,
            &vec![0; relation.symbt3_evaluation_coordinate_len()],
        );
        let old_accumulator_coordinates = vec![0; relation.symbt3_accumulator_coordinate_len()];
        let mut public = BatchedCpSymbt3PublicStatement {
            shape_id: self.shape.shape_id,
            batch_capacity: self.shape.batch_capacity,
            active_count: self.shape.active_count,
            old_accumulator_digest: symbt3_accumulator_coordinates_digest(
                self.shape.accumulator_shape.digest_scheme,
                b"old",
                &old_accumulator_coordinates,
            ),
            new_accumulator_digest: [0u8; 32],
            old_accumulator_coordinates,
            new_accumulator_coordinates: vec![0; relation.symbt3_accumulator_coordinate_len()],
            input_public_boundary_digest,
            batch_manifest_root,
            manifest_oracle_root,
            manifest_eval_claim: 0,
            batch_manifest_layout_digest,
            source_column_layout_digest: relation
                .batch_manifest_layout
                .source_column_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            message_semantic_layout_digest: relation
                .message_semantic_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            production_norm_range_layout_digest: relation
                .ajtai_norm_range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            structured_projection_layout_digest: relation
                .ajtai_norm_range_layout
                .projection_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            monomial_embedding_layout_digest: relation
                .ajtai_norm_range_layout
                .monomial_embedding_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            representative_layout_digest: relation
                .ajtai_norm_range_layout
                .representative_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            norm_range_public_digest: [0u8; 32],
            input_public_values,
            input_commitment_values,
            input_evaluation_values,
            input_accumulator_values,
            source_assignment_roots,
            source_assignment_boundary_digest,
            source_ajtai_opening_roots,
            source_ajtai_commitment_boundary_digest,
            message_oracle_roots,
            folded_public_input: vec![0; relation.symbt3_public_input_coordinate_len()],
            folded_commitment: vec![0; relation.symbt3_commitment_coordinate_len()],
            folded_evaluation: vec![0; relation.symbt3_evaluation_coordinate_len()],
            folded_accumulator_coordinates: vec![0; relation.symbt3_accumulator_coordinate_len()],
            folded_ajtai_opening_root: [0u8; 32],
            folded_ajtai_commitment: vec![0; relation.symbt3_commitment_coordinate_len()],
            folded_gr1cs_boundary_digest,
            ring_module_layout_digest: relation
                .ring_module_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            ajtai_commit_layout_digest: relation
                .ajtai_commit_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            r1cs_evaluator_layout_digest: relation
                .r1cs_evaluator_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            gr1cs_residual_layout_digest: relation
                .gr1cs_residual_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            algebra_law_digest: relation
                .algebra_law
                .digest(self.shape.accumulator_shape.digest_scheme),
            ajtai_linear_algebra_layout_digest: relation
                .ajtai_linear_algebra_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            ajtai_norm_range_layout_digest: relation
                .ajtai_norm_range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            projection_layout_digest: relation
                .ajtai_norm_range_layout
                .projection_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            range_layout_digest: relation
                .ajtai_norm_range_layout
                .range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            folded_gr1cs_product_residual_layout_digest: relation
                .folded_gr1cs_product_residual_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            folded_output_accumulator_root,
            whir_parameter_digest: self.shape.accumulator_shape.whir_parameter_digest,
        };
        public.folded_public_input = relation.derive_folded_public_input_boundary(&public);
        public.folded_commitment = relation.derive_ring_folded_commitment_boundary(&public);
        public.folded_evaluation = relation.derive_folded_evaluation_boundary(&public);
        public.folded_accumulator_coordinates =
            relation.derive_folded_accumulator_boundary(&public);
        public.new_accumulator_coordinates =
            symbt3_accumulator_transition_coordinates(relation, &public)
                .expect("well-formed SYMBT3 accumulator transition");
        public.new_accumulator_digest = symbt3_accumulator_coordinates_digest(
            self.shape.accumulator_shape.digest_scheme,
            b"new",
            &public.new_accumulator_coordinates,
        );
        public.folded_gr1cs_boundary_digest = symbt3_folded_gr1cs_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &public.input_evaluation_values,
            &public.folded_evaluation,
        );
        let folded_opening =
            relation.derive_ring_folded_opening_boundary(&public, &source_ajtai_opening_values);
        public.folded_ajtai_opening_root = symbt3_ajtai_opening_root(
            self.shape.accumulator_shape.digest_scheme,
            &relation.ring_module_layout,
            &folded_opening,
        );
        public.norm_range_public_digest = symbt3_norm_range_public_digest(
            self.shape.accumulator_shape.digest_scheme,
            &public.folded_ajtai_opening_root,
            &public.production_norm_range_layout_digest,
            &public.structured_projection_layout_digest,
            &public.monomial_embedding_layout_digest,
            &public.representative_layout_digest,
        );
        public.folded_ajtai_commitment = public.folded_commitment.clone();
        public.manifest_eval_claim = 0;
        public
    }

    #[must_use]
    pub fn symbt3_witness_for_relation(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> BatchedCpSymbt3Witness {
        let mut witness = BatchedCpSymbt3Witness::from_batched_witness(&self.witness_bundle());
        witness.source_ajtai_opening_values = self
            .items
            .iter()
            .map(flatten_symbt3_full_ajtai_opening)
            .collect::<Vec<_>>();
        witness.source_r1cs_assignment_values = self
            .items
            .iter()
            .flat_map(|item| {
                (0..relation.shape.accumulator_shape.local_public_input_count).map(
                    move |original_index| {
                        flatten_symbt3_source_r1cs_assignment(item, original_index, relation)
                    },
                )
            })
            .collect::<Vec<_>>();
        let public = self.symbt3_public_statement_for_relation(relation);
        witness.folded_ajtai_opening_values = relation
            .derive_ring_folded_opening_boundary(&public, &witness.source_ajtai_opening_values);
        witness
    }

    #[must_use]
    pub fn witness_bundle(&self) -> BatchedCpWitnessBundle {
        let witness_oracle_rows = (0..self.shape.batch_capacity)
            .map(|idx| {
                self.items
                    .get(idx)
                    .map(encode_witness_row)
                    .unwrap_or_default()
            })
            .collect();
        let round_message_oracles = (0..self.shape.accumulator_shape.num_rounds)
            .map(|round| {
                (0..self.shape.batch_capacity)
                    .map(|idx| {
                        self.items
                            .get(idx)
                            .map(|item| item.witness.fs_messages[round].clone())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .collect();
        BatchedCpWitnessBundle {
            items: self.items.clone(),
            witness_oracle_rows,
            round_message_oracles,
        }
    }
}

impl BatchedCpEvaluator {
    pub fn check(
        public: &BatchedCpPublicStatement,
        witness: &BatchedCpWitnessBundle,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> Result<(), BatchedCpError> {
        let bucket = BatchedCpBucket::new(witness.items.clone(), public.whir_parameter_digest)?;
        if bucket.shape != public.shape {
            return Err(BatchedCpError::ShapeMismatch);
        }
        let expected_witness = bucket.witness_bundle();
        if expected_witness.witness_oracle_rows != witness.witness_oracle_rows {
            return Err(BatchedCpError::WitnessOracleMismatch);
        }
        if expected_witness.round_message_oracles != witness.round_message_oracles {
            return Err(BatchedCpError::RoundMessageOracleMismatch);
        }
        if bucket.manifest().digest != public.manifest_digest {
            return Err(BatchedCpError::ManifestMismatch);
        }
        if bucket.round_message_commitments().commitments != public.round_message_commitments {
            return Err(BatchedCpError::RoundMessageCommitmentMismatch);
        }
        let expected_challenge_digest = derive_batch_challenge_digest(
            &public.shape,
            public.manifest_digest,
            &BatchRoundMessageCommitments {
                commitments: public.round_message_commitments.clone(),
            },
        );
        if expected_challenge_digest != public.batch_challenge_digest {
            return Err(BatchedCpError::ChallengeDigestMismatch);
        }
        let expected_output_root = digest_domain_with_scheme(
            public.shape.accumulator_shape.digest_scheme,
            b"batched-cp-folded-output-accumulator-root",
            &encode_folded_output_accumulator_body(&witness.items),
        );
        if expected_output_root != public.folded_output_accumulator_root {
            return Err(BatchedCpError::ManifestMismatch);
        }
        for (idx, item) in witness.items.iter().enumerate() {
            CpFieldRelation::check(&item.public, &item.witness, ajtai, r1cs, input_bound)
                .map_err(|err| BatchedCpError::ItemRelationFailed(idx, err))?;
        }
        Ok(())
    }
}

impl BatchedCpWitnessBundle {
    pub fn canonical_product_oracle_bytes(
        &self,
        shape: &BatchedCpStatementShape,
    ) -> Result<Vec<u8>, BatchedCpError> {
        validate_product_oracle_layout(self, shape)?;
        let mut out = Vec::with_capacity(shape.canonical_product_oracle_byte_len());
        push_bytes(&mut out, b"symphony-batched-cp-product-oracle-v1");
        encode_statement_shape(&mut out, shape);
        push_usize(&mut out, shape.batch_capacity);
        for idx in 0..shape.batch_capacity {
            push_usize(&mut out, idx);
            out.push(u8::from(idx < shape.active_count));
            push_bytes(&mut out, &self.witness_oracle_rows[idx]);
        }
        push_usize(&mut out, shape.round_message_lens.len());
        for (round, rows) in self.round_message_oracles.iter().enumerate() {
            push_usize(&mut out, round);
            push_usize(&mut out, shape.batch_capacity);
            for (idx, message) in rows.iter().enumerate() {
                push_usize(&mut out, idx);
                out.push(u8::from(idx < shape.active_count));
                push_bytes(&mut out, message);
            }
        }
        push_usize(&mut out, shape.round_message_lens.len());
        for (round, rows) in self.round_message_oracles.iter().enumerate() {
            push_bytes(&mut out, b"symphony-batched-cp-round-message-v1");
            out.extend_from_slice(&shape.shape_id);
            push_usize(&mut out, round);
            push_usize(&mut out, shape.batch_capacity);
            for (idx, message) in rows.iter().enumerate() {
                push_usize(&mut out, idx);
                out.push(u8::from(idx < shape.active_count));
                push_bytes(&mut out, message);
            }
        }
        out.extend_from_slice(&encode_manifest_body(shape, &self.items));
        out.extend_from_slice(&encode_fs_commitment_bodies_body(shape, &self.items));
        out.extend_from_slice(&encode_poseidon_fs_commitment_traces_body(
            shape,
            &self.items,
        ));
        let bucket = BatchedCpBucket::new(
            self.items.clone(),
            shape.accumulator_shape.whir_parameter_digest,
        )?;
        let round_commitments = bucket.round_message_commitments();
        out.extend_from_slice(&encode_batch_challenge_body(
            shape,
            bucket.manifest().digest,
            &round_commitments,
        ));
        let public = bucket.public_statement();
        out.extend_from_slice(&encode_challenge_to_beta_body(
            shape,
            public.batch_challenge_digest,
        ));
        out.extend_from_slice(&encode_fold_input_reconstruction_body(shape, &self.items));
        out.extend_from_slice(&encode_folded_output_accumulator_oracle_body(
            shape,
            public.folded_output_accumulator_root,
            &self.items,
        ));
        Ok(out)
    }
}

impl BatchedCpSemanticTraceV2 {
    pub fn encode(
        relation: &BatchedCpSemanticColumnarV2Description,
        statement: &BatchedCpPublicStatement,
        witness: &BatchedCpWitnessBundle,
    ) -> Result<Self, BatchedCpError> {
        let oracle = witness.canonical_product_oracle_bytes(&relation.semantic.shape)?;
        let layout = relation.columnar_layout.clone();
        let mut columns = vec![vec![0u32; layout.column_row_count]; layout.columns.len()];
        for residual in &layout.residuals {
            match residual.family {
                BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy
                | BatchedCpSemanticConstraintFamily::ManifestMembership
                | BatchedCpSemanticConstraintFamily::RoundMessageBinding => {
                    let equalities =
                        columnar_equalities_for_family(&relation.semantic.shape, residual.family);
                    if equalities.len() != residual.row_count {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    for (row, equality) in equalities.iter().enumerate() {
                        let left = *oracle
                            .get(equality.left_offset)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?
                            as u32;
                        let right = *oracle
                            .get(equality.right_offset)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?
                            as u32;
                        columns[residual.left_column][row] = left;
                        columns[residual.right_column][row] = right;
                    }
                }
                BatchedCpSemanticConstraintFamily::ChallengeDerivation
                | BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding => {
                    let packed_values = columnar_packed_values_for_family(
                        &relation.semantic.shape,
                        statement,
                        residual.family,
                    )
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
                    if packed_values.len() != residual.row_count {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    for (row, value) in packed_values.iter().enumerate() {
                        columns[residual.left_column][row] =
                            packed_oracle_value_at(&oracle, value.packed_index)
                                .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                        columns[residual.right_column][row] = value.value;
                    }
                }
                BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness => {
                    fill_columnar_poseidon_residual(relation, &oracle, residual, &mut columns)?;
                }
                BatchedCpSemanticConstraintFamily::FoldedOutputDerivation => {
                    fill_columnar_folded_output_residual(
                        relation,
                        &oracle,
                        residual,
                        &mut columns,
                    )?;
                }
                BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity => {
                    let constraints = relation.semantic.ajtai_opening_linear_constraints();
                    if constraints.len() != residual.row_count {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    for (row, constraint) in constraints.iter().enumerate() {
                        let (left, right) = columnar_ajtai_opening_eval(constraint, &oracle)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                        columns[residual.left_column][row] = left;
                        columns[residual.right_column][row] = right;
                    }
                }
                BatchedCpSemanticConstraintFamily::OriginalR1csValidity => {
                    let constraints = relation.semantic.original_r1cs_constraints();
                    if constraints.len() != residual.row_count || residual.aux_columns.len() != 1 {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    let aux_column = residual.aux_columns[0];
                    for (row, constraint) in constraints.iter().enumerate() {
                        let (a, b, c) = columnar_original_r1cs_eval(constraint, &oracle)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                        columns[residual.left_column][row] = a;
                        columns[aux_column][row] = b;
                        columns[residual.right_column][row] = c;
                    }
                }
            }
        }
        Ok(Self { layout, columns })
    }

    #[must_use]
    pub fn flattened_values(&self) -> Vec<u32> {
        let mut out = Vec::with_capacity(self.columns.len() * self.layout.column_row_count);
        for column in &self.columns {
            out.extend_from_slice(column);
        }
        out
    }

    #[must_use]
    pub fn cell_index(&self, column: usize, row: usize) -> Option<usize> {
        if column >= self.columns.len() || row >= self.layout.column_row_count {
            return None;
        }
        Some(column * self.layout.column_row_count + row)
    }

    #[must_use]
    pub fn residual_value(&self, residual_idx: usize, row: usize) -> Option<i64> {
        let residual = self.layout.residuals.get(residual_idx)?;
        if row >= residual.row_count {
            return None;
        }
        let left = *self.columns.get(residual.left_column)?.get(row)? as i64;
        let right = *self.columns.get(residual.right_column)?.get(row)? as i64;
        let satisfied = match residual.kind {
            BatchedCpSemanticResidualV2Kind::Equality => left == right,
            BatchedCpSemanticResidualV2Kind::Product => {
                let aux_column = *residual.aux_columns.first()?;
                let aux = *self.columns.get(aux_column)?.get(row)?;
                bb_mul_u32(left as u32, aux) == right as u32
            }
        };
        Some(if satisfied { 0 } else { 1 })
    }

    #[must_use]
    pub fn all_residuals_satisfied(&self) -> bool {
        self.layout
            .residuals
            .iter()
            .enumerate()
            .all(|(idx, residual)| {
                (0..residual.row_count).all(|row| self.residual_value(idx, row) == Some(0))
            })
    }
}

impl BatchedCpSemanticFamilyTraceV2 {
    pub fn encode(
        relation: &BatchedCpSemanticFamilyColumnarV2Description,
        statement: &BatchedCpPublicStatement,
        witness: &BatchedCpWitnessBundle,
    ) -> Result<Self, BatchedCpError> {
        let oracle = witness.canonical_product_oracle_bytes(&relation.semantic.shape)?;
        let specs = family_columnar_v2_table_specs(&relation.semantic);
        if specs.len() != relation.family_layout.tables.len() {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut tables = Vec::with_capacity(relation.family_layout.tables.len());
        for (table, spec) in relation.family_layout.tables.iter().zip(specs.iter()) {
            if table.family != spec.family
                || table.kind != spec.kind
                || table.label != spec.label
                || table.transcript_label != spec.transcript_label
                || table.column_kinds != spec.column_kinds
                || table.column_labels != spec.column_labels
                || table.row_count != spec.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            tables.push(fill_family_columnar_v2_table(
                &relation.semantic,
                statement,
                &oracle,
                table,
                spec,
            )?);
        }
        Ok(Self {
            layout: relation.family_layout.clone(),
            tables,
        })
    }

    #[must_use]
    pub fn flattened_values(&self) -> Vec<u32> {
        let mut out = vec![0u32; self.layout.total_field_len];
        for (table, columns) in self.layout.tables.iter().zip(&self.tables) {
            for (column_idx, column) in columns.iter().enumerate() {
                let start = table.table_offset + column_idx * table.padded_row_count;
                out[start..start + table.padded_row_count].copy_from_slice(column);
            }
        }
        out
    }

    #[must_use]
    pub fn cell_index(&self, table_idx: usize, column: usize, row: usize) -> Option<usize> {
        let table = self.layout.tables.get(table_idx)?;
        if column >= table.column_kinds.len() || row >= table.padded_row_count {
            return None;
        }
        Some(table.table_offset + column * table.padded_row_count + row)
    }

    #[must_use]
    pub fn residual_value(&self, table_idx: usize, row: usize) -> Option<i64> {
        let table = self.layout.tables.get(table_idx)?;
        if row >= table.row_count {
            return None;
        }
        let columns = self.tables.get(table_idx)?;
        let left = *columns.first()?.get(row)? as i64;
        let right = *columns.last()?.get(row)? as i64;
        let satisfied = match table.kind {
            BatchedCpSemanticResidualV2Kind::Equality => left == right,
            BatchedCpSemanticResidualV2Kind::Product => {
                let aux = *columns.get(1)?.get(row)?;
                bb_mul_u32(left as u32, aux) == right as u32
            }
        };
        Some(if satisfied { 0 } else { 1 })
    }

    #[must_use]
    pub fn all_residuals_satisfied(&self) -> bool {
        self.layout
            .tables
            .iter()
            .enumerate()
            .all(|(table_idx, table)| {
                (0..table.row_count).all(|row| self.residual_value(table_idx, row) == Some(0))
            })
    }
}

fn columnar_equalities_for_family(
    shape: &BatchedCpStatementShape,
    family: BatchedCpSemanticConstraintFamily,
) -> Vec<BatchedCpOracleByteEquality> {
    match family {
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy => {
            shape.active_marker_byte_equalities()
        }
        BatchedCpSemanticConstraintFamily::ManifestMembership => {
            shape.manifest_membership_byte_equalities()
        }
        BatchedCpSemanticConstraintFamily::RoundMessageBinding => {
            shape.structured_oracle_byte_equalities()
        }
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness
        | BatchedCpSemanticConstraintFamily::ChallengeDerivation
        | BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding
        | BatchedCpSemanticConstraintFamily::FoldedOutputDerivation
        | BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity
        | BatchedCpSemanticConstraintFamily::OriginalR1csValidity => Vec::new(),
    }
}

fn round_message_digest_body_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.round_message_rows.len() || round >= layout.round_message_digest_bodies.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.round_message_rows[round][idx],
            layout.round_message_digest_bodies[round][idx],
            section,
        );
    }
    equalities
}

fn round_message_witness_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.witness_fs_messages.len() || round >= layout.round_message_rows.len() {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.witness_fs_messages[round][idx],
            layout.round_message_rows[round][idx],
            section,
        );
    }
    equalities
}

fn fold_input_commitment_reconstruction_equalities(
    shape: &BatchedCpStatementShape,
    round: usize,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.fold_input_commitments.len()
        || round >= layout.witness_fold_input_commitments.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_range_equalities(
            &mut equalities,
            layout.fold_input_commitments[round][idx],
            layout.witness_fold_input_commitments[round][idx],
        );
    }
    equalities
}

fn fold_input_public_input_reconstruction_equalities(
    shape: &BatchedCpStatementShape,
    round: usize,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.fold_input_public_inputs.len()
        || round >= layout.witness_fold_input_public_inputs.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_range_equalities(
            &mut equalities,
            layout.fold_input_public_inputs[round][idx],
            layout.witness_fold_input_public_inputs[round][idx],
        );
    }
    equalities
}

fn fold_input_eval_message_reconstruction_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.fold_input_eval_messages.len()
        || round >= layout.witness_fold_input_eval_messages.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.fold_input_eval_messages[round][idx],
            layout.witness_fold_input_eval_messages[round][idx],
            section,
        );
    }
    equalities
}

fn fold_input_round_message_reconstruction_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.witness_fold_input_eval_messages.len()
        || round >= layout.round_message_rows.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.witness_fold_input_eval_messages[round][idx],
            layout.round_message_rows[round][idx],
            section,
        );
    }
    equalities
}

fn push_section_range_equalities(
    equalities: &mut Vec<BatchedCpOracleByteEquality>,
    left: BatchedCpOracleByteRange,
    right: BatchedCpOracleByteRange,
    section: &BatchedCpGr1csMessageSection,
) {
    let Some(section_end) = section.offset.checked_add(section.len) else {
        return;
    };
    if section_end > left.len || section_end > right.len {
        return;
    }
    for offset in 0..section.len {
        equalities.push(BatchedCpOracleByteEquality {
            left_offset: left.offset + section.offset + offset,
            right_offset: right.offset + section.offset + offset,
        });
    }
}

fn columnar_packed_values_for_family(
    shape: &BatchedCpStatementShape,
    statement: &BatchedCpPublicStatement,
    family: BatchedCpSemanticConstraintFamily,
) -> Option<Vec<BatchedCpOraclePackedValue>> {
    match family {
        BatchedCpSemanticConstraintFamily::ChallengeDerivation => {
            shape.challenge_derivation_packed_values_for_statement(statement)
        }
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding => {
            shape.challenge_to_beta_packed_values_for_statement(statement)
        }
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness
        | BatchedCpSemanticConstraintFamily::ManifestMembership
        | BatchedCpSemanticConstraintFamily::RoundMessageBinding
        | BatchedCpSemanticConstraintFamily::FoldedOutputDerivation
        | BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity
        | BatchedCpSemanticConstraintFamily::OriginalR1csValidity
        | BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy => Some(Vec::new()),
    }
}

fn fill_family_columnar_v2_table(
    semantic: &BatchedCpSemanticRelationDescription,
    statement: &BatchedCpPublicStatement,
    oracle: &[u8],
    table: &BatchedCpSemanticFamilyColumnarV2Table,
    spec: &BatchedCpFamilyColumnarV2TableSpec,
) -> Result<Vec<Vec<u32>>, BatchedCpError> {
    let mut columns = vec![vec![0u32; table.padded_row_count]; table.column_kinds.len()];
    match &spec.source {
        BatchedCpFamilyColumnarV2TableSource::Equality(equalities) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || equalities.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            fill_family_equality_columns(oracle, equalities, &mut columns)?;
        }
        BatchedCpFamilyColumnarV2TableSource::PackedValue(family) => {
            let packed_values =
                columnar_packed_values_for_family(&semantic.shape, statement, *family)
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || packed_values.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, value) in packed_values.iter().enumerate() {
                columns[0][row] = packed_oracle_value_at(oracle, value.packed_index)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[1][row] = value.value;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::PoseidonR1cs(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Product
                || table.column_kinds.len() != 3
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            fill_family_poseidon_columns(constraints, oracle, &mut columns)?;
        }
        BatchedCpFamilyColumnarV2TableSource::FoldedPublicInputLinear(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_folded_public_input_linear_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::FoldedCommitmentRingMul(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_folded_commitment_ring_mul_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::FoldedEvaluationRingMul(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_folded_evaluation_ring_mul_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::AjtaiOpeningLinear(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_ajtai_opening_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::OriginalR1cs(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Product
                || table.column_kinds.len() != 3
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (a, b, c) = columnar_original_r1cs_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = a;
                columns[1][row] = b;
                columns[2][row] = c;
            }
        }
    }
    Ok(columns)
}

fn fill_family_equality_columns(
    oracle: &[u8],
    equalities: &[BatchedCpOracleByteEquality],
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    for (row, equality) in equalities.iter().enumerate() {
        columns[0][row] = *oracle
            .get(equality.left_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)? as u32;
        columns[1][row] = *oracle
            .get(equality.right_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)? as u32;
    }
    Ok(())
}

#[cfg(feature = "whir")]
fn fill_family_poseidon_columns(
    constraints: &[BatchedCpPoseidonR1csRowConstraint],
    oracle: &[u8],
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    let mut cached_input_len = None;
    let mut cached_r1cs = None;
    for (row, constraint) in constraints.iter().enumerate() {
        if cached_input_len != Some(constraint.input_len) {
            cached_input_len = Some(constraint.input_len);
            cached_r1cs = Some(
                crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
                    b"fs-commit",
                    constraint.input_len,
                ),
            );
        }
        let (r1cs, poseidon_layout) = cached_r1cs
            .as_ref()
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        if constraint.row >= r1cs.num_constraints {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        columns[0][row] = columnar_poseidon_lc_eval(&r1cs.a, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[1][row] = columnar_poseidon_lc_eval(&r1cs.b, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[2][row] = columnar_poseidon_lc_eval(&r1cs.c, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
    }
    Ok(())
}

#[cfg(not(feature = "whir"))]
fn fill_family_poseidon_columns(
    constraints: &[BatchedCpPoseidonR1csRowConstraint],
    _oracle: &[u8],
    _columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    if constraints.is_empty() {
        Ok(())
    } else {
        Err(BatchedCpError::InvalidSemanticRelationContext)
    }
}

fn packed_oracle_value_at(bytes: &[u8], packed_index: usize) -> Option<u32> {
    let start = packed_index.checked_mul(3)?;
    if start >= bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for (idx, &byte) in bytes[start..bytes.len().min(start + 3)].iter().enumerate() {
        value |= (byte as u32) << (8 * idx);
    }
    Some(value)
}

fn fill_columnar_folded_output_residual(
    relation: &BatchedCpSemanticColumnarV2Description,
    oracle: &[u8],
    residual: &BatchedCpSemanticResidualV2,
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    let mut row = 0usize;
    for equality in relation
        .semantic
        .shape
        .folded_output_contribution_byte_equalities()
        .into_iter()
        .chain(
            relation
                .semantic
                .shape
                .folded_output_self_consistency_byte_equalities(),
        )
        .chain(
            relation
                .semantic
                .shape
                .fold_input_reconstruction_byte_equalities(),
        )
    {
        columns[residual.left_column][row] = *oracle
            .get(equality.left_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?
            as u32;
        columns[residual.right_column][row] = *oracle
            .get(equality.right_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?
            as u32;
        row += 1;
    }
    for constraint in relation
        .semantic
        .shape
        .folded_public_input_linear_constraints()
    {
        let (left, right) = columnar_folded_public_input_linear_eval(&constraint, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = left;
        columns[residual.right_column][row] = right;
        row += 1;
    }
    for constraint in relation
        .semantic
        .shape
        .folded_commitment_ring_mul_constraints()
    {
        let (left, right) = columnar_folded_commitment_ring_mul_eval(&constraint, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = left;
        columns[residual.right_column][row] = right;
        row += 1;
    }
    for constraint in relation
        .semantic
        .shape
        .folded_evaluation_ring_mul_constraints()
    {
        let (left, right) = columnar_folded_evaluation_ring_mul_eval(&constraint, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = left;
        columns[residual.right_column][row] = right;
        row += 1;
    }
    if row != residual.row_count {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    Ok(())
}

#[cfg(feature = "whir")]
fn fill_columnar_poseidon_residual(
    relation: &BatchedCpSemanticColumnarV2Description,
    oracle: &[u8],
    residual: &BatchedCpSemanticResidualV2,
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    let constraints = relation
        .semantic
        .shape
        .poseidon_fs_commitment_r1cs_constraints();
    if constraints.len() != residual.row_count || residual.aux_columns.len() != 1 {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    let aux_column = residual.aux_columns[0];
    let mut cached_input_len = None;
    let mut cached_r1cs = None;
    for (row, constraint) in constraints.iter().enumerate() {
        if cached_input_len != Some(constraint.input_len) {
            cached_input_len = Some(constraint.input_len);
            cached_r1cs = Some(
                crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
                    b"fs-commit",
                    constraint.input_len,
                ),
            );
        }
        let (r1cs, poseidon_layout) = cached_r1cs
            .as_ref()
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        if constraint.row >= r1cs.num_constraints {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let a = columnar_poseidon_lc_eval(&r1cs.a, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        let b = columnar_poseidon_lc_eval(&r1cs.b, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        let c = columnar_poseidon_lc_eval(&r1cs.c, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = a;
        columns[aux_column][row] = b;
        columns[residual.right_column][row] = c;
    }
    Ok(())
}

#[cfg(not(feature = "whir"))]
fn fill_columnar_poseidon_residual(
    _relation: &BatchedCpSemanticColumnarV2Description,
    _oracle: &[u8],
    residual: &BatchedCpSemanticResidualV2,
    _columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    if residual.row_count == 0 {
        Ok(())
    } else {
        Err(BatchedCpError::InvalidSemanticRelationContext)
    }
}

fn columnar_folded_public_input_linear_eval(
    constraint: &BatchedCpFoldedPublicInputLinearConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.beta_coeff_offsets.len() != constraint.input_scalar_offsets.len() {
        return None;
    }
    let mut acc = 0u32;
    for (&beta_offset, &input_offset) in constraint
        .beta_coeff_offsets
        .iter()
        .zip(constraint.input_scalar_offsets.iter())
    {
        let beta = bb_from_i64(read_i64_at_offset(oracle, beta_offset)?);
        let input = bb_from_i64(read_i64_at_offset(oracle, input_offset)?);
        acc = bb_add_u32(acc, bb_mul_u32(beta, input));
    }
    let output = bb_from_i64(read_i64_at_offset(oracle, constraint.output_coeff_offset)?);
    Some((acc, output))
}

fn columnar_folded_commitment_ring_mul_eval(
    constraint: &BatchedCpFoldedCommitmentRingMulConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.beta_coeff_offsets.len() != constraint.commitment_coeff_offsets.len()
        || constraint.output_coeff_index >= D
    {
        return None;
    }
    let mut acc = 0u32;
    for (beta_offsets, commitment_offsets) in constraint
        .beta_coeff_offsets
        .iter()
        .zip(constraint.commitment_coeff_offsets.iter())
    {
        let beta = read_bb_ring_at_offsets(oracle, beta_offsets)?;
        let commitment = read_bb_ring_at_offsets(oracle, commitment_offsets)?;
        let product = bb_cyclotomic_mul(&beta, &commitment);
        acc = bb_add_u32(acc, product[constraint.output_coeff_index]);
    }
    let output = bb_from_i64(read_i64_at_offset(oracle, constraint.output_coeff_offset)?);
    Some((acc, output))
}

fn columnar_folded_evaluation_ring_mul_eval(
    constraint: &BatchedCpFoldedEvaluationRingMulConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.beta_coeff_offsets.len() != constraint.evaluation_coeff_offsets.len()
        || constraint.output_coeff_index >= D
    {
        return None;
    }
    let mut acc = 0u32;
    for (beta_offsets, evaluation_offsets) in constraint
        .beta_coeff_offsets
        .iter()
        .zip(constraint.evaluation_coeff_offsets.iter())
    {
        let beta = read_bb_ring_at_offsets(oracle, beta_offsets)?;
        let evaluation = read_bb_ring_at_offsets(oracle, evaluation_offsets)?;
        let product = bb_cyclotomic_mul(&beta, &evaluation);
        acc = bb_add_u32(acc, product[constraint.output_coeff_index]);
    }
    let output = bb_from_i64(read_i64_at_offset(oracle, constraint.output_coeff_offset)?);
    Some((acc, output))
}

fn columnar_ajtai_opening_eval(
    constraint: &BatchedCpAjtaiOpeningLinearConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.coeff >= D
        || constraint.matrix_row.len()
            != constraint.public_input_offsets.len() + constraint.witness_coeff_offsets.len()
    {
        return None;
    }
    let mut acc = 0u32;
    for (matrix_elem, &public_offset) in constraint
        .matrix_row
        .iter()
        .zip(constraint.public_input_offsets.iter())
    {
        let public_scalar = bb_from_i64(read_i64_at_offset(oracle, public_offset)?);
        let matrix_coeff = bb_from_i64(matrix_elem.coeffs[constraint.coeff]);
        acc = bb_add_u32(acc, bb_mul_u32(matrix_coeff, public_scalar));
    }
    for (matrix_elem, witness_offsets) in constraint
        .matrix_row
        .iter()
        .skip(constraint.public_input_offsets.len())
        .zip(constraint.witness_coeff_offsets.iter())
    {
        let witness = read_bb_ring_at_offsets(oracle, witness_offsets)?;
        let product = bb_cyclotomic_mul(&ring_element_to_bb_array(matrix_elem), &witness);
        acc = bb_add_u32(acc, product[constraint.coeff]);
    }
    let commitment = bb_from_i64(read_i64_at_offset(
        oracle,
        constraint.commitment_coeff_offset,
    )?);
    Some((acc, commitment))
}

fn columnar_original_r1cs_eval(
    constraint: &BatchedCpOriginalR1csConstraint,
    oracle: &[u8],
) -> Option<(u32, u32, u32)> {
    let a = columnar_original_r1cs_linear_eval(&constraint.a_terms, oracle)?;
    let b = columnar_original_r1cs_linear_eval(&constraint.b_terms, oracle)?;
    let c = columnar_original_r1cs_linear_eval(&constraint.c_terms, oracle)?;
    Some((a, b, c))
}

fn columnar_original_r1cs_linear_eval(terms: &[(i64, usize)], oracle: &[u8]) -> Option<u32> {
    let mut acc = 0u32;
    for &(matrix_coeff, value_offset) in terms {
        let value = bb_from_i64(read_i64_at_offset(oracle, value_offset)?);
        let coeff = bb_from_i64(matrix_coeff);
        acc = bb_add_u32(acc, bb_mul_u32(coeff, value));
    }
    Some(acc)
}

#[cfg(feature = "whir")]
fn columnar_poseidon_lc_eval(
    matrix: &crate::r1cs::SparseMatrix,
    constraint: &BatchedCpPoseidonR1csRowConstraint,
    layout: &crate::snark::cp_snark::Poseidon2PrivateDigestR1csLayout,
    oracle: &[u8],
) -> Option<u32> {
    let mut acc = 0u32;
    for &(_, col, coeff) in matrix
        .entries
        .iter()
        .filter(|&&(row, _, _)| row == constraint.row)
    {
        let value = if col == layout.off_one {
            1
        } else {
            let offset = columnar_poseidon_var_offset(constraint, layout, col)?;
            read_u32_at_offset(oracle, offset)?
        };
        acc = bb_add_u32(acc, bb_mul_u32(bb_from_i64(coeff), value));
    }
    Some(acc)
}

#[cfg(feature = "whir")]
fn columnar_poseidon_var_offset(
    constraint: &BatchedCpPoseidonR1csRowConstraint,
    layout: &crate::snark::cp_snark::Poseidon2PrivateDigestR1csLayout,
    col: usize,
) -> Option<usize> {
    if (layout.off_output..layout.off_output + 8).contains(&col) {
        return constraint
            .output_offsets
            .get(col - layout.off_output)
            .copied();
    }
    if (layout.off_input..layout.off_input + layout.input_len).contains(&col) {
        return constraint
            .input_offsets
            .get(col - layout.off_input)
            .copied();
    }
    let aux_start = layout.off_input + layout.input_len;
    if (aux_start..layout.num_variables).contains(&col) {
        return constraint.aux_offsets.get(col - aux_start).copied();
    }
    None
}

fn read_i64_at_offset(bytes: &[u8], offset: usize) -> Option<i64> {
    let end = offset.checked_add(8)?;
    let chunk = bytes.get(offset..end)?;
    Some(i64::from_le_bytes(chunk.try_into().ok()?))
}

#[cfg(feature = "whir")]
fn read_u32_at_offset(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let chunk = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn read_bb_ring_at_offsets(bytes: &[u8], offsets: &[usize]) -> Option<[u32; D]> {
    if offsets.len() != D {
        return None;
    }
    let mut out = [0u32; D];
    for (idx, &offset) in offsets.iter().enumerate() {
        out[idx] = bb_from_i64(read_i64_at_offset(bytes, offset)?);
    }
    Some(out)
}

fn ring_element_to_bb_array(value: &RingElement) -> [u32; D] {
    let mut out = [0u32; D];
    for (idx, &coeff) in value.coeffs.iter().enumerate() {
        out[idx] = bb_from_i64(coeff);
    }
    out
}

const BABYBEAR_MODULUS_U64: u64 = 2_013_265_921;

fn bb_from_i64(value: i64) -> u32 {
    (value as i128).rem_euclid(BABYBEAR_MODULUS_U64 as i128) as u32
}

fn bb_add_u32(lhs: u32, rhs: u32) -> u32 {
    let sum = lhs as u64 + rhs as u64;
    if sum >= BABYBEAR_MODULUS_U64 {
        (sum - BABYBEAR_MODULUS_U64) as u32
    } else {
        sum as u32
    }
}

fn bb_sub_u32(lhs: u32, rhs: u32) -> u32 {
    if lhs >= rhs {
        lhs - rhs
    } else {
        (lhs as u64 + BABYBEAR_MODULUS_U64 - rhs as u64) as u32
    }
}

fn bb_mul_u32(lhs: u32, rhs: u32) -> u32 {
    ((lhs as u64 * rhs as u64) % BABYBEAR_MODULUS_U64) as u32
}

fn bb_cyclotomic_mul(lhs: &[u32; D], rhs: &[u32; D]) -> [u32; D] {
    let mut out = [0u32; D];
    for (i, &lhs_coeff) in lhs.iter().enumerate() {
        for (j, &rhs_coeff) in rhs.iter().enumerate() {
            let product = bb_mul_u32(lhs_coeff, rhs_coeff);
            let idx = i + j;
            if idx < D {
                out[idx] = bb_add_u32(out[idx], product);
            } else {
                out[idx - D] = bb_sub_u32(out[idx - D], product);
            }
        }
    }
    out
}

impl BatchedCpPublicStatement {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"symphony-batched-cp-public-statement-v1");
        encode_statement_shape(&mut out, &self.shape);
        out.extend_from_slice(&self.manifest_digest);
        push_usize(&mut out, self.round_message_commitments.len());
        for commitment in &self.round_message_commitments {
            out.extend_from_slice(commitment);
        }
        out.extend_from_slice(&self.batch_challenge_digest);
        out.extend_from_slice(&self.folded_output_accumulator_root);
        out.extend_from_slice(&self.whir_parameter_digest);
        out
    }
}

impl BatchedCpSymbt3PublicStatement {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"symphony-batched-cp-symbt3-compressed-research-public-v1",
        );
        out.extend_from_slice(&self.shape_id);
        push_usize(&mut out, self.batch_capacity);
        push_usize(&mut out, self.active_count);
        out.extend_from_slice(&self.old_accumulator_digest);
        out.extend_from_slice(&self.new_accumulator_digest);
        push_i64_vec(&mut out, &self.old_accumulator_coordinates);
        push_i64_vec(&mut out, &self.new_accumulator_coordinates);
        out.extend_from_slice(&self.input_public_boundary_digest);
        out.extend_from_slice(&self.batch_manifest_root);
        out.extend_from_slice(&self.manifest_oracle_root);
        out.extend_from_slice(&self.manifest_eval_claim.to_le_bytes());
        out.extend_from_slice(&self.batch_manifest_layout_digest);
        out.extend_from_slice(&self.source_column_layout_digest);
        out.extend_from_slice(&self.message_semantic_layout_digest);
        out.extend_from_slice(&self.production_norm_range_layout_digest);
        out.extend_from_slice(&self.structured_projection_layout_digest);
        out.extend_from_slice(&self.monomial_embedding_layout_digest);
        out.extend_from_slice(&self.representative_layout_digest);
        out.extend_from_slice(&self.norm_range_public_digest);
        out.extend_from_slice(&self.source_assignment_boundary_digest);
        out.extend_from_slice(&self.source_ajtai_commitment_boundary_digest);
        push_usize(&mut out, self.message_oracle_roots.len());
        for root in &self.message_oracle_roots {
            out.extend_from_slice(root);
        }
        push_i64_vec(&mut out, &self.folded_public_input);
        push_i64_vec(&mut out, &self.folded_commitment);
        push_i64_vec(&mut out, &self.folded_evaluation);
        push_i64_vec(&mut out, &self.folded_accumulator_coordinates);
        out.extend_from_slice(&self.folded_ajtai_opening_root);
        push_i64_vec(&mut out, &self.folded_ajtai_commitment);
        out.extend_from_slice(&self.folded_gr1cs_boundary_digest);
        out.extend_from_slice(&self.ring_module_layout_digest);
        out.extend_from_slice(&self.ajtai_commit_layout_digest);
        out.extend_from_slice(&self.r1cs_evaluator_layout_digest);
        out.extend_from_slice(&self.gr1cs_residual_layout_digest);
        out.extend_from_slice(&self.algebra_law_digest);
        out.extend_from_slice(&self.ajtai_linear_algebra_layout_digest);
        out.extend_from_slice(&self.ajtai_norm_range_layout_digest);
        out.extend_from_slice(&self.projection_layout_digest);
        out.extend_from_slice(&self.range_layout_digest);
        out.extend_from_slice(&self.folded_gr1cs_product_residual_layout_digest);
        out.extend_from_slice(&self.folded_output_accumulator_root);
        out.extend_from_slice(&self.whir_parameter_digest);
        out
    }

    #[must_use]
    pub fn matches_relation(&self, relation: &BatchedCpSymbt3RelationDescription) -> bool {
        self.shape_id == relation.shape.shape_id
            && self.batch_capacity == relation.shape.batch_capacity
            && self.active_count == relation.shape.active_count
            && self.old_accumulator_digest != [0u8; 32]
            && self.new_accumulator_digest != [0u8; 32]
            && self.old_accumulator_coordinates.len()
                == relation.symbt3_accumulator_coordinate_len()
            && self.new_accumulator_coordinates.len()
                == relation.symbt3_accumulator_coordinate_len()
            && self.old_accumulator_digest
                == symbt3_accumulator_coordinates_digest(
                    relation.shape.accumulator_shape.digest_scheme,
                    b"old",
                    &self.old_accumulator_coordinates,
                )
            && self.new_accumulator_digest
                == symbt3_accumulator_coordinates_digest(
                    relation.shape.accumulator_shape.digest_scheme,
                    b"new",
                    &self.new_accumulator_coordinates,
                )
            && symbt3_accumulator_transition_coordinates(relation, self)
                .is_some_and(|expected| expected == self.new_accumulator_coordinates)
            && self.batch_manifest_layout_digest
                == relation
                    .batch_manifest_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && symbt3_manifest_root_link_is_valid(
                relation.shape.accumulator_shape.digest_scheme,
                self,
            )
            && symbt3_canonical_manifest_root_for_statement(relation, self)
                .is_some_and(|root| root == self.manifest_oracle_root)
            && self.manifest_eval_claim < BABYBEAR_MODULUS_U64 as u32
            && self.source_column_layout_digest
                == relation
                    .batch_manifest_layout
                    .source_column_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.message_semantic_layout_digest
                == relation
                    .message_semantic_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.production_norm_range_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.structured_projection_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .projection_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.monomial_embedding_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .monomial_embedding_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.representative_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .representative_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.source_assignment_boundary_digest != [0u8; 32]
            && self.source_ajtai_commitment_boundary_digest != [0u8; 32]
            && self.message_oracle_roots.len() == relation.shape.round_message_lens.len()
            && self.folded_public_input.len() == relation.symbt3_public_input_coordinate_len()
            && self.folded_commitment.len() == relation.symbt3_commitment_coordinate_len()
            && self.folded_evaluation.len() == relation.symbt3_evaluation_coordinate_len()
            && self.folded_accumulator_coordinates.len()
                == relation.symbt3_accumulator_coordinate_len()
            && self.folded_ajtai_commitment.len() == relation.symbt3_commitment_coordinate_len()
            && self.folded_ajtai_commitment == self.folded_commitment
            && self.ring_module_layout_digest
                == relation
                    .ring_module_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.ajtai_commit_layout_digest
                == relation
                    .ajtai_commit_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.r1cs_evaluator_layout_digest
                == relation
                    .r1cs_evaluator_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.gr1cs_residual_layout_digest
                == relation
                    .gr1cs_residual_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.algebra_law_digest
                == relation
                    .algebra_law
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.ajtai_linear_algebra_layout_digest
                == relation
                    .ajtai_linear_algebra_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.ajtai_norm_range_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.projection_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .projection_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.range_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .range_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.norm_range_public_digest
                == symbt3_norm_range_public_digest(
                    relation.shape.accumulator_shape.digest_scheme,
                    &self.folded_ajtai_opening_root,
                    &self.production_norm_range_layout_digest,
                    &self.structured_projection_layout_digest,
                    &self.monomial_embedding_layout_digest,
                    &self.representative_layout_digest,
                )
            && self.folded_gr1cs_product_residual_layout_digest
                == relation
                    .folded_gr1cs_product_residual_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.whir_parameter_digest == relation.shape.accumulator_shape.whir_parameter_digest
    }
}

impl BatchedCpSymbt3Witness {
    #[must_use]
    pub fn from_batched_witness(witness: &BatchedCpWitnessBundle) -> Self {
        Self {
            message_oracles: witness.round_message_oracles.clone(),
            algebraic_trace_columns: Vec::new(),
            source_ajtai_opening_values: Vec::new(),
            folded_ajtai_opening_values: Vec::new(),
            source_r1cs_assignment_values: Vec::new(),
            manifest_source_values: Vec::new(),
        }
    }
}

impl Symbt3TypedMessageOracle {
    #[must_use]
    pub fn from_round_messages(
        round: usize,
        rows: &[Vec<u8>],
        layout: &Symbt3RoundMessageLayout,
    ) -> Self {
        let rows = rows
            .iter()
            .enumerate()
            .map(|(row_index, message)| {
                let mut sections = layout
                    .sections
                    .iter()
                    .map(|section| {
                        let values = message
                            .get(
                                section.coordinate_offset
                                    ..section
                                        .coordinate_offset
                                        .saturating_add(section.coordinate_len),
                            )
                            .unwrap_or(&[])
                            .iter()
                            .map(|&value| u32::from(value))
                            .collect::<Vec<_>>();
                        Symbt3TypedMessageSection {
                            section_kind: section.section_kind,
                            offset: section.coordinate_offset,
                            values,
                        }
                    })
                    .collect::<Vec<_>>();
                let covered_end = layout
                    .sections
                    .iter()
                    .map(|section| {
                        section
                            .coordinate_offset
                            .saturating_add(section.coordinate_len)
                    })
                    .max()
                    .unwrap_or(0);
                if covered_end < message.len() {
                    sections.push(Symbt3TypedMessageSection {
                        section_kind: Symbt3MessageSectionKind::BoundaryDigestCoordinate,
                        offset: covered_end,
                        values: message[covered_end..]
                            .iter()
                            .map(|&value| u32::from(value))
                            .collect(),
                    });
                }
                Symbt3TypedMessageRow {
                    row_index,
                    sections,
                }
            })
            .collect();
        Self { round, rows }
    }

    #[must_use]
    pub fn to_round_messages(&self, layout: &Symbt3RoundMessageLayout) -> Option<Vec<Vec<u8>>> {
        if self.round != layout.round_index || self.rows.len() != layout.row_count {
            return None;
        }
        let mut rows = Vec::with_capacity(self.rows.len());
        for (expected_row_index, typed_row) in self.rows.iter().enumerate() {
            if typed_row.row_index != expected_row_index {
                return None;
            }
            let mut message = vec![0u8; layout.message_len];
            for typed_section in &typed_row.sections {
                let end = typed_section
                    .offset
                    .checked_add(typed_section.values.len())?;
                if end > message.len() {
                    return None;
                }
                for (dst, &value) in message[typed_section.offset..end]
                    .iter_mut()
                    .zip(&typed_section.values)
                {
                    *dst = u8::try_from(value).ok()?;
                }
            }
            for section_layout in &layout.sections {
                let typed_section = typed_row.sections.iter().find(|section| {
                    section.section_kind == section_layout.section_kind
                        && section.offset == section_layout.coordinate_offset
                })?;
                if typed_section.values.len() != section_layout.coordinate_len {
                    return None;
                }
            }
            rows.push(message);
        }
        Some(rows)
    }
}

impl Symbt3AccumulatorWitness {
    #[must_use]
    pub fn from_symbt3_witness(
        relation: &BatchedCpSymbt3RelationDescription,
        witness: &BatchedCpSymbt3Witness,
    ) -> Self {
        let message_oracles = witness
            .message_oracles
            .iter()
            .enumerate()
            .map(|(round, rows)| {
                let layout = &relation.message_semantic_layout.round_layouts[round];
                Symbt3TypedMessageOracle::from_round_messages(round, rows, layout)
            })
            .collect();
        Self {
            manifest_oracle: witness.manifest_source_values.clone(),
            source_columns: witness.source_r1cs_assignment_values.clone(),
            message_oracles,
            folded_witness_columns: vec![witness.folded_ajtai_opening_values.clone()],
            ajtai_openings: witness.source_ajtai_opening_values.clone(),
            old_accumulator_coordinates: Vec::new(),
            new_accumulator_coordinates: Vec::new(),
        }
    }

    #[must_use]
    pub fn to_symbt3_witness(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> Option<BatchedCpSymbt3Witness> {
        if self.message_oracles.len() != relation.message_semantic_layout.round_layouts.len()
            || self.folded_witness_columns.len() != 1
        {
            return None;
        }
        let mut message_oracles =
            vec![Vec::new(); relation.message_semantic_layout.round_layouts.len()];
        for typed_oracle in &self.message_oracles {
            let layout = relation
                .message_semantic_layout
                .round_layouts
                .get(typed_oracle.round)?;
            message_oracles[typed_oracle.round] = typed_oracle.to_round_messages(layout)?;
        }
        Some(BatchedCpSymbt3Witness {
            message_oracles,
            algebraic_trace_columns: Vec::new(),
            source_ajtai_opening_values: self.ajtai_openings.clone(),
            folded_ajtai_opening_values: self.folded_witness_columns[0].clone(),
            source_r1cs_assignment_values: self.source_columns.clone(),
            manifest_source_values: self.manifest_oracle.clone(),
        })
    }
}

#[must_use]
fn symbt3_default_compressed_boundary_digest_scheme() -> PublicDigestScheme {
    #[cfg(feature = "whir")]
    {
        PublicDigestScheme::Poseidon2BabyBear
    }
    #[cfg(not(feature = "whir"))]
    {
        PublicDigestScheme::Sha256
    }
}

#[must_use]
pub fn symbt3_digest_digest_vec(
    scheme: PublicDigestScheme,
    domain: &'static [u8],
    values: &[Digest32],
) -> Digest32 {
    let mut body = Vec::new();
    push_digest_vec(&mut body, values);
    digest_domain_with_scheme(scheme, domain, &body)
}

#[must_use]
pub fn symbt3_digest_i64_matrix(
    scheme: PublicDigestScheme,
    domain: &'static [u8],
    values: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    push_i64_matrix(&mut body, values);
    digest_domain_with_scheme(scheme, domain, &body)
}

#[must_use]
pub fn symbt3_batch_items_digest(
    scheme: PublicDigestScheme,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
    source_assignment_roots: &[Digest32],
    message_oracle_roots: &[Digest32],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-public-values",
        input_public_values,
    ));
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-commitment-values",
        input_commitment_values,
    ));
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-evaluation-values",
        input_evaluation_values,
    ));
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-accumulator-values",
        input_accumulator_values,
    ));
    body.extend_from_slice(&symbt3_digest_digest_vec(
        scheme,
        b"symbt3-k4-6-source-assignment-roots",
        source_assignment_roots,
    ));
    body.extend_from_slice(&symbt3_digest_digest_vec(
        scheme,
        b"symbt3-k4-6-message-oracle-roots",
        message_oracle_roots,
    ));
    digest_domain_with_scheme(scheme, b"symbt3-k4-6-batch-items", &body)
}

#[must_use]
pub fn symbt3_public_source_boundary_digest(
    scheme: PublicDigestScheme,
    source_assignment_roots_digest: &Digest32,
    source_assignment_boundary_digest: &Digest32,
    source_ajtai_opening_roots_digest: &Digest32,
    source_ajtai_commitment_boundary_digest: &Digest32,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(source_assignment_roots_digest);
    body.extend_from_slice(source_assignment_boundary_digest);
    body.extend_from_slice(source_ajtai_opening_roots_digest);
    body.extend_from_slice(source_ajtai_commitment_boundary_digest);
    digest_domain_with_scheme(scheme, b"symbt3-k4-6-public-source-boundary", &body)
}

impl Symbt3AccumulatorInstance {
    #[must_use]
    pub fn from_public_statement(
        profile_digest: Digest32,
        old_accumulator_digest: Digest32,
        new_accumulator_digest: Digest32,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Self {
        Self::from_public_statement_with_scheme(
            symbt3_default_compressed_boundary_digest_scheme(),
            profile_digest,
            old_accumulator_digest,
            new_accumulator_digest,
            statement,
        )
    }

    #[must_use]
    pub fn from_public_statement_with_scheme(
        scheme: PublicDigestScheme,
        profile_digest: Digest32,
        old_accumulator_digest: Digest32,
        new_accumulator_digest: Digest32,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Self {
        let source_assignment_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-assignment-roots",
            &statement.source_assignment_roots,
        );
        let source_ajtai_opening_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-ajtai-opening-roots",
            &statement.source_ajtai_opening_roots,
        );
        let message_oracle_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-message-oracle-roots",
            &statement.message_oracle_roots,
        );
        let batch_items_digest = symbt3_batch_items_digest(
            scheme,
            &statement.input_public_values,
            &statement.input_commitment_values,
            &statement.input_evaluation_values,
            &statement.input_accumulator_values,
            &statement.source_assignment_roots,
            &statement.message_oracle_roots,
        );
        let public_source_boundary_digest = symbt3_public_source_boundary_digest(
            scheme,
            &source_assignment_roots_digest,
            &statement.source_assignment_boundary_digest,
            &source_ajtai_opening_roots_digest,
            &statement.source_ajtai_commitment_boundary_digest,
        );
        Self {
            profile_digest,
            shape_id: statement.shape_id,
            batch_capacity: statement.batch_capacity,
            active_count: statement.active_count,
            old_accumulator_digest,
            new_accumulator_digest,
            old_accumulator_coordinates: statement.old_accumulator_coordinates.clone(),
            new_accumulator_coordinates: statement.new_accumulator_coordinates.clone(),
            input_public_boundary_digest: statement.input_public_boundary_digest,
            manifest_root: statement.batch_manifest_root,
            manifest_oracle_root: statement.manifest_oracle_root,
            manifest_eval_claim: statement.manifest_eval_claim,
            manifest_layout_digest: statement.batch_manifest_layout_digest,
            source_column_layout_digest: statement.source_column_layout_digest,
            message_semantic_layout_digest: statement.message_semantic_layout_digest,
            production_norm_range_layout_digest: statement.production_norm_range_layout_digest,
            structured_projection_layout_digest: statement.structured_projection_layout_digest,
            monomial_embedding_layout_digest: statement.monomial_embedding_layout_digest,
            representative_layout_digest: statement.representative_layout_digest,
            norm_range_public_digest: statement.norm_range_public_digest,
            batch_items_digest,
            public_source_boundary_digest,
            source_assignment_roots_digest,
            source_ajtai_opening_roots_digest,
            message_oracle_roots_digest,
            input_public_values: statement.input_public_values.clone(),
            input_commitment_values: statement.input_commitment_values.clone(),
            input_evaluation_values: statement.input_evaluation_values.clone(),
            input_accumulator_values: statement.input_accumulator_values.clone(),
            source_assignment_roots: statement.source_assignment_roots.clone(),
            source_assignment_boundary_digest: statement.source_assignment_boundary_digest,
            source_ajtai_opening_roots: statement.source_ajtai_opening_roots.clone(),
            source_ajtai_commitment_boundary_digest: statement
                .source_ajtai_commitment_boundary_digest,
            message_oracle_roots: statement.message_oracle_roots.clone(),
            folded_public_input: statement.folded_public_input.clone(),
            folded_commitment: statement.folded_commitment.clone(),
            folded_evaluation: statement.folded_evaluation.clone(),
            folded_batch_accumulator_coordinates: statement.folded_accumulator_coordinates.clone(),
            folded_ajtai_opening_root: statement.folded_ajtai_opening_root,
            folded_ajtai_commitment: statement.folded_ajtai_commitment.clone(),
            folded_gr1cs_boundary_digest: statement.folded_gr1cs_boundary_digest,
            ring_module_layout_digest: statement.ring_module_layout_digest,
            ajtai_commit_layout_digest: statement.ajtai_commit_layout_digest,
            r1cs_evaluator_layout_digest: statement.r1cs_evaluator_layout_digest,
            gr1cs_residual_layout_digest: statement.gr1cs_residual_layout_digest,
            algebra_law_digest: statement.algebra_law_digest,
            ajtai_linear_algebra_layout_digest: statement.ajtai_linear_algebra_layout_digest,
            ajtai_norm_range_layout_digest: statement.ajtai_norm_range_layout_digest,
            projection_layout_digest: statement.projection_layout_digest,
            range_layout_digest: statement.range_layout_digest,
            folded_gr1cs_product_residual_layout_digest: statement
                .folded_gr1cs_product_residual_layout_digest,
            folded_output_boundary_digest: statement.folded_output_accumulator_root,
            whir_params_digest: statement.whir_parameter_digest,
        }
    }

    #[must_use]
    pub fn to_public_statement(&self) -> BatchedCpSymbt3PublicStatement {
        BatchedCpSymbt3PublicStatement {
            shape_id: self.shape_id,
            batch_capacity: self.batch_capacity,
            active_count: self.active_count,
            old_accumulator_digest: self.old_accumulator_digest,
            new_accumulator_digest: self.new_accumulator_digest,
            old_accumulator_coordinates: self.old_accumulator_coordinates.clone(),
            new_accumulator_coordinates: self.new_accumulator_coordinates.clone(),
            input_public_boundary_digest: self.input_public_boundary_digest,
            batch_manifest_root: self.manifest_root,
            manifest_oracle_root: self.manifest_oracle_root,
            manifest_eval_claim: self.manifest_eval_claim,
            batch_manifest_layout_digest: self.manifest_layout_digest,
            source_column_layout_digest: self.source_column_layout_digest,
            message_semantic_layout_digest: self.message_semantic_layout_digest,
            production_norm_range_layout_digest: self.production_norm_range_layout_digest,
            structured_projection_layout_digest: self.structured_projection_layout_digest,
            monomial_embedding_layout_digest: self.monomial_embedding_layout_digest,
            representative_layout_digest: self.representative_layout_digest,
            norm_range_public_digest: self.norm_range_public_digest,
            input_public_values: self.input_public_values.clone(),
            input_commitment_values: self.input_commitment_values.clone(),
            input_evaluation_values: self.input_evaluation_values.clone(),
            input_accumulator_values: self.input_accumulator_values.clone(),
            source_assignment_roots: self.source_assignment_roots.clone(),
            source_assignment_boundary_digest: self.source_assignment_boundary_digest,
            source_ajtai_opening_roots: self.source_ajtai_opening_roots.clone(),
            source_ajtai_commitment_boundary_digest: self.source_ajtai_commitment_boundary_digest,
            message_oracle_roots: self.message_oracle_roots.clone(),
            folded_public_input: self.folded_public_input.clone(),
            folded_commitment: self.folded_commitment.clone(),
            folded_evaluation: self.folded_evaluation.clone(),
            folded_accumulator_coordinates: self.folded_batch_accumulator_coordinates.clone(),
            folded_ajtai_opening_root: self.folded_ajtai_opening_root,
            folded_ajtai_commitment: self.folded_ajtai_commitment.clone(),
            folded_gr1cs_boundary_digest: self.folded_gr1cs_boundary_digest,
            ring_module_layout_digest: self.ring_module_layout_digest,
            ajtai_commit_layout_digest: self.ajtai_commit_layout_digest,
            r1cs_evaluator_layout_digest: self.r1cs_evaluator_layout_digest,
            gr1cs_residual_layout_digest: self.gr1cs_residual_layout_digest,
            algebra_law_digest: self.algebra_law_digest,
            ajtai_linear_algebra_layout_digest: self.ajtai_linear_algebra_layout_digest,
            ajtai_norm_range_layout_digest: self.ajtai_norm_range_layout_digest,
            projection_layout_digest: self.projection_layout_digest,
            range_layout_digest: self.range_layout_digest,
            folded_gr1cs_product_residual_layout_digest: self
                .folded_gr1cs_product_residual_layout_digest,
            folded_output_accumulator_root: self.folded_output_boundary_digest,
            whir_parameter_digest: self.whir_params_digest,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let scheme = symbt3_default_compressed_boundary_digest_scheme();
        let has_expanded_batch_items = !self.input_public_values.is_empty()
            || !self.input_commitment_values.is_empty()
            || !self.input_evaluation_values.is_empty()
            || !self.input_accumulator_values.is_empty()
            || !self.source_assignment_roots.is_empty()
            || !self.message_oracle_roots.is_empty();
        let source_assignment_roots_digest = if self.source_assignment_roots.is_empty() {
            self.source_assignment_roots_digest
        } else {
            symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-assignment-roots",
                &self.source_assignment_roots,
            )
        };
        let source_ajtai_opening_roots_digest = if self.source_ajtai_opening_roots.is_empty() {
            self.source_ajtai_opening_roots_digest
        } else {
            symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-ajtai-opening-roots",
                &self.source_ajtai_opening_roots,
            )
        };
        let message_oracle_roots_digest = if self.message_oracle_roots.is_empty() {
            self.message_oracle_roots_digest
        } else {
            symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-message-oracle-roots",
                &self.message_oracle_roots,
            )
        };
        let batch_items_digest = if has_expanded_batch_items {
            symbt3_batch_items_digest(
                scheme,
                &self.input_public_values,
                &self.input_commitment_values,
                &self.input_evaluation_values,
                &self.input_accumulator_values,
                &self.source_assignment_roots,
                &self.message_oracle_roots,
            )
        } else {
            self.batch_items_digest
        };
        let public_source_boundary_digest = if self.source_assignment_roots.is_empty()
            && self.source_ajtai_opening_roots.is_empty()
        {
            self.public_source_boundary_digest
        } else {
            symbt3_public_source_boundary_digest(
                scheme,
                &source_assignment_roots_digest,
                &self.source_assignment_boundary_digest,
                &source_ajtai_opening_roots_digest,
                &self.source_ajtai_commitment_boundary_digest,
            )
        };
        let mut out = Vec::new();
        push_bytes(&mut out, b"symphony-symbt3-accumulator-instance-v2");
        out.extend_from_slice(&self.profile_digest);
        out.extend_from_slice(&self.shape_id);
        push_usize(&mut out, self.batch_capacity);
        push_usize(&mut out, self.active_count);
        out.extend_from_slice(&self.old_accumulator_digest);
        out.extend_from_slice(&self.new_accumulator_digest);
        push_i64_vec(&mut out, &self.old_accumulator_coordinates);
        push_i64_vec(&mut out, &self.new_accumulator_coordinates);
        out.extend_from_slice(&self.input_public_boundary_digest);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.manifest_oracle_root);
        out.extend_from_slice(&self.manifest_eval_claim.to_le_bytes());
        out.extend_from_slice(&self.manifest_layout_digest);
        out.extend_from_slice(&self.source_column_layout_digest);
        out.extend_from_slice(&self.message_semantic_layout_digest);
        out.extend_from_slice(&self.production_norm_range_layout_digest);
        out.extend_from_slice(&self.structured_projection_layout_digest);
        out.extend_from_slice(&self.monomial_embedding_layout_digest);
        out.extend_from_slice(&self.representative_layout_digest);
        out.extend_from_slice(&self.norm_range_public_digest);
        out.extend_from_slice(&batch_items_digest);
        out.extend_from_slice(&public_source_boundary_digest);
        out.extend_from_slice(&source_assignment_roots_digest);
        out.extend_from_slice(&self.source_assignment_boundary_digest);
        out.extend_from_slice(&source_ajtai_opening_roots_digest);
        out.extend_from_slice(&self.source_ajtai_commitment_boundary_digest);
        out.extend_from_slice(&message_oracle_roots_digest);
        push_i64_vec(&mut out, &self.folded_public_input);
        push_i64_vec(&mut out, &self.folded_commitment);
        push_i64_vec(&mut out, &self.folded_evaluation);
        push_i64_vec(&mut out, &self.folded_batch_accumulator_coordinates);
        out.extend_from_slice(&self.folded_ajtai_opening_root);
        push_i64_vec(&mut out, &self.folded_ajtai_commitment);
        out.extend_from_slice(&self.folded_gr1cs_boundary_digest);
        out.extend_from_slice(&self.ring_module_layout_digest);
        out.extend_from_slice(&self.ajtai_commit_layout_digest);
        out.extend_from_slice(&self.r1cs_evaluator_layout_digest);
        out.extend_from_slice(&self.gr1cs_residual_layout_digest);
        out.extend_from_slice(&self.algebra_law_digest);
        out.extend_from_slice(&self.ajtai_linear_algebra_layout_digest);
        out.extend_from_slice(&self.ajtai_norm_range_layout_digest);
        out.extend_from_slice(&self.projection_layout_digest);
        out.extend_from_slice(&self.range_layout_digest);
        out.extend_from_slice(&self.folded_gr1cs_product_residual_layout_digest);
        out.extend_from_slice(&self.folded_output_boundary_digest);
        out.extend_from_slice(&self.whir_params_digest);
        out
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        digest_domain_with_scheme(
            scheme,
            b"symphony-symbt3-accumulator-instance-v2",
            &self.canonical_bytes(),
        )
    }

    #[must_use]
    pub fn matches_profile_and_relation(
        &self,
        profile: &Symbt3AuthorityProfile,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> bool {
        let scheme = relation.shape.accumulator_shape.digest_scheme;
        let statement = self.to_public_statement();
        let expected_source_assignment_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-assignment-roots",
            &self.source_assignment_roots,
        );
        let expected_source_ajtai_opening_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-ajtai-opening-roots",
            &self.source_ajtai_opening_roots,
        );
        let expected_message_oracle_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-message-oracle-roots",
            &self.message_oracle_roots,
        );
        let expected_batch_items_digest = symbt3_batch_items_digest(
            scheme,
            &self.input_public_values,
            &self.input_commitment_values,
            &self.input_evaluation_values,
            &self.input_accumulator_values,
            &self.source_assignment_roots,
            &self.message_oracle_roots,
        );
        let expected_public_source_boundary_digest = symbt3_public_source_boundary_digest(
            scheme,
            &expected_source_assignment_roots_digest,
            &self.source_assignment_boundary_digest,
            &expected_source_ajtai_opening_roots_digest,
            &self.source_ajtai_commitment_boundary_digest,
        );
        self.profile_digest == profile.digest(scheme)
            && self.shape_id == relation.shape.shape_id
            && self.batch_capacity == relation.shape.batch_capacity
            && self.active_count == relation.shape.active_count
            && self.batch_items_digest == expected_batch_items_digest
            && self.public_source_boundary_digest == expected_public_source_boundary_digest
            && self.source_assignment_roots_digest == expected_source_assignment_roots_digest
            && self.source_ajtai_opening_roots_digest == expected_source_ajtai_opening_roots_digest
            && self.message_oracle_roots_digest == expected_message_oracle_roots_digest
            && statement.matches_relation(relation)
            && statement.canonical_bytes().len() == relation.public_statement_bytes()
    }
}

#[must_use]
pub fn derive_symbt3_batch_challenge_digest(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.folding_protocol_id());
    body.extend_from_slice(&statement.input_public_boundary_digest);
    body.extend_from_slice(&statement.batch_manifest_root);
    body.extend_from_slice(&statement.batch_manifest_layout_digest);
    body.extend_from_slice(&statement.source_column_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.source_assignment_boundary_digest);
    body.extend_from_slice(&statement.source_ajtai_commitment_boundary_digest);
    body.extend_from_slice(&statement.ring_module_layout_digest);
    body.extend_from_slice(&statement.ajtai_commit_layout_digest);
    body.extend_from_slice(&statement.r1cs_evaluator_layout_digest);
    body.extend_from_slice(&statement.gr1cs_residual_layout_digest);
    body.extend_from_slice(&statement.algebra_law_digest);
    body.extend_from_slice(&statement.ajtai_linear_algebra_layout_digest);
    body.extend_from_slice(&statement.ajtai_norm_range_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    push_usize(&mut body, statement.message_oracle_roots.len());
    for root in &statement.message_oracle_roots {
        body.extend_from_slice(root);
    }
    body.extend_from_slice(&statement.whir_parameter_digest);
    push_usize(&mut body, statement.batch_capacity);
    push_usize(&mut body, statement.active_count);
    digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"SYMBT3-A-BETA",
        &body,
    )
}

#[must_use]
pub fn derive_symbt3_public_statement_digest(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&derive_symbt3_batch_challenge_digest(relation, statement));
    body.extend_from_slice(&statement.old_accumulator_digest);
    body.extend_from_slice(&statement.new_accumulator_digest);
    push_i64_vec(&mut body, &statement.old_accumulator_coordinates);
    push_i64_vec(&mut body, &statement.new_accumulator_coordinates);
    body.extend_from_slice(&statement.batch_manifest_root);
    body.extend_from_slice(&statement.manifest_oracle_root);
    body.extend_from_slice(&statement.manifest_eval_claim.to_le_bytes());
    body.extend_from_slice(&statement.batch_manifest_layout_digest);
    body.extend_from_slice(&statement.source_column_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.production_norm_range_layout_digest);
    body.extend_from_slice(&statement.structured_projection_layout_digest);
    body.extend_from_slice(&statement.monomial_embedding_layout_digest);
    body.extend_from_slice(&statement.representative_layout_digest);
    body.extend_from_slice(&statement.norm_range_public_digest);
    push_i64_vec(&mut body, &statement.folded_public_input);
    push_i64_vec(&mut body, &statement.folded_commitment);
    push_i64_vec(&mut body, &statement.folded_evaluation);
    push_i64_vec(&mut body, &statement.folded_accumulator_coordinates);
    body.extend_from_slice(&statement.folded_ajtai_opening_root);
    push_i64_vec(&mut body, &statement.folded_ajtai_commitment);
    body.extend_from_slice(&statement.folded_gr1cs_boundary_digest);
    body.extend_from_slice(&statement.algebra_law_digest);
    body.extend_from_slice(&statement.ajtai_linear_algebra_layout_digest);
    body.extend_from_slice(&statement.ajtai_norm_range_layout_digest);
    body.extend_from_slice(&statement.projection_layout_digest);
    body.extend_from_slice(&statement.range_layout_digest);
    body.extend_from_slice(&statement.production_norm_range_layout_digest);
    body.extend_from_slice(&statement.structured_projection_layout_digest);
    body.extend_from_slice(&statement.monomial_embedding_layout_digest);
    body.extend_from_slice(&statement.representative_layout_digest);
    body.extend_from_slice(&statement.norm_range_public_digest);
    body.extend_from_slice(&statement.folded_gr1cs_product_residual_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.folded_output_accumulator_root);
    digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"batched-cp-symbt3-proof-public-statement",
        &body,
    )
}

#[must_use]
pub fn derive_symbt3_projection_seed_digest(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    oracle_root: Digest32,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&derive_symbt3_public_statement_digest(relation, statement));
    body.extend_from_slice(&statement.folded_ajtai_opening_root);
    body.extend_from_slice(&oracle_root);
    body.extend_from_slice(&statement.whir_parameter_digest);
    body.extend_from_slice(&statement.ajtai_norm_range_layout_digest);
    body.extend_from_slice(&statement.structured_projection_layout_digest);
    body.extend_from_slice(&statement.monomial_embedding_layout_digest);
    body.extend_from_slice(&statement.representative_layout_digest);
    body.extend_from_slice(&statement.range_layout_digest);
    digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"SYMBT3-J-PROJECTION",
        &body,
    )
}

#[must_use]
pub fn derive_symbt3_beta_coefficients(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Vec<i64> {
    let seed = derive_symbt3_batch_challenge_digest(relation, statement);
    let mut coeffs = Vec::with_capacity(seed.len() * 2);
    for byte in seed {
        let d0 = (byte % 5) as i64;
        let d1 = ((byte / 5) % 5) as i64;
        coeffs.push(d0 - 2);
        coeffs.push(d1 - 2);
    }
    (0..statement.batch_capacity)
        .map(|idx| coeffs[idx % coeffs.len()])
        .collect()
}

#[must_use]
pub fn derive_symbt3_beta_ring_elements(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Vec<RingElement> {
    let seed = derive_symbt3_batch_challenge_digest(relation, statement);
    let mut coeffs = Vec::with_capacity(seed.len() * 2);
    for byte in seed {
        let d0 = (byte % 5) as i64;
        let d1 = ((byte / 5) % 5) as i64;
        coeffs.push(d0 - 2);
        coeffs.push(d1 - 2);
    }
    (0..statement.batch_capacity)
        .map(|idx| {
            let mut ring_coeffs = [0i64; D];
            for (coeff_idx, coeff) in ring_coeffs.iter_mut().enumerate() {
                *coeff = coeffs[(idx * D + coeff_idx) % coeffs.len()];
            }
            RingElement {
                coeffs: ring_coeffs,
            }
        })
        .collect()
}

#[must_use]
pub fn derive_symbt3_round_challenges(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Vec<Digest32> {
    let mut prefix_seed_body = Vec::new();
    prefix_seed_body.extend_from_slice(&relation.folding_protocol_id());
    prefix_seed_body.extend_from_slice(&statement.input_public_boundary_digest);
    prefix_seed_body.extend_from_slice(&statement.batch_manifest_root);
    prefix_seed_body.extend_from_slice(&statement.source_assignment_boundary_digest);
    prefix_seed_body.extend_from_slice(&statement.source_ajtai_commitment_boundary_digest);
    push_usize(&mut prefix_seed_body, statement.batch_capacity);
    push_usize(&mut prefix_seed_body, statement.active_count);
    let mut prior = digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"batched-cp-symbt3-round-challenge-prefix-seed",
        &prefix_seed_body,
    );
    (0..relation.shape.accumulator_shape.num_rounds)
        .map(|round| {
            let mut body = Vec::new();
            body.extend_from_slice(&relation.folding_protocol_id());
            body.extend_from_slice(&statement.input_public_boundary_digest);
            body.extend_from_slice(&statement.batch_manifest_root);
            for root in statement.message_oracle_roots.iter().take(round + 1) {
                body.extend_from_slice(root);
            }
            body.extend_from_slice(&prior);
            push_usize(&mut body, round);
            let challenge = digest_domain_with_scheme(
                relation.shape.accumulator_shape.digest_scheme,
                b"batched-cp-symbt3-round-challenge",
                &body,
            );
            prior = challenge;
            challenge
        })
        .collect()
}

#[must_use]
pub fn symbt3_message_oracle_root(
    scheme: PublicDigestScheme,
    shape: &BatchedCpStatementShape,
    round: usize,
    rows: &[Vec<u8>],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&shape.shape_id);
    push_usize(&mut body, round);
    push_usize(&mut body, rows.len());
    for row in rows {
        push_bytes(&mut body, row);
    }
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-message-oracle-root", &body)
}

#[must_use]
pub fn symbt3_norm_range_public_digest(
    scheme: PublicDigestScheme,
    folded_opening_digest: &Digest32,
    norm_range_layout_digest: &Digest32,
    projection_layout_digest: &Digest32,
    monomial_embedding_layout_digest: &Digest32,
    representative_layout_digest: &Digest32,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(folded_opening_digest);
    body.extend_from_slice(norm_range_layout_digest);
    body.extend_from_slice(projection_layout_digest);
    body.extend_from_slice(monomial_embedding_layout_digest);
    body.extend_from_slice(representative_layout_digest);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-j-norm-range-public", &body)
}

#[must_use]
pub fn symbt3_message_semantic_rows_from_oracles(
    relation: &BatchedCpSymbt3RelationDescription,
    message_oracles: &[Vec<Vec<u8>>],
) -> Option<Vec<Vec<i64>>> {
    if message_oracles.len() != relation.message_semantic_layout.round_layouts.len() {
        return None;
    }
    let mut rows = Vec::with_capacity(relation.message_semantic_layout.round_layouts.len());
    for (round_layout, round_rows) in relation
        .message_semantic_layout
        .round_layouts
        .iter()
        .zip(message_oracles.iter())
    {
        if round_rows.len() != round_layout.row_count {
            return None;
        }
        let mut row_values =
            Vec::with_capacity(round_layout.row_count * round_layout.packed_field_len);
        for item in 0..relation.shape.active_count {
            let message = round_rows.get(item)?;
            if message.len() != round_layout.message_len {
                return None;
            }
            row_values.extend(symbt3_pack_message_bytes(
                message,
                round_layout.packed_field_len,
            ));
        }
        rows.push(row_values);
    }
    Some(rows)
}

#[must_use]
pub fn symbt3_message_semantic_flat_values(
    relation: &BatchedCpSymbt3RelationDescription,
    message_oracles: &[Vec<Vec<u8>>],
) -> Option<Vec<i64>> {
    Some(
        symbt3_message_semantic_rows_from_oracles(relation, message_oracles)?
            .into_iter()
            .flat_map(|row| row.into_iter())
            .collect(),
    )
}

#[must_use]
pub fn symbt3_message_view_flat_values(
    relation: &BatchedCpSymbt3RelationDescription,
    message_oracles: &[Vec<Vec<u8>>],
) -> Option<Vec<i64>> {
    if message_oracles.len() != relation.message_semantic_layout.round_layouts.len() {
        return None;
    }
    let mut values = Vec::with_capacity(
        relation
            .message_semantic_layout
            .view_coordinate_count(relation.shape.active_count),
    );
    for (round_layout, round_rows) in relation
        .message_semantic_layout
        .round_layouts
        .iter()
        .zip(message_oracles.iter())
    {
        if round_rows.len() != round_layout.row_count {
            return None;
        }
        for item in 0..relation.shape.active_count {
            let message = round_rows.get(item)?;
            if message.len() != round_layout.message_len {
                return None;
            }
            let packed = symbt3_pack_message_bytes(message, round_layout.packed_field_len);
            for view in &round_layout.message_views {
                let start = view.message_coordinate_map.message_coordinate_offset;
                let end = start.checked_add(view.message_coordinate_map.coordinate_len)?;
                values.extend(packed.get(start..end)?.iter().copied());
            }
        }
    }
    Some(values)
}

fn symbt3_pack_message_bytes(message: &[u8], packed_field_len: usize) -> Vec<i64> {
    let mut out = message
        .chunks(4)
        .take(packed_field_len)
        .map(|chunk| {
            let mut value = 0u32;
            for (idx, &byte) in chunk.iter().enumerate() {
                value |= (byte as u32) << (8 * idx);
            }
            (value as i128 % BABYBEAR_MODULUS_U64 as i128) as i64
        })
        .collect::<Vec<_>>();
    out.resize(packed_field_len, 0);
    out
}

pub fn bucket_by_exact_shape(
    items: Vec<BatchedCpItem>,
    whir_parameter_digest: Digest32,
) -> Result<Vec<BatchedCpBucket>, BatchedCpError> {
    let mut buckets = BTreeMap::<Digest32, Vec<BatchedCpItem>>::new();
    for item in items {
        let shape =
            CpAccumulatorShape::from_item(&item.public, &item.witness, whir_parameter_digest)?;
        buckets.entry(shape.shape_id()).or_default().push(item);
    }
    buckets
        .into_values()
        .map(|items| BatchedCpBucket::new(items, whir_parameter_digest))
        .collect()
}

#[must_use]
pub fn derive_batch_challenge_digest(
    shape: &BatchedCpStatementShape,
    manifest_digest: Digest32,
    round_commitments: &BatchRoundMessageCommitments,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_batch_challenge_body(
        shape,
        manifest_digest,
        round_commitments,
    ));
    digest_domain_with_scheme(
        shape.accumulator_shape.digest_scheme,
        b"batched-cp-challenge-digest",
        &body,
    )
}

fn estimate_witness_row_len(shape: &CpAccumulatorShape) -> usize {
    32 + shape.public_statement_len
        + shape.folded_output_contribution_len
        + shape.num_rounds * D * 8
        + shape
            .fs_message_lens
            .iter()
            .map(|len| 8 + len)
            .sum::<usize>()
        + (8 + shape.fs_commitment_len) * shape.num_rounds
        + (8 + shape.fs_opening_len) * shape.num_rounds
        + (0..shape.num_rounds)
            .map(|round| {
                8 + shape.fold_input_commitment_lens[round]
                    + 8
                    + shape.fold_input_public_input_lens[round] * 8
                    + 8
                    + shape.fold_input_eval_message_lens[round]
            })
            .sum::<usize>()
        + shape
            .original_witness_lens
            .iter()
            .map(|len| 8 + len * D * 8)
            .sum::<usize>()
}

fn estimate_public_statement_bytes(shape: &BatchedCpStatementShape) -> usize {
    // Shape + five fixed digests plus the round commitment count and one digest
    // per CP round. This mirrors `BatchedCpPublicStatement::canonical_bytes`.
    let mut out = Vec::new();
    push_bytes(&mut out, b"symphony-batched-cp-public-statement-v1");
    encode_statement_shape(&mut out, shape);
    out.extend_from_slice(&[0u8; 32]);
    push_usize(&mut out, shape.accumulator_shape.num_rounds);
    for _ in 0..shape.accumulator_shape.num_rounds {
        out.extend_from_slice(&[0u8; 32]);
    }
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.len()
}

fn estimate_symbt3_public_statement_bytes(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    push_bytes(
        &mut out,
        b"symphony-batched-cp-symbt3-compressed-research-public-v1",
    );
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, shape.batch_capacity);
    push_usize(&mut out, shape.active_count);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    push_usize(&mut out, shape.accumulator_shape.num_rounds);
    for _ in 0..shape.accumulator_shape.num_rounds {
        out.extend_from_slice(&[0u8; 32]);
    }
    let coord_len =
        shape.accumulator_shape.local_public_input_count * shape.accumulator_shape.r1cs_num_public;
    let commitment_len =
        shape.accumulator_shape.commitment_kappa * shape.accumulator_shape.commitment_d;
    let evaluation_len = shape.accumulator_shape.folded_evaluation_count * T * D;
    let accumulator_len = coord_len + commitment_len + evaluation_len;
    push_i64_vec(&mut out, &vec![0; accumulator_len]);
    push_i64_vec(&mut out, &vec![0; accumulator_len]);
    push_i64_vec(&mut out, &vec![0; coord_len]);
    push_i64_vec(&mut out, &vec![0; commitment_len]);
    push_i64_vec(&mut out, &vec![0; evaluation_len]);
    push_i64_vec(&mut out, &vec![0; accumulator_len]);
    out.extend_from_slice(&[0u8; 32]);
    push_i64_vec(&mut out, &vec![0; commitment_len]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.len()
}

fn flatten_symbt3_public_inputs(public_inputs: &[Vec<i64>]) -> Vec<i64> {
    public_inputs
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect()
}

fn flatten_symbt3_commitment(commitment: &crate::commitment::Commitment) -> Vec<i64> {
    commitment
        .value
        .elements
        .iter()
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn flatten_symbt3_evaluations(values: &[crate::ring::tensor::TensorElement]) -> Vec<i64> {
    values
        .iter()
        .flat_map(|tensor| tensor.data.iter().flat_map(|row| row.iter().copied()))
        .collect()
}

fn flatten_symbt3_ring_vector(value: &RingVector) -> Vec<i64> {
    value
        .elements
        .iter()
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn flatten_symbt3_full_ajtai_opening(item: &BatchedCpItem) -> Vec<i64> {
    item.public
        .instance
        .x_folded
        .public_input
        .iter()
        .chain(item.witness.folded_witness.witness.elements.iter())
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn flatten_symbt3_source_r1cs_assignment(
    item: &BatchedCpItem,
    original_index: usize,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Vec<i64> {
    let mut out = Vec::with_capacity(relation.r1cs_evaluator_layout.num_variables * D);
    if let Some(public_inputs) = item.public.public_inputs.get(original_index) {
        for public_idx in 0..relation.r1cs_evaluator_layout.num_public {
            let scalar = public_inputs.get(public_idx).copied().unwrap_or_default();
            out.extend_from_slice(&RingElement::from_constant(scalar).coeffs);
        }
    }
    if let Some(witness) = item.witness.original_witnesses.get(original_index) {
        for elem in &witness.elements {
            out.extend_from_slice(&elem.coeffs);
        }
    }
    out.resize(relation.r1cs_evaluator_layout.num_variables * D, 0);
    out
}

fn symbt3_input_public_boundary_digest(
    scheme: PublicDigestScheme,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    push_i64_matrix(&mut body, input_public_values);
    push_i64_matrix(&mut body, input_commitment_values);
    push_i64_matrix(&mut body, input_evaluation_values);
    push_i64_matrix(&mut body, input_accumulator_values);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-input-public-boundary", &body)
}

fn symbt3_manifest_rows_from_statement_parts(
    relation: &BatchedCpSymbt3RelationDescription,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
    source_assignment_roots: &[Digest32],
    message_oracle_roots: &[Digest32],
) -> Vec<Vec<i64>> {
    (0..relation.shape.active_count)
        .map(|item| {
            let mut row = Vec::with_capacity(
                relation
                    .batch_manifest_layout
                    .source_column_layout
                    .coordinate_count,
            );
            row.extend_from_slice(
                input_public_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_commitment_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_evaluation_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_accumulator_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_commitment_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            let assignment_start = item * relation.shape.accumulator_shape.local_public_input_count;
            let assignment_end =
                assignment_start + relation.shape.accumulator_shape.local_public_input_count;
            for root in source_assignment_roots
                .get(assignment_start..assignment_end)
                .unwrap_or(&[])
            {
                row.extend(root.iter().map(|&byte| byte as i64));
            }
            for root in message_oracle_roots {
                row.extend(root.iter().map(|&byte| byte as i64));
            }
            row.resize(
                relation
                    .batch_manifest_layout
                    .source_column_layout
                    .coordinate_count,
                0,
            );
            row
        })
        .collect()
}

fn symbt3_manifest_source_values_from_statement_parts(
    relation: &BatchedCpSymbt3RelationDescription,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
    source_assignment_roots: &[Digest32],
    message_oracle_roots: &[Digest32],
) -> Vec<i64> {
    let row_width = relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count;
    let mut out = Vec::with_capacity(relation.shape.active_count * row_width);
    for item in 0..relation.shape.active_count {
        let row_start = out.len();
        out.extend_from_slice(
            input_public_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_commitment_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_evaluation_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_accumulator_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_commitment_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        let assignment_start = item * relation.shape.accumulator_shape.local_public_input_count;
        let assignment_end =
            assignment_start + relation.shape.accumulator_shape.local_public_input_count;
        for root in source_assignment_roots
            .get(assignment_start..assignment_end)
            .unwrap_or(&[])
        {
            out.extend(root.iter().map(|&byte| byte as i64));
        }
        for root in message_oracle_roots {
            out.extend(root.iter().map(|&byte| byte as i64));
        }
        out.resize(row_start + row_width, 0);
    }
    out
}

#[must_use]
pub fn symbt3_manifest_rows_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<Vec<i64>>> {
    if statement.input_public_values.len() != relation.shape.active_count
        || statement.input_commitment_values.len() != relation.shape.active_count
        || statement.input_evaluation_values.len() != relation.shape.active_count
        || statement.input_accumulator_values.len() != relation.shape.active_count
        || statement.source_assignment_roots.len()
            != relation.shape.active_count
                * relation.shape.accumulator_shape.local_public_input_count
        || statement.message_oracle_roots.len() != relation.shape.accumulator_shape.num_rounds
    {
        return None;
    }
    let rows = symbt3_manifest_rows_from_statement_parts(
        relation,
        &statement.input_public_values,
        &statement.input_commitment_values,
        &statement.input_evaluation_values,
        &statement.input_accumulator_values,
        &statement.source_assignment_roots,
        &statement.message_oracle_roots,
    );
    rows.iter()
        .all(|row| {
            row.len()
                == relation
                    .batch_manifest_layout
                    .source_column_layout
                    .coordinate_count
        })
        .then_some(rows)
}

#[must_use]
pub fn symbt3_manifest_source_values_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<i64>> {
    if statement.input_public_values.len() != relation.shape.active_count
        || statement.input_commitment_values.len() != relation.shape.active_count
        || statement.input_evaluation_values.len() != relation.shape.active_count
        || statement.input_accumulator_values.len() != relation.shape.active_count
        || statement.source_assignment_roots.len()
            != relation.shape.active_count
                * relation.shape.accumulator_shape.local_public_input_count
        || statement.message_oracle_roots.len() != relation.shape.accumulator_shape.num_rounds
    {
        return None;
    }
    let values = symbt3_manifest_source_values_from_statement_parts(
        relation,
        &statement.input_public_values,
        &statement.input_commitment_values,
        &statement.input_evaluation_values,
        &statement.input_accumulator_values,
        &statement.source_assignment_roots,
        &statement.message_oracle_roots,
    );
    (values.len()
        == relation.shape.active_count
            * relation
                .batch_manifest_layout
                .source_column_layout
                .coordinate_count)
        .then_some(values)
}

#[must_use]
pub fn symbt3_manifest_commitment_policy_digest(
    scheme: PublicDigestScheme,
    policy: ManifestCommitmentPolicy,
) -> Digest32 {
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-manifest-commitment-policy",
        &[manifest_commitment_policy_code(policy)],
    )
}

#[must_use]
pub fn symbt3_challenge_schedule_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    field_policy: Symbt3FieldExtensionPolicy,
    sumcheck_policy: Symbt3SumcheckChallengePolicy,
    repetition_count: usize,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&SYMBT3_CHALLENGE_SCHEDULE_VERSION.to_le_bytes());
    body.push(symbt3_field_extension_policy_code(field_policy));
    body.push(symbt3_sumcheck_challenge_policy_code(sumcheck_policy));
    push_usize(&mut body, repetition_count);
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&relation.folding_protocol_id());
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-challenge-schedule-policy",
        &body,
    )
}

#[must_use]
pub fn symbt3_fiat_shamir_domain_digest(
    scheme: PublicDigestScheme,
    domain_separators: &[&'static str],
    proof_public_statement_schedule: &'static str,
) -> Digest32 {
    let mut body = Vec::new();
    push_bytes(&mut body, proof_public_statement_schedule.as_bytes());
    push_usize(&mut body, domain_separators.len());
    for separator in domain_separators {
        push_bytes(&mut body, separator.as_bytes());
    }
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-fs-domain-policy", &body)
}

#[must_use]
pub fn symbt3_ring_module_law_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.ring_module_layout.digest(scheme));
    body.extend_from_slice(&relation.algebra_law.digest(scheme));
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ring-module-law-policy", &body)
}

#[must_use]
pub fn symbt3_ajtai_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.ajtai_commit_layout.digest(scheme));
    body.extend_from_slice(&relation.ajtai_linear_algebra_layout.digest(scheme));
    body.extend_from_slice(&relation.ajtai_norm_range_layout.digest(scheme));
    body.extend_from_slice(&relation.ajtai_params_digest);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ajtai-policy", &body)
}

#[must_use]
pub fn symbt3_norm_range_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(
        &relation
            .ajtai_norm_range_layout
            .projection_layout
            .digest(scheme),
    );
    body.extend_from_slice(&relation.ajtai_norm_range_layout.range_layout.digest(scheme));
    body.extend_from_slice(
        &relation
            .ajtai_norm_range_layout
            .monomial_embedding_layout
            .digest(scheme),
    );
    body.extend_from_slice(
        &relation
            .ajtai_norm_range_layout
            .representative_layout
            .digest(scheme),
    );
    body.push(symbt3_projection_mode_code(
        relation
            .ajtai_norm_range_layout
            .projection_layout
            .projection_mode,
    ));
    body.push(symbt3_range_mode_code(
        relation.ajtai_norm_range_layout.range_mode,
    ));
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-norm-range-policy", &body)
}

#[must_use]
pub fn symbt3_message_oracle_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.message_semantic_layout.digest(scheme));
    push_usize(
        &mut body,
        relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
    );
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-message-oracle-policy", &body)
}

#[must_use]
pub fn symbt3_batch_manifest_root_from_oracle_root(
    scheme: PublicDigestScheme,
    policy: ManifestCommitmentPolicy,
    manifest_layout_digest: &Digest32,
    manifest_oracle_root: &Digest32,
) -> Digest32 {
    match policy {
        ManifestCommitmentPolicy::DigestOfLayoutAndOracleRootV1
        | ManifestCommitmentPolicy::PublicCanonicalManifestViewV1 => {
            let mut body = Vec::new();
            body.extend_from_slice(manifest_layout_digest);
            body.extend_from_slice(manifest_oracle_root);
            digest_domain_with_scheme(scheme, b"SYMBT3_MANIFEST", &body)
        }
    }
}

#[must_use]
pub fn symbt3_manifest_root_link_is_valid(
    scheme: PublicDigestScheme,
    statement: &BatchedCpSymbt3PublicStatement,
) -> bool {
    statement.manifest_oracle_root != [0u8; 32]
        && statement.batch_manifest_root
            == symbt3_batch_manifest_root_from_oracle_root(
                scheme,
                ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
                &statement.batch_manifest_layout_digest,
                &statement.manifest_oracle_root,
            )
}

#[must_use]
pub fn symbt3_manifest_oracle_root_from_rows(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    rows: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.batch_manifest_layout.digest(scheme));
    body.extend_from_slice(
        &relation
            .batch_manifest_layout
            .source_column_layout
            .digest(scheme),
    );
    push_i64_matrix(&mut body, rows);
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-typed-batch-manifest-root",
        &body,
    )
}

#[must_use]
pub fn symbt3_manifest_oracle_root_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Digest32> {
    let values = symbt3_manifest_source_values_for_statement(relation, statement)?;
    let row_width = relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count;
    if row_width == 0
        || values.len() != statement.active_count.checked_mul(row_width)?
        || statement.active_count != relation.shape.active_count
    {
        return None;
    }

    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let mut body = Vec::new();
    body.extend_from_slice(&relation.batch_manifest_layout.digest(scheme));
    body.extend_from_slice(
        &relation
            .batch_manifest_layout
            .source_column_layout
            .digest(scheme),
    );
    push_usize(&mut body, statement.active_count);
    for row in values.chunks_exact(row_width) {
        push_i64_vec(&mut body, row);
    }
    Some(digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-typed-batch-manifest-root",
        &body,
    ))
}

#[must_use]
pub fn symbt3_canonical_manifest_root_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Digest32> {
    symbt3_manifest_oracle_root_for_statement(relation, statement)
}

#[must_use]
pub fn symbt3_batch_manifest_root_from_rows(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    rows: &[Vec<i64>],
) -> Digest32 {
    let manifest_layout_digest = relation.batch_manifest_layout.digest(scheme);
    let manifest_oracle_root = symbt3_manifest_oracle_root_from_rows(scheme, relation, rows);
    symbt3_batch_manifest_root_from_oracle_root(
        scheme,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
        &manifest_layout_digest,
        &manifest_oracle_root,
    )
}

#[must_use]
pub fn derive_symbt3_manifest_membership_challenge(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Digest32 {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let mut body = Vec::new();
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&relation.folding_protocol_id());
    body.extend_from_slice(&statement.batch_manifest_root);
    body.extend_from_slice(&statement.manifest_oracle_root);
    body.extend_from_slice(proof_oracle_root);
    body.extend_from_slice(&statement.batch_manifest_layout_digest);
    body.extend_from_slice(&statement.source_column_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.whir_parameter_digest);
    body.extend_from_slice(&symbt3_manifest_commitment_policy_digest(
        scheme,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
    ));
    push_usize(&mut body, statement.batch_capacity);
    push_usize(&mut body, statement.active_count);
    digest_domain_with_scheme(scheme, b"SYMBT3-MANIFEST-MEMBERSHIP", &body)
}

#[must_use]
pub fn symbt3_manifest_source_mle_values(rows: &[Vec<i64>]) -> Vec<u32> {
    rows.iter()
        .flat_map(|row| row.iter().map(|&value| bb_from_i64(value)))
        .collect()
}

#[must_use]
pub fn symbt3_manifest_source_mle_values_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<u32>> {
    Some(
        symbt3_manifest_source_values_for_statement(relation, statement)?
            .iter()
            .map(|&value| bb_from_i64(value))
            .collect(),
    )
}

#[must_use]
pub fn symbt3_manifest_oracle_mle_values(rows: &[Vec<i64>]) -> Vec<u32> {
    symbt3_manifest_source_mle_values(rows)
}

#[must_use]
pub fn symbt3_manifest_eval_claim_from_rows(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    rows: &[Vec<i64>],
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    let values = symbt3_manifest_oracle_mle_values(rows);
    if values.is_empty() {
        return None;
    }
    let row_count = symbt3_manifest_eval_row_count(relation, statement)?;
    let point = symbt3_manifest_membership_point(
        relation,
        statement,
        proof_oracle_root,
        row_count.trailing_zeros() as usize,
    );
    Some(bb_mle_eval_u32(&values, &point))
}

#[must_use]
pub fn symbt3_manifest_source_eval_claim_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    symbt3_virtual_source_view_eval_for_statement(relation, statement, proof_oracle_root)
}

#[must_use]
pub fn symbt3_canonical_manifest_view_eval_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    symbt3_virtual_source_view_eval_for_statement(relation, statement, proof_oracle_root)
}

#[must_use]
pub fn symbt3_virtual_source_view_eval_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    if statement.input_public_values.len() != relation.shape.active_count
        || statement.input_commitment_values.len() != relation.shape.active_count
        || statement.input_evaluation_values.len() != relation.shape.active_count
        || statement.input_accumulator_values.len() != relation.shape.active_count
        || statement.source_assignment_roots.len()
            != relation.shape.active_count
                * relation.shape.accumulator_shape.local_public_input_count
        || statement.message_oracle_roots.len() != relation.shape.accumulator_shape.num_rounds
    {
        return None;
    }
    let row_width = relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count;
    let source_len = relation.shape.active_count.checked_mul(row_width)?;
    if row_width == 0 || source_len == 0 {
        return None;
    }
    let row_count = source_len.next_power_of_two().max(1);
    let point = symbt3_manifest_membership_point(
        relation,
        statement,
        proof_oracle_root,
        row_count.trailing_zeros() as usize,
    );
    let mut acc = 0u32;
    let mut index = 0usize;
    for item in 0..relation.shape.active_count {
        let row_end = (item + 1) * row_width;
        for &value in statement.input_public_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_commitment_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_evaluation_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_accumulator_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_commitment_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        let assignment_start = item * relation.shape.accumulator_shape.local_public_input_count;
        let assignment_end =
            assignment_start + relation.shape.accumulator_shape.local_public_input_count;
        for root in &statement.source_assignment_roots[assignment_start..assignment_end] {
            for &byte in root {
                symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, byte as i64);
            }
        }
        for root in &statement.message_oracle_roots {
            for &byte in root {
                symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, byte as i64);
            }
        }
        if index > row_end {
            return None;
        }
        index = row_end;
    }
    (index == source_len).then_some(acc)
}

#[must_use]
pub fn symbt3_manifest_eval_row_count(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<usize> {
    let commitment_len = relation.symbt3_commitment_coordinate_len();
    let opening_len = relation.ring_module_layout.opening_module_dimension * D;
    let r1cs_residual_len = statement.source_assignment_roots.len()
        * relation.r1cs_evaluator_layout.num_constraints
        * D;
    let gr1cs_residual_len = relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count
        / 3;
    let projection_len = relation
        .ajtai_norm_range_layout
        .projection_layout
        .output_len;
    let manifest_len = statement.active_count.checked_mul(
        relation
            .batch_manifest_layout
            .source_column_layout
            .coordinate_count,
    )?;
    let row_len = commitment_len
        .max(opening_len)
        .max(r1cs_residual_len)
        .max(gr1cs_residual_len)
        .max(projection_len)
        .max(manifest_len);
    Some(row_len.next_power_of_two().max(1))
}

fn symbt3_absorb_virtual_view_value(acc: &mut u32, index: &mut usize, point: &[u32], value: i64) {
    let weight = bb_mle_basis_weight_u32(*index, point);
    *acc = bb_add_u32(*acc, bb_mul_u32(bb_from_i64(value), weight));
    *index += 1;
}

fn bb_mle_basis_weight_u32(index: usize, point: &[u32]) -> u32 {
    point
        .iter()
        .enumerate()
        .fold(1u32, |weight, (bit, &challenge)| {
            if ((index >> bit) & 1) == 0 {
                bb_mul_u32(weight, bb_sub_u32(1, challenge))
            } else {
                bb_mul_u32(weight, challenge)
            }
        })
}

#[must_use]
pub fn symbt3_manifest_membership_point(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
    num_vars: usize,
) -> Vec<u32> {
    let seed = derive_symbt3_manifest_membership_challenge(relation, statement, proof_oracle_root);
    (0..num_vars)
        .map(|idx| {
            let mut body = Vec::new();
            body.extend_from_slice(&seed);
            push_usize(&mut body, idx);
            let digest = digest_domain_with_scheme(
                relation.shape.accumulator_shape.digest_scheme,
                b"SYMBT3-MANIFEST-MEMBERSHIP-POINT",
                &body,
            );
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[..8]);
            (u64::from_le_bytes(bytes) % BABYBEAR_MODULUS_U64) as u32
        })
        .collect()
}

fn bb_mle_eval_u32(values: &[u32], point: &[u32]) -> u32 {
    let padded_len = 1usize << point.len();
    if padded_len == 0 {
        return 0;
    }
    let mut layer = vec![0u32; padded_len];
    for (dst, &src) in layer.iter_mut().zip(values.iter()) {
        *dst = src;
    }
    for &r in point {
        let half = layer.len() / 2;
        for idx in 0..half {
            let lo = layer[2 * idx];
            let hi = layer[2 * idx + 1];
            layer[idx] = bb_add_u32(lo, bb_mul_u32(r, bb_sub_u32(hi, lo)));
        }
        layer.truncate(half);
    }
    layer.first().copied().unwrap_or_default()
}

fn symbt3_source_assignment_root(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    values: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.r1cs_evaluator_layout.digest(scheme));
    push_i64_vec(&mut body, values);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-source-assignment-root", &body)
}

fn symbt3_source_assignment_boundary_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    roots: &[Digest32],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.r1cs_evaluator_layout.digest(scheme));
    push_usize(&mut body, roots.len());
    for root in roots {
        body.extend_from_slice(root);
    }
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-source-assignment-boundary",
        &body,
    )
}

fn symbt3_folded_gr1cs_boundary_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    source_evaluations: &[Vec<i64>],
    folded_evaluation: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.gr1cs_residual_layout.digest(scheme));
    push_i64_matrix(&mut body, source_evaluations);
    push_i64_vec(&mut body, folded_evaluation);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-folded-gr1cs-boundary", &body)
}

fn symbt3_source_ajtai_commitment_boundary_digest(
    scheme: PublicDigestScheme,
    input_commitment_values: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    push_i64_matrix(&mut body, input_commitment_values);
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-source-ajtai-commitment-boundary",
        &body,
    )
}

fn symbt3_ajtai_opening_root(
    scheme: PublicDigestScheme,
    layout: &Symbt3RingModuleLayout,
    values: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&layout.digest(scheme));
    push_i64_vec(&mut body, values);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ajtai-opening-root", &body)
}

fn symbt3_linear_fold_values(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    rows: &[Vec<i64>],
    coord_len: usize,
) -> Vec<i64> {
    let betas = derive_symbt3_beta_coefficients(relation, statement);
    let mut out = vec![0i64; coord_len];
    for (row, beta) in rows.iter().take(statement.active_count).zip(betas.iter()) {
        for (dst, &value) in out.iter_mut().zip(row.iter()) {
            *dst = dst.saturating_add(beta.saturating_mul(value));
        }
    }
    out
}

fn symbt3_ring_fold_values(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    rows: &[Vec<i64>],
    module_dimension: usize,
) -> Vec<i64> {
    let betas = derive_symbt3_beta_ring_elements(relation, statement);
    let mut out = RingVector::zero(module_dimension);
    for (row, beta) in rows.iter().take(statement.active_count).zip(betas.iter()) {
        let value = ring_vector_from_flat(row, module_dimension);
        let contribution = value.ring_scalar_mul(beta, relation.ring_module_layout.modulus);
        for (dst, elem) in out.elements.iter_mut().zip(contribution.elements.iter()) {
            dst.add_assign(elem, relation.ring_module_layout.modulus);
        }
    }
    flatten_symbt3_ring_vector(&out)
}

fn symbt3_negacyclic_mul_i64(left: &[i64], right: &[i64], q: u64) -> [i64; D] {
    let mut raw = [0i128; D];
    for i in 0..D {
        let lhs = left.get(i).copied().unwrap_or_default() as i128;
        for j in 0..D {
            let rhs = right.get(j).copied().unwrap_or_default() as i128;
            let product = lhs * rhs;
            let idx = i + j;
            if idx < D {
                raw[idx] += product;
            } else {
                raw[idx - D] -= product;
            }
        }
    }
    let mut out = [0i64; D];
    for (dst, value) in out.iter_mut().zip(raw) {
        *dst = crate::ring::arith::centered_mod(value, q);
    }
    out
}

fn ring_vector_from_flat(values: &[i64], module_dimension: usize) -> RingVector {
    let mut elements = Vec::with_capacity(module_dimension);
    for idx in 0..module_dimension {
        let mut coeffs = [0i64; D];
        let start = idx * D;
        let end = start + D;
        if let Some(slice) = values.get(start..end) {
            coeffs.copy_from_slice(slice);
        }
        elements.push(RingElement { coeffs });
    }
    RingVector { elements }
}

fn manifest_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_manifest_body_template(&mut out, &mut known, shape);
    out.len()
}

fn fs_commitment_bodies_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_fs_commitment_body_template(&mut out, &mut known, shape);
    out.len()
}

fn poseidon_fs_commitment_traces_body_len(shape: &BatchedCpStatementShape) -> usize {
    if !poseidon_fs_commitment_traces_enabled(shape) {
        return 0;
    }
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_poseidon_fs_commitment_trace_template(&mut out, &mut known, shape);
    out.len()
}

fn batch_challenge_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_batch_challenge_body_template(&mut out, &mut known, shape, None);
    out.len()
}

fn challenge_to_beta_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_challenge_to_beta_body_template(&mut out, &mut known, shape, None);
    out.len()
}

fn fold_input_reconstruction_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_fold_input_reconstruction_body_template(&mut out, &mut known, shape);
    out.len()
}

fn folded_instance_encoding_len(shape: &CpAccumulatorShape) -> usize {
    // encode_commitment: ring-vector len + kappa ring elements.
    8 + shape.commitment_kappa * D * 8
        // public_input len + folded public input ring elements.
        + 8
        + shape.folded_public_input_len * D * 8
        // evaluation_values len + tensor values.
        + 8
        + shape.folded_evaluation_count * T * D * 8
}

#[cfg(feature = "whir")]
fn folded_output_contribution_commitment_coeff_offset(
    contribution: BatchedCpOracleByteRange,
    commitment_idx: usize,
    coeff_idx: usize,
) -> usize {
    contribution.offset + 32 + 8 + commitment_idx * D * 8 + coeff_idx * 8
}

#[cfg(feature = "whir")]
fn folded_output_contribution_public_input_coeff_offset(
    shape: &CpAccumulatorShape,
    contribution: BatchedCpOracleByteRange,
    public_idx: usize,
    coeff_idx: usize,
) -> usize {
    contribution.offset
        + 32
        + 8
        + shape.commitment_kappa * D * 8
        + 8
        + public_idx * D * 8
        + coeff_idx * 8
}

#[cfg(feature = "whir")]
fn folded_output_contribution_evaluation_coeff_offset(
    shape: &CpAccumulatorShape,
    contribution: BatchedCpOracleByteRange,
    eval_idx: usize,
    tensor_row: usize,
    coeff_idx: usize,
) -> usize {
    contribution.offset
        + 32
        + 8
        + shape.commitment_kappa * D * 8
        + 8
        + shape.folded_public_input_len * D * 8
        + 8
        + eval_idx * T * D * 8
        + tensor_row * D * 8
        + coeff_idx * 8
}

fn folded_output_accumulator_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_folded_output_accumulator_body_template(&mut out, &mut known, shape, None);
    out.len()
}

fn semantic_constraint_family_code(family: BatchedCpSemanticConstraintFamily) -> u8 {
    match family {
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness => 1,
        BatchedCpSemanticConstraintFamily::ManifestMembership => 2,
        BatchedCpSemanticConstraintFamily::RoundMessageBinding => 3,
        BatchedCpSemanticConstraintFamily::ChallengeDerivation => 4,
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding => 5,
        BatchedCpSemanticConstraintFamily::FoldedOutputDerivation => 6,
        BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity => 7,
        BatchedCpSemanticConstraintFamily::OriginalR1csValidity => 8,
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy => 9,
    }
}

fn semantic_constraint_family_from_code(code: u8) -> Option<BatchedCpSemanticConstraintFamily> {
    Some(match code {
        1 => BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
        2 => BatchedCpSemanticConstraintFamily::ManifestMembership,
        3 => BatchedCpSemanticConstraintFamily::RoundMessageBinding,
        4 => BatchedCpSemanticConstraintFamily::ChallengeDerivation,
        5 => BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
        6 => BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
        7 => BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
        8 => BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
        9 => BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
        _ => return None,
    })
}

fn symbt3_algebraic_column_kind_code(kind: BatchedCpSymbt3AlgebraicColumnKind) -> u8 {
    match kind {
        BatchedCpSymbt3AlgebraicColumnKind::ActiveMask => 1,
        BatchedCpSymbt3AlgebraicColumnKind::BetaCoefficient => 2,
        BatchedCpSymbt3AlgebraicColumnKind::FoldedPublicInput => 3,
        BatchedCpSymbt3AlgebraicColumnKind::FoldedCommitment => 4,
        BatchedCpSymbt3AlgebraicColumnKind::FoldedEvaluation => 5,
        BatchedCpSymbt3AlgebraicColumnKind::AjtaiLinearCombination => 6,
        BatchedCpSymbt3AlgebraicColumnKind::OriginalR1csResidual => 7,
        BatchedCpSymbt3AlgebraicColumnKind::Gr1csResidual => 8,
        BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductLeft => 9,
        BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductRight => 10,
        BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductOutput => 11,
    }
}

fn symbt3_algebraic_column_kind_from_code(code: u8) -> Option<BatchedCpSymbt3AlgebraicColumnKind> {
    Some(match code {
        1 => BatchedCpSymbt3AlgebraicColumnKind::ActiveMask,
        2 => BatchedCpSymbt3AlgebraicColumnKind::BetaCoefficient,
        3 => BatchedCpSymbt3AlgebraicColumnKind::FoldedPublicInput,
        4 => BatchedCpSymbt3AlgebraicColumnKind::FoldedCommitment,
        5 => BatchedCpSymbt3AlgebraicColumnKind::FoldedEvaluation,
        6 => BatchedCpSymbt3AlgebraicColumnKind::AjtaiLinearCombination,
        7 => BatchedCpSymbt3AlgebraicColumnKind::OriginalR1csResidual,
        8 => BatchedCpSymbt3AlgebraicColumnKind::Gr1csResidual,
        9 => BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductLeft,
        10 => BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductRight,
        11 => BatchedCpSymbt3AlgebraicColumnKind::FoldedGr1csProductOutput,
        _ => return None,
    })
}

fn symbt3_product_law_code(value: Symbt3ProductLawId) -> u8 {
    match value {
        Symbt3ProductLawId::FieldCoordinateMulV1 => 1,
        Symbt3ProductLawId::RqNegacyclicConvolutionV1 => 2,
    }
}

fn symbt3_product_law_from_code(code: u8) -> Option<Symbt3ProductLawId> {
    Some(match code {
        1 => Symbt3ProductLawId::FieldCoordinateMulV1,
        2 => Symbt3ProductLawId::RqNegacyclicConvolutionV1,
        _ => return None,
    })
}

fn symbt3_beta_action_code(value: Symbt3BetaActionId) -> u8 {
    match value {
        Symbt3BetaActionId::ScalarFieldCoordinateV1 => 1,
        Symbt3BetaActionId::RingCoefficientActionV1 => 2,
    }
}

fn symbt3_beta_action_from_code(code: u8) -> Option<Symbt3BetaActionId> {
    Some(match code {
        1 => Symbt3BetaActionId::ScalarFieldCoordinateV1,
        2 => Symbt3BetaActionId::RingCoefficientActionV1,
        _ => return None,
    })
}

fn symbt3_ajtai_opening_mode_code(value: Symbt3AjtaiOpeningMode) -> u8 {
    match value {
        Symbt3AjtaiOpeningMode::StrictAfEqualsC => 1,
    }
}

fn symbt3_ajtai_opening_mode_from_code(code: u8) -> Option<Symbt3AjtaiOpeningMode> {
    Some(match code {
        1 => Symbt3AjtaiOpeningMode::StrictAfEqualsC,
        _ => return None,
    })
}

fn symbt3_ajtai_matrix_vector_evaluator_code(value: Symbt3AjtaiMatrixVectorEvaluatorId) -> u8 {
    match value {
        Symbt3AjtaiMatrixVectorEvaluatorId::DirectDevMatrixVectorV1 => 1,
    }
}

fn symbt3_ajtai_matrix_vector_evaluator_from_code(
    code: u8,
) -> Option<Symbt3AjtaiMatrixVectorEvaluatorId> {
    Some(match code {
        1 => Symbt3AjtaiMatrixVectorEvaluatorId::DirectDevMatrixVectorV1,
        _ => return None,
    })
}

fn symbt3_projection_mode_code(value: Symbt3ProjectionMode) -> u8 {
    match value {
        Symbt3ProjectionMode::DirectDevDenseProjectionV1 => 1,
        Symbt3ProjectionMode::StructuredBlockProjectionV1 => 2,
    }
}

fn symbt3_projection_mode_from_code(code: u8) -> Option<Symbt3ProjectionMode> {
    Some(match code {
        1 => Symbt3ProjectionMode::DirectDevDenseProjectionV1,
        2 => Symbt3ProjectionMode::StructuredBlockProjectionV1,
        _ => return None,
    })
}

fn symbt3_projection_seed_policy_code(value: Symbt3ProjectionSeedPolicy) -> u8 {
    match value {
        Symbt3ProjectionSeedPolicy::ProofBoundDeterministicV1 => 1,
    }
}

fn symbt3_projection_seed_policy_from_code(code: u8) -> Option<Symbt3ProjectionSeedPolicy> {
    Some(match code {
        1 => Symbt3ProjectionSeedPolicy::ProofBoundDeterministicV1,
        _ => return None,
    })
}

fn symbt3_range_mode_code(value: Symbt3RangeMode) -> u8 {
    match value {
        Symbt3RangeMode::DirectSignedRangeDevV1 => 1,
        Symbt3RangeMode::MonomialEmbeddingRangeV1 => 2,
    }
}

fn symbt3_range_mode_from_code(code: u8) -> Option<Symbt3RangeMode> {
    Some(match code {
        1 => Symbt3RangeMode::DirectSignedRangeDevV1,
        2 => Symbt3RangeMode::MonomialEmbeddingRangeV1,
        _ => return None,
    })
}

fn symbt3_signed_encoding_code(value: Symbt3SignedEncoding) -> u8 {
    match value {
        Symbt3SignedEncoding::CheckFieldSignedRepresentativeV1 => 1,
    }
}

fn symbt3_signed_encoding_from_code(code: u8) -> Option<Symbt3SignedEncoding> {
    Some(match code {
        1 => Symbt3SignedEncoding::CheckFieldSignedRepresentativeV1,
        _ => return None,
    })
}

fn symbt3_coefficient_encoding_code(value: Symbt3CoefficientEncoding) -> u8 {
    match value {
        Symbt3CoefficientEncoding::CenteredI64LeV1 => 1,
    }
}

fn symbt3_coefficient_encoding_from_code(code: u8) -> Option<Symbt3CoefficientEncoding> {
    Some(match code {
        1 => Symbt3CoefficientEncoding::CenteredI64LeV1,
        _ => return None,
    })
}

fn symbt3_projection_entry_distribution_code(value: Symbt3ProjectionEntryDistribution) -> u8 {
    match value {
        Symbt3ProjectionEntryDistribution::ZeroPlusMinusOneV1 => 1,
    }
}

fn symbt3_projection_entry_distribution_from_code(
    code: u8,
) -> Option<Symbt3ProjectionEntryDistribution> {
    Some(match code {
        1 => Symbt3ProjectionEntryDistribution::ZeroPlusMinusOneV1,
        _ => return None,
    })
}

fn symbt3_monomiality_mode_code(value: Symbt3MonomialityMode) -> u8 {
    match value {
        Symbt3MonomialityMode::OneHotCoefficientVectorV1 => 1,
    }
}

fn symbt3_monomiality_mode_from_code(code: u8) -> Option<Symbt3MonomialityMode> {
    Some(match code {
        1 => Symbt3MonomialityMode::OneHotCoefficientVectorV1,
        _ => return None,
    })
}

fn symbt3_constant_term_policy_code(value: Symbt3ConstantTermPolicy) -> u8 {
    match value {
        Symbt3ConstantTermPolicy::SignedRangeTableV1 => 1,
    }
}

fn symbt3_constant_term_policy_from_code(code: u8) -> Option<Symbt3ConstantTermPolicy> {
    Some(match code {
        1 => Symbt3ConstantTermPolicy::SignedRangeTableV1,
        _ => return None,
    })
}

fn symbt3_signed_convention_code(value: Symbt3SignedConvention) -> u8 {
    match value {
        Symbt3SignedConvention::CenteredExponentV1 => 1,
    }
}

fn symbt3_signed_convention_from_code(code: u8) -> Option<Symbt3SignedConvention> {
    Some(match code {
        1 => Symbt3SignedConvention::CenteredExponentV1,
        _ => return None,
    })
}

fn symbt3_canonical_rep_policy_code(value: Symbt3CanonicalRepPolicy) -> u8 {
    match value {
        Symbt3CanonicalRepPolicy::CenteredModQRepresentativeV1 => 1,
    }
}

fn symbt3_canonical_rep_policy_from_code(code: u8) -> Option<Symbt3CanonicalRepPolicy> {
    Some(match code {
        1 => Symbt3CanonicalRepPolicy::CenteredModQRepresentativeV1,
        _ => return None,
    })
}

fn symbt3_active_policy_code(value: Symbt3ActivePolicy) -> u8 {
    match value {
        Symbt3ActivePolicy::PrefixActiveCountV1 => 1,
    }
}

fn symbt3_active_policy_from_code(code: u8) -> Option<Symbt3ActivePolicy> {
    Some(match code {
        1 => Symbt3ActivePolicy::PrefixActiveCountV1,
        _ => return None,
    })
}

fn symbt3_field_extension_policy_code(value: Symbt3FieldExtensionPolicy) -> u8 {
    match value {
        Symbt3FieldExtensionPolicy::BaseFieldSingleCheckDevelopment => 1,
        Symbt3FieldExtensionPolicy::ExtensionFieldAuthorityRequired => 2,
    }
}

fn symbt3_semantic_profile_code(value: Symbt3SemanticProfile) -> u8 {
    match value {
        Symbt3SemanticProfile::Symbt3J2 => 1,
    }
}

fn symbt3_sumcheck_challenge_policy_code(value: Symbt3SumcheckChallengePolicy) -> u8 {
    match value {
        Symbt3SumcheckChallengePolicy::BaseFieldSingleChallengeDevelopment => 1,
        Symbt3SumcheckChallengePolicy::AuthorityRepetitionOrExtensionV1 => 2,
    }
}

fn symbt3_soundness_status_code(value: Symbt3SoundnessStatus) -> u8 {
    match value {
        Symbt3SoundnessStatus::DevelopmentOnly => 1,
        Symbt3SoundnessStatus::SoundnessCandidate => 2,
    }
}

fn symbt3_zk_status_code(value: Symbt3ZkStatus) -> u8 {
    match value {
        Symbt3ZkStatus::NonZkDevelopment => 1,
        Symbt3ZkStatus::NonZkIntegrityOnly => 2,
        Symbt3ZkStatus::ZkRequiredForProductRoute => 3,
    }
}

fn symbt3_routing_status_code(value: Symbt3RoutingStatus) -> u8 {
    match value {
        Symbt3RoutingStatus::ResearchOnly => 1,
        Symbt3RoutingStatus::ProductAuthority => 2,
    }
}

fn symbt3_product_policy_code(value: Symbt3ProductPolicy) -> u8 {
    match value {
        Symbt3ProductPolicy::MonolithicTypedCpOnly => 1,
        Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn => 2,
        Symbt3ProductPolicy::Symbt3ZkRequired => 3,
    }
}

fn symbt3_authority_status_code(value: Symbt3AuthorityStatus) -> u8 {
    match value {
        Symbt3AuthorityStatus::NonAuthoritativeDevelopment => 1,
        Symbt3AuthorityStatus::AuthorityCandidateV1 => 2,
    }
}

fn symbt3_manifest_component_kind_code(value: Symbt3ManifestComponentKind) -> u8 {
    match value {
        Symbt3ManifestComponentKind::PublicInput => 1,
        Symbt3ManifestComponentKind::SourceCommitmentCoordinate => 2,
        Symbt3ManifestComponentKind::SourceEvaluationCoordinate => 3,
        Symbt3ManifestComponentKind::SourceAccumulatorBoundaryCoordinate => 4,
        Symbt3ManifestComponentKind::SourceAjtaiCommitmentCoordinate => 5,
        Symbt3ManifestComponentKind::SourceAssignmentRootCoordinate => 6,
        Symbt3ManifestComponentKind::SourceMessageRootCoordinate => 7,
    }
}

fn symbt3_manifest_component_kind_from_code(code: u8) -> Option<Symbt3ManifestComponentKind> {
    Some(match code {
        1 => Symbt3ManifestComponentKind::PublicInput,
        2 => Symbt3ManifestComponentKind::SourceCommitmentCoordinate,
        3 => Symbt3ManifestComponentKind::SourceEvaluationCoordinate,
        4 => Symbt3ManifestComponentKind::SourceAccumulatorBoundaryCoordinate,
        5 => Symbt3ManifestComponentKind::SourceAjtaiCommitmentCoordinate,
        6 => Symbt3ManifestComponentKind::SourceAssignmentRootCoordinate,
        7 => Symbt3ManifestComponentKind::SourceMessageRootCoordinate,
        _ => return None,
    })
}

fn symbt3_manifest_visibility_code(value: Symbt3ManifestVisibility) -> u8 {
    match value {
        Symbt3ManifestVisibility::PublicBoundaryCoordinate => 1,
        Symbt3ManifestVisibility::CommittedPrivateRoot => 2,
    }
}

fn symbt3_manifest_visibility_from_code(code: u8) -> Option<Symbt3ManifestVisibility> {
    Some(match code {
        1 => Symbt3ManifestVisibility::PublicBoundaryCoordinate,
        2 => Symbt3ManifestVisibility::CommittedPrivateRoot,
        _ => return None,
    })
}

fn symbt3_membership_mode_code(value: Symbt3MembershipMode) -> u8 {
    match value {
        Symbt3MembershipMode::CoordinateEquality => 1,
        Symbt3MembershipMode::RootDigestEquality => 2,
    }
}

fn symbt3_membership_mode_from_code(code: u8) -> Option<Symbt3MembershipMode> {
    Some(match code {
        1 => Symbt3MembershipMode::CoordinateEquality,
        2 => Symbt3MembershipMode::RootDigestEquality,
        _ => return None,
    })
}

fn symbt3_commitment_scheme_code(value: Symbt3CommitmentSchemeId) -> u8 {
    match value {
        Symbt3CommitmentSchemeId::WhirDevOracleRootV1 => 1,
    }
}

fn symbt3_commitment_scheme_from_code(code: u8) -> Option<Symbt3CommitmentSchemeId> {
    Some(match code {
        1 => Symbt3CommitmentSchemeId::WhirDevOracleRootV1,
        _ => return None,
    })
}

fn symbt3_manifest_root_policy_code(value: Symbt3ManifestRootPolicy) -> u8 {
    match value {
        Symbt3ManifestRootPolicy::TypedDigestRootV1 => 1,
    }
}

fn symbt3_manifest_root_policy_from_code(code: u8) -> Option<Symbt3ManifestRootPolicy> {
    Some(match code {
        1 => Symbt3ManifestRootPolicy::TypedDigestRootV1,
        _ => return None,
    })
}

fn manifest_commitment_policy_code(value: ManifestCommitmentPolicy) -> u8 {
    match value {
        ManifestCommitmentPolicy::DigestOfLayoutAndOracleRootV1 => 1,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1 => 2,
    }
}

fn symbt3_message_section_kind_code(value: Symbt3MessageSectionKind) -> u8 {
    match value {
        Symbt3MessageSectionKind::SumcheckRoundPolynomial => 1,
        Symbt3MessageSectionKind::SumcheckClaimValue => 2,
        Symbt3MessageSectionKind::EvaluationPoint => 3,
        Symbt3MessageSectionKind::EvaluationValue => 4,
        Symbt3MessageSectionKind::FoldedOutputCoordinate => 5,
        Symbt3MessageSectionKind::FoldedGr1csCoordinate => 6,
        Symbt3MessageSectionKind::AjtaiOpeningCoordinate => 7,
        Symbt3MessageSectionKind::AjtaiCommitmentCoordinate => 8,
        Symbt3MessageSectionKind::ProjectionCoordinate => 9,
        Symbt3MessageSectionKind::RangeWitnessCoordinate => 10,
        Symbt3MessageSectionKind::BoundaryDigestCoordinate => 11,
    }
}

fn symbt3_message_section_kind_from_code(code: u8) -> Option<Symbt3MessageSectionKind> {
    Some(match code {
        1 => Symbt3MessageSectionKind::SumcheckRoundPolynomial,
        2 => Symbt3MessageSectionKind::SumcheckClaimValue,
        3 => Symbt3MessageSectionKind::EvaluationPoint,
        4 => Symbt3MessageSectionKind::EvaluationValue,
        5 => Symbt3MessageSectionKind::FoldedOutputCoordinate,
        6 => Symbt3MessageSectionKind::FoldedGr1csCoordinate,
        7 => Symbt3MessageSectionKind::AjtaiOpeningCoordinate,
        8 => Symbt3MessageSectionKind::AjtaiCommitmentCoordinate,
        9 => Symbt3MessageSectionKind::ProjectionCoordinate,
        10 => Symbt3MessageSectionKind::RangeWitnessCoordinate,
        11 => Symbt3MessageSectionKind::BoundaryDigestCoordinate,
        _ => return None,
    })
}

fn symbt3_message_algebra_type_code(value: Symbt3MessageAlgebraType) -> u8 {
    match value {
        Symbt3MessageAlgebraType::BabyBearFieldElement => 1,
        Symbt3MessageAlgebraType::RingCoefficient => 2,
        Symbt3MessageAlgebraType::DigestByteCoordinate => 3,
    }
}

fn symbt3_message_algebra_type_from_code(code: u8) -> Option<Symbt3MessageAlgebraType> {
    Some(match code {
        1 => Symbt3MessageAlgebraType::BabyBearFieldElement,
        2 => Symbt3MessageAlgebraType::RingCoefficient,
        3 => Symbt3MessageAlgebraType::DigestByteCoordinate,
        _ => return None,
    })
}

fn symbt3_message_visibility_code(value: Symbt3MessageVisibility) -> u8 {
    match value {
        Symbt3MessageVisibility::CommittedOracleValue => 1,
        Symbt3MessageVisibility::PublicChallengeConstant => 2,
        Symbt3MessageVisibility::PublicBoundaryCoordinate => 3,
    }
}

fn symbt3_message_visibility_from_code(code: u8) -> Option<Symbt3MessageVisibility> {
    Some(match code {
        1 => Symbt3MessageVisibility::CommittedOracleValue,
        2 => Symbt3MessageVisibility::PublicChallengeConstant,
        3 => Symbt3MessageVisibility::PublicBoundaryCoordinate,
        _ => return None,
    })
}

fn symbt3_message_binding_mode_code(value: Symbt3MessageBindingMode) -> u8 {
    match value {
        Symbt3MessageBindingMode::OracleToTraceEquality => 1,
        Symbt3MessageBindingMode::VerifierChallengeConstant => 2,
        Symbt3MessageBindingMode::SumcheckTransition => 3,
        Symbt3MessageBindingMode::FinalLocalClaim => 4,
        Symbt3MessageBindingMode::BoundaryCoordinateEquality => 5,
    }
}

fn symbt3_message_binding_mode_from_code(code: u8) -> Option<Symbt3MessageBindingMode> {
    Some(match code {
        1 => Symbt3MessageBindingMode::OracleToTraceEquality,
        2 => Symbt3MessageBindingMode::VerifierChallengeConstant,
        3 => Symbt3MessageBindingMode::SumcheckTransition,
        4 => Symbt3MessageBindingMode::FinalLocalClaim,
        5 => Symbt3MessageBindingMode::BoundaryCoordinateEquality,
        _ => return None,
    })
}

fn symbt3_message_semantic_mode_code(value: Symbt3MessageSemanticMode) -> u8 {
    match value {
        Symbt3MessageSemanticMode::TypedAlgebraicOracleV1 => 1,
        Symbt3MessageSemanticMode::NativeOracleViewV1 => 2,
    }
}

fn symbt3_message_semantic_mode_from_code(code: u8) -> Option<Symbt3MessageSemanticMode> {
    Some(match code {
        1 => Symbt3MessageSemanticMode::TypedAlgebraicOracleV1,
        2 => Symbt3MessageSemanticMode::NativeOracleViewV1,
        _ => return None,
    })
}

fn symbt3_trace_kind_code(value: Symbt3TraceKind) -> u8 {
    match value {
        Symbt3TraceKind::SumcheckRoundPolynomial => 1,
        Symbt3TraceKind::SumcheckClaimValue => 2,
        Symbt3TraceKind::EvaluationPoint => 3,
        Symbt3TraceKind::EvaluationValue => 4,
        Symbt3TraceKind::FoldedOutputCoordinate => 5,
        Symbt3TraceKind::FoldedGr1csCoordinate => 6,
        Symbt3TraceKind::AjtaiOpeningCoordinate => 7,
        Symbt3TraceKind::AjtaiCommitmentCoordinate => 8,
        Symbt3TraceKind::ProjectionCoordinate => 9,
        Symbt3TraceKind::RangeWitnessCoordinate => 10,
    }
}

fn symbt3_trace_kind_from_code(code: u8) -> Option<Symbt3TraceKind> {
    Some(match code {
        1 => Symbt3TraceKind::SumcheckRoundPolynomial,
        2 => Symbt3TraceKind::SumcheckClaimValue,
        3 => Symbt3TraceKind::EvaluationPoint,
        4 => Symbt3TraceKind::EvaluationValue,
        5 => Symbt3TraceKind::FoldedOutputCoordinate,
        6 => Symbt3TraceKind::FoldedGr1csCoordinate,
        7 => Symbt3TraceKind::AjtaiOpeningCoordinate,
        8 => Symbt3TraceKind::AjtaiCommitmentCoordinate,
        9 => Symbt3TraceKind::ProjectionCoordinate,
        10 => Symbt3TraceKind::RangeWitnessCoordinate,
        _ => return None,
    })
}

fn symbt3_message_coordinate_map_mode_code(value: Symbt3MessageCoordinateMapMode) -> u8 {
    match value {
        Symbt3MessageCoordinateMapMode::ContiguousOffsetV1 => 1,
    }
}

fn symbt3_message_coordinate_map_mode_from_code(
    code: u8,
) -> Option<Symbt3MessageCoordinateMapMode> {
    Some(match code {
        1 => Symbt3MessageCoordinateMapMode::ContiguousOffsetV1,
        _ => return None,
    })
}

fn symbt3_constraint_family_code(family: BatchedCpSymbt3ConstraintFamily) -> u8 {
    match family {
        BatchedCpSymbt3ConstraintFamily::ChallengeToBeta => 1,
        BatchedCpSymbt3ConstraintFamily::FoldedPublicInputLinearIdentity => 2,
        BatchedCpSymbt3ConstraintFamily::FoldedCommitmentLinearIdentity => 3,
        BatchedCpSymbt3ConstraintFamily::FoldedEvaluationLinearIdentity => 4,
        BatchedCpSymbt3ConstraintFamily::FoldedAccumulatorBoundaryIdentity => 5,
        BatchedCpSymbt3ConstraintFamily::RingBetaAction => 6,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningIdentity => 7,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentIdentity => 8,
        BatchedCpSymbt3ConstraintFamily::AjtaiFoldedResidualZero => 9,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningLinearIdentity => 10,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentLinearIdentity => 11,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiMapConsistency => 12,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectionConsistency => 13,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectedRangeBound => 14,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiMonomialEmbeddingConsistency => 15,
        BatchedCpSymbt3ConstraintFamily::CommittedSourceR1csResidualValidity => 16,
        BatchedCpSymbt3ConstraintFamily::FoldedGr1csResidualValidity => 17,
        BatchedCpSymbt3ConstraintFamily::FoldedGr1csProductResidualZeroCheck => 18,
        BatchedCpSymbt3ConstraintFamily::BatchManifestRootBinding => 19,
        BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership => 20,
        BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim => 21,
        BatchedCpSymbt3ConstraintFamily::SourceAssignmentRootManifestBinding => 22,
        BatchedCpSymbt3ConstraintFamily::SourceMessageRootManifestBinding => 23,
        BatchedCpSymbt3ConstraintFamily::RoundMessageLayoutValidity => 24,
        BatchedCpSymbt3ConstraintFamily::RoundChallengePrefixBinding => 25,
        BatchedCpSymbt3ConstraintFamily::NativeMessageOracleViews => 26,
        BatchedCpSymbt3ConstraintFamily::MessageToTraceColumnBinding => 27,
        BatchedCpSymbt3ConstraintFamily::SumcheckRoundClaimTransition => 28,
        BatchedCpSymbt3ConstraintFamily::SumcheckFinalLocalClaimBinding => 29,
        BatchedCpSymbt3ConstraintFamily::FoldingMessageBoundaryConsistency => 30,
        BatchedCpSymbt3ConstraintFamily::FoldedAjtaiStructuredProjectionConsistency => 31,
        BatchedCpSymbt3ConstraintFamily::ProjectedOpeningMonomialEmbedding => 32,
        BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRangeConstantTerm => 33,
        BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRepresentativeValidity => 34,
        BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency => 35,
    }
}

fn symbt3_constraint_family_from_code(code: u8) -> Option<BatchedCpSymbt3ConstraintFamily> {
    Some(match code {
        1 => BatchedCpSymbt3ConstraintFamily::ChallengeToBeta,
        2 => BatchedCpSymbt3ConstraintFamily::FoldedPublicInputLinearIdentity,
        3 => BatchedCpSymbt3ConstraintFamily::FoldedCommitmentLinearIdentity,
        4 => BatchedCpSymbt3ConstraintFamily::FoldedEvaluationLinearIdentity,
        5 => BatchedCpSymbt3ConstraintFamily::FoldedAccumulatorBoundaryIdentity,
        6 => BatchedCpSymbt3ConstraintFamily::RingBetaAction,
        7 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningIdentity,
        8 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentIdentity,
        9 => BatchedCpSymbt3ConstraintFamily::AjtaiFoldedResidualZero,
        10 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiOpeningLinearIdentity,
        11 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiCommitmentLinearIdentity,
        12 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiMapConsistency,
        13 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectionConsistency,
        14 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiProjectedRangeBound,
        15 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiMonomialEmbeddingConsistency,
        16 => BatchedCpSymbt3ConstraintFamily::CommittedSourceR1csResidualValidity,
        17 => BatchedCpSymbt3ConstraintFamily::FoldedGr1csResidualValidity,
        18 => BatchedCpSymbt3ConstraintFamily::FoldedGr1csProductResidualZeroCheck,
        19 => BatchedCpSymbt3ConstraintFamily::BatchManifestRootBinding,
        20 => BatchedCpSymbt3ConstraintFamily::SourceManifestColumnMembership,
        21 => BatchedCpSymbt3ConstraintFamily::ManifestEvaluationClaim,
        22 => BatchedCpSymbt3ConstraintFamily::SourceAssignmentRootManifestBinding,
        23 => BatchedCpSymbt3ConstraintFamily::SourceMessageRootManifestBinding,
        24 => BatchedCpSymbt3ConstraintFamily::RoundMessageLayoutValidity,
        25 => BatchedCpSymbt3ConstraintFamily::RoundChallengePrefixBinding,
        26 => BatchedCpSymbt3ConstraintFamily::NativeMessageOracleViews,
        27 => BatchedCpSymbt3ConstraintFamily::MessageToTraceColumnBinding,
        28 => BatchedCpSymbt3ConstraintFamily::SumcheckRoundClaimTransition,
        29 => BatchedCpSymbt3ConstraintFamily::SumcheckFinalLocalClaimBinding,
        30 => BatchedCpSymbt3ConstraintFamily::FoldingMessageBoundaryConsistency,
        31 => BatchedCpSymbt3ConstraintFamily::FoldedAjtaiStructuredProjectionConsistency,
        32 => BatchedCpSymbt3ConstraintFamily::ProjectedOpeningMonomialEmbedding,
        33 => BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRangeConstantTerm,
        34 => BatchedCpSymbt3ConstraintFamily::ProjectedOpeningRepresentativeValidity,
        35 => BatchedCpSymbt3ConstraintFamily::AccumulatorTransitionConsistency,
        _ => return None,
    })
}

#[must_use]
pub fn digest_ajtai_params(scheme: PublicDigestScheme, ajtai: &AjtaiParams) -> Digest32 {
    let mut body = Vec::new();
    push_bytes(&mut body, b"symphony-ajtai-params-v1");
    push_usize(&mut body, ajtai.kappa);
    push_usize(&mut body, ajtai.n);
    body.extend_from_slice(&ajtai.q.to_le_bytes());
    push_usize(&mut body, ajtai.a.len());
    for row in &ajtai.a {
        push_usize(&mut body, row.len());
        for elem in row {
            encode_ring_element(&mut body, elem);
        }
    }
    digest_domain_with_scheme(scheme, b"batched-cp-ajtai-params", &body)
}

#[must_use]
pub fn digest_r1cs_matrices(scheme: PublicDigestScheme, r1cs: &R1CSMatrices) -> Digest32 {
    let mut body = Vec::new();
    push_bytes(&mut body, b"symphony-r1cs-matrices-v1");
    push_usize(&mut body, r1cs.num_constraints);
    push_usize(&mut body, r1cs.num_variables);
    push_usize(&mut body, r1cs.num_public);
    encode_sparse_matrix(&mut body, &r1cs.a);
    encode_sparse_matrix(&mut body, &r1cs.b);
    encode_sparse_matrix(&mut body, &r1cs.c);
    digest_domain_with_scheme(scheme, b"batched-cp-r1cs-matrices", &body)
}

#[must_use]
pub fn symbt3_accumulator_coordinates_digest(
    scheme: PublicDigestScheme,
    role: &[u8],
    coordinates: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    push_bytes(&mut body, b"symphony-symbt3-accumulator-coordinates-v1");
    push_bytes(&mut body, role);
    push_i64_vec(&mut body, coordinates);
    digest_domain_with_scheme(scheme, b"SYMBT3_ACCUMULATOR_COORDINATES", &body)
}

#[must_use]
pub fn symbt3_accumulator_transition_profile_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    push_bytes(
        &mut body,
        b"symphony-symbt3-accumulator-transition-profile-v1",
    );
    push_bytes(
        &mut body,
        b"coordinatewise-babybear-linear-v1:new=rho*old+(1-rho)*folded",
    );
    body.extend_from_slice(&relation.ring_module_layout.digest(scheme));
    body.extend_from_slice(&relation.algebra_law.digest(scheme));
    body.extend_from_slice(&relation.shape.shape_id);
    push_usize(&mut body, relation.symbt3_accumulator_coordinate_len());
    digest_domain_with_scheme(scheme, b"SYMBT3_ACC_TRANSITION_PROFILE", &body)
}

#[must_use]
pub fn derive_symbt3_accumulator_transition_challenge(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> u32 {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let mut body = Vec::new();
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&relation.folding_protocol_id());
    body.extend_from_slice(&statement.shape_id);
    push_usize(&mut body, statement.batch_capacity);
    push_usize(&mut body, statement.active_count);
    body.extend_from_slice(&statement.old_accumulator_digest);
    body.extend_from_slice(&statement.folded_output_accumulator_root);
    push_i64_vec(&mut body, &statement.folded_accumulator_coordinates);
    body.extend_from_slice(&statement.ring_module_layout_digest);
    body.extend_from_slice(&statement.algebra_law_digest);
    body.extend_from_slice(&symbt3_accumulator_transition_profile_digest(
        scheme, relation,
    ));
    let digest = digest_domain_with_scheme(scheme, b"SYMBT3_ACC_TRANSITION", &body);
    let mut wide = [0u8; 8];
    wide.copy_from_slice(&digest[..8]);
    (u64::from_le_bytes(wide) % BABYBEAR_MODULUS_U64) as u32
}

#[must_use]
pub fn symbt3_accumulator_transition_coordinates(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<i64>> {
    let len = relation.symbt3_accumulator_coordinate_len();
    if statement.old_accumulator_coordinates.len() != len
        || statement.folded_accumulator_coordinates.len() != len
    {
        return None;
    }
    let rho = derive_symbt3_accumulator_transition_challenge(relation, statement);
    let one_minus_rho = bb_sub_u32(1, rho);
    Some(
        statement
            .old_accumulator_coordinates
            .iter()
            .zip(statement.folded_accumulator_coordinates.iter())
            .map(|(&old, &folded)| {
                let old_term = bb_mul_u32(rho, bb_from_i64(old));
                let folded_term = bb_mul_u32(one_minus_rho, bb_from_i64(folded));
                i64::from(bb_add_u32(old_term, folded_term))
            })
            .collect(),
    )
}

fn encode_sparse_matrix(out: &mut Vec<u8>, matrix: &crate::r1cs::SparseMatrix) {
    push_usize(out, matrix.num_rows);
    push_usize(out, matrix.num_cols);
    push_usize(out, matrix.entries.len());
    for &(row, col, value) in &matrix.entries {
        push_usize(out, row);
        push_usize(out, col);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn validate_product_oracle_layout(
    witness: &BatchedCpWitnessBundle,
    shape: &BatchedCpStatementShape,
) -> Result<(), BatchedCpError> {
    if witness.items.len() != shape.active_count
        || witness.witness_oracle_rows.len() != shape.batch_capacity
        || witness.round_message_oracles.len() != shape.round_message_lens.len()
    {
        return Err(BatchedCpError::WitnessOracleMismatch);
    }
    for (idx, row) in witness.witness_oracle_rows.iter().enumerate() {
        let expected_len = if idx < shape.active_count {
            shape.witness_row_len
        } else {
            0
        };
        if row.len() != expected_len {
            return Err(BatchedCpError::WitnessOracleMismatch);
        }
    }
    for (round, rows) in witness.round_message_oracles.iter().enumerate() {
        if rows.len() != shape.batch_capacity {
            return Err(BatchedCpError::RoundMessageOracleMismatch);
        }
        for (idx, message) in rows.iter().enumerate() {
            let expected_len = if idx < shape.active_count {
                shape.round_message_lens[round]
            } else {
                0
            };
            if message.len() != expected_len {
                return Err(BatchedCpError::RoundMessageOracleMismatch);
            }
        }
    }
    Ok(())
}

fn encode_manifest_body(shape: &BatchedCpStatementShape, items: &[BatchedCpItem]) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"symphony-batched-cp-manifest-v1");
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, shape.batch_log_size);
    push_usize(&mut out, shape.batch_capacity);
    push_usize(&mut out, shape.active_count);
    for idx in 0..shape.batch_capacity {
        push_usize(&mut out, idx);
        if let Some(item) = items.get(idx) {
            out.push(1);
            out.extend_from_slice(&item.item_tag);
            push_bytes(&mut out, &encode_public_statement(&item.public));
        } else {
            out.push(0);
            out.extend_from_slice(&[0u8; 32]);
            push_bytes(&mut out, &[]);
        }
    }
    out
}

fn push_known_manifest_body_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
) {
    push_known_bytes(bytes, known, b"symphony-batched-cp-manifest-v1");
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.batch_log_size);
    push_known_usize(bytes, known, shape.batch_capacity);
    push_known_usize(bytes, known, shape.active_count);
    for idx in 0..shape.batch_capacity {
        push_known_usize(bytes, known, idx);
        push_known_u8(bytes, known, u8::from(idx < shape.active_count));
        if idx < shape.active_count {
            push_private_raw(bytes, known, 32);
            push_private_bytes(bytes, known, shape.accumulator_shape.public_statement_len);
        } else {
            push_known_raw(bytes, known, &[0u8; 32]);
            push_known_bytes(bytes, known, &[]);
        }
    }
}

fn encode_fs_commitment_bodies_body(
    shape: &BatchedCpStatementShape,
    items: &[BatchedCpItem],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"symphony-batched-cp-fs-commitment-bodies-v1");
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, shape.accumulator_shape.num_rounds);
    push_usize(&mut out, shape.active_count);
    for round in 0..shape.accumulator_shape.num_rounds {
        push_usize(&mut out, round);
        for idx in 0..shape.active_count {
            push_usize(&mut out, idx);
            out.push(1);
            let message = &items[idx].witness.fs_messages[round];
            push_usize(&mut out, message.len());
            out.extend_from_slice(message);
            out.extend_from_slice(&items[idx].witness.fs_openings[round]);
        }
    }
    out
}

fn push_known_fs_commitment_body_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
) {
    push_known_bytes(bytes, known, b"symphony-batched-cp-fs-commitment-bodies-v1");
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.accumulator_shape.num_rounds);
    push_known_usize(bytes, known, shape.active_count);
    for (round, &message_len) in shape.accumulator_shape.fs_message_lens.iter().enumerate() {
        push_known_usize(bytes, known, round);
        for idx in 0..shape.active_count {
            push_known_usize(bytes, known, idx);
            push_known_u8(bytes, known, 1);
            push_known_usize(bytes, known, message_len);
            push_private_raw(bytes, known, message_len);
            push_private_raw(bytes, known, shape.accumulator_shape.fs_opening_len);
        }
    }
}

fn encode_poseidon_fs_commitment_traces_body(
    shape: &BatchedCpStatementShape,
    items: &[BatchedCpItem],
) -> Vec<u8> {
    if !poseidon_fs_commitment_traces_enabled(shape) {
        return Vec::new();
    }
    let mut out = Vec::new();
    push_bytes(
        &mut out,
        b"symphony-batched-cp-poseidon-fs-commitment-traces-v1",
    );
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, shape.accumulator_shape.num_rounds);
    push_usize(&mut out, shape.active_count);
    for round in 0..shape.accumulator_shape.num_rounds {
        push_usize(&mut out, round);
        for (idx, item) in items.iter().take(shape.active_count).enumerate() {
            push_usize(&mut out, idx);
            out.push(1);
            let body = poseidon_fs_commitment_body_from_item(item, round);
            let (input_values, output_values, aux_values) =
                poseidon_fs_commitment_trace_values(&body);
            push_usize(&mut out, output_values.len());
            for value in output_values {
                out.extend_from_slice(&value.to_le_bytes());
            }
            push_usize(&mut out, input_values.len());
            for value in input_values {
                out.extend_from_slice(&value.to_le_bytes());
            }
            push_usize(&mut out, aux_values.len());
            for value in aux_values {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    out
}

fn push_known_poseidon_fs_commitment_trace_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
) {
    if !poseidon_fs_commitment_traces_enabled(shape) {
        return;
    }
    push_known_bytes(
        bytes,
        known,
        b"symphony-batched-cp-poseidon-fs-commitment-traces-v1",
    );
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.accumulator_shape.num_rounds);
    push_known_usize(bytes, known, shape.active_count);
    for (round, &message_len) in shape.accumulator_shape.fs_message_lens.iter().enumerate() {
        push_known_usize(bytes, known, round);
        let input_len =
            poseidon_fs_commitment_input_len(message_len, shape.accumulator_shape.fs_opening_len);
        let aux_len = poseidon_fs_commitment_aux_len(input_len);
        for idx in 0..shape.active_count {
            push_known_usize(bytes, known, idx);
            push_known_u8(bytes, known, 1);
            push_known_usize(bytes, known, 8);
            push_private_raw(bytes, known, 8 * 4);
            push_known_usize(bytes, known, input_len);
            push_private_raw(bytes, known, input_len * 4);
            push_known_usize(bytes, known, aux_len);
            push_private_raw(bytes, known, aux_len * 4);
        }
    }
}

fn poseidon_fs_commitment_traces_enabled(shape: &BatchedCpStatementShape) -> bool {
    #[cfg(feature = "whir")]
    {
        shape.accumulator_shape.digest_scheme == PublicDigestScheme::Poseidon2BabyBear
    }
    #[cfg(not(feature = "whir"))]
    {
        let _ = shape;
        false
    }
}

fn encode_batch_challenge_body(
    shape: &BatchedCpStatementShape,
    manifest_digest: Digest32,
    round_commitments: &BatchRoundMessageCommitments,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_bytes(&mut body, b"symphony-batched-cp-challenges-v1");
    body.extend_from_slice(&shape.shape_id);
    push_usize(&mut body, shape.batch_log_size);
    push_usize(&mut body, shape.batch_capacity);
    push_usize(&mut body, shape.active_count);
    body.extend_from_slice(&manifest_digest);
    body.extend_from_slice(&shape.accumulator_shape.whir_parameter_digest);
    push_usize(&mut body, round_commitments.commitments.len());
    for commitment in &round_commitments.commitments {
        body.extend_from_slice(commitment);
    }
    body
}

fn push_known_batch_challenge_body_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
    statement: Option<&BatchedCpPublicStatement>,
) {
    push_known_bytes(bytes, known, b"symphony-batched-cp-challenges-v1");
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.batch_log_size);
    push_known_usize(bytes, known, shape.batch_capacity);
    push_known_usize(bytes, known, shape.active_count);
    if let Some(statement) = statement {
        push_known_raw(bytes, known, &statement.manifest_digest);
    } else {
        push_private_raw(bytes, known, 32);
    }
    push_known_raw(bytes, known, &shape.accumulator_shape.whir_parameter_digest);
    push_known_usize(bytes, known, shape.round_message_lens.len());
    for round in 0..shape.round_message_lens.len() {
        if let Some(statement) = statement {
            push_known_raw(bytes, known, &statement.round_message_commitments[round]);
        } else {
            push_private_raw(bytes, known, 32);
        }
    }
}

fn encode_challenge_to_beta_body(
    shape: &BatchedCpStatementShape,
    challenge_digest: Digest32,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_bytes(&mut body, b"symphony-batched-cp-challenge-to-beta-v1");
    body.extend_from_slice(&shape.shape_id);
    push_usize(&mut body, shape.batch_log_size);
    push_usize(&mut body, shape.batch_capacity);
    push_usize(&mut body, shape.active_count);
    body.extend_from_slice(&challenge_digest);
    encode_ring_element(&mut body, &challenge_digest_to_beta(&challenge_digest));
    body
}

fn push_known_challenge_to_beta_body_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
    statement: Option<&BatchedCpPublicStatement>,
) {
    push_known_bytes(bytes, known, b"symphony-batched-cp-challenge-to-beta-v1");
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.batch_log_size);
    push_known_usize(bytes, known, shape.batch_capacity);
    push_known_usize(bytes, known, shape.active_count);
    if let Some(statement) = statement {
        push_known_raw(bytes, known, &statement.batch_challenge_digest);
        push_known_raw(
            bytes,
            known,
            &encode_ring_element_bytes(&challenge_digest_to_beta(
                &statement.batch_challenge_digest,
            )),
        );
    } else {
        push_private_raw(bytes, known, 32);
        push_private_raw(bytes, known, D * 8);
    }
}

fn encode_fold_input_reconstruction_body(
    shape: &BatchedCpStatementShape,
    items: &[BatchedCpItem],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_bytes(
        &mut body,
        b"symphony-batched-cp-fold-input-reconstruction-v1",
    );
    body.extend_from_slice(&shape.shape_id);
    push_usize(&mut body, shape.batch_log_size);
    push_usize(&mut body, shape.batch_capacity);
    push_usize(&mut body, shape.active_count);
    for (idx, item) in items.iter().enumerate() {
        push_usize(&mut body, idx);
        for (round, input) in item.witness.fold_inputs.iter().enumerate() {
            push_usize(&mut body, round);
            push_bytes(&mut body, &input.commitment_bytes);
            push_i64_vec(&mut body, &input.public_input);
            push_bytes(&mut body, &input.eval_values_bytes);
        }
    }
    body
}

fn push_known_fold_input_reconstruction_body_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
) {
    push_known_bytes(
        bytes,
        known,
        b"symphony-batched-cp-fold-input-reconstruction-v1",
    );
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.batch_log_size);
    push_known_usize(bytes, known, shape.batch_capacity);
    push_known_usize(bytes, known, shape.active_count);
    for idx in 0..shape.active_count {
        push_known_usize(bytes, known, idx);
        for round in 0..shape.accumulator_shape.num_rounds {
            push_known_usize(bytes, known, round);
            push_private_bytes(
                bytes,
                known,
                shape.accumulator_shape.fold_input_commitment_lens[round],
            );
            push_known_usize(
                bytes,
                known,
                shape.accumulator_shape.fold_input_public_input_lens[round],
            );
            push_private_raw(
                bytes,
                known,
                shape.accumulator_shape.fold_input_public_input_lens[round] * 8,
            );
            push_private_bytes(
                bytes,
                known,
                shape.accumulator_shape.fold_input_eval_message_lens[round],
            );
        }
    }
}

fn encode_folded_output_accumulator_oracle_body(
    shape: &BatchedCpStatementShape,
    folded_output_accumulator_root: Digest32,
    items: &[BatchedCpItem],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_bytes(
        &mut body,
        b"symphony-batched-cp-folded-output-accumulator-v1",
    );
    body.extend_from_slice(&shape.shape_id);
    push_usize(&mut body, shape.batch_log_size);
    push_usize(&mut body, shape.batch_capacity);
    push_usize(&mut body, shape.active_count);
    body.extend_from_slice(&folded_output_accumulator_root);
    push_usize(&mut body, items.len());
    for item in items {
        body.extend_from_slice(&encode_folded_output_contribution(item));
    }
    body
}

fn push_known_folded_output_accumulator_body_template(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
    statement: Option<&BatchedCpPublicStatement>,
) {
    push_known_bytes(
        bytes,
        known,
        b"symphony-batched-cp-folded-output-accumulator-v1",
    );
    push_known_raw(bytes, known, &shape.shape_id);
    push_known_usize(bytes, known, shape.batch_log_size);
    push_known_usize(bytes, known, shape.batch_capacity);
    push_known_usize(bytes, known, shape.active_count);
    if let Some(statement) = statement {
        push_known_raw(bytes, known, &statement.folded_output_accumulator_root);
    } else {
        push_private_raw(bytes, known, 32);
    }
    push_known_usize(bytes, known, shape.active_count);
    for _ in 0..shape.active_count {
        push_private_raw(
            bytes,
            known,
            shape.accumulator_shape.folded_output_contribution_len,
        );
    }
}

fn challenge_digest_to_beta(challenge_digest: &Digest32) -> RingElement {
    debug_assert_eq!(D, challenge_digest.len() * 2);
    let mut coeffs = [0i64; D];
    for (byte_idx, &byte) in challenge_digest.iter().enumerate() {
        let even = 2 * byte_idx;
        let odd = even + 1;
        if odd >= D {
            break;
        }
        let d0 = (byte % 5) as i64;
        let d1 = ((byte / 5) % 5) as i64;
        coeffs[even] = d0 - 2;
        coeffs[odd] = d1 - 2;
    }
    RingElement { coeffs }
}

fn gr1cs_hadamard_evaluation_offsets(message: &[u8], count: usize) -> Option<Vec<usize>> {
    let mut pos = 0usize;
    skip_sumcheck_proof(message, &mut pos)?;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        let end = pos.checked_add(T * D * 8)?;
        if end > message.len() {
            return None;
        }
        offsets.push(pos);
        pos = end;
    }
    Some(offsets)
}

fn gr1cs_message_sections(
    proof: &crate::rok::gr1cs::GR1CSProof,
    message_len: usize,
) -> Option<Vec<BatchedCpGr1csMessageSection>> {
    let mut offset = 0usize;
    let mut sections = Vec::new();
    push_message_section(
        &mut sections,
        BatchedCpGr1csMessageSectionKind::Header,
        &mut offset,
        sumcheck_proof_encoded_len(&proof.hadamard_proof.sumcheck_proof)?,
    )?;
    push_message_section(
        &mut sections,
        BatchedCpGr1csMessageSectionKind::HadamardEvals,
        &mut offset,
        proof
            .hadamard_proof
            .evaluation_matrix
            .iter()
            .map(tensor_encoded_len)
            .sum(),
    )?;

    let range_payload_len = 8usize
        .checked_add(
            proof
                .range_proof
                .monomial_commitments
                .iter()
                .map(commitment_encoded_len)
                .try_fold(0usize, |acc, len| acc.checked_add(len))?,
        )?
        .checked_add(8)?
        .checked_add(
            proof
                .range_proof
                .monomial_vectors
                .iter()
                .map(|vector| 8usize.checked_add(vector.len().checked_mul(D)?.checked_mul(8)?))
                .try_fold(0usize, |acc, len| acc.checked_add(len?))?,
        )?;
    push_message_section(
        &mut sections,
        BatchedCpGr1csMessageSectionKind::RangePayload,
        &mut offset,
        range_payload_len,
    )?;

    let monomial_payload_len =
        sumcheck_proof_encoded_len(&proof.range_proof.monomial_proof.sumcheck_proof)?
            .checked_add(8)?
            .checked_add(
                proof
                    .range_proof
                    .monomial_proof
                    .evaluations
                    .iter()
                    .map(tensor_encoded_len)
                    .try_fold(0usize, |acc, len| acc.checked_add(len))?,
            )?;
    push_message_section(
        &mut sections,
        BatchedCpGr1csMessageSectionKind::MonomialPayload,
        &mut offset,
        monomial_payload_len,
    )?;
    push_message_section(
        &mut sections,
        BatchedCpGr1csMessageSectionKind::SquareEvals,
        &mut offset,
        8usize.checked_add(
            proof
                .range_proof
                .monomial_proof
                .sq_evaluations
                .len()
                .checked_mul(16)?,
        )?,
    )?;
    push_message_section(
        &mut sections,
        BatchedCpGr1csMessageSectionKind::ProjectedValues,
        &mut offset,
        8usize.checked_add(proof.range_proof.projected_values.len().checked_mul(8)?)?,
    )?;
    if offset < message_len {
        let trailing_len = message_len - offset;
        push_message_section(
            &mut sections,
            BatchedCpGr1csMessageSectionKind::TrailingFrame,
            &mut offset,
            trailing_len,
        )?;
    }
    message_sections_are_contiguous(&sections, message_len).then_some(sections)
}

fn push_message_section(
    sections: &mut Vec<BatchedCpGr1csMessageSection>,
    kind: BatchedCpGr1csMessageSectionKind,
    offset: &mut usize,
    len: usize,
) -> Option<()> {
    let start = *offset;
    *offset = offset.checked_add(len)?;
    sections.push(BatchedCpGr1csMessageSection {
        kind,
        offset: start,
        len,
    });
    Some(())
}

fn message_sections_are_contiguous(
    sections: &[BatchedCpGr1csMessageSection],
    message_len: usize,
) -> bool {
    let mut cursor = 0usize;
    for section in sections {
        if section.offset != cursor {
            return false;
        }
        let Some(next) = cursor.checked_add(section.len) else {
            return false;
        };
        cursor = next;
    }
    cursor == message_len
}

fn sumcheck_proof_encoded_len(proof: &crate::sumcheck::SumcheckProof) -> Option<usize> {
    proof.round_messages.iter().try_fold(8usize, |acc, round| {
        acc.checked_add(8)?
            .checked_add(round.evaluations.len().checked_mul(16)?)
    })
}

fn tensor_encoded_len(value: &crate::ring::tensor::TensorElement) -> usize {
    value.data.len() * D * 8
}

fn commitment_encoded_len(value: &crate::commitment::Commitment) -> usize {
    8 + value.value.elements.len() * D * 8
}

fn skip_sumcheck_proof(bytes: &[u8], pos: &mut usize) -> Option<()> {
    let rounds = read_u64_at(bytes, pos)? as usize;
    for _ in 0..rounds {
        let evals = read_u64_at(bytes, pos)? as usize;
        *pos = pos.checked_add(evals.checked_mul(16)?)?;
        if *pos > bytes.len() {
            return None;
        }
    }
    Some(())
}

fn read_u64_at(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let chunk = bytes.get(*pos..end)?;
    *pos = end;
    Some(u64::from_le_bytes(chunk.try_into().ok()?))
}

fn encode_ring_element_bytes(value: &RingElement) -> Vec<u8> {
    let mut out = Vec::with_capacity(D * 8);
    encode_ring_element(&mut out, value);
    out
}

fn encode_statement_shape(out: &mut Vec<u8>, shape: &BatchedCpStatementShape) {
    push_bytes(out, b"symphony-batched-cp-statement-shape-v1");
    out.extend_from_slice(&shape.shape_id);
    push_usize(out, shape.batch_log_size);
    push_usize(out, shape.batch_capacity);
    push_usize(out, shape.active_count);
    push_usize(out, shape.witness_row_len);
    push_usize_vec(out, &shape.round_message_lens);
    push_bytes(out, &shape.accumulator_shape.canonical_bytes());
}

fn decode_statement_shape(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<BatchedCpStatementShape, BatchedCpError> {
    let domain = read_bytes(bytes, pos)?;
    if domain != b"symphony-batched-cp-statement-shape-v1" {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    let shape_id = read_digest(bytes, pos)?;
    let batch_log_size = read_usize(bytes, pos)?;
    let batch_capacity = read_usize(bytes, pos)?;
    let active_count = read_usize(bytes, pos)?;
    let witness_row_len = read_usize(bytes, pos)?;
    let round_message_lens = read_usize_vec(bytes, pos)?;
    let accumulator_bytes = read_bytes(bytes, pos)?;
    let accumulator_shape = decode_accumulator_shape(&accumulator_bytes)?;
    let shape = BatchedCpStatementShape {
        accumulator_shape,
        shape_id,
        batch_log_size,
        batch_capacity,
        active_count,
        witness_row_len,
        round_message_lens: round_message_lens.clone(),
    };
    if active_count == 0
        || batch_capacity != active_count.next_power_of_two()
        || batch_log_size != batch_capacity.trailing_zeros() as usize
        || witness_row_len != estimate_witness_row_len(&shape.accumulator_shape)
        || round_message_lens != shape.accumulator_shape.fs_message_lens
        || shape_id != shape.accumulator_shape.shape_id()
    {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    Ok(shape)
}

fn decode_accumulator_shape(bytes: &[u8]) -> Result<CpAccumulatorShape, BatchedCpError> {
    let mut pos = 0;
    let domain = read_bytes(bytes, &mut pos)?;
    if domain != b"symphony-cp-accumulator-shape-v1" {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    let digest_scheme = read_digest_scheme(bytes, &mut pos)?;
    let r1cs_num_constraints = read_usize(bytes, &mut pos)?;
    let r1cs_num_variables = read_usize(bytes, &mut pos)?;
    let r1cs_num_public = read_usize(bytes, &mut pos)?;
    let local_public_input_count = read_usize(bytes, &mut pos)?;
    let public_statement_len = read_usize(bytes, &mut pos)?;
    let num_rounds = read_usize(bytes, &mut pos)?;
    let fs_message_lens = read_usize_vec(bytes, &mut pos)?;
    let fs_commitment_len = read_usize(bytes, &mut pos)?;
    let fs_opening_len = read_usize(bytes, &mut pos)?;
    let fold_input_commitment_lens = read_usize_vec(bytes, &mut pos)?;
    let fold_input_public_input_lens = read_usize_vec(bytes, &mut pos)?;
    let fold_input_eval_message_lens = read_usize_vec(bytes, &mut pos)?;
    let gr1cs_hadamard_eval_offsets = read_nested_usize_vec(bytes, &mut pos)?;
    let gr1cs_message_sections = read_gr1cs_message_sections(bytes, &mut pos)?;
    let original_witness_lens = read_usize_vec(bytes, &mut pos)?;
    let commitment_kappa = read_usize(bytes, &mut pos)?;
    let commitment_d = read_usize(bytes, &mut pos)?;
    let folded_public_input_len = read_usize(bytes, &mut pos)?;
    let folded_evaluation_count = read_usize(bytes, &mut pos)?;
    let folded_output_contribution_len = read_usize(bytes, &mut pos)?;
    let whir_parameter_digest = read_digest(bytes, &mut pos)?;
    if pos != bytes.len()
        || num_rounds == 0
        || fs_message_lens.len() != num_rounds
        || fold_input_commitment_lens.len() != num_rounds
        || fold_input_public_input_lens.len() != num_rounds
        || fold_input_eval_message_lens.len() != num_rounds
        || gr1cs_hadamard_eval_offsets.len() != num_rounds
        || gr1cs_message_sections.len() != num_rounds
        || gr1cs_hadamard_eval_offsets
            .iter()
            .any(|offsets| offsets.len() != folded_evaluation_count)
        || gr1cs_message_sections
            .iter()
            .zip(fs_message_lens.iter())
            .any(|(sections, &message_len)| !message_sections_are_contiguous(sections, message_len))
    {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    Ok(CpAccumulatorShape {
        digest_scheme,
        r1cs_num_constraints,
        r1cs_num_variables,
        r1cs_num_public,
        local_public_input_count,
        public_statement_len,
        num_rounds,
        fs_message_lens,
        fs_commitment_len,
        fs_opening_len,
        fold_input_commitment_lens,
        fold_input_public_input_lens,
        fold_input_eval_message_lens,
        gr1cs_hadamard_eval_offsets,
        gr1cs_message_sections,
        original_witness_lens,
        commitment_kappa,
        commitment_d,
        folded_public_input_len,
        folded_evaluation_count,
        folded_output_contribution_len,
        whir_parameter_digest,
    })
}

fn encode_round_message_body(
    shape: &BatchedCpStatementShape,
    items: &[BatchedCpItem],
    round: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"symphony-batched-cp-round-message-v1");
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, round);
    push_usize(&mut out, shape.batch_capacity);
    for idx in 0..shape.batch_capacity {
        push_usize(&mut out, idx);
        if let Some(item) = items.get(idx) {
            out.push(1);
            push_bytes(&mut out, &item.witness.fs_messages[round]);
        } else {
            out.push(0);
            push_bytes(&mut out, &[]);
        }
    }
    out
}

fn encode_folded_output_accumulator_body(items: &[BatchedCpItem]) -> Vec<u8> {
    let mut out = Vec::new();
    push_usize(&mut out, items.len());
    for item in items {
        out.extend_from_slice(&encode_folded_output_contribution(item));
    }
    out
}

fn encode_folded_output_contribution(item: &BatchedCpItem) -> Vec<u8> {
    encode_folded_output_contribution_parts(&item.public, Some(item.item_tag))
}

fn encode_folded_output_contribution_parts(
    public: &CpPublicStatement,
    item_tag: Option<Digest32>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&item_tag.unwrap_or([0u8; 32]));
    encode_folded_instance(&mut out, &public.instance.x_folded);
    encode_folded_output_instance(&mut out, &public.instance.folded_output);
    out
}

fn encode_public_statement(public: &CpPublicStatement) -> Vec<u8> {
    let mut out = Vec::new();
    push_digest_scheme(&mut out, public.digest_scheme);
    out.extend_from_slice(&public.instance.fs_root);
    out.extend_from_slice(&public.instance.fold_root);
    out.extend_from_slice(&public.instance.challenge_digest);
    out.extend_from_slice(&public.instance.transcript_seed_digest);
    encode_folded_instance(&mut out, &public.instance.x_folded);
    encode_folded_output_instance(&mut out, &public.instance.folded_output);
    push_i64_matrix(&mut out, &public.public_inputs);
    push_usize(&mut out, public.r1cs_num_constraints);
    push_usize(&mut out, public.r1cs_num_variables);
    push_usize(&mut out, public.r1cs_num_public);
    out
}

fn encode_witness_row(item: &BatchedCpItem) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&item.item_tag);
    out.extend_from_slice(&encode_public_statement(&item.public));
    out.extend_from_slice(&encode_folded_output_contribution(item));
    for beta in &item.witness.folding_proof.beta {
        encode_ring_element(&mut out, beta);
    }
    for message in &item.witness.fs_messages {
        push_bytes(&mut out, message);
    }
    for commitment in &item.witness.fs_commitments {
        push_bytes(&mut out, commitment);
    }
    for opening in &item.witness.fs_openings {
        push_bytes(&mut out, opening);
    }
    for input in &item.witness.fold_inputs {
        push_bytes(&mut out, &input.commitment_bytes);
        push_i64_vec(&mut out, &input.public_input);
        push_bytes(&mut out, &input.eval_values_bytes);
    }
    for witness in &item.witness.original_witnesses {
        encode_ring_vector(&mut out, witness);
    }
    out
}

fn poseidon_fs_commitment_body_from_item(item: &BatchedCpItem, round: usize) -> Vec<u8> {
    let mut body = Vec::new();
    let message = &item.witness.fs_messages[round];
    push_usize(&mut body, message.len());
    body.extend_from_slice(message);
    body.extend_from_slice(&item.witness.fs_openings[round]);
    body
}

fn poseidon_fs_commitment_trace_values(body: &[u8]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    #[cfg(feature = "whir")]
    {
        use p3_field::PrimeField32;
        let input_values = crate::digest_core::poseidon_digest_input_elems(b"fs-commit", body)
            .into_iter()
            .map(|value| value.as_canonical_u32())
            .collect::<Vec<_>>();
        let digest =
            crate::snark::cp_snark::typed_r1cs::poseidon2_digest32_from_body(b"fs-commit", body);
        let output_values = digest
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("digest limb")))
            .collect::<Vec<_>>();
        let witness = crate::snark::cp_snark::encode_poseidon2_digest_witness(
            b"fs-commit",
            &crate::digest_core::poseidon_digest_input_elems(b"fs-commit", body),
        );
        let aux_values = witness
            .chunks_exact(8)
            .map(|chunk| {
                let value = i64::from_le_bytes(chunk.try_into().expect("aux limb"));
                u32::try_from(value).expect("Poseidon aux limb should be canonical u32")
            })
            .collect::<Vec<_>>();
        (input_values, output_values, aux_values)
    }
    #[cfg(not(feature = "whir"))]
    {
        let _ = body;
        (Vec::new(), Vec::new(), Vec::new())
    }
}

fn poseidon_fs_commitment_input_len(message_len: usize, opening_len: usize) -> usize {
    let body_len = 8 + message_len + opening_len;
    let frame_len = b"symphony-v2".len() + 8 + b"fs-commit".len() + 8 + body_len;
    frame_len.div_ceil(3) + 1
}

fn poseidon_fs_commitment_aux_len(input_len: usize) -> usize {
    const RATE: usize = 8;
    const WIDTH: usize = 16;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 13;
    let sboxes_per_permutation = 2 * HALF_FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS;
    input_len.div_ceil(RATE) * sboxes_per_permutation * 4
}

#[cfg(feature = "whir")]
fn field_offsets(range: BatchedCpOracleByteRange, count: usize) -> Vec<usize> {
    (0..count).map(|idx| range.offset + idx * 4).collect()
}

#[cfg(feature = "whir")]
fn sampled_poseidon_row_candidates(num_constraints: usize) -> Vec<usize> {
    let mut rows = std::collections::BTreeSet::new();
    rows.extend(0..num_constraints.min(64));
    rows.extend(num_constraints.saturating_sub(16)..num_constraints);
    rows.into_iter().collect()
}

#[cfg(feature = "whir")]
fn r1cs_row_terms(
    matrix: &crate::r1cs::SparseMatrix,
    row: usize,
    coeff: usize,
    public_inputs: BatchedCpOracleByteRange,
    original_witness: BatchedCpOracleByteRange,
    num_public: usize,
) -> Vec<(i64, usize)> {
    matrix
        .entries
        .iter()
        .filter_map(|&(entry_row, col, value)| {
            if entry_row != row {
                return None;
            }
            let offset = if col < num_public {
                if coeff != 0 {
                    return None;
                }
                public_inputs.offset + col * 8
            } else {
                original_witness.offset + (col - num_public) * D * 8 + coeff * 8
            };
            Some((value, offset))
        })
        .collect()
}

fn encode_folded_output_instance(out: &mut Vec<u8>, value: &crate::folding::FoldedOutputInstance) {
    encode_folded_instance(out, &value.folded_instance);
    encode_commitment(out, &value.linear_relation.commitment);
    push_ext_vec(out, &value.linear_relation.evaluation_point);
    for eval in &value.linear_relation.evaluation_values {
        encode_tensor(out, eval);
    }
    push_usize(out, value.batched_relation.commitments.len());
    for commitment in &value.batched_relation.commitments {
        encode_commitment(out, commitment);
    }
    push_ext_vec(out, &value.batched_relation.evaluation_point);
    push_usize(out, value.batched_relation.evaluation_values.len());
    for eval in &value.batched_relation.evaluation_values {
        encode_tensor(out, eval);
    }
}

fn encode_folded_instance(out: &mut Vec<u8>, value: &crate::folding::FoldedInstance) {
    encode_commitment(out, &value.commitment);
    push_usize(out, value.public_input.len());
    for elem in &value.public_input {
        encode_ring_element(out, elem);
    }
    push_usize(out, value.evaluation_values.len());
    for eval in &value.evaluation_values {
        encode_tensor(out, eval);
    }
}

fn encode_commitment(out: &mut Vec<u8>, commitment: &crate::commitment::Commitment) {
    encode_ring_vector(out, &commitment.value);
}

fn encode_ring_vector(out: &mut Vec<u8>, value: &RingVector) {
    push_usize(out, value.elements.len());
    for elem in &value.elements {
        encode_ring_element(out, elem);
    }
}

fn encode_ring_element(out: &mut Vec<u8>, value: &RingElement) {
    for &coeff in &value.coeffs {
        out.extend_from_slice(&coeff.to_le_bytes());
    }
}

fn encode_symbt3_ring_module_layout(out: &mut Vec<u8>, value: &Symbt3RingModuleLayout) {
    push_usize(out, value.ring_degree);
    out.extend_from_slice(&value.modulus.to_le_bytes());
    push_bytes(out, value.basis_order.as_bytes());
    push_bytes(out, value.negacyclic_sign_convention.as_bytes());
    out.push(match value.action_side {
        Symbt3RingActionSide::Left => 1,
    });
    push_usize(out, value.opening_module_dimension);
    push_usize(out, value.commitment_module_dimension);
    push_bytes(out, value.coordinate_encoding.as_bytes());
    push_bytes(out, value.beta_encoding.as_bytes());
    out.extend_from_slice(&value.ring_action_version.to_le_bytes());
}

fn encode_symbt3_ajtai_commit_layout(out: &mut Vec<u8>, value: &Symbt3AjtaiCommitLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.commitment_module_dimension);
    push_usize(out, value.opening_module_dimension);
    push_usize(out, value.ring_degree);
    out.extend_from_slice(&value.modulus.to_le_bytes());
    out.extend_from_slice(&value.indexed_evaluator_id);
    out.push(u8::from(value.separated_message_randomness));
}

fn encode_symbt3_ajtai_linear_algebra_layout(
    out: &mut Vec<u8>,
    value: &Symbt3AjtaiLinearAlgebraLayout,
) {
    out.extend_from_slice(value.version_marker.as_slice());
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.extend_from_slice(&value.algebra_law_digest);
    out.extend_from_slice(&value.ajtai_matrix_digest);
    out.extend_from_slice(&value.ajtai_commit_layout_digest);
    push_usize(out, value.kappa);
    push_usize(out, value.opening_len);
    push_usize(out, value.ring_degree);
    push_usize(out, value.source_opening_column);
    push_usize(out, value.source_commitment_column);
    push_usize(out, value.folded_opening_column);
    push_usize(out, value.folded_commitment_column);
    out.push(symbt3_beta_action_code(value.beta_action));
    out.push(symbt3_product_law_code(value.product_law));
    out.push(symbt3_ajtai_matrix_vector_evaluator_code(
        value.matrix_vector_evaluator,
    ));
    push_bytes(out, value.padding_policy.as_bytes());
    push_bytes(out, value.selector_evaluator.as_bytes());
    out.push(symbt3_ajtai_opening_mode_code(value.opening_mode));
}

fn encode_symbt3_projection_layout(out: &mut Vec<u8>, value: &Symbt3ProjectionLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_projection_mode_code(value.projection_mode));
    out.push(symbt3_projection_seed_policy_code(
        value.projection_seed_policy,
    ));
    out.extend_from_slice(&value.projection_matrix_digest);
    push_usize(out, value.input_len);
    push_usize(out, value.output_len);
    push_usize(out, value.block_len);
    push_usize(out, value.rows_per_block);
    out.push(symbt3_projection_entry_distribution_code(
        value.entry_distribution,
    ));
    push_bytes(out, value.coefficient_domain.as_bytes());
}

fn encode_symbt3_monomial_embedding_layout(
    out: &mut Vec<u8>,
    value: &Symbt3MonomialEmbeddingLayout,
) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.ring_degree);
    push_usize(out, value.bound_b);
    out.extend_from_slice(&value.table_polynomial_digest);
    out.push(symbt3_monomiality_mode_code(value.monomiality_mode));
    out.push(symbt3_constant_term_policy_code(value.constant_term_policy));
    out.push(symbt3_signed_convention_code(value.signed_convention));
}

fn encode_symbt3_representative_layout(out: &mut Vec<u8>, value: &Symbt3RepresentativeLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.extend_from_slice(&value.modulus_digest);
    out.extend_from_slice(&value.signed_range.to_le_bytes());
    out.push(symbt3_canonical_rep_policy_code(value.canonical_rep_policy));
}

fn encode_symbt3_range_layout(out: &mut Vec<u8>, value: &Symbt3RangeLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_range_mode_code(value.range_mode));
    out.extend_from_slice(&value.bound_b.to_le_bytes());
    out.push(symbt3_signed_encoding_code(value.signed_encoding));
    match value.table_digest {
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
        None => out.push(0),
    }
    match value.monomial_embedding_layout_digest {
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
        None => out.push(0),
    }
}

fn encode_symbt3_ajtai_norm_range_layout(out: &mut Vec<u8>, value: &Symbt3AjtaiNormRangeLayout) {
    out.extend_from_slice(value.version_marker.as_slice());
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.extend_from_slice(&value.algebra_law_digest);
    out.extend_from_slice(&value.ajtai_linear_algebra_layout_digest);
    push_usize(out, value.folded_opening_column);
    push_usize(out, value.projected_opening_column);
    push_usize(out, value.monomial_witness_column);
    encode_symbt3_projection_layout(out, &value.projection_layout);
    encode_symbt3_range_layout(out, &value.range_layout);
    encode_symbt3_monomial_embedding_layout(out, &value.monomial_embedding_layout);
    encode_symbt3_representative_layout(out, &value.representative_layout);
    out.extend_from_slice(&value.norm_bound.to_le_bytes());
    out.push(symbt3_coefficient_encoding_code(value.coefficient_encoding));
    push_bytes(out, value.reduction_policy.as_bytes());
    push_bytes(out, value.selector_evaluator.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    out.push(symbt3_range_mode_code(value.range_mode));
}

fn encode_symbt3_manifest_oracle_layout(out: &mut Vec<u8>, value: &Symbt3ManifestOracleLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.row_count);
    push_usize(out, value.component_count);
    push_usize(out, value.coordinate_count);
    push_bytes(out, value.coordinate_ordering.as_bytes());
}

fn encode_symbt3_source_column_layout(out: &mut Vec<u8>, value: &Symbt3SourceColumnLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.component_count);
    push_usize(out, value.coordinate_count);
    push_bytes(out, value.source_column_ordering.as_bytes());
    push_bytes(out, value.root_binding_policy.as_bytes());
}

fn encode_symbt3_manifest_component_layout(
    out: &mut Vec<u8>,
    value: &Symbt3ManifestComponentLayout,
) {
    out.push(symbt3_manifest_component_kind_code(value.kind));
    push_usize(out, value.coordinate_len);
    push_usize(out, value.source_column_id);
    push_usize(out, value.manifest_column_id);
    out.push(symbt3_manifest_visibility_code(value.visibility));
    out.push(symbt3_membership_mode_code(value.membership_mode));
    push_bytes(out, value.padding_policy.as_bytes());
}

fn encode_symbt3_batch_manifest_layout(out: &mut Vec<u8>, value: &Symbt3BatchManifestLayout) {
    out.extend_from_slice(value.version_marker);
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.batch_size);
    push_usize(out, value.active_count);
    out.push(symbt3_active_policy_code(value.active_policy));
    encode_symbt3_manifest_oracle_layout(out, &value.manifest_oracle_layout);
    encode_symbt3_source_column_layout(out, &value.source_column_layout);
    push_usize(out, value.component_kinds.len());
    for component in &value.component_kinds {
        encode_symbt3_manifest_component_layout(out, component);
    }
    out.push(symbt3_commitment_scheme_code(value.commitment_scheme_id));
    out.push(symbt3_manifest_root_policy_code(value.manifest_root_policy));
    push_bytes(out, value.selector_evaluator.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
}

fn encode_symbt3_message_section_layout(out: &mut Vec<u8>, value: &Symbt3MessageSectionLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_message_section_kind_code(value.section_kind));
    push_usize(out, value.coordinate_offset);
    push_usize(out, value.coordinate_len);
    out.push(symbt3_message_algebra_type_code(value.algebra_type));
    out.push(symbt3_message_visibility_code(value.visibility));
    out.push(symbt3_message_binding_mode_code(value.binding_mode));
}

fn encode_symbt3_message_column_binding(out: &mut Vec<u8>, value: &Symbt3MessageColumnBinding) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round_index);
    push_usize(out, value.message_coordinate_offset);
    push_usize(out, value.trace_column_id);
    push_usize(out, value.trace_coordinate_offset);
    push_usize(out, value.coordinate_len);
    out.push(symbt3_message_binding_mode_code(value.binding_mode));
}

fn encode_symbt3_message_coordinate_map(out: &mut Vec<u8>, value: &Symbt3MessageCoordinateMap) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_message_coordinate_map_mode_code(value.mode));
    push_usize(out, value.message_coordinate_offset);
    push_usize(out, value.coordinate_len);
}

fn encode_symbt3_message_view_layout(out: &mut Vec<u8>, value: &Symbt3MessageViewLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round);
    out.push(symbt3_trace_kind_code(value.trace_kind));
    push_bytes(out, value.trace_coordinate_axis.as_bytes());
    encode_symbt3_message_coordinate_map(out, &value.message_coordinate_map);
    out.push(symbt3_message_algebra_type_code(value.algebra_type));
    push_bytes(out, value.padding_policy.as_bytes());
}

fn encode_symbt3_round_message_layout(out: &mut Vec<u8>, value: &Symbt3RoundMessageLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round_index);
    push_usize(out, value.row_count);
    push_usize(out, value.message_len);
    push_usize(out, value.packed_field_len);
    push_bytes(out, value.coordinate_axis.as_bytes());
    push_bytes(out, value.section_axis.as_bytes());
    push_usize(out, value.sections.len());
    for section in &value.sections {
        encode_symbt3_message_section_layout(out, section);
    }
    push_usize(out, value.source_column_bindings.len());
    for binding in &value.source_column_bindings {
        encode_symbt3_message_column_binding(out, binding);
    }
    push_usize(out, value.trace_column_bindings.len());
    for binding in &value.trace_column_bindings {
        encode_symbt3_message_column_binding(out, binding);
    }
    push_usize(out, value.message_views.len());
    for view in &value.message_views {
        encode_symbt3_message_view_layout(out, view);
    }
}

fn encode_symbt3_message_semantic_layout(out: &mut Vec<u8>, value: &Symbt3MessageSemanticLayout) {
    out.extend_from_slice(value.version_marker);
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round_count);
    push_usize(out, value.round_layouts.len());
    for round in &value.round_layouts {
        encode_symbt3_round_message_layout(out, round);
    }
    out.extend_from_slice(&value.challenge_schedule_version.to_le_bytes());
    out.extend_from_slice(&value.message_oracle_layout_digest);
    out.extend_from_slice(&value.algebra_law_digest);
    out.extend_from_slice(&value.gr1cs_layout_digest);
    out.extend_from_slice(&value.ajtai_layout_digest);
    out.extend_from_slice(&value.norm_range_layout_digest);
    out.extend_from_slice(&value.manifest_layout_digest);
    push_bytes(out, value.selector_evaluator.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    out.push(symbt3_message_semantic_mode_code(value.semantic_mode));
}

fn encode_symbt3_r1cs_evaluator_layout(out: &mut Vec<u8>, value: &Symbt3R1csEvaluatorLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_bytes(out, value.field_id.as_bytes());
    out.extend_from_slice(&value.modulus.to_le_bytes());
    push_usize(out, value.num_constraints);
    push_usize(out, value.num_variables);
    push_usize(out, value.num_public);
    push_usize(out, value.num_witness);
    match value.constant_one_wire_index {
        Some(idx) => {
            out.push(1);
            push_usize(out, idx);
        }
        None => out.push(0),
    }
    push_bytes(out, value.public_input_wire_layout.as_bytes());
    push_bytes(out, value.witness_wire_layout.as_bytes());
    push_bytes(out, value.sparse_encoding_format.as_bytes());
    push_bytes(out, value.row_ordering.as_bytes());
    push_bytes(out, value.column_ordering.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    push_bytes(out, value.coefficient_encoding.as_bytes());
    push_bytes(out, value.term_encoding.as_bytes());
    out.extend_from_slice(&value.evaluator_algorithm_id);
}

fn encode_symbt3_gr1cs_residual_layout(out: &mut Vec<u8>, value: &Symbt3Gr1csResidualLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.folded_evaluation_coordinate_count);
    push_usize(out, value.tensor_rows);
    push_usize(out, value.ring_degree);
    push_bytes(out, value.grouping.as_bytes());
    push_bytes(out, value.coordinate_ordering.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    push_usize(out, value.component_kind_tags.len());
    for tag in &value.component_kind_tags {
        push_bytes(out, tag.as_bytes());
    }
}

fn encode_symbt3_algebra_law(out: &mut Vec<u8>, value: &Symbt3AlgebraLaw) {
    out.extend_from_slice(value.version_marker.as_slice());
    out.extend_from_slice(&value.law_version.to_le_bytes());
    push_bytes(out, value.check_field_id.as_bytes());
    push_bytes(out, value.coefficient_domain.as_bytes());
    push_usize(out, value.ring_degree);
    push_bytes(out, value.ring_relation.as_bytes());
    push_bytes(out, value.coefficient_basis.as_bytes());
    push_bytes(out, value.coefficient_order.as_bytes());
    push_bytes(out, value.reduction_policy.as_bytes());
    out.push(symbt3_beta_action_code(value.beta_action));
    out.push(symbt3_product_law_code(value.product_law));
    push_bytes(out, value.module_layout.as_bytes());
    push_bytes(out, value.soundness_profile.as_bytes());
    push_bytes(out, value.zk_profile.as_bytes());
}

fn encode_symbt3_folded_gr1cs_product_residual_layout(
    out: &mut Vec<u8>,
    value: &Symbt3FoldedGr1csProductResidualLayout,
) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.product_domain_log_size);
    push_bytes(out, value.equation_kind_axis.as_bytes());
    push_bytes(out, value.row_axis.as_bytes());
    push_usize(out, value.l_fold_column);
    push_usize(out, value.r_fold_column);
    push_usize(out, value.o_fold_column);
    push_bytes(out, value.selector_evaluator.as_bytes());
    out.push(symbt3_product_law_code(value.product_law));
    out.push(symbt3_beta_action_code(value.beta_action));
    push_bytes(out, value.padding_policy.as_bytes());
    push_bytes(out, value.check_field.as_bytes());
    push_bytes(out, value.soundness_profile.as_bytes());
}

fn encode_ring_matrix(out: &mut Vec<u8>, value: &[Vec<RingElement>]) {
    push_usize(out, value.len());
    for row in value {
        push_usize(out, row.len());
        for elem in row {
            encode_ring_element(out, elem);
        }
    }
}

fn encode_r1cs_matrices(out: &mut Vec<u8>, value: &R1CSMatrices) {
    push_usize(out, value.num_constraints);
    push_usize(out, value.num_variables);
    push_usize(out, value.num_public);
    encode_sparse_matrix(out, &value.a);
    encode_sparse_matrix(out, &value.b);
    encode_sparse_matrix(out, &value.c);
}

fn encode_tensor(out: &mut Vec<u8>, value: &crate::ring::tensor::TensorElement) {
    for row in &value.data {
        for &coeff in row {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

fn push_ext_vec(out: &mut Vec<u8>, values: &[crate::ring::extension::ExtFieldElement]) {
    push_usize(out, values.len());
    for value in values {
        out.extend_from_slice(&value.c0.to_le_bytes());
        out.extend_from_slice(&value.c1.to_le_bytes());
    }
}

fn push_i64_matrix(out: &mut Vec<u8>, values: &[Vec<i64>]) {
    push_usize(out, values.len());
    for row in values {
        push_i64_vec(out, row);
    }
}

fn push_digest_vec(out: &mut Vec<u8>, values: &[Digest32]) {
    push_usize(out, values.len());
    for value in values {
        out.extend_from_slice(value);
    }
}

fn push_i64_vec(out: &mut Vec<u8>, values: &[i64]) {
    push_usize(out, values.len());
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn push_usize_vec(out: &mut Vec<u8>, values: &[usize]) {
    push_usize(out, values.len());
    for &value in values {
        push_usize(out, value);
    }
}

fn push_nested_usize_vec(out: &mut Vec<u8>, values: &[Vec<usize>]) {
    push_usize(out, values.len());
    for row in values {
        push_usize_vec(out, row);
    }
}

fn push_gr1cs_message_sections(out: &mut Vec<u8>, values: &[Vec<BatchedCpGr1csMessageSection>]) {
    push_usize(out, values.len());
    for round in values {
        push_usize(out, round.len());
        for section in round {
            out.push(gr1cs_message_section_kind_code(&section.kind));
            push_usize(out, section.offset);
            push_usize(out, section.len);
        }
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_usize(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn push_usize(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

fn push_digest_scheme(out: &mut Vec<u8>, scheme: PublicDigestScheme) {
    let value = match scheme {
        PublicDigestScheme::Sha256 => 1u8,
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => 2u8,
    };
    out.push(value);
}

fn gr1cs_message_section_kind_code(kind: &BatchedCpGr1csMessageSectionKind) -> u8 {
    match kind {
        BatchedCpGr1csMessageSectionKind::Header => 1,
        BatchedCpGr1csMessageSectionKind::HadamardEvals => 2,
        BatchedCpGr1csMessageSectionKind::RangePayload => 3,
        BatchedCpGr1csMessageSectionKind::MonomialPayload => 4,
        BatchedCpGr1csMessageSectionKind::SquareEvals => 5,
        BatchedCpGr1csMessageSectionKind::ProjectedValues => 6,
        BatchedCpGr1csMessageSectionKind::TrailingFrame => 7,
    }
}

fn gr1cs_message_section_kind_from_code(code: u8) -> Option<BatchedCpGr1csMessageSectionKind> {
    Some(match code {
        1 => BatchedCpGr1csMessageSectionKind::Header,
        2 => BatchedCpGr1csMessageSectionKind::HadamardEvals,
        3 => BatchedCpGr1csMessageSectionKind::RangePayload,
        4 => BatchedCpGr1csMessageSectionKind::MonomialPayload,
        5 => BatchedCpGr1csMessageSectionKind::SquareEvals,
        6 => BatchedCpGr1csMessageSectionKind::ProjectedValues,
        7 => BatchedCpGr1csMessageSectionKind::TrailingFrame,
        _ => return None,
    })
}

fn push_known_statement_shape(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
) {
    let mut encoded = Vec::new();
    encode_statement_shape(&mut encoded, shape);
    push_known_raw(bytes, known, &encoded);
}

fn push_known_bytes(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: &[u8]) {
    push_known_usize(bytes, known, value.len());
    push_known_raw(bytes, known, value);
}

fn push_private_bytes(bytes: &mut Vec<u8>, known: &mut Vec<bool>, len: usize) {
    push_known_usize(bytes, known, len);
    push_private_raw(bytes, known, len);
}

fn push_private_raw(bytes: &mut Vec<u8>, known: &mut Vec<bool>, len: usize) {
    bytes.extend(std::iter::repeat_n(0u8, len));
    known.extend(std::iter::repeat_n(false, len));
}

fn push_known_usize(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: usize) {
    push_known_raw(bytes, known, &(value as u64).to_le_bytes());
}

fn push_known_u8(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: u8) {
    bytes.push(value);
    known.push(true);
}

fn push_known_raw(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: &[u8]) {
    bytes.extend_from_slice(value);
    known.extend(std::iter::repeat_n(true, value.len()));
}

fn read_usize(bytes: &[u8], pos: &mut usize) -> Result<usize, BatchedCpError> {
    Ok(read_u64(bytes, pos)? as usize)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, BatchedCpError> {
    let end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let chunk = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos = end;
    Ok(u64::from_le_bytes(chunk.try_into().map_err(|_| {
        BatchedCpError::InvalidStructuredRelationContext
    })?))
}

fn read_usize_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<usize>, BatchedCpError> {
    let len = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_usize(bytes, pos)?);
    }
    Ok(out)
}

fn read_nested_usize_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<Vec<usize>>, BatchedCpError> {
    let len = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_usize_vec(bytes, pos)?);
    }
    Ok(out)
}

fn read_gr1cs_message_sections(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Vec<Vec<BatchedCpGr1csMessageSection>>, BatchedCpError> {
    let rounds = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let section_count = read_usize(bytes, pos)?;
        let mut sections = Vec::with_capacity(section_count);
        for _ in 0..section_count {
            let Some(&code) = bytes.get(*pos) else {
                return Err(BatchedCpError::InvalidStructuredRelationContext);
            };
            *pos += 1;
            let kind = gr1cs_message_section_kind_from_code(code)
                .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
            sections.push(BatchedCpGr1csMessageSection {
                kind,
                offset: read_usize(bytes, pos)?,
                len: read_usize(bytes, pos)?,
            });
        }
        out.push(sections);
    }
    Ok(out)
}

fn read_bytes(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, BatchedCpError> {
    let len = read_usize(bytes, pos)?;
    let end = pos
        .checked_add(len)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let value = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?
        .to_vec();
    *pos = end;
    Ok(value)
}

fn read_static_str(
    bytes: &[u8],
    pos: &mut usize,
    expected: &'static str,
) -> Result<&'static str, BatchedCpError> {
    let value = read_bytes(bytes, pos)?;
    if value == expected.as_bytes() {
        Ok(expected)
    } else {
        Err(BatchedCpError::InvalidSemanticRelationContext)
    }
}

fn read_digest(bytes: &[u8], pos: &mut usize) -> Result<Digest32, BatchedCpError> {
    let end = pos
        .checked_add(32)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let chunk = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos = end;
    chunk
        .try_into()
        .map_err(|_| BatchedCpError::InvalidStructuredRelationContext)
}

fn read_digest_scheme(bytes: &[u8], pos: &mut usize) -> Result<PublicDigestScheme, BatchedCpError> {
    let value = *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos += 1;
    match value {
        1 => Ok(PublicDigestScheme::Sha256),
        #[cfg(feature = "whir")]
        2 => Ok(PublicDigestScheme::Poseidon2BabyBear),
        _ => Err(BatchedCpError::InvalidStructuredRelationContext),
    }
}

fn read_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, BatchedCpError> {
    let end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let chunk = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos = end;
    Ok(i64::from_le_bytes(chunk.try_into().map_err(|_| {
        BatchedCpError::InvalidStructuredRelationContext
    })?))
}

fn read_ring_element(bytes: &[u8], pos: &mut usize) -> Result<RingElement, BatchedCpError> {
    let mut coeffs = [0i64; D];
    for coeff in &mut coeffs {
        *coeff = read_i64(bytes, pos)?;
    }
    Ok(RingElement { coeffs })
}

fn read_symbt3_ring_module_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RingModuleLayout, BatchedCpError> {
    let ring_degree = read_usize(bytes, pos)?;
    let modulus = read_u64(bytes, pos)?;
    let basis_order = read_static_str(bytes, pos, "coefficient-ascending")?;
    let negacyclic_sign_convention = read_static_str(bytes, pos, "x^D=-1")?;
    let action_side = match *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?
    {
        1 => Symbt3RingActionSide::Left,
        _ => return Err(BatchedCpError::InvalidSemanticRelationContext),
    };
    *pos += 1;
    let opening_module_dimension = read_usize(bytes, pos)?;
    let commitment_module_dimension = read_usize(bytes, pos)?;
    let coordinate_encoding = read_static_str(bytes, pos, "centered-i64-le")?;
    let beta_encoding = read_static_str(bytes, pos, "digest-base5-ring-coefficients")?;
    let ring_action_version = read_u64(bytes, pos)?;
    Ok(Symbt3RingModuleLayout {
        ring_degree,
        modulus,
        basis_order,
        negacyclic_sign_convention,
        action_side,
        opening_module_dimension,
        commitment_module_dimension,
        coordinate_encoding,
        beta_encoding,
        ring_action_version,
    })
}

fn read_symbt3_ajtai_commit_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AjtaiCommitLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let commitment_module_dimension = read_usize(bytes, pos)?;
    let opening_module_dimension = read_usize(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let modulus = read_u64(bytes, pos)?;
    let indexed_evaluator_id = read_digest(bytes, pos)?;
    let separated_message_randomness = match *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?
    {
        0 => false,
        1 => true,
        _ => return Err(BatchedCpError::InvalidSemanticRelationContext),
    };
    *pos += 1;
    Ok(Symbt3AjtaiCommitLayout {
        layout_version,
        commitment_module_dimension,
        opening_module_dimension,
        ring_degree,
        modulus,
        indexed_evaluator_id,
        separated_message_randomness,
    })
}

fn read_symbt3_ajtai_linear_algebra_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AjtaiLinearAlgebraLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3F\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let algebra_law_digest = read_digest(bytes, pos)?;
    let ajtai_matrix_digest = read_digest(bytes, pos)?;
    let ajtai_commit_layout_digest = read_digest(bytes, pos)?;
    let kappa = read_usize(bytes, pos)?;
    let opening_len = read_usize(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let source_opening_column = read_usize(bytes, pos)?;
    let source_commitment_column = read_usize(bytes, pos)?;
    let folded_opening_column = read_usize(bytes, pos)?;
    let folded_commitment_column = read_usize(bytes, pos)?;
    let beta_action = symbt3_beta_action_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let product_law = symbt3_product_law_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let matrix_vector_evaluator = symbt3_ajtai_matrix_vector_evaluator_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let selector_evaluator = read_static_str(bytes, pos, "prefix-active-item-selector-v1")?;
    let opening_mode = symbt3_ajtai_opening_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3AjtaiLinearAlgebraLayout {
        version_marker: b"SYMBT3F\0",
        layout_version,
        algebra_law_digest,
        ajtai_matrix_digest,
        ajtai_commit_layout_digest,
        kappa,
        opening_len,
        ring_degree,
        source_opening_column,
        source_commitment_column,
        folded_opening_column,
        folded_commitment_column,
        beta_action,
        product_law,
        matrix_vector_evaluator,
        padding_policy,
        selector_evaluator,
        opening_mode,
    })
}

fn read_optional_digest(bytes: &[u8], pos: &mut usize) -> Result<Option<Digest32>, BatchedCpError> {
    let tag = *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_digest(bytes, pos)?)),
        _ => Err(BatchedCpError::InvalidSemanticRelationContext),
    }
}

fn read_symbt3_projection_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3ProjectionLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let projection_mode = symbt3_projection_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let projection_seed_policy = symbt3_projection_seed_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let projection_matrix_digest = read_digest(bytes, pos)?;
    let input_len = read_usize(bytes, pos)?;
    let output_len = read_usize(bytes, pos)?;
    let block_len = read_usize(bytes, pos)?;
    let rows_per_block = read_usize(bytes, pos)?;
    let entry_distribution = symbt3_projection_entry_distribution_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let coefficient_domain = read_static_str(bytes, pos, "check-field-native-ring-coefficients")?;
    Ok(Symbt3ProjectionLayout {
        layout_version,
        projection_mode,
        projection_seed_policy,
        projection_matrix_digest,
        input_len,
        output_len,
        block_len,
        rows_per_block,
        entry_distribution,
        coefficient_domain,
    })
}

fn read_symbt3_monomial_embedding_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MonomialEmbeddingLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let bound_b = read_usize(bytes, pos)?;
    let table_polynomial_digest = read_digest(bytes, pos)?;
    let monomiality_mode = symbt3_monomiality_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let constant_term_policy = symbt3_constant_term_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let signed_convention = symbt3_signed_convention_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MonomialEmbeddingLayout {
        layout_version,
        ring_degree,
        bound_b,
        table_polynomial_digest,
        monomiality_mode,
        constant_term_policy,
        signed_convention,
    })
}

fn read_symbt3_representative_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RepresentativeLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let modulus_digest = read_digest(bytes, pos)?;
    let signed_range = read_i64(bytes, pos)?;
    let canonical_rep_policy = symbt3_canonical_rep_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3RepresentativeLayout {
        layout_version,
        modulus_digest,
        signed_range,
        canonical_rep_policy,
    })
}

fn read_symbt3_range_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RangeLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let range_mode = symbt3_range_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let bound_b = read_i64(bytes, pos)?;
    let signed_encoding = symbt3_signed_encoding_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let table_digest = read_optional_digest(bytes, pos)?;
    let monomial_embedding_layout_digest = read_optional_digest(bytes, pos)?;
    Ok(Symbt3RangeLayout {
        layout_version,
        range_mode,
        bound_b,
        signed_encoding,
        table_digest,
        monomial_embedding_layout_digest,
    })
}

fn read_symbt3_ajtai_norm_range_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AjtaiNormRangeLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3J\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let algebra_law_digest = read_digest(bytes, pos)?;
    let ajtai_linear_algebra_layout_digest = read_digest(bytes, pos)?;
    let folded_opening_column = read_usize(bytes, pos)?;
    let projected_opening_column = read_usize(bytes, pos)?;
    let monomial_witness_column = read_usize(bytes, pos)?;
    let projection_layout = read_symbt3_projection_layout(bytes, pos)?;
    let range_layout = read_symbt3_range_layout(bytes, pos)?;
    let monomial_embedding_layout = read_symbt3_monomial_embedding_layout(bytes, pos)?;
    let representative_layout = read_symbt3_representative_layout(bytes, pos)?;
    let norm_bound = read_i64(bytes, pos)?;
    let coefficient_encoding = symbt3_coefficient_encoding_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let reduction_policy = read_static_str(bytes, pos, "CheckFieldNativeV1")?;
    let selector_evaluator =
        read_static_str(bytes, pos, "valid-folded-opening-coordinate-selector-v1")?;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let range_mode = symbt3_range_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3AjtaiNormRangeLayout {
        version_marker: b"SYMBT3J\0",
        layout_version,
        algebra_law_digest,
        ajtai_linear_algebra_layout_digest,
        folded_opening_column,
        projected_opening_column,
        monomial_witness_column,
        projection_layout,
        range_layout,
        monomial_embedding_layout,
        representative_layout,
        norm_bound,
        coefficient_encoding,
        reduction_policy,
        selector_evaluator,
        padding_policy,
        range_mode,
    })
}

fn read_symbt3_manifest_oracle_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3ManifestOracleLayout, BatchedCpError> {
    Ok(Symbt3ManifestOracleLayout {
        layout_version: read_u64(bytes, pos)?,
        row_count: read_usize(bytes, pos)?,
        component_count: read_usize(bytes, pos)?,
        coordinate_count: read_usize(bytes, pos)?,
        coordinate_ordering: read_static_str(bytes, pos, "item-component-coordinate")?,
    })
}

fn read_symbt3_source_column_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3SourceColumnLayout, BatchedCpError> {
    Ok(Symbt3SourceColumnLayout {
        layout_version: read_u64(bytes, pos)?,
        component_count: read_usize(bytes, pos)?,
        coordinate_count: read_usize(bytes, pos)?,
        source_column_ordering: read_static_str(bytes, pos, "item-component-coordinate")?,
        root_binding_policy: read_static_str(bytes, pos, "digest-coordinate-boundary-v1")?,
    })
}

fn read_symbt3_manifest_component_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3ManifestComponentLayout, BatchedCpError> {
    let kind = symbt3_manifest_component_kind_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let coordinate_len = read_usize(bytes, pos)?;
    let source_column_id = read_usize(bytes, pos)?;
    let manifest_column_id = read_usize(bytes, pos)?;
    let visibility = symbt3_manifest_visibility_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let membership_mode = symbt3_membership_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3ManifestComponentLayout {
        kind,
        coordinate_len,
        source_column_id,
        manifest_column_id,
        visibility,
        membership_mode,
        padding_policy: read_static_str(bytes, pos, "selector-zero-padded-tail")?,
    })
}

fn read_symbt3_batch_manifest_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3BatchManifestLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3H\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let batch_size = read_usize(bytes, pos)?;
    let active_count = read_usize(bytes, pos)?;
    let active_policy = symbt3_active_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let manifest_oracle_layout = read_symbt3_manifest_oracle_layout(bytes, pos)?;
    let source_column_layout = read_symbt3_source_column_layout(bytes, pos)?;
    let component_count = read_usize(bytes, pos)?;
    let mut component_kinds = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        component_kinds.push(read_symbt3_manifest_component_layout(bytes, pos)?);
    }
    let commitment_scheme_id = symbt3_commitment_scheme_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let manifest_root_policy = symbt3_manifest_root_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3BatchManifestLayout {
        version_marker: b"SYMBT3H\0",
        layout_version,
        batch_size,
        active_count,
        active_policy,
        manifest_oracle_layout,
        source_column_layout,
        component_kinds,
        commitment_scheme_id,
        manifest_root_policy,
        selector_evaluator: read_static_str(
            bytes,
            pos,
            "prefix-active-valid-component-selector-v1",
        )?,
        padding_policy: read_static_str(bytes, pos, "selector-zero-padded-tail")?,
    })
}

fn read_symbt3_message_section_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageSectionLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let section_kind = symbt3_message_section_kind_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let coordinate_offset = read_usize(bytes, pos)?;
    let coordinate_len = read_usize(bytes, pos)?;
    let algebra_type = symbt3_message_algebra_type_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let visibility = symbt3_message_visibility_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let binding_mode = symbt3_message_binding_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MessageSectionLayout {
        layout_version,
        section_kind,
        coordinate_offset,
        coordinate_len,
        algebra_type,
        visibility,
        binding_mode,
    })
}

fn read_symbt3_message_column_binding(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageColumnBinding, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let round_index = read_usize(bytes, pos)?;
    let message_coordinate_offset = read_usize(bytes, pos)?;
    let trace_column_id = read_usize(bytes, pos)?;
    let trace_coordinate_offset = read_usize(bytes, pos)?;
    let coordinate_len = read_usize(bytes, pos)?;
    let binding_mode = symbt3_message_binding_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MessageColumnBinding {
        layout_version,
        round_index,
        message_coordinate_offset,
        trace_column_id,
        trace_coordinate_offset,
        coordinate_len,
        binding_mode,
    })
}

fn read_symbt3_message_coordinate_map(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageCoordinateMap, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let mode = symbt3_message_coordinate_map_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let message_coordinate_offset = read_usize(bytes, pos)?;
    let coordinate_len = read_usize(bytes, pos)?;
    Ok(Symbt3MessageCoordinateMap {
        layout_version,
        mode,
        message_coordinate_offset,
        coordinate_len,
    })
}

fn read_symbt3_message_view_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageViewLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let round = read_usize(bytes, pos)?;
    let trace_kind = symbt3_trace_kind_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let trace_coordinate_axis = read_static_str(bytes, pos, "item-packed-message-coordinate")?;
    let message_coordinate_map = read_symbt3_message_coordinate_map(bytes, pos)?;
    let algebra_type = symbt3_message_algebra_type_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    Ok(Symbt3MessageViewLayout {
        layout_version,
        round,
        trace_kind,
        trace_coordinate_axis,
        message_coordinate_map,
        algebra_type,
        padding_policy,
    })
}

fn read_symbt3_round_message_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RoundMessageLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let round_index = read_usize(bytes, pos)?;
    let row_count = read_usize(bytes, pos)?;
    let message_len = read_usize(bytes, pos)?;
    let packed_field_len = read_usize(bytes, pos)?;
    let coordinate_axis = read_static_str(bytes, pos, "item-packed-message-coordinate")?;
    let section_axis = read_static_str(bytes, pos, "typed-round-message-section")?;
    let section_count = read_usize(bytes, pos)?;
    let mut sections = Vec::with_capacity(section_count);
    for _ in 0..section_count {
        sections.push(read_symbt3_message_section_layout(bytes, pos)?);
    }
    let source_binding_count = read_usize(bytes, pos)?;
    let mut source_column_bindings = Vec::with_capacity(source_binding_count);
    for _ in 0..source_binding_count {
        source_column_bindings.push(read_symbt3_message_column_binding(bytes, pos)?);
    }
    let trace_binding_count = read_usize(bytes, pos)?;
    let mut trace_column_bindings = Vec::with_capacity(trace_binding_count);
    for _ in 0..trace_binding_count {
        trace_column_bindings.push(read_symbt3_message_column_binding(bytes, pos)?);
    }
    let message_view_count = read_usize(bytes, pos)?;
    let mut message_views = Vec::with_capacity(message_view_count);
    for _ in 0..message_view_count {
        message_views.push(read_symbt3_message_view_layout(bytes, pos)?);
    }
    Ok(Symbt3RoundMessageLayout {
        layout_version,
        round_index,
        row_count,
        message_len,
        packed_field_len,
        coordinate_axis,
        section_axis,
        sections,
        source_column_bindings,
        trace_column_bindings,
        message_views,
    })
}

fn read_symbt3_message_semantic_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageSemanticLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3I\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let round_count = read_usize(bytes, pos)?;
    let round_layout_count = read_usize(bytes, pos)?;
    let mut round_layouts = Vec::with_capacity(round_layout_count);
    for _ in 0..round_layout_count {
        round_layouts.push(read_symbt3_round_message_layout(bytes, pos)?);
    }
    let challenge_schedule_version = read_u64(bytes, pos)?;
    let message_oracle_layout_digest = read_digest(bytes, pos)?;
    let algebra_law_digest = read_digest(bytes, pos)?;
    let gr1cs_layout_digest = read_digest(bytes, pos)?;
    let ajtai_layout_digest = read_digest(bytes, pos)?;
    let norm_range_layout_digest = read_digest(bytes, pos)?;
    let manifest_layout_digest = read_digest(bytes, pos)?;
    let selector_evaluator =
        read_static_str(bytes, pos, "prefix-active-message-coordinate-selector-v1")?;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let semantic_mode = symbt3_message_semantic_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MessageSemanticLayout {
        version_marker: b"SYMBT3I\0",
        layout_version,
        round_count,
        round_layouts,
        challenge_schedule_version,
        message_oracle_layout_digest,
        algebra_law_digest,
        gr1cs_layout_digest,
        ajtai_layout_digest,
        norm_range_layout_digest,
        manifest_layout_digest,
        selector_evaluator,
        padding_policy,
        semantic_mode,
    })
}

fn read_optional_usize(bytes: &[u8], pos: &mut usize) -> Result<Option<usize>, BatchedCpError> {
    let tag = *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_usize(bytes, pos)?)),
        _ => Err(BatchedCpError::InvalidSemanticRelationContext),
    }
}

fn read_symbt3_r1cs_evaluator_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3R1csEvaluatorLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let field_id = read_static_str(bytes, pos, "BabyBear")?;
    let modulus = read_u64(bytes, pos)?;
    let num_constraints = read_usize(bytes, pos)?;
    let num_variables = read_usize(bytes, pos)?;
    let num_public = read_usize(bytes, pos)?;
    let num_witness = read_usize(bytes, pos)?;
    let constant_one_wire_index = read_optional_usize(bytes, pos)?;
    let public_input_wire_layout = read_static_str(bytes, pos, "public-prefix-constant-ring")?;
    let witness_wire_layout = read_static_str(bytes, pos, "witness-suffix-ring-coefficients")?;
    let sparse_encoding_format = read_static_str(bytes, pos, "coo-row-col-i64-v1")?;
    let row_ordering = read_static_str(bytes, pos, "ascending-row-index")?;
    let column_ordering = read_static_str(bytes, pos, "ascending-column-index")?;
    let padding_policy = read_static_str(bytes, pos, "zero-pad-to-power-of-two")?;
    let coefficient_encoding = read_static_str(bytes, pos, "centered-i64-le")?;
    let term_encoding = read_static_str(bytes, pos, "babybear-linear-form-v1")?;
    let evaluator_algorithm_id = read_digest(bytes, pos)?;
    Ok(Symbt3R1csEvaluatorLayout {
        layout_version,
        field_id,
        modulus,
        num_constraints,
        num_variables,
        num_public,
        num_witness,
        constant_one_wire_index,
        public_input_wire_layout,
        witness_wire_layout,
        sparse_encoding_format,
        row_ordering,
        column_ordering,
        padding_policy,
        coefficient_encoding,
        term_encoding,
        evaluator_algorithm_id,
    })
}

fn read_symbt3_gr1cs_residual_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3Gr1csResidualLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let folded_evaluation_coordinate_count = read_usize(bytes, pos)?;
    let tensor_rows = read_usize(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let grouping = read_static_str(bytes, pos, "triples-left-right-output")?;
    let coordinate_ordering = read_static_str(bytes, pos, "evaluation-index-tensor-row-coeff")?;
    let padding_policy = read_static_str(bytes, pos, "ignore-incomplete-trailing-triple")?;
    let tag_len = read_usize(bytes, pos)?;
    let mut component_kind_tags = Vec::with_capacity(tag_len);
    for expected in ["left", "right", "output"] {
        component_kind_tags.push(read_static_str(bytes, pos, expected)?);
    }
    if tag_len != component_kind_tags.len() {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    Ok(Symbt3Gr1csResidualLayout {
        layout_version,
        folded_evaluation_coordinate_count,
        tensor_rows,
        ring_degree,
        grouping,
        coordinate_ordering,
        padding_policy,
        component_kind_tags,
    })
}

fn read_symbt3_algebra_law(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AlgebraLaw, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3E\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let law_version = read_u64(bytes, pos)?;
    let check_field_id = read_static_str(bytes, pos, "BabyBear")?;
    let coefficient_domain = read_static_str(bytes, pos, "check-field-native-ring")?;
    let ring_degree = read_usize(bytes, pos)?;
    let ring_relation = read_static_str(bytes, pos, "X^D+1")?;
    let coefficient_basis = read_static_str(bytes, pos, "coefficient-ascending")?;
    let coefficient_order = read_static_str(bytes, pos, "little-endian")?;
    let reduction_policy = read_static_str(bytes, pos, "CheckFieldNativeV1")?;
    let beta_action = symbt3_beta_action_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let product_law = symbt3_product_law_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let module_layout = read_static_str(bytes, pos, "coordinatewise-ring-module")?;
    let soundness_profile = read_static_str(
        bytes,
        pos,
        "NonAuthoritativeDevelopmentBaseFieldSingleCheck",
    )?;
    let zk_profile = read_static_str(bytes, pos, "NonZkDevelopment")?;
    Ok(Symbt3AlgebraLaw {
        version_marker: b"SYMBT3E\0",
        law_version,
        check_field_id,
        coefficient_domain,
        ring_degree,
        ring_relation,
        coefficient_basis,
        coefficient_order,
        reduction_policy,
        beta_action,
        product_law,
        module_layout,
        soundness_profile,
        zk_profile,
    })
}

fn read_symbt3_folded_gr1cs_product_residual_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3FoldedGr1csProductResidualLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let product_domain_log_size = read_usize(bytes, pos)?;
    let equation_kind_axis = read_static_str(bytes, pos, "folded-gr1cs-left-right-output")?;
    let row_axis = read_static_str(bytes, pos, "evaluation-index-tensor-row-coeff")?;
    let l_fold_column = read_usize(bytes, pos)?;
    let r_fold_column = read_usize(bytes, pos)?;
    let o_fold_column = read_usize(bytes, pos)?;
    let selector_evaluator = read_static_str(bytes, pos, "prefix-valid-coordinate-selector-v1")?;
    let product_law = symbt3_product_law_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let beta_action = symbt3_beta_action_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let check_field = read_static_str(bytes, pos, "BabyBear")?;
    let soundness_profile = read_static_str(
        bytes,
        pos,
        "NonAuthoritativeDevelopmentBaseFieldSingleCheck",
    )?;
    Ok(Symbt3FoldedGr1csProductResidualLayout {
        layout_version,
        product_domain_log_size,
        equation_kind_axis,
        row_axis,
        l_fold_column,
        r_fold_column,
        o_fold_column,
        selector_evaluator,
        product_law,
        beta_action,
        padding_policy,
        check_field,
        soundness_profile,
    })
}

fn read_ring_matrix(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Vec<Vec<RingElement>>, BatchedCpError> {
    let rows = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(rows);
    for _ in 0..rows {
        let cols = read_usize(bytes, pos)?;
        let mut row = Vec::with_capacity(cols);
        for _ in 0..cols {
            row.push(read_ring_element(bytes, pos)?);
        }
        out.push(row);
    }
    Ok(out)
}

fn read_sparse_matrix(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<crate::r1cs::SparseMatrix, BatchedCpError> {
    let num_rows = read_usize(bytes, pos)?;
    let num_cols = read_usize(bytes, pos)?;
    let entries_len = read_usize(bytes, pos)?;
    let mut matrix = crate::r1cs::SparseMatrix::new(num_rows, num_cols);
    for _ in 0..entries_len {
        let row = read_usize(bytes, pos)?;
        let col = read_usize(bytes, pos)?;
        let coeff = read_i64(bytes, pos)?;
        if row >= num_rows || col >= num_cols {
            return Err(BatchedCpError::InvalidStructuredRelationContext);
        }
        matrix.insert(row, col, coeff);
    }
    Ok(matrix)
}

fn read_r1cs_matrices(bytes: &[u8], pos: &mut usize) -> Result<R1CSMatrices, BatchedCpError> {
    let num_constraints = read_usize(bytes, pos)?;
    let num_variables = read_usize(bytes, pos)?;
    let num_public = read_usize(bytes, pos)?;
    let a = read_sparse_matrix(bytes, pos)?;
    let b = read_sparse_matrix(bytes, pos)?;
    let c = read_sparse_matrix(bytes, pos)?;
    if a.num_rows != num_constraints
        || b.num_rows != num_constraints
        || c.num_rows != num_constraints
        || a.num_cols != num_variables
        || b.num_cols != num_variables
        || c.num_cols != num_variables
    {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    Ok(R1CSMatrices {
        a,
        b,
        c,
        num_constraints,
        num_variables,
        num_public,
    })
}
