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

pub const SYMBT3_AUTHORITY_GATE_RESEARCH_V0: &str = "ResearchAuthorityCandidateV0";
pub const SYMBT3_AUTHORITY_GATE_ACCUMULATOR_SOUNDNESS_V1: &str =
    "AccumulatorSoundnessAuthorityCandidateV1";
pub const SYMBT3_AUTHORITY_GATE_PRODUCT: &str = "ProductAuthority";
pub const SYMBT3_PRODUCT_MODE_NON_ZK_INTEGRITY: &str = "NonZKIntegrity";
pub const SYMBT3_MANIFEST_POLICY_PUBLIC_CANONICAL_VIEW_V1: &str = "PublicCanonicalManifestViewV1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestCommitmentPolicy {
    /// DiagnosticOnly legacy link policy retained for compatibility checks.
    DigestOfLayoutAndOracleRootV1,
    /// Product-facing K1e.2 policy: the public boundary binds the canonical
    /// manifest view instead of materializing dense manifest/source columns.
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

// K4/K6 compressed public accumulator boundary.
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

// K4/K6 witness-side adapter. This remains outside public proof objects.
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
