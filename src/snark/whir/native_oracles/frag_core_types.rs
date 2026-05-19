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

