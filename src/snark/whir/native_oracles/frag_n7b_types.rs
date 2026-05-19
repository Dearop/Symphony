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

