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
