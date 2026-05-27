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
