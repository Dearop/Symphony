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
