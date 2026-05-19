// Native-oracle encoders (included into native_oracles module).

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
        Symbt3NativeMultiOracleMode::SameDomainRlcTupleLeafV1 => SYMBT3_SAME_DOMAIN_RLC_TUPLE_LEAF_LAYOUT,
        Symbt3NativeMultiOracleMode::SameDomainVectorTupleLeafV1 => SYMBT3_SAME_DOMAIN_VECTOR_TUPLE_LEAF_LAYOUT,
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

fn push_optional_role(out: &mut Vec<u8>, value: Option<&WhirNativeOracleRole>) {
    match value {
        Some(value) => {
            push_bool(out, true);
            push_bytes(out, &value.canonical_bytes());
        }
        None => push_bool(out, false),
    }
}
