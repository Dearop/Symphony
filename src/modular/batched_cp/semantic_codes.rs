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

