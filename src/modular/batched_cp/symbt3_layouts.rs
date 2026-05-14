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
    pub fn authority_gate_label(&self) -> &'static str {
        if self.routing_status == Symbt3RoutingStatus::ProductAuthority {
            SYMBT3_AUTHORITY_GATE_PRODUCT
        } else if self.semantic_profile_version >= 1 {
            SYMBT3_AUTHORITY_GATE_ACCUMULATOR_SOUNDNESS_V1
        } else {
            SYMBT3_AUTHORITY_GATE_RESEARCH_V0
        }
    }

    #[must_use]
    pub fn product_mode_label(&self) -> &'static str {
        match self.product_policy {
            Symbt3ProductPolicy::Symbt3NonZkIntegrityOptIn => SYMBT3_PRODUCT_MODE_NON_ZK_INTEGRITY,
            Symbt3ProductPolicy::MonolithicTypedCpOnly => "MonolithicTypedCpOnly",
            Symbt3ProductPolicy::Symbt3ZkRequired => "ZkRequired",
        }
    }

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
    profile_meets_accumulator_soundness_authority(profile)
        && symbt3_relation_meets_accumulator_soundness_policy(profile, relation)
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
    profile_meets_accumulator_soundness_non_zk_integrity_product(profile)
        && symbt3_relation_meets_accumulator_soundness_policy(profile, relation)
}

fn symbt3_relation_meets_accumulator_soundness_policy(
    profile: &Symbt3AuthorityProfile,
    relation: &BatchedCpSymbt3RelationDescription,
) -> bool {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    profile.matches_relation_metadata(relation)
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

