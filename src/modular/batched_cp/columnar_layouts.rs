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

