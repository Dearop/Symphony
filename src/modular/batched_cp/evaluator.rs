impl BatchedCpEvaluator {
    pub fn check(
        public: &BatchedCpPublicStatement,
        witness: &BatchedCpWitnessBundle,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> Result<(), BatchedCpError> {
        let bucket = BatchedCpBucket::new(witness.items.clone(), public.whir_parameter_digest)?;
        if bucket.shape != public.shape {
            return Err(BatchedCpError::ShapeMismatch);
        }
        let expected_witness = bucket.witness_bundle();
        if expected_witness.witness_oracle_rows != witness.witness_oracle_rows {
            return Err(BatchedCpError::WitnessOracleMismatch);
        }
        if expected_witness.round_message_oracles != witness.round_message_oracles {
            return Err(BatchedCpError::RoundMessageOracleMismatch);
        }
        if bucket.manifest().digest != public.manifest_digest {
            return Err(BatchedCpError::ManifestMismatch);
        }
        if bucket.round_message_commitments().commitments != public.round_message_commitments {
            return Err(BatchedCpError::RoundMessageCommitmentMismatch);
        }
        let expected_challenge_digest = derive_batch_challenge_digest(
            &public.shape,
            public.manifest_digest,
            &BatchRoundMessageCommitments {
                commitments: public.round_message_commitments.clone(),
            },
        );
        if expected_challenge_digest != public.batch_challenge_digest {
            return Err(BatchedCpError::ChallengeDigestMismatch);
        }
        let expected_output_root = digest_domain_with_scheme(
            public.shape.accumulator_shape.digest_scheme,
            b"batched-cp-folded-output-accumulator-root",
            &encode_folded_output_accumulator_body(&witness.items),
        );
        if expected_output_root != public.folded_output_accumulator_root {
            return Err(BatchedCpError::ManifestMismatch);
        }
        for (idx, item) in witness.items.iter().enumerate() {
            CpFieldRelation::check(&item.public, &item.witness, ajtai, r1cs, input_bound)
                .map_err(|err| BatchedCpError::ItemRelationFailed(idx, err))?;
        }
        Ok(())
    }
}

impl BatchedCpWitnessBundle {
    pub fn canonical_product_oracle_bytes(
        &self,
        shape: &BatchedCpStatementShape,
    ) -> Result<Vec<u8>, BatchedCpError> {
        validate_product_oracle_layout(self, shape)?;
        let mut out = Vec::with_capacity(shape.canonical_product_oracle_byte_len());
        push_bytes(&mut out, b"symphony-batched-cp-product-oracle-v1");
        encode_statement_shape(&mut out, shape);
        push_usize(&mut out, shape.batch_capacity);
        for idx in 0..shape.batch_capacity {
            push_usize(&mut out, idx);
            out.push(u8::from(idx < shape.active_count));
            push_bytes(&mut out, &self.witness_oracle_rows[idx]);
        }
        push_usize(&mut out, shape.round_message_lens.len());
        for (round, rows) in self.round_message_oracles.iter().enumerate() {
            push_usize(&mut out, round);
            push_usize(&mut out, shape.batch_capacity);
            for (idx, message) in rows.iter().enumerate() {
                push_usize(&mut out, idx);
                out.push(u8::from(idx < shape.active_count));
                push_bytes(&mut out, message);
            }
        }
        push_usize(&mut out, shape.round_message_lens.len());
        for (round, rows) in self.round_message_oracles.iter().enumerate() {
            push_bytes(&mut out, b"symphony-batched-cp-round-message-v1");
            out.extend_from_slice(&shape.shape_id);
            push_usize(&mut out, round);
            push_usize(&mut out, shape.batch_capacity);
            for (idx, message) in rows.iter().enumerate() {
                push_usize(&mut out, idx);
                out.push(u8::from(idx < shape.active_count));
                push_bytes(&mut out, message);
            }
        }
        out.extend_from_slice(&encode_manifest_body(shape, &self.items));
        out.extend_from_slice(&encode_fs_commitment_bodies_body(shape, &self.items));
        out.extend_from_slice(&encode_poseidon_fs_commitment_traces_body(
            shape,
            &self.items,
        ));
        let bucket = BatchedCpBucket::new(
            self.items.clone(),
            shape.accumulator_shape.whir_parameter_digest,
        )?;
        let round_commitments = bucket.round_message_commitments();
        out.extend_from_slice(&encode_batch_challenge_body(
            shape,
            bucket.manifest().digest,
            &round_commitments,
        ));
        let public = bucket.public_statement();
        out.extend_from_slice(&encode_challenge_to_beta_body(
            shape,
            public.batch_challenge_digest,
        ));
        out.extend_from_slice(&encode_fold_input_reconstruction_body(shape, &self.items));
        out.extend_from_slice(&encode_folded_output_accumulator_oracle_body(
            shape,
            public.folded_output_accumulator_root,
            &self.items,
        ));
        Ok(out)
    }
}

impl BatchedCpSemanticTraceV2 {
    pub fn encode(
        relation: &BatchedCpSemanticColumnarV2Description,
        statement: &BatchedCpPublicStatement,
        witness: &BatchedCpWitnessBundle,
    ) -> Result<Self, BatchedCpError> {
        let oracle = witness.canonical_product_oracle_bytes(&relation.semantic.shape)?;
        let layout = relation.columnar_layout.clone();
        let mut columns = vec![vec![0u32; layout.column_row_count]; layout.columns.len()];
        for residual in &layout.residuals {
            match residual.family {
                BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy
                | BatchedCpSemanticConstraintFamily::ManifestMembership
                | BatchedCpSemanticConstraintFamily::RoundMessageBinding => {
                    let equalities =
                        columnar_equalities_for_family(&relation.semantic.shape, residual.family);
                    if equalities.len() != residual.row_count {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    for (row, equality) in equalities.iter().enumerate() {
                        let left = *oracle
                            .get(equality.left_offset)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?
                            as u32;
                        let right = *oracle
                            .get(equality.right_offset)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?
                            as u32;
                        columns[residual.left_column][row] = left;
                        columns[residual.right_column][row] = right;
                    }
                }
                BatchedCpSemanticConstraintFamily::ChallengeDerivation
                | BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding => {
                    let packed_values = columnar_packed_values_for_family(
                        &relation.semantic.shape,
                        statement,
                        residual.family,
                    )
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
                    if packed_values.len() != residual.row_count {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    for (row, value) in packed_values.iter().enumerate() {
                        columns[residual.left_column][row] =
                            packed_oracle_value_at(&oracle, value.packed_index)
                                .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                        columns[residual.right_column][row] = value.value;
                    }
                }
                BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness => {
                    fill_columnar_poseidon_residual(relation, &oracle, residual, &mut columns)?;
                }
                BatchedCpSemanticConstraintFamily::FoldedOutputDerivation => {
                    fill_columnar_folded_output_residual(
                        relation,
                        &oracle,
                        residual,
                        &mut columns,
                    )?;
                }
                BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity => {
                    let constraints = relation.semantic.ajtai_opening_linear_constraints();
                    if constraints.len() != residual.row_count {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    for (row, constraint) in constraints.iter().enumerate() {
                        let (left, right) = columnar_ajtai_opening_eval(constraint, &oracle)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                        columns[residual.left_column][row] = left;
                        columns[residual.right_column][row] = right;
                    }
                }
                BatchedCpSemanticConstraintFamily::OriginalR1csValidity => {
                    let constraints = relation.semantic.original_r1cs_constraints();
                    if constraints.len() != residual.row_count || residual.aux_columns.len() != 1 {
                        return Err(BatchedCpError::InvalidSemanticRelationContext);
                    }
                    let aux_column = residual.aux_columns[0];
                    for (row, constraint) in constraints.iter().enumerate() {
                        let (a, b, c) = columnar_original_r1cs_eval(constraint, &oracle)
                            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                        columns[residual.left_column][row] = a;
                        columns[aux_column][row] = b;
                        columns[residual.right_column][row] = c;
                    }
                }
            }
        }
        Ok(Self { layout, columns })
    }

    #[must_use]
    pub fn flattened_values(&self) -> Vec<u32> {
        let mut out = Vec::with_capacity(self.columns.len() * self.layout.column_row_count);
        for column in &self.columns {
            out.extend_from_slice(column);
        }
        out
    }

    #[must_use]
    pub fn cell_index(&self, column: usize, row: usize) -> Option<usize> {
        if column >= self.columns.len() || row >= self.layout.column_row_count {
            return None;
        }
        Some(column * self.layout.column_row_count + row)
    }

    #[must_use]
    pub fn residual_value(&self, residual_idx: usize, row: usize) -> Option<i64> {
        let residual = self.layout.residuals.get(residual_idx)?;
        if row >= residual.row_count {
            return None;
        }
        let left = *self.columns.get(residual.left_column)?.get(row)? as i64;
        let right = *self.columns.get(residual.right_column)?.get(row)? as i64;
        let satisfied = match residual.kind {
            BatchedCpSemanticResidualV2Kind::Equality => left == right,
            BatchedCpSemanticResidualV2Kind::Product => {
                let aux_column = *residual.aux_columns.first()?;
                let aux = *self.columns.get(aux_column)?.get(row)?;
                bb_mul_u32(left as u32, aux) == right as u32
            }
        };
        Some(if satisfied { 0 } else { 1 })
    }

    #[must_use]
    pub fn all_residuals_satisfied(&self) -> bool {
        self.layout
            .residuals
            .iter()
            .enumerate()
            .all(|(idx, residual)| {
                (0..residual.row_count).all(|row| self.residual_value(idx, row) == Some(0))
            })
    }
}

impl BatchedCpSemanticFamilyTraceV2 {
    pub fn encode(
        relation: &BatchedCpSemanticFamilyColumnarV2Description,
        statement: &BatchedCpPublicStatement,
        witness: &BatchedCpWitnessBundle,
    ) -> Result<Self, BatchedCpError> {
        let oracle = witness.canonical_product_oracle_bytes(&relation.semantic.shape)?;
        let specs = family_columnar_v2_table_specs(&relation.semantic);
        if specs.len() != relation.family_layout.tables.len() {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut tables = Vec::with_capacity(relation.family_layout.tables.len());
        for (table, spec) in relation.family_layout.tables.iter().zip(specs.iter()) {
            if table.family != spec.family
                || table.kind != spec.kind
                || table.label != spec.label
                || table.transcript_label != spec.transcript_label
                || table.column_kinds != spec.column_kinds
                || table.column_labels != spec.column_labels
                || table.row_count != spec.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            tables.push(fill_family_columnar_v2_table(
                &relation.semantic,
                statement,
                &oracle,
                table,
                spec,
            )?);
        }
        Ok(Self {
            layout: relation.family_layout.clone(),
            tables,
        })
    }

    #[must_use]
    pub fn flattened_values(&self) -> Vec<u32> {
        let mut out = vec![0u32; self.layout.total_field_len];
        for (table, columns) in self.layout.tables.iter().zip(&self.tables) {
            for (column_idx, column) in columns.iter().enumerate() {
                let start = table.table_offset + column_idx * table.padded_row_count;
                out[start..start + table.padded_row_count].copy_from_slice(column);
            }
        }
        out
    }

    #[must_use]
    pub fn cell_index(&self, table_idx: usize, column: usize, row: usize) -> Option<usize> {
        let table = self.layout.tables.get(table_idx)?;
        if column >= table.column_kinds.len() || row >= table.padded_row_count {
            return None;
        }
        Some(table.table_offset + column * table.padded_row_count + row)
    }

    #[must_use]
    pub fn residual_value(&self, table_idx: usize, row: usize) -> Option<i64> {
        let table = self.layout.tables.get(table_idx)?;
        if row >= table.row_count {
            return None;
        }
        let columns = self.tables.get(table_idx)?;
        let left = *columns.first()?.get(row)? as i64;
        let right = *columns.last()?.get(row)? as i64;
        let satisfied = match table.kind {
            BatchedCpSemanticResidualV2Kind::Equality => left == right,
            BatchedCpSemanticResidualV2Kind::Product => {
                let aux = *columns.get(1)?.get(row)?;
                bb_mul_u32(left as u32, aux) == right as u32
            }
        };
        Some(if satisfied { 0 } else { 1 })
    }

    #[must_use]
    pub fn all_residuals_satisfied(&self) -> bool {
        self.layout
            .tables
            .iter()
            .enumerate()
            .all(|(table_idx, table)| {
                (0..table.row_count).all(|row| self.residual_value(table_idx, row) == Some(0))
            })
    }
}

fn columnar_equalities_for_family(
    shape: &BatchedCpStatementShape,
    family: BatchedCpSemanticConstraintFamily,
) -> Vec<BatchedCpOracleByteEquality> {
    match family {
        BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy => {
            shape.active_marker_byte_equalities()
        }
        BatchedCpSemanticConstraintFamily::ManifestMembership => {
            shape.manifest_membership_byte_equalities()
        }
        BatchedCpSemanticConstraintFamily::RoundMessageBinding => {
            shape.structured_oracle_byte_equalities()
        }
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness
        | BatchedCpSemanticConstraintFamily::ChallengeDerivation
        | BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding
        | BatchedCpSemanticConstraintFamily::FoldedOutputDerivation
        | BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity
        | BatchedCpSemanticConstraintFamily::OriginalR1csValidity => Vec::new(),
    }
}

fn round_message_digest_body_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.round_message_rows.len() || round >= layout.round_message_digest_bodies.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.round_message_rows[round][idx],
            layout.round_message_digest_bodies[round][idx],
            section,
        );
    }
    equalities
}

fn round_message_witness_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.witness_fs_messages.len() || round >= layout.round_message_rows.len() {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.witness_fs_messages[round][idx],
            layout.round_message_rows[round][idx],
            section,
        );
    }
    equalities
}

fn fold_input_commitment_reconstruction_equalities(
    shape: &BatchedCpStatementShape,
    round: usize,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.fold_input_commitments.len()
        || round >= layout.witness_fold_input_commitments.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_range_equalities(
            &mut equalities,
            layout.fold_input_commitments[round][idx],
            layout.witness_fold_input_commitments[round][idx],
        );
    }
    equalities
}

fn fold_input_public_input_reconstruction_equalities(
    shape: &BatchedCpStatementShape,
    round: usize,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.fold_input_public_inputs.len()
        || round >= layout.witness_fold_input_public_inputs.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_range_equalities(
            &mut equalities,
            layout.fold_input_public_inputs[round][idx],
            layout.witness_fold_input_public_inputs[round][idx],
        );
    }
    equalities
}

fn fold_input_eval_message_reconstruction_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.fold_input_eval_messages.len()
        || round >= layout.witness_fold_input_eval_messages.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.fold_input_eval_messages[round][idx],
            layout.witness_fold_input_eval_messages[round][idx],
            section,
        );
    }
    equalities
}

fn fold_input_round_message_reconstruction_equalities_for_section(
    shape: &BatchedCpStatementShape,
    round: usize,
    section: &BatchedCpGr1csMessageSection,
) -> Vec<BatchedCpOracleByteEquality> {
    let layout = shape.product_oracle_layout();
    if round >= layout.witness_fold_input_eval_messages.len()
        || round >= layout.round_message_rows.len()
    {
        return Vec::new();
    }
    let mut equalities = Vec::new();
    for idx in 0..shape.active_count {
        push_section_range_equalities(
            &mut equalities,
            layout.witness_fold_input_eval_messages[round][idx],
            layout.round_message_rows[round][idx],
            section,
        );
    }
    equalities
}

fn push_section_range_equalities(
    equalities: &mut Vec<BatchedCpOracleByteEquality>,
    left: BatchedCpOracleByteRange,
    right: BatchedCpOracleByteRange,
    section: &BatchedCpGr1csMessageSection,
) {
    let Some(section_end) = section.offset.checked_add(section.len) else {
        return;
    };
    if section_end > left.len || section_end > right.len {
        return;
    }
    for offset in 0..section.len {
        equalities.push(BatchedCpOracleByteEquality {
            left_offset: left.offset + section.offset + offset,
            right_offset: right.offset + section.offset + offset,
        });
    }
}

fn columnar_packed_values_for_family(
    shape: &BatchedCpStatementShape,
    statement: &BatchedCpPublicStatement,
    family: BatchedCpSemanticConstraintFamily,
) -> Option<Vec<BatchedCpOraclePackedValue>> {
    match family {
        BatchedCpSemanticConstraintFamily::ChallengeDerivation => {
            shape.challenge_derivation_packed_values_for_statement(statement)
        }
        BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding => {
            shape.challenge_to_beta_packed_values_for_statement(statement)
        }
        BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness
        | BatchedCpSemanticConstraintFamily::ManifestMembership
        | BatchedCpSemanticConstraintFamily::RoundMessageBinding
        | BatchedCpSemanticConstraintFamily::FoldedOutputDerivation
        | BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity
        | BatchedCpSemanticConstraintFamily::OriginalR1csValidity
        | BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy => Some(Vec::new()),
    }
}

fn fill_family_columnar_v2_table(
    semantic: &BatchedCpSemanticRelationDescription,
    statement: &BatchedCpPublicStatement,
    oracle: &[u8],
    table: &BatchedCpSemanticFamilyColumnarV2Table,
    spec: &BatchedCpFamilyColumnarV2TableSpec,
) -> Result<Vec<Vec<u32>>, BatchedCpError> {
    let mut columns = vec![vec![0u32; table.padded_row_count]; table.column_kinds.len()];
    match &spec.source {
        BatchedCpFamilyColumnarV2TableSource::Equality(equalities) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || equalities.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            fill_family_equality_columns(oracle, equalities, &mut columns)?;
        }
        BatchedCpFamilyColumnarV2TableSource::PackedValue(family) => {
            let packed_values =
                columnar_packed_values_for_family(&semantic.shape, statement, *family)
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || packed_values.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, value) in packed_values.iter().enumerate() {
                columns[0][row] = packed_oracle_value_at(oracle, value.packed_index)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[1][row] = value.value;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::PoseidonR1cs(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Product
                || table.column_kinds.len() != 3
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            fill_family_poseidon_columns(constraints, oracle, &mut columns)?;
        }
        BatchedCpFamilyColumnarV2TableSource::FoldedPublicInputLinear(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_folded_public_input_linear_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::FoldedCommitmentRingMul(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_folded_commitment_ring_mul_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::FoldedEvaluationRingMul(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_folded_evaluation_ring_mul_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::AjtaiOpeningLinear(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Equality
                || table.column_kinds.len() != 2
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (left, right) = columnar_ajtai_opening_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = left;
                columns[1][row] = right;
            }
        }
        BatchedCpFamilyColumnarV2TableSource::OriginalR1cs(constraints) => {
            if table.kind != BatchedCpSemanticResidualV2Kind::Product
                || table.column_kinds.len() != 3
                || constraints.len() != table.row_count
            {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            }
            for (row, constraint) in constraints.iter().enumerate() {
                let (a, b, c) = columnar_original_r1cs_eval(constraint, oracle)
                    .ok_or(BatchedCpError::WitnessOracleMismatch)?;
                columns[0][row] = a;
                columns[1][row] = b;
                columns[2][row] = c;
            }
        }
    }
    Ok(columns)
}

fn fill_family_equality_columns(
    oracle: &[u8],
    equalities: &[BatchedCpOracleByteEquality],
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    for (row, equality) in equalities.iter().enumerate() {
        columns[0][row] = *oracle
            .get(equality.left_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)? as u32;
        columns[1][row] = *oracle
            .get(equality.right_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)? as u32;
    }
    Ok(())
}

#[cfg(feature = "whir")]
fn fill_family_poseidon_columns(
    constraints: &[BatchedCpPoseidonR1csRowConstraint],
    oracle: &[u8],
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    let mut cached_input_len = None;
    let mut cached_r1cs = None;
    for (row, constraint) in constraints.iter().enumerate() {
        if cached_input_len != Some(constraint.input_len) {
            cached_input_len = Some(constraint.input_len);
            cached_r1cs = Some(
                crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
                    b"fs-commit",
                    constraint.input_len,
                ),
            );
        }
        let (r1cs, poseidon_layout) = cached_r1cs
            .as_ref()
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        if constraint.row >= r1cs.num_constraints {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        columns[0][row] = columnar_poseidon_lc_eval(&r1cs.a, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[1][row] = columnar_poseidon_lc_eval(&r1cs.b, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[2][row] = columnar_poseidon_lc_eval(&r1cs.c, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
    }
    Ok(())
}

#[cfg(not(feature = "whir"))]
fn fill_family_poseidon_columns(
    constraints: &[BatchedCpPoseidonR1csRowConstraint],
    _oracle: &[u8],
    _columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    if constraints.is_empty() {
        Ok(())
    } else {
        Err(BatchedCpError::InvalidSemanticRelationContext)
    }
}

fn packed_oracle_value_at(bytes: &[u8], packed_index: usize) -> Option<u32> {
    let start = packed_index.checked_mul(3)?;
    if start >= bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for (idx, &byte) in bytes[start..bytes.len().min(start + 3)].iter().enumerate() {
        value |= (byte as u32) << (8 * idx);
    }
    Some(value)
}

fn fill_columnar_folded_output_residual(
    relation: &BatchedCpSemanticColumnarV2Description,
    oracle: &[u8],
    residual: &BatchedCpSemanticResidualV2,
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    let mut row = 0usize;
    for equality in relation
        .semantic
        .shape
        .folded_output_contribution_byte_equalities()
        .into_iter()
        .chain(
            relation
                .semantic
                .shape
                .folded_output_self_consistency_byte_equalities(),
        )
        .chain(
            relation
                .semantic
                .shape
                .fold_input_reconstruction_byte_equalities(),
        )
    {
        columns[residual.left_column][row] = *oracle
            .get(equality.left_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?
            as u32;
        columns[residual.right_column][row] = *oracle
            .get(equality.right_offset)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?
            as u32;
        row += 1;
    }
    for constraint in relation
        .semantic
        .shape
        .folded_public_input_linear_constraints()
    {
        let (left, right) = columnar_folded_public_input_linear_eval(&constraint, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = left;
        columns[residual.right_column][row] = right;
        row += 1;
    }
    for constraint in relation
        .semantic
        .shape
        .folded_commitment_ring_mul_constraints()
    {
        let (left, right) = columnar_folded_commitment_ring_mul_eval(&constraint, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = left;
        columns[residual.right_column][row] = right;
        row += 1;
    }
    for constraint in relation
        .semantic
        .shape
        .folded_evaluation_ring_mul_constraints()
    {
        let (left, right) = columnar_folded_evaluation_ring_mul_eval(&constraint, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = left;
        columns[residual.right_column][row] = right;
        row += 1;
    }
    if row != residual.row_count {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    Ok(())
}

#[cfg(feature = "whir")]
fn fill_columnar_poseidon_residual(
    relation: &BatchedCpSemanticColumnarV2Description,
    oracle: &[u8],
    residual: &BatchedCpSemanticResidualV2,
    columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    let constraints = relation
        .semantic
        .shape
        .poseidon_fs_commitment_r1cs_constraints();
    if constraints.len() != residual.row_count || residual.aux_columns.len() != 1 {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    let aux_column = residual.aux_columns[0];
    let mut cached_input_len = None;
    let mut cached_r1cs = None;
    for (row, constraint) in constraints.iter().enumerate() {
        if cached_input_len != Some(constraint.input_len) {
            cached_input_len = Some(constraint.input_len);
            cached_r1cs = Some(
                crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
                    b"fs-commit",
                    constraint.input_len,
                ),
            );
        }
        let (r1cs, poseidon_layout) = cached_r1cs
            .as_ref()
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
        if constraint.row >= r1cs.num_constraints {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let a = columnar_poseidon_lc_eval(&r1cs.a, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        let b = columnar_poseidon_lc_eval(&r1cs.b, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        let c = columnar_poseidon_lc_eval(&r1cs.c, constraint, poseidon_layout, oracle)
            .ok_or(BatchedCpError::WitnessOracleMismatch)?;
        columns[residual.left_column][row] = a;
        columns[aux_column][row] = b;
        columns[residual.right_column][row] = c;
    }
    Ok(())
}

#[cfg(not(feature = "whir"))]
fn fill_columnar_poseidon_residual(
    _relation: &BatchedCpSemanticColumnarV2Description,
    _oracle: &[u8],
    residual: &BatchedCpSemanticResidualV2,
    _columns: &mut [Vec<u32>],
) -> Result<(), BatchedCpError> {
    if residual.row_count == 0 {
        Ok(())
    } else {
        Err(BatchedCpError::InvalidSemanticRelationContext)
    }
}

fn columnar_folded_public_input_linear_eval(
    constraint: &BatchedCpFoldedPublicInputLinearConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.beta_coeff_offsets.len() != constraint.input_scalar_offsets.len() {
        return None;
    }
    let mut acc = 0u32;
    for (&beta_offset, &input_offset) in constraint
        .beta_coeff_offsets
        .iter()
        .zip(constraint.input_scalar_offsets.iter())
    {
        let beta = bb_from_i64(read_i64_at_offset(oracle, beta_offset)?);
        let input = bb_from_i64(read_i64_at_offset(oracle, input_offset)?);
        acc = bb_add_u32(acc, bb_mul_u32(beta, input));
    }
    let output = bb_from_i64(read_i64_at_offset(oracle, constraint.output_coeff_offset)?);
    Some((acc, output))
}

fn columnar_folded_commitment_ring_mul_eval(
    constraint: &BatchedCpFoldedCommitmentRingMulConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.beta_coeff_offsets.len() != constraint.commitment_coeff_offsets.len()
        || constraint.output_coeff_index >= D
    {
        return None;
    }
    let mut acc = 0u32;
    for (beta_offsets, commitment_offsets) in constraint
        .beta_coeff_offsets
        .iter()
        .zip(constraint.commitment_coeff_offsets.iter())
    {
        let beta = read_bb_ring_at_offsets(oracle, beta_offsets)?;
        let commitment = read_bb_ring_at_offsets(oracle, commitment_offsets)?;
        let product = bb_cyclotomic_mul(&beta, &commitment);
        acc = bb_add_u32(acc, product[constraint.output_coeff_index]);
    }
    let output = bb_from_i64(read_i64_at_offset(oracle, constraint.output_coeff_offset)?);
    Some((acc, output))
}

fn columnar_folded_evaluation_ring_mul_eval(
    constraint: &BatchedCpFoldedEvaluationRingMulConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.beta_coeff_offsets.len() != constraint.evaluation_coeff_offsets.len()
        || constraint.output_coeff_index >= D
    {
        return None;
    }
    let mut acc = 0u32;
    for (beta_offsets, evaluation_offsets) in constraint
        .beta_coeff_offsets
        .iter()
        .zip(constraint.evaluation_coeff_offsets.iter())
    {
        let beta = read_bb_ring_at_offsets(oracle, beta_offsets)?;
        let evaluation = read_bb_ring_at_offsets(oracle, evaluation_offsets)?;
        let product = bb_cyclotomic_mul(&beta, &evaluation);
        acc = bb_add_u32(acc, product[constraint.output_coeff_index]);
    }
    let output = bb_from_i64(read_i64_at_offset(oracle, constraint.output_coeff_offset)?);
    Some((acc, output))
}

fn columnar_ajtai_opening_eval(
    constraint: &BatchedCpAjtaiOpeningLinearConstraint,
    oracle: &[u8],
) -> Option<(u32, u32)> {
    if constraint.coeff >= D
        || constraint.matrix_row.len()
            != constraint.public_input_offsets.len() + constraint.witness_coeff_offsets.len()
    {
        return None;
    }
    let mut acc = 0u32;
    for (matrix_elem, &public_offset) in constraint
        .matrix_row
        .iter()
        .zip(constraint.public_input_offsets.iter())
    {
        let public_scalar = bb_from_i64(read_i64_at_offset(oracle, public_offset)?);
        let matrix_coeff = bb_from_i64(matrix_elem.coeffs[constraint.coeff]);
        acc = bb_add_u32(acc, bb_mul_u32(matrix_coeff, public_scalar));
    }
    for (matrix_elem, witness_offsets) in constraint
        .matrix_row
        .iter()
        .skip(constraint.public_input_offsets.len())
        .zip(constraint.witness_coeff_offsets.iter())
    {
        let witness = read_bb_ring_at_offsets(oracle, witness_offsets)?;
        let product = bb_cyclotomic_mul(&ring_element_to_bb_array(matrix_elem), &witness);
        acc = bb_add_u32(acc, product[constraint.coeff]);
    }
    let commitment = bb_from_i64(read_i64_at_offset(
        oracle,
        constraint.commitment_coeff_offset,
    )?);
    Some((acc, commitment))
}

fn columnar_original_r1cs_eval(
    constraint: &BatchedCpOriginalR1csConstraint,
    oracle: &[u8],
) -> Option<(u32, u32, u32)> {
    let a = columnar_original_r1cs_linear_eval(&constraint.a_terms, oracle)?;
    let b = columnar_original_r1cs_linear_eval(&constraint.b_terms, oracle)?;
    let c = columnar_original_r1cs_linear_eval(&constraint.c_terms, oracle)?;
    Some((a, b, c))
}

fn columnar_original_r1cs_linear_eval(terms: &[(i64, usize)], oracle: &[u8]) -> Option<u32> {
    let mut acc = 0u32;
    for &(matrix_coeff, value_offset) in terms {
        let value = bb_from_i64(read_i64_at_offset(oracle, value_offset)?);
        let coeff = bb_from_i64(matrix_coeff);
        acc = bb_add_u32(acc, bb_mul_u32(coeff, value));
    }
    Some(acc)
}

#[cfg(feature = "whir")]
fn columnar_poseidon_lc_eval(
    matrix: &crate::r1cs::SparseMatrix,
    constraint: &BatchedCpPoseidonR1csRowConstraint,
    layout: &crate::snark::cp_snark::Poseidon2PrivateDigestR1csLayout,
    oracle: &[u8],
) -> Option<u32> {
    let mut acc = 0u32;
    for &(_, col, coeff) in matrix
        .entries
        .iter()
        .filter(|&&(row, _, _)| row == constraint.row)
    {
        let value = if col == layout.off_one {
            1
        } else {
            let offset = columnar_poseidon_var_offset(constraint, layout, col)?;
            read_u32_at_offset(oracle, offset)?
        };
        acc = bb_add_u32(acc, bb_mul_u32(bb_from_i64(coeff), value));
    }
    Some(acc)
}

#[cfg(feature = "whir")]
fn columnar_poseidon_var_offset(
    constraint: &BatchedCpPoseidonR1csRowConstraint,
    layout: &crate::snark::cp_snark::Poseidon2PrivateDigestR1csLayout,
    col: usize,
) -> Option<usize> {
    if (layout.off_output..layout.off_output + 8).contains(&col) {
        return constraint
            .output_offsets
            .get(col - layout.off_output)
            .copied();
    }
    if (layout.off_input..layout.off_input + layout.input_len).contains(&col) {
        return constraint
            .input_offsets
            .get(col - layout.off_input)
            .copied();
    }
    let aux_start = layout.off_input + layout.input_len;
    if (aux_start..layout.num_variables).contains(&col) {
        return constraint.aux_offsets.get(col - aux_start).copied();
    }
    None
}

fn read_i64_at_offset(bytes: &[u8], offset: usize) -> Option<i64> {
    let end = offset.checked_add(8)?;
    let chunk = bytes.get(offset..end)?;
    Some(i64::from_le_bytes(chunk.try_into().ok()?))
}

#[cfg(feature = "whir")]
fn read_u32_at_offset(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let chunk = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn read_bb_ring_at_offsets(bytes: &[u8], offsets: &[usize]) -> Option<[u32; D]> {
    if offsets.len() != D {
        return None;
    }
    let mut out = [0u32; D];
    for (idx, &offset) in offsets.iter().enumerate() {
        out[idx] = bb_from_i64(read_i64_at_offset(bytes, offset)?);
    }
    Some(out)
}

fn ring_element_to_bb_array(value: &RingElement) -> [u32; D] {
    let mut out = [0u32; D];
    for (idx, &coeff) in value.coeffs.iter().enumerate() {
        out[idx] = bb_from_i64(coeff);
    }
    out
}

const BABYBEAR_MODULUS_U64: u64 = 2_013_265_921;

fn bb_from_i64(value: i64) -> u32 {
    (value as i128).rem_euclid(BABYBEAR_MODULUS_U64 as i128) as u32
}

fn bb_add_u32(lhs: u32, rhs: u32) -> u32 {
    let sum = lhs as u64 + rhs as u64;
    if sum >= BABYBEAR_MODULUS_U64 {
        (sum - BABYBEAR_MODULUS_U64) as u32
    } else {
        sum as u32
    }
}

fn bb_sub_u32(lhs: u32, rhs: u32) -> u32 {
    if lhs >= rhs {
        lhs - rhs
    } else {
        (lhs as u64 + BABYBEAR_MODULUS_U64 - rhs as u64) as u32
    }
}

fn bb_mul_u32(lhs: u32, rhs: u32) -> u32 {
    ((lhs as u64 * rhs as u64) % BABYBEAR_MODULUS_U64) as u32
}
