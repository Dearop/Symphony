fn bb_cyclotomic_mul(lhs: &[u32; D], rhs: &[u32; D]) -> [u32; D] {
    let mut out = [0u32; D];
    for (i, &lhs_coeff) in lhs.iter().enumerate() {
        for (j, &rhs_coeff) in rhs.iter().enumerate() {
            let product = bb_mul_u32(lhs_coeff, rhs_coeff);
            let idx = i + j;
            if idx < D {
                out[idx] = bb_add_u32(out[idx], product);
            } else {
                out[idx - D] = bb_sub_u32(out[idx - D], product);
            }
        }
    }
    out
}

impl BatchedCpPublicStatement {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"symphony-batched-cp-public-statement-v1");
        encode_statement_shape(&mut out, &self.shape);
        out.extend_from_slice(&self.manifest_digest);
        push_usize(&mut out, self.round_message_commitments.len());
        for commitment in &self.round_message_commitments {
            out.extend_from_slice(commitment);
        }
        out.extend_from_slice(&self.batch_challenge_digest);
        out.extend_from_slice(&self.folded_output_accumulator_root);
        out.extend_from_slice(&self.whir_parameter_digest);
        out
    }
}

impl BatchedCpSymbt3PublicStatement {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"symphony-batched-cp-symbt3-compressed-research-public-v1",
        );
        out.extend_from_slice(&self.shape_id);
        push_usize(&mut out, self.batch_capacity);
        push_usize(&mut out, self.active_count);
        out.extend_from_slice(&self.old_accumulator_digest);
        out.extend_from_slice(&self.new_accumulator_digest);
        push_i64_vec(&mut out, &self.old_accumulator_coordinates);
        push_i64_vec(&mut out, &self.new_accumulator_coordinates);
        out.extend_from_slice(&self.input_public_boundary_digest);
        out.extend_from_slice(&self.batch_manifest_root);
        out.extend_from_slice(&self.manifest_oracle_root);
        out.extend_from_slice(&self.manifest_eval_claim.to_le_bytes());
        out.extend_from_slice(&self.batch_manifest_layout_digest);
        out.extend_from_slice(&self.source_column_layout_digest);
        out.extend_from_slice(&self.message_semantic_layout_digest);
        out.extend_from_slice(&self.production_norm_range_layout_digest);
        out.extend_from_slice(&self.structured_projection_layout_digest);
        out.extend_from_slice(&self.monomial_embedding_layout_digest);
        out.extend_from_slice(&self.representative_layout_digest);
        out.extend_from_slice(&self.norm_range_public_digest);
        out.extend_from_slice(&self.source_assignment_boundary_digest);
        out.extend_from_slice(&self.source_ajtai_commitment_boundary_digest);
        push_usize(&mut out, self.message_oracle_roots.len());
        for root in &self.message_oracle_roots {
            out.extend_from_slice(root);
        }
        push_i64_vec(&mut out, &self.folded_public_input);
        push_i64_vec(&mut out, &self.folded_commitment);
        push_i64_vec(&mut out, &self.folded_evaluation);
        push_i64_vec(&mut out, &self.folded_accumulator_coordinates);
        out.extend_from_slice(&self.folded_ajtai_opening_root);
        push_i64_vec(&mut out, &self.folded_ajtai_commitment);
        out.extend_from_slice(&self.folded_gr1cs_boundary_digest);
        out.extend_from_slice(&self.ring_module_layout_digest);
        out.extend_from_slice(&self.ajtai_commit_layout_digest);
        out.extend_from_slice(&self.r1cs_evaluator_layout_digest);
        out.extend_from_slice(&self.gr1cs_residual_layout_digest);
        out.extend_from_slice(&self.algebra_law_digest);
        out.extend_from_slice(&self.ajtai_linear_algebra_layout_digest);
        out.extend_from_slice(&self.ajtai_norm_range_layout_digest);
        out.extend_from_slice(&self.projection_layout_digest);
        out.extend_from_slice(&self.range_layout_digest);
        out.extend_from_slice(&self.folded_gr1cs_product_residual_layout_digest);
        out.extend_from_slice(&self.folded_output_accumulator_root);
        out.extend_from_slice(&self.whir_parameter_digest);
        out
    }

    #[must_use]
    pub fn matches_relation(&self, relation: &BatchedCpSymbt3RelationDescription) -> bool {
        self.shape_id == relation.shape.shape_id
            && self.batch_capacity == relation.shape.batch_capacity
            && self.active_count == relation.shape.active_count
            && self.old_accumulator_digest != [0u8; 32]
            && self.new_accumulator_digest != [0u8; 32]
            && self.old_accumulator_coordinates.len()
                == relation.symbt3_accumulator_coordinate_len()
            && self.new_accumulator_coordinates.len()
                == relation.symbt3_accumulator_coordinate_len()
            && self.old_accumulator_digest
                == symbt3_accumulator_coordinates_digest(
                    relation.shape.accumulator_shape.digest_scheme,
                    b"old",
                    &self.old_accumulator_coordinates,
                )
            && self.new_accumulator_digest
                == symbt3_accumulator_coordinates_digest(
                    relation.shape.accumulator_shape.digest_scheme,
                    b"new",
                    &self.new_accumulator_coordinates,
                )
            && symbt3_accumulator_transition_coordinates(relation, self)
                .is_some_and(|expected| expected == self.new_accumulator_coordinates)
            && self.batch_manifest_layout_digest
                == relation
                    .batch_manifest_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && symbt3_manifest_root_link_is_valid(
                relation.shape.accumulator_shape.digest_scheme,
                self,
            )
            && symbt3_canonical_manifest_root_for_statement(relation, self)
                .is_some_and(|root| root == self.manifest_oracle_root)
            && self.manifest_eval_claim < BABYBEAR_MODULUS_U64 as u32
            && self.source_column_layout_digest
                == relation
                    .batch_manifest_layout
                    .source_column_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.message_semantic_layout_digest
                == relation
                    .message_semantic_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.production_norm_range_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.structured_projection_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .projection_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.monomial_embedding_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .monomial_embedding_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.representative_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .representative_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.source_assignment_boundary_digest != [0u8; 32]
            && self.source_ajtai_commitment_boundary_digest != [0u8; 32]
            && self.message_oracle_roots.len() == relation.shape.round_message_lens.len()
            && self.folded_public_input.len() == relation.symbt3_public_input_coordinate_len()
            && self.folded_commitment.len() == relation.symbt3_commitment_coordinate_len()
            && self.folded_evaluation.len() == relation.symbt3_evaluation_coordinate_len()
            && self.folded_accumulator_coordinates.len()
                == relation.symbt3_accumulator_coordinate_len()
            && self.folded_ajtai_commitment.len() == relation.symbt3_commitment_coordinate_len()
            && self.folded_ajtai_commitment == self.folded_commitment
            && self.ring_module_layout_digest
                == relation
                    .ring_module_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.ajtai_commit_layout_digest
                == relation
                    .ajtai_commit_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.r1cs_evaluator_layout_digest
                == relation
                    .r1cs_evaluator_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.gr1cs_residual_layout_digest
                == relation
                    .gr1cs_residual_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.algebra_law_digest
                == relation
                    .algebra_law
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.ajtai_linear_algebra_layout_digest
                == relation
                    .ajtai_linear_algebra_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.ajtai_norm_range_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.projection_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .projection_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.range_layout_digest
                == relation
                    .ajtai_norm_range_layout
                    .range_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.norm_range_public_digest
                == symbt3_norm_range_public_digest(
                    relation.shape.accumulator_shape.digest_scheme,
                    &self.folded_ajtai_opening_root,
                    &self.production_norm_range_layout_digest,
                    &self.structured_projection_layout_digest,
                    &self.monomial_embedding_layout_digest,
                    &self.representative_layout_digest,
                )
            && self.folded_gr1cs_product_residual_layout_digest
                == relation
                    .folded_gr1cs_product_residual_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme)
            && self.whir_parameter_digest == relation.shape.accumulator_shape.whir_parameter_digest
    }
}

impl BatchedCpSymbt3Witness {
    #[must_use]
    pub fn from_batched_witness(witness: &BatchedCpWitnessBundle) -> Self {
        Self {
            message_oracles: witness.round_message_oracles.clone(),
            algebraic_trace_columns: Vec::new(),
            source_ajtai_opening_values: Vec::new(),
            folded_ajtai_opening_values: Vec::new(),
            source_r1cs_assignment_values: Vec::new(),
            manifest_source_values: Vec::new(),
        }
    }
}

impl Symbt3TypedMessageOracle {
    #[must_use]
    pub fn from_round_messages(
        round: usize,
        rows: &[Vec<u8>],
        layout: &Symbt3RoundMessageLayout,
    ) -> Self {
        let rows = rows
            .iter()
            .enumerate()
            .map(|(row_index, message)| {
                let mut sections = layout
                    .sections
                    .iter()
                    .map(|section| {
                        let values = message
                            .get(
                                section.coordinate_offset
                                    ..section
                                        .coordinate_offset
                                        .saturating_add(section.coordinate_len),
                            )
                            .unwrap_or(&[])
                            .iter()
                            .map(|&value| u32::from(value))
                            .collect::<Vec<_>>();
                        Symbt3TypedMessageSection {
                            section_kind: section.section_kind,
                            offset: section.coordinate_offset,
                            values,
                        }
                    })
                    .collect::<Vec<_>>();
                let covered_end = layout
                    .sections
                    .iter()
                    .map(|section| {
                        section
                            .coordinate_offset
                            .saturating_add(section.coordinate_len)
                    })
                    .max()
                    .unwrap_or(0);
                if covered_end < message.len() {
                    sections.push(Symbt3TypedMessageSection {
                        section_kind: Symbt3MessageSectionKind::BoundaryDigestCoordinate,
                        offset: covered_end,
                        values: message[covered_end..]
                            .iter()
                            .map(|&value| u32::from(value))
                            .collect(),
                    });
                }
                Symbt3TypedMessageRow {
                    row_index,
                    sections,
                }
            })
            .collect();
        Self { round, rows }
    }

    #[must_use]
    pub fn to_round_messages(&self, layout: &Symbt3RoundMessageLayout) -> Option<Vec<Vec<u8>>> {
        if self.round != layout.round_index || self.rows.len() != layout.row_count {
            return None;
        }
        let mut rows = Vec::with_capacity(self.rows.len());
        for (expected_row_index, typed_row) in self.rows.iter().enumerate() {
            if typed_row.row_index != expected_row_index {
                return None;
            }
            let mut message = vec![0u8; layout.message_len];
            for typed_section in &typed_row.sections {
                let end = typed_section
                    .offset
                    .checked_add(typed_section.values.len())?;
                if end > message.len() {
                    return None;
                }
                for (dst, &value) in message[typed_section.offset..end]
                    .iter_mut()
                    .zip(&typed_section.values)
                {
                    *dst = u8::try_from(value).ok()?;
                }
            }
            for section_layout in &layout.sections {
                let typed_section = typed_row.sections.iter().find(|section| {
                    section.section_kind == section_layout.section_kind
                        && section.offset == section_layout.coordinate_offset
                })?;
                if typed_section.values.len() != section_layout.coordinate_len {
                    return None;
                }
            }
            rows.push(message);
        }
        Some(rows)
    }
}

impl Symbt3AccumulatorWitness {
    #[must_use]
    pub fn from_symbt3_witness(
        relation: &BatchedCpSymbt3RelationDescription,
        witness: &BatchedCpSymbt3Witness,
    ) -> Self {
        let message_oracles = witness
            .message_oracles
            .iter()
            .enumerate()
            .map(|(round, rows)| {
                let layout = &relation.message_semantic_layout.round_layouts[round];
                Symbt3TypedMessageOracle::from_round_messages(round, rows, layout)
            })
            .collect();
        Self {
            manifest_oracle: witness.manifest_source_values.clone(),
            source_columns: witness.source_r1cs_assignment_values.clone(),
            message_oracles,
            folded_witness_columns: vec![witness.folded_ajtai_opening_values.clone()],
            ajtai_openings: witness.source_ajtai_opening_values.clone(),
            old_accumulator_coordinates: Vec::new(),
            new_accumulator_coordinates: Vec::new(),
        }
    }

    #[must_use]
    pub fn to_symbt3_witness(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> Option<BatchedCpSymbt3Witness> {
        if self.message_oracles.len() != relation.message_semantic_layout.round_layouts.len()
            || self.folded_witness_columns.len() != 1
        {
            return None;
        }
        let mut message_oracles =
            vec![Vec::new(); relation.message_semantic_layout.round_layouts.len()];
        for typed_oracle in &self.message_oracles {
            let layout = relation
                .message_semantic_layout
                .round_layouts
                .get(typed_oracle.round)?;
            message_oracles[typed_oracle.round] = typed_oracle.to_round_messages(layout)?;
        }
        Some(BatchedCpSymbt3Witness {
            message_oracles,
            algebraic_trace_columns: Vec::new(),
            source_ajtai_opening_values: self.ajtai_openings.clone(),
            folded_ajtai_opening_values: self.folded_witness_columns[0].clone(),
            source_r1cs_assignment_values: self.source_columns.clone(),
            manifest_source_values: self.manifest_oracle.clone(),
        })
    }
}

#[must_use]
fn symbt3_default_compressed_boundary_digest_scheme() -> PublicDigestScheme {
    #[cfg(feature = "whir")]
    {
        PublicDigestScheme::Poseidon2BabyBear
    }
    #[cfg(not(feature = "whir"))]
    {
        PublicDigestScheme::Sha256
    }
}

#[must_use]
pub fn symbt3_digest_digest_vec(
    scheme: PublicDigestScheme,
    domain: &'static [u8],
    values: &[Digest32],
) -> Digest32 {
    let mut body = Vec::new();
    push_digest_vec(&mut body, values);
    digest_domain_with_scheme(scheme, domain, &body)
}

#[must_use]
pub fn symbt3_digest_i64_matrix(
    scheme: PublicDigestScheme,
    domain: &'static [u8],
    values: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    push_i64_matrix(&mut body, values);
    digest_domain_with_scheme(scheme, domain, &body)
}

#[must_use]
pub fn symbt3_batch_items_digest(
    scheme: PublicDigestScheme,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
    source_assignment_roots: &[Digest32],
    message_oracle_roots: &[Digest32],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-public-values",
        input_public_values,
    ));
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-commitment-values",
        input_commitment_values,
    ));
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-evaluation-values",
        input_evaluation_values,
    ));
    body.extend_from_slice(&symbt3_digest_i64_matrix(
        scheme,
        b"symbt3-k4-6-input-accumulator-values",
        input_accumulator_values,
    ));
    body.extend_from_slice(&symbt3_digest_digest_vec(
        scheme,
        b"symbt3-k4-6-source-assignment-roots",
        source_assignment_roots,
    ));
    body.extend_from_slice(&symbt3_digest_digest_vec(
        scheme,
        b"symbt3-k4-6-message-oracle-roots",
        message_oracle_roots,
    ));
    digest_domain_with_scheme(scheme, b"symbt3-k4-6-batch-items", &body)
}

#[must_use]
pub fn symbt3_public_source_boundary_digest(
    scheme: PublicDigestScheme,
    source_assignment_roots_digest: &Digest32,
    source_assignment_boundary_digest: &Digest32,
    source_ajtai_opening_roots_digest: &Digest32,
    source_ajtai_commitment_boundary_digest: &Digest32,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(source_assignment_roots_digest);
    body.extend_from_slice(source_assignment_boundary_digest);
    body.extend_from_slice(source_ajtai_opening_roots_digest);
    body.extend_from_slice(source_ajtai_commitment_boundary_digest);
    digest_domain_with_scheme(scheme, b"symbt3-k4-6-public-source-boundary", &body)
}

impl Symbt3AccumulatorInstance {
    #[must_use]
    pub fn from_public_statement(
        profile_digest: Digest32,
        old_accumulator_digest: Digest32,
        new_accumulator_digest: Digest32,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Self {
        Self::from_public_statement_with_scheme(
            symbt3_default_compressed_boundary_digest_scheme(),
            profile_digest,
            old_accumulator_digest,
            new_accumulator_digest,
            statement,
        )
    }

    #[must_use]
    pub fn from_public_statement_with_scheme(
        scheme: PublicDigestScheme,
        profile_digest: Digest32,
        old_accumulator_digest: Digest32,
        new_accumulator_digest: Digest32,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Self {
        let source_assignment_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-assignment-roots",
            &statement.source_assignment_roots,
        );
        let source_ajtai_opening_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-ajtai-opening-roots",
            &statement.source_ajtai_opening_roots,
        );
        let message_oracle_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-message-oracle-roots",
            &statement.message_oracle_roots,
        );
        let batch_items_digest = symbt3_batch_items_digest(
            scheme,
            &statement.input_public_values,
            &statement.input_commitment_values,
            &statement.input_evaluation_values,
            &statement.input_accumulator_values,
            &statement.source_assignment_roots,
            &statement.message_oracle_roots,
        );
        let public_source_boundary_digest = symbt3_public_source_boundary_digest(
            scheme,
            &source_assignment_roots_digest,
            &statement.source_assignment_boundary_digest,
            &source_ajtai_opening_roots_digest,
            &statement.source_ajtai_commitment_boundary_digest,
        );
        Self {
            profile_digest,
            shape_id: statement.shape_id,
            batch_capacity: statement.batch_capacity,
            active_count: statement.active_count,
            old_accumulator_digest,
            new_accumulator_digest,
            old_accumulator_coordinates: statement.old_accumulator_coordinates.clone(),
            new_accumulator_coordinates: statement.new_accumulator_coordinates.clone(),
            input_public_boundary_digest: statement.input_public_boundary_digest,
            manifest_root: statement.batch_manifest_root,
            manifest_oracle_root: statement.manifest_oracle_root,
            manifest_eval_claim: statement.manifest_eval_claim,
            manifest_layout_digest: statement.batch_manifest_layout_digest,
            source_column_layout_digest: statement.source_column_layout_digest,
            message_semantic_layout_digest: statement.message_semantic_layout_digest,
            production_norm_range_layout_digest: statement.production_norm_range_layout_digest,
            structured_projection_layout_digest: statement.structured_projection_layout_digest,
            monomial_embedding_layout_digest: statement.monomial_embedding_layout_digest,
            representative_layout_digest: statement.representative_layout_digest,
            norm_range_public_digest: statement.norm_range_public_digest,
            batch_items_digest,
            public_source_boundary_digest,
            source_assignment_roots_digest,
            source_ajtai_opening_roots_digest,
            message_oracle_roots_digest,
            input_public_values: statement.input_public_values.clone(),
            input_commitment_values: statement.input_commitment_values.clone(),
            input_evaluation_values: statement.input_evaluation_values.clone(),
            input_accumulator_values: statement.input_accumulator_values.clone(),
            source_assignment_roots: statement.source_assignment_roots.clone(),
            source_assignment_boundary_digest: statement.source_assignment_boundary_digest,
            source_ajtai_opening_roots: statement.source_ajtai_opening_roots.clone(),
            source_ajtai_commitment_boundary_digest: statement
                .source_ajtai_commitment_boundary_digest,
            message_oracle_roots: statement.message_oracle_roots.clone(),
            folded_public_input: statement.folded_public_input.clone(),
            folded_commitment: statement.folded_commitment.clone(),
            folded_evaluation: statement.folded_evaluation.clone(),
            folded_batch_accumulator_coordinates: statement.folded_accumulator_coordinates.clone(),
            folded_ajtai_opening_root: statement.folded_ajtai_opening_root,
            folded_ajtai_commitment: statement.folded_ajtai_commitment.clone(),
            folded_gr1cs_boundary_digest: statement.folded_gr1cs_boundary_digest,
            ring_module_layout_digest: statement.ring_module_layout_digest,
            ajtai_commit_layout_digest: statement.ajtai_commit_layout_digest,
            r1cs_evaluator_layout_digest: statement.r1cs_evaluator_layout_digest,
            gr1cs_residual_layout_digest: statement.gr1cs_residual_layout_digest,
            algebra_law_digest: statement.algebra_law_digest,
            ajtai_linear_algebra_layout_digest: statement.ajtai_linear_algebra_layout_digest,
            ajtai_norm_range_layout_digest: statement.ajtai_norm_range_layout_digest,
            projection_layout_digest: statement.projection_layout_digest,
            range_layout_digest: statement.range_layout_digest,
            folded_gr1cs_product_residual_layout_digest: statement
                .folded_gr1cs_product_residual_layout_digest,
            folded_output_boundary_digest: statement.folded_output_accumulator_root,
            whir_params_digest: statement.whir_parameter_digest,
        }
    }

    #[must_use]
    pub fn to_public_statement(&self) -> BatchedCpSymbt3PublicStatement {
        BatchedCpSymbt3PublicStatement {
            shape_id: self.shape_id,
            batch_capacity: self.batch_capacity,
            active_count: self.active_count,
            old_accumulator_digest: self.old_accumulator_digest,
            new_accumulator_digest: self.new_accumulator_digest,
            old_accumulator_coordinates: self.old_accumulator_coordinates.clone(),
            new_accumulator_coordinates: self.new_accumulator_coordinates.clone(),
            input_public_boundary_digest: self.input_public_boundary_digest,
            batch_manifest_root: self.manifest_root,
            manifest_oracle_root: self.manifest_oracle_root,
            manifest_eval_claim: self.manifest_eval_claim,
            batch_manifest_layout_digest: self.manifest_layout_digest,
            source_column_layout_digest: self.source_column_layout_digest,
            message_semantic_layout_digest: self.message_semantic_layout_digest,
            production_norm_range_layout_digest: self.production_norm_range_layout_digest,
            structured_projection_layout_digest: self.structured_projection_layout_digest,
            monomial_embedding_layout_digest: self.monomial_embedding_layout_digest,
            representative_layout_digest: self.representative_layout_digest,
            norm_range_public_digest: self.norm_range_public_digest,
            input_public_values: self.input_public_values.clone(),
            input_commitment_values: self.input_commitment_values.clone(),
            input_evaluation_values: self.input_evaluation_values.clone(),
            input_accumulator_values: self.input_accumulator_values.clone(),
            source_assignment_roots: self.source_assignment_roots.clone(),
            source_assignment_boundary_digest: self.source_assignment_boundary_digest,
            source_ajtai_opening_roots: self.source_ajtai_opening_roots.clone(),
            source_ajtai_commitment_boundary_digest: self.source_ajtai_commitment_boundary_digest,
            message_oracle_roots: self.message_oracle_roots.clone(),
            folded_public_input: self.folded_public_input.clone(),
            folded_commitment: self.folded_commitment.clone(),
            folded_evaluation: self.folded_evaluation.clone(),
            folded_accumulator_coordinates: self.folded_batch_accumulator_coordinates.clone(),
            folded_ajtai_opening_root: self.folded_ajtai_opening_root,
            folded_ajtai_commitment: self.folded_ajtai_commitment.clone(),
            folded_gr1cs_boundary_digest: self.folded_gr1cs_boundary_digest,
            ring_module_layout_digest: self.ring_module_layout_digest,
            ajtai_commit_layout_digest: self.ajtai_commit_layout_digest,
            r1cs_evaluator_layout_digest: self.r1cs_evaluator_layout_digest,
            gr1cs_residual_layout_digest: self.gr1cs_residual_layout_digest,
            algebra_law_digest: self.algebra_law_digest,
            ajtai_linear_algebra_layout_digest: self.ajtai_linear_algebra_layout_digest,
            ajtai_norm_range_layout_digest: self.ajtai_norm_range_layout_digest,
            projection_layout_digest: self.projection_layout_digest,
            range_layout_digest: self.range_layout_digest,
            folded_gr1cs_product_residual_layout_digest: self
                .folded_gr1cs_product_residual_layout_digest,
            folded_output_accumulator_root: self.folded_output_boundary_digest,
            whir_parameter_digest: self.whir_params_digest,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let scheme = symbt3_default_compressed_boundary_digest_scheme();
        let has_expanded_batch_items = !self.input_public_values.is_empty()
            || !self.input_commitment_values.is_empty()
            || !self.input_evaluation_values.is_empty()
            || !self.input_accumulator_values.is_empty()
            || !self.source_assignment_roots.is_empty()
            || !self.message_oracle_roots.is_empty();
        let source_assignment_roots_digest = if self.source_assignment_roots.is_empty() {
            self.source_assignment_roots_digest
        } else {
            symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-assignment-roots",
                &self.source_assignment_roots,
            )
        };
        let source_ajtai_opening_roots_digest = if self.source_ajtai_opening_roots.is_empty() {
            self.source_ajtai_opening_roots_digest
        } else {
            symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-source-ajtai-opening-roots",
                &self.source_ajtai_opening_roots,
            )
        };
        let message_oracle_roots_digest = if self.message_oracle_roots.is_empty() {
            self.message_oracle_roots_digest
        } else {
            symbt3_digest_digest_vec(
                scheme,
                b"symbt3-k4-6-message-oracle-roots",
                &self.message_oracle_roots,
            )
        };
        let batch_items_digest = if has_expanded_batch_items {
            symbt3_batch_items_digest(
                scheme,
                &self.input_public_values,
                &self.input_commitment_values,
                &self.input_evaluation_values,
                &self.input_accumulator_values,
                &self.source_assignment_roots,
                &self.message_oracle_roots,
            )
        } else {
            self.batch_items_digest
        };
        let public_source_boundary_digest = if self.source_assignment_roots.is_empty()
            && self.source_ajtai_opening_roots.is_empty()
        {
            self.public_source_boundary_digest
        } else {
            symbt3_public_source_boundary_digest(
                scheme,
                &source_assignment_roots_digest,
                &self.source_assignment_boundary_digest,
                &source_ajtai_opening_roots_digest,
                &self.source_ajtai_commitment_boundary_digest,
            )
        };
        let mut out = Vec::new();
        push_bytes(&mut out, b"symphony-symbt3-accumulator-instance-v2");
        out.extend_from_slice(&self.profile_digest);
        out.extend_from_slice(&self.shape_id);
        push_usize(&mut out, self.batch_capacity);
        push_usize(&mut out, self.active_count);
        out.extend_from_slice(&self.old_accumulator_digest);
        out.extend_from_slice(&self.new_accumulator_digest);
        push_i64_vec(&mut out, &self.old_accumulator_coordinates);
        push_i64_vec(&mut out, &self.new_accumulator_coordinates);
        out.extend_from_slice(&self.input_public_boundary_digest);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.manifest_oracle_root);
        out.extend_from_slice(&self.manifest_eval_claim.to_le_bytes());
        out.extend_from_slice(&self.manifest_layout_digest);
        out.extend_from_slice(&self.source_column_layout_digest);
        out.extend_from_slice(&self.message_semantic_layout_digest);
        out.extend_from_slice(&self.production_norm_range_layout_digest);
        out.extend_from_slice(&self.structured_projection_layout_digest);
        out.extend_from_slice(&self.monomial_embedding_layout_digest);
        out.extend_from_slice(&self.representative_layout_digest);
        out.extend_from_slice(&self.norm_range_public_digest);
        out.extend_from_slice(&batch_items_digest);
        out.extend_from_slice(&public_source_boundary_digest);
        out.extend_from_slice(&source_assignment_roots_digest);
        out.extend_from_slice(&self.source_assignment_boundary_digest);
        out.extend_from_slice(&source_ajtai_opening_roots_digest);
        out.extend_from_slice(&self.source_ajtai_commitment_boundary_digest);
        out.extend_from_slice(&message_oracle_roots_digest);
        push_i64_vec(&mut out, &self.folded_public_input);
        push_i64_vec(&mut out, &self.folded_commitment);
        push_i64_vec(&mut out, &self.folded_evaluation);
        push_i64_vec(&mut out, &self.folded_batch_accumulator_coordinates);
        out.extend_from_slice(&self.folded_ajtai_opening_root);
        push_i64_vec(&mut out, &self.folded_ajtai_commitment);
        out.extend_from_slice(&self.folded_gr1cs_boundary_digest);
        out.extend_from_slice(&self.ring_module_layout_digest);
        out.extend_from_slice(&self.ajtai_commit_layout_digest);
        out.extend_from_slice(&self.r1cs_evaluator_layout_digest);
        out.extend_from_slice(&self.gr1cs_residual_layout_digest);
        out.extend_from_slice(&self.algebra_law_digest);
        out.extend_from_slice(&self.ajtai_linear_algebra_layout_digest);
        out.extend_from_slice(&self.ajtai_norm_range_layout_digest);
        out.extend_from_slice(&self.projection_layout_digest);
        out.extend_from_slice(&self.range_layout_digest);
        out.extend_from_slice(&self.folded_gr1cs_product_residual_layout_digest);
        out.extend_from_slice(&self.folded_output_boundary_digest);
        out.extend_from_slice(&self.whir_params_digest);
        out
    }

    #[must_use]
    pub fn digest(&self, scheme: PublicDigestScheme) -> Digest32 {
        digest_domain_with_scheme(
            scheme,
            b"symphony-symbt3-accumulator-instance-v2",
            &self.canonical_bytes(),
        )
    }

    #[must_use]
    pub fn matches_profile_and_relation(
        &self,
        profile: &Symbt3AuthorityProfile,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> bool {
        let scheme = relation.shape.accumulator_shape.digest_scheme;
        let statement = self.to_public_statement();
        let expected_source_assignment_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-assignment-roots",
            &self.source_assignment_roots,
        );
        let expected_source_ajtai_opening_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-source-ajtai-opening-roots",
            &self.source_ajtai_opening_roots,
        );
        let expected_message_oracle_roots_digest = symbt3_digest_digest_vec(
            scheme,
            b"symbt3-k4-6-message-oracle-roots",
            &self.message_oracle_roots,
        );
        let expected_batch_items_digest = symbt3_batch_items_digest(
            scheme,
            &self.input_public_values,
            &self.input_commitment_values,
            &self.input_evaluation_values,
            &self.input_accumulator_values,
            &self.source_assignment_roots,
            &self.message_oracle_roots,
        );
        let expected_public_source_boundary_digest = symbt3_public_source_boundary_digest(
            scheme,
            &expected_source_assignment_roots_digest,
            &self.source_assignment_boundary_digest,
            &expected_source_ajtai_opening_roots_digest,
            &self.source_ajtai_commitment_boundary_digest,
        );
        self.profile_digest == profile.digest(scheme)
            && self.shape_id == relation.shape.shape_id
            && self.batch_capacity == relation.shape.batch_capacity
            && self.active_count == relation.shape.active_count
            && self.batch_items_digest == expected_batch_items_digest
            && self.public_source_boundary_digest == expected_public_source_boundary_digest
            && self.source_assignment_roots_digest == expected_source_assignment_roots_digest
            && self.source_ajtai_opening_roots_digest == expected_source_ajtai_opening_roots_digest
            && self.message_oracle_roots_digest == expected_message_oracle_roots_digest
            && statement.matches_relation(relation)
            && statement.canonical_bytes().len() == relation.public_statement_bytes()
    }
}

#[must_use]
pub fn derive_symbt3_batch_challenge_digest(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.folding_protocol_id());
    body.extend_from_slice(&statement.input_public_boundary_digest);
    body.extend_from_slice(&statement.batch_manifest_root);
    body.extend_from_slice(&statement.batch_manifest_layout_digest);
    body.extend_from_slice(&statement.source_column_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.source_assignment_boundary_digest);
    body.extend_from_slice(&statement.source_ajtai_commitment_boundary_digest);
    body.extend_from_slice(&statement.ring_module_layout_digest);
    body.extend_from_slice(&statement.ajtai_commit_layout_digest);
    body.extend_from_slice(&statement.r1cs_evaluator_layout_digest);
    body.extend_from_slice(&statement.gr1cs_residual_layout_digest);
    body.extend_from_slice(&statement.algebra_law_digest);
    body.extend_from_slice(&statement.ajtai_linear_algebra_layout_digest);
    body.extend_from_slice(&statement.ajtai_norm_range_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    push_usize(&mut body, statement.message_oracle_roots.len());
    for root in &statement.message_oracle_roots {
        body.extend_from_slice(root);
    }
    body.extend_from_slice(&statement.whir_parameter_digest);
    push_usize(&mut body, statement.batch_capacity);
    push_usize(&mut body, statement.active_count);
    digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"SYMBT3-A-BETA",
        &body,
    )
}

#[must_use]
pub fn derive_symbt3_public_statement_digest(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&derive_symbt3_batch_challenge_digest(relation, statement));
    body.extend_from_slice(&statement.old_accumulator_digest);
    body.extend_from_slice(&statement.new_accumulator_digest);
    push_i64_vec(&mut body, &statement.old_accumulator_coordinates);
    push_i64_vec(&mut body, &statement.new_accumulator_coordinates);
    body.extend_from_slice(&statement.batch_manifest_root);
    body.extend_from_slice(&statement.manifest_oracle_root);
    body.extend_from_slice(&statement.manifest_eval_claim.to_le_bytes());
    body.extend_from_slice(&statement.batch_manifest_layout_digest);
    body.extend_from_slice(&statement.source_column_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.production_norm_range_layout_digest);
    body.extend_from_slice(&statement.structured_projection_layout_digest);
    body.extend_from_slice(&statement.monomial_embedding_layout_digest);
    body.extend_from_slice(&statement.representative_layout_digest);
    body.extend_from_slice(&statement.norm_range_public_digest);
    push_i64_vec(&mut body, &statement.folded_public_input);
    push_i64_vec(&mut body, &statement.folded_commitment);
    push_i64_vec(&mut body, &statement.folded_evaluation);
    push_i64_vec(&mut body, &statement.folded_accumulator_coordinates);
    body.extend_from_slice(&statement.folded_ajtai_opening_root);
    push_i64_vec(&mut body, &statement.folded_ajtai_commitment);
    body.extend_from_slice(&statement.folded_gr1cs_boundary_digest);
    body.extend_from_slice(&statement.algebra_law_digest);
    body.extend_from_slice(&statement.ajtai_linear_algebra_layout_digest);
    body.extend_from_slice(&statement.ajtai_norm_range_layout_digest);
    body.extend_from_slice(&statement.projection_layout_digest);
    body.extend_from_slice(&statement.range_layout_digest);
    body.extend_from_slice(&statement.production_norm_range_layout_digest);
    body.extend_from_slice(&statement.structured_projection_layout_digest);
    body.extend_from_slice(&statement.monomial_embedding_layout_digest);
    body.extend_from_slice(&statement.representative_layout_digest);
    body.extend_from_slice(&statement.norm_range_public_digest);
    body.extend_from_slice(&statement.folded_gr1cs_product_residual_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.folded_output_accumulator_root);
    digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"batched-cp-symbt3-proof-public-statement",
        &body,
    )
}

#[must_use]
pub fn derive_symbt3_projection_seed_digest(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    oracle_root: Digest32,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&derive_symbt3_public_statement_digest(relation, statement));
    body.extend_from_slice(&statement.folded_ajtai_opening_root);
    body.extend_from_slice(&oracle_root);
    body.extend_from_slice(&statement.whir_parameter_digest);
    body.extend_from_slice(&statement.ajtai_norm_range_layout_digest);
    body.extend_from_slice(&statement.structured_projection_layout_digest);
    body.extend_from_slice(&statement.monomial_embedding_layout_digest);
    body.extend_from_slice(&statement.representative_layout_digest);
    body.extend_from_slice(&statement.range_layout_digest);
    digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"SYMBT3-J-PROJECTION",
        &body,
    )
}

#[must_use]
pub fn derive_symbt3_beta_coefficients(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Vec<i64> {
    let seed = derive_symbt3_batch_challenge_digest(relation, statement);
    let mut coeffs = Vec::with_capacity(seed.len() * 2);
    for byte in seed {
        let d0 = (byte % 5) as i64;
        let d1 = ((byte / 5) % 5) as i64;
        coeffs.push(d0 - 2);
        coeffs.push(d1 - 2);
    }
    (0..statement.batch_capacity)
        .map(|idx| coeffs[idx % coeffs.len()])
        .collect()
}

#[must_use]
pub fn derive_symbt3_beta_ring_elements(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Vec<RingElement> {
    let seed = derive_symbt3_batch_challenge_digest(relation, statement);
    let mut coeffs = Vec::with_capacity(seed.len() * 2);
    for byte in seed {
        let d0 = (byte % 5) as i64;
        let d1 = ((byte / 5) % 5) as i64;
        coeffs.push(d0 - 2);
        coeffs.push(d1 - 2);
    }
    (0..statement.batch_capacity)
        .map(|idx| {
            let mut ring_coeffs = [0i64; D];
            for (coeff_idx, coeff) in ring_coeffs.iter_mut().enumerate() {
                *coeff = coeffs[(idx * D + coeff_idx) % coeffs.len()];
            }
            RingElement {
                coeffs: ring_coeffs,
            }
        })
        .collect()
}

#[must_use]
pub fn derive_symbt3_round_challenges(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Vec<Digest32> {
    let mut prefix_seed_body = Vec::new();
    prefix_seed_body.extend_from_slice(&relation.folding_protocol_id());
    prefix_seed_body.extend_from_slice(&statement.input_public_boundary_digest);
    prefix_seed_body.extend_from_slice(&statement.batch_manifest_root);
    prefix_seed_body.extend_from_slice(&statement.source_assignment_boundary_digest);
    prefix_seed_body.extend_from_slice(&statement.source_ajtai_commitment_boundary_digest);
    push_usize(&mut prefix_seed_body, statement.batch_capacity);
    push_usize(&mut prefix_seed_body, statement.active_count);
    let mut prior = digest_domain_with_scheme(
        relation.shape.accumulator_shape.digest_scheme,
        b"batched-cp-symbt3-round-challenge-prefix-seed",
        &prefix_seed_body,
    );
    (0..relation.shape.accumulator_shape.num_rounds)
        .map(|round| {
            let mut body = Vec::new();
            body.extend_from_slice(&relation.folding_protocol_id());
            body.extend_from_slice(&statement.input_public_boundary_digest);
            body.extend_from_slice(&statement.batch_manifest_root);
            for root in statement.message_oracle_roots.iter().take(round + 1) {
                body.extend_from_slice(root);
            }
            body.extend_from_slice(&prior);
            push_usize(&mut body, round);
            let challenge = digest_domain_with_scheme(
                relation.shape.accumulator_shape.digest_scheme,
                b"batched-cp-symbt3-round-challenge",
                &body,
            );
            prior = challenge;
            challenge
        })
        .collect()
}

#[must_use]
pub fn symbt3_message_oracle_root(
    scheme: PublicDigestScheme,
    shape: &BatchedCpStatementShape,
    round: usize,
    rows: &[Vec<u8>],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&shape.shape_id);
    push_usize(&mut body, round);
    push_usize(&mut body, rows.len());
    for row in rows {
        push_bytes(&mut body, row);
    }
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-message-oracle-root", &body)
}

#[must_use]
pub fn symbt3_norm_range_public_digest(
    scheme: PublicDigestScheme,
    folded_opening_digest: &Digest32,
    norm_range_layout_digest: &Digest32,
    projection_layout_digest: &Digest32,
    monomial_embedding_layout_digest: &Digest32,
    representative_layout_digest: &Digest32,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(folded_opening_digest);
    body.extend_from_slice(norm_range_layout_digest);
    body.extend_from_slice(projection_layout_digest);
    body.extend_from_slice(monomial_embedding_layout_digest);
    body.extend_from_slice(representative_layout_digest);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-j-norm-range-public", &body)
}

#[must_use]
pub fn symbt3_message_semantic_rows_from_oracles(
    relation: &BatchedCpSymbt3RelationDescription,
    message_oracles: &[Vec<Vec<u8>>],
) -> Option<Vec<Vec<i64>>> {
    if message_oracles.len() != relation.message_semantic_layout.round_layouts.len() {
        return None;
    }
    let mut rows = Vec::with_capacity(relation.message_semantic_layout.round_layouts.len());
    for (round_layout, round_rows) in relation
        .message_semantic_layout
        .round_layouts
        .iter()
        .zip(message_oracles.iter())
    {
        if round_rows.len() != round_layout.row_count {
            return None;
        }
        let mut row_values =
            Vec::with_capacity(round_layout.row_count * round_layout.packed_field_len);
        for item in 0..relation.shape.active_count {
            let message = round_rows.get(item)?;
            if message.len() != round_layout.message_len {
                return None;
            }
            row_values.extend(symbt3_pack_message_bytes(
                message,
                round_layout.packed_field_len,
            ));
        }
        rows.push(row_values);
    }
    Some(rows)
}

#[must_use]
pub fn symbt3_message_semantic_flat_values(
    relation: &BatchedCpSymbt3RelationDescription,
    message_oracles: &[Vec<Vec<u8>>],
) -> Option<Vec<i64>> {
    Some(
        symbt3_message_semantic_rows_from_oracles(relation, message_oracles)?
            .into_iter()
            .flat_map(|row| row.into_iter())
            .collect(),
    )
}

#[must_use]
pub fn symbt3_message_view_flat_values(
    relation: &BatchedCpSymbt3RelationDescription,
    message_oracles: &[Vec<Vec<u8>>],
) -> Option<Vec<i64>> {
    if message_oracles.len() != relation.message_semantic_layout.round_layouts.len() {
        return None;
    }
    let mut values = Vec::with_capacity(
        relation
            .message_semantic_layout
            .view_coordinate_count(relation.shape.active_count),
    );
    for (round_layout, round_rows) in relation
        .message_semantic_layout
        .round_layouts
        .iter()
        .zip(message_oracles.iter())
    {
        if round_rows.len() != round_layout.row_count {
            return None;
        }
        for item in 0..relation.shape.active_count {
            let message = round_rows.get(item)?;
            if message.len() != round_layout.message_len {
                return None;
            }
            let packed = symbt3_pack_message_bytes(message, round_layout.packed_field_len);
            for view in &round_layout.message_views {
                let start = view.message_coordinate_map.message_coordinate_offset;
                let end = start.checked_add(view.message_coordinate_map.coordinate_len)?;
                values.extend(packed.get(start..end)?.iter().copied());
            }
        }
    }
    Some(values)
}

fn symbt3_pack_message_bytes(message: &[u8], packed_field_len: usize) -> Vec<i64> {
    let mut out = message
        .chunks(4)
        .take(packed_field_len)
        .map(|chunk| {
            let mut value = 0u32;
            for (idx, &byte) in chunk.iter().enumerate() {
                value |= (byte as u32) << (8 * idx);
            }
            (value as i128 % BABYBEAR_MODULUS_U64 as i128) as i64
        })
        .collect::<Vec<_>>();
    out.resize(packed_field_len, 0);
    out
}

pub fn bucket_by_exact_shape(
    items: Vec<BatchedCpItem>,
    whir_parameter_digest: Digest32,
) -> Result<Vec<BatchedCpBucket>, BatchedCpError> {
    let mut buckets = BTreeMap::<Digest32, Vec<BatchedCpItem>>::new();
    for item in items {
        let shape =
            CpAccumulatorShape::from_item(&item.public, &item.witness, whir_parameter_digest)?;
        buckets.entry(shape.shape_id()).or_default().push(item);
    }
    buckets
        .into_values()
        .map(|items| BatchedCpBucket::new(items, whir_parameter_digest))
        .collect()
}

#[must_use]
pub fn derive_batch_challenge_digest(
    shape: &BatchedCpStatementShape,
    manifest_digest: Digest32,
    round_commitments: &BatchRoundMessageCommitments,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_batch_challenge_body(
        shape,
        manifest_digest,
        round_commitments,
    ));
    digest_domain_with_scheme(
        shape.accumulator_shape.digest_scheme,
        b"batched-cp-challenge-digest",
        &body,
    )
}

fn estimate_witness_row_len(shape: &CpAccumulatorShape) -> usize {
    32 + shape.public_statement_len
        + shape.folded_output_contribution_len
        + shape.num_rounds * D * 8
        + shape
            .fs_message_lens
            .iter()
            .map(|len| 8 + len)
            .sum::<usize>()
        + (8 + shape.fs_commitment_len) * shape.num_rounds
        + (8 + shape.fs_opening_len) * shape.num_rounds
        + (0..shape.num_rounds)
            .map(|round| {
                8 + shape.fold_input_commitment_lens[round]
                    + 8
                    + shape.fold_input_public_input_lens[round] * 8
                    + 8
                    + shape.fold_input_eval_message_lens[round]
            })
            .sum::<usize>()
        + shape
            .original_witness_lens
            .iter()
            .map(|len| 8 + len * D * 8)
            .sum::<usize>()
}

fn estimate_public_statement_bytes(shape: &BatchedCpStatementShape) -> usize {
    // Shape + five fixed digests plus the round commitment count and one digest
    // per CP round. This mirrors `BatchedCpPublicStatement::canonical_bytes`.
    let mut out = Vec::new();
    push_bytes(&mut out, b"symphony-batched-cp-public-statement-v1");
    encode_statement_shape(&mut out, shape);
    out.extend_from_slice(&[0u8; 32]);
    push_usize(&mut out, shape.accumulator_shape.num_rounds);
    for _ in 0..shape.accumulator_shape.num_rounds {
        out.extend_from_slice(&[0u8; 32]);
    }
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.len()
}

fn estimate_symbt3_public_statement_bytes(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    push_bytes(
        &mut out,
        b"symphony-batched-cp-symbt3-compressed-research-public-v1",
    );
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, shape.batch_capacity);
    push_usize(&mut out, shape.active_count);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    push_usize(&mut out, shape.accumulator_shape.num_rounds);
    for _ in 0..shape.accumulator_shape.num_rounds {
        out.extend_from_slice(&[0u8; 32]);
    }
    let coord_len =
        shape.accumulator_shape.local_public_input_count * shape.accumulator_shape.r1cs_num_public;
    let commitment_len =
        shape.accumulator_shape.commitment_kappa * shape.accumulator_shape.commitment_d;
    let evaluation_len = shape.accumulator_shape.folded_evaluation_count * T * D;
    let accumulator_len = coord_len + commitment_len + evaluation_len;
    push_i64_vec(&mut out, &vec![0; accumulator_len]);
    push_i64_vec(&mut out, &vec![0; accumulator_len]);
    push_i64_vec(&mut out, &vec![0; coord_len]);
    push_i64_vec(&mut out, &vec![0; commitment_len]);
    push_i64_vec(&mut out, &vec![0; evaluation_len]);
    push_i64_vec(&mut out, &vec![0; accumulator_len]);
    out.extend_from_slice(&[0u8; 32]);
    push_i64_vec(&mut out, &vec![0; commitment_len]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0u8; 32]);
    out.len()
}

fn flatten_symbt3_public_inputs(public_inputs: &[Vec<i64>]) -> Vec<i64> {
    public_inputs
        .iter()
        .flat_map(|row| row.iter().copied())
        .collect()
}

fn flatten_symbt3_commitment(commitment: &crate::commitment::Commitment) -> Vec<i64> {
    commitment
        .value
        .elements
        .iter()
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn flatten_symbt3_evaluations(values: &[crate::ring::tensor::TensorElement]) -> Vec<i64> {
    values
        .iter()
        .flat_map(|tensor| tensor.data.iter().flat_map(|row| row.iter().copied()))
        .collect()
}

fn flatten_symbt3_ring_vector(value: &RingVector) -> Vec<i64> {
    value
        .elements
        .iter()
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn flatten_symbt3_full_ajtai_opening(item: &BatchedCpItem) -> Vec<i64> {
    item.public
        .instance
        .x_folded
        .public_input
        .iter()
        .chain(item.witness.folded_witness.witness.elements.iter())
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn flatten_symbt3_source_r1cs_assignment(
    item: &BatchedCpItem,
    original_index: usize,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Vec<i64> {
    let mut out = Vec::with_capacity(relation.r1cs_evaluator_layout.num_variables * D);
    if let Some(public_inputs) = item.public.public_inputs.get(original_index) {
        for public_idx in 0..relation.r1cs_evaluator_layout.num_public {
            let scalar = public_inputs.get(public_idx).copied().unwrap_or_default();
            out.extend_from_slice(&RingElement::from_constant(scalar).coeffs);
        }
    }
    if let Some(witness) = item.witness.original_witnesses.get(original_index) {
        for elem in &witness.elements {
            out.extend_from_slice(&elem.coeffs);
        }
    }
    out.resize(relation.r1cs_evaluator_layout.num_variables * D, 0);
    out
}

fn symbt3_input_public_boundary_digest(
    scheme: PublicDigestScheme,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    push_i64_matrix(&mut body, input_public_values);
    push_i64_matrix(&mut body, input_commitment_values);
    push_i64_matrix(&mut body, input_evaluation_values);
    push_i64_matrix(&mut body, input_accumulator_values);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-input-public-boundary", &body)
}

fn symbt3_manifest_rows_from_statement_parts(
    relation: &BatchedCpSymbt3RelationDescription,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
    source_assignment_roots: &[Digest32],
    message_oracle_roots: &[Digest32],
) -> Vec<Vec<i64>> {
    (0..relation.shape.active_count)
        .map(|item| {
            let mut row = Vec::with_capacity(
                relation
                    .batch_manifest_layout
                    .source_column_layout
                    .coordinate_count,
            );
            row.extend_from_slice(
                input_public_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_commitment_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_evaluation_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_accumulator_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            row.extend_from_slice(
                input_commitment_values
                    .get(item)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            );
            let assignment_start = item * relation.shape.accumulator_shape.local_public_input_count;
            let assignment_end =
                assignment_start + relation.shape.accumulator_shape.local_public_input_count;
            for root in source_assignment_roots
                .get(assignment_start..assignment_end)
                .unwrap_or(&[])
            {
                row.extend(root.iter().map(|&byte| byte as i64));
            }
            for root in message_oracle_roots {
                row.extend(root.iter().map(|&byte| byte as i64));
            }
            row.resize(
                relation
                    .batch_manifest_layout
                    .source_column_layout
                    .coordinate_count,
                0,
            );
            row
        })
        .collect()
}

fn symbt3_manifest_source_values_from_statement_parts(
    relation: &BatchedCpSymbt3RelationDescription,
    input_public_values: &[Vec<i64>],
    input_commitment_values: &[Vec<i64>],
    input_evaluation_values: &[Vec<i64>],
    input_accumulator_values: &[Vec<i64>],
    source_assignment_roots: &[Digest32],
    message_oracle_roots: &[Digest32],
) -> Vec<i64> {
    let row_width = relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count;
    let mut out = Vec::with_capacity(relation.shape.active_count * row_width);
    for item in 0..relation.shape.active_count {
        let row_start = out.len();
        out.extend_from_slice(
            input_public_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_commitment_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_evaluation_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_accumulator_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(
            input_commitment_values
                .get(item)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        let assignment_start = item * relation.shape.accumulator_shape.local_public_input_count;
        let assignment_end =
            assignment_start + relation.shape.accumulator_shape.local_public_input_count;
        for root in source_assignment_roots
            .get(assignment_start..assignment_end)
            .unwrap_or(&[])
        {
            out.extend(root.iter().map(|&byte| byte as i64));
        }
        for root in message_oracle_roots {
            out.extend(root.iter().map(|&byte| byte as i64));
        }
        out.resize(row_start + row_width, 0);
    }
    out
}

#[must_use]
pub fn symbt3_manifest_rows_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<Vec<i64>>> {
    if statement.input_public_values.len() != relation.shape.active_count
        || statement.input_commitment_values.len() != relation.shape.active_count
        || statement.input_evaluation_values.len() != relation.shape.active_count
        || statement.input_accumulator_values.len() != relation.shape.active_count
        || statement.source_assignment_roots.len()
            != relation.shape.active_count
                * relation.shape.accumulator_shape.local_public_input_count
        || statement.message_oracle_roots.len() != relation.shape.accumulator_shape.num_rounds
    {
        return None;
    }
    let rows = symbt3_manifest_rows_from_statement_parts(
        relation,
        &statement.input_public_values,
        &statement.input_commitment_values,
        &statement.input_evaluation_values,
        &statement.input_accumulator_values,
        &statement.source_assignment_roots,
        &statement.message_oracle_roots,
    );
    rows.iter()
        .all(|row| {
            row.len()
                == relation
                    .batch_manifest_layout
                    .source_column_layout
                    .coordinate_count
        })
        .then_some(rows)
}

#[must_use]
pub fn symbt3_manifest_source_values_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<i64>> {
    if statement.input_public_values.len() != relation.shape.active_count
        || statement.input_commitment_values.len() != relation.shape.active_count
        || statement.input_evaluation_values.len() != relation.shape.active_count
        || statement.input_accumulator_values.len() != relation.shape.active_count
        || statement.source_assignment_roots.len()
            != relation.shape.active_count
                * relation.shape.accumulator_shape.local_public_input_count
        || statement.message_oracle_roots.len() != relation.shape.accumulator_shape.num_rounds
    {
        return None;
    }
    let values = symbt3_manifest_source_values_from_statement_parts(
        relation,
        &statement.input_public_values,
        &statement.input_commitment_values,
        &statement.input_evaluation_values,
        &statement.input_accumulator_values,
        &statement.source_assignment_roots,
        &statement.message_oracle_roots,
    );
    (values.len()
        == relation.shape.active_count
            * relation
                .batch_manifest_layout
                .source_column_layout
                .coordinate_count)
        .then_some(values)
}

// K1e.2 public-canonical manifest helpers. The verifier path uses statement
// fields and roots directly; row materialization helpers below are diagnostics.

#[must_use]
pub fn symbt3_manifest_commitment_policy_digest(
    scheme: PublicDigestScheme,
    policy: ManifestCommitmentPolicy,
) -> Digest32 {
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-manifest-commitment-policy",
        &[manifest_commitment_policy_code(policy)],
    )
}

#[must_use]
pub fn symbt3_challenge_schedule_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    field_policy: Symbt3FieldExtensionPolicy,
    sumcheck_policy: Symbt3SumcheckChallengePolicy,
    repetition_count: usize,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&SYMBT3_CHALLENGE_SCHEDULE_VERSION.to_le_bytes());
    body.push(symbt3_field_extension_policy_code(field_policy));
    body.push(symbt3_sumcheck_challenge_policy_code(sumcheck_policy));
    push_usize(&mut body, repetition_count);
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&relation.folding_protocol_id());
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-challenge-schedule-policy",
        &body,
    )
}

#[must_use]
pub fn symbt3_fiat_shamir_domain_digest(
    scheme: PublicDigestScheme,
    domain_separators: &[&'static str],
    proof_public_statement_schedule: &'static str,
) -> Digest32 {
    let mut body = Vec::new();
    push_bytes(&mut body, proof_public_statement_schedule.as_bytes());
    push_usize(&mut body, domain_separators.len());
    for separator in domain_separators {
        push_bytes(&mut body, separator.as_bytes());
    }
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-fs-domain-policy", &body)
}

#[must_use]
pub fn symbt3_ring_module_law_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.ring_module_layout.digest(scheme));
    body.extend_from_slice(&relation.algebra_law.digest(scheme));
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ring-module-law-policy", &body)
}

#[must_use]
pub fn symbt3_ajtai_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.ajtai_commit_layout.digest(scheme));
    body.extend_from_slice(&relation.ajtai_linear_algebra_layout.digest(scheme));
    body.extend_from_slice(&relation.ajtai_norm_range_layout.digest(scheme));
    body.extend_from_slice(&relation.ajtai_params_digest);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ajtai-policy", &body)
}

#[must_use]
pub fn symbt3_norm_range_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(
        &relation
            .ajtai_norm_range_layout
            .projection_layout
            .digest(scheme),
    );
    body.extend_from_slice(&relation.ajtai_norm_range_layout.range_layout.digest(scheme));
    body.extend_from_slice(
        &relation
            .ajtai_norm_range_layout
            .monomial_embedding_layout
            .digest(scheme),
    );
    body.extend_from_slice(
        &relation
            .ajtai_norm_range_layout
            .representative_layout
            .digest(scheme),
    );
    body.push(symbt3_projection_mode_code(
        relation
            .ajtai_norm_range_layout
            .projection_layout
            .projection_mode,
    ));
    body.push(symbt3_range_mode_code(
        relation.ajtai_norm_range_layout.range_mode,
    ));
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-norm-range-policy", &body)
}

#[must_use]
pub fn symbt3_message_oracle_policy_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.message_semantic_layout.digest(scheme));
    push_usize(
        &mut body,
        relation
            .message_semantic_layout
            .message_to_trace_binding_count(),
    );
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-message-oracle-policy", &body)
}

#[must_use]
pub fn symbt3_batch_manifest_root_from_oracle_root(
    scheme: PublicDigestScheme,
    policy: ManifestCommitmentPolicy,
    manifest_layout_digest: &Digest32,
    manifest_oracle_root: &Digest32,
) -> Digest32 {
    match policy {
        ManifestCommitmentPolicy::DigestOfLayoutAndOracleRootV1
        | ManifestCommitmentPolicy::PublicCanonicalManifestViewV1 => {
            let mut body = Vec::new();
            body.extend_from_slice(manifest_layout_digest);
            body.extend_from_slice(manifest_oracle_root);
            digest_domain_with_scheme(scheme, b"SYMBT3_MANIFEST", &body)
        }
    }
}

#[must_use]
pub fn symbt3_manifest_root_link_is_valid(
    scheme: PublicDigestScheme,
    statement: &BatchedCpSymbt3PublicStatement,
) -> bool {
    statement.manifest_oracle_root != [0u8; 32]
        && statement.batch_manifest_root
            == symbt3_batch_manifest_root_from_oracle_root(
                scheme,
                ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
                &statement.batch_manifest_layout_digest,
                &statement.manifest_oracle_root,
            )
}

#[must_use]
pub fn symbt3_manifest_oracle_root_from_rows(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    rows: &[Vec<i64>],
) -> Digest32 {
    // DiagnosticOnly: retained for tests/reporting that compare the virtual
    // public-canonical view with an explicitly materialized manifest.
    let mut body = Vec::new();
    body.extend_from_slice(&relation.batch_manifest_layout.digest(scheme));
    body.extend_from_slice(
        &relation
            .batch_manifest_layout
            .source_column_layout
            .digest(scheme),
    );
    push_i64_matrix(&mut body, rows);
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-typed-batch-manifest-root",
        &body,
    )
}

#[must_use]
pub fn symbt3_manifest_oracle_root_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Digest32> {
    let values = symbt3_manifest_source_values_for_statement(relation, statement)?;
    let row_width = relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count;
    if row_width == 0
        || values.len() != statement.active_count.checked_mul(row_width)?
        || statement.active_count != relation.shape.active_count
    {
        return None;
    }

    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let mut body = Vec::new();
    body.extend_from_slice(&relation.batch_manifest_layout.digest(scheme));
    body.extend_from_slice(
        &relation
            .batch_manifest_layout
            .source_column_layout
            .digest(scheme),
    );
    push_usize(&mut body, statement.active_count);
    for row in values.chunks_exact(row_width) {
        push_i64_vec(&mut body, row);
    }
    Some(digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-typed-batch-manifest-root",
        &body,
    ))
}

#[must_use]
pub fn symbt3_canonical_manifest_root_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Digest32> {
    symbt3_manifest_oracle_root_for_statement(relation, statement)
}

#[must_use]
pub fn symbt3_batch_manifest_root_from_rows(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    rows: &[Vec<i64>],
) -> Digest32 {
    // DiagnosticOnly: production public verification links the canonical
    // manifest root from public statement data, not dense manifest rows.
    let manifest_layout_digest = relation.batch_manifest_layout.digest(scheme);
    let manifest_oracle_root = symbt3_manifest_oracle_root_from_rows(scheme, relation, rows);
    symbt3_batch_manifest_root_from_oracle_root(
        scheme,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
        &manifest_layout_digest,
        &manifest_oracle_root,
    )
}

#[must_use]
pub fn derive_symbt3_manifest_membership_challenge(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Digest32 {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let mut body = Vec::new();
    body.extend_from_slice(&relation.relation_id());
    body.extend_from_slice(&relation.folding_protocol_id());
    body.extend_from_slice(&statement.batch_manifest_root);
    body.extend_from_slice(&statement.manifest_oracle_root);
    body.extend_from_slice(proof_oracle_root);
    body.extend_from_slice(&statement.batch_manifest_layout_digest);
    body.extend_from_slice(&statement.source_column_layout_digest);
    body.extend_from_slice(&statement.message_semantic_layout_digest);
    body.extend_from_slice(&statement.whir_parameter_digest);
    body.extend_from_slice(&symbt3_manifest_commitment_policy_digest(
        scheme,
        ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
    ));
    push_usize(&mut body, statement.batch_capacity);
    push_usize(&mut body, statement.active_count);
    digest_domain_with_scheme(scheme, b"SYMBT3-MANIFEST-MEMBERSHIP", &body)
}

#[must_use]
pub fn symbt3_manifest_source_mle_values(rows: &[Vec<i64>]) -> Vec<u32> {
    rows.iter()
        .flat_map(|row| row.iter().map(|&value| bb_from_i64(value)))
        .collect()
}

#[must_use]
pub fn symbt3_manifest_source_mle_values_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<Vec<u32>> {
    Some(
        symbt3_manifest_source_values_for_statement(relation, statement)?
            .iter()
            .map(|&value| bb_from_i64(value))
            .collect(),
    )
}

#[must_use]
pub fn symbt3_manifest_oracle_mle_values(rows: &[Vec<i64>]) -> Vec<u32> {
    symbt3_manifest_source_mle_values(rows)
}

#[must_use]
pub fn symbt3_manifest_eval_claim_from_rows(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    rows: &[Vec<i64>],
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    // DiagnosticOnly: retained for row-materialized consistency checks. The
    // K1e.2 verifier-side path evaluates the public-canonical view directly.
    let values = symbt3_manifest_oracle_mle_values(rows);
    if values.is_empty() {
        return None;
    }
    let row_count = symbt3_manifest_eval_row_count(relation, statement)?;
    let point = symbt3_manifest_membership_point(
        relation,
        statement,
        proof_oracle_root,
        row_count.trailing_zeros() as usize,
    );
    Some(bb_mle_eval_u32(&values, &point))
}

#[must_use]
pub fn symbt3_manifest_source_eval_claim_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    symbt3_virtual_source_view_eval_for_statement(relation, statement, proof_oracle_root)
}

#[must_use]
pub fn symbt3_canonical_manifest_view_eval_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    symbt3_virtual_source_view_eval_for_statement(relation, statement, proof_oracle_root)
}

#[must_use]
pub fn symbt3_virtual_source_view_eval_for_statement(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
) -> Option<u32> {
    // K1e.2: this is a virtual public-boundary evaluator, not a committed
    // dense source-view column in the SYMBT3 backend table.
    if statement.input_public_values.len() != relation.shape.active_count
        || statement.input_commitment_values.len() != relation.shape.active_count
        || statement.input_evaluation_values.len() != relation.shape.active_count
        || statement.input_accumulator_values.len() != relation.shape.active_count
        || statement.source_assignment_roots.len()
            != relation.shape.active_count
                * relation.shape.accumulator_shape.local_public_input_count
        || statement.message_oracle_roots.len() != relation.shape.accumulator_shape.num_rounds
    {
        return None;
    }
    let row_width = relation
        .batch_manifest_layout
        .source_column_layout
        .coordinate_count;
    let source_len = relation.shape.active_count.checked_mul(row_width)?;
    if row_width == 0 || source_len == 0 {
        return None;
    }
    let row_count = source_len.next_power_of_two().max(1);
    let point = symbt3_manifest_membership_point(
        relation,
        statement,
        proof_oracle_root,
        row_count.trailing_zeros() as usize,
    );
    let mut acc = 0u32;
    let mut index = 0usize;
    for item in 0..relation.shape.active_count {
        let row_end = (item + 1) * row_width;
        for &value in statement.input_public_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_commitment_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_evaluation_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_accumulator_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        for &value in statement.input_commitment_values[item].iter() {
            symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, value);
        }
        let assignment_start = item * relation.shape.accumulator_shape.local_public_input_count;
        let assignment_end =
            assignment_start + relation.shape.accumulator_shape.local_public_input_count;
        for root in &statement.source_assignment_roots[assignment_start..assignment_end] {
            for &byte in root {
                symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, byte as i64);
            }
        }
        for root in &statement.message_oracle_roots {
            for &byte in root {
                symbt3_absorb_virtual_view_value(&mut acc, &mut index, &point, byte as i64);
            }
        }
        if index > row_end {
            return None;
        }
        index = row_end;
    }
    (index == source_len).then_some(acc)
}

#[must_use]
pub fn symbt3_manifest_eval_row_count(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
) -> Option<usize> {
    let commitment_len = relation.symbt3_commitment_coordinate_len();
    let opening_len = relation.ring_module_layout.opening_module_dimension * D;
    let r1cs_residual_len = statement.source_assignment_roots.len()
        * relation.r1cs_evaluator_layout.num_constraints
        * D;
    let gr1cs_residual_len = relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count
        / 3;
    let projection_len = relation
        .ajtai_norm_range_layout
        .projection_layout
        .output_len;
    let manifest_len = statement.active_count.checked_mul(
        relation
            .batch_manifest_layout
            .source_column_layout
            .coordinate_count,
    )?;
    let row_len = commitment_len
        .max(opening_len)
        .max(r1cs_residual_len)
        .max(gr1cs_residual_len)
        .max(projection_len)
        .max(manifest_len);
    Some(row_len.next_power_of_two().max(1))
}

fn symbt3_absorb_virtual_view_value(acc: &mut u32, index: &mut usize, point: &[u32], value: i64) {
    let weight = bb_mle_basis_weight_u32(*index, point);
    *acc = bb_add_u32(*acc, bb_mul_u32(bb_from_i64(value), weight));
    *index += 1;
}

fn bb_mle_basis_weight_u32(index: usize, point: &[u32]) -> u32 {
    point
        .iter()
        .enumerate()
        .fold(1u32, |weight, (bit, &challenge)| {
            if ((index >> bit) & 1) == 0 {
                bb_mul_u32(weight, bb_sub_u32(1, challenge))
            } else {
                bb_mul_u32(weight, challenge)
            }
        })
}

#[must_use]
pub fn symbt3_manifest_membership_point(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    proof_oracle_root: &Digest32,
    num_vars: usize,
) -> Vec<u32> {
    let seed = derive_symbt3_manifest_membership_challenge(relation, statement, proof_oracle_root);
    (0..num_vars)
        .map(|idx| {
            let mut body = Vec::new();
            body.extend_from_slice(&seed);
            push_usize(&mut body, idx);
            let digest = digest_domain_with_scheme(
                relation.shape.accumulator_shape.digest_scheme,
                b"SYMBT3-MANIFEST-MEMBERSHIP-POINT",
                &body,
            );
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[..8]);
            (u64::from_le_bytes(bytes) % BABYBEAR_MODULUS_U64) as u32
        })
        .collect()
}

fn bb_mle_eval_u32(values: &[u32], point: &[u32]) -> u32 {
    let padded_len = 1usize << point.len();
    if padded_len == 0 {
        return 0;
    }
    let mut layer = vec![0u32; padded_len];
    for (dst, &src) in layer.iter_mut().zip(values.iter()) {
        *dst = src;
    }
    for &r in point {
        let half = layer.len() / 2;
        for idx in 0..half {
            let lo = layer[2 * idx];
            let hi = layer[2 * idx + 1];
            layer[idx] = bb_add_u32(lo, bb_mul_u32(r, bb_sub_u32(hi, lo)));
        }
        layer.truncate(half);
    }
    layer.first().copied().unwrap_or_default()
}

fn symbt3_source_assignment_root(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    values: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.r1cs_evaluator_layout.digest(scheme));
    push_i64_vec(&mut body, values);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-source-assignment-root", &body)
}

fn symbt3_source_assignment_boundary_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    roots: &[Digest32],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.r1cs_evaluator_layout.digest(scheme));
    push_usize(&mut body, roots.len());
    for root in roots {
        body.extend_from_slice(root);
    }
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-source-assignment-boundary",
        &body,
    )
}

fn symbt3_folded_gr1cs_boundary_digest(
    scheme: PublicDigestScheme,
    relation: &BatchedCpSymbt3RelationDescription,
    source_evaluations: &[Vec<i64>],
    folded_evaluation: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&relation.gr1cs_residual_layout.digest(scheme));
    push_i64_matrix(&mut body, source_evaluations);
    push_i64_vec(&mut body, folded_evaluation);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-folded-gr1cs-boundary", &body)
}

fn symbt3_source_ajtai_commitment_boundary_digest(
    scheme: PublicDigestScheme,
    input_commitment_values: &[Vec<i64>],
) -> Digest32 {
    let mut body = Vec::new();
    push_i64_matrix(&mut body, input_commitment_values);
    digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-source-ajtai-commitment-boundary",
        &body,
    )
}

fn symbt3_ajtai_opening_root(
    scheme: PublicDigestScheme,
    layout: &Symbt3RingModuleLayout,
    values: &[i64],
) -> Digest32 {
    let mut body = Vec::new();
    body.extend_from_slice(&layout.digest(scheme));
    push_i64_vec(&mut body, values);
    digest_domain_with_scheme(scheme, b"batched-cp-symbt3-ajtai-opening-root", &body)
}

fn symbt3_linear_fold_values(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    rows: &[Vec<i64>],
    coord_len: usize,
) -> Vec<i64> {
    let betas = derive_symbt3_beta_coefficients(relation, statement);
    let mut out = vec![0i64; coord_len];
    for (row, beta) in rows.iter().take(statement.active_count).zip(betas.iter()) {
        for (dst, &value) in out.iter_mut().zip(row.iter()) {
            *dst = dst.saturating_add(beta.saturating_mul(value));
        }
    }
    out
}

fn symbt3_ring_fold_values(
    relation: &BatchedCpSymbt3RelationDescription,
    statement: &BatchedCpSymbt3PublicStatement,
    rows: &[Vec<i64>],
    module_dimension: usize,
) -> Vec<i64> {
    let betas = derive_symbt3_beta_ring_elements(relation, statement);
    let mut out = RingVector::zero(module_dimension);
    for (row, beta) in rows.iter().take(statement.active_count).zip(betas.iter()) {
        let value = ring_vector_from_flat(row, module_dimension);
        let contribution = value.ring_scalar_mul(beta, relation.ring_module_layout.modulus);
        for (dst, elem) in out.elements.iter_mut().zip(contribution.elements.iter()) {
            dst.add_assign(elem, relation.ring_module_layout.modulus);
        }
    }
    flatten_symbt3_ring_vector(&out)
}

fn symbt3_negacyclic_mul_i64(left: &[i64], right: &[i64], q: u64) -> [i64; D] {
    let mut raw = [0i128; D];
    for i in 0..D {
        let lhs = left.get(i).copied().unwrap_or_default() as i128;
        for j in 0..D {
            let rhs = right.get(j).copied().unwrap_or_default() as i128;
            let product = lhs * rhs;
            let idx = i + j;
            if idx < D {
                raw[idx] += product;
            } else {
                raw[idx - D] -= product;
            }
        }
    }
    let mut out = [0i64; D];
    for (dst, value) in out.iter_mut().zip(raw) {
        *dst = crate::ring::arith::centered_mod(value, q);
    }
    out
}

fn ring_vector_from_flat(values: &[i64], module_dimension: usize) -> RingVector {
    let mut elements = Vec::with_capacity(module_dimension);
    for idx in 0..module_dimension {
        let mut coeffs = [0i64; D];
        let start = idx * D;
        let end = start + D;
        if let Some(slice) = values.get(start..end) {
            coeffs.copy_from_slice(slice);
        }
        elements.push(RingElement { coeffs });
    }
    RingVector { elements }
}

fn manifest_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_manifest_body_template(&mut out, &mut known, shape);
    out.len()
}

fn fs_commitment_bodies_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_fs_commitment_body_template(&mut out, &mut known, shape);
    out.len()
}

fn poseidon_fs_commitment_traces_body_len(shape: &BatchedCpStatementShape) -> usize {
    if !poseidon_fs_commitment_traces_enabled(shape) {
        return 0;
    }
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_poseidon_fs_commitment_trace_template(&mut out, &mut known, shape);
    out.len()
}

fn batch_challenge_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_batch_challenge_body_template(&mut out, &mut known, shape, None);
    out.len()
}

fn challenge_to_beta_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_challenge_to_beta_body_template(&mut out, &mut known, shape, None);
    out.len()
}

fn fold_input_reconstruction_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_fold_input_reconstruction_body_template(&mut out, &mut known, shape);
    out.len()
}

fn folded_instance_encoding_len(shape: &CpAccumulatorShape) -> usize {
    // encode_commitment: ring-vector len + kappa ring elements.
    8 + shape.commitment_kappa * D * 8
        // public_input len + folded public input ring elements.
        + 8
        + shape.folded_public_input_len * D * 8
        // evaluation_values len + tensor values.
        + 8
        + shape.folded_evaluation_count * T * D * 8
}

#[cfg(feature = "whir")]
fn folded_output_contribution_commitment_coeff_offset(
    contribution: BatchedCpOracleByteRange,
    commitment_idx: usize,
    coeff_idx: usize,
) -> usize {
    contribution.offset + 32 + 8 + commitment_idx * D * 8 + coeff_idx * 8
}

#[cfg(feature = "whir")]
fn folded_output_contribution_public_input_coeff_offset(
    shape: &CpAccumulatorShape,
    contribution: BatchedCpOracleByteRange,
    public_idx: usize,
    coeff_idx: usize,
) -> usize {
    contribution.offset
        + 32
        + 8
        + shape.commitment_kappa * D * 8
        + 8
        + public_idx * D * 8
        + coeff_idx * 8
}

#[cfg(feature = "whir")]
fn folded_output_contribution_evaluation_coeff_offset(
    shape: &CpAccumulatorShape,
    contribution: BatchedCpOracleByteRange,
    eval_idx: usize,
    tensor_row: usize,
    coeff_idx: usize,
) -> usize {
    contribution.offset
        + 32
        + 8
        + shape.commitment_kappa * D * 8
        + 8
        + shape.folded_public_input_len * D * 8
        + 8
        + eval_idx * T * D * 8
        + tensor_row * D * 8
        + coeff_idx * 8
}

fn folded_output_accumulator_body_len(shape: &BatchedCpStatementShape) -> usize {
    let mut out = Vec::new();
    let mut known = Vec::new();
    push_known_folded_output_accumulator_body_template(&mut out, &mut known, shape, None);
    out.len()
}
