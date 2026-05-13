
impl CpAccumulatorShape {
    pub fn from_item(
        public: &CpPublicStatement,
        witness: &CpWitnessBundle,
        whir_parameter_digest: Digest32,
    ) -> Result<Self, BatchedCpError> {
        if witness.fs_messages.is_empty()
            || witness.fs_messages.len() != witness.fs_commitments.len()
            || witness.fs_messages.len() != witness.fs_openings.len()
            || witness.fs_messages.len() != witness.fold_inputs.len()
            || witness.fs_messages.len() != witness.folding_proof.gr1cs_proofs.len()
            || witness.fs_messages.len() != witness.folding_proof.beta.len()
            || public.public_inputs.len() != witness.original_witnesses.len()
        {
            return Err(BatchedCpError::InvalidShape);
        }
        let first_commitment = witness
            .folding_proof
            .commitments
            .first()
            .ok_or(BatchedCpError::InvalidShape)?;
        let commitment_kappa = first_commitment.value.elements.len();
        let commitment_d = first_commitment
            .value
            .elements
            .first()
            .map(|elem| elem.coeffs.len())
            .ok_or(BatchedCpError::InvalidShape)?;
        let folded_evaluation_count = public.instance.x_folded.evaluation_values.len();
        let gr1cs_hadamard_eval_offsets: Vec<Vec<usize>> = witness
            .fold_inputs
            .iter()
            .map(|input| {
                gr1cs_hadamard_evaluation_offsets(&input.eval_values_bytes, folded_evaluation_count)
            })
            .collect::<Option<_>>()
            .ok_or(BatchedCpError::InvalidShape)?;
        let gr1cs_message_sections: Vec<Vec<BatchedCpGr1csMessageSection>> = witness
            .folding_proof
            .gr1cs_proofs
            .iter()
            .zip(witness.fs_messages.iter())
            .map(|(proof, message)| gr1cs_message_sections(proof, message.len()))
            .collect::<Option<_>>()
            .ok_or(BatchedCpError::InvalidShape)?;

        Ok(Self {
            digest_scheme: public.digest_scheme,
            r1cs_num_constraints: public.r1cs_num_constraints,
            r1cs_num_variables: public.r1cs_num_variables,
            r1cs_num_public: public.r1cs_num_public,
            local_public_input_count: public.public_inputs.len(),
            public_statement_len: encode_public_statement(public).len(),
            num_rounds: witness.fs_messages.len(),
            fs_message_lens: witness.fs_messages.iter().map(Vec::len).collect(),
            fs_commitment_len: witness.fs_commitments[0].len(),
            fs_opening_len: witness.fs_openings[0].len(),
            fold_input_commitment_lens: witness
                .fold_inputs
                .iter()
                .map(|input| input.commitment_bytes.len())
                .collect(),
            fold_input_public_input_lens: witness
                .fold_inputs
                .iter()
                .map(|input| input.public_input.len())
                .collect(),
            fold_input_eval_message_lens: witness
                .fold_inputs
                .iter()
                .map(|input| input.eval_values_bytes.len())
                .collect(),
            gr1cs_hadamard_eval_offsets,
            gr1cs_message_sections,
            original_witness_lens: witness
                .original_witnesses
                .iter()
                .map(RingVector::len)
                .collect(),
            commitment_kappa,
            commitment_d,
            folded_public_input_len: public.instance.x_folded.public_input.len(),
            folded_evaluation_count,
            folded_output_contribution_len: encode_folded_output_contribution_parts(public, None)
                .len(),
            whir_parameter_digest,
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"symphony-cp-accumulator-shape-v1");
        push_digest_scheme(&mut out, self.digest_scheme);
        push_usize(&mut out, self.r1cs_num_constraints);
        push_usize(&mut out, self.r1cs_num_variables);
        push_usize(&mut out, self.r1cs_num_public);
        push_usize(&mut out, self.local_public_input_count);
        push_usize(&mut out, self.public_statement_len);
        push_usize(&mut out, self.num_rounds);
        push_usize_vec(&mut out, &self.fs_message_lens);
        push_usize(&mut out, self.fs_commitment_len);
        push_usize(&mut out, self.fs_opening_len);
        push_usize_vec(&mut out, &self.fold_input_commitment_lens);
        push_usize_vec(&mut out, &self.fold_input_public_input_lens);
        push_usize_vec(&mut out, &self.fold_input_eval_message_lens);
        push_nested_usize_vec(&mut out, &self.gr1cs_hadamard_eval_offsets);
        push_gr1cs_message_sections(&mut out, &self.gr1cs_message_sections);
        push_usize_vec(&mut out, &self.original_witness_lens);
        push_usize(&mut out, self.commitment_kappa);
        push_usize(&mut out, self.commitment_d);
        push_usize(&mut out, self.folded_public_input_len);
        push_usize(&mut out, self.folded_evaluation_count);
        push_usize(&mut out, self.folded_output_contribution_len);
        out.extend_from_slice(&self.whir_parameter_digest);
        out
    }

    #[must_use]
    pub fn shape_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.digest_scheme,
            b"batched-cp-shape-id",
            &self.canonical_bytes(),
        )
    }
}

impl BatchedCpStatementShape {
    pub fn new(
        accumulator_shape: CpAccumulatorShape,
        active_count: usize,
    ) -> Result<Self, BatchedCpError> {
        if active_count == 0 {
            return Err(BatchedCpError::EmptyBatch);
        }
        let batch_capacity = active_count.next_power_of_two();
        let batch_log_size = batch_capacity.trailing_zeros() as usize;
        let witness_row_len = estimate_witness_row_len(&accumulator_shape);
        let shape_id = accumulator_shape.shape_id();
        let round_message_lens = accumulator_shape.fs_message_lens.clone();
        Ok(Self {
            accumulator_shape,
            shape_id,
            batch_log_size,
            batch_capacity,
            active_count,
            witness_row_len,
            round_message_lens,
        })
    }

    #[must_use]
    pub fn product_domain_size(&self) -> usize {
        self.batch_capacity * self.witness_row_len
    }

    #[must_use]
    pub fn canonical_product_oracle_byte_len(&self) -> usize {
        self.canonical_product_oracle_public_byte_template().0.len()
    }

    #[must_use]
    pub fn canonical_product_oracle_public_byte_template(&self) -> (Vec<u8>, Vec<bool>) {
        self.canonical_product_oracle_public_byte_template_inner(None)
    }

    pub fn canonical_product_oracle_public_byte_template_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<(Vec<u8>, Vec<bool>)> {
        if statement.shape != *self
            || statement.round_message_commitments.len() != self.round_message_lens.len()
        {
            return None;
        }
        Some(self.canonical_product_oracle_public_byte_template_inner(Some(statement)))
    }

    fn canonical_product_oracle_public_byte_template_inner(
        &self,
        statement: Option<&BatchedCpPublicStatement>,
    ) -> (Vec<u8>, Vec<bool>) {
        let mut bytes = Vec::new();
        let mut known = Vec::new();
        push_known_bytes(
            &mut bytes,
            &mut known,
            b"symphony-batched-cp-product-oracle-v1",
        );
        push_known_statement_shape(&mut bytes, &mut known, self);
        push_known_usize(&mut bytes, &mut known, self.batch_capacity);
        for idx in 0..self.batch_capacity {
            push_known_usize(&mut bytes, &mut known, idx);
            push_known_u8(&mut bytes, &mut known, u8::from(idx < self.active_count));
            if idx < self.active_count {
                push_private_bytes(&mut bytes, &mut known, self.witness_row_len);
            } else {
                push_known_bytes(&mut bytes, &mut known, &[]);
            }
        }
        push_known_usize(&mut bytes, &mut known, self.round_message_lens.len());
        for (round, &message_len) in self.round_message_lens.iter().enumerate() {
            push_known_usize(&mut bytes, &mut known, round);
            push_known_usize(&mut bytes, &mut known, self.batch_capacity);
            for idx in 0..self.batch_capacity {
                push_known_usize(&mut bytes, &mut known, idx);
                push_known_u8(&mut bytes, &mut known, u8::from(idx < self.active_count));
                if idx < self.active_count {
                    push_private_bytes(&mut bytes, &mut known, message_len);
                } else {
                    push_known_bytes(&mut bytes, &mut known, &[]);
                }
            }
        }
        push_known_usize(&mut bytes, &mut known, self.round_message_lens.len());
        for (round, &message_len) in self.round_message_lens.iter().enumerate() {
            push_known_bytes(
                &mut bytes,
                &mut known,
                b"symphony-batched-cp-round-message-v1",
            );
            push_known_raw(&mut bytes, &mut known, &self.shape_id);
            push_known_usize(&mut bytes, &mut known, round);
            push_known_usize(&mut bytes, &mut known, self.batch_capacity);
            for idx in 0..self.batch_capacity {
                push_known_usize(&mut bytes, &mut known, idx);
                push_known_u8(&mut bytes, &mut known, u8::from(idx < self.active_count));
                if idx < self.active_count {
                    push_private_bytes(&mut bytes, &mut known, message_len);
                } else {
                    push_known_bytes(&mut bytes, &mut known, &[]);
                }
            }
        }
        push_known_manifest_body_template(&mut bytes, &mut known, self);
        push_known_fs_commitment_body_template(&mut bytes, &mut known, self);
        push_known_poseidon_fs_commitment_trace_template(&mut bytes, &mut known, self);
        push_known_batch_challenge_body_template(&mut bytes, &mut known, self, statement);
        push_known_challenge_to_beta_body_template(&mut bytes, &mut known, self, statement);
        push_known_fold_input_reconstruction_body_template(&mut bytes, &mut known, self);
        push_known_folded_output_accumulator_body_template(&mut bytes, &mut known, self, statement);
        debug_assert_eq!(bytes.len(), known.len());
        (bytes, known)
    }

    #[must_use]
    pub fn canonical_product_oracle_public_packed_claim_count(&self) -> usize {
        let (bytes, known) = self.canonical_product_oracle_public_byte_template();
        count_fully_known_packed_chunks(&bytes, &known)
    }

    pub fn canonical_product_oracle_public_packed_claim_count_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<usize> {
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(count_fully_known_packed_chunks(&bytes, &known))
    }

    pub fn challenge_derivation_packed_values_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<Vec<BatchedCpOraclePackedValue>> {
        let layout = self.product_oracle_layout();
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(packed_values_for_known_range(
            &bytes,
            &known,
            layout.batch_challenge_body,
        ))
    }

    pub fn challenge_to_beta_packed_values_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<Vec<BatchedCpOraclePackedValue>> {
        let layout = self.product_oracle_layout();
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(packed_values_for_known_range(
            &bytes,
            &known,
            layout.challenge_to_beta_body,
        ))
    }

    pub fn folded_output_packed_values_for_statement(
        &self,
        statement: &BatchedCpPublicStatement,
    ) -> Option<Vec<BatchedCpOraclePackedValue>> {
        let layout = self.product_oracle_layout();
        let (bytes, known) =
            self.canonical_product_oracle_public_byte_template_for_statement(statement)?;
        Some(packed_values_for_known_range(
            &bytes,
            &known,
            layout.folded_output_accumulator_body,
        ))
    }

    #[must_use]
    pub fn structured_oracle_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities: Vec<_> = layout
            .round_message_rows
            .iter()
            .zip(layout.round_message_digest_bodies.iter())
            .flat_map(|(message_rows, digest_rows)| {
                message_rows
                    .iter()
                    .zip(digest_rows.iter())
                    .flat_map(|(message, digest)| {
                        let len = message.len.min(digest.len);
                        (0..len).map(move |offset| BatchedCpOracleByteEquality {
                            left_offset: message.offset + offset,
                            right_offset: digest.offset + offset,
                        })
                    })
            })
            .collect();
        for round in 0..self.accumulator_shape.num_rounds {
            for idx in 0..self.active_count {
                push_range_equalities(
                    &mut equalities,
                    layout.witness_fs_messages[round][idx],
                    layout.round_message_rows[round][idx],
                );
            }
        }
        equalities
    }

    #[must_use]
    pub fn fs_commitment_body_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for round in 0..self.accumulator_shape.num_rounds {
            for idx in 0..self.active_count {
                push_range_equalities(
                    &mut equalities,
                    layout.fs_commitment_body_messages[round][idx],
                    layout.witness_fs_messages[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.fs_commitment_body_openings[round][idx],
                    layout.witness_fs_openings[round][idx],
                );
                if poseidon_fs_commitment_traces_enabled(self) {
                    for limb in 0..8 {
                        for byte in 0..4 {
                            equalities.push(BatchedCpOracleByteEquality {
                                left_offset: layout.poseidon_fs_commitment_trace_outputs[round]
                                    [idx]
                                    .offset
                                    + limb * 4
                                    + byte,
                                right_offset: layout.witness_fs_commitments[round][idx].offset
                                    + limb * 4
                                    + byte,
                            });
                        }
                    }
                }
            }
        }
        equalities
    }

    #[must_use]
    pub fn poseidon_fs_commitment_r1cs_constraints(
        &self,
    ) -> Vec<BatchedCpPoseidonR1csRowConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let mut constraints = Vec::new();
            for surface in self.poseidon_fs_commitment_r1cs_surfaces() {
                let row_candidates = sampled_poseidon_row_candidates(surface.num_rows);
                for row in row_candidates {
                    if let Some(constraint) = surface.row_constraint(row) {
                        constraints.push(constraint);
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn poseidon_fs_commitment_r1cs_surfaces(&self) -> Vec<BatchedCpPoseidonR1csSurface> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut surfaces = Vec::new();
            for round in 0..self.accumulator_shape.num_rounds {
                let input_len = poseidon_fs_commitment_input_len(
                    self.accumulator_shape.fs_message_lens[round],
                    self.accumulator_shape.fs_opening_len,
                );
                let (r1cs, _) = crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
                    b"fs-commit",
                    input_len,
                );
                for item in 0..self.active_count {
                    surfaces.push(BatchedCpPoseidonR1csSurface {
                        round,
                        item,
                        input_len,
                        num_rows: r1cs.num_constraints,
                        output_offsets: field_offsets(
                            layout.poseidon_fs_commitment_trace_outputs[round][item],
                            8,
                        ),
                        input_offsets: field_offsets(
                            layout.poseidon_fs_commitment_trace_inputs[round][item],
                            input_len,
                        ),
                        aux_offsets: field_offsets(
                            layout.poseidon_fs_commitment_trace_aux[round][item],
                            poseidon_fs_commitment_aux_len(input_len),
                        ),
                    });
                }
            }
            surfaces
        }
    }

    #[must_use]
    pub fn active_marker_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for idx in 0..self.batch_capacity {
            let manifest_marker = layout.manifest_active_markers[idx];
            equalities.push(BatchedCpOracleByteEquality {
                left_offset: manifest_marker,
                right_offset: layout.witness_active_markers[idx],
            });
            for round_markers in &layout.round_message_active_markers {
                equalities.push(BatchedCpOracleByteEquality {
                    left_offset: manifest_marker,
                    right_offset: round_markers[idx],
                });
            }
            for round_markers in &layout.round_message_digest_body_active_markers {
                equalities.push(BatchedCpOracleByteEquality {
                    left_offset: manifest_marker,
                    right_offset: round_markers[idx],
                });
            }
            if idx < self.active_count {
                for round_markers in &layout.fs_commitment_body_active_markers {
                    equalities.push(BatchedCpOracleByteEquality {
                        left_offset: manifest_marker,
                        right_offset: round_markers[idx],
                    });
                }
                if poseidon_fs_commitment_traces_enabled(self) {
                    for round_markers in &layout.poseidon_fs_commitment_trace_active_markers {
                        equalities.push(BatchedCpOracleByteEquality {
                            left_offset: manifest_marker,
                            right_offset: round_markers[idx],
                        });
                    }
                }
            }
        }
        equalities
    }

    #[must_use]
    pub fn manifest_membership_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for idx in 0..self.active_count {
            push_range_equalities(
                &mut equalities,
                layout.manifest_item_tags[idx],
                layout.witness_item_tags[idx],
            );
            push_range_equalities(
                &mut equalities,
                layout.manifest_public_statements[idx],
                layout.witness_public_statements[idx],
            );
        }
        equalities
    }

    #[must_use]
    pub fn folded_output_contribution_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for idx in 0..self.active_count {
            push_range_equalities(
                &mut equalities,
                layout.folded_output_contributions[idx],
                layout.witness_folded_output_contributions[idx],
            );
        }
        equalities
    }

    #[must_use]
    pub fn folded_output_self_consistency_byte_equalities(
        &self,
    ) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let folded_instance_len = folded_instance_encoding_len(&self.accumulator_shape);
        let mut equalities = Vec::new();
        for idx in 0..self.active_count {
            let contribution = layout.folded_output_contributions[idx];
            let x_folded = BatchedCpOracleByteRange {
                offset: contribution.offset + 32,
                len: folded_instance_len,
            };
            let folded_output_instance = BatchedCpOracleByteRange {
                offset: contribution.offset + 32 + folded_instance_len,
                len: folded_instance_len,
            };
            push_range_equalities(&mut equalities, x_folded, folded_output_instance);
        }
        equalities
    }

    #[must_use]
    pub fn fold_input_reconstruction_byte_equalities(&self) -> Vec<BatchedCpOracleByteEquality> {
        let layout = self.product_oracle_layout();
        let mut equalities = Vec::new();
        for round in 0..self.accumulator_shape.num_rounds {
            for idx in 0..self.active_count {
                push_range_equalities(
                    &mut equalities,
                    layout.fold_input_commitments[round][idx],
                    layout.witness_fold_input_commitments[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.fold_input_public_inputs[round][idx],
                    layout.witness_fold_input_public_inputs[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.fold_input_eval_messages[round][idx],
                    layout.witness_fold_input_eval_messages[round][idx],
                );
                push_range_equalities(
                    &mut equalities,
                    layout.witness_fold_input_eval_messages[round][idx],
                    layout.round_message_rows[round][idx],
                );
            }
        }
        equalities
    }

    #[must_use]
    pub fn folded_public_input_linear_constraints(
        &self,
    ) -> Vec<BatchedCpFoldedPublicInputLinearConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut constraints = Vec::new();
            for idx in 0..self.active_count {
                for public_idx in 0..self.accumulator_shape.folded_public_input_len {
                    for coeff_idx in 0..D {
                        constraints.push(BatchedCpFoldedPublicInputLinearConstraint {
                            beta_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    layout.witness_local_betas[round][idx].offset + coeff_idx * 8
                                })
                                .collect(),
                            input_scalar_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    layout.fold_input_public_inputs[round][idx].offset
                                        + public_idx * 8
                                })
                                .collect(),
                            output_coeff_offset:
                                folded_output_contribution_public_input_coeff_offset(
                                    &self.accumulator_shape,
                                    layout.folded_output_contributions[idx],
                                    public_idx,
                                    coeff_idx,
                                ),
                        });
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn folded_commitment_ring_mul_constraints(
        &self,
    ) -> Vec<BatchedCpFoldedCommitmentRingMulConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut constraints = Vec::new();
            for idx in 0..self.active_count {
                for commitment_idx in 0..self.accumulator_shape.commitment_kappa {
                    for coeff_idx in 0..D {
                        constraints.push(BatchedCpFoldedCommitmentRingMulConstraint {
                            beta_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    (0..D)
                                        .map(|beta_coeff_idx| {
                                            layout.witness_local_betas[round][idx].offset
                                                + beta_coeff_idx * 8
                                        })
                                        .collect()
                                })
                                .collect(),
                            commitment_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                .map(|round| {
                                    let commitment = layout.fold_input_commitments[round][idx];
                                    (0..D)
                                        .map(|commitment_coeff_idx| {
                                            commitment.offset
                                                + 8
                                                + commitment_idx * D * 8
                                                + commitment_coeff_idx * 8
                                        })
                                        .collect()
                                })
                                .collect(),
                            output_coeff_index: coeff_idx,
                            output_coeff_offset: folded_output_contribution_commitment_coeff_offset(
                                layout.folded_output_contributions[idx],
                                commitment_idx,
                                coeff_idx,
                            ),
                        });
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn folded_evaluation_ring_mul_constraints(
        &self,
    ) -> Vec<BatchedCpFoldedEvaluationRingMulConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            let layout = self.product_oracle_layout();
            let mut constraints = Vec::new();
            for idx in 0..self.active_count {
                for eval_idx in 0..self.accumulator_shape.folded_evaluation_count {
                    for tensor_row in 0..T {
                        for coeff_idx in 0..D {
                            constraints.push(BatchedCpFoldedEvaluationRingMulConstraint {
                                beta_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                    .map(|round| {
                                        (0..D)
                                            .map(|beta_coeff_idx| {
                                                layout.witness_local_betas[round][idx].offset
                                                    + beta_coeff_idx * 8
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                evaluation_coeff_offsets: (0..self.accumulator_shape.num_rounds)
                                    .map(|round| {
                                        let eval_offset = self
                                            .accumulator_shape
                                            .gr1cs_hadamard_eval_offsets[round][eval_idx];
                                        (0..D)
                                            .map(|input_coeff_idx| {
                                                layout.fold_input_eval_messages[round][idx].offset
                                                    + eval_offset
                                                    + tensor_row * D * 8
                                                    + input_coeff_idx * 8
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                output_coeff_index: coeff_idx,
                                output_coeff_offset:
                                    folded_output_contribution_evaluation_coeff_offset(
                                        &self.accumulator_shape,
                                        layout.folded_output_contributions[idx],
                                        eval_idx,
                                        tensor_row,
                                        coeff_idx,
                                    ),
                            });
                        }
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn product_oracle_layout(&self) -> BatchedCpProductOracleLayout {
        let mut cursor = ProductOracleCursor::new();
        cursor.push_bytes(b"symphony-batched-cp-product-oracle-v1");
        cursor.push_raw_len(encoded_statement_shape(self).len());
        cursor.push_usize();
        let mut witness_rows = Vec::with_capacity(self.batch_capacity);
        let mut witness_item_tags = Vec::with_capacity(self.batch_capacity);
        let mut witness_public_statements = Vec::with_capacity(self.batch_capacity);
        let mut witness_folded_output_contributions = Vec::with_capacity(self.batch_capacity);
        let mut witness_local_betas: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fs_commitments: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fs_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fs_openings: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fold_input_commitments: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fold_input_public_inputs: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_fold_input_eval_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.batch_capacity))
                .collect();
        let mut witness_original_witnesses: Vec<Vec<BatchedCpOracleByteRange>> = self
            .accumulator_shape
            .original_witness_lens
            .iter()
            .map(|_| Vec::with_capacity(self.batch_capacity))
            .collect();
        let mut witness_active_markers = Vec::with_capacity(self.batch_capacity);
        for idx in 0..self.batch_capacity {
            cursor.push_usize();
            witness_active_markers.push(cursor.offset);
            cursor.push_u8();
            if idx < self.active_count {
                let row_offset = cursor.offset + 8;
                witness_rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(self.witness_row_len),
                    len: self.witness_row_len,
                });
                witness_item_tags.push(BatchedCpOracleByteRange {
                    offset: row_offset,
                    len: 32,
                });
                witness_public_statements.push(BatchedCpOracleByteRange {
                    offset: row_offset + 32,
                    len: self.accumulator_shape.public_statement_len,
                });
                witness_folded_output_contributions.push(BatchedCpOracleByteRange {
                    offset: row_offset + 32 + self.accumulator_shape.public_statement_len,
                    len: self.accumulator_shape.folded_output_contribution_len,
                });
                let mut inner = row_offset
                    + 32
                    + self.accumulator_shape.public_statement_len
                    + self.accumulator_shape.folded_output_contribution_len;
                for betas in witness_local_betas
                    .iter_mut()
                    .take(self.accumulator_shape.num_rounds)
                {
                    betas.push(BatchedCpOracleByteRange {
                        offset: inner,
                        len: D * 8,
                    });
                    inner += D * 8;
                }
                for (round, &message_len) in
                    self.accumulator_shape.fs_message_lens.iter().enumerate()
                {
                    witness_fs_messages[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: message_len,
                    });
                    inner += 8 + message_len;
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    let commitment_len = self.accumulator_shape.fs_commitment_len;
                    witness_fs_commitments[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: commitment_len,
                    });
                    inner += 8 + commitment_len;
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    witness_fs_openings[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: self.accumulator_shape.fs_opening_len,
                    });
                    inner += 8 + self.accumulator_shape.fs_opening_len;
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    let commitment_len = self.accumulator_shape.fold_input_commitment_lens[round];
                    witness_fold_input_commitments[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: commitment_len,
                    });
                    inner += 8 + commitment_len;

                    let public_input_len =
                        self.accumulator_shape.fold_input_public_input_lens[round] * 8;
                    witness_fold_input_public_inputs[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: public_input_len,
                    });
                    inner += 8 + public_input_len;

                    let eval_message_len =
                        self.accumulator_shape.fold_input_eval_message_lens[round];
                    witness_fold_input_eval_messages[round].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: eval_message_len,
                    });
                    inner += 8 + eval_message_len;
                }
                for (witness_idx, &witness_len) in self
                    .accumulator_shape
                    .original_witness_lens
                    .iter()
                    .enumerate()
                {
                    witness_original_witnesses[witness_idx].push(BatchedCpOracleByteRange {
                        offset: inner + 8,
                        len: witness_len * D * 8,
                    });
                    inner += 8 + witness_len * D * 8;
                }
            } else {
                witness_rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(0),
                    len: 0,
                });
                witness_item_tags.push(BatchedCpOracleByteRange {
                    offset: cursor.offset,
                    len: 0,
                });
                witness_public_statements.push(BatchedCpOracleByteRange {
                    offset: cursor.offset,
                    len: 0,
                });
                witness_folded_output_contributions.push(BatchedCpOracleByteRange {
                    offset: cursor.offset,
                    len: 0,
                });
                for betas in witness_local_betas
                    .iter_mut()
                    .take(self.accumulator_shape.num_rounds)
                {
                    betas.push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
                for round in 0..self.accumulator_shape.num_rounds {
                    witness_fs_messages[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fs_commitments[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fs_openings[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fold_input_commitments[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fold_input_public_inputs[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                    witness_fold_input_eval_messages[round].push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
                for witness_ranges in witness_original_witnesses.iter_mut() {
                    witness_ranges.push(BatchedCpOracleByteRange {
                        offset: cursor.offset,
                        len: 0,
                    });
                }
            }
        }

        cursor.push_usize();
        let mut round_message_rows = Vec::with_capacity(self.round_message_lens.len());
        let mut round_message_active_markers = Vec::with_capacity(self.round_message_lens.len());
        for &message_len in &self.round_message_lens {
            cursor.push_usize();
            cursor.push_usize();
            let mut rows = Vec::with_capacity(self.batch_capacity);
            let mut markers = Vec::with_capacity(self.batch_capacity);
            for idx in 0..self.batch_capacity {
                cursor.push_usize();
                markers.push(cursor.offset);
                cursor.push_u8();
                let len = if idx < self.active_count {
                    message_len
                } else {
                    0
                };
                rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(len),
                    len,
                });
            }
            round_message_rows.push(rows);
            round_message_active_markers.push(markers);
        }

        cursor.push_usize();
        let mut round_message_digest_bodies = Vec::with_capacity(self.round_message_lens.len());
        let mut round_message_digest_body_active_markers =
            Vec::with_capacity(self.round_message_lens.len());
        for &message_len in &self.round_message_lens {
            cursor.push_bytes(b"symphony-batched-cp-round-message-v1");
            cursor.push_raw_len(32);
            cursor.push_usize();
            cursor.push_usize();
            let mut rows = Vec::with_capacity(self.batch_capacity);
            let mut markers = Vec::with_capacity(self.batch_capacity);
            for idx in 0..self.batch_capacity {
                cursor.push_usize();
                markers.push(cursor.offset);
                cursor.push_u8();
                let len = if idx < self.active_count {
                    message_len
                } else {
                    0
                };
                rows.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(len),
                    len,
                });
            }
            round_message_digest_bodies.push(rows);
            round_message_digest_body_active_markers.push(markers);
        }

        let manifest_start = cursor.offset;
        let mut manifest_active_markers = Vec::with_capacity(self.batch_capacity);
        let mut manifest_item_tags = Vec::with_capacity(self.batch_capacity);
        let mut manifest_public_statements = Vec::with_capacity(self.batch_capacity);
        cursor.push_bytes(b"symphony-batched-cp-manifest-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        for idx in 0..self.batch_capacity {
            cursor.push_usize();
            manifest_active_markers.push(cursor.offset);
            cursor.push_u8();
            manifest_item_tags.push(BatchedCpOracleByteRange {
                offset: cursor.push_raw_len(32),
                len: 32,
            });
            if idx < self.active_count {
                manifest_public_statements.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(self.accumulator_shape.public_statement_len),
                    len: self.accumulator_shape.public_statement_len,
                });
            } else {
                manifest_public_statements.push(BatchedCpOracleByteRange {
                    offset: cursor.push_bytes_len(0),
                    len: 0,
                });
            }
        }
        let manifest_body = BatchedCpOracleByteRange {
            offset: manifest_start,
            len: cursor.offset - manifest_start,
        };
        debug_assert_eq!(manifest_body.len, manifest_body_len(self));
        let fs_commitment_body_start = cursor.offset;
        let mut fs_commitment_bodies: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fs_commitment_body_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fs_commitment_body_openings: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fs_commitment_body_active_markers: Vec<Vec<usize>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut poseidon_fs_commitment_trace_outputs: Vec<Vec<BatchedCpOracleByteRange>> = (0
            ..self.accumulator_shape.num_rounds)
            .map(|_| Vec::with_capacity(self.active_count))
            .collect();
        let mut poseidon_fs_commitment_trace_inputs: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut poseidon_fs_commitment_trace_aux: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut poseidon_fs_commitment_trace_active_markers: Vec<Vec<usize>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        cursor.push_bytes(b"symphony-batched-cp-fs-commitment-bodies-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        for round in 0..self.accumulator_shape.num_rounds {
            cursor.push_usize();
            for _idx in 0..self.active_count {
                cursor.push_usize();
                fs_commitment_body_active_markers[round].push(cursor.offset);
                cursor.push_u8();
                let body_start = cursor.offset;
                cursor.push_usize();
                let message_len = self.accumulator_shape.fs_message_lens[round];
                fs_commitment_body_messages[round].push(BatchedCpOracleByteRange {
                    offset: cursor.push_raw_len(message_len),
                    len: message_len,
                });
                let opening_len = self.accumulator_shape.fs_opening_len;
                fs_commitment_body_openings[round].push(BatchedCpOracleByteRange {
                    offset: cursor.push_raw_len(opening_len),
                    len: opening_len,
                });
                fs_commitment_bodies[round].push(BatchedCpOracleByteRange {
                    offset: body_start,
                    len: cursor.offset - body_start,
                });
            }
        }
        let fs_commitment_body = BatchedCpOracleByteRange {
            offset: fs_commitment_body_start,
            len: cursor.offset - fs_commitment_body_start,
        };
        debug_assert_eq!(fs_commitment_body.len, fs_commitment_bodies_body_len(self));
        if poseidon_fs_commitment_traces_enabled(self) {
            let poseidon_trace_start = cursor.offset;
            cursor.push_bytes(b"symphony-batched-cp-poseidon-fs-commitment-traces-v1");
            cursor.push_raw_len(32);
            cursor.push_usize();
            cursor.push_usize();
            for round in 0..self.accumulator_shape.num_rounds {
                cursor.push_usize();
                let input_len = poseidon_fs_commitment_input_len(
                    self.accumulator_shape.fs_message_lens[round],
                    self.accumulator_shape.fs_opening_len,
                );
                let aux_len = poseidon_fs_commitment_aux_len(input_len);
                for _idx in 0..self.active_count {
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_active_markers[round].push(cursor.offset);
                    cursor.push_u8();
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_outputs[round].push(BatchedCpOracleByteRange {
                        offset: cursor.push_raw_len(8 * 4),
                        len: 8 * 4,
                    });
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_inputs[round].push(BatchedCpOracleByteRange {
                        offset: cursor.push_raw_len(input_len * 4),
                        len: input_len * 4,
                    });
                    cursor.push_usize();
                    poseidon_fs_commitment_trace_aux[round].push(BatchedCpOracleByteRange {
                        offset: cursor.push_raw_len(aux_len * 4),
                        len: aux_len * 4,
                    });
                }
            }
            let poseidon_trace_body = BatchedCpOracleByteRange {
                offset: poseidon_trace_start,
                len: cursor.offset - poseidon_trace_start,
            };
            debug_assert_eq!(
                poseidon_trace_body.len,
                poseidon_fs_commitment_traces_body_len(self)
            );
        }
        let batch_challenge_body = BatchedCpOracleByteRange {
            offset: cursor.offset,
            len: batch_challenge_body_len(self),
        };
        cursor.push_raw_len(batch_challenge_body.len);
        let challenge_to_beta_start = cursor.offset;
        cursor.push_bytes(b"symphony-batched-cp-challenge-to-beta-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        let challenge_to_beta_digest = BatchedCpOracleByteRange {
            offset: cursor.push_raw_len(32),
            len: 32,
        };
        let challenge_to_beta_beta = BatchedCpOracleByteRange {
            offset: cursor.push_raw_len(D * 8),
            len: D * 8,
        };
        let challenge_to_beta_body = BatchedCpOracleByteRange {
            offset: challenge_to_beta_start,
            len: cursor.offset - challenge_to_beta_start,
        };
        debug_assert_eq!(challenge_to_beta_body.len, challenge_to_beta_body_len(self));
        let fold_input_start = cursor.offset;
        let mut fold_input_commitments: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fold_input_public_inputs: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        let mut fold_input_eval_messages: Vec<Vec<BatchedCpOracleByteRange>> =
            (0..self.accumulator_shape.num_rounds)
                .map(|_| Vec::with_capacity(self.active_count))
                .collect();
        cursor.push_bytes(b"symphony-batched-cp-fold-input-reconstruction-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        for _idx in 0..self.active_count {
            cursor.push_usize();
            for round in 0..self.accumulator_shape.num_rounds {
                cursor.push_usize();
                fold_input_commitments[round].push(BatchedCpOracleByteRange {
                    offset: cursor
                        .push_bytes_len(self.accumulator_shape.fold_input_commitment_lens[round]),
                    len: self.accumulator_shape.fold_input_commitment_lens[round],
                });
                let public_input_len =
                    self.accumulator_shape.fold_input_public_input_lens[round] * 8;
                cursor.push_usize();
                fold_input_public_inputs[round].push(BatchedCpOracleByteRange {
                    offset: cursor.push_raw_len(public_input_len),
                    len: public_input_len,
                });
                fold_input_eval_messages[round].push(BatchedCpOracleByteRange {
                    offset: cursor
                        .push_bytes_len(self.accumulator_shape.fold_input_eval_message_lens[round]),
                    len: self.accumulator_shape.fold_input_eval_message_lens[round],
                });
            }
        }
        let fold_input_reconstruction_body = BatchedCpOracleByteRange {
            offset: fold_input_start,
            len: cursor.offset - fold_input_start,
        };
        debug_assert_eq!(
            fold_input_reconstruction_body.len,
            fold_input_reconstruction_body_len(self)
        );
        let folded_output_start = cursor.offset;
        let mut folded_output_contributions = Vec::with_capacity(self.active_count);
        cursor.push_bytes(b"symphony-batched-cp-folded-output-accumulator-v1");
        cursor.push_raw_len(32);
        cursor.push_usize();
        cursor.push_usize();
        cursor.push_usize();
        let folded_output_accumulator_root = BatchedCpOracleByteRange {
            offset: cursor.push_raw_len(32),
            len: 32,
        };
        cursor.push_usize();
        for _ in 0..self.active_count {
            folded_output_contributions.push(BatchedCpOracleByteRange {
                offset: cursor.push_raw_len(self.accumulator_shape.folded_output_contribution_len),
                len: self.accumulator_shape.folded_output_contribution_len,
            });
        }
        let folded_output_accumulator_body = BatchedCpOracleByteRange {
            offset: folded_output_start,
            len: cursor.offset - folded_output_start,
        };
        debug_assert_eq!(
            folded_output_accumulator_body.len,
            folded_output_accumulator_body_len(self)
        );
        let byte_len = cursor.offset;
        BatchedCpProductOracleLayout {
            byte_len,
            packed_field_len: byte_len.div_ceil(3) + 1,
            witness_rows,
            witness_item_tags,
            witness_public_statements,
            witness_folded_output_contributions,
            witness_local_betas,
            witness_fs_commitments,
            witness_fold_input_commitments,
            witness_fold_input_public_inputs,
            witness_fold_input_eval_messages,
            witness_original_witnesses,
            witness_fs_messages,
            witness_fs_openings,
            witness_active_markers,
            round_message_rows,
            round_message_active_markers,
            round_message_digest_bodies,
            round_message_digest_body_active_markers,
            fs_commitment_bodies,
            fs_commitment_body_messages,
            fs_commitment_body_openings,
            fs_commitment_body_active_markers,
            poseidon_fs_commitment_trace_outputs,
            poseidon_fs_commitment_trace_inputs,
            poseidon_fs_commitment_trace_aux,
            poseidon_fs_commitment_trace_active_markers,
            manifest_active_markers,
            manifest_item_tags,
            manifest_public_statements,
            manifest_body,
            batch_challenge_body,
            challenge_to_beta_body,
            challenge_to_beta_digest,
            challenge_to_beta_beta,
            folded_output_accumulator_body,
            folded_output_accumulator_root,
            folded_output_contributions,
            fold_input_reconstruction_body,
            fold_input_commitments,
            fold_input_public_inputs,
            fold_input_eval_messages,
        }
    }

    #[must_use]
    pub fn structured_relation_description(&self) -> BatchedCpStructuredRelationDescription {
        BatchedCpStructuredRelationDescription {
            shape: self.clone(),
            public_statement_bytes: estimate_public_statement_bytes(self),
            product_domain_size: self.product_domain_size(),
            witness_oracle_row_len: self.witness_row_len,
            round_message_oracle_lens: self.round_message_lens.clone(),
        }
    }

    #[must_use]
    pub fn semantic_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticRelationDescription {
        BatchedCpSemanticRelationDescription {
            shape: self.clone(),
            oracle_layout: self.product_oracle_layout(),
            ajtai_params_digest: digest_ajtai_params(self.accumulator_shape.digest_scheme, ajtai),
            ajtai_matrix: ajtai.a.clone(),
            r1cs_matrices_digest: digest_r1cs_matrices(self.accumulator_shape.digest_scheme, r1cs),
            r1cs_matrices: r1cs.clone(),
            input_bound,
            constraint_families: vec![
                BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                BatchedCpSemanticConstraintFamily::ManifestMembership,
                BatchedCpSemanticConstraintFamily::RoundMessageBinding,
                BatchedCpSemanticConstraintFamily::ChallengeDerivation,
                BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
                BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
                BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
                BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
                BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
            ],
        }
    }

    #[must_use]
    pub fn semantic_v2_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticRelationV2Description {
        let semantic = self.semantic_relation_description(ajtai, r1cs, input_bound);
        BatchedCpSemanticRelationV2Description {
            v2_layout: BatchedCpSemanticOracleV2Layout::from_semantic(&semantic),
            semantic,
        }
    }

    #[must_use]
    pub fn semantic_columnar_v2_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticColumnarV2Description {
        let semantic = self.semantic_relation_description(ajtai, r1cs, input_bound);
        BatchedCpSemanticColumnarV2Description {
            v2_layout: BatchedCpSemanticOracleV2Layout::from_semantic(&semantic),
            columnar_layout: BatchedCpSemanticColumnarV2Layout::from_semantic(&semantic),
            semantic,
        }
    }

    #[must_use]
    pub fn semantic_family_columnar_v2_relation_description(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSemanticFamilyColumnarV2Description {
        let semantic = self.semantic_relation_description(ajtai, r1cs, input_bound);
        BatchedCpSemanticFamilyColumnarV2Description {
            v2_layout: BatchedCpSemanticOracleV2Layout::from_semantic(&semantic),
            family_layout: BatchedCpSemanticFamilyColumnarV2Layout::from_semantic(&semantic),
            semantic,
        }
    }

    #[must_use]
    pub fn symbt3_setup_descriptor(
        &self,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> BatchedCpSymbt3SetupDescriptor {
        let ajtai_params_digest = digest_ajtai_params(self.accumulator_shape.digest_scheme, ajtai);
        let ring_module_layout = Symbt3RingModuleLayout::from_shape_and_ajtai(self, ajtai);
        let ajtai_commit_layout =
            Symbt3AjtaiCommitLayout::from_shape_and_ajtai(self, ajtai, ajtai_params_digest);
        let r1cs_matrices_digest = digest_r1cs_matrices(self.accumulator_shape.digest_scheme, r1cs);
        let r1cs_evaluator_layout =
            Symbt3R1csEvaluatorLayout::from_shape_and_r1cs(self, r1cs, r1cs_matrices_digest);
        let gr1cs_residual_layout = Symbt3Gr1csResidualLayout::from_shape(self);
        let algebra_law = Symbt3AlgebraLaw::from_shape(self);
        let ajtai_linear_algebra_layout = Symbt3AjtaiLinearAlgebraLayout::from_shape_and_layouts(
            self,
            &algebra_law,
            &ajtai_commit_layout,
            ajtai_params_digest,
            self.accumulator_shape.digest_scheme,
        );
        let ajtai_norm_range_layout = Symbt3AjtaiNormRangeLayout::from_shape_and_layouts(
            self,
            &algebra_law,
            &ajtai_linear_algebra_layout,
            input_bound,
            self.accumulator_shape.digest_scheme,
        );
        let batch_manifest_layout = Symbt3BatchManifestLayout::from_shape(self);
        let message_semantic_layout = Symbt3MessageSemanticLayout::from_shape_and_layouts(
            self,
            &BatchedCpSymbt3OracleLayout::from_shape(self),
            &algebra_law,
            &gr1cs_residual_layout,
            &ajtai_linear_algebra_layout,
            &ajtai_norm_range_layout,
            &batch_manifest_layout,
            self.accumulator_shape.digest_scheme,
        );
        let folded_gr1cs_product_residual_layout =
            Symbt3FoldedGr1csProductResidualLayout::from_shape(self);
        BatchedCpSymbt3SetupDescriptor {
            shape: self.clone(),
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
            ajtai_matrix: ajtai.a.clone(),
            r1cs_matrices: r1cs.clone(),
            ajtai_params_digest,
            r1cs_matrices_digest,
            input_bound,
        }
    }
}

