struct ProductOracleCursor {
    offset: usize,
}

impl ProductOracleCursor {
    fn new() -> Self {
        Self { offset: 0 }
    }

    fn push_u8(&mut self) {
        self.offset += 1;
    }

    fn push_usize(&mut self) {
        self.offset += 8;
    }

    fn push_raw_len(&mut self, len: usize) -> usize {
        let start = self.offset;
        self.offset += len;
        start
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> usize {
        self.push_bytes_len(bytes.len())
    }

    fn push_bytes_len(&mut self, len: usize) -> usize {
        self.push_usize();
        self.push_raw_len(len)
    }
}

fn encoded_statement_shape(shape: &BatchedCpStatementShape) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_statement_shape(&mut encoded, shape);
    encoded
}

impl BatchedCpStructuredRelationDescription {
    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STRUCTURED_RELATION_CONTEXT_MAGIC);
        encode_statement_shape(&mut out, &self.shape);
        push_usize(&mut out, self.public_statement_bytes);
        push_usize(&mut out, self.product_domain_size);
        push_usize(&mut out, self.witness_oracle_row_len);
        push_usize_vec(&mut out, &self.round_message_oracle_lens);
        out
    }

    #[must_use]
    pub fn relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-structured-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes,
            num_witness_vars: self.product_domain_size,
            // This is intentionally not a flattened/appended R1CS. The real
            // structured WHIR path consumes the context metadata directly.
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < STRUCTURED_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..STRUCTURED_RELATION_CONTEXT_MAGIC.len()]
                != STRUCTURED_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidStructuredRelationContext);
        }
        let mut pos = STRUCTURED_RELATION_CONTEXT_MAGIC.len();
        let shape = decode_statement_shape(bytes, &mut pos)?;
        let public_statement_bytes = read_usize(bytes, &mut pos)?;
        let product_domain_size = read_usize(bytes, &mut pos)?;
        let witness_oracle_row_len = read_usize(bytes, &mut pos)?;
        let round_message_oracle_lens = read_usize_vec(bytes, &mut pos)?;
        if pos != bytes.len()
            || product_domain_size != shape.product_domain_size()
            || witness_oracle_row_len != shape.witness_row_len
            || round_message_oracle_lens != shape.round_message_lens
        {
            return Err(BatchedCpError::InvalidStructuredRelationContext);
        }
        Ok(Self {
            shape,
            public_statement_bytes,
            product_domain_size,
            witness_oracle_row_len,
            round_message_oracle_lens,
        })
    }
}

impl BatchedCpSemanticRelationDescription {
    #[must_use]
    pub fn public_statement_bytes(&self) -> usize {
        estimate_public_statement_bytes(&self.shape)
    }

    #[must_use]
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEMANTIC_RELATION_CONTEXT_MAGIC);
        encode_statement_shape(&mut out, &self.shape);
        push_usize(&mut out, self.oracle_layout.byte_len);
        push_usize(&mut out, self.oracle_layout.packed_field_len);
        out.extend_from_slice(&self.ajtai_params_digest);
        encode_ring_matrix(&mut out, &self.ajtai_matrix);
        out.extend_from_slice(&self.r1cs_matrices_digest);
        encode_r1cs_matrices(&mut out, &self.r1cs_matrices);
        out.extend_from_slice(&self.input_bound.to_le_bytes());
        push_usize(&mut out, self.constraint_families.len());
        for family in &self.constraint_families {
            out.push(semantic_constraint_family_code(*family));
        }
        out
    }

    #[must_use]
    pub fn semantic_relation_id(&self) -> Digest32 {
        digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-semantic-relation-id",
            &self.canonical_context_bytes(),
        )
    }

    #[must_use]
    pub fn to_relation_description(&self) -> RelationDescription {
        RelationDescription {
            num_instance_vars: self.public_statement_bytes(),
            num_witness_vars: self.oracle_layout.packed_field_len,
            // The semantic context is intentionally not an appended R1CS. A
            // later WHIR structured-constraint interface must consume these
            // families directly before this route can become authoritative.
            num_constraints: 0,
            context: Some(self.canonical_context_bytes()),
        }
    }

    pub fn from_context_bytes(bytes: &[u8]) -> Result<Self, BatchedCpError> {
        if bytes.len() < SEMANTIC_RELATION_CONTEXT_MAGIC.len()
            || &bytes[..SEMANTIC_RELATION_CONTEXT_MAGIC.len()] != SEMANTIC_RELATION_CONTEXT_MAGIC
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let mut pos = SEMANTIC_RELATION_CONTEXT_MAGIC.len();
        let shape = decode_statement_shape(bytes, &mut pos)?;
        let byte_len = read_usize(bytes, &mut pos)?;
        let packed_field_len = read_usize(bytes, &mut pos)?;
        let ajtai_params_digest = read_digest(bytes, &mut pos)?;
        let ajtai_matrix = read_ring_matrix(bytes, &mut pos)?;
        let r1cs_matrices_digest = read_digest(bytes, &mut pos)?;
        let r1cs_matrices = read_r1cs_matrices(bytes, &mut pos)?;
        let input_bound = read_u64(bytes, &mut pos)?;
        let family_count = read_usize(bytes, &mut pos)?;
        let mut constraint_families = Vec::with_capacity(family_count);
        for _ in 0..family_count {
            let Some(&code) = bytes.get(pos) else {
                return Err(BatchedCpError::InvalidSemanticRelationContext);
            };
            pos += 1;
            constraint_families.push(
                semantic_constraint_family_from_code(code)
                    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
            );
        }
        if pos != bytes.len() {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        let oracle_layout = shape.product_oracle_layout();
        if byte_len != oracle_layout.byte_len
            || packed_field_len != oracle_layout.packed_field_len
            || ajtai_matrix.len() != shape.accumulator_shape.commitment_kappa
            || ajtai_matrix
                .iter()
                .any(|row| row.len() != shape.accumulator_shape.r1cs_num_variables)
            || r1cs_matrices.num_constraints != shape.accumulator_shape.r1cs_num_constraints
            || r1cs_matrices.num_variables != shape.accumulator_shape.r1cs_num_variables
            || r1cs_matrices.num_public != shape.accumulator_shape.r1cs_num_public
        {
            return Err(BatchedCpError::InvalidSemanticRelationContext);
        }
        Ok(Self {
            shape,
            oracle_layout,
            ajtai_params_digest,
            ajtai_matrix,
            r1cs_matrices_digest,
            r1cs_matrices,
            input_bound,
            constraint_families,
        })
    }

    #[must_use]
    pub fn supported_constraint_blocks(&self) -> Vec<BatchedCpSemanticConstraintBlock> {
        self.supported_constraint_blocks_for_statement(None)
    }

    #[must_use]
    pub fn supported_constraint_blocks_for_statement(
        &self,
        statement: Option<&BatchedCpPublicStatement>,
    ) -> Vec<BatchedCpSemanticConstraintBlock> {
        let mut blocks = Vec::new();
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                label: "fs-commitment-body-message-opening-byte-equality",
                constraints: self
                    .shape
                    .fs_commitment_body_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .chain(
                        self.shape
                            .poseidon_fs_commitment_r1cs_constraints()
                            .into_iter()
                            .map(BatchedCpSemanticConstraint::PoseidonR1csRow),
                    )
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::RoundMessageBinding)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::RoundMessageBinding,
                label: "round-message-oracle-to-digest-body-byte-equality",
                constraints: self
                    .shape
                    .structured_oracle_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ManifestMembership)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::ManifestMembership,
                label: "manifest-item-to-witness-row-byte-equality",
                constraints: self
                    .shape
                    .manifest_membership_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ChallengeDerivation)
        {
            if let Some(statement) = statement {
                let constraints = self
                    .shape
                    .challenge_derivation_packed_values_for_statement(statement)
                    .unwrap_or_default()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::PackedValue)
                    .collect();
                blocks.push(BatchedCpSemanticConstraintBlock {
                    family: BatchedCpSemanticConstraintFamily::ChallengeDerivation,
                    label: "batch-challenge-body-public-packed-values",
                    constraints,
                });
            }
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding)
        {
            if let Some(statement) = statement {
                let constraints = self
                    .shape
                    .challenge_to_beta_packed_values_for_statement(statement)
                    .unwrap_or_default()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::PackedValue)
                    .collect();
                blocks.push(BatchedCpSemanticConstraintBlock {
                    family: BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding,
                    label: "batch-challenge-digest-to-beta-packed-values",
                    constraints,
                });
            }
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::FoldedOutputDerivation)
        {
            let mut constraints = Vec::new();
            constraints.extend(
                self.shape
                    .folded_output_contribution_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality),
            );
            constraints.extend(
                self.shape
                    .folded_output_self_consistency_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality),
            );
            constraints.extend(
                self.shape
                    .fold_input_reconstruction_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality),
            );
            constraints.extend(
                self.shape
                    .folded_public_input_linear_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::FoldedPublicInputLinear),
            );
            constraints.extend(
                self.shape
                    .folded_commitment_ring_mul_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::FoldedCommitmentRingMul),
            );
            constraints.extend(
                self.shape
                    .folded_evaluation_ring_mul_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::FoldedEvaluationRingMul),
            );
            if let Some(statement) = statement {
                constraints.extend(
                    self.shape
                        .folded_output_packed_values_for_statement(statement)
                        .unwrap_or_default()
                        .into_iter()
                        .map(BatchedCpSemanticConstraint::PackedValue),
                );
            }
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::FoldedOutputDerivation,
                label: "folded-output-accumulator-body-binding",
                constraints,
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity,
                label: "original-commitment-ajtai-opening-linear-equations",
                constraints: self
                    .ajtai_opening_linear_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::AjtaiOpeningLinear)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::OriginalR1csValidity)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::OriginalR1csValidity,
                label: "original-r1cs-row-hadamard-equations",
                constraints: self
                    .original_r1cs_constraints()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::OriginalR1cs)
                    .collect(),
            });
        }
        if self
            .constraint_families
            .contains(&BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy)
        {
            blocks.push(BatchedCpSemanticConstraintBlock {
                family: BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy,
                label: "active-marker-consistency",
                constraints: self
                    .shape
                    .active_marker_byte_equalities()
                    .into_iter()
                    .map(BatchedCpSemanticConstraint::ByteEquality)
                    .collect(),
            });
        }
        blocks
    }

    #[must_use]
    pub fn ajtai_opening_linear_constraints(&self) -> Vec<BatchedCpAjtaiOpeningLinearConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.shape.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            if self.ajtai_matrix.len() != self.shape.accumulator_shape.commitment_kappa
                || self
                    .ajtai_matrix
                    .iter()
                    .any(|row| row.len() != self.shape.accumulator_shape.r1cs_num_variables)
            {
                return Vec::new();
            }

            let layout = self.shape.product_oracle_layout();
            let mut constraints = Vec::new();
            for item in 0..self.shape.active_count {
                for round in 0..self.shape.accumulator_shape.num_rounds {
                    let public_inputs = layout.fold_input_public_inputs[round][item];
                    let original_witness = layout.witness_original_witnesses[round][item];
                    if original_witness.len
                        != self.shape.accumulator_shape.original_witness_lens[round] * D * 8
                    {
                        continue;
                    }
                    for (row, matrix_row) in self.ajtai_matrix.iter().enumerate() {
                        for coeff in 0..D {
                            constraints.push(BatchedCpAjtaiOpeningLinearConstraint {
                                item,
                                round,
                                row,
                                coeff,
                                matrix_row: matrix_row.clone(),
                                public_input_offsets: (0..self
                                    .shape
                                    .accumulator_shape
                                    .r1cs_num_public)
                                    .map(|public_idx| public_inputs.offset + public_idx * 8)
                                    .collect(),
                                witness_coeff_offsets: (0..self
                                    .shape
                                    .accumulator_shape
                                    .original_witness_lens[round])
                                    .map(|witness_idx| {
                                        (0..D)
                                            .map(|witness_coeff| {
                                                original_witness.offset
                                                    + witness_idx * D * 8
                                                    + witness_coeff * 8
                                            })
                                            .collect()
                                    })
                                    .collect(),
                                commitment_coeff_offset: layout.fold_input_commitments[round][item]
                                    .offset
                                    + 8
                                    + row * D * 8
                                    + coeff * 8,
                            });
                        }
                    }
                }
            }
            constraints
        }
    }

    #[must_use]
    pub fn original_r1cs_constraints(&self) -> Vec<BatchedCpOriginalR1csConstraint> {
        #[cfg(not(feature = "whir"))]
        {
            Vec::new()
        }
        #[cfg(feature = "whir")]
        {
            if self.shape.accumulator_shape.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
                return Vec::new();
            }
            if self.r1cs_matrices.num_constraints
                != self.shape.accumulator_shape.r1cs_num_constraints
                || self.r1cs_matrices.num_variables
                    != self.shape.accumulator_shape.r1cs_num_variables
                || self.r1cs_matrices.num_public != self.shape.accumulator_shape.r1cs_num_public
            {
                return Vec::new();
            }
            let layout = self.shape.product_oracle_layout();
            let mut constraints = Vec::new();
            for item in 0..self.shape.active_count {
                for original_index in 0..self.shape.accumulator_shape.local_public_input_count {
                    let public_inputs = layout.fold_input_public_inputs[original_index][item];
                    let original_witness = layout.witness_original_witnesses[original_index][item];
                    for row in 0..self.r1cs_matrices.num_constraints {
                        for coeff in 0..D {
                            constraints.push(BatchedCpOriginalR1csConstraint {
                                item,
                                original_index,
                                row,
                                coeff,
                                a_terms: r1cs_row_terms(
                                    &self.r1cs_matrices.a,
                                    row,
                                    coeff,
                                    public_inputs,
                                    original_witness,
                                    self.r1cs_matrices.num_public,
                                ),
                                b_terms: r1cs_row_terms(
                                    &self.r1cs_matrices.b,
                                    row,
                                    coeff,
                                    public_inputs,
                                    original_witness,
                                    self.r1cs_matrices.num_public,
                                ),
                                c_terms: r1cs_row_terms(
                                    &self.r1cs_matrices.c,
                                    row,
                                    coeff,
                                    public_inputs,
                                    original_witness,
                                    self.r1cs_matrices.num_public,
                                ),
                            });
                        }
                    }
                }
            }
            constraints
        }
    }
}

impl BatchedCpBucket {
    pub fn new(
        items: Vec<BatchedCpItem>,
        whir_parameter_digest: Digest32,
    ) -> Result<Self, BatchedCpError> {
        if items.is_empty() {
            return Err(BatchedCpError::EmptyBatch);
        }
        let mut tags = BTreeSet::new();
        for item in &items {
            if !tags.insert(item.item_tag) {
                return Err(BatchedCpError::DuplicateItemTag);
            }
        }
        let first_shape = CpAccumulatorShape::from_item(
            &items[0].public,
            &items[0].witness,
            whir_parameter_digest,
        )?;
        for item in &items[1..] {
            let shape =
                CpAccumulatorShape::from_item(&item.public, &item.witness, whir_parameter_digest)?;
            if shape != first_shape {
                return Err(BatchedCpError::ShapeMismatch);
            }
        }
        let shape = BatchedCpStatementShape::new(first_shape, items.len())?;
        Ok(Self { shape, items })
    }

    #[must_use]
    pub fn manifest(&self) -> BatchManifest {
        let body = encode_manifest_body(&self.shape, &self.items);
        let digest = digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-manifest",
            &body,
        );
        BatchManifest { digest, body }
    }

    #[must_use]
    pub fn round_message_commitments(&self) -> BatchRoundMessageCommitments {
        let commitments = (0..self.shape.accumulator_shape.num_rounds)
            .map(|round| {
                let body = encode_round_message_body(&self.shape, &self.items, round);
                digest_domain_with_scheme(
                    self.shape.accumulator_shape.digest_scheme,
                    b"batched-cp-round-message",
                    &body,
                )
            })
            .collect();
        BatchRoundMessageCommitments { commitments }
    }

    #[must_use]
    pub fn public_statement(&self) -> BatchedCpPublicStatement {
        let manifest = self.manifest();
        let round_commitments = self.round_message_commitments();
        let challenge_digest =
            derive_batch_challenge_digest(&self.shape, manifest.digest, &round_commitments);
        let folded_output_accumulator_root = digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-folded-output-accumulator-root",
            &encode_folded_output_accumulator_body(&self.items),
        );
        BatchedCpPublicStatement {
            shape: self.shape.clone(),
            manifest_digest: manifest.digest,
            round_message_commitments: round_commitments.commitments,
            batch_challenge_digest: challenge_digest,
            folded_output_accumulator_root,
            whir_parameter_digest: self.shape.accumulator_shape.whir_parameter_digest,
        }
    }

    #[must_use]
    pub fn symbt3_public_statement_for_relation(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> BatchedCpSymbt3PublicStatement {
        let witness = self.witness_bundle();
        let message_oracle_roots: Vec<Digest32> = witness
            .round_message_oracles
            .iter()
            .enumerate()
            .map(|(round, rows)| {
                symbt3_message_oracle_root(
                    self.shape.accumulator_shape.digest_scheme,
                    &self.shape,
                    round,
                    rows,
                )
            })
            .collect();
        let folded_output_accumulator_root = digest_domain_with_scheme(
            self.shape.accumulator_shape.digest_scheme,
            b"batched-cp-folded-output-accumulator-root",
            &encode_folded_output_accumulator_body(&self.items),
        );
        let input_public_values = self
            .items
            .iter()
            .map(|item| flatten_symbt3_public_inputs(&item.public.public_inputs))
            .collect::<Vec<_>>();
        let input_commitment_values = self
            .items
            .iter()
            .map(|item| flatten_symbt3_commitment(&item.public.instance.x_folded.commitment))
            .collect::<Vec<_>>();
        let input_evaluation_values = self
            .items
            .iter()
            .map(|item| {
                flatten_symbt3_evaluations(&item.public.instance.x_folded.evaluation_values)
            })
            .collect::<Vec<_>>();
        let input_accumulator_values = input_public_values
            .iter()
            .zip(input_commitment_values.iter())
            .zip(input_evaluation_values.iter())
            .map(|((public, commitment), evaluation)| {
                let mut out = Vec::with_capacity(relation.symbt3_accumulator_coordinate_len());
                out.extend_from_slice(public);
                out.extend_from_slice(commitment);
                out.extend_from_slice(evaluation);
                out
            })
            .collect::<Vec<_>>();
        let source_ajtai_opening_values = self
            .items
            .iter()
            .map(flatten_symbt3_full_ajtai_opening)
            .collect::<Vec<_>>();
        let source_r1cs_assignment_values = self
            .items
            .iter()
            .flat_map(|item| {
                (0..relation.shape.accumulator_shape.local_public_input_count).map(
                    move |original_index| {
                        flatten_symbt3_source_r1cs_assignment(item, original_index, relation)
                    },
                )
            })
            .collect::<Vec<_>>();
        let source_assignment_roots = source_r1cs_assignment_values
            .iter()
            .map(|row| {
                symbt3_source_assignment_root(
                    self.shape.accumulator_shape.digest_scheme,
                    relation,
                    row,
                )
            })
            .collect::<Vec<_>>();
        let source_ajtai_opening_roots = source_ajtai_opening_values
            .iter()
            .map(|row| {
                symbt3_ajtai_opening_root(
                    self.shape.accumulator_shape.digest_scheme,
                    &relation.ring_module_layout,
                    row,
                )
            })
            .collect::<Vec<_>>();
        let input_public_boundary_digest = symbt3_input_public_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            &input_public_values,
            &input_commitment_values,
            &input_evaluation_values,
            &input_accumulator_values,
        );
        let source_ajtai_commitment_boundary_digest =
            symbt3_source_ajtai_commitment_boundary_digest(
                self.shape.accumulator_shape.digest_scheme,
                &input_commitment_values,
            );
        let source_assignment_boundary_digest = symbt3_source_assignment_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &source_assignment_roots,
        );
        let manifest_rows = symbt3_manifest_rows_from_statement_parts(
            relation,
            &input_public_values,
            &input_commitment_values,
            &input_evaluation_values,
            &input_accumulator_values,
            &source_assignment_roots,
            &message_oracle_roots,
        );
        let manifest_oracle_root = symbt3_manifest_oracle_root_from_rows(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &manifest_rows,
        );
        let batch_manifest_layout_digest = relation
            .batch_manifest_layout
            .digest(self.shape.accumulator_shape.digest_scheme);
        let batch_manifest_root = symbt3_batch_manifest_root_from_oracle_root(
            self.shape.accumulator_shape.digest_scheme,
            ManifestCommitmentPolicy::PublicCanonicalManifestViewV1,
            &batch_manifest_layout_digest,
            &manifest_oracle_root,
        );
        let folded_gr1cs_boundary_digest = symbt3_folded_gr1cs_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &input_evaluation_values,
            &vec![0; relation.symbt3_evaluation_coordinate_len()],
        );
        let old_accumulator_coordinates = vec![0; relation.symbt3_accumulator_coordinate_len()];
        let mut public = BatchedCpSymbt3PublicStatement {
            shape_id: self.shape.shape_id,
            batch_capacity: self.shape.batch_capacity,
            active_count: self.shape.active_count,
            old_accumulator_digest: symbt3_accumulator_coordinates_digest(
                self.shape.accumulator_shape.digest_scheme,
                b"old",
                &old_accumulator_coordinates,
            ),
            new_accumulator_digest: [0u8; 32],
            old_accumulator_coordinates,
            new_accumulator_coordinates: vec![0; relation.symbt3_accumulator_coordinate_len()],
            input_public_boundary_digest,
            batch_manifest_root,
            manifest_oracle_root,
            manifest_eval_claim: 0,
            batch_manifest_layout_digest,
            source_column_layout_digest: relation
                .batch_manifest_layout
                .source_column_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            message_semantic_layout_digest: relation
                .message_semantic_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            production_norm_range_layout_digest: relation
                .ajtai_norm_range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            structured_projection_layout_digest: relation
                .ajtai_norm_range_layout
                .projection_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            monomial_embedding_layout_digest: relation
                .ajtai_norm_range_layout
                .monomial_embedding_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            representative_layout_digest: relation
                .ajtai_norm_range_layout
                .representative_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            norm_range_public_digest: [0u8; 32],
            input_public_values,
            input_commitment_values,
            input_evaluation_values,
            input_accumulator_values,
            source_assignment_roots,
            source_assignment_boundary_digest,
            source_ajtai_opening_roots,
            source_ajtai_commitment_boundary_digest,
            message_oracle_roots,
            folded_public_input: vec![0; relation.symbt3_public_input_coordinate_len()],
            folded_commitment: vec![0; relation.symbt3_commitment_coordinate_len()],
            folded_evaluation: vec![0; relation.symbt3_evaluation_coordinate_len()],
            folded_accumulator_coordinates: vec![0; relation.symbt3_accumulator_coordinate_len()],
            folded_ajtai_opening_root: [0u8; 32],
            folded_ajtai_commitment: vec![0; relation.symbt3_commitment_coordinate_len()],
            folded_gr1cs_boundary_digest,
            ring_module_layout_digest: relation
                .ring_module_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            ajtai_commit_layout_digest: relation
                .ajtai_commit_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            r1cs_evaluator_layout_digest: relation
                .r1cs_evaluator_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            gr1cs_residual_layout_digest: relation
                .gr1cs_residual_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            algebra_law_digest: relation
                .algebra_law
                .digest(self.shape.accumulator_shape.digest_scheme),
            ajtai_linear_algebra_layout_digest: relation
                .ajtai_linear_algebra_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            ajtai_norm_range_layout_digest: relation
                .ajtai_norm_range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            projection_layout_digest: relation
                .ajtai_norm_range_layout
                .projection_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            range_layout_digest: relation
                .ajtai_norm_range_layout
                .range_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            folded_gr1cs_product_residual_layout_digest: relation
                .folded_gr1cs_product_residual_layout
                .digest(self.shape.accumulator_shape.digest_scheme),
            folded_output_accumulator_root,
            whir_parameter_digest: self.shape.accumulator_shape.whir_parameter_digest,
        };
        public.folded_public_input = relation.derive_folded_public_input_boundary(&public);
        public.folded_commitment = relation.derive_ring_folded_commitment_boundary(&public);
        public.folded_evaluation = relation.derive_folded_evaluation_boundary(&public);
        public.folded_accumulator_coordinates =
            relation.derive_folded_accumulator_boundary(&public);
        public.new_accumulator_coordinates =
            symbt3_accumulator_transition_coordinates(relation, &public)
                .expect("well-formed SYMBT3 accumulator transition");
        public.new_accumulator_digest = symbt3_accumulator_coordinates_digest(
            self.shape.accumulator_shape.digest_scheme,
            b"new",
            &public.new_accumulator_coordinates,
        );
        public.folded_gr1cs_boundary_digest = symbt3_folded_gr1cs_boundary_digest(
            self.shape.accumulator_shape.digest_scheme,
            relation,
            &public.input_evaluation_values,
            &public.folded_evaluation,
        );
        let folded_opening =
            relation.derive_ring_folded_opening_boundary(&public, &source_ajtai_opening_values);
        public.folded_ajtai_opening_root = symbt3_ajtai_opening_root(
            self.shape.accumulator_shape.digest_scheme,
            &relation.ring_module_layout,
            &folded_opening,
        );
        public.norm_range_public_digest = symbt3_norm_range_public_digest(
            self.shape.accumulator_shape.digest_scheme,
            &public.folded_ajtai_opening_root,
            &public.production_norm_range_layout_digest,
            &public.structured_projection_layout_digest,
            &public.monomial_embedding_layout_digest,
            &public.representative_layout_digest,
        );
        public.folded_ajtai_commitment = public.folded_commitment.clone();
        public.manifest_eval_claim = 0;
        public
    }

    #[must_use]
    pub fn symbt3_witness_for_relation(
        &self,
        relation: &BatchedCpSymbt3RelationDescription,
    ) -> BatchedCpSymbt3Witness {
        let mut witness = BatchedCpSymbt3Witness::from_batched_witness(&self.witness_bundle());
        witness.source_ajtai_opening_values = self
            .items
            .iter()
            .map(flatten_symbt3_full_ajtai_opening)
            .collect::<Vec<_>>();
        witness.source_r1cs_assignment_values = self
            .items
            .iter()
            .flat_map(|item| {
                (0..relation.shape.accumulator_shape.local_public_input_count).map(
                    move |original_index| {
                        flatten_symbt3_source_r1cs_assignment(item, original_index, relation)
                    },
                )
            })
            .collect::<Vec<_>>();
        let public = self.symbt3_public_statement_for_relation(relation);
        witness.folded_ajtai_opening_values = relation
            .derive_ring_folded_opening_boundary(&public, &witness.source_ajtai_opening_values);
        witness
    }

    #[must_use]
    pub fn witness_bundle(&self) -> BatchedCpWitnessBundle {
        let witness_oracle_rows = (0..self.shape.batch_capacity)
            .map(|idx| {
                self.items
                    .get(idx)
                    .map(encode_witness_row)
                    .unwrap_or_default()
            })
            .collect();
        let round_message_oracles = (0..self.shape.accumulator_shape.num_rounds)
            .map(|round| {
                (0..self.shape.batch_capacity)
                    .map(|idx| {
                        self.items
                            .get(idx)
                            .map(|item| item.witness.fs_messages[round].clone())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .collect();
        BatchedCpWitnessBundle {
            items: self.items.clone(),
            witness_oracle_rows,
            round_message_oracles,
        }
    }
}

