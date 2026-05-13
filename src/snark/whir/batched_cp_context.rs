fn typed_batched_cp_oracle_num_vars(shape: &crate::batched_cp::BatchedCpStatementShape) -> usize {
    let field_len = shape
        .canonical_product_oracle_byte_len()
        .div_ceil(field::BYTES_PER_ELEMENT)
        + 1;
    field_len.next_power_of_two().max(2).trailing_zeros() as usize
}

enum WhirBatchedCpRelationContext {
    ProductOracle(crate::batched_cp::BatchedCpStructuredRelationDescription),
    Semantic(crate::batched_cp::BatchedCpSemanticRelationDescription),
    SemanticV2(crate::batched_cp::BatchedCpSemanticRelationV2Description),
    ColumnarV2(crate::batched_cp::BatchedCpSemanticColumnarV2Description),
    FamilyColumnarV2(crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description),
}

impl WhirBatchedCpRelationContext {
    fn from_context_bytes(bytes: &[u8]) -> Option<Self> {
        if let Ok(family_columnar_v2) =
            crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description::from_context_bytes(
                bytes,
            )
        {
            return Some(Self::FamilyColumnarV2(family_columnar_v2));
        }
        if let Ok(columnar_v2) =
            crate::batched_cp::BatchedCpSemanticColumnarV2Description::from_context_bytes(bytes)
        {
            return Some(Self::ColumnarV2(columnar_v2));
        }
        if let Ok(semantic_v2) =
            crate::batched_cp::BatchedCpSemanticRelationV2Description::from_context_bytes(bytes)
        {
            return Some(Self::SemanticV2(semantic_v2));
        }
        if let Ok(semantic) =
            crate::batched_cp::BatchedCpSemanticRelationDescription::from_context_bytes(bytes)
        {
            return Some(Self::Semantic(semantic));
        }
        crate::batched_cp::BatchedCpStructuredRelationDescription::from_context_bytes(bytes)
            .ok()
            .map(Self::ProductOracle)
    }

    fn shape(&self) -> &crate::batched_cp::BatchedCpStatementShape {
        match self {
            Self::ProductOracle(relation) => &relation.shape,
            Self::Semantic(relation) => &relation.shape,
            Self::SemanticV2(relation) => &relation.semantic.shape,
            Self::ColumnarV2(relation) => &relation.semantic.shape,
            Self::FamilyColumnarV2(relation) => &relation.semantic.shape,
        }
    }

    fn public_statement_bytes(&self) -> usize {
        match self {
            Self::ProductOracle(relation) => relation.public_statement_bytes,
            Self::Semantic(relation) => relation.public_statement_bytes(),
            Self::SemanticV2(relation) => relation.public_statement_bytes(),
            Self::ColumnarV2(relation) => relation.public_statement_bytes(),
            Self::FamilyColumnarV2(relation) => relation.public_statement_bytes(),
        }
    }

    fn relation_id(&self) -> crate::digest_core::Digest32 {
        match self {
            Self::ProductOracle(relation) => relation.relation_id(),
            Self::Semantic(relation) => relation.semantic_relation_id(),
            Self::SemanticV2(relation) => relation.semantic_relation_id(),
            Self::ColumnarV2(relation) => relation.semantic_relation_id(),
            Self::FamilyColumnarV2(relation) => relation.semantic_relation_id(),
        }
    }

    fn enforces_full_semantic_blocks(&self) -> bool {
        matches!(self, Self::SemanticV2(_))
    }

    fn columnar_v2(&self) -> Option<&crate::batched_cp::BatchedCpSemanticColumnarV2Description> {
        match self {
            Self::ColumnarV2(relation) => Some(relation),
            Self::ProductOracle(_)
            | Self::Semantic(_)
            | Self::SemanticV2(_)
            | Self::FamilyColumnarV2(_) => None,
        }
    }

    fn family_columnar_v2(
        &self,
    ) -> Option<&crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description> {
        match self {
            Self::FamilyColumnarV2(relation) => Some(relation),
            Self::ProductOracle(_)
            | Self::Semantic(_)
            | Self::SemanticV2(_)
            | Self::ColumnarV2(_) => None,
        }
    }

    fn semantic_constraint_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<crate::batched_cp::BatchedCpSemanticConstraintBlock> {
        match self {
            Self::ProductOracle(_) => Vec::new(),
            Self::Semantic(relation) => {
                relation.supported_constraint_blocks_for_statement(Some(statement))
            }
            Self::SemanticV2(relation) => {
                relation.supported_constraint_blocks_for_statement(Some(statement))
            }
            Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
        }
    }

    fn byte_equality_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpByteEqualityBlock> {
        match self {
            Self::ProductOracle(relation) => vec![WhirBatchedCpByteEqualityBlock {
                family: crate::batched_cp::BatchedCpSemanticConstraintFamily::RoundMessageBinding,
                label: "legacy-product-oracle-round-message-binding",
                equalities: relation.shape.structured_oracle_byte_equalities(),
            }],
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let equalities: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| {
                            match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(
                                equality,
                            ) => Some(equality),
                            crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(_) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                _,
                            ) => None,
                        }
                        })
                        .collect();
                    (!equalities.is_empty()).then_some(WhirBatchedCpByteEqualityBlock {
                        family: block.family,
                        label: block.label,
                        equalities,
                    })
                })
                .collect(),
            Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
        }
    }

    fn packed_value_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpPackedValueBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let values: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| {
                            match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(value) => {
                                Some(value)
                            }
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(_) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                _,
                            ) => None,
                            crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                _,
                            ) => None,
                        }
                        })
                        .collect();
                    (!values.is_empty()).then_some(WhirBatchedCpPackedValueBlock { values })
                })
                .collect(),
        }
    }

    fn folded_public_input_linear_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpFoldedPublicInputLinearBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let constraints: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| {
                            match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                constraint,
                            ) => Some(constraint),
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                _,
                            ) => None,
                        }
                        })
                        .collect();
                    (!constraints.is_empty()).then_some(WhirBatchedCpFoldedPublicInputLinearBlock {
                        family: block.family,
                        label: block.label,
                        constraints,
                    })
                })
                .collect(),
        }
    }

    fn folded_commitment_ring_mul_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpFoldedCommitmentRingMulBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let constraints: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                constraint,
                            ) => Some(constraint),
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                _,
                            ) => None,
                        })
                        .collect();
                    (!constraints.is_empty()).then_some(
                        WhirBatchedCpFoldedCommitmentRingMulBlock {
                            family: block.family,
                            label: block.label,
                            constraints,
                        },
                    )
                })
                .collect(),
        }
    }

    fn folded_evaluation_ring_mul_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpFoldedEvaluationRingMulBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let constraints: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                constraint,
                            ) => Some(constraint),
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                _,
                            ) => None,
                        })
                        .collect();
                    (!constraints.is_empty()).then_some(
                        WhirBatchedCpFoldedEvaluationRingMulBlock {
                            family: block.family,
                            label: block.label,
                            constraints,
                        },
                    )
                })
                .collect(),
        }
    }

    fn poseidon_r1cs_blocks(
        &self,
        _statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpPoseidonR1csBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(relation) => {
                if !relation.constraint_families.contains(
                    &crate::batched_cp::BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                ) {
                    return Vec::new();
                }
                let surfaces = relation.shape.poseidon_fs_commitment_r1cs_surfaces();
                (!surfaces.is_empty())
                    .then_some(WhirBatchedCpPoseidonR1csBlock {
                        family: crate::batched_cp::BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                        label: "fs-commitment-full-poseidon-r1cs-row-domain",
                        surfaces,
                    })
                    .into_iter()
                    .collect()
            }
            Self::SemanticV2(relation) => {
                if !relation.semantic.constraint_families.contains(
                    &crate::batched_cp::BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                ) {
                    return Vec::new();
                }
                let surfaces = relation
                    .semantic
                    .shape
                    .poseidon_fs_commitment_r1cs_surfaces();
                (!surfaces.is_empty())
                    .then_some(WhirBatchedCpPoseidonR1csBlock {
                        family: crate::batched_cp::BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness,
                        label: "fs-commitment-full-poseidon-r1cs-row-domain-v2",
                        surfaces,
                    })
                    .into_iter()
                    .collect()
            }
        }
    }

    fn ajtai_opening_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpAjtaiOpeningBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let constraints: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                constraint,
                            ) => Some(constraint),
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                _,
                            ) => None,
                        })
                        .collect();
                    (!constraints.is_empty()).then_some(WhirBatchedCpAjtaiOpeningBlock {
                        family: block.family,
                        label: block.label,
                        constraints,
                    })
                })
                .collect(),
        }
    }

    fn original_r1cs_blocks(
        &self,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
    ) -> Vec<WhirBatchedCpOriginalR1csBlock> {
        match self {
            Self::ProductOracle(_) | Self::ColumnarV2(_) | Self::FamilyColumnarV2(_) => Vec::new(),
            Self::Semantic(_) | Self::SemanticV2(_) => self
                .semantic_constraint_blocks(statement)
                .into_iter()
                .filter_map(|block| {
                    let constraints: Vec<_> = block
                        .constraints
                        .into_iter()
                        .filter_map(|constraint| match constraint {
                            crate::batched_cp::BatchedCpSemanticConstraint::OriginalR1cs(
                                constraint,
                            ) => Some(constraint),
                            crate::batched_cp::BatchedCpSemanticConstraint::ByteEquality(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::PackedValue(_)
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedPublicInputLinear(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedCommitmentRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::FoldedEvaluationRingMul(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::PoseidonR1csRow(
                                _,
                            )
                            | crate::batched_cp::BatchedCpSemanticConstraint::AjtaiOpeningLinear(
                                _,
                            ) => None,
                        })
                        .collect();
                    (!constraints.is_empty()).then_some(WhirBatchedCpOriginalR1csBlock {
                        family: block.family,
                        label: block.label,
                        constraints,
                    })
                })
                .collect(),
        }
    }
}

