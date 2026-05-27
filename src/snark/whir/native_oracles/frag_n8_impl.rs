impl Symbt3N8IntegratedConstraintKind {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_N8_INTEGRATED_CONSTRAINT_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorMainV1 => 1,
            Self::NativeTupleLeafRepeatedRlcV1 => 2,
            Self::AccumulatorTransitionBindingV1 => 3,
        });
        out
    }
}

impl Symbt3N8IntegratedConstraintDescriptor {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_N8_INTEGRATED_CONSTRAINT_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.num_vars as u64);
        push_u64(&mut out, self.oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl IntegratedK6aNativeK6aPaddingModeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_K6A_PADDING_MODE_V1");
        out.push(match self {
            Self::NoPadding => 1,
            Self::ZeroExtendRowsToIntegratedNumVars => 2,
        });
        out
    }
}

impl IntegratedK6aNativeK6aPaddingPolicyV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_K6A_PADDING_POLICY_V1");
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_u64(&mut out, self.source_num_vars as u64);
        push_u64(&mut out, self.target_num_vars as u64);
        push_u64(&mut out, self.source_oracle_len as u64);
        push_u64(&mut out, self.target_oracle_len as u64);
        push_u64(&mut out, self.added_num_vars as u64);
        push_u64(&mut out, self.padded_row_count as u64);
        out
    }
}

impl IntegratedK6aNativeTupleRepetitionAxisPlacementV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_TUPLE_REPETITION_AXIS_PLACEMENT_V1",
        );
        out.push(match self {
            Self::AppendedAfterLogicalAxes => 1,
        });
        out
    }
}

impl IntegratedK6aNativeTupleRepetitionAxisMappingV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_TUPLE_REPETITION_AXIS_MAPPING_V1",
        );
        push_bytes(&mut out, &self.placement.canonical_bytes());
        push_u64(&mut out, self.logical_num_vars as u64);
        push_u64(&mut out, self.repetition_axis_start as u64);
        push_u64(&mut out, self.repetition_axis_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.packed_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_padding_num_vars as u64);
        out
    }
}

impl IntegratedK6aNativeLogicalOracleKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_LOGICAL_ORACLE_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorMainV1 => 1,
            Self::NativeTupleLeafPackedV1 => 2,
            Self::NativeTupleLeafLogicalV1 => 3,
        });
        out
    }
}

impl IntegratedK6aNativeLogicalOracleDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_LOGICAL_ORACLE_DESCRIPTOR_V1",
        );
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_optional_u32(&mut out, self.oracle_id);
        push_optional_role(&mut out, self.role.as_ref());
        push_digest(&mut out, &self.layout_digest);
        push_optional_digest(&mut out, self.root_digest.as_ref());
        push_u64(&mut out, self.source_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl IntegratedK6aNativeClaimDescriptorKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_CLAIM_DESCRIPTOR_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorMainClaimsV1 => 1,
            Self::NativeTupleLeafPackedClaimsV1 => 2,
            Self::NativeTupleLeafLogicalClaimsV1 => 3,
        });
        out
    }
}

impl IntegratedK6aNativeClaimDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_CLAIM_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.claim_count as u64);
        push_u64(&mut out, self.num_vars as u64);
        push_digest(&mut out, &self.claims_digest);
        out
    }
}

impl IntegratedK6aNativeClaimPlanV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_CLAIM_PLAN_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.k6a_relation_id);
        push_digest(&mut out, &self.k6a_public_statement_digest);
        push_digest(&mut out, &self.k6a_semantic_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_u64(&mut out, self.k6a_num_vars as u64);
        push_u64(&mut out, self.k6a_oracle_len as u64);
        push_u64(&mut out, self.tuple_logical_oracle_count as u64);
        push_u64(&mut out, self.tuple_logical_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_bytes(&mut out, &self.k6a_padding_policy.canonical_bytes());
        push_bytes(&mut out, &self.tuple_repetition_axis.canonical_bytes());
        push_u64(&mut out, self.logical_oracle_descriptors.len() as u64);
        for descriptor in &self.logical_oracle_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_u64(&mut out, self.constraint_descriptors.len() as u64);
        for descriptor in &self.constraint_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_u64(&mut out, self.claim_descriptors.len() as u64);
        for descriptor in &self.claim_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_digest(&mut out, &self.combined_logical_oracle_descriptor_digest);
        push_digest(&mut out, &self.combined_constraint_descriptor_digest);
        push_digest(&mut out, &self.combined_claim_descriptor_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.claim_plan_digest);
        out
    }
}

impl N8IntegratedK6aSemanticConstraintRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINT_ROW_KIND_V1",
        );
        out.push(match self {
            Self::VerifierOpeningClaimV1 => 1,
            Self::FinalResidualZeroV1 => 2,
            Self::ZEvalBindingV1 => 3,
            Self::ProductSumcheckAcceptedV1 => 4,
            Self::K6aPaddingZeroV1 => 5,
        });
        out
    }
}

impl N8IntegratedK6aSemanticConstraintRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINT_ROW_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl N8IntegratedK6aSemanticConstraintsV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_K6A_SEMANTIC_CONSTRAINTS_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.complete);
        push_digest(&mut out, &self.k6a_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_u64(&mut out, self.k6a_num_vars as u64);
        push_u64(&mut out, self.k6a_oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.verifier_point_count as u64);
        push_u64(&mut out, self.verifier_claim_count as u64);
        push_u64(&mut out, self.final_residual_count as u64);
        push_u64(&mut out, self.product_sumcheck_round_count as u64);
        push_u64(&mut out, self.padding_row_count as u64);
        push_digest(&mut out, &self.verifier_points_digest);
        push_digest(&mut out, &self.verifier_claims_digest);
        push_digest(&mut out, &self.final_residual_digest);
        push_digest(&mut out, &self.product_sumcheck_digest);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_digest(&mut out, &self.rows_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8IntegratedTupleRlcSemanticConstraintRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINT_ROW_KIND_V1",
        );
        out.push(match self {
            Self::PackedOpeningClaimV1 => 1,
            Self::LogicalOpeningClaimV1 => 2,
            Self::RlcResidualZeroV1 => 3,
            Self::TuplePaddingZeroV1 => 4,
        });
        out
    }
}

impl N8IntegratedTupleRlcSemanticConstraintRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINT_ROW_V1",
        );
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        match self.repetition_index {
            Some(index) => {
                push_bool(&mut out, true);
                push_u64(&mut out, index as u64);
            }
            None => push_bool(&mut out, false),
        }
        push_optional_u32(&mut out, self.oracle_id);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl N8IntegratedTupleRlcSemanticConstraintsV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_TUPLE_RLC_SEMANTIC_CONSTRAINTS_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.complete);
        push_digest(&mut out, &self.proof_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.packed_root);
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.logical_num_vars as u64);
        push_u64(&mut out, self.packed_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_bytes(&mut out, self.tuple_leaf_layout.as_bytes());
        push_bool(&mut out, self.same_domain);
        push_bool(&mut out, self.same_field);
        push_bool(&mut out, self.same_rate);
        push_bool(&mut out, self.same_folding_parameter);
        encode_claim_kind(&mut out, self.claim_kind);
        push_digest(&mut out, &self.packing_challenge_digest);
        push_digest(&mut out, &self.derived_packing_challenge_digest);
        push_digest(&mut out, &self.packed_claims_digest);
        push_digest(&mut out, &self.logical_claims_digest);
        push_digest(&mut out, &self.opening_points_digest);
        push_digest(&mut out, &self.residuals_digest);
        push_u64(&mut out, self.packed_row_count as u64);
        push_u64(&mut out, self.logical_row_count as u64);
        push_u64(&mut out, self.residual_row_count as u64);
        push_u64(&mut out, self.padding_row_count as u64);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_digest(&mut out, &self.rows_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8IntegratedTransitionBindingSemanticConstraintRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_ROW_KIND_V1",
        );
        out.push(match self {
            Self::AccumulatorBoundaryDigestV1 => 1,
            Self::PublicStatementAndK6aProofV1 => 2,
            Self::TupleLeafRootAndLayoutV1 => 3,
            Self::NativeDescriptorAndMessageRootsV1 => 4,
            Self::ManifestSourceBatchRootsV1 => 5,
            Self::BatchShapeV1 => 6,
            Self::WorkloadKindV1 => 7,
            Self::N8PlanTableLayoutV1 => 8,
        });
        out
    }
}

impl N8IntegratedTransitionBindingSemanticConstraintRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_ROW_V1",
        );
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl N8IntegratedTransitionBindingSemanticConstraintsV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"N8_INTEGRATED_TRANSITION_BINDING_SEMANTIC_CONSTRAINTS_V1",
        );
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.complete);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.profile_digest);
        push_digest(&mut out, &self.accumulator_instance_digest);
        push_digest(&mut out, &self.old_accumulator_digest);
        push_digest(&mut out, &self.new_accumulator_digest);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.main_symbt3_relation_id);
        push_digest(&mut out, &self.k6a_proof_digest);
        push_digest(&mut out, &self.tuple_leaf_root);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_packing_challenge_digest);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_message_roots_digest);
        push_digest(&mut out, &self.manifest_oracle_root);
        push_digest(&mut out, &self.source_oracle_root);
        push_digest(&mut out, &self.batch_manifest_root);
        push_u64(&mut out, self.batch_size);
        push_u64(&mut out, self.active_count);
        push_u64(&mut out, self.k6a_num_vars as u64);
        push_u64(&mut out, self.k6a_oracle_len as u64);
        push_u64(&mut out, self.tuple_logical_oracle_count as u64);
        push_u64(&mut out, self.tuple_logical_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_num_vars as u64);
        push_u64(&mut out, self.tuple_packed_oracle_len as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_digest(&mut out, &self.k6a_semantic_descriptor_digest);
        push_digest(&mut out, &self.tuple_rlc_semantic_descriptor_digest);
        push_digest(&mut out, &self.n8_claim_plan_digest);
        push_digest(&mut out, &self.n8_committed_table_layout_digest);
        push_digest(&mut out, &self.n8_committed_table_digest);
        push_digest(&mut out, &self.n8_combined_constraint_descriptor_digest);
        push_digest(&mut out, &self.n8_combined_claim_descriptor_digest);
        push_digest(&mut out, &self.k6a_constraint_descriptor_digest);
        push_digest(&mut out, &self.tuple_constraint_descriptor_digest);
        push_digest(&mut out, &self.transition_constraint_descriptor_digest);
        push_digest(&mut out, &self.transition_binding_digest);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_digest(&mut out, &self.rows_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8IntegratedSemanticCompletionFlagsV1 {
    #[must_use]
    pub const fn none_complete() -> Self {
        Self {
            version: N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION,
            k6a_semantics_complete: false,
            tuple_rlc_semantics_complete: false,
            transition_semantics_complete: false,
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.k6a_semantics_complete);
        push_bool(&mut out, self.tuple_rlc_semantics_complete);
        push_bool(&mut out, self.transition_semantics_complete);
        out
    }

    #[must_use]
    pub const fn all_complete(&self) -> bool {
        self.k6a_semantics_complete
            && self.tuple_rlc_semantics_complete
            && self.transition_semantics_complete
    }
}

impl N8SemanticBatchingFamilyV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_SEMANTIC_BATCHING_FAMILY_V1");
        out.push(match self {
            Self::K6aSemanticRowsV1 => 1,
            Self::TupleRlcSemanticRowsV1 => 2,
            Self::TransitionBindingSemanticRowsV1 => 3,
            Self::K6aSourceRowsV1 => 4,
        });
        out
    }
}

impl N8SemanticBatchingFamilyDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_SEMANTIC_BATCHING_FAMILY_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.family.canonical_bytes());
        push_u64(&mut out, self.source_row_count as u64);
        push_u64(&mut out, self.batched_query_count as u64);
        push_digest(&mut out, &self.row_digest);
        push_digest(&mut out, &self.challenge_point_digest);
        push_u64(&mut out, self.soundness_bits as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8K6aSourceRowBatchingV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_K6A_SOURCE_ROW_BATCHING_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.enabled);
        push_bytes(&mut out, &self.descriptor.canonical_bytes());
        push_u64(&mut out, self.unbatched_source_opening_count as u64);
        push_u64(&mut out, self.batched_source_opening_count as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl N8SemanticBatchingV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_SEMANTIC_BATCHING_V1");
        push_u64(&mut out, self.version);
        push_bool(&mut out, self.enabled);
        push_digest(&mut out, &self.descriptor_binding_digest);
        push_bytes(&mut out, &self.k6a_source.canonical_bytes());
        push_bytes(&mut out, &self.k6a.canonical_bytes());
        push_bytes(&mut out, &self.tuple_rlc.canonical_bytes());
        push_bytes(&mut out, &self.transition_binding.canonical_bytes());
        push_u64(&mut out, self.unbatched_semantic_opening_count as u64);
        push_u64(&mut out, self.batched_semantic_opening_count as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl IntegratedK6aNativeCommittedTableRowOwnerV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_ROW_OWNER_V1",
        );
        out.push(match self {
            Self::K6aAccumulatorMainRows => 1,
            Self::K6aZeroPaddingRows => 2,
            Self::NativeTupleLeafRepeatedRlcRows => 3,
            Self::NativeTupleLeafIntegratedPaddingRows => 4,
        });
        out
    }
}

impl IntegratedK6aNativeCommittedTableRowRangeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_ROW_RANGE_V1",
        );
        push_bytes(&mut out, &self.owner.canonical_bytes());
        push_u64(&mut out, self.integrated_start as u64);
        push_u64(&mut out, self.row_count as u64);
        push_u64(&mut out, self.source_start as u64);
        push_u64(&mut out, self.source_row_count as u64);
        out
    }
}

impl IntegratedK6aNativeCommittedTableAxisOwnerV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_AXIS_OWNER_V1",
        );
        out.push(match self {
            Self::K6aSourceAxes => 1,
            Self::K6aPaddingAxes => 2,
            Self::TupleLeafLogicalAxes => 3,
            Self::TupleLeafRepetitionAxes => 4,
            Self::TupleLeafIntegratedPaddingAxes => 5,
        });
        out
    }
}

impl IntegratedK6aNativeCommittedTableAxisRangeV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_AXIS_RANGE_V1",
        );
        push_bytes(&mut out, &self.owner.canonical_bytes());
        push_u64(&mut out, self.axis_start as u64);
        push_u64(&mut out, self.axis_len as u64);
        out
    }
}

impl IntegratedK6aNativeCommittedTableCountersV1 {
    #[must_use]
    pub fn canonical_bytes_without_digests(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_COUNTERS_V1",
        );
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.k6a_padded_rows as u64);
        push_u64(&mut out, self.tuple_rows as u64);
        push_u64(&mut out, self.combined_constraint_count as u64);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digests();
        push_digest(&mut out, &self.table_digest);
        push_digest(&mut out, &self.layout_digest);
        out
    }
}

impl IntegratedK6aNativeCommittedTableV1 {
    #[must_use]
    pub fn canonical_layout_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_LAYOUT_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.plan_digest);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_bytes(&mut out, &self.k6a_padding_policy.canonical_bytes());
        push_bytes(&mut out, &self.tuple_repetition_axis.canonical_bytes());
        push_u64(&mut out, self.row_ownership.len() as u64);
        for range in &self.row_ownership {
            push_bytes(&mut out, &range.canonical_bytes());
        }
        push_u64(&mut out, self.axis_ownership.len() as u64);
        for range in &self.axis_ownership {
            push_bytes(&mut out, &range.canonical_bytes());
        }
        push_u64(&mut out, self.logical_integrated_oracle_count as u64);
        push_bool(&mut out, self.one_oracle_per_batch_item_layout);
        push_u64(&mut out, self.introduced_whir_root_count as u64);
        push_u64(&mut out, self.introduced_whir_proof_count as u64);
        out
    }

    #[must_use]
    pub fn canonical_table_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"INTEGRATED_K6A_NATIVE_COMMITTED_TABLE_V1");
        push_bytes(&mut out, &self.canonical_layout_bytes_without_digest());
        push_digest(&mut out, &self.layout_digest);
        push_bytes(&mut out, &self.counters.canonical_bytes_without_digests());
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_table_bytes_without_digest();
        push_digest(&mut out, &self.table_digest);
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorRowKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_ROW_KIND_V1",
        );
        out.push(match self {
            Self::K6aAccumulatorOpeningClaimV1 => 1,
            Self::K6aAccumulatorResidualClaimV1 => 2,
            Self::K6aAccumulatorZEvalClaimV1 => 3,
            Self::K6aProductSumcheckRoundClaimV1 => 4,
            Self::K6aZeroPaddingClaimV1 => 5,
            Self::K6aSemanticVerifierOpeningClaimV1 => 6,
            Self::K6aSemanticFinalResidualZeroV1 => 7,
            Self::K6aSemanticZEvalBindingV1 => 8,
            Self::K6aSemanticProductSumcheckAcceptedV1 => 9,
            Self::K6aSemanticPaddingZeroV1 => 10,
            Self::NativeTupleLeafPackedRlcClaimV1 => 11,
            Self::NativeTupleLeafLogicalRlcClaimV1 => 12,
            Self::NativeTupleLeafRlcBindingResidualV1 => 13,
            Self::NativeTupleLeafIntegratedPaddingClaimV1 => 14,
            Self::AccumulatorTransitionBindingClaimV1 => 15,
        });
        out
    }
}

impl RealIntegratedK6aNativeLogicalColumnV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"REAL_INTEGRATED_K6A_NATIVE_LOGICAL_COLUMN_V1");
        out.push(match self {
            Self::K6aAccumulatorMain => 1,
            Self::NativeTupleLeafPacked => 2,
            Self::NativeTupleLeafLogical => 3,
            Self::AccumulatorTransitionBinding => 4,
        });
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorRowV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_ROW_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_bytes(&mut out, &self.logical_column.canonical_bytes());
        push_u64(&mut out, self.source_index as u64);
        push_u64(&mut out, self.integrated_row as u64);
        match self.repetition_index {
            Some(index) => {
                push_bool(&mut out, true);
                push_u64(&mut out, index as u64);
            }
            None => push_bool(&mut out, false),
        }
        push_optional_u32(&mut out, self.oracle_id);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_digest(&mut out, &self.aux_digest);
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorCountersV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_COUNTERS_V1",
        );
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.k6a_claim_rows as u64);
        push_u64(&mut out, self.k6a_semantic_rows as u64);
        push_u64(&mut out, self.tuple_claim_rows as u64);
        push_u64(&mut out, self.padding_rows as u64);
        push_u64(&mut out, self.transition_binding_rows as u64);
        out
    }
}

impl RealIntegratedK6aNativeEvaluatorV1 {
    #[must_use]
    pub fn canonical_bytes_without_digests(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"REAL_INTEGRATED_K6A_NATIVE_EVALUATOR_V1");
        push_u64(&mut out, self.version);
        push_digest(&mut out, &self.plan_digest);
        push_digest(&mut out, &self.committed_table_layout_digest);
        push_digest(&mut out, &self.committed_table_digest);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.rows.len() as u64);
        for row in &self.rows {
            push_bytes(&mut out, &row.canonical_bytes());
        }
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digests();
        push_digest(&mut out, &self.rows_digest);
        push_digest(&mut out, &self.table_digest);
        push_digest(&mut out, &self.evaluator_digest);
        out
    }
}

impl Symbt3IntegratedK6aNativeWhirRelationV1 {
    #[must_use]
    pub fn canonical_bytes_without_transcript_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_V1",
        );
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_digest(&mut out, &self.main_symbt3_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_bool(&mut out, self.same_field);
        push_bool(&mut out, self.same_rate);
        push_bool(&mut out, self.same_folding_parameter);
        push_bytes(&mut out, &self.claim_plan.canonical_bytes());
        push_bytes(&mut out, &self.committed_table.canonical_bytes());
        push_bytes(&mut out, &self.k6a_semantic_constraints.canonical_bytes());
        push_bytes(
            &mut out,
            &self.tuple_rlc_semantic_constraints.canonical_bytes(),
        );
        push_bytes(
            &mut out,
            &self
                .transition_binding_semantic_constraints
                .canonical_bytes(),
        );
        push_bytes(&mut out, &self.semantic_completion.canonical_bytes());
        push_bytes(&mut out, &self.real_evaluator.canonical_bytes());
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_transcript_digest();
        push_digest(&mut out, &self.transcript_binding_digest);
        out
    }
}

impl N8IntegratedWhirTableRepresentationV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_TABLE_REPRESENTATION_V1");
        out.push(match self {
            Self::SameDomainMultipleLogicalColumns => 1,
            Self::ScalarOracleSelectorGatedRegions => 2,
        });
        out
    }
}

impl N8IntegratedWhirClaimBridgeKindV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_CLAIM_BRIDGE_KIND_V1");
        out.push(match self {
            Self::K6aAccumulatorConstraintsV1 => 1,
            Self::NativeTupleLeafRepeatedRlcConstraintsV1 => 2,
            Self::AccumulatorTransitionBindingConstraintsV1 => 3,
        });
        out
    }
}

impl N8IntegratedWhirClaimBridgeDescriptorV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_CLAIM_BRIDGE_DESCRIPTOR_V1");
        push_bytes(&mut out, &self.kind.canonical_bytes());
        push_u64(&mut out, self.claim_count as u64);
        push_u64(&mut out, self.source_num_vars as u64);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_digest(&mut out, &self.source_constraint_digest);
        push_digest(&mut out, &self.source_claim_digest);
        push_digest(&mut out, &self.table_layout_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl<'a> N8IntegratedWhirProofInputs<'a> {
    #[must_use]
    pub const fn from_descriptor(descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1) -> Self {
        Self {
            version: N8_INTEGRATED_WHIR_PROOF_INPUTS_VERSION,
            descriptor,
            table_representation:
                N8IntegratedWhirTableRepresentationV1::SameDomainMultipleLogicalColumns,
            integrated_whir_root: None,
            integrated_whir_proof: None,
            extra_whir_root_count: 0,
            extra_whir_proof_count: 0,
            legacy_k6a_proof: None,
            legacy_tuple_leaf_proof: None,
        }
    }
}

impl N8IntegratedWhirProofPlan {
    #[must_use]
    pub fn canonical_bytes_without_transcript_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_PROOF_PLAN_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.workload_kind.canonical_bytes());
        push_bytes(&mut out, &self.table_representation.canonical_bytes());
        push_digest(&mut out, &self.descriptor_transcript_digest);
        push_digest(&mut out, &self.claim_plan_digest);
        push_digest(&mut out, &self.committed_table_layout_digest);
        push_digest(&mut out, &self.committed_table_digest);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_u64(&mut out, self.integrated_oracle_len as u64);
        push_u64(&mut out, self.integrated_whir_root_count as u64);
        push_u64(&mut out, self.integrated_whir_proof_count as u64);
        push_bool(&mut out, self.delegated_split_proof_material_present);
        push_bytes(&mut out, &self.semantic_batching.canonical_bytes());
        push_u64(&mut out, self.bridge_claim_descriptors.len() as u64);
        for descriptor in &self.bridge_claim_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_digest(&mut out, &self.combined_bridge_claim_descriptor_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_transcript_digest();
        push_digest(&mut out, &self.transcript_digest);
        out
    }
}

impl N8IntegratedWhirQueryClaimV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_QUERY_CLAIM_V1");
        push_bytes(&mut out, &self.bridge_kind.canonical_bytes());
        push_babybear_vec(&mut out, &self.point);
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        out
    }
}

impl N8IntegratedWhirQueryScheduleV1 {
    #[must_use]
    pub fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_QUERY_SCHEDULE_V1");
        push_u64(&mut out, self.version);
        push_u64(&mut out, self.integrated_num_vars as u64);
        push_digest(&mut out, &self.transcript_digest);
        push_digest(&mut out, &self.combined_bridge_claim_descriptor_digest);
        push_u64(&mut out, self.query_claims.len() as u64);
        for claim in &self.query_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_digest(&mut out, &self.query_claims_digest);
        out
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes_without_digest();
        push_digest(&mut out, &self.query_schedule_digest);
        out
    }
}

impl<'a> N8IntegratedWhirVerifierInput<'a> {
    #[must_use]
    pub fn from_descriptor_and_plan(
        descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1,
        proof_plan: &'a N8IntegratedWhirProofPlan,
        integrated_whir_root: Option<Digest32>,
        integrated_whir_proof: Option<&'a WhirProof>,
        query_schedule: Option<&'a N8IntegratedWhirQueryScheduleV1>,
    ) -> Self {
        Self {
            version: N8_INTEGRATED_WHIR_VERIFIER_INPUT_VERSION,
            prover_mode: N8IntegratedWhirProverModeV1::RealIntegratedK6aNativeEvaluatorV1,
            descriptor,
            proof_plan,
            claim_plan: &descriptor.claim_plan,
            committed_table_layout_digest: descriptor.committed_table.layout_digest,
            committed_table_digest: descriptor.committed_table.table_digest,
            combined_claim_descriptors: &proof_plan.bridge_claim_descriptors,
            combined_claim_descriptor_digest: proof_plan.combined_bridge_claim_descriptor_digest,
            integrated_whir_root,
            integrated_whir_proof,
            query_schedule,
            whir_instance_count: usize::from(integrated_whir_proof.is_some()),
            root_count: usize::from(integrated_whir_root.is_some()),
            extra_whir_root_count: 0,
            extra_whir_proof_count: 0,
            legacy_k6a_proof: None,
            legacy_tuple_leaf_proof: None,
        }
    }
}

impl N8IntegratedWhirProverModeV1 {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_PROVER_MODE_V1");
        out.push(match self {
            Self::SyntheticNonAuthoritativeV1 => 1,
            Self::RealIntegratedK6aNativeEvaluatorV1 => 2,
        });
        out
    }
}

impl N8IntegratedWhirProverOutput {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_PROVER_OUTPUT_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_bytes(&mut out, &self.proof_plan.canonical_bytes());
        push_digest(&mut out, &self.integrated_whir_root);
        push_bytes(
            &mut out,
            &canonical_whir_proof_bytes(&self.integrated_whir_proof),
        );
        push_bytes(&mut out, &self.query_schedule.canonical_bytes());
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn verifier_input<'a>(
        &'a self,
        descriptor: &'a Symbt3IntegratedK6aNativeWhirRelationV1,
    ) -> N8IntegratedWhirVerifierInput<'a> {
        let mut input = N8IntegratedWhirVerifierInput::from_descriptor_and_plan(
            descriptor,
            &self.proof_plan,
            Some(self.integrated_whir_root),
            Some(&self.integrated_whir_proof),
            Some(&self.query_schedule),
        );
        input.whir_instance_count = self.counters.whir_instance_count;
        input.root_count = self.counters.root_count;
        input.prover_mode = self.mode;
        input
    }
}

impl N8IntegratedWhirPrototypeCounters {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"N8_INTEGRATED_WHIR_PROTOTYPE_COUNTERS_V1");
        push_u64(&mut out, self.whir_instance_count as u64);
        push_u64(&mut out, self.root_count as u64);
        push_u64(&mut out, self.query_schedule_count as u64);
        push_u64(&mut out, self.tuple_pcs_proof_count as u64);
        push_bool(&mut out, self.delegated_split_proof_material_present);
        push_bool(&mut out, self.synthetic_non_authoritative);
        out
    }
}

impl Symbt3N8IntegratedPrototypeGateReport {
    fn ok() -> Self {
        Self {
            ok: true,
            blocked: false,
            blocker: None,
            semantic_completion: N8IntegratedSemanticCompletionFlagsV1::none_complete(),
        }
    }

    fn ok_with_semantic_completion(
        semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    ) -> Self {
        Self {
            ok: true,
            blocked: false,
            blocker: None,
            semantic_completion,
        }
    }

    fn blocked(blocker: Symbt3N8IntegratedPrototypeBlocker) -> Self {
        Self {
            ok: false,
            blocked: true,
            blocker: Some(blocker),
            semantic_completion: N8IntegratedSemanticCompletionFlagsV1::none_complete(),
        }
    }

    fn blocked_with_semantic_completion(
        blocker: Symbt3N8IntegratedPrototypeBlocker,
        semantic_completion: N8IntegratedSemanticCompletionFlagsV1,
    ) -> Self {
        Self {
            ok: false,
            blocked: true,
            blocker: Some(blocker),
            semantic_completion,
        }
    }
}

impl Symbt3AccumulatorPublicInstance {
    fn from_statement_coordinates(
        profile_digest: Digest32,
        shape_id: Digest32,
        coordinates: Vec<i64>,
    ) -> Self {
        let accumulator_digest = symbt3_accumulator_coordinates_digest(
            crate::digest_core::PublicDigestScheme::Poseidon2BabyBear,
            b"state",
            &coordinates,
        );
        Self {
            profile_digest,
            shape_id,
            accumulator_digest,
            accumulator_coordinates: coordinates,
        }
    }

    #[must_use]
    pub fn from_old_public_statement(
        profile_digest: Digest32,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Self {
        Self::from_statement_coordinates(
            profile_digest,
            statement.shape_id,
            statement.old_accumulator_coordinates.clone(),
        )
    }

    #[must_use]
    pub fn from_new_public_statement(
        profile_digest: Digest32,
        statement: &BatchedCpSymbt3PublicStatement,
    ) -> Self {
        Self::from_statement_coordinates(
            profile_digest,
            statement.shape_id,
            statement.new_accumulator_coordinates.clone(),
        )
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_ACCUMULATOR_PUBLIC_INSTANCE_V1");
        push_u64(&mut out, SYMBT3_ACCUMULATOR_PUBLIC_INSTANCE_VERSION);
        push_digest(&mut out, &self.profile_digest);
        push_digest(&mut out, &self.shape_id);
        push_digest(&mut out, &self.accumulator_digest);
        push_i64_slice(&mut out, &self.accumulator_coordinates);
        out
    }

    #[must_use]
    pub fn object_digest(&self) -> Digest32 {
        digest_bytes(&self.canonical_bytes())
    }
}

impl Symbt3AccumulatorObject {
    #[must_use]
    pub fn from_public_instance(public_instance: Symbt3AccumulatorPublicInstance) -> Self {
        Self { public_instance }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_ACCUMULATOR_OBJECT_V1");
        push_u64(&mut out, SYMBT3_ACCUMULATOR_OBJECT_VERSION);
        push_bytes(&mut out, &self.public_instance.canonical_bytes());
        out
    }

    #[must_use]
    pub fn object_digest(&self) -> Digest32 {
        digest_bytes(&self.canonical_bytes())
    }
}

impl Symbt3AccumulationBatch {
    #[must_use]
    pub fn from_accumulator_instance(
        profile: Symbt3AuthorityProfile,
        accumulator_instance: &Symbt3AccumulatorInstance,
    ) -> Self {
        Self {
            profile,
            public_statement: accumulator_instance.to_public_statement(),
        }
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_ACCUMULATION_BATCH_V1");
        push_u64(&mut out, SYMBT3_ACCUMULATION_BATCH_VERSION);
        push_bytes(&mut out, &self.profile.canonical_bytes());
        push_bytes(&mut out, &self.public_statement.canonical_bytes());
        out
    }

    #[must_use]
    pub fn batch_digest(&self) -> Digest32 {
        digest_bytes(&self.canonical_bytes())
    }
}

impl Symbt3AccumulationProof {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_N8_ACCUMULATION_PROOF_V1");
        push_u64(&mut out, self.version);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.accumulator_instance_digest);
        push_digest(&mut out, &self.old_accumulator_digest);
        push_digest(&mut out, &self.new_accumulator_digest);
        push_u64(&mut out, self.batch_size);
        push_u64(&mut out, self.active_count);
        push_digest(&mut out, &self.k6a_relation_id);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.tuple_leaf_root);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.tuple_leaf_descriptor_digest);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_message_roots_digest);
        push_digest(&mut out, &self.n8_transcript_binding_digest);
        push_digest(&mut out, &self.n8_claim_plan_digest);
        push_digest(&mut out, &self.n8_committed_table_layout_digest);
        push_digest(&mut out, &self.n8_committed_table_digest);
        push_bytes(&mut out, &self.semantic_completion.canonical_bytes());
        push_bytes(&mut out, &self.descriptor.canonical_bytes());
        push_bytes(&mut out, &self.output.canonical_bytes());
        out
    }

    #[must_use]
    pub fn proof_digest(&self) -> Digest32 {
        digest_bytes(&self.canonical_bytes())
    }
}

impl Symbt3AccumulationVerificationReport {
    fn ok(semantic_completion: N8IntegratedSemanticCompletionFlagsV1) -> Self {
        Self {
            ok: true,
            blocked: false,
            blocker: None,
            semantic_completion,
        }
    }

    fn blocked(blocker: Symbt3N8IntegratedPrototypeBlocker) -> Self {
        Self {
            ok: false,
            blocked: true,
            blocker: Some(blocker),
            semantic_completion: N8IntegratedSemanticCompletionFlagsV1::none_complete(),
        }
    }

    fn from_gate_report(report: Symbt3N8IntegratedPrototypeGateReport) -> Self {
        Self {
            ok: report.ok,
            blocked: report.blocked,
            blocker: report.blocker,
            semantic_completion: report.semantic_completion,
        }
    }
}

impl Symbt3AccumulationAuthorityProfile {
    #[must_use]
    pub const fn version(self) -> u64 {
        match self {
            Self::N8NonZkSameShapeV1 => SYMBT3_ACCUMULATION_AUTHORITY_PROFILE_VERSION,
        }
    }

    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_ACCUMULATION_AUTHORITY_PROFILE_V1");
        push_u64(&mut out, self.version());
        out.push(match self {
            Self::N8NonZkSameShapeV1 => 1,
        });
        out
    }
}

struct Symbt3N8AccumulationPublicContext {
    relation: BatchedCpSymbt3RelationDescription,
    accumulator_instance: Symbt3AccumulatorInstance,
    new_accumulator: Symbt3AccumulatorObject,
    public_statement_digest: Digest32,
    accumulator_instance_digest: Digest32,
}

fn symbt3_n8_accumulation_public_context_from_relation(
    relation: BatchedCpSymbt3RelationDescription,
    batch: &Symbt3AccumulationBatch,
    old_accumulator_public: &Symbt3AccumulatorPublicInstance,
    new_accumulator_public: Option<&Symbt3AccumulatorPublicInstance>,
) -> Result<Symbt3N8AccumulationPublicContext, Symbt3N8IntegratedPrototypeBlocker> {
    if batch.public_statement.batch_capacity == 0 || batch.public_statement.active_count == 0 {
        return Err(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch);
    }
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let profile_digest = batch.profile.digest(scheme);
    let expected_old = Symbt3AccumulatorPublicInstance::from_old_public_statement(
        profile_digest,
        &batch.public_statement,
    );
    if old_accumulator_public != &expected_old {
        return Err(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    let expected_new = Symbt3AccumulatorPublicInstance::from_new_public_statement(
        profile_digest,
        &batch.public_statement,
    );
    if let Some(new_accumulator_public) = new_accumulator_public {
        if new_accumulator_public != &expected_new {
            return Err(
                Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
            );
        }
    }
    let accumulator_instance = Symbt3AccumulatorInstance::from_public_statement_with_scheme(
        scheme,
        profile_digest,
        batch.public_statement.old_accumulator_digest,
        batch.public_statement.new_accumulator_digest,
        &batch.public_statement,
    );
    if !accumulator_instance.matches_profile_and_relation(&batch.profile, &relation) {
        return Err(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    let public_statement_digest =
        derive_symbt3_public_statement_digest(&relation, &batch.public_statement);
    let accumulator_instance_digest = accumulator_instance.digest(scheme);
    Ok(Symbt3N8AccumulationPublicContext {
        relation,
        accumulator_instance,
        new_accumulator: Symbt3AccumulatorObject::from_public_instance(expected_new),
        public_statement_digest,
        accumulator_instance_digest,
    })
}

fn symbt3_n8_accumulation_public_context_from_pk(
    pk: &WhirProvingKey,
    batch: &Symbt3AccumulationBatch,
    old_accumulator_public: &Symbt3AccumulatorPublicInstance,
) -> Result<Symbt3N8AccumulationPublicContext, Symbt3N8IntegratedPrototypeBlocker> {
    let relation = symbt3_k6a_relation_from_context(
        pk.relation
            .context
            .as_ref()
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    symbt3_n8_accumulation_public_context_from_relation(
        relation,
        batch,
        old_accumulator_public,
        None,
    )
}

fn symbt3_n8_accumulation_public_context_from_vk(
    vk: &WhirVerifyingKey,
    batch: &Symbt3AccumulationBatch,
    old_accumulator_public: &Symbt3AccumulatorPublicInstance,
    new_accumulator_public: &Symbt3AccumulatorPublicInstance,
) -> Result<Symbt3N8AccumulationPublicContext, Symbt3N8IntegratedPrototypeBlocker> {
    let relation = symbt3_k6a_relation_from_context(
        vk.relation
            .context
            .as_ref()
            .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?,
    )
    .ok_or(Symbt3N8IntegratedPrototypeBlocker::ShapeMismatch)?;
    symbt3_n8_accumulation_public_context_from_relation(
        relation,
        batch,
        old_accumulator_public,
        Some(new_accumulator_public),
    )
}

fn symbt3_n8_accumulation_proof_from_descriptor_output(
    public_statement_digest: Digest32,
    accumulator_instance_digest: Digest32,
    descriptor: Symbt3IntegratedK6aNativeWhirRelationV1,
    output: N8IntegratedWhirProverOutput,
) -> Symbt3AccumulationProof {
    let transition = &descriptor.transition_binding_semantic_constraints;
    Symbt3AccumulationProof {
        version: SYMBT3_N8_ACCUMULATION_PROOF_VERSION,
        public_statement_digest,
        accumulator_instance_digest,
        old_accumulator_digest: transition.old_accumulator_digest,
        new_accumulator_digest: transition.new_accumulator_digest,
        batch_size: transition.batch_size,
        active_count: transition.active_count,
        k6a_relation_id: descriptor.main_symbt3_relation_id,
        whir_param_digest: descriptor.whir_param_digest,
        tuple_leaf_root: transition.tuple_leaf_root,
        tuple_leaf_layout_digest: descriptor.tuple_leaf_layout_digest,
        tuple_leaf_descriptor_digest: descriptor.tuple_leaf_descriptor_digest,
        native_oracle_descriptor_digest: transition.native_oracle_descriptor_digest,
        native_message_roots_digest: transition.native_message_roots_digest,
        n8_transcript_binding_digest: descriptor.transcript_binding_digest,
        n8_claim_plan_digest: descriptor.claim_plan.claim_plan_digest,
        n8_committed_table_layout_digest: descriptor.committed_table.layout_digest,
        n8_committed_table_digest: descriptor.committed_table.table_digest,
        semantic_completion: descriptor.semantic_completion,
        descriptor,
        output,
    }
}

fn symbt3_n8_accumulation_binding_blocker(
    relation: &BatchedCpSymbt3RelationDescription,
    context: &Symbt3N8AccumulationPublicContext,
    proof: &Symbt3AccumulationProof,
) -> Option<Symbt3N8IntegratedPrototypeBlocker> {
    let transition = &proof.descriptor.transition_binding_semantic_constraints;
    let relation_id = relation.relation_id();
    let expected_batch_size = context.accumulator_instance.batch_capacity as u64;
    let expected_active_count = context.accumulator_instance.active_count as u64;
    if proof.version != SYMBT3_N8_ACCUMULATION_PROOF_VERSION
        || proof.descriptor.version != SYMBT3_N8_INTEGRATED_K6A_NATIVE_WHIR_RELATION_VERSION
        || proof.output.version != N8_INTEGRATED_WHIR_PROVER_OUTPUT_VERSION
        || proof.output.proof_plan.version != N8_INTEGRATED_WHIR_PROOF_PLAN_VERSION
        || proof.output.query_schedule.version != N8_INTEGRATED_WHIR_QUERY_SCHEDULE_VERSION
        || proof.semantic_completion.version != N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION
        || proof.descriptor.semantic_completion.version
            != N8_INTEGRATED_SEMANTIC_COMPLETION_FLAGS_VERSION
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if proof.descriptor.workload_kind
        != Symbt3NativeAccumulatorAuthorityWorkload::FullK6aAccumulatorV1
        || proof.descriptor.main_symbt3_relation_id != relation_id
        || proof.k6a_relation_id != relation_id
    {
        return Some(Symbt3N8IntegratedPrototypeBlocker::WorkloadKindMismatch);
    }
    if proof.public_statement_digest != context.public_statement_digest
        || proof.accumulator_instance_digest != context.accumulator_instance_digest
        || proof.old_accumulator_digest != context.accumulator_instance.old_accumulator_digest
        || proof.new_accumulator_digest != context.accumulator_instance.new_accumulator_digest
        || proof.batch_size != expected_batch_size
        || proof.active_count != expected_active_count
        || proof.descriptor.public_statement_digest != context.public_statement_digest
        || proof.descriptor.claim_plan.k6a_public_statement_digest
            != context.public_statement_digest
        || transition.profile_digest != context.accumulator_instance.profile_digest
        || transition.accumulator_instance_digest != context.accumulator_instance_digest
        || transition.old_accumulator_digest != context.accumulator_instance.old_accumulator_digest
        || transition.new_accumulator_digest != context.accumulator_instance.new_accumulator_digest
        || transition.public_statement_digest != context.public_statement_digest
        || transition.batch_size != expected_batch_size
        || transition.active_count != expected_active_count
        || transition.main_symbt3_relation_id != relation_id
        || transition.whir_param_digest != proof.whir_param_digest
        || transition.tuple_leaf_root != proof.tuple_leaf_root
        || transition.tuple_leaf_layout_digest != proof.tuple_leaf_layout_digest
        || transition.tuple_leaf_descriptor_digest != proof.tuple_leaf_descriptor_digest
        || transition.native_oracle_descriptor_digest != proof.native_oracle_descriptor_digest
        || transition.native_message_roots_digest != proof.native_message_roots_digest
        || transition.n8_claim_plan_digest != proof.n8_claim_plan_digest
        || transition.n8_committed_table_layout_digest != proof.n8_committed_table_layout_digest
        || transition.n8_committed_table_digest != proof.n8_committed_table_digest
        || proof.n8_transcript_binding_digest != proof.descriptor.transcript_binding_digest
        || proof.n8_claim_plan_digest != proof.descriptor.claim_plan.claim_plan_digest
        || proof.n8_committed_table_layout_digest != proof.descriptor.committed_table.layout_digest
        || proof.n8_committed_table_digest != proof.descriptor.committed_table.table_digest
        || proof.semantic_completion != proof.descriptor.semantic_completion
        || !proof.semantic_completion.all_complete()
    {
        return Some(
            Symbt3N8IntegratedPrototypeBlocker::TransitionBindingSemanticConstraintViolation,
        );
    }
    None
}
