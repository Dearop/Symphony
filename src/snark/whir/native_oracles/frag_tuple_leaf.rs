#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbt3NativeMultiOracleMode {
    CompatibilityEnvelopeV1,
    SameDomainRlcTupleLeafV1,
    SameDomainVectorTupleLeafV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TupleLeafLayoutV1 {
    pub version: u64,
    pub mode: Symbt3NativeMultiOracleMode,
    pub logical_oracle_count: usize,
    pub num_vars: usize,
    pub packing_challenge_digest: Digest32,
    pub descriptor_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TupleLeafPackedEvalClaim {
    pub point_digest: Digest32,
    pub value: BabyBear,
    pub claim_kind: WhirNativeEvalClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbt3TupleLeafMultiOracleCounters {
    pub logical_oracle_count: usize,
    pub whir_instance_count: usize,
    pub query_schedule_count: usize,
    pub transcript_count: usize,
    pub root_count: usize,
    pub native_oracle_pcs_opening_count: usize,
    pub logical_eval_claim_count: usize,
    pub rlc_repetition_count: usize,
    pub rlc_batching_bits_per_repetition: usize,
    pub total_rlc_batching_bits: usize,
    pub effective_soundness_bits: usize,
    pub tuple_leaf_layout: String,
    pub same_domain: bool,
    pub same_field: bool,
    pub same_rate: bool,
    pub same_folding_parameter: bool,
    pub merkle_path_proxy: usize,
    pub hash_estimate: usize,
    pub field_op_estimate: usize,
}

#[derive(Debug, Clone)]
pub struct Symbt3TupleLeafMultiOracleProof {
    pub version: u64,
    pub mode: Symbt3NativeMultiOracleMode,
    pub proof_relation_id: Digest32,
    pub public_statement_digest: Digest32,
    pub whir_param_digest: Digest32,
    pub logical_descriptors: Vec<WhirNativeOracleSpec>,
    pub descriptor_digest: Digest32,
    pub tuple_leaf_layout_digest: Digest32,
    pub packing_challenge_digest: Digest32,
    pub packed_root: Digest32,
    pub packed_eval_claims: Vec<Symbt3TupleLeafPackedEvalClaim>,
    pub logical_eval_claims: Vec<WhirNativeOracleEvalClaim>,
    pub whir_pcs_proof: WhirPcsProof<F, EF, WhirMmcs>,
    pub counters: Symbt3TupleLeafMultiOracleCounters,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbt3TupleLeafProofByteSections {
    pub descriptor_layout_profile_metadata_bytes: usize,
    pub duplicated_main_k6a_context_bytes: usize,
    pub logical_eval_claim_bytes: usize,
    pub repeated_rlc_claim_bytes: usize,
    pub pcs_payload_length_prefix_bytes: usize,
    pub pcs_compact_canonical_payload_bytes: usize,
    pub pcs_legacy_json_payload_bytes: usize,
    pub pcs_merkle_root_path_payload_bytes: usize,
    pub pcs_query_value_payload_bytes: usize,
    pub pcs_transcript_payload_bytes: usize,
    pub pcs_json_framing_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbt3N7bFullAuthorityProofByteSections {
    pub proof_header_bytes: usize,
    pub main_k6a_whir_proof_bytes: usize,
    pub k6a_adapter_bytes: usize,
    pub tuple_leaf_native_proof_bytes: usize,
    pub native_tuple_leaf_part_metadata_bytes: usize,
    pub binding_digest_profile_metadata_bytes: usize,
    pub wrapper_counters_bytes: usize,
    pub serialization_framing_bytes: usize,
    pub total_bytes: usize,
}

impl WhirNativeMultiOracleProof {
    #[must_use]
    pub const fn top_level_whir_proof_count(&self) -> usize {
        1
    }

    #[must_use]
    pub const fn family_columnar_subproof_count(&self) -> usize {
        0
    }

    #[must_use]
    pub const fn native_oracle_pcs_opening_count(&self) -> usize {
        self.pcs_openings.len()
    }

    #[must_use]
    pub fn metadata_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"WHIR_NATIVE_MULTI_ORACLE_ENVELOPE_METADATA_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.root_policy.canonical_bytes());
        push_digest(&mut out, &self.proof_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_digest(&mut out, &self.native_oracle_descriptor_digest);
        push_digest(&mut out, &self.native_oracle_eval_claims_digest);
        push_u64(&mut out, self.descriptors.len() as u64);
        for descriptor in &self.descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_u64(&mut out, self.eval_claims.len() as u64);
        for claim in &self.eval_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_u64(&mut out, self.pcs_openings.len() as u64);
        for opening in &self.pcs_openings {
            push_u32(&mut out, opening.oracle_id);
        }
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }
}

impl Symbt3NativeMultiOracleMode {
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_NATIVE_MULTI_ORACLE_MODE_V1");
        encode_native_multi_oracle_mode(&mut out, self);
        out
    }
}

impl Symbt3TupleLeafLayoutV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_TUPLE_LEAF_LAYOUT_V1");
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.num_vars as u64);
        push_digest(&mut out, &self.packing_challenge_digest);
        push_digest(&mut out, &self.descriptor_digest);
        out
    }
}

impl Symbt3TupleLeafPackedEvalClaim {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_TUPLE_LEAF_PACKED_EVAL_CLAIM_V1");
        push_digest(&mut out, &self.point_digest);
        push_babybear(&mut out, self.value);
        push_bytes(&mut out, &self.claim_kind.canonical_bytes());
        out
    }
}

impl Symbt3TupleLeafMultiOracleCounters {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, b"SYMBT3_TUPLE_LEAF_MULTI_ORACLE_COUNTERS_V1");
        push_u64(&mut out, self.logical_oracle_count as u64);
        push_u64(&mut out, self.whir_instance_count as u64);
        push_u64(&mut out, self.query_schedule_count as u64);
        push_u64(&mut out, self.transcript_count as u64);
        push_u64(&mut out, self.root_count as u64);
        push_u64(&mut out, self.native_oracle_pcs_opening_count as u64);
        push_u64(&mut out, self.logical_eval_claim_count as u64);
        push_u64(&mut out, self.rlc_repetition_count as u64);
        push_u64(&mut out, self.rlc_batching_bits_per_repetition as u64);
        push_u64(&mut out, self.total_rlc_batching_bits as u64);
        push_u64(&mut out, self.effective_soundness_bits as u64);
        push_bytes(&mut out, self.tuple_leaf_layout.as_bytes());
        out.push(u8::from(self.same_domain));
        out.push(u8::from(self.same_field));
        out.push(u8::from(self.same_rate));
        out.push(u8::from(self.same_folding_parameter));
        push_u64(&mut out, self.merkle_path_proxy as u64);
        push_u64(&mut out, self.hash_estimate as u64);
        push_u64(&mut out, self.field_op_estimate as u64);
        out
    }
}

impl Symbt3TupleLeafMultiOracleProof {
    #[must_use]
    pub const fn top_level_whir_proof_count(&self) -> usize {
        1
    }

    #[must_use]
    pub const fn family_columnar_subproof_count(&self) -> usize {
        0
    }

    #[must_use]
    pub const fn native_oracle_pcs_opening_count(&self) -> usize {
        1
    }

    #[must_use]
    pub fn metadata_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(
            &mut out,
            b"SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_METADATA_V1",
        );
        push_u64(&mut out, self.version);
        push_bytes(&mut out, &self.mode.canonical_bytes());
        push_digest(&mut out, &self.proof_relation_id);
        push_digest(&mut out, &self.public_statement_digest);
        push_digest(&mut out, &self.whir_param_digest);
        push_u64(&mut out, self.logical_descriptors.len() as u64);
        for descriptor in &self.logical_descriptors {
            push_bytes(&mut out, &descriptor.canonical_bytes());
        }
        push_digest(&mut out, &self.descriptor_digest);
        push_digest(&mut out, &self.tuple_leaf_layout_digest);
        push_digest(&mut out, &self.packing_challenge_digest);
        push_digest(&mut out, &self.packed_root);
        push_u64(&mut out, self.packed_eval_claims.len() as u64);
        for claim in &self.packed_eval_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_u64(&mut out, self.logical_eval_claims.len() as u64);
        for claim in &self.logical_eval_claims {
            push_bytes(&mut out, &claim.canonical_bytes());
        }
        push_bytes(&mut out, &self.counters.canonical_bytes());
        out
    }

    #[must_use]
    pub fn accounting_byte_sections(&self) -> Symbt3TupleLeafProofByteSections {
        let descriptor_layout_profile_metadata_bytes = encoded_len(|out| {
            push_bytes(out, b"SYMBT3_TUPLE_LEAF_MULTI_ORACLE_PROOF_METADATA_V1");
            push_u64(out, self.version);
            push_bytes(out, &self.mode.canonical_bytes());
            push_u64(out, self.logical_descriptors.len() as u64);
            for descriptor in &self.logical_descriptors {
                push_bytes(out, &descriptor.canonical_bytes());
            }
            push_digest(out, &self.descriptor_digest);
            push_digest(out, &self.tuple_leaf_layout_digest);
            push_digest(out, &self.packing_challenge_digest);
            push_digest(out, &self.packed_root);
            push_bytes(out, &self.counters.canonical_bytes());
        });
        let duplicated_main_k6a_context_bytes = encoded_len(|out| {
            push_digest(out, &self.proof_relation_id);
            push_digest(out, &self.public_statement_digest);
            push_digest(out, &self.whir_param_digest);
        });
        let repeated_rlc_claim_bytes = encoded_len(|out| {
            push_u64(out, self.packed_eval_claims.len() as u64);
            for claim in &self.packed_eval_claims {
                push_bytes(out, &claim.canonical_bytes());
            }
        });
        let logical_eval_claim_bytes = encoded_len(|out| {
            push_u64(out, self.logical_eval_claims.len() as u64);
            for claim in &self.logical_eval_claims {
                push_bytes(out, &claim.canonical_bytes());
            }
        });
        debug_assert_eq!(
            self.metadata_canonical_bytes().len(),
            descriptor_layout_profile_metadata_bytes
                + duplicated_main_k6a_context_bytes
                + repeated_rlc_claim_bytes
                + logical_eval_claim_bytes
        );

        let pcs_legacy_json_bytes = serde_json::to_vec(&self.whir_pcs_proof)
            .expect("tuple-leaf WHIR PCS proof must serialize for byte accounting");
        let pcs_compact_canonical_bytes = whir_pcs_compact_canonical_bytes(&self.whir_pcs_proof)
            .expect("tuple-leaf WHIR PCS proof must compact-serialize for byte accounting");
        let pcs_json = serde_json::to_value(&self.whir_pcs_proof)
            .expect("tuple-leaf WHIR PCS proof must convert to JSON for byte accounting");
        let (
            pcs_merkle_root_path_payload_bytes,
            pcs_query_value_payload_bytes,
            pcs_transcript_payload_bytes,
        ) = whir_pcs_json_payload_sections(&pcs_json);
        let accounted_pcs_bytes = pcs_merkle_root_path_payload_bytes
            + pcs_query_value_payload_bytes
            + pcs_transcript_payload_bytes;
        let pcs_json_framing_bytes = pcs_legacy_json_bytes
            .len()
            .saturating_sub(accounted_pcs_bytes);
        let pcs_payload_length_prefix_bytes = 8;
        let total_bytes = descriptor_layout_profile_metadata_bytes
            + duplicated_main_k6a_context_bytes
            + logical_eval_claim_bytes
            + repeated_rlc_claim_bytes
            + pcs_payload_length_prefix_bytes
            + pcs_compact_canonical_bytes.len();

        Symbt3TupleLeafProofByteSections {
            descriptor_layout_profile_metadata_bytes,
            duplicated_main_k6a_context_bytes,
            logical_eval_claim_bytes,
            repeated_rlc_claim_bytes,
            pcs_payload_length_prefix_bytes,
            pcs_compact_canonical_payload_bytes: pcs_compact_canonical_bytes.len(),
            pcs_legacy_json_payload_bytes: pcs_legacy_json_bytes.len(),
            pcs_merkle_root_path_payload_bytes,
            pcs_query_value_payload_bytes,
            pcs_transcript_payload_bytes,
            pcs_json_framing_bytes,
            total_bytes,
        }
    }

    #[must_use]
    pub fn accounting_serialized_bytes_len(&self) -> usize {
        self.accounting_byte_sections().total_bytes
    }
}

