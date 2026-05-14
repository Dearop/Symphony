fn encode_statement_shape(out: &mut Vec<u8>, shape: &BatchedCpStatementShape) {
    push_bytes(out, b"symphony-batched-cp-statement-shape-v1");
    out.extend_from_slice(&shape.shape_id);
    push_usize(out, shape.batch_log_size);
    push_usize(out, shape.batch_capacity);
    push_usize(out, shape.active_count);
    push_usize(out, shape.witness_row_len);
    push_usize_vec(out, &shape.round_message_lens);
    push_bytes(out, &shape.accumulator_shape.canonical_bytes());
}

fn decode_statement_shape(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<BatchedCpStatementShape, BatchedCpError> {
    let domain = read_bytes(bytes, pos)?;
    if domain != b"symphony-batched-cp-statement-shape-v1" {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    let shape_id = read_digest(bytes, pos)?;
    let batch_log_size = read_usize(bytes, pos)?;
    let batch_capacity = read_usize(bytes, pos)?;
    let active_count = read_usize(bytes, pos)?;
    let witness_row_len = read_usize(bytes, pos)?;
    let round_message_lens = read_usize_vec(bytes, pos)?;
    let accumulator_bytes = read_bytes(bytes, pos)?;
    let accumulator_shape = decode_accumulator_shape(&accumulator_bytes)?;
    let shape = BatchedCpStatementShape {
        accumulator_shape,
        shape_id,
        batch_log_size,
        batch_capacity,
        active_count,
        witness_row_len,
        round_message_lens: round_message_lens.clone(),
    };
    if active_count == 0
        || batch_capacity != active_count.next_power_of_two()
        || batch_log_size != batch_capacity.trailing_zeros() as usize
        || witness_row_len != estimate_witness_row_len(&shape.accumulator_shape)
        || round_message_lens != shape.accumulator_shape.fs_message_lens
        || shape_id != shape.accumulator_shape.shape_id()
    {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    Ok(shape)
}

fn decode_accumulator_shape(bytes: &[u8]) -> Result<CpAccumulatorShape, BatchedCpError> {
    let mut pos = 0;
    let domain = read_bytes(bytes, &mut pos)?;
    if domain != b"symphony-cp-accumulator-shape-v1" {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    let digest_scheme = read_digest_scheme(bytes, &mut pos)?;
    let r1cs_num_constraints = read_usize(bytes, &mut pos)?;
    let r1cs_num_variables = read_usize(bytes, &mut pos)?;
    let r1cs_num_public = read_usize(bytes, &mut pos)?;
    let local_public_input_count = read_usize(bytes, &mut pos)?;
    let public_statement_len = read_usize(bytes, &mut pos)?;
    let num_rounds = read_usize(bytes, &mut pos)?;
    let fs_message_lens = read_usize_vec(bytes, &mut pos)?;
    let fs_commitment_len = read_usize(bytes, &mut pos)?;
    let fs_opening_len = read_usize(bytes, &mut pos)?;
    let fold_input_commitment_lens = read_usize_vec(bytes, &mut pos)?;
    let fold_input_public_input_lens = read_usize_vec(bytes, &mut pos)?;
    let fold_input_eval_message_lens = read_usize_vec(bytes, &mut pos)?;
    let gr1cs_hadamard_eval_offsets = read_nested_usize_vec(bytes, &mut pos)?;
    let gr1cs_message_sections = read_gr1cs_message_sections(bytes, &mut pos)?;
    let original_witness_lens = read_usize_vec(bytes, &mut pos)?;
    let commitment_kappa = read_usize(bytes, &mut pos)?;
    let commitment_d = read_usize(bytes, &mut pos)?;
    let folded_public_input_len = read_usize(bytes, &mut pos)?;
    let folded_evaluation_count = read_usize(bytes, &mut pos)?;
    let folded_output_contribution_len = read_usize(bytes, &mut pos)?;
    let whir_parameter_digest = read_digest(bytes, &mut pos)?;
    if pos != bytes.len()
        || num_rounds == 0
        || fs_message_lens.len() != num_rounds
        || fold_input_commitment_lens.len() != num_rounds
        || fold_input_public_input_lens.len() != num_rounds
        || fold_input_eval_message_lens.len() != num_rounds
        || gr1cs_hadamard_eval_offsets.len() != num_rounds
        || gr1cs_message_sections.len() != num_rounds
        || gr1cs_hadamard_eval_offsets
            .iter()
            .any(|offsets| offsets.len() != folded_evaluation_count)
        || gr1cs_message_sections
            .iter()
            .zip(fs_message_lens.iter())
            .any(|(sections, &message_len)| !message_sections_are_contiguous(sections, message_len))
    {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    Ok(CpAccumulatorShape {
        digest_scheme,
        r1cs_num_constraints,
        r1cs_num_variables,
        r1cs_num_public,
        local_public_input_count,
        public_statement_len,
        num_rounds,
        fs_message_lens,
        fs_commitment_len,
        fs_opening_len,
        fold_input_commitment_lens,
        fold_input_public_input_lens,
        fold_input_eval_message_lens,
        gr1cs_hadamard_eval_offsets,
        gr1cs_message_sections,
        original_witness_lens,
        commitment_kappa,
        commitment_d,
        folded_public_input_len,
        folded_evaluation_count,
        folded_output_contribution_len,
        whir_parameter_digest,
    })
}

fn encode_round_message_body(
    shape: &BatchedCpStatementShape,
    items: &[BatchedCpItem],
    round: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, b"symphony-batched-cp-round-message-v1");
    out.extend_from_slice(&shape.shape_id);
    push_usize(&mut out, round);
    push_usize(&mut out, shape.batch_capacity);
    for idx in 0..shape.batch_capacity {
        push_usize(&mut out, idx);
        if let Some(item) = items.get(idx) {
            out.push(1);
            push_bytes(&mut out, &item.witness.fs_messages[round]);
        } else {
            out.push(0);
            push_bytes(&mut out, &[]);
        }
    }
    out
}

fn encode_folded_output_accumulator_body(items: &[BatchedCpItem]) -> Vec<u8> {
    let mut out = Vec::new();
    push_usize(&mut out, items.len());
    for item in items {
        out.extend_from_slice(&encode_folded_output_contribution(item));
    }
    out
}

fn encode_folded_output_contribution(item: &BatchedCpItem) -> Vec<u8> {
    encode_folded_output_contribution_parts(&item.public, Some(item.item_tag))
}

fn encode_folded_output_contribution_parts(
    public: &CpPublicStatement,
    item_tag: Option<Digest32>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&item_tag.unwrap_or([0u8; 32]));
    encode_folded_instance(&mut out, &public.instance.x_folded);
    encode_folded_output_instance(&mut out, &public.instance.folded_output);
    out
}

fn encode_public_statement(public: &CpPublicStatement) -> Vec<u8> {
    let mut out = Vec::new();
    push_digest_scheme(&mut out, public.digest_scheme);
    out.extend_from_slice(&public.instance.fs_root);
    out.extend_from_slice(&public.instance.fold_root);
    out.extend_from_slice(&public.instance.challenge_digest);
    out.extend_from_slice(&public.instance.transcript_seed_digest);
    encode_folded_instance(&mut out, &public.instance.x_folded);
    encode_folded_output_instance(&mut out, &public.instance.folded_output);
    push_i64_matrix(&mut out, &public.public_inputs);
    push_usize(&mut out, public.r1cs_num_constraints);
    push_usize(&mut out, public.r1cs_num_variables);
    push_usize(&mut out, public.r1cs_num_public);
    out
}

fn encode_witness_row(item: &BatchedCpItem) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&item.item_tag);
    out.extend_from_slice(&encode_public_statement(&item.public));
    out.extend_from_slice(&encode_folded_output_contribution(item));
    for beta in &item.witness.folding_proof.beta {
        encode_ring_element(&mut out, beta);
    }
    for message in &item.witness.fs_messages {
        push_bytes(&mut out, message);
    }
    for commitment in &item.witness.fs_commitments {
        push_bytes(&mut out, commitment);
    }
    for opening in &item.witness.fs_openings {
        push_bytes(&mut out, opening);
    }
    for input in &item.witness.fold_inputs {
        push_bytes(&mut out, &input.commitment_bytes);
        push_i64_vec(&mut out, &input.public_input);
        push_bytes(&mut out, &input.eval_values_bytes);
    }
    for witness in &item.witness.original_witnesses {
        encode_ring_vector(&mut out, witness);
    }
    out
}

fn poseidon_fs_commitment_body_from_item(item: &BatchedCpItem, round: usize) -> Vec<u8> {
    let mut body = Vec::new();
    let message = &item.witness.fs_messages[round];
    push_usize(&mut body, message.len());
    body.extend_from_slice(message);
    body.extend_from_slice(&item.witness.fs_openings[round]);
    body
}

fn poseidon_fs_commitment_trace_values(body: &[u8]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    #[cfg(feature = "whir")]
    {
        use p3_field::PrimeField32;
        let input_values = crate::digest_core::poseidon_digest_input_elems(b"fs-commit", body)
            .into_iter()
            .map(|value| value.as_canonical_u32())
            .collect::<Vec<_>>();
        let digest =
            crate::snark::cp_snark::typed_r1cs::poseidon2_digest32_from_body(b"fs-commit", body);
        let output_values = digest
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("digest limb")))
            .collect::<Vec<_>>();
        let witness = crate::snark::cp_snark::encode_poseidon2_digest_witness(
            b"fs-commit",
            &crate::digest_core::poseidon_digest_input_elems(b"fs-commit", body),
        );
        let aux_values = witness
            .chunks_exact(8)
            .map(|chunk| {
                let value = i64::from_le_bytes(chunk.try_into().expect("aux limb"));
                u32::try_from(value).expect("Poseidon aux limb should be canonical u32")
            })
            .collect::<Vec<_>>();
        (input_values, output_values, aux_values)
    }
    #[cfg(not(feature = "whir"))]
    {
        let _ = body;
        (Vec::new(), Vec::new(), Vec::new())
    }
}

fn poseidon_fs_commitment_input_len(message_len: usize, opening_len: usize) -> usize {
    let body_len = 8 + message_len + opening_len;
    let frame_len = b"symphony-v2".len() + 8 + b"fs-commit".len() + 8 + body_len;
    frame_len.div_ceil(3) + 1
}

fn poseidon_fs_commitment_aux_len(input_len: usize) -> usize {
    const RATE: usize = 8;
    const WIDTH: usize = 16;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 13;
    let sboxes_per_permutation = 2 * HALF_FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS;
    input_len.div_ceil(RATE) * sboxes_per_permutation * 4
}

#[cfg(feature = "whir")]
fn field_offsets(range: BatchedCpOracleByteRange, count: usize) -> Vec<usize> {
    (0..count).map(|idx| range.offset + idx * 4).collect()
}

#[cfg(feature = "whir")]
fn sampled_poseidon_row_candidates(num_constraints: usize) -> Vec<usize> {
    let mut rows = std::collections::BTreeSet::new();
    rows.extend(0..num_constraints.min(64));
    rows.extend(num_constraints.saturating_sub(16)..num_constraints);
    rows.into_iter().collect()
}

#[cfg(feature = "whir")]
fn r1cs_row_terms(
    matrix: &crate::r1cs::SparseMatrix,
    row: usize,
    coeff: usize,
    public_inputs: BatchedCpOracleByteRange,
    original_witness: BatchedCpOracleByteRange,
    num_public: usize,
) -> Vec<(i64, usize)> {
    matrix
        .entries
        .iter()
        .filter_map(|&(entry_row, col, value)| {
            if entry_row != row {
                return None;
            }
            let offset = if col < num_public {
                if coeff != 0 {
                    return None;
                }
                public_inputs.offset + col * 8
            } else {
                original_witness.offset + (col - num_public) * D * 8 + coeff * 8
            };
            Some((value, offset))
        })
        .collect()
}

fn encode_folded_output_instance(out: &mut Vec<u8>, value: &crate::folding::FoldedOutputInstance) {
    encode_folded_instance(out, &value.folded_instance);
    encode_commitment(out, &value.linear_relation.commitment);
    push_ext_vec(out, &value.linear_relation.evaluation_point);
    for eval in &value.linear_relation.evaluation_values {
        encode_tensor(out, eval);
    }
    push_usize(out, value.batched_relation.commitments.len());
    for commitment in &value.batched_relation.commitments {
        encode_commitment(out, commitment);
    }
    push_ext_vec(out, &value.batched_relation.evaluation_point);
    push_usize(out, value.batched_relation.evaluation_values.len());
    for eval in &value.batched_relation.evaluation_values {
        encode_tensor(out, eval);
    }
}

fn encode_folded_instance(out: &mut Vec<u8>, value: &crate::folding::FoldedInstance) {
    encode_commitment(out, &value.commitment);
    push_usize(out, value.public_input.len());
    for elem in &value.public_input {
        encode_ring_element(out, elem);
    }
    push_usize(out, value.evaluation_values.len());
    for eval in &value.evaluation_values {
        encode_tensor(out, eval);
    }
}

fn encode_commitment(out: &mut Vec<u8>, commitment: &crate::commitment::Commitment) {
    encode_ring_vector(out, &commitment.value);
}

fn encode_ring_vector(out: &mut Vec<u8>, value: &RingVector) {
    push_usize(out, value.elements.len());
    for elem in &value.elements {
        encode_ring_element(out, elem);
    }
}

fn encode_ring_element(out: &mut Vec<u8>, value: &RingElement) {
    for &coeff in &value.coeffs {
        out.extend_from_slice(&coeff.to_le_bytes());
    }
}

fn encode_symbt3_ring_module_layout(out: &mut Vec<u8>, value: &Symbt3RingModuleLayout) {
    push_usize(out, value.ring_degree);
    out.extend_from_slice(&value.modulus.to_le_bytes());
    push_bytes(out, value.basis_order.as_bytes());
    push_bytes(out, value.negacyclic_sign_convention.as_bytes());
    out.push(match value.action_side {
        Symbt3RingActionSide::Left => 1,
    });
    push_usize(out, value.opening_module_dimension);
    push_usize(out, value.commitment_module_dimension);
    push_bytes(out, value.coordinate_encoding.as_bytes());
    push_bytes(out, value.beta_encoding.as_bytes());
    out.extend_from_slice(&value.ring_action_version.to_le_bytes());
}

fn encode_symbt3_ajtai_commit_layout(out: &mut Vec<u8>, value: &Symbt3AjtaiCommitLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.commitment_module_dimension);
    push_usize(out, value.opening_module_dimension);
    push_usize(out, value.ring_degree);
    out.extend_from_slice(&value.modulus.to_le_bytes());
    out.extend_from_slice(&value.indexed_evaluator_id);
    out.push(u8::from(value.separated_message_randomness));
}

fn encode_symbt3_ajtai_linear_algebra_layout(
    out: &mut Vec<u8>,
    value: &Symbt3AjtaiLinearAlgebraLayout,
) {
    out.extend_from_slice(value.version_marker.as_slice());
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.extend_from_slice(&value.algebra_law_digest);
    out.extend_from_slice(&value.ajtai_matrix_digest);
    out.extend_from_slice(&value.ajtai_commit_layout_digest);
    push_usize(out, value.kappa);
    push_usize(out, value.opening_len);
    push_usize(out, value.ring_degree);
    push_usize(out, value.source_opening_column);
    push_usize(out, value.source_commitment_column);
    push_usize(out, value.folded_opening_column);
    push_usize(out, value.folded_commitment_column);
    out.push(symbt3_beta_action_code(value.beta_action));
    out.push(symbt3_product_law_code(value.product_law));
    out.push(symbt3_ajtai_matrix_vector_evaluator_code(
        value.matrix_vector_evaluator,
    ));
    push_bytes(out, value.padding_policy.as_bytes());
    push_bytes(out, value.selector_evaluator.as_bytes());
    out.push(symbt3_ajtai_opening_mode_code(value.opening_mode));
}

fn encode_symbt3_projection_layout(out: &mut Vec<u8>, value: &Symbt3ProjectionLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_projection_mode_code(value.projection_mode));
    out.push(symbt3_projection_seed_policy_code(
        value.projection_seed_policy,
    ));
    out.extend_from_slice(&value.projection_matrix_digest);
    push_usize(out, value.input_len);
    push_usize(out, value.output_len);
    push_usize(out, value.block_len);
    push_usize(out, value.rows_per_block);
    out.push(symbt3_projection_entry_distribution_code(
        value.entry_distribution,
    ));
    push_bytes(out, value.coefficient_domain.as_bytes());
}

fn encode_symbt3_monomial_embedding_layout(
    out: &mut Vec<u8>,
    value: &Symbt3MonomialEmbeddingLayout,
) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.ring_degree);
    push_usize(out, value.bound_b);
    out.extend_from_slice(&value.table_polynomial_digest);
    out.push(symbt3_monomiality_mode_code(value.monomiality_mode));
    out.push(symbt3_constant_term_policy_code(value.constant_term_policy));
    out.push(symbt3_signed_convention_code(value.signed_convention));
}

fn encode_symbt3_representative_layout(out: &mut Vec<u8>, value: &Symbt3RepresentativeLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.extend_from_slice(&value.modulus_digest);
    out.extend_from_slice(&value.signed_range.to_le_bytes());
    out.push(symbt3_canonical_rep_policy_code(value.canonical_rep_policy));
}

fn encode_symbt3_range_layout(out: &mut Vec<u8>, value: &Symbt3RangeLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_range_mode_code(value.range_mode));
    out.extend_from_slice(&value.bound_b.to_le_bytes());
    out.push(symbt3_signed_encoding_code(value.signed_encoding));
    match value.table_digest {
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
        None => out.push(0),
    }
    match value.monomial_embedding_layout_digest {
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
        None => out.push(0),
    }
}

fn encode_symbt3_ajtai_norm_range_layout(out: &mut Vec<u8>, value: &Symbt3AjtaiNormRangeLayout) {
    out.extend_from_slice(value.version_marker.as_slice());
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.extend_from_slice(&value.algebra_law_digest);
    out.extend_from_slice(&value.ajtai_linear_algebra_layout_digest);
    push_usize(out, value.folded_opening_column);
    push_usize(out, value.projected_opening_column);
    push_usize(out, value.monomial_witness_column);
    encode_symbt3_projection_layout(out, &value.projection_layout);
    encode_symbt3_range_layout(out, &value.range_layout);
    encode_symbt3_monomial_embedding_layout(out, &value.monomial_embedding_layout);
    encode_symbt3_representative_layout(out, &value.representative_layout);
    out.extend_from_slice(&value.norm_bound.to_le_bytes());
    out.push(symbt3_coefficient_encoding_code(value.coefficient_encoding));
    push_bytes(out, value.reduction_policy.as_bytes());
    push_bytes(out, value.selector_evaluator.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    out.push(symbt3_range_mode_code(value.range_mode));
}

fn encode_symbt3_manifest_oracle_layout(out: &mut Vec<u8>, value: &Symbt3ManifestOracleLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.row_count);
    push_usize(out, value.component_count);
    push_usize(out, value.coordinate_count);
    push_bytes(out, value.coordinate_ordering.as_bytes());
}

fn encode_symbt3_source_column_layout(out: &mut Vec<u8>, value: &Symbt3SourceColumnLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.component_count);
    push_usize(out, value.coordinate_count);
    push_bytes(out, value.source_column_ordering.as_bytes());
    push_bytes(out, value.root_binding_policy.as_bytes());
}

fn encode_symbt3_manifest_component_layout(
    out: &mut Vec<u8>,
    value: &Symbt3ManifestComponentLayout,
) {
    out.push(symbt3_manifest_component_kind_code(value.kind));
    push_usize(out, value.coordinate_len);
    push_usize(out, value.source_column_id);
    push_usize(out, value.manifest_column_id);
    out.push(symbt3_manifest_visibility_code(value.visibility));
    out.push(symbt3_membership_mode_code(value.membership_mode));
    push_bytes(out, value.padding_policy.as_bytes());
}

fn encode_symbt3_batch_manifest_layout(out: &mut Vec<u8>, value: &Symbt3BatchManifestLayout) {
    out.extend_from_slice(value.version_marker);
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.batch_size);
    push_usize(out, value.active_count);
    out.push(symbt3_active_policy_code(value.active_policy));
    encode_symbt3_manifest_oracle_layout(out, &value.manifest_oracle_layout);
    encode_symbt3_source_column_layout(out, &value.source_column_layout);
    push_usize(out, value.component_kinds.len());
    for component in &value.component_kinds {
        encode_symbt3_manifest_component_layout(out, component);
    }
    out.push(symbt3_commitment_scheme_code(value.commitment_scheme_id));
    out.push(symbt3_manifest_root_policy_code(value.manifest_root_policy));
    push_bytes(out, value.selector_evaluator.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
}

fn encode_symbt3_message_section_layout(out: &mut Vec<u8>, value: &Symbt3MessageSectionLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_message_section_kind_code(value.section_kind));
    push_usize(out, value.coordinate_offset);
    push_usize(out, value.coordinate_len);
    out.push(symbt3_message_algebra_type_code(value.algebra_type));
    out.push(symbt3_message_visibility_code(value.visibility));
    out.push(symbt3_message_binding_mode_code(value.binding_mode));
}

fn encode_symbt3_message_column_binding(out: &mut Vec<u8>, value: &Symbt3MessageColumnBinding) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round_index);
    push_usize(out, value.message_coordinate_offset);
    push_usize(out, value.trace_column_id);
    push_usize(out, value.trace_coordinate_offset);
    push_usize(out, value.coordinate_len);
    out.push(symbt3_message_binding_mode_code(value.binding_mode));
}

fn encode_symbt3_message_coordinate_map(out: &mut Vec<u8>, value: &Symbt3MessageCoordinateMap) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    out.push(symbt3_message_coordinate_map_mode_code(value.mode));
    push_usize(out, value.message_coordinate_offset);
    push_usize(out, value.coordinate_len);
}

fn encode_symbt3_message_view_layout(out: &mut Vec<u8>, value: &Symbt3MessageViewLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round);
    out.push(symbt3_trace_kind_code(value.trace_kind));
    push_bytes(out, value.trace_coordinate_axis.as_bytes());
    encode_symbt3_message_coordinate_map(out, &value.message_coordinate_map);
    out.push(symbt3_message_algebra_type_code(value.algebra_type));
    push_bytes(out, value.padding_policy.as_bytes());
}

fn encode_symbt3_round_message_layout(out: &mut Vec<u8>, value: &Symbt3RoundMessageLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round_index);
    push_usize(out, value.row_count);
    push_usize(out, value.message_len);
    push_usize(out, value.packed_field_len);
    push_bytes(out, value.coordinate_axis.as_bytes());
    push_bytes(out, value.section_axis.as_bytes());
    push_usize(out, value.sections.len());
    for section in &value.sections {
        encode_symbt3_message_section_layout(out, section);
    }
    push_usize(out, value.source_column_bindings.len());
    for binding in &value.source_column_bindings {
        encode_symbt3_message_column_binding(out, binding);
    }
    push_usize(out, value.trace_column_bindings.len());
    for binding in &value.trace_column_bindings {
        encode_symbt3_message_column_binding(out, binding);
    }
    push_usize(out, value.message_views.len());
    for view in &value.message_views {
        encode_symbt3_message_view_layout(out, view);
    }
}

fn encode_symbt3_message_semantic_layout(out: &mut Vec<u8>, value: &Symbt3MessageSemanticLayout) {
    out.extend_from_slice(value.version_marker);
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.round_count);
    push_usize(out, value.round_layouts.len());
    for round in &value.round_layouts {
        encode_symbt3_round_message_layout(out, round);
    }
    out.extend_from_slice(&value.challenge_schedule_version.to_le_bytes());
    out.extend_from_slice(&value.message_oracle_layout_digest);
    out.extend_from_slice(&value.algebra_law_digest);
    out.extend_from_slice(&value.gr1cs_layout_digest);
    out.extend_from_slice(&value.ajtai_layout_digest);
    out.extend_from_slice(&value.norm_range_layout_digest);
    out.extend_from_slice(&value.manifest_layout_digest);
    push_bytes(out, value.selector_evaluator.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    out.push(symbt3_message_semantic_mode_code(value.semantic_mode));
}

fn encode_symbt3_r1cs_evaluator_layout(out: &mut Vec<u8>, value: &Symbt3R1csEvaluatorLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_bytes(out, value.field_id.as_bytes());
    out.extend_from_slice(&value.modulus.to_le_bytes());
    push_usize(out, value.num_constraints);
    push_usize(out, value.num_variables);
    push_usize(out, value.num_public);
    push_usize(out, value.num_witness);
    match value.constant_one_wire_index {
        Some(idx) => {
            out.push(1);
            push_usize(out, idx);
        }
        None => out.push(0),
    }
    push_bytes(out, value.public_input_wire_layout.as_bytes());
    push_bytes(out, value.witness_wire_layout.as_bytes());
    push_bytes(out, value.sparse_encoding_format.as_bytes());
    push_bytes(out, value.row_ordering.as_bytes());
    push_bytes(out, value.column_ordering.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    push_bytes(out, value.coefficient_encoding.as_bytes());
    push_bytes(out, value.term_encoding.as_bytes());
    out.extend_from_slice(&value.evaluator_algorithm_id);
}

fn encode_symbt3_gr1cs_residual_layout(out: &mut Vec<u8>, value: &Symbt3Gr1csResidualLayout) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.folded_evaluation_coordinate_count);
    push_usize(out, value.tensor_rows);
    push_usize(out, value.ring_degree);
    push_bytes(out, value.grouping.as_bytes());
    push_bytes(out, value.coordinate_ordering.as_bytes());
    push_bytes(out, value.padding_policy.as_bytes());
    push_usize(out, value.component_kind_tags.len());
    for tag in &value.component_kind_tags {
        push_bytes(out, tag.as_bytes());
    }
}

fn encode_symbt3_algebra_law(out: &mut Vec<u8>, value: &Symbt3AlgebraLaw) {
    out.extend_from_slice(value.version_marker.as_slice());
    out.extend_from_slice(&value.law_version.to_le_bytes());
    push_bytes(out, value.check_field_id.as_bytes());
    push_bytes(out, value.coefficient_domain.as_bytes());
    push_usize(out, value.ring_degree);
    push_bytes(out, value.ring_relation.as_bytes());
    push_bytes(out, value.coefficient_basis.as_bytes());
    push_bytes(out, value.coefficient_order.as_bytes());
    push_bytes(out, value.reduction_policy.as_bytes());
    out.push(symbt3_beta_action_code(value.beta_action));
    out.push(symbt3_product_law_code(value.product_law));
    push_bytes(out, value.module_layout.as_bytes());
    push_bytes(out, value.soundness_profile.as_bytes());
    push_bytes(out, value.zk_profile.as_bytes());
}

fn encode_symbt3_folded_gr1cs_product_residual_layout(
    out: &mut Vec<u8>,
    value: &Symbt3FoldedGr1csProductResidualLayout,
) {
    out.extend_from_slice(&value.layout_version.to_le_bytes());
    push_usize(out, value.product_domain_log_size);
    push_bytes(out, value.equation_kind_axis.as_bytes());
    push_bytes(out, value.row_axis.as_bytes());
    push_usize(out, value.l_fold_column);
    push_usize(out, value.r_fold_column);
    push_usize(out, value.o_fold_column);
    push_bytes(out, value.selector_evaluator.as_bytes());
    out.push(symbt3_product_law_code(value.product_law));
    out.push(symbt3_beta_action_code(value.beta_action));
    push_bytes(out, value.padding_policy.as_bytes());
    push_bytes(out, value.check_field.as_bytes());
    push_bytes(out, value.soundness_profile.as_bytes());
}

fn encode_ring_matrix(out: &mut Vec<u8>, value: &[Vec<RingElement>]) {
    push_usize(out, value.len());
    for row in value {
        push_usize(out, row.len());
        for elem in row {
            encode_ring_element(out, elem);
        }
    }
}

fn encode_r1cs_matrices(out: &mut Vec<u8>, value: &R1CSMatrices) {
    push_usize(out, value.num_constraints);
    push_usize(out, value.num_variables);
    push_usize(out, value.num_public);
    encode_sparse_matrix(out, &value.a);
    encode_sparse_matrix(out, &value.b);
    encode_sparse_matrix(out, &value.c);
}

fn encode_tensor(out: &mut Vec<u8>, value: &crate::ring::tensor::TensorElement) {
    for row in &value.data {
        for &coeff in row {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

fn push_ext_vec(out: &mut Vec<u8>, values: &[crate::ring::extension::ExtFieldElement]) {
    push_usize(out, values.len());
    for value in values {
        out.extend_from_slice(&value.c0.to_le_bytes());
        out.extend_from_slice(&value.c1.to_le_bytes());
    }
}

fn push_i64_matrix(out: &mut Vec<u8>, values: &[Vec<i64>]) {
    push_usize(out, values.len());
    for row in values {
        push_i64_vec(out, row);
    }
}

fn push_digest_vec(out: &mut Vec<u8>, values: &[Digest32]) {
    push_usize(out, values.len());
    for value in values {
        out.extend_from_slice(value);
    }
}

fn push_i64_vec(out: &mut Vec<u8>, values: &[i64]) {
    push_usize(out, values.len());
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn push_usize_vec(out: &mut Vec<u8>, values: &[usize]) {
    push_usize(out, values.len());
    for &value in values {
        push_usize(out, value);
    }
}

fn push_nested_usize_vec(out: &mut Vec<u8>, values: &[Vec<usize>]) {
    push_usize(out, values.len());
    for row in values {
        push_usize_vec(out, row);
    }
}

fn push_gr1cs_message_sections(out: &mut Vec<u8>, values: &[Vec<BatchedCpGr1csMessageSection>]) {
    push_usize(out, values.len());
    for round in values {
        push_usize(out, round.len());
        for section in round {
            out.push(gr1cs_message_section_kind_code(&section.kind));
            push_usize(out, section.offset);
            push_usize(out, section.len);
        }
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_usize(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn push_usize(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

fn push_digest_scheme(out: &mut Vec<u8>, scheme: PublicDigestScheme) {
    let value = match scheme {
        PublicDigestScheme::Sha256 => 1u8,
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => 2u8,
    };
    out.push(value);
}

fn gr1cs_message_section_kind_code(kind: &BatchedCpGr1csMessageSectionKind) -> u8 {
    match kind {
        BatchedCpGr1csMessageSectionKind::Header => 1,
        BatchedCpGr1csMessageSectionKind::HadamardEvals => 2,
        BatchedCpGr1csMessageSectionKind::RangePayload => 3,
        BatchedCpGr1csMessageSectionKind::MonomialPayload => 4,
        BatchedCpGr1csMessageSectionKind::SquareEvals => 5,
        BatchedCpGr1csMessageSectionKind::ProjectedValues => 6,
        BatchedCpGr1csMessageSectionKind::TrailingFrame => 7,
    }
}

fn gr1cs_message_section_kind_from_code(code: u8) -> Option<BatchedCpGr1csMessageSectionKind> {
    Some(match code {
        1 => BatchedCpGr1csMessageSectionKind::Header,
        2 => BatchedCpGr1csMessageSectionKind::HadamardEvals,
        3 => BatchedCpGr1csMessageSectionKind::RangePayload,
        4 => BatchedCpGr1csMessageSectionKind::MonomialPayload,
        5 => BatchedCpGr1csMessageSectionKind::SquareEvals,
        6 => BatchedCpGr1csMessageSectionKind::ProjectedValues,
        7 => BatchedCpGr1csMessageSectionKind::TrailingFrame,
        _ => return None,
    })
}

fn push_known_statement_shape(
    bytes: &mut Vec<u8>,
    known: &mut Vec<bool>,
    shape: &BatchedCpStatementShape,
) {
    let mut encoded = Vec::new();
    encode_statement_shape(&mut encoded, shape);
    push_known_raw(bytes, known, &encoded);
}

fn push_known_bytes(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: &[u8]) {
    push_known_usize(bytes, known, value.len());
    push_known_raw(bytes, known, value);
}

fn push_private_bytes(bytes: &mut Vec<u8>, known: &mut Vec<bool>, len: usize) {
    push_known_usize(bytes, known, len);
    push_private_raw(bytes, known, len);
}

fn push_private_raw(bytes: &mut Vec<u8>, known: &mut Vec<bool>, len: usize) {
    bytes.extend(std::iter::repeat_n(0u8, len));
    known.extend(std::iter::repeat_n(false, len));
}

fn push_known_usize(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: usize) {
    push_known_raw(bytes, known, &(value as u64).to_le_bytes());
}

fn push_known_u8(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: u8) {
    bytes.push(value);
    known.push(true);
}

fn push_known_raw(bytes: &mut Vec<u8>, known: &mut Vec<bool>, value: &[u8]) {
    bytes.extend_from_slice(value);
    known.extend(std::iter::repeat_n(true, value.len()));
}

fn read_usize(bytes: &[u8], pos: &mut usize) -> Result<usize, BatchedCpError> {
    Ok(read_u64(bytes, pos)? as usize)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, BatchedCpError> {
    let end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let chunk = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos = end;
    Ok(u64::from_le_bytes(chunk.try_into().map_err(|_| {
        BatchedCpError::InvalidStructuredRelationContext
    })?))
}

fn read_usize_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<usize>, BatchedCpError> {
    let len = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_usize(bytes, pos)?);
    }
    Ok(out)
}

fn read_nested_usize_vec(bytes: &[u8], pos: &mut usize) -> Result<Vec<Vec<usize>>, BatchedCpError> {
    let len = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_usize_vec(bytes, pos)?);
    }
    Ok(out)
}

fn read_gr1cs_message_sections(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Vec<Vec<BatchedCpGr1csMessageSection>>, BatchedCpError> {
    let rounds = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let section_count = read_usize(bytes, pos)?;
        let mut sections = Vec::with_capacity(section_count);
        for _ in 0..section_count {
            let Some(&code) = bytes.get(*pos) else {
                return Err(BatchedCpError::InvalidStructuredRelationContext);
            };
            *pos += 1;
            let kind = gr1cs_message_section_kind_from_code(code)
                .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
            sections.push(BatchedCpGr1csMessageSection {
                kind,
                offset: read_usize(bytes, pos)?,
                len: read_usize(bytes, pos)?,
            });
        }
        out.push(sections);
    }
    Ok(out)
}

fn read_bytes(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, BatchedCpError> {
    let len = read_usize(bytes, pos)?;
    let end = pos
        .checked_add(len)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let value = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?
        .to_vec();
    *pos = end;
    Ok(value)
}

fn read_static_str(
    bytes: &[u8],
    pos: &mut usize,
    expected: &'static str,
) -> Result<&'static str, BatchedCpError> {
    let value = read_bytes(bytes, pos)?;
    if value == expected.as_bytes() {
        Ok(expected)
    } else {
        Err(BatchedCpError::InvalidSemanticRelationContext)
    }
}

fn read_digest(bytes: &[u8], pos: &mut usize) -> Result<Digest32, BatchedCpError> {
    let end = pos
        .checked_add(32)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let chunk = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos = end;
    chunk
        .try_into()
        .map_err(|_| BatchedCpError::InvalidStructuredRelationContext)
}

fn read_digest_scheme(bytes: &[u8], pos: &mut usize) -> Result<PublicDigestScheme, BatchedCpError> {
    let value = *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos += 1;
    match value {
        1 => Ok(PublicDigestScheme::Sha256),
        #[cfg(feature = "whir")]
        2 => Ok(PublicDigestScheme::Poseidon2BabyBear),
        _ => Err(BatchedCpError::InvalidStructuredRelationContext),
    }
}

fn read_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, BatchedCpError> {
    let end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    let chunk = bytes
        .get(*pos..end)
        .ok_or(BatchedCpError::InvalidStructuredRelationContext)?;
    *pos = end;
    Ok(i64::from_le_bytes(chunk.try_into().map_err(|_| {
        BatchedCpError::InvalidStructuredRelationContext
    })?))
}

fn read_ring_element(bytes: &[u8], pos: &mut usize) -> Result<RingElement, BatchedCpError> {
    let mut coeffs = [0i64; D];
    for coeff in &mut coeffs {
        *coeff = read_i64(bytes, pos)?;
    }
    Ok(RingElement { coeffs })
}

fn read_symbt3_ring_module_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RingModuleLayout, BatchedCpError> {
    let ring_degree = read_usize(bytes, pos)?;
    let modulus = read_u64(bytes, pos)?;
    let basis_order = read_static_str(bytes, pos, "coefficient-ascending")?;
    let negacyclic_sign_convention = read_static_str(bytes, pos, "x^D=-1")?;
    let action_side = match *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?
    {
        1 => Symbt3RingActionSide::Left,
        _ => return Err(BatchedCpError::InvalidSemanticRelationContext),
    };
    *pos += 1;
    let opening_module_dimension = read_usize(bytes, pos)?;
    let commitment_module_dimension = read_usize(bytes, pos)?;
    let coordinate_encoding = read_static_str(bytes, pos, "centered-i64-le")?;
    let beta_encoding = read_static_str(bytes, pos, "digest-base5-ring-coefficients")?;
    let ring_action_version = read_u64(bytes, pos)?;
    Ok(Symbt3RingModuleLayout {
        ring_degree,
        modulus,
        basis_order,
        negacyclic_sign_convention,
        action_side,
        opening_module_dimension,
        commitment_module_dimension,
        coordinate_encoding,
        beta_encoding,
        ring_action_version,
    })
}

fn read_symbt3_ajtai_commit_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AjtaiCommitLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let commitment_module_dimension = read_usize(bytes, pos)?;
    let opening_module_dimension = read_usize(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let modulus = read_u64(bytes, pos)?;
    let indexed_evaluator_id = read_digest(bytes, pos)?;
    let separated_message_randomness = match *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?
    {
        0 => false,
        1 => true,
        _ => return Err(BatchedCpError::InvalidSemanticRelationContext),
    };
    *pos += 1;
    Ok(Symbt3AjtaiCommitLayout {
        layout_version,
        commitment_module_dimension,
        opening_module_dimension,
        ring_degree,
        modulus,
        indexed_evaluator_id,
        separated_message_randomness,
    })
}

fn read_symbt3_ajtai_linear_algebra_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AjtaiLinearAlgebraLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3F\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let algebra_law_digest = read_digest(bytes, pos)?;
    let ajtai_matrix_digest = read_digest(bytes, pos)?;
    let ajtai_commit_layout_digest = read_digest(bytes, pos)?;
    let kappa = read_usize(bytes, pos)?;
    let opening_len = read_usize(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let source_opening_column = read_usize(bytes, pos)?;
    let source_commitment_column = read_usize(bytes, pos)?;
    let folded_opening_column = read_usize(bytes, pos)?;
    let folded_commitment_column = read_usize(bytes, pos)?;
    let beta_action = symbt3_beta_action_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let product_law = symbt3_product_law_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let matrix_vector_evaluator = symbt3_ajtai_matrix_vector_evaluator_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let selector_evaluator = read_static_str(bytes, pos, "prefix-active-item-selector-v1")?;
    let opening_mode = symbt3_ajtai_opening_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3AjtaiLinearAlgebraLayout {
        version_marker: b"SYMBT3F\0",
        layout_version,
        algebra_law_digest,
        ajtai_matrix_digest,
        ajtai_commit_layout_digest,
        kappa,
        opening_len,
        ring_degree,
        source_opening_column,
        source_commitment_column,
        folded_opening_column,
        folded_commitment_column,
        beta_action,
        product_law,
        matrix_vector_evaluator,
        padding_policy,
        selector_evaluator,
        opening_mode,
    })
}

fn read_optional_digest(bytes: &[u8], pos: &mut usize) -> Result<Option<Digest32>, BatchedCpError> {
    let tag = *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_digest(bytes, pos)?)),
        _ => Err(BatchedCpError::InvalidSemanticRelationContext),
    }
}

fn read_symbt3_projection_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3ProjectionLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let projection_mode = symbt3_projection_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let projection_seed_policy = symbt3_projection_seed_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let projection_matrix_digest = read_digest(bytes, pos)?;
    let input_len = read_usize(bytes, pos)?;
    let output_len = read_usize(bytes, pos)?;
    let block_len = read_usize(bytes, pos)?;
    let rows_per_block = read_usize(bytes, pos)?;
    let entry_distribution = symbt3_projection_entry_distribution_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let coefficient_domain = read_static_str(bytes, pos, "check-field-native-ring-coefficients")?;
    Ok(Symbt3ProjectionLayout {
        layout_version,
        projection_mode,
        projection_seed_policy,
        projection_matrix_digest,
        input_len,
        output_len,
        block_len,
        rows_per_block,
        entry_distribution,
        coefficient_domain,
    })
}

fn read_symbt3_monomial_embedding_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MonomialEmbeddingLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let bound_b = read_usize(bytes, pos)?;
    let table_polynomial_digest = read_digest(bytes, pos)?;
    let monomiality_mode = symbt3_monomiality_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let constant_term_policy = symbt3_constant_term_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let signed_convention = symbt3_signed_convention_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MonomialEmbeddingLayout {
        layout_version,
        ring_degree,
        bound_b,
        table_polynomial_digest,
        monomiality_mode,
        constant_term_policy,
        signed_convention,
    })
}

fn read_symbt3_representative_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RepresentativeLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let modulus_digest = read_digest(bytes, pos)?;
    let signed_range = read_i64(bytes, pos)?;
    let canonical_rep_policy = symbt3_canonical_rep_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3RepresentativeLayout {
        layout_version,
        modulus_digest,
        signed_range,
        canonical_rep_policy,
    })
}

fn read_symbt3_range_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RangeLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let range_mode = symbt3_range_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let bound_b = read_i64(bytes, pos)?;
    let signed_encoding = symbt3_signed_encoding_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let table_digest = read_optional_digest(bytes, pos)?;
    let monomial_embedding_layout_digest = read_optional_digest(bytes, pos)?;
    Ok(Symbt3RangeLayout {
        layout_version,
        range_mode,
        bound_b,
        signed_encoding,
        table_digest,
        monomial_embedding_layout_digest,
    })
}

fn read_symbt3_ajtai_norm_range_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AjtaiNormRangeLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3J\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let algebra_law_digest = read_digest(bytes, pos)?;
    let ajtai_linear_algebra_layout_digest = read_digest(bytes, pos)?;
    let folded_opening_column = read_usize(bytes, pos)?;
    let projected_opening_column = read_usize(bytes, pos)?;
    let monomial_witness_column = read_usize(bytes, pos)?;
    let projection_layout = read_symbt3_projection_layout(bytes, pos)?;
    let range_layout = read_symbt3_range_layout(bytes, pos)?;
    let monomial_embedding_layout = read_symbt3_monomial_embedding_layout(bytes, pos)?;
    let representative_layout = read_symbt3_representative_layout(bytes, pos)?;
    let norm_bound = read_i64(bytes, pos)?;
    let coefficient_encoding = symbt3_coefficient_encoding_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let reduction_policy = read_static_str(bytes, pos, "CheckFieldNativeV1")?;
    let selector_evaluator =
        read_static_str(bytes, pos, "valid-folded-opening-coordinate-selector-v1")?;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let range_mode = symbt3_range_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3AjtaiNormRangeLayout {
        version_marker: b"SYMBT3J\0",
        layout_version,
        algebra_law_digest,
        ajtai_linear_algebra_layout_digest,
        folded_opening_column,
        projected_opening_column,
        monomial_witness_column,
        projection_layout,
        range_layout,
        monomial_embedding_layout,
        representative_layout,
        norm_bound,
        coefficient_encoding,
        reduction_policy,
        selector_evaluator,
        padding_policy,
        range_mode,
    })
}

fn read_symbt3_manifest_oracle_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3ManifestOracleLayout, BatchedCpError> {
    Ok(Symbt3ManifestOracleLayout {
        layout_version: read_u64(bytes, pos)?,
        row_count: read_usize(bytes, pos)?,
        component_count: read_usize(bytes, pos)?,
        coordinate_count: read_usize(bytes, pos)?,
        coordinate_ordering: read_static_str(bytes, pos, "item-component-coordinate")?,
    })
}

fn read_symbt3_source_column_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3SourceColumnLayout, BatchedCpError> {
    Ok(Symbt3SourceColumnLayout {
        layout_version: read_u64(bytes, pos)?,
        component_count: read_usize(bytes, pos)?,
        coordinate_count: read_usize(bytes, pos)?,
        source_column_ordering: read_static_str(bytes, pos, "item-component-coordinate")?,
        root_binding_policy: read_static_str(bytes, pos, "digest-coordinate-boundary-v1")?,
    })
}

fn read_symbt3_manifest_component_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3ManifestComponentLayout, BatchedCpError> {
    let kind = symbt3_manifest_component_kind_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let coordinate_len = read_usize(bytes, pos)?;
    let source_column_id = read_usize(bytes, pos)?;
    let manifest_column_id = read_usize(bytes, pos)?;
    let visibility = symbt3_manifest_visibility_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let membership_mode = symbt3_membership_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3ManifestComponentLayout {
        kind,
        coordinate_len,
        source_column_id,
        manifest_column_id,
        visibility,
        membership_mode,
        padding_policy: read_static_str(bytes, pos, "selector-zero-padded-tail")?,
    })
}

fn read_symbt3_batch_manifest_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3BatchManifestLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3H\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let batch_size = read_usize(bytes, pos)?;
    let active_count = read_usize(bytes, pos)?;
    let active_policy = symbt3_active_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let manifest_oracle_layout = read_symbt3_manifest_oracle_layout(bytes, pos)?;
    let source_column_layout = read_symbt3_source_column_layout(bytes, pos)?;
    let component_count = read_usize(bytes, pos)?;
    let mut component_kinds = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        component_kinds.push(read_symbt3_manifest_component_layout(bytes, pos)?);
    }
    let commitment_scheme_id = symbt3_commitment_scheme_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let manifest_root_policy = symbt3_manifest_root_policy_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3BatchManifestLayout {
        version_marker: b"SYMBT3H\0",
        layout_version,
        batch_size,
        active_count,
        active_policy,
        manifest_oracle_layout,
        source_column_layout,
        component_kinds,
        commitment_scheme_id,
        manifest_root_policy,
        selector_evaluator: read_static_str(
            bytes,
            pos,
            "prefix-active-valid-component-selector-v1",
        )?,
        padding_policy: read_static_str(bytes, pos, "selector-zero-padded-tail")?,
    })
}

fn read_symbt3_message_section_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageSectionLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let section_kind = symbt3_message_section_kind_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let coordinate_offset = read_usize(bytes, pos)?;
    let coordinate_len = read_usize(bytes, pos)?;
    let algebra_type = symbt3_message_algebra_type_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let visibility = symbt3_message_visibility_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let binding_mode = symbt3_message_binding_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MessageSectionLayout {
        layout_version,
        section_kind,
        coordinate_offset,
        coordinate_len,
        algebra_type,
        visibility,
        binding_mode,
    })
}

fn read_symbt3_message_column_binding(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageColumnBinding, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let round_index = read_usize(bytes, pos)?;
    let message_coordinate_offset = read_usize(bytes, pos)?;
    let trace_column_id = read_usize(bytes, pos)?;
    let trace_coordinate_offset = read_usize(bytes, pos)?;
    let coordinate_len = read_usize(bytes, pos)?;
    let binding_mode = symbt3_message_binding_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MessageColumnBinding {
        layout_version,
        round_index,
        message_coordinate_offset,
        trace_column_id,
        trace_coordinate_offset,
        coordinate_len,
        binding_mode,
    })
}

fn read_symbt3_message_coordinate_map(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageCoordinateMap, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let mode = symbt3_message_coordinate_map_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let message_coordinate_offset = read_usize(bytes, pos)?;
    let coordinate_len = read_usize(bytes, pos)?;
    Ok(Symbt3MessageCoordinateMap {
        layout_version,
        mode,
        message_coordinate_offset,
        coordinate_len,
    })
}

fn read_symbt3_message_view_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageViewLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let round = read_usize(bytes, pos)?;
    let trace_kind = symbt3_trace_kind_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let trace_coordinate_axis = read_static_str(bytes, pos, "item-packed-message-coordinate")?;
    let message_coordinate_map = read_symbt3_message_coordinate_map(bytes, pos)?;
    let algebra_type = symbt3_message_algebra_type_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    Ok(Symbt3MessageViewLayout {
        layout_version,
        round,
        trace_kind,
        trace_coordinate_axis,
        message_coordinate_map,
        algebra_type,
        padding_policy,
    })
}

fn read_symbt3_round_message_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3RoundMessageLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let round_index = read_usize(bytes, pos)?;
    let row_count = read_usize(bytes, pos)?;
    let message_len = read_usize(bytes, pos)?;
    let packed_field_len = read_usize(bytes, pos)?;
    let coordinate_axis = read_static_str(bytes, pos, "item-packed-message-coordinate")?;
    let section_axis = read_static_str(bytes, pos, "typed-round-message-section")?;
    let section_count = read_usize(bytes, pos)?;
    let mut sections = Vec::with_capacity(section_count);
    for _ in 0..section_count {
        sections.push(read_symbt3_message_section_layout(bytes, pos)?);
    }
    let source_binding_count = read_usize(bytes, pos)?;
    let mut source_column_bindings = Vec::with_capacity(source_binding_count);
    for _ in 0..source_binding_count {
        source_column_bindings.push(read_symbt3_message_column_binding(bytes, pos)?);
    }
    let trace_binding_count = read_usize(bytes, pos)?;
    let mut trace_column_bindings = Vec::with_capacity(trace_binding_count);
    for _ in 0..trace_binding_count {
        trace_column_bindings.push(read_symbt3_message_column_binding(bytes, pos)?);
    }
    let message_view_count = read_usize(bytes, pos)?;
    let mut message_views = Vec::with_capacity(message_view_count);
    for _ in 0..message_view_count {
        message_views.push(read_symbt3_message_view_layout(bytes, pos)?);
    }
    Ok(Symbt3RoundMessageLayout {
        layout_version,
        round_index,
        row_count,
        message_len,
        packed_field_len,
        coordinate_axis,
        section_axis,
        sections,
        source_column_bindings,
        trace_column_bindings,
        message_views,
    })
}

fn read_symbt3_message_semantic_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3MessageSemanticLayout, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3I\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let layout_version = read_u64(bytes, pos)?;
    let round_count = read_usize(bytes, pos)?;
    let round_layout_count = read_usize(bytes, pos)?;
    let mut round_layouts = Vec::with_capacity(round_layout_count);
    for _ in 0..round_layout_count {
        round_layouts.push(read_symbt3_round_message_layout(bytes, pos)?);
    }
    let challenge_schedule_version = read_u64(bytes, pos)?;
    let message_oracle_layout_digest = read_digest(bytes, pos)?;
    let algebra_law_digest = read_digest(bytes, pos)?;
    let gr1cs_layout_digest = read_digest(bytes, pos)?;
    let ajtai_layout_digest = read_digest(bytes, pos)?;
    let norm_range_layout_digest = read_digest(bytes, pos)?;
    let manifest_layout_digest = read_digest(bytes, pos)?;
    let selector_evaluator =
        read_static_str(bytes, pos, "prefix-active-message-coordinate-selector-v1")?;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let semantic_mode = symbt3_message_semantic_mode_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    Ok(Symbt3MessageSemanticLayout {
        version_marker: b"SYMBT3I\0",
        layout_version,
        round_count,
        round_layouts,
        challenge_schedule_version,
        message_oracle_layout_digest,
        algebra_law_digest,
        gr1cs_layout_digest,
        ajtai_layout_digest,
        norm_range_layout_digest,
        manifest_layout_digest,
        selector_evaluator,
        padding_policy,
        semantic_mode,
    })
}

fn read_optional_usize(bytes: &[u8], pos: &mut usize) -> Result<Option<usize>, BatchedCpError> {
    let tag = *bytes
        .get(*pos)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(read_usize(bytes, pos)?)),
        _ => Err(BatchedCpError::InvalidSemanticRelationContext),
    }
}

fn read_symbt3_r1cs_evaluator_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3R1csEvaluatorLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let field_id = read_static_str(bytes, pos, "BabyBear")?;
    let modulus = read_u64(bytes, pos)?;
    let num_constraints = read_usize(bytes, pos)?;
    let num_variables = read_usize(bytes, pos)?;
    let num_public = read_usize(bytes, pos)?;
    let num_witness = read_usize(bytes, pos)?;
    let constant_one_wire_index = read_optional_usize(bytes, pos)?;
    let public_input_wire_layout = read_static_str(bytes, pos, "public-prefix-constant-ring")?;
    let witness_wire_layout = read_static_str(bytes, pos, "witness-suffix-ring-coefficients")?;
    let sparse_encoding_format = read_static_str(bytes, pos, "coo-row-col-i64-v1")?;
    let row_ordering = read_static_str(bytes, pos, "ascending-row-index")?;
    let column_ordering = read_static_str(bytes, pos, "ascending-column-index")?;
    let padding_policy = read_static_str(bytes, pos, "zero-pad-to-power-of-two")?;
    let coefficient_encoding = read_static_str(bytes, pos, "centered-i64-le")?;
    let term_encoding = read_static_str(bytes, pos, "babybear-linear-form-v1")?;
    let evaluator_algorithm_id = read_digest(bytes, pos)?;
    Ok(Symbt3R1csEvaluatorLayout {
        layout_version,
        field_id,
        modulus,
        num_constraints,
        num_variables,
        num_public,
        num_witness,
        constant_one_wire_index,
        public_input_wire_layout,
        witness_wire_layout,
        sparse_encoding_format,
        row_ordering,
        column_ordering,
        padding_policy,
        coefficient_encoding,
        term_encoding,
        evaluator_algorithm_id,
    })
}

fn read_symbt3_gr1cs_residual_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3Gr1csResidualLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let folded_evaluation_coordinate_count = read_usize(bytes, pos)?;
    let tensor_rows = read_usize(bytes, pos)?;
    let ring_degree = read_usize(bytes, pos)?;
    let grouping = read_static_str(bytes, pos, "triples-left-right-output")?;
    let coordinate_ordering = read_static_str(bytes, pos, "evaluation-index-tensor-row-coeff")?;
    let padding_policy = read_static_str(bytes, pos, "ignore-incomplete-trailing-triple")?;
    let tag_len = read_usize(bytes, pos)?;
    let mut component_kind_tags = Vec::with_capacity(tag_len);
    for expected in ["left", "right", "output"] {
        component_kind_tags.push(read_static_str(bytes, pos, expected)?);
    }
    if tag_len != component_kind_tags.len() {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    Ok(Symbt3Gr1csResidualLayout {
        layout_version,
        folded_evaluation_coordinate_count,
        tensor_rows,
        ring_degree,
        grouping,
        coordinate_ordering,
        padding_policy,
        component_kind_tags,
    })
}

fn read_symbt3_algebra_law(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3AlgebraLaw, BatchedCpError> {
    let marker_end = pos
        .checked_add(8)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    let marker = bytes
        .get(*pos..marker_end)
        .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    if marker != b"SYMBT3E\0" {
        return Err(BatchedCpError::InvalidSemanticRelationContext);
    }
    *pos = marker_end;
    let law_version = read_u64(bytes, pos)?;
    let check_field_id = read_static_str(bytes, pos, "BabyBear")?;
    let coefficient_domain = read_static_str(bytes, pos, "check-field-native-ring")?;
    let ring_degree = read_usize(bytes, pos)?;
    let ring_relation = read_static_str(bytes, pos, "X^D+1")?;
    let coefficient_basis = read_static_str(bytes, pos, "coefficient-ascending")?;
    let coefficient_order = read_static_str(bytes, pos, "little-endian")?;
    let reduction_policy = read_static_str(bytes, pos, "CheckFieldNativeV1")?;
    let beta_action = symbt3_beta_action_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let product_law = symbt3_product_law_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let module_layout = read_static_str(bytes, pos, "coordinatewise-ring-module")?;
    let soundness_profile = read_static_str(
        bytes,
        pos,
        "NonAuthoritativeDevelopmentBaseFieldSingleCheck",
    )?;
    let zk_profile = read_static_str(bytes, pos, "NonZkDevelopment")?;
    Ok(Symbt3AlgebraLaw {
        version_marker: b"SYMBT3E\0",
        law_version,
        check_field_id,
        coefficient_domain,
        ring_degree,
        ring_relation,
        coefficient_basis,
        coefficient_order,
        reduction_policy,
        beta_action,
        product_law,
        module_layout,
        soundness_profile,
        zk_profile,
    })
}

fn read_symbt3_folded_gr1cs_product_residual_layout(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Symbt3FoldedGr1csProductResidualLayout, BatchedCpError> {
    let layout_version = read_u64(bytes, pos)?;
    let product_domain_log_size = read_usize(bytes, pos)?;
    let equation_kind_axis = read_static_str(bytes, pos, "folded-gr1cs-left-right-output")?;
    let row_axis = read_static_str(bytes, pos, "evaluation-index-tensor-row-coeff")?;
    let l_fold_column = read_usize(bytes, pos)?;
    let r_fold_column = read_usize(bytes, pos)?;
    let o_fold_column = read_usize(bytes, pos)?;
    let selector_evaluator = read_static_str(bytes, pos, "prefix-valid-coordinate-selector-v1")?;
    let product_law = symbt3_product_law_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let beta_action = symbt3_beta_action_from_code(
        *bytes
            .get(*pos)
            .ok_or(BatchedCpError::InvalidSemanticRelationContext)?,
    )
    .ok_or(BatchedCpError::InvalidSemanticRelationContext)?;
    *pos += 1;
    let padding_policy = read_static_str(bytes, pos, "selector-zero-padded-tail")?;
    let check_field = read_static_str(bytes, pos, "BabyBear")?;
    let soundness_profile = read_static_str(
        bytes,
        pos,
        "NonAuthoritativeDevelopmentBaseFieldSingleCheck",
    )?;
    Ok(Symbt3FoldedGr1csProductResidualLayout {
        layout_version,
        product_domain_log_size,
        equation_kind_axis,
        row_axis,
        l_fold_column,
        r_fold_column,
        o_fold_column,
        selector_evaluator,
        product_law,
        beta_action,
        padding_policy,
        check_field,
        soundness_profile,
    })
}

fn read_ring_matrix(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Vec<Vec<RingElement>>, BatchedCpError> {
    let rows = read_usize(bytes, pos)?;
    let mut out = Vec::with_capacity(rows);
    for _ in 0..rows {
        let cols = read_usize(bytes, pos)?;
        let mut row = Vec::with_capacity(cols);
        for _ in 0..cols {
            row.push(read_ring_element(bytes, pos)?);
        }
        out.push(row);
    }
    Ok(out)
}

fn read_sparse_matrix(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<crate::r1cs::SparseMatrix, BatchedCpError> {
    let num_rows = read_usize(bytes, pos)?;
    let num_cols = read_usize(bytes, pos)?;
    let entries_len = read_usize(bytes, pos)?;
    let mut matrix = crate::r1cs::SparseMatrix::new(num_rows, num_cols);
    for _ in 0..entries_len {
        let row = read_usize(bytes, pos)?;
        let col = read_usize(bytes, pos)?;
        let coeff = read_i64(bytes, pos)?;
        if row >= num_rows || col >= num_cols {
            return Err(BatchedCpError::InvalidStructuredRelationContext);
        }
        matrix.insert(row, col, coeff);
    }
    Ok(matrix)
}

fn read_r1cs_matrices(bytes: &[u8], pos: &mut usize) -> Result<R1CSMatrices, BatchedCpError> {
    let num_constraints = read_usize(bytes, pos)?;
    let num_variables = read_usize(bytes, pos)?;
    let num_public = read_usize(bytes, pos)?;
    let a = read_sparse_matrix(bytes, pos)?;
    let b = read_sparse_matrix(bytes, pos)?;
    let c = read_sparse_matrix(bytes, pos)?;
    if a.num_rows != num_constraints
        || b.num_rows != num_constraints
        || c.num_rows != num_constraints
        || a.num_cols != num_variables
        || b.num_cols != num_variables
        || c.num_cols != num_variables
    {
        return Err(BatchedCpError::InvalidStructuredRelationContext);
    }
    Ok(R1CSMatrices {
        a,
        b,
        c,
        num_constraints,
        num_variables,
        num_public,
    })
}
