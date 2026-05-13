fn typed_gr1cs_message_shape(
    proof: &GR1CSProof,
    expected_message_len: usize,
) -> Option<TypedCpGr1csMessageShape> {
    if crate::snark::cp_snark::encode_gr1cs_round_message(proof).len() != expected_message_len {
        return None;
    }
    let hadamard_sumcheck_round_evals = proof
        .hadamard_proof
        .sumcheck_proof
        .round_messages
        .iter()
        .map(|round| round.evaluations.len())
        .collect::<Vec<_>>();
    let hadamard_eval_matrix_rows = proof
        .hadamard_proof
        .evaluation_matrix
        .iter()
        .map(|te| te.data.len())
        .collect::<Vec<_>>();
    let range = TypedCpRangeMessageShape {
        monomial_commitment_elem_lens: proof
            .range_proof
            .monomial_commitments
            .iter()
            .map(|commitment| commitment.value.elements.len())
            .collect(),
        monomial_vector_lens: proof
            .range_proof
            .monomial_vectors
            .iter()
            .map(Vec::len)
            .collect(),
        monomial_sumcheck_round_evals: proof
            .range_proof
            .monomial_proof
            .sumcheck_proof
            .round_messages
            .iter()
            .map(|round| round.evaluations.len())
            .collect(),
        monomial_evaluation_rows: proof
            .range_proof
            .monomial_proof
            .evaluations
            .iter()
            .map(|te| te.data.len())
            .collect(),
        sq_evaluations_count: proof.range_proof.monomial_proof.sq_evaluations.len(),
        projected_values_count: proof.range_proof.projected_values.len(),
    };
    Some(TypedCpGr1csMessageShape {
        hadamard_sumcheck_round_evals,
        hadamard_eval_matrix_rows,
        range: Some(range),
    })
}

fn gr1cs_range_message_shape_constraints_count(shape: &TypedCpRangeMessageShape) -> usize {
    8 * (6
        + shape.monomial_commitment_elem_lens.len()
        + shape.monomial_vector_lens.len()
        + shape.monomial_sumcheck_round_evals.len())
}

fn insert_gr1cs_range_message_shape_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    message_byte_col: usize,
    message_shape: &TypedCpGr1csMessageShape,
    range_shape: &TypedCpRangeMessageShape,
    message_len: usize,
) -> usize {
    let mut offset = gr1cs_hadamard_section_len(message_shape);

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_commitment_elem_lens.len() as u64,
    );
    offset += 8;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + offset, elem_len as u64);
        offset += commitment_message_len(elem_len);
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_vector_lens.len() as u64,
    );
    offset += 8;
    for &vector_len in &range_shape.monomial_vector_lens {
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + offset, vector_len as u64);
        offset += 8 + vector_len * D * 8;
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_sumcheck_round_evals.len() as u64,
    );
    offset += 8;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + offset, eval_count as u64);
        offset += 8 + eval_count * 2 * 8;
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_evaluation_rows.len() as u64,
    );
    offset += 8;
    for &rows in &range_shape.monomial_evaluation_rows {
        offset += rows * D * 8;
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.sq_evaluations_count as u64,
    );
    offset += 8 + range_shape.sq_evaluations_count * 2 * 8;

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.projected_values_count as u64,
    );
    offset += 8 + range_shape.projected_values_count * 8;

    debug_assert_eq!(offset, message_len);
    row
}

fn gr1cs_projected_values_payload_offset(
    message_shape: &TypedCpGr1csMessageShape,
    range_shape: &TypedCpRangeMessageShape,
) -> usize {
    let mut offset = gr1cs_hadamard_section_len(message_shape);

    offset += 8;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        offset += commitment_message_len(elem_len);
    }

    offset += 8;
    for &vector_len in &range_shape.monomial_vector_lens {
        offset += 8 + vector_len * D * 8;
    }

    offset += 8;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        offset += 8 + eval_count * 2 * 8;
    }

    offset += 8;
    for &rows in &range_shape.monomial_evaluation_rows {
        offset += rows * D * 8;
    }

    offset += 8 + range_shape.sq_evaluations_count * 2 * 8;
    offset + 8
}

fn insert_gr1cs_range_payload_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    message_byte_col: usize,
    message_bit_col: usize,
    message_shape: &TypedCpGr1csMessageShape,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
) -> usize {
    assert_eq!(
        payload.monomial_commitment_coeffs_count,
        range_shape
            .monomial_commitment_elem_lens
            .iter()
            .map(|&elem_len| elem_len * D)
            .sum::<usize>()
    );
    assert_eq!(
        payload.monomial_vector_coeffs_count,
        range_shape
            .monomial_vector_lens
            .iter()
            .map(|&vector_len| vector_len * D)
            .sum::<usize>()
    );
    assert_eq!(
        payload.monomial_vector_elements_count,
        range_shape.monomial_vector_lens.iter().sum::<usize>()
    );
    assert_eq!(
        payload.monomial_sumcheck_evaluation_coeffs_count,
        range_shape
            .monomial_sumcheck_round_evals
            .iter()
            .map(|&eval_count| eval_count * 2)
            .sum::<usize>()
    );
    assert_eq!(
        payload.monomial_evaluation_coeffs_count,
        range_shape
            .monomial_evaluation_rows
            .iter()
            .map(|&rows| rows * D)
            .sum::<usize>()
    );
    assert_eq!(
        payload.sq_evaluation_coeffs_count,
        range_shape.sq_evaluations_count * 2
    );
    assert_eq!(
        payload.projected_values_count,
        range_shape.projected_values_count
    );

    let mut offset = gr1cs_hadamard_section_len(message_shape);
    let mut var_offset = 0;

    offset += 8;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        offset += 8;
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_commitments + var_offset,
            elem_len * D,
        );
        var_offset += elem_len * D;
        offset += elem_len * D * 8;
    }
    debug_assert_eq!(var_offset, payload.monomial_commitment_coeffs_count);

    offset += 8;
    var_offset = 0;
    for &vector_len in &range_shape.monomial_vector_lens {
        offset += 8;
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_vectors + var_offset,
            vector_len * D,
        );
        var_offset += vector_len * D;
        offset += vector_len * D * 8;
    }
    debug_assert_eq!(var_offset, payload.monomial_vector_coeffs_count);

    offset += 8;
    var_offset = 0;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        offset += 8;
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_sumcheck_evaluations + var_offset,
            eval_count * 2,
        );
        var_offset += eval_count * 2;
        offset += eval_count * 2 * 8;
    }
    debug_assert_eq!(
        var_offset,
        payload.monomial_sumcheck_evaluation_coeffs_count
    );

    offset += 8;
    var_offset = 0;
    for &rows in &range_shape.monomial_evaluation_rows {
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_evaluations + var_offset,
            rows * D,
        );
        var_offset += rows * D;
        offset += rows * D * 8;
    }
    debug_assert_eq!(var_offset, payload.monomial_evaluation_coeffs_count);

    offset += 8;
    row = insert_i64_payload_bytes_equal_vars(
        r1cs,
        row,
        message_byte_col,
        message_bit_col,
        offset,
        payload.off_sq_evaluations,
        payload.sq_evaluation_coeffs_count,
    );
    offset += payload.sq_evaluation_coeffs_count * 8;

    offset += 8;
    debug_assert_eq!(
        offset,
        gr1cs_projected_values_payload_offset(message_shape, range_shape)
    );
    for idx in 0..payload.projected_values_count {
        let offset = offset + idx * 8;
        row = insert_i64_limb_bytes_equal_var(
            r1cs,
            row,
            message_byte_col + offset,
            message_bit_col + (offset + 7) * 8 + 7,
            payload.off_projected_values + idx,
        );
    }
    row
}

fn insert_i64_payload_bytes_equal_vars(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    message_byte_col: usize,
    message_bit_col: usize,
    payload_byte_offset: usize,
    var_col: usize,
    count: usize,
) -> usize {
    for idx in 0..count {
        let offset = payload_byte_offset + idx * 8;
        row = insert_i64_limb_bytes_equal_var(
            r1cs,
            row,
            message_byte_col + offset,
            message_bit_col + (offset + 7) * 8 + 7,
            var_col + idx,
        );
    }
    row
}

fn insert_gr1cs_range_semantic_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    ajtai: &crate::commitment::AjtaiParams,
) -> usize {
    assert_eq!(
        payload.monomial_vector_coeffs_count,
        payload.monomial_vector_elements_count * D
    );

    row = insert_monomial_commitment_opening_constraints(r1cs, row, range_shape, payload, ajtai);

    for coeff_idx in 0..payload.monomial_vector_coeffs_count {
        let coeff_col = payload.off_monomial_vectors + coeff_idx;
        let square_col = payload.off_monomial_vector_squares + coeff_idx;
        r1cs.a.insert(row, coeff_col, 1);
        r1cs.b.insert(row, coeff_col, 1);
        r1cs.c.insert(row, square_col, 1);
        row += 1;
    }

    let mut vector_coeff_offset = 0usize;
    for &vector_len in &range_shape.monomial_vector_lens {
        for elem_idx in 0..vector_len {
            let square_start =
                payload.off_monomial_vector_squares + vector_coeff_offset + elem_idx * D;
            for coeff in 0..D {
                r1cs.a.insert(row, square_start + coeff, 1);
                r1cs.b.insert(row, square_start + coeff, 1);
            }
            r1cs.b.insert(row, 0, -1);
            row += 1;
        }
        vector_coeff_offset += vector_len * D;
    }

    for projected_idx in 0..payload.projected_values_count {
        r1cs.a
            .insert(row, payload.off_projected_values + projected_idx, 1);

        let mut coeff_offset = 0usize;
        let mut d_power = 1i128;
        for &vector_len in &range_shape.monomial_vector_lens {
            if projected_idx < vector_len {
                let elem_start = payload.off_monomial_vectors + coeff_offset + projected_idx * D;
                for coeff in 0..D {
                    let weight = monomial_digit_weight(coeff) as i128;
                    if weight != 0 {
                        r1cs.a
                            .insert(row, elem_start + coeff, centered_i128(-d_power * weight));
                    }
                }
            }
            coeff_offset += vector_len * D;
            d_power *= typed_range_d_prime() as i128;
        }
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }

    row = insert_monomial_sumcheck_semantic_constraints(r1cs, row, range_shape, payload, ajtai.q);

    row
}

fn insert_monomial_commitment_opening_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    ajtai: &crate::commitment::AjtaiParams,
) -> usize {
    assert_eq!(
        range_shape.monomial_commitment_elem_lens.len(),
        range_shape.monomial_vector_lens.len(),
        "each monomial vector must have one commitment"
    );

    let mut commitment_coeff_offset = 0usize;
    let mut vector_coeff_offset = 0usize;
    for (&commitment_len, &vector_len) in range_shape
        .monomial_commitment_elem_lens
        .iter()
        .zip(range_shape.monomial_vector_lens.iter())
    {
        assert_eq!(
            commitment_len, ajtai.kappa,
            "monomial commitment must use the parent kappa"
        );
        let mon_ajtai = crate::commitment::AjtaiParams::setup_deterministic(
            ajtai.kappa,
            vector_len,
            ajtai.q,
            &ajtai.ntt,
            b"range-proof-monomial",
        );
        for commitment_row in 0..mon_ajtai.kappa {
            for coeff in 0..D {
                for col in 0..mon_ajtai.n {
                    let a = &mon_ajtai.a[commitment_row][col];
                    for a_coeff in 0..D {
                        let (w_coeff, sign) = negacyclic_partner(coeff, a_coeff);
                        let z_col =
                            payload.off_monomial_vectors + vector_coeff_offset + col * D + w_coeff;
                        r1cs.a.insert(
                            row,
                            z_col,
                            centered_mod(sign * a.coeffs[a_coeff] as i128, BB_P),
                        );
                    }
                }
                r1cs.a.insert(
                    row,
                    payload.off_monomial_commitments + commitment_coeff_offset,
                    -1,
                );
                r1cs.a.insert(
                    row,
                    payload.off_monomial_commitment_wraps + commitment_coeff_offset,
                    -(ajtai.q as i64),
                );
                r1cs.b.insert(row, 0, 1);
                row += 1;
                commitment_coeff_offset += 1;
            }
        }
        vector_coeff_offset += vector_len * D;
    }
    debug_assert_eq!(
        commitment_coeff_offset,
        payload.monomial_commitment_coeffs_count
    );
    debug_assert_eq!(vector_coeff_offset, payload.monomial_vector_coeffs_count);
    row
}
