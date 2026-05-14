fn circuit_permutation(
    builder: &mut Builder,
    constants: &Poseidon2Constants,
    state: &mut [Lin; WIDTH],
) {
    circuit_mds_light(state);
    for round in &constants.external_initial {
        for i in 0..WIDTH {
            state[i] = builder.sbox7(state[i].add(&Lin::constant(builder.one, round[i])));
        }
        circuit_mds_light(state);
    }
    for &rc in &constants.internal {
        state[0] = builder.sbox7(state[0].add(&Lin::constant(builder.one, rc)));
        circuit_internal_linear(state);
    }
    for round in &constants.external_terminal {
        for i in 0..WIDTH {
            state[i] = builder.sbox7(state[i].add(&Lin::constant(builder.one, round[i])));
        }
        circuit_mds_light(state);
    }
}

fn insert_ajtai_opening_lc(
    r1cs: &mut R1CSMatrices,
    row: usize,
    layout: &OriginalStatementR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    commitment_row: usize,
    coeff: usize,
) {
    for col in 0..ajtai.n {
        let a = &ajtai.a[commitment_row][col];
        if col < layout.n_public {
            let public_col = layout.off_public_input + col;
            r1cs.a
                .insert(row, public_col, centered_mod(a.coeffs[coeff] as i128, BB_P));
        } else {
            let witness_col = col - layout.n_public;
            for a_coeff in 0..D {
                let (w_coeff, sign) = negacyclic_partner(coeff, a_coeff);
                let z_col = layout.off_witness + witness_col * D + w_coeff;
                r1cs.a.insert(
                    row,
                    z_col,
                    centered_mod(sign * a.coeffs[a_coeff] as i128, BB_P),
                );
            }
        }
    }
    let commitment_col = layout.off_commitment + commitment_row * D + coeff;
    r1cs.a.insert(row, commitment_col, -1);
    let wrap_col = layout.off_ajtai_wrap + commitment_row * D + coeff;
    r1cs.a.insert(row, wrap_col, -(ajtai.q as i64));
    r1cs.b.insert(row, layout.off_one, 1);
}

fn copy_r1cs_block(
    target: &mut R1CSMatrices,
    source: &R1CSMatrices,
    row_offset: usize,
    col_map: &dyn Fn(usize) -> usize,
) {
    for &(row, col, value) in &source.a.entries {
        target.a.insert(row_offset + row, col_map(col), value);
    }
    for &(row, col, value) in &source.b.entries {
        target.b.insert(row_offset + row, col_map(col), value);
    }
    for &(row, col, value) in &source.c.entries {
        target.c.insert(row_offset + row, col_map(col), value);
    }
}

fn insert_digest_body_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    _domain: &[u8],
    block: &TypedCpDigestBlockLayout,
) -> usize {
    for byte_idx in 0..block.body_len {
        let byte_col = block.off_body_bytes + byte_idx;
        r1cs.a.insert(row, byte_col, 1);
        for bit in 0..8 {
            let bit_col = block.off_body_bits + byte_idx * 8 + bit;
            r1cs.a.insert(row, bit_col, -(1i64 << bit));
        }
        r1cs.b.insert(row, 0, 1);
        row += 1;

        for bit in 0..8 {
            let bit_col = block.off_body_bits + byte_idx * 8 + bit;
            r1cs.a.insert(row, bit_col, 1);
            r1cs.b.insert(row, bit_col, 1);
            r1cs.b.insert(row, 0, -1);
            row += 1;
        }
    }

    row
}

fn insert_fs_root_commitment_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    fs_commitment_blocks: &[TypedCpDigestBlockLayout],
    fs_root_block: &TypedCpDigestBlockLayout,
) -> usize {
    let num_commitments = fs_commitment_blocks.len();
    let expected_body_len = 8 + num_commitments * (8 + OUT * 4);
    assert_eq!(fs_root_block.body_len, expected_body_len);

    for commitment_idx in 0..num_commitments {
        let body_commitment_offset = 8 + commitment_idx * (8 + OUT * 4) + 8;
        for limb in 0..OUT {
            let commitment_limb_col = fs_commitment_blocks[commitment_idx].off_public_output + limb;
            let body_byte_col = fs_root_block.off_body_bytes + body_commitment_offset + limb * 4;
            r1cs.a.insert(row, commitment_limb_col, 1);
            r1cs.a.insert(row, body_byte_col, -1);
            r1cs.a.insert(row, body_byte_col + 1, -256);
            r1cs.a.insert(row, body_byte_col + 2, -65_536);
            r1cs.a.insert(row, body_byte_col + 3, -16_777_216);
            r1cs.b.insert(row, 0, 1);
            row += 1;
        }
    }
    row
}

fn structured_digest_body_constraints_count(
    lengths: &TypedCpDigestInputLengths,
    cp_layout: &CpR1csLayout,
    original_r1cs_num_constraints: usize,
    original_r1cs_num_variables: usize,
) -> usize {
    let ell = lengths.fs_commitment_inputs.len();
    let msg_bytes: usize = lengths.gr1cs_message_bodies.iter().sum();
    let fold_commit_limb_constraints = ell * cp_layout.kappa * cp_layout.d;
    let fold_public_input_constraints = ell * cp_layout.n_in;
    let transcript_public_input_constraints = ell * cp_layout.n_in;
    let challenge_output_constraints = ell * OUT;
    let challenge_transcript_public_input_constraints = ell * ell * cp_layout.n_in;
    let challenge_transcript_fs_commitment_constraints = ell * ell * OUT;
    let gr1cs_hadamard_constraints: usize = lengths
        .gr1cs_message_bodies
        .iter()
        .filter(|&&msg_len| msg_len >= gr1cs_hadamard_message_prefix_len(cp_layout))
        .map(|_| gr1cs_hadamard_message_constraints_count(cp_layout))
        .sum();
    let gr1cs_range_shape_constraints: usize = lengths
        .gr1cs_message_shapes
        .iter()
        .filter_map(|shape| shape.range.as_ref())
        .map(gr1cs_range_message_shape_constraints_count)
        .sum();
    let gr1cs_projected_value_payload_constraints: usize = lengths
        .gr1cs_message_shapes
        .iter()
        .filter_map(|shape| shape.range.as_ref())
        .map(|shape| {
            shape
                .monomial_commitment_elem_lens
                .iter()
                .map(|&elem_len| elem_len * D)
                .sum::<usize>()
                + shape
                    .monomial_vector_lens
                    .iter()
                    .map(|&vector_len| vector_len * D)
                    .sum::<usize>()
                + shape
                    .monomial_sumcheck_round_evals
                    .iter()
                    .map(|&eval_count| eval_count * 2)
                    .sum::<usize>()
                + shape
                    .monomial_evaluation_rows
                    .iter()
                    .map(|&rows| rows * D)
                    .sum::<usize>()
                + shape.sq_evaluations_count * 2
                + shape.projected_values_count
        })
        .sum();
    let gr1cs_range_semantic_constraints: usize = lengths
        .gr1cs_message_shapes
        .iter()
        .filter_map(|shape| shape.range.as_ref())
        .map(|shape| {
            let monomial_vector_coeffs: usize = shape
                .monomial_vector_lens
                .iter()
                .map(|&vector_len| vector_len * D)
                .sum();
            let monomial_commitment_coeffs: usize = shape
                .monomial_commitment_elem_lens
                .iter()
                .map(|&elem_len| elem_len * D)
                .sum();
            let monomial_vector_elements: usize = shape.monomial_vector_lens.iter().sum();
            let semantic_counts = monomial_sumcheck_semantic_counts(shape);
            monomial_commitment_coeffs
                + monomial_vector_coeffs
                + monomial_vector_elements
                + shape.projected_values_count
                + semantic_counts.constraint_count
        })
        .sum();
    let structured_length_constraints = ell * 8 // fs-commit message lengths
        + 8 + ell * 8 // fs-root count and commitment lengths
        + 8 + ell * 24 // fold-root count and per-entry lengths
        + 8 + ell * 8 + 3 * 8 // transcript-seed count, input lengths, metadata
        + 8 + ell * 8; // challenge-digest count and per-challenge lengths
    let challenge_static_constraints = ell
        * challenge_body_static_constraints_count(
            cp_layout,
            original_r1cs_num_constraints,
            original_r1cs_num_variables,
        );
    ell * OUT
        + msg_bytes
        + gr1cs_hadamard_constraints
        + gr1cs_range_shape_constraints
        + gr1cs_projected_value_payload_constraints
        + gr1cs_range_semantic_constraints
        + fold_commit_limb_constraints
        + fold_public_input_constraints
        + transcript_public_input_constraints
        + challenge_output_constraints
        + challenge_transcript_public_input_constraints
        + challenge_transcript_fs_commitment_constraints
        + structured_length_constraints
        + challenge_static_constraints
}

fn typed_cp_beta_binding_constraints_count(cp_layout: &CpR1csLayout) -> usize {
    assert_eq!(cp_layout.d, D);
    assert_eq!(D, TYPED_BETA_CHALLENGE_BYTES * 2);
    cp_layout.ell_np * TYPED_BETA_CHALLENGE_BYTES * TYPED_BETA_CONSTRAINTS_PER_BYTE
}

fn beta_binding_selector_base(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
) -> usize {
    off_beta_binding_selectors
        + (ell * TYPED_BETA_CHALLENGE_BYTES + byte_idx) * TYPED_BETA_SELECTORS_PER_BYTE
}

fn beta_binding_d0_selector(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
    value: usize,
) -> usize {
    debug_assert!(value < TYPED_BETA_DIGIT_SELECTOR_VALUES);
    beta_binding_selector_base(off_beta_binding_selectors, ell, byte_idx) + value
}

fn beta_binding_d1_selector(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
    value: usize,
) -> usize {
    debug_assert!(value < TYPED_BETA_DIGIT_SELECTOR_VALUES);
    beta_binding_selector_base(off_beta_binding_selectors, ell, byte_idx)
        + TYPED_BETA_DIGIT_SELECTOR_VALUES
        + value
}

fn beta_binding_q_selector(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
    value: usize,
) -> usize {
    debug_assert!(value < TYPED_BETA_QUOTIENT_SELECTOR_VALUES);
    beta_binding_selector_base(off_beta_binding_selectors, ell, byte_idx)
        + TYPED_BETA_DIGIT_SELECTOR_VALUES * 2
        + value
}

fn insert_selector_bool_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    first_selector: usize,
    count: usize,
) -> usize {
    for idx in 0..count {
        let col = first_selector + idx;
        r1cs.a.insert(row, col, 1);
        r1cs.b.insert(row, col, 1);
        r1cs.b.insert(row, 0, -1);
        row += 1;
    }
    row
}

fn insert_selector_sum_one_constraint(
    r1cs: &mut R1CSMatrices,
    row: usize,
    first_selector: usize,
    count: usize,
) -> usize {
    for idx in 0..count {
        r1cs.a.insert(row, first_selector + idx, 1);
    }
    r1cs.a.insert(row, 0, -1);
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_typed_cp_beta_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    challenge_digest_block: &TypedCpDigestBlockLayout,
    off_beta_binding_selectors: usize,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    assert_eq!(cp_layout.d, D);
    assert_eq!(D, TYPED_BETA_CHALLENGE_BYTES * 2);
    assert_eq!(
        challenge_digest_block.body_len,
        8 + cp_layout.ell_np * (8 + TYPED_BETA_CHALLENGE_BYTES)
    );

    for ell in 0..cp_layout.ell_np {
        let challenge_bytes = challenge_digest_challenge_body_offset(ell);
        for byte_idx in 0..TYPED_BETA_CHALLENGE_BYTES {
            let d0_base = beta_binding_d0_selector(off_beta_binding_selectors, ell, byte_idx, 0);
            let d1_base = beta_binding_d1_selector(off_beta_binding_selectors, ell, byte_idx, 0);
            let q_base = beta_binding_q_selector(off_beta_binding_selectors, ell, byte_idx, 0);

            row = insert_selector_bool_constraints(
                r1cs,
                row,
                d0_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_bool_constraints(
                r1cs,
                row,
                d1_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_bool_constraints(
                r1cs,
                row,
                q_base,
                TYPED_BETA_QUOTIENT_SELECTOR_VALUES,
            );
            row = insert_selector_sum_one_constraint(
                r1cs,
                row,
                d0_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_sum_one_constraint(
                r1cs,
                row,
                d1_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_sum_one_constraint(
                r1cs,
                row,
                q_base,
                TYPED_BETA_QUOTIENT_SELECTOR_VALUES,
            );

            let byte_col = challenge_digest_block.off_body_bytes + challenge_bytes + byte_idx;
            r1cs.a.insert(row, byte_col, 1);
            for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
                r1cs.a.insert(row, d0_base + value, -(value as i64));
                r1cs.a.insert(row, d1_base + value, -(5 * value as i64));
            }
            for value in 0..TYPED_BETA_QUOTIENT_SELECTOR_VALUES {
                r1cs.a.insert(row, q_base + value, -(25 * value as i64));
            }
            r1cs.b.insert(row, 0, 1);
            row += 1;

            let beta0 = cp_col_in_digest_r1cs(
                statement,
                digest_public_shift,
                cp_layout.beta(ell, 2 * byte_idx),
            );
            r1cs.a.insert(row, beta0, 1);
            for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
                let mapped = value as i64 - 2;
                r1cs.a.insert(row, d0_base + value, -mapped);
            }
            r1cs.b.insert(row, 0, 1);
            row += 1;

            let beta1 = cp_col_in_digest_r1cs(
                statement,
                digest_public_shift,
                cp_layout.beta(ell, 2 * byte_idx + 1),
            );
            r1cs.a.insert(row, beta1, 1);
            for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
                let mapped = value as i64 - 2;
                r1cs.a.insert(row, d1_base + value, -mapped);
            }
            r1cs.b.insert(row, 0, 1);
            row += 1;
        }
    }

    row
}

fn folded_eval_product_col(
    off_folded_eval_products: usize,
    cp_layout: &CpR1csLayout,
    folded_eval_count: usize,
    ell: usize,
    eval_idx: usize,
    tensor_row: usize,
    coeff: usize,
) -> usize {
    off_folded_eval_products
        + (((ell * folded_eval_count + eval_idx) * T + tensor_row) * cp_layout.d + coeff)
}

fn folded_eval_public_col(
    off_folded_evaluations: usize,
    cp_layout: &CpR1csLayout,
    eval_idx: usize,
    tensor_row: usize,
    coeff: usize,
) -> usize {
    off_folded_evaluations + (eval_idx * T + tensor_row) * cp_layout.d + coeff
}

fn folded_eval_wrap_col(
    off_folded_eval_wraps: usize,
    cp_layout: &CpR1csLayout,
    eval_idx: usize,
    tensor_row: usize,
    coeff: usize,
) -> usize {
    off_folded_eval_wraps + (eval_idx * T + tensor_row) * cp_layout.d + coeff
}

fn babybear_ntt_coeff_rows() -> Vec<Vec<i64>> {
    let bb_ntt = crate::ring::ntt::NttContext::new(BB_P);
    let mut ntt_coeff = vec![vec![0i64; D]; D];
    for coeff in 0..D {
        let mut basis = [0i64; D];
        basis[coeff] = 1;
        let evals = bb_ntt.forward(&RingElement { coeffs: basis });
        for slot in 0..D {
            ntt_coeff[slot][coeff] = centered_mod(evals[slot] as i128, BB_P);
        }
    }
    ntt_coeff
}

fn folded_evaluation_derivation_constraints_count(
    lengths: &TypedCpDigestInputLengths,
    cp_layout: &CpR1csLayout,
) -> usize {
    cp_layout.ell_np * lengths.folded_evaluation_values * T * cp_layout.d
        + lengths.folded_evaluation_values * T * cp_layout.d
}

#[allow(clippy::too_many_arguments)]
fn insert_folded_evaluation_derivation_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    off_folded_evaluations: usize,
    folded_eval_count: usize,
    off_folded_eval_products: usize,
    off_folded_eval_wraps: usize,
    q: u64,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    assert!(folded_eval_count <= 3);
    let ntt_coeff = babybear_ntt_coeff_rows();
    let q_embed = centered_mod(q as i128, BB_P);

    for ell in 0..cp_layout.ell_np {
        for eval_idx in 0..folded_eval_count {
            for tensor_row in 0..T {
                for coeffs in ntt_coeff.iter().take(cp_layout.d) {
                    for (coeff, &ntt_coeff) in coeffs.iter().enumerate().take(cp_layout.d) {
                        let beta_col = cp_col_in_digest_r1cs(
                            statement,
                            digest_public_shift,
                            cp_layout.beta(ell, coeff),
                        );
                        r1cs.a.insert(row, beta_col, ntt_coeff);

                        let eval_col = cp_col_in_digest_r1cs(
                            statement,
                            digest_public_shift,
                            cp_layout.had_eval_matrix(ell, eval_idx, tensor_row, coeff),
                        );
                        r1cs.b.insert(row, eval_col, ntt_coeff);

                        let prod_col = folded_eval_product_col(
                            off_folded_eval_products,
                            cp_layout,
                            folded_eval_count,
                            ell,
                            eval_idx,
                            tensor_row,
                            coeff,
                        );
                        r1cs.c.insert(row, prod_col, ntt_coeff);
                    }
                    row += 1;
                }
            }
        }
    }

    for eval_idx in 0..folded_eval_count {
        for tensor_row in 0..T {
            for coeff in 0..cp_layout.d {
                r1cs.a.insert(row, 0, 1);
                r1cs.b.insert(
                    row,
                    folded_eval_public_col(
                        off_folded_evaluations,
                        cp_layout,
                        eval_idx,
                        tensor_row,
                        coeff,
                    ),
                    1,
                );
                for ell in 0..cp_layout.ell_np {
                    r1cs.c.insert(
                        row,
                        folded_eval_product_col(
                            off_folded_eval_products,
                            cp_layout,
                            folded_eval_count,
                            ell,
                            eval_idx,
                            tensor_row,
                            coeff,
                        ),
                        1,
                    );
                }
                r1cs.c.insert(
                    row,
                    folded_eval_wrap_col(
                        off_folded_eval_wraps,
                        cp_layout,
                        eval_idx,
                        tensor_row,
                        coeff,
                    ),
                    q_embed,
                );
                row += 1;
            }
        }
    }

    row
}

#[allow(clippy::too_many_arguments)]
fn insert_structured_digest_body_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    fs_commitment_blocks: &[TypedCpDigestBlockLayout],
    fs_root_block: &TypedCpDigestBlockLayout,
    fold_root_block: &TypedCpDigestBlockLayout,
    challenge_digest_block: &TypedCpDigestBlockLayout,
    transcript_seed_block: &TypedCpDigestBlockLayout,
    challenge_blocks: &[TypedCpDigestBlockLayout],
    range_payload_blocks: &[Option<TypedCpRangePayloadBlockLayout>],
    lengths: &TypedCpDigestInputLengths,
    digest_public_shift: usize,
    ajtai: &crate::commitment::AjtaiParams,
    audit: &mut Option<&mut TypedCpAuditBuilder>,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;

    let start = row;
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        fs_root_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        fold_root_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        challenge_digest_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    audit_push(
        audit,
        TypedCpAuditBlockKind::ByteConstraints,
        "structured-root-counts",
        start,
        row,
        &["FS/fold/challenge/transcript root body length framing"],
    );

    for ell in 0..cp_layout.ell_np {
        let start = row;
        let msg_len = lengths.gr1cs_message_bodies[ell];
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fs_commitment_blocks[ell].off_body_bytes,
            msg_len as u64,
        );

        let fs_root_len_offset = 8 + ell * (8 + OUT * 4);
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fs_root_block.off_body_bytes + fs_root_len_offset,
            (OUT * 4) as u64,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("structured-length-prefixes-{ell}"),
            start,
            row,
            &["canonical structured digest length prefixes"],
        );

        let fs_msg = fs_commit_message_body_offset(&fs_commitment_blocks[ell]);
        let fold_msg = fold_root_eval_message_body_offset(cp_layout, lengths, ell);
        let start = row;
        row = insert_bytes_equal(
            r1cs,
            row,
            fs_commitment_blocks[ell].off_body_bytes + fs_msg,
            fold_root_block.off_body_bytes + fold_msg,
            msg_len,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::Gr1csMessageReconstruction,
            format!("fs-message-fold-root-byte-equality-{ell}"),
            start,
            row,
            &["GR1CS message bytes bind FS commitments and fold root"],
        );
        if msg_len >= gr1cs_hadamard_message_prefix_len(cp_layout) {
            let start = row;
            row = insert_gr1cs_hadamard_message_constraints(
                r1cs,
                row,
                statement,
                digest_public_shift,
                fs_commitment_blocks[ell].off_body_bytes + fs_msg,
                fs_commitment_blocks[ell].off_body_bits + fs_msg * 8,
                ell,
            );
            audit_push(
                audit,
                TypedCpAuditBlockKind::Gr1csMessageReconstruction,
                format!("hadamard-message-reconstruction-{ell}"),
                start,
                row,
                &["Hadamard GR1CS message bytes reconstruct from CP columns"],
            );
        }
        if let Some(range_shape) = lengths.gr1cs_message_shapes[ell].range.as_ref() {
            let start = row;
            row = insert_gr1cs_range_message_shape_constraints(
                r1cs,
                row,
                fs_commitment_blocks[ell].off_body_bytes + fs_msg,
                &lengths.gr1cs_message_shapes[ell],
                range_shape,
                msg_len,
            );
            audit_push(
                audit,
                TypedCpAuditBlockKind::Gr1csMessageReconstruction,
                format!("range-message-shape-{ell}"),
                start,
                row,
                &["range proof serialization shape is canonical"],
            );
            if let Some(range_payload_block) = range_payload_blocks[ell].as_ref() {
                let start = row;
                row = insert_gr1cs_range_payload_constraints(
                    r1cs,
                    row,
                    fs_commitment_blocks[ell].off_body_bytes + fs_msg,
                    fs_commitment_blocks[ell].off_body_bits + fs_msg * 8,
                    &lengths.gr1cs_message_shapes[ell],
                    range_shape,
                    range_payload_block,
                );
                audit_push(
                    audit,
                    TypedCpAuditBlockKind::Gr1csMessageReconstruction,
                    format!("range-message-payload-reconstruction-{ell}"),
                    start,
                    row,
                    &["range proof payload bytes reconstruct from structured variables"],
                );
                let start = row;
                row = insert_gr1cs_range_semantic_constraints(
                    r1cs,
                    row,
                    range_shape,
                    range_payload_block,
                    ajtai,
                );
                audit_push(
                    audit,
                    TypedCpAuditBlockKind::RangeMonomialSemantics,
                    format!("range-monomial-semantics-{ell}"),
                    start,
                    row,
                    &[
                        "range proof monomial commitment opening validity",
                        "monomiality",
                        "monomial sumcheck consistency",
                        "monomial evaluation consistency",
                        "square-evaluation consistency",
                        "projected-value decomposition and reconstruction",
                    ],
                );
            }
        }

        let fold_entry = fold_root_entry_body_offset(cp_layout, lengths, ell);
        let fold_commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fold_root_block.off_body_bytes + fold_entry,
            fold_commitment_len as u64,
        );
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fold_root_block.off_body_bytes
                + fold_root_public_input_body_offset(cp_layout, lengths, ell)
                - 8,
            cp_layout.n_in as u64,
        );
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fold_root_block.off_body_bytes + fold_msg - 8,
            msg_len as u64,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("fold-root-entry-length-prefixes-{ell}"),
            start,
            row,
            &["fold root entry length framing"],
        );

        let fold_commitment = fold_root_commitment_body_offset(cp_layout, lengths, ell);
        let start = row;
        for i in 0..cp_layout.kappa {
            for j in 0..cp_layout.d {
                let body = fold_root_block.off_body_bytes
                    + fold_commitment
                    + 8
                    + (i * cp_layout.d + j) * 8;
                let cp_col =
                    cp_col_in_digest_r1cs(statement, digest_public_shift, cp_layout.c(ell, i, j));
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    body,
                    fold_root_block.off_body_bits
                        + (body - fold_root_block.off_body_bytes + 7) * 8
                        + 7,
                    cp_col,
                );
            }
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::FoldedOutputDerivation,
            format!("fold-root-commitment-binding-{ell}"),
            start,
            row,
            &["fold root commitment bytes bind CP commitment columns"],
        );

        let fold_public_input = fold_root_public_input_body_offset(cp_layout, lengths, ell);
        let transcript_public_input = transcript_seed_public_input_body_offset(cp_layout, ell);
        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            transcript_seed_block.off_body_bytes + transcript_public_input - 8,
            cp_layout.n_in as u64,
        );
        for slot in 0..cp_layout.n_in {
            let public_col = statement.off_public_inputs + ell * cp_layout.n_in + slot;
            row = insert_i64_limb_bytes_equal_var(
                r1cs,
                row,
                fold_root_block.off_body_bytes + fold_public_input + slot * 8,
                fold_root_block.off_body_bits + (fold_public_input + slot * 8 + 7) * 8 + 7,
                public_col,
            );
            row = insert_i64_limb_bytes_equal_var(
                r1cs,
                row,
                transcript_seed_block.off_body_bytes + transcript_public_input + slot * 8,
                transcript_seed_block.off_body_bits
                    + (transcript_public_input + slot * 8 + 7) * 8
                    + 7,
                public_col,
            );
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::PublicInputBinding,
            format!("public-input-digest-body-binding-{ell}"),
            start,
            row,
            &["public inputs bind fold root, transcript seed, and CP statement"],
        );

        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            challenge_digest_block.off_body_bytes + 8 + ell * (8 + 32),
            (OUT * 4) as u64,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("challenge-digest-entry-length-{ell}"),
            start,
            row,
            &["challenge digest entry length framing"],
        );
    }

    let transcript_seed_meta = transcript_seed_metadata_body_offset(cp_layout);
    let start = row;
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes + transcript_seed_meta,
        statement.partial.original_r1cs_num_constraints as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes + transcript_seed_meta + 8,
        statement.partial.original_r1cs_num_variables as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes + transcript_seed_meta + 16,
        cp_layout.n_in as u64,
    );
    audit_push(
        audit,
        TypedCpAuditBlockKind::PublicInputBinding,
        "transcript-seed-r1cs-metadata-binding",
        start,
        row,
        &["R1CS metadata binds transcript seed digest"],
    );

    for (challenge_idx, challenge_block) in challenge_blocks.iter().enumerate() {
        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            challenge_block.off_body_bytes,
            challenge_idx as u64,
        );
        row = insert_challenge_transcript_static_constraints(r1cs, row, statement, challenge_block);
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("challenge-transcript-static-frame-{challenge_idx}"),
            start,
            row,
            &["challenge transcript static frame is canonical"],
        );

        let challenge_digest_bytes = challenge_digest_challenge_body_offset(challenge_idx);
        let start = row;
        for limb in 0..OUT {
            row = insert_u32_limb_bytes_equal_var(
                r1cs,
                row,
                challenge_digest_block.off_body_bytes + challenge_digest_bytes + limb * 4,
                challenge_block.off_public_output + limb,
            );
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::ChallengeToBetaBinding,
            format!("challenge-output-to-digest-body-{challenge_idx}"),
            start,
            row,
            &["per-round challenge output feeds challenge digest"],
        );

        let start = row;
        for ell in 0..cp_layout.ell_np {
            let transcript_public_input =
                challenge_body_transcript_public_input_payload_offset(cp_layout, ell);
            for slot in 0..cp_layout.n_in {
                let public_col = statement.off_public_inputs + ell * cp_layout.n_in + slot;
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    challenge_block.off_body_bytes + 8 + transcript_public_input + slot * 8,
                    challenge_block.off_body_bits
                        + (8 + transcript_public_input + slot * 8 + 7) * 8
                        + 7,
                    public_col,
                );
            }
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::PublicInputBinding,
            format!("challenge-transcript-public-input-binding-{challenge_idx}"),
            start,
            row,
            &["public inputs bind per-round challenge transcripts"],
        );

        let start = row;
        for commitment_idx in 0..cp_layout.ell_np {
            let transcript_commitment =
                challenge_body_transcript_fs_commitment_payload_offset(cp_layout, commitment_idx);
            for limb in 0..OUT {
                row = insert_u32_limb_bytes_equal_var(
                    r1cs,
                    row,
                    challenge_block.off_body_bytes + 8 + transcript_commitment + limb * 4,
                    fs_commitment_blocks[commitment_idx].off_public_output + limb,
                );
            }
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("challenge-transcript-fs-commitment-binding-{challenge_idx}"),
            start,
            row,
            &["FS commitments bind per-round challenge transcripts"],
        );
    }

    row
}

fn challenge_body_static_constraints_count(
    cp_layout: &CpR1csLayout,
    original_r1cs_num_constraints: usize,
    original_r1cs_num_variables: usize,
) -> usize {
    let transcript = canonical_challenge_transcript_template(
        cp_layout,
        original_r1cs_num_constraints,
        original_r1cs_num_variables,
    );
    let variable_payload_bytes = cp_layout.ell_np * cp_layout.n_in * 8 + cp_layout.ell_np * OUT * 4;
    8 + transcript.len() - variable_payload_bytes
}

fn insert_challenge_transcript_static_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    challenge_block: &TypedCpDigestBlockLayout,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    let transcript = canonical_challenge_transcript_template(
        cp_layout,
        statement.partial.original_r1cs_num_constraints,
        statement.partial.original_r1cs_num_variables,
    );
    assert_eq!(challenge_block.body_len, 8 + transcript.len());

    for (idx, byte) in transcript.iter().copied().enumerate() {
        if !is_challenge_transcript_variable_payload(cp_layout, idx) {
            row = insert_byte_constant(r1cs, row, challenge_block.off_body_bytes + 8 + idx, byte);
        }
    }
    row
}

fn canonical_challenge_transcript_template(
    cp_layout: &CpR1csLayout,
    original_r1cs_num_constraints: usize,
    original_r1cs_num_variables: usize,
) -> Vec<u8> {
    let public_inputs = vec![vec![0i64; cp_layout.n_in]; cp_layout.ell_np];
    let fs_commitments = vec![vec![0u8; OUT * 4]; cp_layout.ell_np];
    crate::cp_relation_core::cp_relation_transcript_bytes(
        &public_inputs,
        original_r1cs_num_constraints,
        original_r1cs_num_variables,
        cp_layout.n_in,
        &fs_commitments,
    )
}

fn is_challenge_transcript_variable_payload(cp_layout: &CpR1csLayout, offset: usize) -> bool {
    for ell in 0..cp_layout.ell_np {
        let start = challenge_body_transcript_public_input_payload_offset(cp_layout, ell);
        if (start..start + cp_layout.n_in * 8).contains(&offset) {
            return true;
        }
    }
    for commitment_idx in 0..cp_layout.ell_np {
        let start =
            challenge_body_transcript_fs_commitment_payload_offset(cp_layout, commitment_idx);
        if (start..start + OUT * 4).contains(&offset) {
            return true;
        }
    }
    false
}
