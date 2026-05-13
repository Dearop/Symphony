fn typed_range_d_prime() -> i64 {
    D as i64 - 2
}

fn monomial_digit_weight(coeff: usize) -> i64 {
    if coeff == 0 || coeff == D / 2 {
        0
    } else {
        coeff.min(D - coeff) as i64
    }
}

fn gr1cs_hadamard_section_len(shape: &TypedCpGr1csMessageShape) -> usize {
    let sumcheck_len = 8 + shape
        .hadamard_sumcheck_round_evals
        .iter()
        .map(|&eval_count| 8 + eval_count * 2 * 8)
        .sum::<usize>();
    let eval_matrix_len = shape
        .hadamard_eval_matrix_rows
        .iter()
        .map(|&rows| rows * D * 8)
        .sum::<usize>();
    sumcheck_len + eval_matrix_len
}

fn gr1cs_message_len_from_shape(shape: &TypedCpGr1csMessageShape) -> Option<usize> {
    let mut len = gr1cs_hadamard_section_len(shape);
    let Some(range_shape) = &shape.range else {
        return Some(len);
    };

    len = len.checked_add(8)?;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        len = len.checked_add(commitment_message_len(elem_len))?;
    }

    len = len.checked_add(8)?;
    for &vector_len in &range_shape.monomial_vector_lens {
        len = len
            .checked_add(8)?
            .checked_add(vector_len.checked_mul(D)?.checked_mul(8)?)?;
    }

    len = len.checked_add(8)?;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        len = len
            .checked_add(8)?
            .checked_add(eval_count.checked_mul(2)?.checked_mul(8)?)?;
    }

    len = len.checked_add(8)?;
    for &rows in &range_shape.monomial_evaluation_rows {
        len = len.checked_add(rows.checked_mul(D)?.checked_mul(8)?)?;
    }

    len = len.checked_add(8)?.checked_add(
        range_shape
            .sq_evaluations_count
            .checked_mul(2)?
            .checked_mul(8)?,
    )?;
    len = len
        .checked_add(8)?
        .checked_add(range_shape.projected_values_count.checked_mul(8)?)?;
    Some(len)
}

fn commitment_message_len(num_elements: usize) -> usize {
    8 + num_elements * D * 8
}

fn gr1cs_hadamard_message_constraints_count(cp_layout: &CpR1csLayout) -> usize {
    8 + cp_layout.had_num_vars * 8 + cp_layout.had_num_vars * 4 * 2 + 3 * 2 * cp_layout.d
}

fn gr1cs_hadamard_message_prefix_len(cp_layout: &CpR1csLayout) -> usize {
    8 + cp_layout.had_num_vars * (8 + 4 * 2 * 8) + 3 * 2 * cp_layout.d * 8
}

fn gr1cs_hadamard_round_len_offset(round: usize) -> usize {
    8 + round * (8 + 4 * 2 * 8)
}

fn gr1cs_hadamard_eval_offset(round: usize, point: usize, comp: usize) -> usize {
    gr1cs_hadamard_round_len_offset(round) + 8 + (point * 2 + comp) * 8
}

fn gr1cs_hadamard_eval_matrix_offset(
    cp_layout: &CpR1csLayout,
    matrix_idx: usize,
    row: usize,
    col: usize,
) -> usize {
    8 + cp_layout.had_num_vars * (8 + 4 * 2 * 8)
        + (matrix_idx * 2 + row) * cp_layout.d * 8
        + col * 8
}

fn insert_gr1cs_hadamard_message_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    message_byte_col: usize,
    message_bit_col: usize,
    ell: usize,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    row = insert_u64_bytes_constant(r1cs, row, message_byte_col, cp_layout.had_num_vars as u64);

    for round in 0..cp_layout.had_num_vars {
        let round_len = gr1cs_hadamard_round_len_offset(round);
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + round_len, 4);
        for point in 0..4 {
            for comp in 0..2 {
                let offset = gr1cs_hadamard_eval_offset(round, point, comp);
                let cp_col = cp_col_in_digest_r1cs(
                    statement,
                    digest_public_shift,
                    cp_layout.had_eval(ell, round, point, comp),
                );
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    message_byte_col + offset,
                    message_bit_col + (offset + 7) * 8 + 7,
                    cp_col,
                );
            }
        }
    }

    for matrix_idx in 0..3 {
        for matrix_row in 0..2 {
            for col in 0..cp_layout.d {
                let offset =
                    gr1cs_hadamard_eval_matrix_offset(cp_layout, matrix_idx, matrix_row, col);
                let cp_col = cp_col_in_digest_r1cs(
                    statement,
                    digest_public_shift,
                    cp_layout.had_eval_matrix(ell, matrix_idx, matrix_row, col),
                );
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    message_byte_col + offset,
                    message_bit_col + (offset + 7) * 8 + 7,
                    cp_col,
                );
            }
        }
    }

    row
}

fn cp_col_in_digest_r1cs(
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    cp_col: usize,
) -> usize {
    let statement_col = if cp_col < statement.partial.num_public {
        cp_col
    } else {
        cp_col + statement.added_public_inputs
    };
    if statement_col < statement.num_public {
        statement_col
    } else {
        statement_col + digest_public_shift
    }
}

fn insert_i64_limb_bytes_equal_var(
    r1cs: &mut R1CSMatrices,
    row: usize,
    byte_col: usize,
    sign_bit_col: usize,
    var_col: usize,
) -> usize {
    r1cs.a.insert(row, var_col, 1);
    for idx in 0..8 {
        r1cs.a.insert(row, byte_col + idx, -(1i64 << (8 * idx)));
    }
    r1cs.a
        .insert(row, sign_bit_col, centered_mod(1i128 << 64, BB_P));
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_u32_limb_bytes_equal_var(
    r1cs: &mut R1CSMatrices,
    row: usize,
    byte_col: usize,
    var_col: usize,
) -> usize {
    r1cs.a.insert(row, var_col, 1);
    r1cs.a.insert(row, byte_col, -1);
    r1cs.a.insert(row, byte_col + 1, -256);
    r1cs.a.insert(row, byte_col + 2, -65_536);
    r1cs.a.insert(row, byte_col + 3, -16_777_216);
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_u64_bytes_constant(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    byte_col: usize,
    value: u64,
) -> usize {
    for (idx, byte) in value.to_le_bytes().iter().copied().enumerate() {
        r1cs.a.insert(row, byte_col + idx, 1);
        r1cs.a.insert(row, 0, -(byte as i64));
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }
    row
}

fn insert_byte_constant(r1cs: &mut R1CSMatrices, row: usize, byte_col: usize, value: u8) -> usize {
    r1cs.a.insert(row, byte_col, 1);
    r1cs.a.insert(row, 0, -(value as i64));
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_bytes_equal(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    left: usize,
    right: usize,
    len: usize,
) -> usize {
    for idx in 0..len {
        r1cs.a.insert(row, left + idx, 1);
        r1cs.a.insert(row, right + idx, -1);
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }
    row
}

fn fs_commit_message_body_offset(_block: &TypedCpDigestBlockLayout) -> usize {
    8
}

fn fold_root_entry_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    let commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
    let mut offset = 8;
    for prev in 0..ell {
        offset +=
            8 + commitment_len + 8 + cp_layout.n_in * 8 + 8 + lengths.gr1cs_message_bodies[prev];
    }
    offset
}

fn fold_root_commitment_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    fold_root_entry_body_offset(cp_layout, lengths, ell) + 8
}

fn fold_root_public_input_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    let commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
    fold_root_entry_body_offset(cp_layout, lengths, ell) + 8 + commitment_len + 8
}

fn fold_root_eval_message_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    let commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
    fold_root_entry_body_offset(cp_layout, lengths, ell)
        + 8
        + commitment_len
        + 8
        + cp_layout.n_in * 8
        + 8
}

fn transcript_seed_public_input_body_offset(cp_layout: &CpR1csLayout, ell: usize) -> usize {
    let mut offset = 8;
    for _ in 0..ell {
        offset += 8 + cp_layout.n_in * 8;
    }
    offset + 8
}

fn transcript_seed_metadata_body_offset(cp_layout: &CpR1csLayout) -> usize {
    let mut offset = 8;
    for _ in 0..cp_layout.ell_np {
        offset += 8 + cp_layout.n_in * 8;
    }
    offset
}

fn challenge_digest_challenge_body_offset(index: usize) -> usize {
    8 + index * (8 + 32) + 8
}

fn challenge_body_transcript_public_input_payload_offset(
    cp_layout: &CpR1csLayout,
    ell: usize,
) -> usize {
    let mut offset = transcript_header_len();
    for current in 0..=ell {
        let payload = offset + event_header_len(b"public-input");
        if current == ell {
            return payload;
        }
        offset = payload + cp_layout.n_in * 8;
    }
    unreachable!("public input offset loop must return")
}

fn challenge_body_transcript_fs_commitment_payload_offset(
    cp_layout: &CpR1csLayout,
    commitment_idx: usize,
) -> usize {
    let mut offset = transcript_header_len();
    for _ in 0..cp_layout.ell_np {
        offset += event_header_len(b"public-input") + cp_layout.n_in * 8;
    }
    for label in [
        b"r1cs-m".as_slice(),
        b"r1cs-n".as_slice(),
        b"r1cs-pub".as_slice(),
    ] {
        offset += event_header_len(label) + 8;
    }
    for current in 0..=commitment_idx {
        let payload = offset + event_header_len(b"fs-commitment");
        if current == commitment_idx {
            return payload;
        }
        offset = payload + 32;
    }
    unreachable!("FS commitment offset loop must return")
}

fn transcript_header_len() -> usize {
    crate::transcript_core::TRANSCRIPT_MAGIC.len() + 2 + 8 + b"symphony-v1".len() + 8
}

fn event_header_len(label: &[u8]) -> usize {
    1 + 8 + label.len() + 8
}

#[allow(clippy::too_many_arguments)]
fn map_original_col_to_typed_cp(
    col: usize,
    ell: usize,
    cp_layout: &CpR1csLayout,
    original_layout: &OriginalStatementR1csLayout,
    original_witness_size: usize,
    original_ajtai_wrap_size: usize,
    original_r1cs_wrap_size: usize,
    off_original_witnesses: usize,
    off_original_ajtai_wraps: usize,
    off_original_r1cs_wraps: usize,
) -> usize {
    if col == original_layout.off_one {
        return cp_layout.off_one;
    }
    if (original_layout.off_public_input..original_layout.off_commitment).contains(&col) {
        let slot = col - original_layout.off_public_input;
        return cp_layout.x_in(ell, slot, 0);
    }
    let commitment_end = original_layout.off_commitment + original_layout.kappa * D;
    if (original_layout.off_commitment..commitment_end).contains(&col) {
        let local = col - original_layout.off_commitment;
        return cp_layout.c(ell, local / D, local % D);
    }
    let witness_end = original_layout.off_witness + original_witness_size;
    if (original_layout.off_witness..witness_end).contains(&col) {
        return off_original_witnesses
            + ell * original_witness_size
            + (col - original_layout.off_witness);
    }
    let ajtai_wrap_end = original_layout.off_ajtai_wrap + original_ajtai_wrap_size;
    if (original_layout.off_ajtai_wrap..ajtai_wrap_end).contains(&col) {
        return off_original_ajtai_wraps
            + ell * original_ajtai_wrap_size
            + (col - original_layout.off_ajtai_wrap);
    }
    let r1cs_wrap_end = original_layout.off_r1cs_wrap + original_r1cs_wrap_size;
    debug_assert!((original_layout.off_r1cs_wrap..r1cs_wrap_end).contains(&col));
    off_original_r1cs_wraps + ell * original_r1cs_wrap_size + (col - original_layout.off_r1cs_wrap)
}

fn insert_original_r1cs_lc(
    r1cs: &mut R1CSMatrices,
    row: usize,
    layout: &OriginalStatementR1csLayout,
    r1cs_src: &R1CSMatrices,
    constraint: usize,
    coeff: usize,
) {
    insert_original_matrix_row_lc(&mut r1cs.a, row, layout, &r1cs_src.a, constraint, coeff);
    insert_original_matrix_row_lc(&mut r1cs.b, row, layout, &r1cs_src.b, constraint, coeff);
    insert_original_matrix_row_lc(&mut r1cs.c, row, layout, &r1cs_src.c, constraint, coeff);
    let wrap_col = layout.off_r1cs_wrap + constraint * D + coeff;
    r1cs.c.insert(row, wrap_col, layout.q as i64);
}

fn insert_original_matrix_row_lc(
    target: &mut crate::r1cs::SparseMatrix,
    row: usize,
    layout: &OriginalStatementR1csLayout,
    source: &crate::r1cs::SparseMatrix,
    source_row: usize,
    coeff: usize,
) {
    for &(r, col, value) in &source.entries {
        if r != source_row {
            continue;
        }
        if col < layout.n_public {
            if coeff == 0 {
                target.insert(row, layout.off_public_input + col, value);
            }
        } else {
            target.insert(
                row,
                layout.off_witness + (col - layout.n_public) * D + coeff,
                value,
            );
        }
    }
}

fn assemble_full_ring_witness(public_input: &[i64], witness_part: &RingVector) -> RingVector {
    let mut elements = Vec::with_capacity(public_input.len() + witness_part.len());
    elements.extend(public_input.iter().copied().map(RingElement::from_constant));
    elements.extend(witness_part.elements.iter().cloned());
    RingVector::from(elements)
}

fn raw_ajtai_coeff(
    ajtai: &crate::commitment::AjtaiParams,
    full_witness: &RingVector,
    commitment_row: usize,
    coeff: usize,
) -> i128 {
    let mut acc = 0i128;
    for col in 0..ajtai.n {
        let a = &ajtai.a[commitment_row][col];
        let w = &full_witness.elements[col];
        for a_coeff in 0..D {
            let (w_coeff, sign) = negacyclic_partner(coeff, a_coeff);
            acc += sign * a.coeffs[a_coeff] as i128 * w.coeffs[w_coeff] as i128;
        }
    }
    acc
}

fn raw_original_r1cs_row(
    r1cs_src: &R1CSMatrices,
    full_witness: &RingVector,
    constraint: usize,
    coeff: usize,
) -> (i128, i128, i128) {
    let eval = |matrix: &crate::r1cs::SparseMatrix| -> i128 {
        matrix
            .entries
            .iter()
            .filter(|&&(row, _, _)| row == constraint)
            .map(|&(_, col, value)| {
                value as i128 * full_witness.elements[col].coeffs[coeff] as i128
            })
            .sum()
    };
    (eval(&r1cs_src.a), eval(&r1cs_src.b), eval(&r1cs_src.c))
}

fn negacyclic_partner(target_coeff: usize, a_coeff: usize) -> (usize, i128) {
    if target_coeff >= a_coeff {
        (target_coeff - a_coeff, 1)
    } else {
        (D + target_coeff - a_coeff, -1)
    }
}

fn wrap_quotient(diff: i128, q: u64) -> i64 {
    assert_eq!(diff.rem_euclid(q as i128), 0);
    i64::try_from(diff / q as i128).expect("typed CP wrap quotient exceeds i64")
}

fn sponge_permute_input(constants: &Poseidon2Constants, state: &mut [u32; WIDTH], input: &[u32]) {
    let mut pos = 0usize;
    loop {
        let mut absorbed = 0usize;
        for slot in state.iter_mut().take(RATE) {
            if pos < input.len() {
                *slot = input[pos];
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    software_permutation(constants, state);
                }
                return;
            }
        }
        software_permutation(constants, state);
    }
}

fn sponge_permute_input_recording(
    constants: &Poseidon2Constants,
    state: &mut [u32; WIDTH],
    input: &[u32],
    witness_values: &mut Vec<u32>,
) {
    let mut pos = 0usize;
    loop {
        let mut absorbed = 0usize;
        for slot in state.iter_mut().take(RATE) {
            if pos < input.len() {
                *slot = input[pos];
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    software_permutation_recording(constants, state, witness_values);
                }
                return;
            }
        }
        software_permutation_recording(constants, state, witness_values);
    }
}

fn software_permutation(constants: &Poseidon2Constants, state: &mut [u32; WIDTH]) {
    software_mds_light(state);
    for round in &constants.external_initial {
        for i in 0..WIDTH {
            state[i] = exp7(add(state[i], round[i]));
        }
        software_mds_light(state);
    }
    for &rc in &constants.internal {
        state[0] = exp7(add(state[0], rc));
        software_internal_linear(state);
    }
    for round in &constants.external_terminal {
        for i in 0..WIDTH {
            state[i] = exp7(add(state[i], round[i]));
        }
        software_mds_light(state);
    }
}

fn software_permutation_recording(
    constants: &Poseidon2Constants,
    state: &mut [u32; WIDTH],
    witness_values: &mut Vec<u32>,
) {
    software_mds_light(state);
    for round in &constants.external_initial {
        for i in 0..WIDTH {
            state[i] = exp7_recording(add(state[i], round[i]), witness_values);
        }
        software_mds_light(state);
    }
    for &rc in &constants.internal {
        state[0] = exp7_recording(add(state[0], rc), witness_values);
        software_internal_linear(state);
    }
    for round in &constants.external_terminal {
        for i in 0..WIDTH {
            state[i] = exp7_recording(add(state[i], round[i]), witness_values);
        }
        software_mds_light(state);
    }
}

fn circuit_mds_light(state: &mut [Lin; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let x = [
            chunk[0].clone(),
            chunk[1].clone(),
            chunk[2].clone(),
            chunk[3].clone(),
        ];
        chunk[0] = x[0].scale(2).add(&x[1].scale(3)).add(&x[2]).add(&x[3]);
        chunk[1] = x[0].add(&x[1].scale(2)).add(&x[2].scale(3)).add(&x[3]);
        chunk[2] = x[0].add(&x[1]).add(&x[2].scale(2)).add(&x[3].scale(3));
        chunk[3] = x[0].scale(3).add(&x[1]).add(&x[2]).add(&x[3].scale(2));
    }
    let sums: [Lin; 4] = core::array::from_fn(|k| {
        let mut acc = Lin::zero();
        for j in (0..WIDTH).step_by(4) {
            acc = acc.add(&state[j + k]);
        }
        acc
    });
    for i in 0..WIDTH {
        state[i] = state[i].add(&sums[i % 4]);
    }
}

fn circuit_internal_linear(state: &mut [Lin; WIDTH]) {
    let mut part_sum = Lin::zero();
    for item in state.iter().take(WIDTH).skip(1) {
        part_sum = part_sum.add(item);
    }
    let full_sum = part_sum.add(&state[0]);
    state[0] = part_sum.sub(&state[0]);
    let diag = internal_diag();
    for i in 1..WIDTH {
        state[i] = full_sum.add(&state[i].scale(diag[i]));
    }
}

fn software_mds_light(state: &mut [u32; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let x = [chunk[0], chunk[1], chunk[2], chunk[3]];
        chunk[0] = add(add(add(mul_small(x[0], 2), mul_small(x[1], 3)), x[2]), x[3]);
        chunk[1] = add(add(add(x[0], mul_small(x[1], 2)), mul_small(x[2], 3)), x[3]);
        chunk[2] = add(add(add(x[0], x[1]), mul_small(x[2], 2)), mul_small(x[3], 3));
        chunk[3] = add(add(add(mul_small(x[0], 3), x[1]), x[2]), mul_small(x[3], 2));
    }
    let sums: [u32; 4] = core::array::from_fn(|k| {
        let mut acc = 0u32;
        for j in (0..WIDTH).step_by(4) {
            acc = add(acc, state[j + k]);
        }
        acc
    });
    for i in 0..WIDTH {
        state[i] = add(state[i], sums[i % 4]);
    }
}

fn software_internal_linear(state: &mut [u32; WIDTH]) {
    let mut part_sum = 0u32;
    for &value in state.iter().skip(1) {
        part_sum = add(part_sum, value);
    }
    let full_sum = add(part_sum, state[0]);
    state[0] = sub(part_sum, state[0]);
    let diag = internal_diag();
    for i in 1..WIDTH {
        state[i] = add(full_sum, mul(state[i], diag[i]));
    }
}

fn internal_diag() -> [u32; WIDTH] {
    [
        sub(0, 2),
        1,
        2,
        inv_pow2(1),
        3,
        4,
        sub(0, inv_pow2(1)),
        sub(0, 3),
        sub(0, 4),
        inv_pow2(8),
        inv_pow2(2),
        inv_pow2(3),
        inv_pow2(27),
        sub(0, inv_pow2(8)),
        sub(0, inv_pow2(4)),
        sub(0, inv_pow2(27)),
    ]
}

fn exp7(x: u32) -> u32 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    let x6 = mul(x4, x2);
    mul(x6, x)
}

fn exp7_recording(x: u32, witness_values: &mut Vec<u32>) -> u32 {
    let x2 = mul(x, x);
    witness_values.push(x2);
    let x4 = mul(x2, x2);
    witness_values.push(x4);
    let x6 = mul(x4, x2);
    witness_values.push(x6);
    let x7 = mul(x6, x);
    witness_values.push(x7);
    x7
}

fn add(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % BB_P) as u32
}

fn sub(a: u32, b: u32) -> u32 {
    ((a as u64 + BB_P - b as u64) % BB_P) as u32
}

fn mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % BB_P) as u32
}

fn mul_small(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % BB_P) as u32
}

fn inv_pow2(exp: u64) -> u32 {
    mod_pow_u64(2, BB_P - 1 - exp) as u32
}

fn mod_pow_u64(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base %= BB_P;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % BB_P;
        }
        base = (base * base) % BB_P;
        exp >>= 1;
    }
    result
}

fn centered_coeff(value: u32) -> i64 {
    if value as u64 > BB_P / 2 {
        value as i64 - BB_P as i64
    } else {
        value as i64
    }
}

fn centered_i128(value: i128) -> i64 {
    let p = BB_P as i128;
    let value = value.rem_euclid(p);
    if value > p / 2 {
        (value - p) as i64
    } else {
        value as i64
    }
}

