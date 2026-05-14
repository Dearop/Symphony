#[derive(Debug, Clone, Copy)]
struct MonomialSumcheckSemanticCounts {
    challenge_len: usize,
    aux_count: usize,
    wrap_count: usize,
    constraint_count: usize,
}

fn monomial_sumcheck_semantic_counts(
    range_shape: &TypedCpRangeMessageShape,
) -> MonomialSumcheckSemanticCounts {
    let verifier = monomial_sumcheck_verifier_counts(range_shape);
    let evaluation_binding = monomial_evaluation_binding_counts(range_shape);
    MonomialSumcheckSemanticCounts {
        challenge_len: verifier.challenge_len,
        aux_count: verifier.aux_count + evaluation_binding.aux_count,
        wrap_count: verifier.wrap_count + evaluation_binding.wrap_count,
        constraint_count: verifier.constraint_count + evaluation_binding.constraint_count,
    }
}

fn monomial_sumcheck_verifier_counts(
    range_shape: &TypedCpRangeMessageShape,
) -> MonomialSumcheckSemanticCounts {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let k_g = range_shape.monomial_evaluation_rows.len();
    let total_terms = k_g * D + k_g;
    let ext_mul_count = 4 * nv
        + if nv > 0 { 2 * nv - 1 } else { 0 }
        + k_g * D * 2
        + k_g
        + total_terms.saturating_sub(2)
        + total_terms.saturating_sub(1)
        + if nv > 0 { 1 } else { 0 };
    let linear_rows = 2 * nv + 2;
    MonomialSumcheckSemanticCounts {
        challenge_len: nv * 2,
        aux_count: ext_mul_count * 4,
        wrap_count: ext_mul_count * 4 + linear_rows,
        constraint_count: ext_mul_count * 4 + linear_rows,
    }
}

fn monomial_evaluation_binding_counts(
    range_shape: &TypedCpRangeMessageShape,
) -> MonomialSumcheckSemanticCounts {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let k_g = range_shape.monomial_evaluation_rows.len();
    let table_size = 1usize
        .checked_shl(nv as u32)
        .expect("typed CP monomial sumcheck round count too large");
    let table_count = k_g * (D + 1);
    let fold_count = table_count * table_size.saturating_sub(1);
    let final_equalities = table_count;
    let linear_rows = 2 * (fold_count + final_equalities);
    MonomialSumcheckSemanticCounts {
        challenge_len: 0,
        aux_count: fold_count * 6,
        wrap_count: fold_count * 4 + linear_rows,
        constraint_count: fold_count * 4 + linear_rows,
    }
}

#[derive(Debug, Clone)]
struct ExtLc {
    c0: Vec<(usize, i64)>,
    c1: Vec<(usize, i64)>,
}

fn ext_zero_lc() -> ExtLc {
    ExtLc {
        c0: Vec::new(),
        c1: Vec::new(),
    }
}

fn ext_one_lc() -> ExtLc {
    ExtLc {
        c0: vec![(0, 1)],
        c1: Vec::new(),
    }
}

fn ext_var_lc(c0: usize, c1: usize) -> ExtLc {
    ExtLc {
        c0: vec![(c0, 1)],
        c1: vec![(c1, 1)],
    }
}

fn ext_const_lc(value: i64) -> ExtLc {
    if value == 0 {
        ext_zero_lc()
    } else {
        ExtLc {
            c0: vec![(0, value)],
            c1: Vec::new(),
        }
    }
}

fn lc_add(lhs: &[(usize, i64)], rhs: &[(usize, i64)]) -> Vec<(usize, i64)> {
    let mut out = lhs.to_vec();
    out.extend_from_slice(rhs);
    normalize_lc(out)
}

fn lc_sub(lhs: &[(usize, i64)], rhs: &[(usize, i64)]) -> Vec<(usize, i64)> {
    let mut out = lhs.to_vec();
    out.extend(rhs.iter().map(|&(idx, coeff)| (idx, -coeff)));
    normalize_lc(out)
}

fn lc_scale(lhs: &[(usize, i64)], coeff: i64) -> Vec<(usize, i64)> {
    if coeff == 0 {
        return Vec::new();
    }
    normalize_lc(
        lhs.iter()
            .map(|&(idx, c)| (idx, centered_i128(c as i128 * coeff as i128)))
            .collect(),
    )
}

fn normalize_lc(entries: Vec<(usize, i64)>) -> Vec<(usize, i64)> {
    let mut acc = BTreeMap::<usize, i128>::new();
    for (idx, coeff) in entries {
        *acc.entry(idx).or_insert(0) += coeff as i128;
    }
    acc.into_iter()
        .filter_map(|(idx, coeff)| {
            let coeff = centered_i128(coeff);
            (coeff != 0).then_some((idx, coeff))
        })
        .collect()
}

fn ext_add_lc(lhs: &ExtLc, rhs: &ExtLc) -> ExtLc {
    ExtLc {
        c0: lc_add(&lhs.c0, &rhs.c0),
        c1: lc_add(&lhs.c1, &rhs.c1),
    }
}

fn ext_sub_lc(lhs: &ExtLc, rhs: &ExtLc) -> ExtLc {
    ExtLc {
        c0: lc_sub(&lhs.c0, &rhs.c0),
        c1: lc_sub(&lhs.c1, &rhs.c1),
    }
}

fn ext_scale_lc(lhs: &ExtLc, coeff: i64) -> ExtLc {
    ExtLc {
        c0: lc_scale(&lhs.c0, coeff),
        c1: lc_scale(&lhs.c1, coeff),
    }
}

fn q_field_const(value: i128, q: u64) -> i64 {
    centered_mod(value, q)
}

fn q_inv_const(value: u64, q: u64) -> i64 {
    q_field_const(mod_inv(value % q, q) as i128, q)
}

fn insert_ext_linear_eq_mod_q(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    lhs: &ExtLc,
    rhs: &ExtLc,
    wrap_col: usize,
    q: u64,
) -> usize {
    let q_embed = centered_mod(q as i128, BB_P);
    for (comp, (lhs_lc, rhs_lc)) in [(&lhs.c0, &rhs.c0), (&lhs.c1, &rhs.c1)]
        .into_iter()
        .enumerate()
    {
        for &(col, coeff) in lhs_lc {
            r1cs.a.insert(row, col, coeff);
        }
        for &(col, coeff) in rhs_lc {
            r1cs.a.insert(row, col, -coeff);
        }
        r1cs.a.insert(row, wrap_col + comp, -q_embed);
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }
    row
}

#[allow(clippy::too_many_arguments)]
fn insert_ext_mul_lc_mod_q(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    lhs: &ExtLc,
    rhs: &ExtLc,
    aux_col: usize,
    wrap_col: usize,
    q: u64,
    qnr: i64,
) -> (usize, ExtLc) {
    let q_embed = centered_mod(q as i128, BB_P);
    let p1 = aux_col;
    let p2 = aux_col + 1;
    let c0 = aux_col + 2;
    let c1 = aux_col + 3;

    for &(col, coeff) in &lhs.c0 {
        r1cs.a.insert(row, col, coeff);
    }
    for &(col, coeff) in &rhs.c0 {
        r1cs.b.insert(row, col, coeff);
    }
    r1cs.c.insert(row, p1, 1);
    r1cs.c.insert(row, wrap_col, q_embed);
    row += 1;

    for &(col, coeff) in &lhs.c1 {
        r1cs.a.insert(row, col, coeff);
    }
    for &(col, coeff) in &rhs.c1 {
        r1cs.b.insert(row, col, coeff);
    }
    r1cs.c.insert(row, p2, 1);
    r1cs.c.insert(row, wrap_col + 1, q_embed);
    row += 1;

    for &(col, coeff) in lhs.c0.iter().chain(lhs.c1.iter()) {
        r1cs.a.insert(row, col, coeff);
    }
    for &(col, coeff) in rhs.c0.iter().chain(rhs.c1.iter()) {
        r1cs.b.insert(row, col, coeff);
    }
    r1cs.c.insert(row, c1, 1);
    r1cs.c.insert(row, p1, 1);
    r1cs.c.insert(row, p2, 1);
    r1cs.c.insert(row, wrap_col + 2, q_embed);
    row += 1;

    r1cs.a.insert(row, 0, 1);
    r1cs.b.insert(row, c0, 1);
    r1cs.c.insert(row, p1, 1);
    r1cs.c.insert(row, p2, qnr);
    r1cs.c.insert(row, wrap_col + 3, q_embed);
    row += 1;

    (row, ext_var_lc(c0, c1))
}

fn monomial_round_eval_col(
    payload: &TypedCpRangePayloadBlockLayout,
    range_shape: &TypedCpRangeMessageShape,
    round: usize,
    point: usize,
    comp: usize,
) -> usize {
    let prev: usize = range_shape
        .monomial_sumcheck_round_evals
        .iter()
        .take(round)
        .map(|&eval_count| eval_count * 2)
        .sum();
    payload.off_monomial_sumcheck_evaluations + prev + point * 2 + comp
}

fn monomial_eval_col(
    payload: &TypedCpRangePayloadBlockLayout,
    range_shape: &TypedCpRangeMessageShape,
    vector: usize,
    coeff: usize,
    comp: usize,
) -> usize {
    let prev: usize = range_shape
        .monomial_evaluation_rows
        .iter()
        .take(vector)
        .map(|&rows| rows * D)
        .sum();
    payload.off_monomial_evaluations + prev + comp * D + coeff
}

fn monomial_sq_eval_col(
    payload: &TypedCpRangePayloadBlockLayout,
    vector: usize,
    comp: usize,
) -> usize {
    payload.off_sq_evaluations + vector * 2 + comp
}

fn insert_monomial_sumcheck_semantic_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    q: u64,
) -> usize {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let k_g = range_shape.monomial_evaluation_rows.len();
    assert!(range_shape
        .monomial_sumcheck_round_evals
        .iter()
        .all(|&eval_count| eval_count == 5));
    assert!(range_shape
        .monomial_evaluation_rows
        .iter()
        .all(|&rows| rows >= 2));
    assert_eq!(range_shape.sq_evaluations_count, k_g);

    let counts = monomial_sumcheck_semantic_counts(range_shape);
    assert_eq!(payload.monomial_sumcheck_aux_count, counts.aux_count);
    assert_eq!(payload.monomial_sumcheck_wrap_count, counts.wrap_count);

    let qnr = crate::ring::extension::ExtFieldContext::new(q).alpha;
    let inv2 = q_inv_const(2, q);
    let inv6 = q_inv_const(6, q);
    let inv24 = q_inv_const(24, q);
    let mut aux_offset = 0usize;
    let mut wrap_offset = 0usize;
    let mut claim = ext_zero_lc();

    let ext_mul = |r1cs: &mut R1CSMatrices,
                   row: usize,
                   lhs: &ExtLc,
                   rhs: &ExtLc,
                   aux_offset: &mut usize,
                   wrap_offset: &mut usize|
     -> (usize, ExtLc) {
        let (row, out) = insert_ext_mul_lc_mod_q(
            r1cs,
            row,
            lhs,
            rhs,
            payload.off_monomial_sumcheck_aux + *aux_offset,
            payload.off_monomial_sumcheck_wraps + *wrap_offset,
            q,
            qnr,
        );
        *aux_offset += 4;
        *wrap_offset += 4;
        (row, out)
    };

    for round in 0..nv {
        let ev = |point: usize| {
            ext_var_lc(
                monomial_round_eval_col(payload, range_shape, round, point, 0),
                monomial_round_eval_col(payload, range_shape, round, point, 1),
            )
        };
        let e0 = ev(0);
        let e1 = ev(1);
        let e2 = ev(2);
        let e3 = ev(3);
        let e4 = ev(4);
        let lhs = ext_add_lc(&e0, &e1);
        row = insert_ext_linear_eq_mod_q(
            r1cs,
            row,
            &lhs,
            &claim,
            payload.off_monomial_sumcheck_wraps + wrap_offset,
            q,
        );
        wrap_offset += 2;

        let d1 = ext_sub_lc(&e1, &e0);
        let d2 = ext_scale_lc(
            &ext_add_lc(&ext_sub_lc(&e0, &ext_scale_lc(&e1, 2)), &e2),
            inv2,
        );
        let d3 = ext_scale_lc(
            &ext_add_lc(
                &ext_add_lc(
                    &ext_sub_lc(&ext_scale_lc(&e1, 3), &e0),
                    &ext_scale_lc(&e2, -3),
                ),
                &e3,
            ),
            inv6,
        );
        let d4 = ext_scale_lc(
            &ext_add_lc(
                &ext_add_lc(
                    &ext_add_lc(
                        &ext_sub_lc(&e0, &ext_scale_lc(&e1, 4)),
                        &ext_scale_lc(&e2, 6),
                    ),
                    &ext_scale_lc(&e3, -4),
                ),
                &e4,
            ),
            inv24,
        );
        let r_chal = ext_var_lc(
            payload.off_monomial_sumcheck_challenges + round * 2,
            payload.off_monomial_sumcheck_challenges + round * 2 + 1,
        );
        let (next_row, m1) = ext_mul(
            r1cs,
            row,
            &d4,
            &ext_sub_lc(&r_chal, &ext_const_lc(3)),
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        let (next_row, m2) = ext_mul(
            r1cs,
            row,
            &ext_add_lc(&m1, &d3),
            &ext_sub_lc(&r_chal, &ext_const_lc(2)),
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        let (next_row, m3) = ext_mul(
            r1cs,
            row,
            &ext_add_lc(&m2, &d2),
            &ext_sub_lc(&r_chal, &ext_const_lc(1)),
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        let (next_row, m4) = ext_mul(
            r1cs,
            row,
            &ext_add_lc(&m3, &d1),
            &r_chal,
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        claim = ext_add_lc(&m4, &e0);
    }

    let eq_val = if nv == 0 {
        ext_one_lc()
    } else {
        let mut factor = ext_zero_lc();
        for i in 0..nv {
            let seed = ext_var_lc(
                payload.off_monomial_sumcheck_seed + i * 2,
                payload.off_monomial_sumcheck_seed + i * 2 + 1,
            );
            let r_idx = nv - 1 - i;
            let challenge = ext_var_lc(
                payload.off_monomial_sumcheck_challenges + r_idx * 2,
                payload.off_monomial_sumcheck_challenges + r_idx * 2 + 1,
            );
            let (next_row, sr) = ext_mul(
                r1cs,
                row,
                &seed,
                &challenge,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            let next_factor = ext_add_lc(
                &ext_sub_lc(&ext_sub_lc(&ext_scale_lc(&sr, 2), &seed), &challenge),
                &ext_one_lc(),
            );
            if i == 0 {
                factor = next_factor;
            } else {
                let (next_row, product) = ext_mul(
                    r1cs,
                    row,
                    &factor,
                    &next_factor,
                    &mut aux_offset,
                    &mut wrap_offset,
                );
                row = next_row;
                factor = product;
            }
        }
        factor
    };

    let alpha = ext_var_lc(payload.off_monomial_alpha, payload.off_monomial_alpha + 1);
    let total_terms = k_g * D + k_g;
    let mut combined = ext_zero_lc();
    let mut alpha_power = ext_one_lc();
    for term_idx in 0..total_terms {
        if term_idx == 1 {
            alpha_power = alpha.clone();
        } else if term_idx > 1 {
            let (next_row, next_power) = ext_mul(
                r1cs,
                row,
                &alpha_power,
                &alpha,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            alpha_power = next_power;
        }

        let poly_term = if term_idx < k_g * D {
            let vector = term_idx / D;
            let coeff = term_idx % D;
            let c_val = ext_var_lc(
                monomial_eval_col(payload, range_shape, vector, coeff, 0),
                monomial_eval_col(payload, range_shape, vector, coeff, 1),
            );
            let (next_row, c_minus_times_plus) = ext_mul(
                r1cs,
                row,
                &ext_sub_lc(&c_val, &ext_one_lc()),
                &ext_add_lc(&c_val, &ext_one_lc()),
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            let (next_row, cubic) = ext_mul(
                r1cs,
                row,
                &c_val,
                &c_minus_times_plus,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            cubic
        } else {
            let vector = term_idx - k_g * D;
            let sq = ext_var_lc(
                monomial_sq_eval_col(payload, vector, 0),
                monomial_sq_eval_col(payload, vector, 1),
            );
            let (next_row, sq_bool) = ext_mul(
                r1cs,
                row,
                &sq,
                &ext_sub_lc(&sq, &ext_one_lc()),
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            sq_bool
        };

        let weighted_term = if term_idx == 0 {
            poly_term
        } else {
            let (next_row, weighted) = ext_mul(
                r1cs,
                row,
                &alpha_power,
                &poly_term,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            weighted
        };
        combined = ext_add_lc(&combined, &weighted_term);
    }

    let expected = if nv == 0 {
        combined
    } else {
        let (next_row, expected) = ext_mul(
            r1cs,
            row,
            &eq_val,
            &combined,
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        expected
    };
    row = insert_ext_linear_eq_mod_q(
        r1cs,
        row,
        &expected,
        &claim,
        payload.off_monomial_sumcheck_wraps + wrap_offset,
        q,
    );
    wrap_offset += 2;

    row = insert_monomial_evaluation_binding_constraints(
        r1cs,
        row,
        range_shape,
        payload,
        q,
        qnr,
        &mut aux_offset,
        &mut wrap_offset,
    );

    debug_assert_eq!(aux_offset, payload.monomial_sumcheck_aux_count);
    debug_assert_eq!(wrap_offset, payload.monomial_sumcheck_wrap_count);
    row
}

#[allow(clippy::too_many_arguments)]
fn insert_monomial_evaluation_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    q: u64,
    qnr: i64,
    aux_offset: &mut usize,
    wrap_offset: &mut usize,
) -> usize {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let table_size = 1usize
        .checked_shl(nv as u32)
        .expect("typed CP monomial sumcheck round count too large");
    assert_eq!(
        range_shape.monomial_vector_lens.len(),
        range_shape.monomial_evaluation_rows.len()
    );
    assert_eq!(
        range_shape.sq_evaluations_count,
        range_shape.monomial_vector_lens.len()
    );
    assert!(range_shape
        .monomial_vector_lens
        .iter()
        .all(|&vector_len| vector_len <= table_size));

    let mut vector_coeff_offset = 0usize;
    for (vector_idx, &vector_len) in range_shape.monomial_vector_lens.iter().enumerate() {
        for coeff in 0..D {
            let mut initial = Vec::with_capacity(table_size);
            for idx in 0..table_size {
                if idx < vector_len {
                    initial.push(ExtLc {
                        c0: vec![(
                            payload.off_monomial_vectors + vector_coeff_offset + idx * D + coeff,
                            1,
                        )],
                        c1: Vec::new(),
                    });
                } else {
                    initial.push(ext_zero_lc());
                }
            }
            let claim = ext_var_lc(
                monomial_eval_col(payload, range_shape, vector_idx, coeff, 0),
                monomial_eval_col(payload, range_shape, vector_idx, coeff, 1),
            );
            row = insert_mle_binding_constraints(
                r1cs,
                row,
                initial,
                &claim,
                payload,
                q,
                qnr,
                aux_offset,
                wrap_offset,
            );
        }

        let mut initial_sq = Vec::with_capacity(table_size);
        for idx in 0..table_size {
            if idx < vector_len {
                let square_start =
                    payload.off_monomial_vector_squares + vector_coeff_offset + idx * D;
                initial_sq.push(ExtLc {
                    c0: (0..D).map(|coeff| (square_start + coeff, 1)).collect(),
                    c1: Vec::new(),
                });
            } else {
                initial_sq.push(ext_zero_lc());
            }
        }
        let sq_claim = ext_var_lc(
            monomial_sq_eval_col(payload, vector_idx, 0),
            monomial_sq_eval_col(payload, vector_idx, 1),
        );
        row = insert_mle_binding_constraints(
            r1cs,
            row,
            initial_sq,
            &sq_claim,
            payload,
            q,
            qnr,
            aux_offset,
            wrap_offset,
        );

        vector_coeff_offset += vector_len * D;
    }
    row
}

#[allow(clippy::too_many_arguments)]
fn insert_mle_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    mut values: Vec<ExtLc>,
    claim: &ExtLc,
    payload: &TypedCpRangePayloadBlockLayout,
    q: u64,
    qnr: i64,
    aux_offset: &mut usize,
    wrap_offset: &mut usize,
) -> usize {
    let mut round = 0usize;
    while values.len() > 1 {
        let half = values.len() / 2;
        let challenge = ext_var_lc(
            payload.off_monomial_sumcheck_challenges + round * 2,
            payload.off_monomial_sumcheck_challenges + round * 2 + 1,
        );
        let mut next = Vec::with_capacity(half);
        for idx in 0..half {
            let left = &values[idx];
            let right = &values[half + idx];
            let diff = ext_sub_lc(right, left);
            let (next_row, scaled) = insert_ext_mul_lc_mod_q(
                r1cs,
                row,
                &challenge,
                &diff,
                payload.off_monomial_sumcheck_aux + *aux_offset,
                payload.off_monomial_sumcheck_wraps + *wrap_offset,
                q,
                qnr,
            );
            row = next_row;
            *aux_offset += 4;
            *wrap_offset += 4;

            let folded = ext_var_lc(
                payload.off_monomial_sumcheck_aux + *aux_offset,
                payload.off_monomial_sumcheck_aux + *aux_offset + 1,
            );
            row = insert_ext_linear_eq_mod_q(
                r1cs,
                row,
                &ext_add_lc(left, &scaled),
                &folded,
                payload.off_monomial_sumcheck_wraps + *wrap_offset,
                q,
            );
            *aux_offset += 2;
            *wrap_offset += 2;
            next.push(folded);
        }
        values = next;
        round += 1;
    }

    row = insert_ext_linear_eq_mod_q(
        r1cs,
        row,
        &values[0],
        claim,
        payload.off_monomial_sumcheck_wraps + *wrap_offset,
        q,
    );
    *wrap_offset += 2;
    row
}
