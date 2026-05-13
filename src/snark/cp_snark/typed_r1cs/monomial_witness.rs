fn append_monomial_sumcheck_semantic_witness(
    out: &mut Vec<u8>,
    proof: &GR1CSProof,
    shared: &crate::cp_relation_core::CpSharedChallengeData,
    block: &TypedCpRangePayloadBlockLayout,
    q: u64,
) -> Option<()> {
    let range_proof = &proof.range_proof;
    let monomial_proof = &range_proof.monomial_proof;
    let nv = monomial_proof.sumcheck_proof.round_messages.len();
    let k_g = monomial_proof.evaluations.len();
    if shared.sumcheck_seed_mon.len() != nv
        || shared.monomial_sumcheck_challenges.len() != nv
        || monomial_proof.sq_evaluations.len() != k_g
    {
        return None;
    }
    if monomial_proof
        .sumcheck_proof
        .round_messages
        .iter()
        .any(|round| round.evaluations.len() != 5)
    {
        return None;
    }

    for challenge in &shared.sumcheck_seed_mon {
        out.extend_from_slice(&challenge.c0.to_le_bytes());
        out.extend_from_slice(&challenge.c1.to_le_bytes());
    }
    for challenge in &shared.monomial_sumcheck_challenges {
        out.extend_from_slice(&challenge.c0.to_le_bytes());
        out.extend_from_slice(&challenge.c1.to_le_bytes());
    }
    out.extend_from_slice(&shared.alpha.c0.to_le_bytes());
    out.extend_from_slice(&shared.alpha.c1.to_le_bytes());

    let mut aux_values = Vec::<i64>::new();
    let mut wrap_values = Vec::<i64>::new();
    let mut claim = ext_wit_const(0);
    let inv2 = q_inv_const(2, q);
    let inv6 = q_inv_const(6, q);
    let inv24 = q_inv_const(24, q);

    for round in 0..nv {
        let evals = &monomial_proof.sumcheck_proof.round_messages[round].evaluations;
        push_ext_linear_eq_wrap(
            ext_wit_add(ext_wit(evals[0]), ext_wit(evals[1]), q),
            claim,
            q,
            &mut wrap_values,
        )?;

        let e0 = ext_wit(evals[0]);
        let e1 = ext_wit(evals[1]);
        let e2 = ext_wit(evals[2]);
        let e3 = ext_wit(evals[3]);
        let e4 = ext_wit(evals[4]);
        let d1 = ext_wit_sub(e1, e0, q);
        let d2 = ext_wit_scale(
            ext_wit_add(ext_wit_sub(e0, ext_wit_scale(e1, 2, q), q), e2, q),
            inv2,
            q,
        );
        let d3 = ext_wit_scale(
            ext_wit_add(
                ext_wit_add(
                    ext_wit_sub(ext_wit_scale(e1, 3, q), e0, q),
                    ext_wit_scale(e2, -3, q),
                    q,
                ),
                e3,
                q,
            ),
            inv6,
            q,
        );
        let d4 = ext_wit_scale(
            ext_wit_add(
                ext_wit_add(
                    ext_wit_add(
                        ext_wit_sub(e0, ext_wit_scale(e1, 4, q), q),
                        ext_wit_scale(e2, 6, q),
                        q,
                    ),
                    ext_wit_scale(e3, -4, q),
                    q,
                ),
                e4,
                q,
            ),
            inv24,
            q,
        );
        let r = ext_wit(shared.monomial_sumcheck_challenges[round]);
        let m1 = record_ext_mul_value(
            d4,
            ext_wit_sub(r, ext_wit_const(3), q),
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        let m2 = record_ext_mul_value(
            ext_wit_add(m1, d3, q),
            ext_wit_sub(r, ext_wit_const(2), q),
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        let m3 = record_ext_mul_value(
            ext_wit_add(m2, d2, q),
            ext_wit_sub(r, ext_wit_const(1), q),
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        let m4 = record_ext_mul_value(
            ext_wit_add(m3, d1, q),
            r,
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        claim = ext_wit_add(m4, e0, q);
    }

    let eq_val = if nv == 0 {
        ext_wit_const(1)
    } else {
        let mut acc = ext_wit_const(0);
        for i in 0..nv {
            let seed = ext_wit(shared.sumcheck_seed_mon[i]);
            let r = ext_wit(shared.monomial_sumcheck_challenges[nv - 1 - i]);
            let sr = record_ext_mul_value(seed, r, q, &mut aux_values, &mut wrap_values)?;
            let factor = ext_wit_add(
                ext_wit_sub(ext_wit_sub(ext_wit_scale(sr, 2, q), seed, q), r, q),
                ext_wit_const(1),
                q,
            );
            if i == 0 {
                acc = factor;
            } else {
                acc = record_ext_mul_value(acc, factor, q, &mut aux_values, &mut wrap_values)?;
            }
        }
        acc
    };

    let total_terms = k_g * D + k_g;
    let mut combined = ext_wit_const(0);
    let mut alpha_power = ext_wit_const(1);
    let alpha = ext_wit(shared.alpha);
    for term_idx in 0..total_terms {
        if term_idx == 1 {
            alpha_power = alpha;
        } else if term_idx > 1 {
            alpha_power =
                record_ext_mul_value(alpha_power, alpha, q, &mut aux_values, &mut wrap_values)?;
        }

        let poly_term = if term_idx < k_g * D {
            let vector = term_idx / D;
            let coeff = term_idx % D;
            let c_val = ext_wit(monomial_proof.evaluations[vector].col(coeff));
            let c_minus_times_plus = record_ext_mul_value(
                ext_wit_sub(c_val, ext_wit_const(1), q),
                ext_wit_add(c_val, ext_wit_const(1), q),
                q,
                &mut aux_values,
                &mut wrap_values,
            )?;
            record_ext_mul_value(
                c_val,
                c_minus_times_plus,
                q,
                &mut aux_values,
                &mut wrap_values,
            )?
        } else {
            let vector = term_idx - k_g * D;
            let sq = ext_wit(monomial_proof.sq_evaluations[vector]);
            record_ext_mul_value(
                sq,
                ext_wit_sub(sq, ext_wit_const(1), q),
                q,
                &mut aux_values,
                &mut wrap_values,
            )?
        };

        let weighted_term = if term_idx == 0 {
            poly_term
        } else {
            record_ext_mul_value(alpha_power, poly_term, q, &mut aux_values, &mut wrap_values)?
        };
        combined = ext_wit_add(combined, weighted_term, q);
    }

    let expected = if nv == 0 {
        combined
    } else {
        record_ext_mul_value(eq_val, combined, q, &mut aux_values, &mut wrap_values)?
    };
    push_ext_linear_eq_wrap(expected, claim, q, &mut wrap_values)?;

    append_monomial_evaluation_binding_witness(
        proof,
        shared,
        q,
        &mut aux_values,
        &mut wrap_values,
    )?;

    if aux_values.len() != block.monomial_sumcheck_aux_count
        || wrap_values.len() != block.monomial_sumcheck_wrap_count
    {
        return None;
    }
    for value in aux_values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in wrap_values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Some(())
}

fn append_monomial_evaluation_binding_witness(
    proof: &GR1CSProof,
    shared: &crate::cp_relation_core::CpSharedChallengeData,
    q: u64,
    aux_values: &mut Vec<i64>,
    wrap_values: &mut Vec<i64>,
) -> Option<()> {
    let monomial_proof = &proof.range_proof.monomial_proof;
    let nv = monomial_proof.sumcheck_proof.round_messages.len();
    let table_size = 1usize.checked_shl(nv as u32)?;
    if shared.monomial_sumcheck_challenges.len() != nv {
        return None;
    }

    for (vector_idx, monomial_vector) in proof.range_proof.monomial_vectors.iter().enumerate() {
        let tensor = monomial_proof.evaluations.get(vector_idx)?;
        for coeff in 0..D {
            let mut initial = Vec::with_capacity(table_size);
            for idx in 0..table_size {
                let value = monomial_vector
                    .get(idx)
                    .map(|elem| elem.coeffs[coeff])
                    .unwrap_or(0);
                initial.push(ext_wit(ExtFieldElement { c0: value, c1: 0 }));
            }
            append_mle_binding_witness(
                initial,
                ext_wit(tensor.col(coeff)),
                &shared.monomial_sumcheck_challenges,
                q,
                aux_values,
                wrap_values,
            )?;
        }

        let mut initial_sq = Vec::with_capacity(table_size);
        for idx in 0..table_size {
            let sq_sum = monomial_vector
                .get(idx)
                .map(|elem| elem.coeffs.iter().map(|&coeff| coeff * coeff).sum())
                .unwrap_or(0);
            initial_sq.push(ext_wit(ExtFieldElement { c0: sq_sum, c1: 0 }));
        }
        append_mle_binding_witness(
            initial_sq,
            ext_wit(*monomial_proof.sq_evaluations.get(vector_idx)?),
            &shared.monomial_sumcheck_challenges,
            q,
            aux_values,
            wrap_values,
        )?;
    }
    Some(())
}

fn append_mle_binding_witness(
    mut values: Vec<ExtWitnessValue>,
    claim: ExtWitnessValue,
    challenges: &[ExtFieldElement],
    q: u64,
    aux_values: &mut Vec<i64>,
    wrap_values: &mut Vec<i64>,
) -> Option<()> {
    for challenge in challenges {
        let half = values.len() / 2;
        let r = ext_wit(*challenge);
        let mut next = Vec::with_capacity(half);
        for idx in 0..half {
            let left = values[idx];
            let right = values[half + idx];
            let diff = ext_wit_sub(right, left, q);
            let scaled = record_ext_mul_value(r, diff, q, aux_values, wrap_values)?;
            let folded_expr = ext_wit_add(left, scaled, q);
            let folded_var = ext_wit(folded_expr.reduced);
            aux_values.extend_from_slice(&[folded_var.reduced.c0, folded_var.reduced.c1]);
            push_ext_linear_eq_wrap(folded_expr, folded_var, q, wrap_values)?;
            next.push(folded_var);
        }
        values = next;
    }
    if values.len() != 1 {
        return None;
    }
    push_ext_linear_eq_wrap(values[0], claim, q, wrap_values)
}

#[derive(Clone, Copy)]
struct ExtWitnessValue {
    reduced: ExtFieldElement,
    raw_c0: i128,
    raw_c1: i128,
}

fn ext_wit(value: ExtFieldElement) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: value,
        raw_c0: value.c0 as i128,
        raw_c1: value.c1 as i128,
    }
}

fn ext_wit_const(value: i64) -> ExtWitnessValue {
    ext_wit(ExtFieldElement { c0: value, c1: 0 })
}

fn ext_wit_add(a: ExtWitnessValue, b: ExtWitnessValue, q: u64) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: ExtFieldElement {
            c0: centered_mod(a.reduced.c0 as i128 + b.reduced.c0 as i128, q),
            c1: centered_mod(a.reduced.c1 as i128 + b.reduced.c1 as i128, q),
        },
        raw_c0: a.raw_c0 + b.raw_c0,
        raw_c1: a.raw_c1 + b.raw_c1,
    }
}

fn ext_wit_sub(a: ExtWitnessValue, b: ExtWitnessValue, q: u64) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: ExtFieldElement {
            c0: centered_mod(a.reduced.c0 as i128 - b.reduced.c0 as i128, q),
            c1: centered_mod(a.reduced.c1 as i128 - b.reduced.c1 as i128, q),
        },
        raw_c0: a.raw_c0 - b.raw_c0,
        raw_c1: a.raw_c1 - b.raw_c1,
    }
}

fn ext_wit_scale(a: ExtWitnessValue, coeff: i64, q: u64) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: ExtFieldElement {
            c0: centered_mod(a.reduced.c0 as i128 * coeff as i128, q),
            c1: centered_mod(a.reduced.c1 as i128 * coeff as i128, q),
        },
        raw_c0: a.raw_c0 * coeff as i128,
        raw_c1: a.raw_c1 * coeff as i128,
    }
}

fn q_wrap(diff: i128, q: u64) -> Option<i64> {
    if diff.rem_euclid(q as i128) != 0 {
        return None;
    }
    i64::try_from(diff / q as i128).ok()
}

fn push_ext_linear_eq_wrap(
    lhs: ExtWitnessValue,
    rhs: ExtWitnessValue,
    q: u64,
    wraps: &mut Vec<i64>,
) -> Option<()> {
    wraps.push(q_wrap(lhs.raw_c0 - rhs.raw_c0, q)?);
    wraps.push(q_wrap(lhs.raw_c1 - rhs.raw_c1, q)?);
    Some(())
}

fn record_ext_mul_value(
    lhs: ExtWitnessValue,
    rhs: ExtWitnessValue,
    q: u64,
    aux_values: &mut Vec<i64>,
    wrap_values: &mut Vec<i64>,
) -> Option<ExtWitnessValue> {
    let qnr = crate::ring::extension::ExtFieldContext::new(q).alpha;
    let p1 = centered_mod(lhs.raw_c0 * rhs.raw_c0, q);
    let p2 = centered_mod(lhs.raw_c1 * rhs.raw_c1, q);
    let c1 = centered_mod(
        (lhs.raw_c0 + lhs.raw_c1) * (rhs.raw_c0 + rhs.raw_c1) - p1 as i128 - p2 as i128,
        q,
    );
    let c0 = centered_mod(p1 as i128 + qnr as i128 * p2 as i128, q);

    aux_values.extend_from_slice(&[p1, p2, c0, c1]);
    wrap_values.push(q_wrap(lhs.raw_c0 * rhs.raw_c0 - p1 as i128, q)?);
    wrap_values.push(q_wrap(lhs.raw_c1 * rhs.raw_c1 - p2 as i128, q)?);
    wrap_values.push(q_wrap(
        (lhs.raw_c0 + lhs.raw_c1) * (rhs.raw_c0 + rhs.raw_c1)
            - c1 as i128
            - p1 as i128
            - p2 as i128,
        q,
    )?);
    wrap_values.push(q_wrap(
        c0 as i128 - p1 as i128 - qnr as i128 * p2 as i128,
        q,
    )?);

    Some(ext_wit(ExtFieldElement { c0, c1 }))
}
