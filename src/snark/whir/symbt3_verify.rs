fn elapsed_ms(start: std::time::Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn verify_symbt3_batched_cp_with_profile(
    vk: &WhirVerifyingKey,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    proof: &WhirProof,
    mut profile: Option<&mut Symbt3VerifierCostProfile>,
) -> Option<bool> {
    let total_start = std::time::Instant::now();
    let decode_start = std::time::Instant::now();
    let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
        vk.relation.context.as_ref()?,
    )
    .ok()?;
    let statement_bytes = statement.canonical_bytes();
    if !statement.matches_relation(&relation)
        || statement_bytes.len() != relation.public_statement_bytes()
    {
        if let Some(profile) = profile.as_deref_mut() {
            let elapsed = elapsed_ms(decode_start);
            profile.verify_accumulator_decoding_ms += elapsed;
            profile.verify_public_input_parsing_ms += elapsed;
            profile.verify_total_ms = elapsed_ms(total_start);
        }
        return Some(false);
    }
    if let Some(profile) = profile.as_deref_mut() {
        let elapsed = elapsed_ms(decode_start);
        profile.verify_accumulator_decoding_ms += elapsed;
        profile.verify_public_input_parsing_ms += elapsed;
    }

    let proof_decode_start = std::time::Instant::now();
    if proof.is_output
        || !proof.sumcheck_rounds_3.is_empty()
        || !proof.linear_checks.is_empty()
        || !proof.family_columnar_subproofs.is_empty()
        || !relation.has_symbt3_i_families()
    {
        if let Some(profile) = profile.as_deref_mut() {
            profile.verify_proof_deserialization_ms += elapsed_ms(proof_decode_start);
            profile.verify_total_ms = elapsed_ms(total_start);
        }
        return Some(false);
    }
    if let Some(profile) = profile.as_deref_mut() {
        profile.verify_proof_deserialization_ms += elapsed_ms(proof_decode_start);
    }

    let transcript_start = std::time::Instant::now();
    if let Some(profile) = profile.as_deref_mut() {
        profile.verify_transcript_ms += elapsed_ms(transcript_start);
    }

    let constraint_start = std::time::Instant::now();
    let Some(claims) = symbt3_c_table_and_claims(
        &vk.seed,
        &relation,
        statement,
        None,
        Some(&proof.private_opening_evals),
        Some(&proof.sumcheck_rounds_4),
    ) else {
        if let Some(profile) = profile.as_deref_mut() {
            profile.verify_final_constraint_eval_ms += elapsed_ms(constraint_start);
            profile.verify_total_ms = elapsed_ms(total_start);
        }
        return Some(false);
    };
    if let Some(profile) = profile.as_deref_mut() {
        let elapsed = elapsed_ms(constraint_start);
        profile.verify_final_constraint_eval_ms += elapsed;
        profile.verify_constraint_batching_ms += elapsed;
        profile.verify_field_ops_ms += elapsed;
        profile.verify_field_extension_ops_ms += claims.eval_profile.verify_sumcheck_rounds_ms;
        profile.verify_fold_query_eval_ms += claims.eval_profile.verify_final_eval_folded_boundary_ms;
        profile.verify_eq_lagrange_eval_ms += claims.eval_profile.verify_sumcheck_rounds_ms
            + claims.eval_profile.verify_final_eval_product_residual_ms;
        profile.verify_sumcheck_rounds_ms += claims.eval_profile.verify_sumcheck_rounds_ms;
        profile.verify_final_eval_manifest_ms += claims.eval_profile.verify_final_eval_manifest_ms;
        profile.verify_final_eval_source_r1cs_ms +=
            claims.eval_profile.verify_final_eval_source_r1cs_ms;
        profile.verify_final_eval_folded_boundary_ms +=
            claims.eval_profile.verify_final_eval_folded_boundary_ms;
        profile.verify_final_eval_product_residual_ms +=
            claims.eval_profile.verify_final_eval_product_residual_ms;
        profile.verify_final_eval_ajtai_ms += claims.eval_profile.verify_final_eval_ajtai_ms;
        profile.verify_final_eval_range_ms += claims.eval_profile.verify_final_eval_range_ms;
        profile.verify_final_eval_message_view_ms +=
            claims.eval_profile.verify_final_eval_message_view_ms;
        profile.verify_manifest_membership_eval_ms +=
            claims.eval_profile.verify_manifest_membership_eval_ms;
        profile.verify_message_view_eval_ms += claims.eval_profile.verify_message_view_eval_ms;
        profile.verify_projection_eval_ms += claims.eval_profile.verify_projection_eval_ms;
        profile.verify_monomial_embedding_eval_ms +=
            claims.eval_profile.verify_monomial_embedding_eval_ms;
        profile.verify_representative_eval_ms += claims.eval_profile.verify_representative_eval_ms;
        profile.verify_ajtai_eval_ms += claims.eval_profile.verify_ajtai_eval_ms;
        profile.source_r1cs_residual_claims = claims.eval_profile.source_r1cs_residual_claims;
        profile.source_r1cs_residual_verifier_evaluations = claims
            .eval_profile
            .source_r1cs_residual_verifier_evaluations;
    }
    if proof.num_vars != claims.num_vars
        || proof.evaluations != claims.evaluations
        || proof.z_eval != claims.z_eval
        || claims
            .evaluations
            .iter()
            .any(|&eval| eval != BabyBear::ZERO)
    {
        if let Some(profile) = profile.as_deref_mut() {
            profile.verify_total_ms = elapsed_ms(total_start);
        }
        return Some(false);
    }
    let pcs_start = std::time::Instant::now();
    let ok = whir_verify_opening_multi(
        &vk.seed,
        claims.num_vars,
        &proof.whir_pcs_proof,
        &claims.points,
        &proof.private_opening_evals,
    );
    if let Some(profile) = profile.as_deref_mut() {
        let pcs_ms = elapsed_ms(pcs_start);
        profile.verify_whir_pcs_ms += pcs_ms;
        profile.verify_merkle_or_pcs_opening_ms += pcs_ms;
        profile.verify_total_ms = elapsed_ms(total_start);
    }
    Some(ok)
}

// ---------------------------------------------------------------------------
// Output SNARK: full R1CS verification via sumcheck over BabyBear
// ---------------------------------------------------------------------------

/// Sparse matrix in COO format over BabyBear.
#[derive(Debug, Clone)]
struct FlatSparseMatrixBB {
    entries: Vec<(usize, usize, BabyBear)>,
    #[allow(dead_code)]
    num_rows: usize,
    #[allow(dead_code)]
    num_cols: usize,
}

/// Flatten ring R1CS to scalar R1CS over BabyBear.
fn flatten_ring_r1cs_bb(
    a: &SparseMatrix,
    b: &SparseMatrix,
    c: &SparseMatrix,
    num_constraints: usize,
    num_variables: usize,
    d: usize,
    _q: u64,
) -> (FlatSparseMatrixBB, FlatSparseMatrixBB, FlatSparseMatrixBB) {
    let flat_rows = num_constraints * d;
    let flat_cols = num_variables * d;

    let flatten_matrix = |mat: &SparseMatrix| -> FlatSparseMatrixBB {
        let mut entries = Vec::with_capacity(mat.entries.len() * d);
        for &(row, col, val) in &mat.entries {
            let s = BabyBear::from_i64(val);
            for j in 0..d {
                entries.push((row * d + j, col * d + j, s));
            }
        }
        FlatSparseMatrixBB {
            entries,
            num_rows: flat_rows,
            num_cols: flat_cols,
        }
    };

    (flatten_matrix(a), flatten_matrix(b), flatten_matrix(c))
}

/// Compute Az, Bz, Cz as dense vectors.
fn compute_matrix_vector_products_bb(
    flat_a: &FlatSparseMatrixBB,
    flat_b: &FlatSparseMatrixBB,
    flat_c: &FlatSparseMatrixBB,
    z_flat: &[BabyBear],
    num_vars: usize,
) -> (Vec<BabyBear>, Vec<BabyBear>, Vec<BabyBear>) {
    let n = 1 << num_vars;

    let sparse_mul = |mat: &FlatSparseMatrixBB| -> Vec<BabyBear> {
        let mut result = vec![BabyBear::ZERO; n];
        for &(row, col, val) in &mat.entries {
            if row < n && col < z_flat.len() {
                result[row] += val * z_flat[col];
            }
        }
        result
    };

    (sparse_mul(flat_a), sparse_mul(flat_b), sparse_mul(flat_c))
}

fn eval_eq_index_bb(point: &[BabyBear], index: usize) -> BabyBear {
    point
        .iter()
        .enumerate()
        .fold(BabyBear::ONE, |acc, (bit, &r)| {
            let shift = point.len() - 1 - bit;
            if ((index >> shift) & 1) == 1 {
                acc * r
            } else {
                acc * (BabyBear::ONE - r)
            }
        })
}

fn compute_matrix_mle_row_bb(
    mat: &FlatSparseMatrixBB,
    row_point: &[BabyBear],
    num_cols: usize,
) -> Vec<BabyBear> {
    let mut result = vec![BabyBear::ZERO; num_cols];
    let num_rows = 1usize << row_point.len();
    for &(row, col, val) in &mat.entries {
        if row < num_rows && col < num_cols {
            result[col] += eval_eq_index_bb(row_point, row) * val;
        }
    }
    result
}

fn eval_matrix_mle_at_points_bb(
    mat: &FlatSparseMatrixBB,
    row_point: &[BabyBear],
    col_point: &[BabyBear],
    num_cols: usize,
) -> BabyBear {
    let num_rows = 1usize << row_point.len();
    mat.entries
        .iter()
        .filter(|&&(row, col, _)| row < num_rows && col < num_cols)
        .fold(BabyBear::ZERO, |acc, &(row, col, val)| {
            acc + val * eval_eq_index_bb(row_point, row) * eval_eq_index_bb(col_point, col)
        })
}

fn pad_point(point: &[BabyBear], len: usize) -> Vec<BabyBear> {
    point
        .iter()
        .copied()
        .chain(std::iter::repeat(BabyBear::ZERO))
        .take(len)
        .collect()
}

fn sumcheck_point_to_mle_point(point: &[BabyBear], len: usize) -> Vec<BabyBear> {
    let mut padded = pad_point(point, len);
    padded.reverse();
    padded
}

fn boolean_point_for_index(index: usize, len: usize) -> Vec<BabyBear> {
    (0..len)
        .map(|bit| {
            if ((index >> bit) & 1) == 1 {
                BabyBear::ONE
            } else {
                BabyBear::ZERO
            }
        })
        .collect()
}
