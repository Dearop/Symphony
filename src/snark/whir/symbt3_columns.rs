#[derive(Clone)]
struct Symbt3CClaims {
    table: Option<Vec<BabyBear>>,
    points: Vec<Vec<BabyBear>>,
    claimed: Vec<BabyBear>,
    evaluations: [BabyBear; 3],
    z_eval: BabyBear,
    num_vars: usize,
    product_sumcheck_rounds: Vec<[BabyBear; 4]>,
    eval_profile: Symbt3VerifierCostProfile,
}

fn symbt3_c_table_and_claims(
    seed: &[u8; 32],
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    witness: Option<&crate::batched_cp::BatchedCpSymbt3Witness>,
    claimed_override: Option<&[BabyBear]>,
    product_sumcheck_rounds_override: Option<&[[BabyBear; 4]]>,
) -> Option<Symbt3CClaims> {
    let mut eval_profile = Symbt3VerifierCostProfile::default();
    if !statement.matches_relation(relation) || !relation.has_symbt3_i_families() {
        return None;
    }
    let commitment_len = relation.symbt3_commitment_coordinate_len();
    let opening_len = relation.ring_module_layout.opening_module_dimension
        * relation.ring_module_layout.ring_degree;
    if commitment_len == 0
        || opening_len == 0
        || statement.folded_ajtai_commitment.len() != commitment_len
        || statement.input_commitment_values.len() != statement.active_count
        || statement
            .input_commitment_values
            .iter()
            .any(|row| row.len() != commitment_len)
    {
        return None;
    }

    let r1cs_residual_len = statement.source_assignment_roots.len()
        * relation.r1cs_evaluator_layout.num_constraints
        * D;
    eval_profile.source_r1cs_residual_claims = r1cs_residual_len;
    eval_profile.source_r1cs_residual_verifier_evaluations = usize::from(r1cs_residual_len > 0);
    let gr1cs_residual_len = relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count
        / 3;
    let product_residual_len = gr1cs_residual_len;
    let projection_len = relation
        .ajtai_norm_range_layout
        .projection_layout
        .output_len;
    let row_len = commitment_len
        .max(opening_len)
        .max(r1cs_residual_len)
        .max(gr1cs_residual_len)
        .max(product_residual_len)
        .max(projection_len);
    let row_count = row_len.next_power_of_two().max(1);
    let row_vars = row_count.trailing_zeros() as usize;
    let acted_commitment_sum_col: usize = 1;
    let commitment_wrap_col = 2;
    let folded_opening_col = 3;
    let acted_opening_sum_col = 4;
    let opening_wrap_col = 5;
    let ajtai_actual_col = 6;
    let source_r1cs_residual_col = 7;
    let folded_gr1cs_residual_col = source_r1cs_residual_col + 1;
    let product_residual_col = folded_gr1cs_residual_col + 1;
    let projected_opening_col = product_residual_col + 1;
    let projection_residual_col = projected_opening_col + 1;
    let range_residual_col = projection_residual_col + 1;
    let monomial_residual_col = range_residual_col + 1;
    let column_count: usize = monomial_residual_col + 1;
    let padded_column_count = column_count.next_power_of_two().max(1);
    let col_vars = padded_column_count.trailing_zeros() as usize;
    let num_vars = row_vars + col_vars;

    let beta_rings = crate::batched_cp::derive_symbt3_beta_ring_elements(relation, statement);
    let source_commitment_ring = statement
        .input_commitment_values
        .iter()
        .map(|row| {
            symbt3_flat_to_ring_vector(row, relation.ring_module_layout.commitment_module_dimension)
        })
        .collect::<Vec<_>>();
    let (folded_commitment_check, commitment_wrap) = symbt3_ring_fold_with_wrap(
        &statement.input_commitment_values,
        &beta_rings,
        relation.ring_module_layout.commitment_module_dimension,
        relation.ring_module_layout.modulus,
    );
    if folded_commitment_check != statement.folded_ajtai_commitment {
        return None;
    }
    let acted_commitments = source_commitment_ring
        .iter()
        .zip(beta_rings.iter())
        .map(|(value, beta)| value.ring_scalar_mul(beta, relation.ring_module_layout.modulus))
        .collect::<Vec<_>>();
    let acted_commitment_sum = symbt3_sum_ring_vectors_flat(&acted_commitments);
    let public_manifest_view_eval = BabyBear::from_u32(
        crate::batched_cp::symbt3_canonical_manifest_view_eval_for_statement(
            relation,
            statement,
            &statement.manifest_oracle_root,
        )?,
    );
    let public_source_view_eval = BabyBear::from_u32(
        crate::batched_cp::symbt3_virtual_source_view_eval_for_statement(
            relation,
            statement,
            &statement.manifest_oracle_root,
        )?,
    );
    // SYMBT3-K1e.2 treats SourceView as a virtual public-boundary evaluator.
    // The verifier derives both sides from compressed public boundary data
    // instead of committing a dense source-view column in the WHIR table.
    eval_profile.verify_manifest_membership_eval_ms += 0.0;
    eval_profile.verify_final_eval_manifest_ms += 0.0;
    let (mut product_l_values, mut product_r_values, mut product_o_values) =
        symbt3_folded_gr1cs_product_columns(relation, statement)?;
    let mut product_residual_values = symbt3_folded_gr1cs_product_residual_values(
        relation,
        &product_l_values,
        &product_r_values,
        &product_o_values,
    )?;
    product_l_values.resize(row_count, BabyBear::ZERO);
    product_r_values.resize(row_count, BabyBear::ZERO);
    product_o_values.resize(row_count, BabyBear::ZERO);
    product_residual_values.resize(row_count, BabyBear::ZERO);
    let product_transcript =
        symbt3_d2_product_sumcheck_transcript(seed, relation, statement, row_count);
    let product_rho = (0..row_vars)
        .map(|idx| derive_challenge(&product_transcript, idx, b"symbt3-d2-prod-rho"))
        .collect::<Vec<_>>();
    let product_eq_table = build_eq_table_bb(&product_rho, row_vars);

    let table = witness.map(|witness| {
        if witness.source_ajtai_opening_values.len() != statement.active_count
            || witness.folded_ajtai_opening_values.len() != opening_len
            || witness.source_r1cs_assignment_values.len()
                != statement.source_assignment_roots.len()
            || witness.message_oracles.len() != relation.oracle_layout.message_oracles.len()
            || witness
                .source_ajtai_opening_values
                .iter()
                .any(|row| row.len() != opening_len)
            || witness
                .source_r1cs_assignment_values
                .iter()
                .any(|row| row.len() != relation.r1cs_evaluator_layout.num_variables * D)
        {
            return Vec::new();
        }
        for (round, (rows, root)) in witness
            .message_oracles
            .iter()
            .zip(statement.message_oracle_roots.iter())
            .enumerate()
        {
            if crate::batched_cp::symbt3_message_oracle_root(
                relation.shape.accumulator_shape.digest_scheme,
                &relation.shape,
                round,
                rows,
            ) != *root
            {
                return Vec::new();
            }
        }
        for (row, root) in witness
            .source_r1cs_assignment_values
            .iter()
            .zip(statement.source_assignment_roots.iter())
        {
            if symbt3_source_assignment_root_for_whir(relation, row) != *root {
                return Vec::new();
            }
        }
        let (folded_opening_check, opening_wrap) = symbt3_ring_fold_with_wrap(
            &witness.source_ajtai_opening_values,
            &beta_rings,
            relation.ring_module_layout.opening_module_dimension,
            relation.ring_module_layout.modulus,
        );
        if folded_opening_check != witness.folded_ajtai_opening_values {
            return Vec::new();
        }
        let source_openings = witness
            .source_ajtai_opening_values
            .iter()
            .map(|row| {
                symbt3_flat_to_ring_vector(
                    row,
                    relation.ring_module_layout.opening_module_dimension,
                )
            })
            .collect::<Vec<_>>();
        let folded_opening = symbt3_flat_to_ring_vector(
            &witness.folded_ajtai_opening_values,
            relation.ring_module_layout.opening_module_dimension,
        );
        let Some(projected_opening_values) =
            symbt3_folded_ajtai_projection_values(relation, &witness.folded_ajtai_opening_values)
        else {
            return Vec::new();
        };
        let Some(projection_residual_values) = symbt3_projection_residual_values(
            relation,
            &witness.folded_ajtai_opening_values,
            &projected_opening_values,
        ) else {
            return Vec::new();
        };
        let Some(range_residual_values) =
            symbt3_range_residual_values(relation, &projected_opening_values)
        else {
            return Vec::new();
        };
        let Some(monomial_residual_values) =
            symbt3_monomial_embedding_residual_values(relation, &projected_opening_values)
        else {
            return Vec::new();
        };
        if range_residual_values
            .iter()
            .chain(projection_residual_values.iter())
            .chain(monomial_residual_values.iter())
            .any(|&value| value != BabyBear::ZERO)
        {
            return Vec::new();
        }
        let acted_openings = source_openings
            .iter()
            .zip(beta_rings.iter())
            .map(|(value, beta)| value.ring_scalar_mul(beta, relation.ring_module_layout.modulus))
            .collect::<Vec<_>>();
        let acted_opening_sum = symbt3_sum_ring_vectors_flat(&acted_openings);
        let ajtai_actual = symbt3_ajtai_mul(
            &relation.ajtai_matrix,
            &folded_opening,
            relation.ring_module_layout.modulus,
        );
        let source_r1cs_residuals =
            symbt3_source_r1cs_residual_values(relation, &witness.source_r1cs_assignment_values);
        let folded_gr1cs_residuals = symbt3_folded_gr1cs_residual_values(relation, statement);
        let mut table = vec![BabyBear::ZERO; row_count * padded_column_count];
        symbt3_write_flat_column(&mut table, row_count, 0, &statement.folded_ajtai_commitment);
        symbt3_write_flat_column(
            &mut table,
            row_count,
            acted_commitment_sum_col,
            &acted_commitment_sum,
        );
        symbt3_write_flat_column(&mut table, row_count, commitment_wrap_col, &commitment_wrap);
        symbt3_write_flat_column(
            &mut table,
            row_count,
            folded_opening_col,
            &witness.folded_ajtai_opening_values,
        );
        symbt3_write_flat_column(
            &mut table,
            row_count,
            acted_opening_sum_col,
            &acted_opening_sum,
        );
        symbt3_write_flat_column(&mut table, row_count, opening_wrap_col, &opening_wrap);
        symbt3_write_flat_column(
            &mut table,
            row_count,
            ajtai_actual_col,
            &symbt3_ring_vector_to_flat(&ajtai_actual),
        );
        symbt3_write_bb_column(
            &mut table,
            row_count,
            source_r1cs_residual_col,
            &source_r1cs_residuals,
        );
        symbt3_write_bb_column(
            &mut table,
            row_count,
            folded_gr1cs_residual_col,
            &folded_gr1cs_residuals,
        );
        symbt3_write_bb_column(
            &mut table,
            row_count,
            product_residual_col,
            &product_residual_values,
        );
        symbt3_write_flat_column(
            &mut table,
            row_count,
            projected_opening_col,
            &projected_opening_values,
        );
        symbt3_write_bb_column(
            &mut table,
            row_count,
            projection_residual_col,
            &projection_residual_values,
        );
        symbt3_write_bb_column(
            &mut table,
            row_count,
            range_residual_col,
            &range_residual_values,
        );
        symbt3_write_bb_column(
            &mut table,
            row_count,
            monomial_residual_col,
            &monomial_residual_values,
        );
        table
    });
    if table.as_ref().is_some_and(Vec::is_empty) {
        return None;
    }

    let public_digest =
        crate::batched_cp::derive_symbt3_public_statement_digest(relation, statement);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"symphony-symbt3-c-coordinate-zeta-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(&relation.relation_id());
    transcript.extend_from_slice(&public_digest);
    let row_point = (0..row_vars)
        .map(|idx| derive_challenge(&transcript, idx, b"symbt3-c-row-point"))
        .collect::<Vec<_>>();
    let source_r1cs_residual_row_point =
        symbt3_source_r1cs_residual_batching_point(seed, relation, statement, row_vars);

    let product_sumcheck_start = std::time::Instant::now();
    let (product_sumcheck_rounds, product_challenges, product_final_claim) = if let Some(rounds) =
        product_sumcheck_rounds_override
    {
        let mut transcript = product_transcript.clone();
        let (final_claim, challenges) =
            verify_sumcheck_r1cs(rounds, BabyBear::ZERO, row_vars, &mut transcript)?;
        (rounds.to_vec(), challenges, final_claim)
    } else {
        let mut transcript = product_transcript.clone();
        let product_one_values = vec![BabyBear::ONE; row_count];
        let product_zero_values = vec![BabyBear::ZERO; row_count];
        let (rounds, challenges, final_l, final_r, final_o, final_eq) = prove_sumcheck_r1cs(
            &product_eq_table,
            &product_residual_values,
            &product_one_values,
            &product_zero_values,
            row_vars,
            &mut transcript,
        );
        if !rounds.is_empty() && rounds[0][0] + rounds[0][1] != BabyBear::ZERO {
            return None;
        }
        if rounds.is_empty() && product_eq_table[0] * product_residual_values[0] != BabyBear::ZERO {
            return None;
        }
        let final_claim = final_eq * (final_l * final_r - final_o);
        (rounds, challenges, final_claim)
    };
    eval_profile.verify_sumcheck_rounds_ms += elapsed_ms(product_sumcheck_start);
    let product_row_point = sumcheck_point_to_mle_point(&product_challenges, row_vars);

    let mut points = Vec::with_capacity(column_count + 1);
    for column in 0..column_count {
        let mut point = if column == source_r1cs_residual_col {
            source_r1cs_residual_row_point.clone()
        } else {
            row_point.clone()
        };
        for bit in 0..col_vars {
            point.push(BabyBear::from_u32(((column >> bit) & 1) as u32));
        }
        points.push(point);
    }
    for column in [product_residual_col] {
        let mut point = product_row_point.clone();
        for bit in 0..col_vars {
            point.push(BabyBear::from_u32(((column >> bit) & 1) as u32));
        }
        points.push(point);
    }
    let claimed = if let Some(claimed) = claimed_override {
        if claimed.len() != column_count + 1 {
            return None;
        }
        claimed.to_vec()
    } else {
        let table_ref = table.as_ref()?;
        points
            .iter()
            .map(|point| mle_eval_bb_fast(table_ref, point))
            .collect::<Vec<_>>()
    };

    let mut public_table = vec![BabyBear::ZERO; row_count * padded_column_count];
    symbt3_write_flat_column(
        &mut public_table,
        row_count,
        0,
        &statement.folded_ajtai_commitment,
    );
    symbt3_write_flat_column(
        &mut public_table,
        row_count,
        acted_commitment_sum_col,
        &acted_commitment_sum,
    );
    symbt3_write_flat_column(
        &mut public_table,
        row_count,
        commitment_wrap_col,
        &commitment_wrap,
    );
    symbt3_write_bb_column(
        &mut public_table,
        row_count,
        folded_gr1cs_residual_col,
        &symbt3_folded_gr1cs_residual_values(relation, statement),
    );
    symbt3_write_bb_column(
        &mut public_table,
        row_count,
        product_residual_col,
        &product_residual_values,
    );
    let public_expected = points
        .iter()
        .map(|point| mle_eval_bb_fast(&public_table, point))
        .collect::<Vec<_>>();
    for idx in 0..=commitment_wrap_col {
        if claimed[idx] != public_expected[idx] {
            return None;
        }
    }
    if claimed[folded_gr1cs_residual_col] != public_expected[folded_gr1cs_residual_col] {
        return None;
    }
    for idx in column_count..column_count + 1 {
        if claimed[idx] != public_expected[idx] {
            return None;
        }
    }
    let folded_boundary_start = std::time::Instant::now();
    let folded_commitment_eval = claimed[0];
    let folded_opening_eval = claimed[folded_opening_col];
    let weighted_commitment_eval = claimed[acted_commitment_sum_col];
    let weighted_opening_eval = claimed[acted_opening_sum_col];
    let ajtai_actual_eval = claimed[ajtai_actual_col];
    eval_profile.verify_final_eval_folded_boundary_ms += elapsed_ms(folded_boundary_start);
    let source_r1cs_start = std::time::Instant::now();
    let source_r1cs_residual_eval = claimed[source_r1cs_residual_col];
    eval_profile.verify_final_eval_source_r1cs_ms += elapsed_ms(source_r1cs_start);
    let folded_gr1cs_start = std::time::Instant::now();
    let folded_gr1cs_residual_eval = claimed[folded_gr1cs_residual_col];
    eval_profile.verify_final_eval_folded_boundary_ms += elapsed_ms(folded_gr1cs_start);
    let product_eval_start = std::time::Instant::now();
    let product_residual_final = claimed[column_count];
    let product_eq_final = mle_eval_bb_fast(&product_eq_table, &product_row_point);
    let product_final_residual = product_final_claim - product_eq_final * product_residual_final;
    eval_profile.verify_final_eval_product_residual_ms += elapsed_ms(product_eval_start);
    let manifest_eval_start = std::time::Instant::now();
    let manifest_residual = public_source_view_eval - public_manifest_view_eval;
    eval_profile.verify_manifest_membership_eval_ms += elapsed_ms(manifest_eval_start);
    eval_profile.verify_final_eval_manifest_ms += elapsed_ms(manifest_eval_start);
    let range_eval_start = std::time::Instant::now();
    let projection_residual_eval = claimed[projection_residual_col];
    let range_residual_eval = claimed[range_residual_col];
    let monomial_residual_eval = claimed[monomial_residual_col];
    eval_profile.verify_projection_eval_ms += elapsed_ms(range_eval_start);
    eval_profile.verify_monomial_embedding_eval_ms += elapsed_ms(range_eval_start);
    eval_profile.verify_representative_eval_ms += elapsed_ms(range_eval_start);
    eval_profile.verify_final_eval_range_ms += elapsed_ms(range_eval_start);
    let q_eval = BabyBear::from_u32(
        (relation.ring_module_layout.modulus % BabyBear::ORDER_U32 as u64) as u32,
    );
    let commitment_residual =
        folded_commitment_eval - weighted_commitment_eval + claimed[commitment_wrap_col] * q_eval;
    let opening_residual =
        folded_opening_eval - weighted_opening_eval + claimed[opening_wrap_col] * q_eval;
    let ajtai_eval_start = std::time::Instant::now();
    let ajtai_residual = ajtai_actual_eval - folded_commitment_eval
        + source_r1cs_residual_eval
        + folded_gr1cs_residual_eval
        + product_final_residual
        + manifest_residual
        + projection_residual_eval
        + range_residual_eval
        + monomial_residual_eval;
    eval_profile.verify_ajtai_eval_ms += elapsed_ms(ajtai_eval_start);
    eval_profile.verify_final_eval_ajtai_ms += elapsed_ms(ajtai_eval_start);
    Some(Symbt3CClaims {
        table,
        points,
        claimed,
        evaluations: [commitment_residual, opening_residual, ajtai_residual],
        z_eval: folded_commitment_eval,
        num_vars,
        product_sumcheck_rounds,
        eval_profile,
    })
}

fn symbt3_write_flat_column(
    table: &mut [BabyBear],
    row_count: usize,
    column: usize,
    values: &[i64],
) {
    let offset = column * row_count;
    for (row, &value) in values.iter().take(row_count).enumerate() {
        table[offset + row] = BabyBear::from_i64(value);
    }
}

fn symbt3_write_bb_column(
    table: &mut [BabyBear],
    row_count: usize,
    column: usize,
    values: &[BabyBear],
) {
    let offset = column * row_count;
    for (row, &value) in values.iter().take(row_count).enumerate() {
        table[offset + row] = value;
    }
}

fn symbt3_source_assignment_root_for_whir(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    values: &[i64],
) -> [u8; 32] {
    let scheme = relation.shape.accumulator_shape.digest_scheme;
    let mut body = Vec::new();
    body.extend_from_slice(&relation.r1cs_evaluator_layout.digest(scheme));
    body.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for &value in values {
        body.extend_from_slice(&value.to_le_bytes());
    }
    crate::digest_core::digest_domain_with_scheme(
        scheme,
        b"batched-cp-symbt3-source-assignment-root",
        &body,
    )
}

fn symbt3_source_r1cs_residual_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    assignments: &[Vec<i64>],
) -> Vec<BabyBear> {
    let q = BabyBear::ORDER_U32 as u64;
    let mut out =
        Vec::with_capacity(assignments.len() * relation.r1cs_evaluator_layout.num_constraints * D);
    for assignment in assignments {
        for row in 0..relation.r1cs_evaluator_layout.num_constraints {
            let a = symbt3_r1cs_linear_ring(&relation.r1cs_matrices.a, row, assignment, q);
            let b = symbt3_r1cs_linear_ring(&relation.r1cs_matrices.b, row, assignment, q);
            let c = symbt3_r1cs_linear_ring(&relation.r1cs_matrices.c, row, assignment, q);
            let residual = a.mul(&b, q).sub(&c, q);
            out.extend(
                residual
                    .coeffs
                    .iter()
                    .map(|&coeff| BabyBear::from_i64(coeff)),
            );
        }
    }
    out
}

fn symbt3_source_r1cs_residual_batching_point(
    seed: &[u8; 32],
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    row_vars: usize,
) -> Vec<BabyBear> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"SYMBT3_SOURCE_R1CS_RESIDUAL_BATCH");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(&relation.relation_id());
    transcript.extend_from_slice(&statement.shape_id);
    transcript.extend_from_slice(&statement.source_assignment_boundary_digest);
    transcript.extend_from_slice(&statement.source_column_layout_digest);
    transcript.extend_from_slice(&statement.r1cs_evaluator_layout_digest);
    transcript.extend_from_slice(&statement.folded_gr1cs_boundary_digest);
    transcript.extend_from_slice(&statement.whir_parameter_digest);
    transcript.extend_from_slice(&crate::batched_cp::derive_symbt3_public_statement_digest(
        relation, statement,
    ));
    (0..row_vars)
        .map(|idx| derive_challenge(&transcript, idx, b"symbt3-source-r1cs-residual-row"))
        .collect()
}

fn symbt3_r1cs_linear_ring(
    matrix: &SparseMatrix,
    row: usize,
    assignment: &[i64],
    q: u64,
) -> RingElement {
    let mut acc = RingElement::zero();
    for &(_, col, coeff) in matrix.entries.iter().filter(|&&(r, _, _)| r == row) {
        let start = col * D;
        let end = start + D;
        if let Some(slice) = assignment.get(start..end) {
            let mut coeffs = [0i64; D];
            coeffs.copy_from_slice(slice);
            let term = RingElement { coeffs }.scalar_mul(coeff, q);
            acc.add_assign(&term, q);
        }
    }
    acc
}

fn symbt3_folded_gr1cs_residual_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
) -> Vec<BabyBear> {
    let expected = relation.derive_folded_evaluation_boundary(statement);
    statement
        .folded_evaluation
        .iter()
        .zip(expected.iter())
        .map(|(&actual, &expected)| BabyBear::from_i64(actual) - BabyBear::from_i64(expected))
        .collect()
}

fn symbt3_folded_gr1cs_product_columns(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
) -> Option<(Vec<BabyBear>, Vec<BabyBear>, Vec<BabyBear>)> {
    let product_len = relation
        .gr1cs_residual_layout
        .folded_evaluation_coordinate_count
        / 3;
    if product_len == 0 || statement.folded_evaluation.len() < product_len * 3 {
        return None;
    }
    let l = statement.folded_evaluation[..product_len]
        .iter()
        .map(|&value| BabyBear::from_i64(value))
        .collect::<Vec<_>>();
    let r = statement.folded_evaluation[product_len..2 * product_len]
        .iter()
        .map(|&value| BabyBear::from_i64(value))
        .collect::<Vec<_>>();
    let o = statement.folded_evaluation[2 * product_len..3 * product_len]
        .iter()
        .map(|&value| BabyBear::from_i64(value))
        .collect::<Vec<_>>();
    Some((l, r, o))
}

fn symbt3_folded_gr1cs_product_residual_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    l_values: &[BabyBear],
    r_values: &[BabyBear],
    o_values: &[BabyBear],
) -> Option<Vec<BabyBear>> {
    match relation.folded_gr1cs_product_residual_layout.product_law {
        crate::batched_cp::Symbt3ProductLawId::FieldCoordinateMulV1 => Some(
            l_values
                .iter()
                .zip(r_values.iter())
                .zip(o_values.iter())
                .map(|((&l, &r), &o)| l * r - o)
                .collect(),
        ),
        crate::batched_cp::Symbt3ProductLawId::RqNegacyclicConvolutionV1 => {
            let product_len = l_values.len();
            if product_len != r_values.len()
                || product_len != o_values.len()
                || product_len % D != 0
            {
                return None;
            }
            let mut out = Vec::with_capacity(product_len);
            for chunk_start in (0..product_len).step_by(D) {
                let product = symbt3_negacyclic_mul_bb(
                    &l_values[chunk_start..chunk_start + D],
                    &r_values[chunk_start..chunk_start + D],
                );
                out.extend(
                    product
                        .iter()
                        .zip(o_values[chunk_start..chunk_start + D].iter())
                        .map(|(&product, &output)| product - output),
                );
            }
            Some(out)
        }
    }
}

fn symbt3_folded_ajtai_projection_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    folded_opening: &[i64],
) -> Option<Vec<i64>> {
    let layout = &relation.ajtai_norm_range_layout.projection_layout;
    if layout.input_len != folded_opening.len() {
        return None;
    }
    match layout.projection_mode {
        crate::batched_cp::Symbt3ProjectionMode::DirectDevDenseProjectionV1 => {
            if layout.output_len != folded_opening.len() {
                return None;
            }
            Some(folded_opening.to_vec())
        }
        crate::batched_cp::Symbt3ProjectionMode::StructuredBlockProjectionV1 => {
            symbt3_structured_projection_values(layout, folded_opening)
        }
    }
}

fn symbt3_projection_residual_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    folded_opening: &[i64],
    projected_opening: &[i64],
) -> Option<Vec<BabyBear>> {
    let expected = symbt3_folded_ajtai_projection_values(relation, folded_opening)?;
    if expected.len() != projected_opening.len() {
        return None;
    }
    Some(
        projected_opening
            .iter()
            .zip(expected.iter())
            .map(|(&projected, &folded)| BabyBear::from_i64(projected) - BabyBear::from_i64(folded))
            .collect(),
    )
}

fn symbt3_structured_projection_values(
    layout: &crate::batched_cp::Symbt3ProjectionLayout,
    folded_opening: &[i64],
) -> Option<Vec<i64>> {
    if layout.block_len == 0
        || layout.rows_per_block == 0
        || layout.entry_distribution
            != crate::batched_cp::Symbt3ProjectionEntryDistribution::ZeroPlusMinusOneV1
    {
        return None;
    }
    let block_count = layout.input_len.div_ceil(layout.block_len);
    if layout.output_len != block_count * layout.rows_per_block {
        return None;
    }
    let mut out = Vec::with_capacity(layout.output_len);
    for block in 0..block_count {
        let block_start = block * layout.block_len;
        for row in 0..layout.rows_per_block {
            let mut acc = 0i64;
            for j in 0..layout.block_len {
                let idx = block_start + j;
                if idx >= folded_opening.len() {
                    break;
                }
                let sign = symbt3_projection_entry_sign(layout, row, j);
                acc = acc.saturating_add(sign.saturating_mul(folded_opening[idx]));
            }
            out.push(acc);
        }
    }
    Some(out)
}

fn symbt3_projection_entry_sign(
    layout: &crate::batched_cp::Symbt3ProjectionLayout,
    row: usize,
    coeff: usize,
) -> i64 {
    let idx = (row.wrapping_mul(layout.block_len).wrapping_add(coeff))
        % layout.projection_matrix_digest.len();
    match layout.projection_matrix_digest[idx] % 3 {
        0 => 0,
        1 => 1,
        _ => -1,
    }
}

fn symbt3_range_residual_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    projected_opening: &[i64],
) -> Option<Vec<BabyBear>> {
    let layout = &relation.ajtai_norm_range_layout;
    if layout.range_layout.bound_b != layout.norm_bound {
        return None;
    }
    let bound = layout.norm_bound;
    Some(
        projected_opening
            .iter()
            .map(|&value| {
                if value.saturating_abs() <= bound {
                    BabyBear::ZERO
                } else {
                    BabyBear::ONE
                }
            })
            .collect(),
    )
}

fn symbt3_monomial_embedding_residual_values(
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    projected_opening: &[i64],
) -> Option<Vec<BabyBear>> {
    let layout = &relation.ajtai_norm_range_layout;
    if layout.range_mode == crate::batched_cp::Symbt3RangeMode::DirectSignedRangeDevV1
        && layout.range_layout.range_mode
            == crate::batched_cp::Symbt3RangeMode::DirectSignedRangeDevV1
    {
        return Some(vec![BabyBear::ZERO; projected_opening.len()]);
    }
    if layout.range_mode != crate::batched_cp::Symbt3RangeMode::MonomialEmbeddingRangeV1
        || layout.range_layout.range_mode
            != crate::batched_cp::Symbt3RangeMode::MonomialEmbeddingRangeV1
        || layout.range_layout.table_digest
            != Some(layout.monomial_embedding_layout.table_polynomial_digest)
        || layout.range_layout.monomial_embedding_layout_digest
            != Some(
                layout
                    .monomial_embedding_layout
                    .digest(relation.shape.accumulator_shape.digest_scheme),
            )
        || layout.representative_layout.canonical_rep_policy
            != crate::batched_cp::Symbt3CanonicalRepPolicy::CenteredModQRepresentativeV1
        || layout.representative_layout.signed_range != layout.norm_bound
    {
        return None;
    }
    Some(
        projected_opening
            .iter()
            .map(|&projected| {
                if projected.saturating_abs() <= layout.norm_bound {
                    BabyBear::ZERO
                } else {
                    BabyBear::ONE
                }
            })
            .collect(),
    )
}

fn symbt3_negacyclic_mul_bb(left: &[BabyBear], right: &[BabyBear]) -> [BabyBear; D] {
    let mut out = [BabyBear::ZERO; D];
    for i in 0..D {
        let lhs = left.get(i).copied().unwrap_or(BabyBear::ZERO);
        for j in 0..D {
            let rhs = right.get(j).copied().unwrap_or(BabyBear::ZERO);
            let product = lhs * rhs;
            let idx = i + j;
            if idx < D {
                out[idx] += product;
            } else {
                out[idx - D] -= product;
            }
        }
    }
    out
}

fn symbt3_d2_product_sumcheck_transcript(
    seed: &[u8; 32],
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    row_count: usize,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"symphony-symbt3-d2-product-sumcheck-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(&relation.relation_id());
    transcript.extend_from_slice(&relation.folding_protocol_id());
    transcript.extend_from_slice(&crate::batched_cp::derive_symbt3_public_statement_digest(
        relation, statement,
    ));
    transcript.extend_from_slice(&statement.folded_gr1cs_boundary_digest);
    transcript.extend_from_slice(&statement.folded_gr1cs_product_residual_layout_digest);
    transcript.extend_from_slice(&statement.whir_parameter_digest);
    transcript.extend_from_slice(&(row_count as u64).to_le_bytes());
    transcript
}

fn symbt3_flat_to_ring_vector(values: &[i64], module_dimension: usize) -> crate::ring::RingVector {
    let mut elements = Vec::with_capacity(module_dimension);
    for idx in 0..module_dimension {
        let mut coeffs = [0i64; D];
        let start = idx * D;
        let end = start + D;
        if let Some(slice) = values.get(start..end) {
            coeffs.copy_from_slice(slice);
        }
        elements.push(RingElement { coeffs });
    }
    crate::ring::RingVector { elements }
}

fn symbt3_ring_vector_to_flat(value: &crate::ring::RingVector) -> Vec<i64> {
    value
        .elements
        .iter()
        .flat_map(|elem| elem.coeffs.iter().copied())
        .collect()
}

fn symbt3_sum_ring_vectors_flat(values: &[crate::ring::RingVector]) -> Vec<i64> {
    let Some(first) = values.first() else {
        return Vec::new();
    };
    let mut out = vec![0i64; first.elements.len() * D];
    for value in values {
        for (elem_idx, elem) in value.elements.iter().enumerate() {
            for coeff_idx in 0..D {
                out[elem_idx * D + coeff_idx] += elem.coeffs[coeff_idx];
            }
        }
    }
    out
}

fn symbt3_ring_fold_with_wrap(
    rows: &[Vec<i64>],
    betas: &[RingElement],
    module_dimension: usize,
    q: u64,
) -> (Vec<i64>, Vec<i64>) {
    let mut raw = vec![0i128; module_dimension * D];
    for (row, beta) in rows.iter().zip(betas.iter()) {
        let value = symbt3_flat_to_ring_vector(row, module_dimension);
        for (elem_idx, elem) in value.elements.iter().enumerate() {
            let product = symbt3_ring_mul_raw(beta, elem);
            for coeff in 0..D {
                raw[elem_idx * D + coeff] +=
                    crate::ring::arith::centered_mod(product[coeff], q) as i128;
            }
        }
    }
    let mut folded = Vec::with_capacity(raw.len());
    let mut wraps = Vec::with_capacity(raw.len());
    for value in raw {
        let reduced = crate::ring::arith::centered_mod(value, q);
        folded.push(reduced);
        wraps.push(((value - reduced as i128) / q as i128) as i64);
    }
    (folded, wraps)
}

fn symbt3_ring_mul_raw(left: &RingElement, right: &RingElement) -> [i128; D] {
    let mut acc = [0i128; D];
    for i in 0..D {
        for j in 0..D {
            let prod = left.coeffs[i] as i128 * right.coeffs[j] as i128;
            let idx = i + j;
            if idx < D {
                acc[idx] += prod;
            } else {
                acc[idx - D] -= prod;
            }
        }
    }
    acc
}

fn symbt3_ajtai_mul(
    matrix: &[Vec<RingElement>],
    opening: &crate::ring::RingVector,
    q: u64,
) -> crate::ring::RingVector {
    let mut out = Vec::with_capacity(matrix.len());
    for row in matrix {
        let mut acc = RingElement::zero();
        for (a, value) in row.iter().zip(opening.elements.iter()) {
            acc.add_assign(&a.mul(value, q), q);
        }
        out.push(acc);
    }
    crate::ring::RingVector { elements: out }
}
