fn typed_batched_cp_opening_point(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    num_vars: usize,
) -> Vec<BabyBear> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-product-domain-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(&relation.relation_id());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(num_vars as u64).to_le_bytes());
    (0..num_vars)
        .map(|idx| derive_challenge(&transcript, idx, b"oracle-point"))
        .collect()
}

fn verify_output_with_transcript_instance(
    vk: &WhirVerifyingKey,
    r1cs_instance: &[u8],
    transcript_instance: &[u8],
    proof: &WhirProof,
    ctx: &WhirContext,
) -> bool {
    if !proof.is_output {
        return false;
    }
    if !proof.private_opening_evals.is_empty() {
        return false;
    }
    if !proof.family_columnar_subproofs.is_empty() {
        return false;
    }

    let d = ctx.d;
    let mut instance_bb = bytes_to_babybear_direct(r1cs_instance);
    let expected_instance_len = ctx.r1cs.num_public * d;
    instance_bb.resize(expected_instance_len, BabyBear::ZERO);

    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    if proof.num_vars != num_vars {
        return false;
    }

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v2");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(transcript_instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(transcript_instance);

    // Derive tau
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    // Verify sumcheck
    let (final_eval, challenges) = match verify_sumcheck_r1cs(
        &proof.sumcheck_rounds_4,
        BabyBear::ZERO,
        num_vars,
        &mut transcript,
    ) {
        Some(v) => v,
        None => return false,
    };

    // Check final evaluation: eq(tau, r*) * (Az_eval * Bz_eval - Cz_eval)
    // Recompute eq(tau, r*) by folding the same eq table convention used by prover.
    let mut eq_fold = build_eq_table_bb(&tau, num_vars);
    for &r in &challenges {
        let half = eq_fold.len() / 2;
        let one_minus_r = BabyBear::ONE - r;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(eq_fold[j] * one_minus_r + eq_fold[half + j] * r);
        }
        eq_fold = next;
    }
    let eq_at_r = eq_fold[0];
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify WHIR PCS opening for z polynomial
    let total_vars = ctx.r1cs.num_variables * d;
    let z_padded_len = (1usize << ceil_log2(total_vars.max(1))).max(2);
    let z_num_vars = z_padded_len.trailing_zeros() as usize;

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        d,
        ctx.q,
    );

    let mut opening_points = vec![sumcheck_point_to_mle_point(&challenges, z_num_vars)];
    let mut opening_evals = vec![proof.z_eval];
    if !verify_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &proof.evaluations,
        total_vars,
        z_num_vars,
        &proof.linear_checks,
        &mut transcript,
        &mut opening_points,
        &mut opening_evals,
    ) {
        return false;
    }
    for (idx, expected) in instance_bb.iter().copied().enumerate() {
        opening_points.push(boolean_point_for_index(idx, z_num_vars));
        opening_evals.push(expected);
    }

    whir_verify_opening_multi(
        &vk.seed,
        z_num_vars,
        &proof.whir_pcs_proof,
        &opening_points,
        &opening_evals,
    )
}

// ---------------------------------------------------------------------------
// CP-SNARK R1CS path: folding constraints via R1CS sumcheck over BabyBear
// ---------------------------------------------------------------------------
// Reuses the same R1CS-over-BabyBear sumcheck as the output path, but with
// CP-specific R1CS matrices (folding linear combination constraints).

fn parse_i64_chunks_to_babybear(bytes: &[u8]) -> Vec<BabyBear> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(8));
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let v = i64::from_le_bytes(bytes[i..i + 8].try_into().expect("8-byte chunk"));
        out.push(BabyBear::from_i64(v));
        i += 8;
    }
    if i < bytes.len() {
        let mut buf = [0u8; 8];
        buf[..bytes.len() - i].copy_from_slice(&bytes[i..]);
        let v = i64::from_le_bytes(buf);
        out.push(BabyBear::from_i64(v));
    }
    out
}

fn prove_cp_r1cs(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    // Identical to prove_output but with a different transcript domain separator
    // and is_output = false on the proof.
    //
    // IMPORTANT: CP-R1CS context is already scalarized over BabyBear.
    // Do NOT multiply dimensions by ring degree `d` again.
    let q = ctx.q;

    // Parse only CP-R1CS public prefix from `instance`; ignore trailer bytes.
    let mut instance_bb = parse_i64_chunks_to_babybear(instance);
    let expected_instance_len = ctx.r1cs.num_public;
    instance_bb.resize(expected_instance_len, BabyBear::ZERO);
    let witness_bb = parse_i64_chunks_to_babybear(witness);

    let total_vars = ctx.r1cs.num_variables;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_bb);
    z_flat.extend_from_slice(&witness_bb);
    z_flat.resize(total_vars, BabyBear::ZERO);

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        1,
        q,
    );
    let num_constraints = ctx.r1cs.num_constraints;
    let num_vars = ceil_log2(num_constraints.max(1));

    let (az, bz, cz) =
        compute_matrix_vector_products_bb(&flat_a, &flat_b, &flat_c, &z_flat, num_vars);
    let z_padded_len = (1 << ceil_log2(z_flat.len().max(1))).max(2);
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);
    let z_num_vars = z_padded.len().trailing_zeros() as usize;

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-r1cs-v1");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges, az_eval, bz_eval, cz_eval, _eq_final) =
        prove_sumcheck_r1cs(&eq_table, &az, &bz, &cz, num_vars, &mut transcript);

    let mut opening_points = Vec::new();
    let main_point = sumcheck_point_to_mle_point(&challenges, z_num_vars);
    let z_eval = mle_eval_bb(&z_padded, &main_point);
    opening_points.push(main_point);

    let (linear_checks, linear_points) = prove_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &z_padded,
        z_num_vars,
        &mut transcript,
    );
    opening_points.extend(linear_points);

    let (whir_pcs_proof, opening_evals) =
        whir_commit_and_prove_multi(&pk.seed, z_num_vars, &z_padded, &opening_points);
    assert_eq!(opening_evals.first().copied(), Some(z_eval));

    WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: rounds,
        evaluations: [az_eval, bz_eval, cz_eval],
        whir_pcs_proof,
        z_eval,
        linear_checks,
        private_opening_evals: Vec::new(),
        family_columnar_subproofs: Vec::new(),
        num_vars,
        is_output: false,
    }
}

fn verify_cp_r1cs(
    vk: &WhirVerifyingKey,
    instance: &[u8],
    proof: &WhirProof,
    ctx: &WhirContext,
) -> bool {
    // Must not be marked as output
    if proof.is_output {
        return false;
    }
    if !proof.private_opening_evals.is_empty() {
        return false;
    }
    if !proof.family_columnar_subproofs.is_empty() {
        return false;
    }
    if instance.is_empty() {
        return false;
    }

    // CP-R1CS is already scalarized over BabyBear.
    let expected_num_vars = ceil_log2(ctx.r1cs.num_constraints.max(1));
    if proof.num_vars != expected_num_vars {
        return false;
    }

    let num_vars = proof.num_vars;
    if num_vars > 0 && proof.sumcheck_rounds_4.len() != num_vars {
        return false;
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-r1cs-v1");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let (final_eval, challenges) = match verify_sumcheck_r1cs(
        &proof.sumcheck_rounds_4,
        BabyBear::ZERO,
        num_vars,
        &mut transcript,
    ) {
        Some(v) => v,
        None => return false,
    };

    // Check final evaluation: eq(tau, r*) * (Az * Bz - Cz)
    // Recompute eq(tau, r*) by folding the same eq table convention used by prover.
    let mut eq_fold = build_eq_table_bb(&tau, num_vars);
    for &r in &challenges {
        let half = eq_fold.len() / 2;
        let one_minus_r = BabyBear::ONE - r;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(eq_fold[j] * one_minus_r + eq_fold[half + j] * r);
        }
        eq_fold = next;
    }
    let eq_at_r = eq_fold[0];
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify WHIR PCS opening.
    // CP witness polynomial length is based on scalar CP-R1CS variable count.
    let total_vars = ctx.r1cs.num_variables;
    let z_padded_len = (1usize << ceil_log2(total_vars.max(1))).max(2);
    let z_num_vars = z_padded_len.trailing_zeros() as usize;

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        1,
        ctx.q,
    );

    let mut opening_points = vec![sumcheck_point_to_mle_point(&challenges, z_num_vars)];
    let mut opening_evals = vec![proof.z_eval];
    if !verify_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &proof.evaluations,
        total_vars,
        z_num_vars,
        &proof.linear_checks,
        &mut transcript,
        &mut opening_points,
        &mut opening_evals,
    ) {
        return false;
    }
    whir_verify_opening_multi(
        &vk.seed,
        z_num_vars,
        &proof.whir_pcs_proof,
        &opening_points,
        &opening_evals,
    )
}

// ---------------------------------------------------------------------------
// CP-SNARK path (trivial): witness commitment + sumcheck over BabyBear
// ---------------------------------------------------------------------------

fn prove_cp(pk: &WhirProvingKey, instance: &[u8], witness: &[u8]) -> WhirProof {
    let q = SymphonyParams::default_from_paper().q;

    let mut table = bytes_to_babybear(witness, q);
    pad_to_power_of_two(&mut table);
    // WHIR requires at least 2 evaluations (1 variable)
    if table.len() < 2 {
        table.resize(2, BabyBear::ZERO);
    }
    let num_vars = table.len().trailing_zeros() as usize;

    // Build transcript for sumcheck challenge derivation
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v2");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges) = prove_sumcheck_product(&eq_table, &table, num_vars, &mut transcript);

    let w_eval = mle_eval_bb(&table, &challenges);

    // --- WHIR PCS: commit to witness polynomial and prove evaluation ---
    let whir_pcs_proof = whir_commit_and_prove(&pk.seed, num_vars, &table, &challenges, w_eval);

    WhirProof {
        sumcheck_rounds_3: rounds,
        sumcheck_rounds_4: Vec::new(),
        evaluations: [w_eval, BabyBear::ZERO, BabyBear::ZERO],
        whir_pcs_proof,
        z_eval: w_eval,
        linear_checks: Vec::new(),
        private_opening_evals: Vec::new(),
        family_columnar_subproofs: Vec::new(),
        num_vars,
        is_output: false,
    }
}

fn verify_cp(vk: &WhirVerifyingKey, instance: &[u8], proof: &WhirProof) -> bool {
    if proof.is_output {
        return false;
    }
    if !proof.linear_checks.is_empty()
        || !proof.private_opening_evals.is_empty()
        || !proof.family_columnar_subproofs.is_empty()
    {
        return false;
    }

    // Enforce instance is non-empty.
    if instance.is_empty() {
        return false;
    }

    // Validate proof structure: sumcheck rounds must match the claimed
    // number of variables, and the relation's expected sizes.
    let num_vars = proof.num_vars;
    if num_vars == 0 && !proof.sumcheck_rounds_3.is_empty() {
        return false;
    }
    if num_vars > 0 && proof.sumcheck_rounds_3.len() != num_vars {
        return false;
    }

    // When the relation carries sizing metadata, enforce it.
    if vk.relation.num_instance_vars > 0 && instance.len() < vk.relation.num_instance_vars {
        return false;
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v2");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let challenges =
        match verify_sumcheck_product(&proof.sumcheck_rounds_3, num_vars, &mut transcript) {
            Some(c) => c,
            None => return false,
        };

    let [w_eval, _, _] = proof.evaluations;
    let eq_at_r = eval_eq_at_point_bb(&tau, &challenges);
    let expected = eq_at_r * w_eval;

    if num_vars == 0 {
        if expected != w_eval {
            return false;
        }
    } else {
        let last_round = match proof.sumcheck_rounds_3.last() {
            Some(r) => r,
            None => return false,
        };
        let last_challenge = challenges.last().copied().unwrap_or(BabyBear::ZERO);
        let final_eval = eval_univariate_3(last_round, last_challenge);
        if final_eval != expected {
            return false;
        }
    }

    // Critical: sumcheck and WHIR opening must agree on the same evaluation.
    // Without this check, a prover could use different polynomials for the
    // sumcheck and the WHIR opening, decoupling the two proof components.
    if proof.evaluations[0] != proof.z_eval {
        return false;
    }

    // Verify WHIR PCS opening
    if !whir_verify_opening(
        &vk.seed,
        num_vars,
        &proof.whir_pcs_proof,
        &challenges,
        proof.z_eval,
    ) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// WHIR PCS: commit and prove / verify
// ---------------------------------------------------------------------------

fn prove_linear_bindings(
    matrices: [&FlatSparseMatrixBB; 3],
    row_point: &[BabyBear],
    z_table: &[BabyBear],
    z_num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<WhirLinearCheckProof>, Vec<Vec<BabyBear>>) {
    let mut proofs = Vec::with_capacity(3);
    let mut opening_points = Vec::with_capacity(3);
    let num_cols = z_table.len();

    for (i, mat) in matrices.iter().enumerate() {
        transcript.extend_from_slice(b"whir-linear-binding-v1");
        transcript.push(i as u8);
        let row = compute_matrix_mle_row_bb(mat, row_point, num_cols);
        let (rounds, point, z_eval) =
            prove_sumcheck_inner_product(&row, z_table, z_num_vars, transcript);
        proofs.push(WhirLinearCheckProof { rounds, z_eval });
        opening_points.push(sumcheck_point_to_mle_point(&point, z_num_vars));
    }

    (proofs, opening_points)
}

#[allow(clippy::too_many_arguments)]
fn verify_linear_bindings(
    matrices: [&FlatSparseMatrixBB; 3],
    row_point: &[BabyBear],
    claimed_evals: &[BabyBear; 3],
    num_cols: usize,
    z_num_vars: usize,
    proofs: &[WhirLinearCheckProof],
    transcript: &mut Vec<u8>,
    opening_points: &mut Vec<Vec<BabyBear>>,
    opening_evals: &mut Vec<BabyBear>,
) -> bool {
    if proofs.len() != 3 {
        return false;
    }

    for (i, (mat, proof)) in matrices.iter().zip(proofs.iter()).enumerate() {
        transcript.extend_from_slice(b"whir-linear-binding-v1");
        transcript.push(i as u8);
        let (final_eval, point) = match verify_sumcheck_inner_product(
            &proof.rounds,
            claimed_evals[i],
            z_num_vars,
            transcript,
        ) {
            Some(v) => v,
            None => return false,
        };
        let row_eval = eval_matrix_mle_at_points_bb(mat, row_point, &point, num_cols);
        if final_eval != row_eval * proof.z_eval {
            return false;
        }
        opening_points.push(sumcheck_point_to_mle_point(&point, z_num_vars));
        opening_evals.push(proof.z_eval);
    }

    true
}

/// Commit to a multilinear polynomial and prove evaluation claims using WHIR.
fn whir_commit_and_prove_multi(
    seed: &[u8; 32],
    num_variables: usize,
    evaluations: &[BabyBear],
    points: &[Vec<BabyBear>],
) -> (WhirPcsProof<F, EF, WhirMmcs>, Vec<BabyBear>) {
    whir_commit_and_prove_multi_with_profile(seed, num_variables, evaluations, points, None)
}

fn whir_commit_initial_root_only(
    seed: &[u8; 32],
    num_variables: usize,
    evaluations: &[BabyBear],
) -> Option<WhirPcsProof<F, EF, WhirMmcs>> {
    if evaluations.len() != 1usize.checked_shl(num_variables as u32)? {
        return None;
    }

    let infra = build_whir_infra(seed, num_variables);
    let dft = Radix2DFTSmallBatch::<F>::default();
    let poly = EvaluationsList::new(evaluations.to_vec());
    let mut statement = infra
        .params
        .initial_statement(poly, SumcheckStrategy::Classic);
    let mut challenger = make_challenger(&infra.perm);
    infra.domainsep.observe_domain_separator(&mut challenger);
    let mut proof = WhirPcsProof::<F, EF, WhirMmcs>::from_protocol_parameters(
        &infra.protocol_params,
        num_variables,
    );
    CommitmentWriter::new(&infra.params)
        .commit(&dft, &mut proof, &mut challenger, &mut statement)
        .ok()?;
    Some(proof)
}

fn whir_commit_and_prove_multi_with_profile(
    seed: &[u8; 32],
    num_variables: usize,
    evaluations: &[BabyBear],
    points: &[Vec<BabyBear>],
    mut profile: Option<&mut Symbt3ProverCostProfile>,
) -> (WhirPcsProof<F, EF, WhirMmcs>, Vec<BabyBear>) {
    let total_start = std::time::Instant::now();
    assert_eq!(evaluations.len(), 1 << num_variables);
    for point in points {
        assert_eq!(point.len(), num_variables);
    }

    let transcript_start = std::time::Instant::now();
    let infra = build_whir_infra(seed, num_variables);
    if let Some(profile) = profile.as_deref_mut() {
        profile.prove_transcript_ms += elapsed_ms(transcript_start);
    }

    let oracle_start = std::time::Instant::now();
    let dft = Radix2DFTSmallBatch::<F>::default();

    // Build the polynomial in evaluation form
    let poly = EvaluationsList::new(evaluations.to_vec());

    // Create the initial statement
    let mut statement = infra
        .params
        .initial_statement(poly, SumcheckStrategy::Classic);
    if let Some(profile) = profile.as_deref_mut() {
        let elapsed = elapsed_ms(oracle_start);
        profile.prove_oracle_construction_ms += elapsed;
        profile.prove_allocations_copies_ms += elapsed;
    }

    // Add evaluation constraints. WHIR computes the evaluations internally for
    // the prover; verification receives the returned claimed values explicitly.
    // NOTE: Plonky3 multilinear convention has point[0] as the *slowest* variable
    // (controls the top-half split), while our mle_eval_bb has point[0] as the
    // *fastest* variable. Reverse the point to match conventions.
    let constraint_start = std::time::Instant::now();
    let mut claimed_evals = Vec::with_capacity(points.len());
    for point in points {
        let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
        let ml_point = MultilinearPoint::new(ef_point);
        let _whir_eval = statement.evaluate(&ml_point);
        claimed_evals.push(mle_eval_bb_fast(evaluations, point));
    }

    // Normalize for verifier
    let _verifier_statement = statement.normalize();
    if let Some(profile) = profile.as_deref_mut() {
        let elapsed = elapsed_ms(constraint_start);
        profile.prove_constraint_construction_ms += elapsed;
        profile.prove_constraint_batching_ms += elapsed;
        profile.prove_field_ops_ms += elapsed;
        profile.prove_field_extension_ops_ms += elapsed;
    }

    // Create prover challenger
    let transcript_start = std::time::Instant::now();
    let mut prover_challenger = make_challenger(&infra.perm);
    infra
        .domainsep
        .observe_domain_separator(&mut prover_challenger);

    // Create proof struct
    let mut proof = WhirPcsProof::<F, EF, WhirMmcs>::from_protocol_parameters(
        &infra.protocol_params,
        num_variables,
    );
    if let Some(profile) = profile.as_deref_mut() {
        profile.prove_transcript_ms += elapsed_ms(transcript_start);
    }

    // Commit
    let merkle_start = std::time::Instant::now();
    let committer = CommitmentWriter::new(&infra.params);
    let prover_data = committer
        .commit(&dft, &mut proof, &mut prover_challenger, &mut statement)
        .expect("WHIR commit failed");
    if let Some(profile) = profile.as_deref_mut() {
        profile.prove_merkle_tree_build_ms += elapsed_ms(merkle_start);
    }

    // Prove
    let folding_start = std::time::Instant::now();
    let prover = WhirProver(&infra.params);
    prover
        .prove(
            &dft,
            &mut proof,
            &mut prover_challenger,
            &statement,
            prover_data,
        )
        .expect("WHIR prove failed");
    if let Some(profile) = profile.as_deref_mut() {
        let elapsed = elapsed_ms(folding_start);
        profile.prove_whir_folding_layers_ms += elapsed;
        profile.prove_merkle_path_materialization_ms += elapsed;
        profile.prove_field_extension_ops_ms += elapsed;
        profile.prove_total_ms += elapsed_ms(total_start);
    }

    (proof, claimed_evals)
}

/// Verify a WHIR PCS opening proof with one or more evaluation constraints.
fn whir_verify_opening_multi(
    seed: &[u8; 32],
    num_variables: usize,
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    points: &[Vec<BabyBear>],
    claimed_evals: &[BabyBear],
) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        whir_verify_opening_multi_inner(seed, num_variables, proof, points, claimed_evals)
    }))
    .unwrap_or(false)
}

fn whir_verify_opening_multi_inner(
    seed: &[u8; 32],
    num_variables: usize,
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    points: &[Vec<BabyBear>],
    claimed_evals: &[BabyBear],
) -> bool {
    if points.len() != claimed_evals.len() {
        return false;
    }
    if points.iter().any(|point| point.len() != num_variables) {
        return false;
    }

    let infra = build_whir_infra(seed, num_variables);
    let entry = WhirVerifierInfraEntry {
        num_variables,
        infra,
    };
    whir_verify_opening_multi_with_entry(&entry, proof, points, claimed_evals)
}

fn whir_verify_opening_multi_with_entry(
    entry: &WhirVerifierInfraEntry,
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    points: &[Vec<BabyBear>],
    claimed_evals: &[BabyBear],
) -> bool {
    let num_variables = entry.num_variables;
    // Create verifier challenger (must match prover's)
    let mut verifier_challenger = make_challenger(&entry.infra.perm);
    entry
        .infra
        .domainsep
        .observe_domain_separator(&mut verifier_challenger);

    // Parse commitment
    let commitment_reader = CommitmentReader::new(&entry.infra.params);
    let parsed_commitment =
        commitment_reader.parse_commitment::<F, DIGEST_ELEMS>(proof, &mut verifier_challenger);

    // Build verifier statement: the verifier must know each claimed (point,
    // evaluation) pair.
    // Reverse point to match Plonky3 convention (point[0] = slowest variable).
    use whir_p3::constraints::statement::EqStatement;
    let mut verifier_statement = EqStatement::initialize(num_variables);
    for (point, &claimed_eval) in points.iter().zip(claimed_evals.iter()) {
        let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
        let ml_point = MultilinearPoint::new(ef_point);
        verifier_statement.add_evaluated_constraint(ml_point, EF::from(claimed_eval));
    }

    let verifier = WhirVerifier::new(&entry.infra.params);
    verifier
        .verify(
            proof,
            &mut verifier_challenger,
            &parsed_commitment,
            verifier_statement,
        )
        .is_ok()
}

fn whir_commit_and_prove(
    seed: &[u8; 32],
    num_variables: usize,
    evaluations: &[BabyBear],
    point: &[BabyBear],
    claimed_eval: BabyBear,
) -> WhirPcsProof<F, EF, WhirMmcs> {
    let points = vec![point.to_vec()];
    let (proof, evals) = whir_commit_and_prove_multi(seed, num_variables, evaluations, &points);
    assert_eq!(evals, vec![claimed_eval]);
    proof
}

fn whir_verify_opening(
    seed: &[u8; 32],
    num_variables: usize,
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    point: &[BabyBear],
    claimed_eval: BabyBear,
) -> bool {
    whir_verify_opening_multi(
        seed,
        num_variables,
        proof,
        &[point.to_vec()],
        &[claimed_eval],
    )
}

// ---------------------------------------------------------------------------
// R1CS sumcheck: degree-3, evaluations at {0, 1, 2, 3}
// ---------------------------------------------------------------------------

/// Prove sumcheck for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)].
fn prove_sumcheck_r1cs(
    eq_table: &[BabyBear],
    az_table: &[BabyBear],
    bz_table: &[BabyBear],
    cz_table: &[BabyBear],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (
    Vec<[BabyBear; 4]>,
    Vec<BabyBear>,
    BabyBear,
    BabyBear,
    BabyBear,
    BabyBear,
) {
    let n = 1 << num_vars;
    assert_eq!(eq_table.len(), n);
    assert_eq!(az_table.len(), n);
    assert_eq!(bz_table.len(), n);
    assert_eq!(cz_table.len(), n);

    let mut eq = eq_table.to_vec();
    let mut az = az_table.to_vec();
    let mut bz = bz_table.to_vec();
    let mut cz = cz_table.to_vec();

    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = eq.len() / 2;

        let mut evals = [BabyBear::ZERO; 4];
        for j in 0..half {
            let eq0 = eq[j];
            let eq1 = eq[half + j];
            let az0 = az[j];
            let az1 = az[half + j];
            let bz0 = bz[j];
            let bz1 = bz[half + j];
            let cz0 = cz[j];
            let cz1 = cz[half + j];

            for t in 0u32..4 {
                let t_bb = BabyBear::from_u32(t);
                let one_minus_t = BabyBear::ONE - t_bb;

                let eq_t = eq0 * one_minus_t + eq1 * t_bb;
                let az_t = az0 * one_minus_t + az1 * t_bb;
                let bz_t = bz0 * one_minus_t + bz1 * t_bb;
                let cz_t = cz0 * one_minus_t + cz1 * t_bb;

                evals[t as usize] += eq_t * (az_t * bz_t - cz_t);
            }
        }

        rounds.push(evals);

        for e in &evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r1cs");
        challenges.push(r);

        let one_minus_r = BabyBear::ONE - r;
        let mut new_eq = Vec::with_capacity(half);
        let mut new_az = Vec::with_capacity(half);
        let mut new_bz = Vec::with_capacity(half);
        let mut new_cz = Vec::with_capacity(half);
        for j in 0..half {
            new_eq.push(eq[j] * one_minus_r + eq[half + j] * r);
            new_az.push(az[j] * one_minus_r + az[half + j] * r);
            new_bz.push(bz[j] * one_minus_r + bz[half + j] * r);
            new_cz.push(cz[j] * one_minus_r + cz[half + j] * r);
        }
        eq = new_eq;
        az = new_az;
        bz = new_bz;
        cz = new_cz;
    }

    let final_az = az[0];
    let final_bz = bz[0];
    let final_cz = cz[0];
    let final_eq = eq[0];

    (rounds, challenges, final_az, final_bz, final_cz, final_eq)
}

/// Verify R1CS sumcheck (degree-3 round polynomials).
fn verify_sumcheck_r1cs(
    rounds: &[[BabyBear; 4]],
    claimed_sum: BabyBear,
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Option<(BabyBear, Vec<BabyBear>)> {
    if rounds.len() != num_vars {
        return None;
    }
    if num_vars == 0 {
        return Some((claimed_sum, Vec::new()));
    }

    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, evals) in rounds.iter().enumerate() {
        if evals[0] + evals[1] != current_claim {
            return None;
        }

        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r1cs");
        challenges.push(r);

        current_claim = lagrange_interpolate_4(evals, r);
    }

    Some((current_claim, challenges))
}

/// Lagrange interpolation at {0, 1, 2, 3} evaluated at t.
fn lagrange_interpolate_4(evals: &[BabyBear; 4], t: BabyBear) -> BabyBear {
    let [e0, e1, e2, e3] = *evals;
    let six_inv = BabyBear::from_u32(6).inverse();
    let two_inv = BabyBear::TWO.inverse();

    let t1 = t - BabyBear::ONE;
    let t2 = t - BabyBear::TWO;
    let t3 = t - BabyBear::from_u32(3);

    let l0 = t1 * t2 * t3 * (-six_inv);
    let l1 = t * t2 * t3 * two_inv;
    let l2 = t * t1 * t3 * (-two_inv);
    let l3 = t * t1 * t2 * six_inv;

    e0 * l0 + e1 * l1 + e2 * l2 + e3 * l3
}

// ---------------------------------------------------------------------------
// CP sumcheck: degree-2, evaluations at {0, 1, 2}
// ---------------------------------------------------------------------------

fn prove_sumcheck_inner_product(
    a_table: &[BabyBear],
    b_table: &[BabyBear],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<[BabyBear; 3]>, Vec<BabyBear>, BabyBear) {
    let n = 1 << num_vars;
    assert_eq!(a_table.len(), n);
    assert_eq!(b_table.len(), n);

    let mut a = a_table.to_vec();
    let mut b = b_table.to_vec();
    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = a.len() / 2;
        let mut evals = [BabyBear::ZERO; 3];

        for j in 0..half {
            let a0 = a[j];
            let a1 = a[half + j];
            let b0 = b[j];
            let b1 = b[half + j];
            for t in 0u32..3 {
                let t_bb = BabyBear::from_u32(t);
                let one_minus_t = BabyBear::ONE - t_bb;
                let a_t = a0 * one_minus_t + a1 * t_bb;
                let b_t = b0 * one_minus_t + b1 * t_bb;
                evals[t as usize] += a_t * b_t;
            }
        }

        rounds.push(evals);
        for e in &evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }
        let r = derive_challenge(transcript, round, b"sc-inner");
        challenges.push(r);

        let one_minus_r = BabyBear::ONE - r;
        let mut new_a = Vec::with_capacity(half);
        let mut new_b = Vec::with_capacity(half);
        for j in 0..half {
            new_a.push(a[j] * one_minus_r + a[half + j] * r);
            new_b.push(b[j] * one_minus_r + b[half + j] * r);
        }
        a = new_a;
        b = new_b;
    }

    (rounds, challenges, b[0])
}

fn verify_sumcheck_inner_product(
    rounds: &[[BabyBear; 3]],
    claimed_sum: BabyBear,
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Option<(BabyBear, Vec<BabyBear>)> {
    if rounds.len() != num_vars {
        return None;
    }
    if num_vars == 0 {
        return Some((claimed_sum, Vec::new()));
    }

    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);
    for (round, evals) in rounds.iter().enumerate() {
        if evals[0] + evals[1] != current_claim {
            return None;
        }
        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }
        let r = derive_challenge(transcript, round, b"sc-inner");
        challenges.push(r);
        current_claim = eval_univariate_3(evals, r);
    }

    Some((current_claim, challenges))
}

/// Prove sumcheck for F(x) = eq(x) * w(x) (degree-2, CP path).
fn prove_sumcheck_product(
    eq_table: &[BabyBear],
    w_table: &[BabyBear],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<[BabyBear; 3]>, Vec<BabyBear>) {
    let n = 1 << num_vars;
    assert_eq!(eq_table.len(), n);
    assert_eq!(w_table.len(), n);

    let mut eq = eq_table.to_vec();
    let mut w = w_table.to_vec();
    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = 1 << (num_vars - 1 - round);

        let mut e0 = BabyBear::ZERO;
        let mut e1 = BabyBear::ZERO;
        let mut e2 = BabyBear::ZERO;

        for j in 0..half {
            let eq_lo = eq[2 * j];
            let eq_hi = eq[2 * j + 1];
            let w_lo = w[2 * j];
            let w_hi = w[2 * j + 1];

            e0 += eq_lo * w_lo;
            e1 += eq_hi * w_hi;
            let eq_at_2 = eq_hi.double() - eq_lo;
            let w_at_2 = w_hi.double() - w_lo;
            e2 += eq_at_2 * w_at_2;
        }

        let round_evals = [e0, e1, e2];
        rounds.push(round_evals);

        for e in &round_evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r");
        challenges.push(r);

        let mut new_eq = Vec::with_capacity(half);
        let mut new_w = Vec::with_capacity(half);
        for j in 0..half {
            new_eq.push(eq[2 * j] * (BabyBear::ONE - r) + eq[2 * j + 1] * r);
            new_w.push(w[2 * j] * (BabyBear::ONE - r) + w[2 * j + 1] * r);
        }
        eq = new_eq;
        w = new_w;
    }

    (rounds, challenges)
}

/// Verify CP sumcheck.
fn verify_sumcheck_product(
    rounds: &[[BabyBear; 3]],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Option<Vec<BabyBear>> {
    if rounds.len() != num_vars {
        return None;
    }
    if num_vars == 0 {
        return Some(Vec::new());
    }

    let claimed_sum = rounds[0][0] + rounds[0][1];
    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, evals) in rounds.iter().enumerate() {
        if evals[0] + evals[1] != current_claim {
            return None;
        }

        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r");
        challenges.push(r);

        current_claim = eval_univariate_3(evals, r);
    }

    Some(challenges)
}

// ---------------------------------------------------------------------------
// BabyBear helpers
// ---------------------------------------------------------------------------

/// Build eq(tau, x) table over {0,1}^n.
fn build_eq_table_bb(tau: &[BabyBear], num_vars: usize) -> Vec<BabyBear> {
    let n = 1 << num_vars;
    let mut table = vec![BabyBear::ONE; n];
    for (i, &ti) in tau.iter().enumerate() {
        let half = 1 << (num_vars - 1 - i);
        for j in (0..n).rev() {
            let bit = (j >> (num_vars - 1 - i)) & 1;
            if bit == 1 {
                table[j] = table[j - half] * ti;
            } else {
                table[j] *= BabyBear::ONE - ti;
            }
        }
    }
    table
}

/// Evaluate multilinear extension at a point.
fn mle_eval_bb(table: &[BabyBear], point: &[BabyBear]) -> BabyBear {
    let mut current = table.to_vec();
    for &r in point.iter() {
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(current[2 * j] * (BabyBear::ONE - r) + current[2 * j + 1] * r);
        }
        current = next;
    }
    current[0]
}

fn mle_eval_bb_fast(table: &[BabyBear], point: &[BabyBear]) -> BabyBear {
    if let Some(index) = boolean_index_from_point(point) {
        return table.get(index).copied().unwrap_or(BabyBear::ZERO);
    }
    mle_eval_bb(table, point)
}

fn boolean_index_from_point(point: &[BabyBear]) -> Option<usize> {
    if point.len() > usize::BITS as usize {
        return None;
    }
    let mut index = 0usize;
    for (bit, &value) in point.iter().enumerate() {
        if value == BabyBear::ONE {
            index |= 1usize << bit;
        } else if value != BabyBear::ZERO {
            return None;
        }
    }
    Some(index)
}

/// Evaluate eq(a, b) = prod_i (a_i * b_i + (1-a_i)*(1-b_i)) in O(n) field ops.
///
/// This avoids building the full 2^n eq table when only a single-point
/// evaluation is needed (e.g., eq(tau, r*) after sumcheck verification).
fn eval_eq_at_point_bb(a: &[BabyBear], b: &[BabyBear]) -> BabyBear {
    assert_eq!(a.len(), b.len());
    // Convention note:
    // - build_eq_table_bb indexes tau[0] as the slowest variable (MSB position)
    // - mle_eval_bb consumes point[0] as the fastest variable (LSB position)
    // Therefore, to match mle_eval_bb(build_eq_table_bb(a), b), we pair a[i]
    // with b[n-1-i].
    a.iter()
        .zip(b.iter().rev())
        .fold(BabyBear::ONE, |acc, (ai, bi)| {
            acc * (*ai * *bi + (BabyBear::ONE - *ai) * (BabyBear::ONE - *bi))
        })
}

/// Evaluate a degree-2 univariate at point t, given evals at {0, 1, 2}.
fn eval_univariate_3(evals: &[BabyBear; 3], t: BabyBear) -> BabyBear {
    let [e0, e1, e2] = *evals;
    let two_inv = BabyBear::TWO.inverse();
    let l0 = (t - BabyBear::ONE) * (t - BabyBear::TWO) * two_inv;
    let l1 = -t * (t - BabyBear::TWO);
    let l2 = t * (t - BabyBear::ONE) * two_inv;
    e0 * l0 + e1 * l1 + e2 * l2
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_typed_output_public_instance(
    instance: &FoldedOutputInstance,
    ctx: &WhirContext,
) -> bool {
    if instance.linear_relation.commitment != instance.folded_instance.commitment {
        return false;
    }
    if instance.linear_relation.evaluation_values.to_vec()
        != instance.folded_instance.evaluation_values
    {
        return false;
    }
    if instance.folded_instance.public_input.len() != ctx.r1cs.num_public {
        return false;
    }
    if instance.batched_relation.commitments.len()
        != instance.batched_relation.evaluation_values.len()
    {
        return false;
    }

    true
}

fn validate_typed_output_relation(
    instance: &FoldedOutputInstance,
    witness: &FoldedOutputWitness,
    ctx: &WhirContext,
) -> bool {
    if !validate_typed_output_public_instance(instance, ctx) {
        return false;
    }
    let expected_witness_len = ctx.r1cs.num_variables.saturating_sub(ctx.r1cs.num_public);
    if witness.folded_witness.witness.len() != expected_witness_len {
        return false;
    }
    if instance.batched_relation.commitments.len() != witness.folded_witness.monomial_vectors.len()
        || instance.batched_relation.evaluation_values.len()
            != witness.folded_witness.monomial_vectors.len()
    {
        return false;
    }

    let ext_ctx = ExtFieldContext::new(ctx.q);
    let expected_linear = compute_hadamard_output_evaluations(
        &instance.folded_instance.public_input,
        &witness.folded_witness.witness.elements,
        &instance.linear_relation.evaluation_point,
        ctx,
        &ext_ctx,
    );
    if expected_linear != instance.linear_relation.evaluation_values {
        return false;
    }

    let expected_batched = compute_monomial_output_evaluations(
        &witness.folded_witness.monomial_vectors,
        &instance.batched_relation.evaluation_point,
        ctx,
        &ext_ctx,
    );
    expected_batched == instance.batched_relation.evaluation_values
}

fn compute_hadamard_output_evaluations(
    public_input: &[RingElement],
    witness: &[RingElement],
    point: &[ExtFieldElement],
    ctx: &WhirContext,
    ext_ctx: &ExtFieldContext,
) -> [TensorElement; 3] {
    let mut assignment = Vec::with_capacity(public_input.len() + witness.len());
    assignment.extend_from_slice(public_input);
    assignment.extend_from_slice(witness);

    let table_size = 1usize << ceil_log2(ctx.r1cs.num_constraints.max(1));
    let mut evaluations = [
        TensorElement::zero(),
        TensorElement::zero(),
        TensorElement::zero(),
    ];

    for j in 0..ctx.d.min(D) {
        let col: Vec<i64> = assignment.iter().map(|elem| elem.coeffs[j]).collect();
        let mut rows = [
            ctx.r1cs.a.mul_vec_mod(&col, ctx.q),
            ctx.r1cs.b.mul_vec_mod(&col, ctx.q),
            ctx.r1cs.c.mul_vec_mod(&col, ctx.q),
        ];
        for row in &mut rows {
            row.resize(table_size, 0);
        }
        for (i, row) in rows.iter().enumerate() {
            let val = mle_eval_ext_i64(row, point, ext_ctx);
            evaluations[i].data[0][j] = val.c0;
            evaluations[i].data[1][j] = val.c1;
        }
    }

    evaluations
}

fn compute_monomial_output_evaluations(
    monomial_vectors: &[crate::ring::RingVector],
    point: &[ExtFieldElement],
    ctx: &WhirContext,
    ext_ctx: &ExtFieldContext,
) -> Vec<TensorElement> {
    monomial_vectors
        .iter()
        .map(|vector| {
            let table_size = 1usize << ceil_log2(vector.len().max(1));
            let mut evaluation = TensorElement::zero();
            for j in 0..ctx.d.min(D) {
                let mut table: Vec<i64> =
                    vector.elements.iter().map(|elem| elem.coeffs[j]).collect();
                table.resize(table_size, 0);
                let val = mle_eval_ext_i64(&table, point, ext_ctx);
                evaluation.data[0][j] = val.c0;
                evaluation.data[1][j] = val.c1;
            }
            evaluation
        })
        .collect()
}

fn mle_eval_ext_i64(
    table: &[i64],
    point: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> ExtFieldElement {
    if table.is_empty() {
        return ctx.zero();
    }

    let mut current: Vec<ExtFieldElement> = table
        .iter()
        .map(|&v| ExtFieldElement { c0: v, c1: 0 })
        .collect();
    for r in point.iter().take(ceil_log2(table.len().max(1))) {
        if current.len() == 1 {
            break;
        }
        let half = current.len() / 2;
        let one_minus_r = ctx.sub(&ctx.one(), r);
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            next.push(ctx.add(
                &ctx.mul(&one_minus_r, &current[i]),
                &ctx.mul(r, &current[half + i]),
            ));
        }
        current = next;
    }
    current.first().copied().unwrap_or_else(|| ctx.zero())
}

fn compute_context_hash(context: &Option<Vec<u8>>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"whir-context-binding");
    if let Some(ref ctx_bytes) = context {
        h.update((ctx_bytes.len() as u64).to_le_bytes());
        h.update(ctx_bytes);
    } else {
        h.update(0u64.to_le_bytes());
    }
    h.finalize().into()
}

fn derive_challenge(transcript: &[u8], index: usize, label: &[u8]) -> BabyBear {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update((index as u64).to_le_bytes());
    hasher.update(transcript);
    let hash: [u8; 32] = hasher.finalize().into();
    let val = u32::from_le_bytes(hash[..4].try_into().unwrap());
    BabyBear::from_u32(val)
}

fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
