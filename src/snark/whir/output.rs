fn prove_output(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    prove_output_with_transcript_instance(pk, instance, instance, witness, ctx)
}

fn prove_output_with_transcript_instance(
    pk: &WhirProvingKey,
    r1cs_instance: &[u8],
    transcript_instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    let d = ctx.d;
    let q = ctx.q;

    // Parse instance and witness bytes into BabyBear elements
    // Parse only the CP-R1CS public prefix from `instance`.
    // Any trailer bytes are transcript-binding metadata and must not shift the
    // R1CS witness layout.
    let mut instance_bb = bytes_to_babybear_direct(r1cs_instance);
    let expected_instance_len = ctx.r1cs.num_public * d;
    instance_bb.resize(expected_instance_len, BabyBear::ZERO);
    let witness_bb = bytes_to_babybear_direct(witness);

    // Build z_flat = (instance, witness), padded to total_vars * d
    let total_vars = ctx.r1cs.num_variables * d;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_bb);
    z_flat.extend_from_slice(&witness_bb);
    z_flat.resize(total_vars, BabyBear::ZERO);

    // Flatten R1CS
    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        d,
        q,
    );
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    // Compute Az, Bz, Cz
    let (az, bz, cz) =
        compute_matrix_vector_products_bb(&flat_a, &flat_b, &flat_c, &z_flat, num_vars);

    // Pad z_flat to power of two for WHIR polynomial (at least 2 elements)
    let z_padded_len = (1 << ceil_log2(z_flat.len().max(1))).max(2);
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);
    let z_num_vars = z_padded.len().trailing_zeros() as usize;

    // Build transcript for Spartan sumcheck challenge derivation
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v2");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(transcript_instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(transcript_instance);

    // Derive tau for the sumcheck
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    // Build eq(tau, x) table
    let eq_table = build_eq_table_bb(&tau, num_vars);

    // Sumcheck for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)]
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
    for idx in 0..expected_instance_len {
        opening_points.push(boolean_point_for_index(idx, z_num_vars));
    }

    let (whir_pcs_proof, opening_evals) =
        whir_commit_and_prove_multi(&pk.seed, z_num_vars, &z_padded, &opening_points);
    assert_eq!(opening_evals.first().copied(), Some(z_eval));
    let public_eval_offset = 1 + linear_checks.len();
    for (idx, expected) in instance_bb.iter().copied().enumerate() {
        assert_eq!(
            opening_evals.get(public_eval_offset + idx).copied(),
            Some(expected)
        );
    }

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
        is_output: true,
    }
}

fn verify_output(
    vk: &WhirVerifyingKey,
    instance: &[u8],
    proof: &WhirProof,
    ctx: &WhirContext,
) -> bool {
    verify_output_with_transcript_instance(vk, instance, instance, proof, ctx)
}

fn typed_output_binding_context(ctx: &WhirContext) -> WhirContext {
    let mut r1cs = R1CSMatrices::new(1, 1, 1);
    r1cs.a.insert(0, 0, 0);
    WhirContext {
        r1cs,
        q: ctx.q,
        d: 1,
        n_pub: 1,
        is_output_snark: true,
        is_cp_snark: false,
        typed_cp: None,
    }
}

fn typed_output_binding_instance() -> [u8; 8] {
    1i64.to_le_bytes()
}
