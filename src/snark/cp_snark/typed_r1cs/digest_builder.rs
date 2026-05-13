fn generate_typed_cp_digest_r1cs_with_audit_mode(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
    lengths: &TypedCpDigestInputLengths,
    fs_commitments_are_public: bool,
) -> (R1CSMatrices, TypedCpDigestR1csLayout, TypedCpAuditReport) {
    let (statement_r1cs, statement_layout) =
        generate_typed_cp_statement_r1cs(cp_r1cs, cp_layout, ajtai, original_r1cs);
    assert_eq!(lengths.fs_commitment_inputs.len(), cp_layout.ell_np);
    assert_eq!(lengths.gr1cs_message_bodies.len(), cp_layout.ell_np);
    assert_eq!(lengths.gr1cs_message_shapes.len(), cp_layout.ell_np);
    assert_eq!(lengths.challenge_inputs.len(), cp_layout.ell_np);
    assert_eq!(lengths.challenge_bodies.len(), cp_layout.ell_np);

    let public_fs_commitments = if fs_commitments_are_public {
        lengths.fs_commitment_inputs.len()
    } else {
        0
    };
    let digest_publics = (public_fs_commitments + 4) * OUT;
    let folded_eval_publics = lengths.folded_evaluation_values * T * D;
    let off_fs_commitments = statement_layout.num_public;
    let off_fs_root = off_fs_commitments + public_fs_commitments * OUT;
    let off_fold_root = off_fs_root + OUT;
    let off_challenge_digest = off_fold_root + OUT;
    let off_transcript_seed_digest = off_challenge_digest + OUT;
    let off_folded_evaluations = off_transcript_seed_digest + OUT;
    let added_digest_public = digest_publics + folded_eval_publics;
    let num_public = statement_layout.num_public + added_digest_public;
    let statement_private_shift = added_digest_public;

    let mut digest_specs = Vec::<(&[u8], usize, usize, usize, bool)>::new();
    for (idx, (&input_len, &body_len)) in lengths
        .fs_commitment_inputs
        .iter()
        .zip(lengths.fs_commitment_bodies.iter())
        .enumerate()
    {
        digest_specs.push((
            b"fs-commit",
            input_len,
            body_len,
            off_fs_commitments + idx * OUT,
            !fs_commitments_are_public,
        ));
    }
    digest_specs.push((
        b"fs-root",
        lengths.fs_root_input,
        lengths.fs_root_body,
        off_fs_root,
        false,
    ));
    digest_specs.push((
        b"fold-root",
        lengths.fold_root_input,
        lengths.fold_root_body,
        off_fold_root,
        false,
    ));
    digest_specs.push((
        b"challenge-digest",
        lengths.challenge_digest_input,
        lengths.challenge_digest_body,
        off_challenge_digest,
        false,
    ));
    digest_specs.push((
        b"transcript-seed",
        lengths.transcript_seed_input,
        lengths.transcript_seed_body,
        off_transcript_seed_digest,
        false,
    ));
    for (&input_len, &body_len) in lengths
        .challenge_inputs
        .iter()
        .zip(lengths.challenge_bodies.iter())
    {
        digest_specs.push((b"challenge", input_len, body_len, 0, true));
    }

    let mut digest_blocks = Vec::new();
    let mut next_private = statement_layout.num_variables + statement_private_shift;
    let mut total_constraints = statement_r1cs.num_constraints;
    for &(_, input_len, body_len, off_public_output, output_is_private) in &digest_specs {
        let digest_witness_len = poseidon2_digest_aux_len(input_len);
        let off_public_output = if output_is_private {
            let off = next_private;
            next_private += OUT;
            off
        } else {
            off_public_output
        };
        let off_private_witness = next_private;
        next_private += digest_witness_len;
        let off_body_bytes = next_private;
        next_private += body_len;
        let off_body_bits = next_private;
        next_private += body_len * 8;
        let witness_len =
            digest_witness_len + body_len + body_len * 8 + if output_is_private { OUT } else { 0 };
        digest_blocks.push(TypedCpDigestBlockLayout {
            off_public_output,
            off_private_witness,
            off_body_bytes,
            off_body_bits,
            input_len,
            body_len,
            witness_len,
        });
        total_constraints += poseidon2_direct_digest_constraints_count(input_len);
        total_constraints += body_len * 9;
    }
    let mut range_payload_blocks = Vec::with_capacity(lengths.gr1cs_message_shapes.len());
    for shape in &lengths.gr1cs_message_shapes {
        if let Some(range_shape) = shape.range.as_ref() {
            let monomial_commitment_coeffs_count = range_shape
                .monomial_commitment_elem_lens
                .iter()
                .map(|&elem_len| elem_len * D)
                .sum();
            let monomial_vector_coeffs_count = range_shape
                .monomial_vector_lens
                .iter()
                .map(|&vector_len| vector_len * D)
                .sum();
            let monomial_vector_elements_count = range_shape.monomial_vector_lens.iter().sum();
            let monomial_sumcheck_evaluation_coeffs_count = range_shape
                .monomial_sumcheck_round_evals
                .iter()
                .map(|&eval_count| eval_count * 2)
                .sum();
            let monomial_evaluation_coeffs_count = range_shape
                .monomial_evaluation_rows
                .iter()
                .map(|&rows| rows * D)
                .sum();
            let sq_evaluation_coeffs_count = range_shape.sq_evaluations_count * 2;
            let off_monomial_commitments = next_private;
            next_private += monomial_commitment_coeffs_count;
            let off_monomial_commitment_wraps = next_private;
            next_private += monomial_commitment_coeffs_count;
            let off_monomial_vectors = next_private;
            next_private += monomial_vector_coeffs_count;
            let off_monomial_vector_squares = next_private;
            next_private += monomial_vector_coeffs_count;
            let off_monomial_sumcheck_evaluations = next_private;
            next_private += monomial_sumcheck_evaluation_coeffs_count;
            let off_monomial_evaluations = next_private;
            next_private += monomial_evaluation_coeffs_count;
            let off_sq_evaluations = next_private;
            next_private += sq_evaluation_coeffs_count;
            let off_projected_values = next_private;
            next_private += range_shape.projected_values_count;
            let monomial_semantic_counts = monomial_sumcheck_semantic_counts(range_shape);
            let off_monomial_sumcheck_seed = next_private;
            next_private += monomial_semantic_counts.challenge_len;
            let off_monomial_sumcheck_challenges = next_private;
            next_private += monomial_semantic_counts.challenge_len;
            let off_monomial_alpha = next_private;
            next_private += 2;
            let off_monomial_sumcheck_aux = next_private;
            next_private += monomial_semantic_counts.aux_count;
            let off_monomial_sumcheck_wraps = next_private;
            next_private += monomial_semantic_counts.wrap_count;
            range_payload_blocks.push(Some(TypedCpRangePayloadBlockLayout {
                off_monomial_commitments,
                monomial_commitment_coeffs_count,
                off_monomial_commitment_wraps,
                off_monomial_vectors,
                monomial_vector_coeffs_count,
                off_monomial_vector_squares,
                monomial_vector_elements_count,
                off_monomial_sumcheck_evaluations,
                monomial_sumcheck_evaluation_coeffs_count,
                off_monomial_evaluations,
                monomial_evaluation_coeffs_count,
                off_sq_evaluations,
                sq_evaluation_coeffs_count,
                off_projected_values,
                projected_values_count: range_shape.projected_values_count,
                off_monomial_sumcheck_seed,
                off_monomial_sumcheck_challenges,
                off_monomial_alpha,
                off_monomial_sumcheck_aux,
                monomial_sumcheck_aux_count: monomial_semantic_counts.aux_count,
                off_monomial_sumcheck_wraps,
                monomial_sumcheck_wrap_count: monomial_semantic_counts.wrap_count,
            }));
        } else {
            range_payload_blocks.push(None);
        }
    }
    let folded_eval_product_count =
        cp_layout.ell_np * lengths.folded_evaluation_values * T * cp_layout.d;
    let off_folded_eval_products = next_private;
    next_private += folded_eval_product_count;
    let folded_eval_wrap_count = lengths.folded_evaluation_values * T * cp_layout.d;
    let off_folded_eval_wraps = next_private;
    next_private += folded_eval_wrap_count;
    let beta_binding_selector_count =
        cp_layout.ell_np * TYPED_BETA_CHALLENGE_BYTES * TYPED_BETA_SELECTORS_PER_BYTE;
    let off_beta_binding_selectors = next_private;
    next_private += beta_binding_selector_count;
    total_constraints += structured_digest_body_constraints_count(
        lengths,
        cp_layout,
        original_r1cs.num_constraints,
        original_r1cs.num_variables,
    );
    total_constraints += typed_cp_beta_binding_constraints_count(cp_layout);
    total_constraints += folded_evaluation_derivation_constraints_count(lengths, cp_layout);

    let num_variables = next_private;
    let mut r1cs = R1CSMatrices::new(total_constraints, num_variables, num_public);
    let mut audit = TypedCpAuditBuilder::default();
    let statement_map = |col: usize| -> usize {
        if col < statement_layout.num_public {
            col
        } else {
            col + statement_private_shift
        }
    };
    copy_r1cs_block(&mut r1cs, &statement_r1cs, 0, &statement_map);
    audit.push(
        TypedCpAuditBlockKind::CpFoldingCore,
        "cp-folding-core",
        0,
        cp_r1cs.num_constraints,
        &[
            "folded commitment consistency",
            "folded public input consistency",
            "Hadamard sumcheck core constraints",
        ],
    );
    let mut audit_statement_row = cp_r1cs.num_constraints;
    let ajtai_rows = ajtai.kappa * D;
    let original_rows = original_r1cs.num_constraints * D;
    for ell in 0..cp_layout.ell_np {
        let start = audit_statement_row;
        audit_statement_row += ajtai_rows;
        audit.push(
            TypedCpAuditBlockKind::AjtaiOpeningChecks,
            format!("original-ajtai-opening-{ell}"),
            start,
            audit_statement_row,
            &["original Ajtai witness opening validity"],
        );

        let start = audit_statement_row;
        audit_statement_row += original_rows;
        audit.push(
            TypedCpAuditBlockKind::OriginalR1csValidity,
            format!("original-r1cs-validity-{ell}"),
            start,
            audit_statement_row,
            &["original R1CS witness validity"],
        );
    }
    audit.push(
        TypedCpAuditBlockKind::PublicInputBinding,
        "public-input-binding",
        audit_statement_row,
        statement_r1cs.num_constraints,
        &["public input and R1CS metadata binding"],
    );

    let mut row_offset = statement_r1cs.num_constraints;
    for (idx, (&(domain, _, _, _, _), block)) in
        digest_specs.iter().zip(digest_blocks.iter()).enumerate()
    {
        let start = row_offset;
        let (block_r1cs, aux_end) =
            generate_poseidon2_direct_digest_r1cs(domain, block, num_public);
        debug_assert_eq!(
            aux_end,
            block.off_private_witness + poseidon2_digest_aux_len(block.input_len)
        );
        copy_r1cs_block(&mut r1cs, &block_r1cs, row_offset, &|col| col);
        row_offset += block_r1cs.num_constraints;
        audit.push(
            TypedCpAuditBlockKind::PoseidonDigestGadgets,
            format!(
                "poseidon-digest-gadget-{}-{idx}",
                String::from_utf8_lossy(domain)
            ),
            start,
            row_offset,
            &["Poseidon2/BabyBear digest correctness"],
        );
    }
    for (&(domain, _, _, _, _), block) in digest_specs.iter().zip(digest_blocks.iter()) {
        let start = row_offset;
        row_offset = insert_digest_body_binding_constraints(&mut r1cs, row_offset, domain, block);
        audit.push(
            TypedCpAuditBlockKind::ByteConstraints,
            format!(
                "digest-body-byte-packing-{}",
                String::from_utf8_lossy(domain)
            ),
            start,
            row_offset,
            &["exact-byte Poseidon digest body packing"],
        );
    }
    let fs_count = lengths.fs_commitment_inputs.len();
    let fs_root_idx = fs_count;
    let fold_root_idx = fs_count + 1;
    let challenge_digest_idx = fs_count + 2;
    let transcript_seed_idx = fs_count + 3;
    let challenge_start_idx = fs_count + 4;
    let start = row_offset;
    row_offset = insert_fs_root_commitment_constraints(
        &mut r1cs,
        row_offset,
        &digest_blocks[0..fs_count],
        &digest_blocks[fs_root_idx],
    );
    audit.push(
        TypedCpAuditBlockKind::ByteConstraints,
        "fs-root-commitment-limb-binding",
        start,
        row_offset,
        &["FS root binds FS commitment digest outputs"],
    );
    let mut audit_ref = Some(&mut audit);
    row_offset = insert_structured_digest_body_constraints(
        &mut r1cs,
        row_offset,
        &statement_layout,
        &digest_blocks[0..fs_count],
        &digest_blocks[fs_root_idx],
        &digest_blocks[fold_root_idx],
        &digest_blocks[challenge_digest_idx],
        &digest_blocks[transcript_seed_idx],
        &digest_blocks[challenge_start_idx..challenge_start_idx + fs_count],
        &range_payload_blocks,
        lengths,
        added_digest_public,
        ajtai,
        &mut audit_ref,
    );
    let start = row_offset;
    row_offset = insert_folded_evaluation_derivation_constraints(
        &mut r1cs,
        row_offset,
        &statement_layout,
        added_digest_public,
        off_folded_evaluations,
        lengths.folded_evaluation_values,
        off_folded_eval_products,
        off_folded_eval_wraps,
        ajtai.q,
    );
    audit.push(
        TypedCpAuditBlockKind::FoldedOutputDerivation,
        "folded-evaluation-derivation",
        start,
        row_offset,
        &["folded output evaluation values derive from beta-weighted GR1CS evaluations"],
    );
    let start = row_offset;
    row_offset = insert_typed_cp_beta_binding_constraints(
        &mut r1cs,
        row_offset,
        &statement_layout,
        added_digest_public,
        &digest_blocks[challenge_digest_idx],
        off_beta_binding_selectors,
    );
    audit.push(
        TypedCpAuditBlockKind::ChallengeToBetaBinding,
        "challenge-to-beta-binding",
        start,
        row_offset,
        &["Poseidon challenge outputs bind CP beta coefficients"],
    );
    debug_assert_eq!(row_offset, r1cs.num_constraints);

    let mut blocks_iter = digest_blocks.into_iter();
    let fs_commitment_blocks = (0..lengths.fs_commitment_inputs.len())
        .map(|_| blocks_iter.next().expect("fs commitment digest block"))
        .collect();
    let fs_root_block = blocks_iter.next().expect("fs root digest block");
    let fold_root_block = blocks_iter.next().expect("fold root digest block");
    let challenge_digest_block = blocks_iter.next().expect("challenge digest block");
    let transcript_seed_block = blocks_iter.next().expect("transcript seed digest block");
    let challenge_blocks = (0..lengths.challenge_inputs.len())
        .map(|_| {
            blocks_iter
                .next()
                .expect("per-round challenge digest block")
        })
        .collect();

    let layout = TypedCpDigestR1csLayout {
        statement: statement_layout,
        fs_commitments_are_public,
        fs_commitment_blocks,
        challenge_blocks,
        range_payload_blocks,
        fs_root_block,
        fold_root_block,
        challenge_digest_block,
        transcript_seed_block,
        off_fs_commitments,
        off_fs_root,
        off_fold_root,
        off_challenge_digest,
        off_transcript_seed_digest,
        off_folded_evaluations,
        folded_evaluation_values: lengths.folded_evaluation_values,
        off_folded_eval_products,
        off_folded_eval_wraps,
        off_beta_binding_selectors,
        beta_binding_selector_count,
        added_digest_public,
        num_public,
        num_variables,
    };
    let audit = audit.finish(num_public, num_variables, total_constraints);
    debug_assert!(audit.validate_against(&r1cs).is_ok());
    (r1cs, layout, audit)
}
