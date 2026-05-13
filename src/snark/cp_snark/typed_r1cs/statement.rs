pub fn generate_original_statement_r1cs(
    ajtai: &crate::commitment::AjtaiParams,
    r1cs_src: &R1CSMatrices,
) -> (R1CSMatrices, OriginalStatementR1csLayout) {
    assert_eq!(ajtai.n, r1cs_src.num_variables);
    assert_eq!(ajtai.kappa, ajtai.a.len());
    let n_public = r1cs_src.num_public;
    let n_witness = r1cs_src.num_variables - r1cs_src.num_public;
    let off_one = 0;
    let off_public_input = 1;
    let off_commitment = off_public_input + n_public;
    let num_public = off_commitment + ajtai.kappa * D;
    let off_witness = num_public;
    let off_ajtai_wrap = off_witness + n_witness * D;
    let off_r1cs_wrap = off_ajtai_wrap + ajtai.kappa * D;
    let num_variables = off_r1cs_wrap + r1cs_src.num_constraints * D;
    let num_constraints = ajtai.kappa * D + r1cs_src.num_constraints * D;
    let layout = OriginalStatementR1csLayout {
        n_public,
        n_witness,
        kappa: ajtai.kappa,
        q: ajtai.q,
        d: D,
        off_one,
        off_public_input,
        off_commitment,
        off_witness,
        off_ajtai_wrap,
        off_r1cs_wrap,
        num_public,
        num_variables,
    };

    let mut r1cs = R1CSMatrices::new(num_constraints, num_variables, num_public);
    let mut row = 0usize;
    for i in 0..ajtai.kappa {
        for coeff in 0..D {
            insert_ajtai_opening_lc(&mut r1cs, row, &layout, ajtai, i, coeff);
            row += 1;
        }
    }
    for constraint in 0..r1cs_src.num_constraints {
        for coeff in 0..D {
            insert_original_r1cs_lc(&mut r1cs, row, &layout, r1cs_src, constraint, coeff);
            row += 1;
        }
    }
    debug_assert_eq!(row, num_constraints);
    (r1cs, layout)
}

pub fn encode_original_statement_instance(
    public_input: &[i64],
    commitment: &crate::commitment::Commitment,
    layout: &OriginalStatementR1csLayout,
) -> Vec<u8> {
    assert_eq!(public_input.len(), layout.n_public);
    assert_eq!(commitment.value.elements.len(), layout.kappa);
    let mut out = Vec::with_capacity(layout.num_public * 8);
    out.extend_from_slice(&1i64.to_le_bytes());
    for &value in public_input {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for elem in &commitment.value.elements {
        for &coeff in &elem.coeffs {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    out
}

pub fn encode_original_statement_witness(
    public_input: &[i64],
    witness_part: &RingVector,
    commitment: &crate::commitment::Commitment,
    ajtai: &crate::commitment::AjtaiParams,
    r1cs_src: &R1CSMatrices,
    layout: &OriginalStatementR1csLayout,
) -> Vec<u8> {
    assert_eq!(witness_part.len(), layout.n_witness);
    let full = assemble_full_ring_witness(public_input, witness_part);
    let mut values = Vec::<i64>::with_capacity(layout.num_variables - layout.num_public);
    for elem in &witness_part.elements {
        values.extend_from_slice(&elem.coeffs);
    }
    for i in 0..ajtai.kappa {
        for coeff in 0..D {
            let raw = raw_ajtai_coeff(ajtai, &full, i, coeff);
            let committed = commitment.value.elements[i].coeffs[coeff] as i128;
            values.push(wrap_quotient(raw - committed, ajtai.q));
        }
    }
    for constraint in 0..r1cs_src.num_constraints {
        for coeff in 0..D {
            let (az, bz, cz) = raw_original_r1cs_row(r1cs_src, &full, constraint, coeff);
            values.push(wrap_quotient(az * bz - cz, ajtai.q));
        }
    }

    let mut out = Vec::with_capacity(values.len() * 8);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

pub fn generate_typed_cp_partial_r1cs(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
) -> (R1CSMatrices, TypedCpPartialR1csLayout) {
    assert_eq!(cp_r1cs.num_public, cp_layout.num_instance);
    assert_eq!(cp_r1cs.num_variables, cp_layout.num_variables);
    assert_eq!(ajtai.n, original_r1cs.num_variables);
    assert_eq!(cp_layout.kappa, ajtai.kappa);
    assert_eq!(cp_layout.n_in, original_r1cs.num_public);

    let n_witness = original_r1cs.num_variables - original_r1cs.num_public;
    let original_witness_size = n_witness * D;
    let original_ajtai_wrap_size = ajtai.kappa * D;
    let original_r1cs_wrap_size = original_r1cs.num_constraints * D;
    let original_block_size =
        original_witness_size + original_ajtai_wrap_size + original_r1cs_wrap_size;
    let original_constraints_per_instance = ajtai.kappa * D + original_r1cs.num_constraints * D;

    let off_original_witnesses = cp_layout.num_variables;
    let off_original_ajtai_wraps =
        off_original_witnesses + cp_layout.ell_np * original_witness_size;
    let off_original_r1cs_wraps =
        off_original_ajtai_wraps + cp_layout.ell_np * original_ajtai_wrap_size;
    let num_variables = off_original_r1cs_wraps + cp_layout.ell_np * original_r1cs_wrap_size;
    let num_constraints =
        cp_r1cs.num_constraints + cp_layout.ell_np * original_constraints_per_instance;
    let mut r1cs = R1CSMatrices::new(num_constraints, num_variables, cp_r1cs.num_public);

    copy_r1cs_block(&mut r1cs, cp_r1cs, 0, &|col| col);

    let mut row_offset = cp_r1cs.num_constraints;
    let (original_block, original_layout) = generate_original_statement_r1cs(ajtai, original_r1cs);
    for ell in 0..cp_layout.ell_np {
        let mapper = |col: usize| -> usize {
            map_original_col_to_typed_cp(
                col,
                ell,
                cp_layout,
                &original_layout,
                original_witness_size,
                original_ajtai_wrap_size,
                original_r1cs_wrap_size,
                off_original_witnesses,
                off_original_ajtai_wraps,
                off_original_r1cs_wraps,
            )
        };
        copy_r1cs_block(&mut r1cs, &original_block, row_offset, &mapper);
        row_offset += original_block.num_constraints;
    }
    debug_assert_eq!(row_offset, num_constraints);

    let layout = TypedCpPartialR1csLayout {
        cp_layout: cp_layout.clone(),
        original_r1cs_num_constraints: original_r1cs.num_constraints,
        original_r1cs_num_variables: original_r1cs.num_variables,
        off_original_witnesses,
        off_original_ajtai_wraps,
        off_original_r1cs_wraps,
        original_block_size,
        original_constraints_per_instance,
        num_public: cp_r1cs.num_public,
        num_variables,
    };
    (r1cs, layout)
}

pub fn generate_typed_cp_statement_r1cs(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
) -> (R1CSMatrices, TypedCpStatementR1csLayout) {
    let (partial_r1cs, partial_layout) =
        generate_typed_cp_partial_r1cs(cp_r1cs, cp_layout, ajtai, original_r1cs);
    let added_public_inputs = cp_layout.ell_np * cp_layout.n_in;
    let off_public_inputs = partial_layout.num_public;
    let num_public = partial_layout.num_public + added_public_inputs;
    let num_variables = partial_layout.num_variables + added_public_inputs;
    let public_input_constraints = cp_layout.ell_np * cp_layout.n_in * D;
    let mut r1cs = R1CSMatrices::new(
        partial_r1cs.num_constraints + public_input_constraints,
        num_variables,
        num_public,
    );
    let map_col = |col: usize| -> usize {
        if col < partial_layout.num_public {
            col
        } else {
            col + added_public_inputs
        }
    };
    copy_r1cs_block(&mut r1cs, &partial_r1cs, 0, &map_col);

    let mut row = partial_r1cs.num_constraints;
    for ell in 0..cp_layout.ell_np {
        for slot in 0..cp_layout.n_in {
            let public_col = off_public_inputs + ell * cp_layout.n_in + slot;
            let cp_const_coeff_col = map_col(cp_layout.x_in(ell, slot, 0));
            r1cs.a.insert(row, cp_const_coeff_col, 1);
            r1cs.a.insert(row, public_col, -1);
            r1cs.b.insert(row, cp_layout.off_one, 1);
            row += 1;

            for coeff in 1..D {
                let cp_coeff_col = map_col(cp_layout.x_in(ell, slot, coeff));
                r1cs.a.insert(row, cp_coeff_col, 1);
                r1cs.b.insert(row, cp_layout.off_one, 1);
                row += 1;
            }
        }
    }
    debug_assert_eq!(row, r1cs.num_constraints);

    let layout = TypedCpStatementR1csLayout {
        partial: partial_layout,
        off_public_inputs,
        added_public_inputs,
        num_public,
        num_variables,
    };
    (r1cs, layout)
}

pub fn typed_cp_digest_input_lengths(
    public: &crate::cp_relation_core::CpPublicStatement,
    witness: &crate::cp_relation_core::CpWitnessBundle,
) -> Option<TypedCpDigestInputLengths> {
    if public.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
        return None;
    }
    if witness.fs_messages.len() != witness.fs_openings.len()
        || witness.fs_messages.len() != witness.fs_commitments.len()
    {
        return None;
    }

    let fs_commitment_bodies = witness
        .fs_messages
        .iter()
        .zip(witness.fs_openings.iter())
        .map(|(message, opening)| {
            let opening: Digest32 = opening.as_slice().try_into().ok()?;
            Some(poseidon_fs_commit_body(message, &opening).len())
        })
        .collect::<Option<Vec<_>>>()?;
    let fs_commitment_inputs = fs_commitment_bodies
        .iter()
        .map(|&body_len| poseidon_digest_input_len(b"fs-commit", body_len))
        .collect();
    let gr1cs_message_bodies = fs_commitment_bodies
        .iter()
        .map(|&body_len| body_len.checked_sub(8 + 32))
        .collect::<Option<Vec<_>>>()?;
    let gr1cs_message_shapes = witness
        .fs_messages
        .iter()
        .enumerate()
        .map(|(idx, message)| {
            witness
                .folding_proof
                .gr1cs_proofs
                .get(idx)
                .and_then(|proof| typed_gr1cs_message_shape(proof, message.len()))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    let challenges = derive_challenges_with_scheme(
        public.digest_scheme,
        &public.public_inputs,
        public.r1cs_num_constraints,
        public.r1cs_num_variables,
        public.r1cs_num_public,
        &witness.fs_commitments,
    );
    let challenge_bodies = (0..witness.fs_commitments.len())
        .map(|idx| {
            poseidon_challenge_body(
                idx,
                &public.public_inputs,
                public.r1cs_num_constraints,
                public.r1cs_num_variables,
                public.r1cs_num_public,
                &witness.fs_commitments,
            )
            .len()
        })
        .collect::<Vec<_>>();
    let challenge_inputs = challenge_bodies
        .iter()
        .map(|&body_len| poseidon_digest_input_len(b"challenge", body_len))
        .collect();
    let fs_root_body = poseidon_fs_root_body(&witness.fs_commitments).len();
    let fold_root_body = poseidon_fold_root_body(&witness.fold_inputs).len();
    let challenge_digest_body = poseidon_challenge_digest_body(&challenges).len();
    let transcript_seed_body = poseidon_transcript_seed_body(
        &public.public_inputs,
        public.r1cs_num_constraints,
        public.r1cs_num_variables,
        public.r1cs_num_public,
    )
    .len();
    if public.instance.folded_output.folded_instance != public.instance.x_folded {
        return None;
    }
    let folded_evaluation_values = public.instance.x_folded.evaluation_values.len();
    if folded_evaluation_values > 3 {
        return None;
    }
    Some(TypedCpDigestInputLengths {
        fs_commitment_inputs,
        fs_commitment_bodies,
        gr1cs_message_bodies,
        gr1cs_message_shapes,
        challenge_inputs,
        challenge_bodies,
        fs_root_input: poseidon_digest_input_len(b"fs-root", fs_root_body),
        fs_root_body,
        fold_root_input: poseidon_digest_input_len(b"fold-root", fold_root_body),
        fold_root_body,
        challenge_digest_input: poseidon_digest_input_len(
            b"challenge-digest",
            challenge_digest_body,
        ),
        challenge_digest_body,
        transcript_seed_input: poseidon_digest_input_len(b"transcript-seed", transcript_seed_body),
        transcript_seed_body,
        folded_evaluation_values,
    })
}

pub fn typed_cp_digest_input_lengths_from_setup(
    ell_np: usize,
    kappa: usize,
    n_in: usize,
    lambda_pj: usize,
    ell_h: usize,
    k_g: usize,
    original_r1cs: &R1CSMatrices,
) -> Option<TypedCpDigestInputLengths> {
    if ell_np == 0 || kappa == 0 || ell_h == 0 || k_g == 0 {
        return None;
    }

    let had_num_vars = if original_r1cs.num_constraints <= 1 {
        0
    } else {
        (usize::BITS - (original_r1cs.num_constraints - 1).leading_zeros()) as usize
    };
    let total_coeffs = original_r1cs.num_variables.checked_mul(D)?;
    let projection_blocks = if total_coeffs == 0 {
        1
    } else {
        total_coeffs.div_ceil(ell_h)
    };
    let projected_values_count = projection_blocks.checked_mul(lambda_pj)?;
    let monomial_vector_len = projected_values_count.next_power_of_two();
    let monomial_num_vars = if monomial_vector_len <= 1 {
        0
    } else {
        (usize::BITS - (monomial_vector_len - 1).leading_zeros()) as usize
    };

    let range_shape = TypedCpRangeMessageShape {
        monomial_commitment_elem_lens: vec![kappa; k_g],
        monomial_vector_lens: vec![monomial_vector_len; k_g],
        monomial_sumcheck_round_evals: vec![5; monomial_num_vars],
        monomial_evaluation_rows: vec![T; k_g],
        sq_evaluations_count: k_g,
        projected_values_count,
    };
    let message_shape = TypedCpGr1csMessageShape {
        hadamard_sumcheck_round_evals: vec![4; had_num_vars],
        hadamard_eval_matrix_rows: vec![T; 3],
        range: Some(range_shape),
    };
    let message_len = gr1cs_message_len_from_shape(&message_shape)?;

    let fs_commitment_body = 8usize.checked_add(message_len)?.checked_add(32)?;
    let fs_commitment_input = poseidon_digest_input_len(b"fs-commit", fs_commitment_body);
    let fs_commitment_inputs = vec![fs_commitment_input; ell_np];
    let fs_commitment_bodies = vec![fs_commitment_body; ell_np];
    let gr1cs_message_bodies = vec![message_len; ell_np];
    let gr1cs_message_shapes = vec![message_shape; ell_np];

    let fs_root_body = 8usize.checked_add(ell_np.checked_mul(8 + 32)?)?;
    let commitment_len = commitment_message_len(kappa);
    let fold_input_len = 8usize
        .checked_add(commitment_len)?
        .checked_add(8)?
        .checked_add(n_in.checked_mul(8)?)?
        .checked_add(8)?
        .checked_add(message_len)?;
    let fold_root_body = 8usize.checked_add(ell_np.checked_mul(fold_input_len)?)?;
    let challenge_digest_body = 8usize.checked_add(ell_np.checked_mul(8 + 32)?)?;

    let dummy_public_inputs = vec![vec![0i64; n_in]; ell_np];
    let dummy_fs_commitments = vec![vec![0u8; 32]; ell_np];
    let transcript_len = crate::cp_relation_core::cp_relation_transcript_bytes(
        &dummy_public_inputs,
        original_r1cs.num_constraints,
        original_r1cs.num_variables,
        original_r1cs.num_public,
        &dummy_fs_commitments,
    )
    .len();
    let challenge_body = 8usize.checked_add(transcript_len)?;
    let challenge_inputs = vec![poseidon_digest_input_len(b"challenge", challenge_body); ell_np];
    let challenge_bodies = vec![challenge_body; ell_np];

    let transcript_seed_body = 8usize
        .checked_add(ell_np.checked_mul(8 + n_in.checked_mul(8)?)?)?
        .checked_add(3 * 8)?;

    Some(TypedCpDigestInputLengths {
        fs_commitment_inputs,
        fs_commitment_bodies,
        gr1cs_message_bodies,
        gr1cs_message_shapes,
        challenge_inputs,
        challenge_bodies,
        fs_root_input: poseidon_digest_input_len(b"fs-root", fs_root_body),
        fs_root_body,
        fold_root_input: poseidon_digest_input_len(b"fold-root", fold_root_body),
        fold_root_body,
        challenge_digest_input: poseidon_digest_input_len(
            b"challenge-digest",
            challenge_digest_body,
        ),
        challenge_digest_body,
        transcript_seed_input: poseidon_digest_input_len(b"transcript-seed", transcript_seed_body),
        transcript_seed_body,
        folded_evaluation_values: 3,
    })
}

pub fn generate_typed_cp_digest_r1cs(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
    lengths: &TypedCpDigestInputLengths,
) -> (R1CSMatrices, TypedCpDigestR1csLayout) {
    let (r1cs, layout, _audit) =
        generate_typed_cp_digest_r1cs_with_audit(cp_r1cs, cp_layout, ajtai, original_r1cs, lengths);
    (r1cs, layout)
}

pub fn generate_typed_cp_digest_r1cs_with_audit(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
    lengths: &TypedCpDigestInputLengths,
) -> (R1CSMatrices, TypedCpDigestR1csLayout, TypedCpAuditReport) {
    generate_typed_cp_digest_r1cs_with_audit_mode(
        cp_r1cs,
        cp_layout,
        ajtai,
        original_r1cs,
        lengths,
        true,
    )
}

pub fn generate_typed_cp_digest_r1cs_compressed_fs_with_audit(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
    lengths: &TypedCpDigestInputLengths,
) -> (R1CSMatrices, TypedCpDigestR1csLayout, TypedCpAuditReport) {
    generate_typed_cp_digest_r1cs_with_audit_mode(
        cp_r1cs,
        cp_layout,
        ajtai,
        original_r1cs,
        lengths,
        false,
    )
}

pub fn generate_typed_cp_digest_r1cs_compressed_fs(
    cp_r1cs: &R1CSMatrices,
    cp_layout: &CpR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
    lengths: &TypedCpDigestInputLengths,
) -> (R1CSMatrices, TypedCpDigestR1csLayout) {
    let (r1cs, layout, _audit) = generate_typed_cp_digest_r1cs_compressed_fs_with_audit(
        cp_r1cs,
        cp_layout,
        ajtai,
        original_r1cs,
        lengths,
    );
    (r1cs, layout)
}

