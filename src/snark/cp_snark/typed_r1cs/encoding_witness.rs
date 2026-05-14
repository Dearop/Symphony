#[allow(clippy::too_many_arguments)]
pub fn encode_typed_cp_partial_witness(
    commitments: &[crate::commitment::Commitment],
    public_inputs: &[Vec<i64>],
    beta: &[RingElement],
    folded_instance: &FoldedInstance,
    layout: &TypedCpPartialR1csLayout,
    ntt: &Option<crate::ring::ntt::NttContext>,
    gr1cs_proofs: &[GR1CSProof],
    had_seed: &[ExtFieldElement],
    had_alpha: &ExtFieldElement,
    had_challenges: &[ExtFieldElement],
    qnr: i64,
    q: u64,
    original_witnesses: &[RingVector],
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
) -> Vec<u8> {
    let mut buf = encode_cp_witness_r1cs(
        commitments,
        public_inputs,
        beta,
        folded_instance,
        &layout.cp_layout,
        ntt,
        gr1cs_proofs,
        had_seed,
        had_alpha,
        had_challenges,
        qnr,
        q,
    );

    let n_witness = original_r1cs.num_variables - original_r1cs.num_public;
    let original_witness_size = n_witness * D;
    let original_ajtai_wrap_size = ajtai.kappa * D;
    let original_r1cs_wrap_size = original_r1cs.num_constraints * D;

    for ell in 0..layout.cp_layout.ell_np {
        if let Some(witness_part) = original_witnesses.get(ell) {
            assert_eq!(witness_part.len(), n_witness);
            for elem in &witness_part.elements {
                for &coeff in &elem.coeffs {
                    buf.extend_from_slice(&coeff.to_le_bytes());
                }
            }
        } else {
            buf.resize(buf.len() + original_witness_size * 8, 0);
        }
    }

    for ell in 0..layout.cp_layout.ell_np {
        if ell < original_witnesses.len() && ell < commitments.len() && ell < public_inputs.len() {
            let full = assemble_full_ring_witness(&public_inputs[ell], &original_witnesses[ell]);
            for i in 0..ajtai.kappa {
                for coeff in 0..D {
                    let raw = raw_ajtai_coeff(ajtai, &full, i, coeff);
                    let committed = commitments[ell].value.elements[i].coeffs[coeff] as i128;
                    let wrap = wrap_quotient(raw - committed, ajtai.q);
                    buf.extend_from_slice(&wrap.to_le_bytes());
                }
            }
        } else {
            buf.resize(buf.len() + original_ajtai_wrap_size * 8, 0);
        }
    }

    for ell in 0..layout.cp_layout.ell_np {
        if ell < original_witnesses.len() && ell < public_inputs.len() {
            let full = assemble_full_ring_witness(&public_inputs[ell], &original_witnesses[ell]);
            for constraint in 0..original_r1cs.num_constraints {
                for coeff in 0..D {
                    let (az, bz, cz) =
                        raw_original_r1cs_row(original_r1cs, &full, constraint, coeff);
                    let wrap = wrap_quotient(az * bz - cz, ajtai.q);
                    buf.extend_from_slice(&wrap.to_le_bytes());
                }
            }
        } else {
            buf.resize(buf.len() + original_r1cs_wrap_size * 8, 0);
        }
    }

    debug_assert_eq!(buf.len(), (layout.num_variables - layout.num_public) * 8);
    buf
}

pub fn encode_typed_cp_statement_instance(
    folded_instance: &FoldedInstance,
    public_inputs: &[Vec<i64>],
    layout: &TypedCpStatementR1csLayout,
) -> Vec<u8> {
    let mut out = super::r1cs::encode_cp_instance_r1cs(folded_instance, &layout.partial.cp_layout);
    for ell in 0..layout.partial.cp_layout.ell_np {
        for slot in 0..layout.partial.cp_layout.n_in {
            let value = public_inputs
                .get(ell)
                .and_then(|pi| pi.get(slot))
                .copied()
                .unwrap_or(0);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    out
}

pub fn digest32_to_babybear_elems(digest: &Digest32) -> Option<[BabyBear; OUT]> {
    let mut out = [BabyBear::ZERO; OUT];
    for (idx, chunk) in digest.chunks_exact(4).enumerate() {
        let value = u32::from_le_bytes(chunk.try_into().ok()?);
        if value as u64 >= BB_P {
            return None;
        }
        out[idx] = BabyBear::from_u32(value);
    }
    Some(out)
}

pub fn encode_typed_cp_digest_instance(
    public: &crate::cp_relation_core::CpPublicStatement,
    fs_commitments: &[Vec<u8>],
    layout: &TypedCpDigestR1csLayout,
) -> Option<Vec<u8>> {
    if layout.fs_commitments_are_public && fs_commitments.len() != layout.fs_commitment_blocks.len()
    {
        return None;
    }
    if !layout.fs_commitments_are_public && !fs_commitments.is_empty() {
        return None;
    }
    let mut out = encode_typed_cp_statement_instance(
        &public.instance.x_folded,
        &public.public_inputs,
        &layout.statement,
    );
    if layout.fs_commitments_are_public {
        for commitment in fs_commitments {
            let commitment: Digest32 = commitment.as_slice().try_into().ok()?;
            for elem in digest32_to_babybear_elems(&commitment)? {
                out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
            }
        }
    }
    for digest in [
        &public.instance.fs_root,
        &public.instance.fold_root,
        &public.instance.challenge_digest,
        &public.instance.transcript_seed_digest,
    ] {
        for elem in digest32_to_babybear_elems(digest)? {
            out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
        }
    }
    if public.instance.x_folded.evaluation_values.len() != layout.folded_evaluation_values
        || public.instance.folded_output.folded_instance != public.instance.x_folded
    {
        return None;
    }
    for eval in &public.instance.x_folded.evaluation_values {
        for row in &eval.data {
            for &coeff in row.iter().take(D) {
                out.extend_from_slice(&coeff.to_le_bytes());
            }
        }
    }
    Some(out)
}

#[allow(clippy::too_many_arguments)]
pub fn encode_typed_cp_digest_witness(
    public: &crate::cp_relation_core::CpPublicStatement,
    witness: &crate::cp_relation_core::CpWitnessBundle,
    layout: &TypedCpDigestR1csLayout,
    ntt: &Option<crate::ring::ntt::NttContext>,
    qnr: i64,
    q: u64,
    ajtai: &crate::commitment::AjtaiParams,
    original_r1cs: &R1CSMatrices,
) -> Option<Vec<u8>> {
    if public.digest_scheme != PublicDigestScheme::Poseidon2BabyBear {
        return None;
    }
    if witness.fs_messages.len() != layout.fs_commitment_blocks.len()
        || witness.fs_openings.len() != layout.fs_commitment_blocks.len()
        || witness.fs_commitments.len() != layout.fs_commitment_blocks.len()
    {
        return None;
    }
    let actual_lengths = typed_cp_digest_input_lengths(public, witness)?;
    if !typed_cp_digest_layout_matches_lengths(layout, &actual_lengths) {
        return None;
    }
    let challenges = derive_challenges_with_scheme(
        public.digest_scheme,
        &public.public_inputs,
        public.r1cs_num_constraints,
        public.r1cs_num_variables,
        public.r1cs_num_public,
        &witness.fs_commitments,
    );
    if challenges.len() != layout.challenge_blocks.len()
        || layout.challenge_blocks.len() != layout.statement.partial.cp_layout.ell_np
    {
        return None;
    }
    let typed_beta = poseidon_challenges_to_betas(&challenges)?;
    let mut out = encode_typed_cp_partial_witness(
        &witness.folding_proof.commitments,
        &public.public_inputs,
        &typed_beta,
        &public.instance.x_folded,
        &layout.statement.partial,
        ntt,
        &witness.folding_proof.gr1cs_proofs,
        &witness.shared_challenges.sumcheck_seed_had,
        &witness.shared_challenges.alpha,
        &witness.shared_challenges.hadamard_sumcheck_challenges,
        qnr,
        q,
        &witness.original_witnesses,
        ajtai,
        original_r1cs,
    );

    let mut append_digest_witness = |domain: &[u8],
                                     body: Vec<u8>,
                                     block: &TypedCpDigestBlockLayout,
                                     output_is_private: bool,
                                     expected_digest: Option<&[u8]>|
     -> Option<()> {
        if body.len() != block.body_len {
            return None;
        }
        let input = poseidon_digest_input_elems(domain, &body);
        if input.len() != block.input_len {
            return None;
        }
        let digest = poseidon2_babybear_digest_elems(domain, &input);
        let digest_bytes = serialize_poseidon_digest_elems(digest);
        if expected_digest.is_some_and(|expected| expected != digest_bytes.as_slice()) {
            return None;
        }
        if output_is_private {
            for elem in digest {
                out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
            }
        }
        out.extend_from_slice(&encode_poseidon2_digest_witness(domain, &input));
        append_digest_body_binding_witness(&mut out, &body);
        Some(())
    };

    for (((message, opening), commitment), block) in witness
        .fs_messages
        .iter()
        .zip(witness.fs_openings.iter())
        .zip(witness.fs_commitments.iter())
        .zip(layout.fs_commitment_blocks.iter())
    {
        let opening: Digest32 = opening.as_slice().try_into().ok()?;
        append_digest_witness(
            b"fs-commit",
            poseidon_fs_commit_body(message, &opening),
            block,
            !layout.fs_commitments_are_public,
            Some(commitment.as_slice()),
        )?;
    }
    append_digest_witness(
        b"fs-root",
        poseidon_fs_root_body(&witness.fs_commitments),
        &layout.fs_root_block,
        false,
        Some(public.instance.fs_root.as_slice()),
    )?;
    append_digest_witness(
        b"fold-root",
        poseidon_fold_root_body(&witness.fold_inputs),
        &layout.fold_root_block,
        false,
        Some(public.instance.fold_root.as_slice()),
    )?;
    append_digest_witness(
        b"challenge-digest",
        poseidon_challenge_digest_body(&challenges),
        &layout.challenge_digest_block,
        false,
        Some(public.instance.challenge_digest.as_slice()),
    )?;
    append_digest_witness(
        b"transcript-seed",
        poseidon_transcript_seed_body(
            &public.public_inputs,
            public.r1cs_num_constraints,
            public.r1cs_num_variables,
            public.r1cs_num_public,
        ),
        &layout.transcript_seed_block,
        false,
        Some(public.instance.transcript_seed_digest.as_slice()),
    )?;

    for (idx, block) in layout.challenge_blocks.iter().enumerate() {
        let body = poseidon_challenge_body(
            idx,
            &public.public_inputs,
            public.r1cs_num_constraints,
            public.r1cs_num_variables,
            public.r1cs_num_public,
            &witness.fs_commitments,
        );
        append_digest_witness(
            b"challenge",
            body,
            block,
            true,
            challenges.get(idx).map(Vec::as_slice),
        )?;
    }

    for (idx, block) in layout.range_payload_blocks.iter().enumerate() {
        let Some(block) = block else {
            continue;
        };
        let proof = witness.folding_proof.gr1cs_proofs.get(idx)?;
        let mut written = 0;
        for commitment in &proof.range_proof.monomial_commitments {
            for elem in &commitment.value.elements {
                for &coeff in &elem.coeffs {
                    out.extend_from_slice(&coeff.to_le_bytes());
                    written += 1;
                }
            }
        }
        if written != block.monomial_commitment_coeffs_count {
            return None;
        }

        for (commitment, monomial_vector) in proof
            .range_proof
            .monomial_commitments
            .iter()
            .zip(proof.range_proof.monomial_vectors.iter())
        {
            let mon_ajtai = crate::commitment::AjtaiParams::setup_deterministic(
                ajtai.kappa,
                monomial_vector.len(),
                ajtai.q,
                &ajtai.ntt,
                b"range-proof-monomial",
            );
            let monomial_ring_vec = RingVector::from(monomial_vector.clone());
            for commitment_row in 0..mon_ajtai.kappa {
                for coeff in 0..D {
                    let raw =
                        raw_ajtai_coeff(&mon_ajtai, &monomial_ring_vec, commitment_row, coeff);
                    let committed = commitment.value.elements[commitment_row].coeffs[coeff] as i128;
                    let wrap = wrap_quotient(raw - committed, mon_ajtai.q);
                    out.extend_from_slice(&wrap.to_le_bytes());
                }
            }
        }

        written = 0;
        let mut monomial_vector_squares = Vec::with_capacity(block.monomial_vector_coeffs_count);
        for monomial_vector in &proof.range_proof.monomial_vectors {
            for elem in monomial_vector {
                for &coeff in &elem.coeffs {
                    out.extend_from_slice(&coeff.to_le_bytes());
                    monomial_vector_squares.push(coeff * coeff);
                    written += 1;
                }
            }
        }
        if written != block.monomial_vector_coeffs_count {
            return None;
        }
        for square in monomial_vector_squares {
            out.extend_from_slice(&square.to_le_bytes());
        }

        written = 0;
        for round in &proof
            .range_proof
            .monomial_proof
            .sumcheck_proof
            .round_messages
        {
            for eval in &round.evaluations {
                out.extend_from_slice(&eval.c0.to_le_bytes());
                out.extend_from_slice(&eval.c1.to_le_bytes());
                written += 2;
            }
        }
        if written != block.monomial_sumcheck_evaluation_coeffs_count {
            return None;
        }

        written = 0;
        for tensor in &proof.range_proof.monomial_proof.evaluations {
            for row in &tensor.data {
                for &coeff in row.iter().take(D) {
                    out.extend_from_slice(&coeff.to_le_bytes());
                    written += 1;
                }
            }
        }
        if written != block.monomial_evaluation_coeffs_count {
            return None;
        }

        written = 0;
        for eval in &proof.range_proof.monomial_proof.sq_evaluations {
            out.extend_from_slice(&eval.c0.to_le_bytes());
            out.extend_from_slice(&eval.c1.to_le_bytes());
            written += 2;
        }
        if written != block.sq_evaluation_coeffs_count {
            return None;
        }

        if proof.range_proof.projected_values.len() != block.projected_values_count {
            return None;
        }
        for &value in &proof.range_proof.projected_values {
            out.extend_from_slice(&value.to_le_bytes());
        }

        append_monomial_sumcheck_semantic_witness(
            &mut out,
            proof,
            &witness.shared_challenges,
            block,
            ajtai.q,
        )?;
    }

    append_folded_evaluation_derivation_witness(&mut out, public, witness, layout, &typed_beta, q)?;

    for challenge in &challenges {
        append_typed_beta_binding_witness(&mut out, challenge)?;
    }

    Some(out)
}

fn typed_cp_digest_layout_matches_lengths(
    layout: &TypedCpDigestR1csLayout,
    lengths: &TypedCpDigestInputLengths,
) -> bool {
    layout.fs_commitment_blocks.len() == lengths.fs_commitment_inputs.len()
        && layout.challenge_blocks.len() == lengths.challenge_inputs.len()
        && layout.folded_evaluation_values == lengths.folded_evaluation_values
        && layout
            .fs_commitment_blocks
            .iter()
            .zip(
                lengths
                    .fs_commitment_inputs
                    .iter()
                    .zip(lengths.fs_commitment_bodies.iter()),
            )
            .all(|(block, (&input_len, &body_len))| {
                block.input_len == input_len && block.body_len == body_len
            })
        && layout
            .challenge_blocks
            .iter()
            .zip(
                lengths
                    .challenge_inputs
                    .iter()
                    .zip(lengths.challenge_bodies.iter()),
            )
            .all(|(block, (&input_len, &body_len))| {
                block.input_len == input_len && block.body_len == body_len
            })
        && layout.fs_root_block.input_len == lengths.fs_root_input
        && layout.fs_root_block.body_len == lengths.fs_root_body
        && layout.fold_root_block.input_len == lengths.fold_root_input
        && layout.fold_root_block.body_len == lengths.fold_root_body
        && layout.challenge_digest_block.input_len == lengths.challenge_digest_input
        && layout.challenge_digest_block.body_len == lengths.challenge_digest_body
        && layout.transcript_seed_block.input_len == lengths.transcript_seed_input
        && layout.transcript_seed_block.body_len == lengths.transcript_seed_body
        && layout.range_payload_blocks.len() == lengths.gr1cs_message_shapes.len()
}

fn ring_mul_babybear(a: &RingElement, b: &RingElement) -> RingElement {
    let mut acc = [0i128; D];
    for i in 0..D {
        for j in 0..D {
            let prod = a.coeffs[i] as i128 * b.coeffs[j] as i128;
            let idx = i + j;
            if idx < D {
                acc[idx] += prod;
            } else {
                acc[idx - D] -= prod;
            }
        }
    }
    let mut coeffs = [0i64; D];
    for (out, &value) in coeffs.iter_mut().zip(acc.iter()) {
        *out = centered_mod(value, BB_P);
    }
    RingElement { coeffs }
}

fn babybear_sum_wrap(target: i64, sum_prod: i128, q: u64) -> i64 {
    let p_i128 = BB_P as i128;
    let q_embed = centered_mod(q as i128, BB_P) as i128;
    let q_embed_nonzero = q_embed.rem_euclid(p_i128);
    if q_embed_nonzero == 0 {
        return 0;
    }
    let inv_q_embed = mod_pow_u64(q_embed_nonzero as u64, BB_P - 2);
    let target = centered_mod(target as i128, BB_P) as i128;
    let delta = (target - sum_prod).rem_euclid(p_i128) as u64;
    let w_mod = ((delta as u128 * inv_q_embed as u128) % BB_P as u128) as u64;
    centered_mod(w_mod as i128, BB_P)
}

fn append_folded_evaluation_derivation_witness(
    out: &mut Vec<u8>,
    public: &crate::cp_relation_core::CpPublicStatement,
    witness: &crate::cp_relation_core::CpWitnessBundle,
    layout: &TypedCpDigestR1csLayout,
    typed_beta: &[RingElement],
    q: u64,
) -> Option<()> {
    let cp_layout = &layout.statement.partial.cp_layout;
    let folded_eval_count = layout.folded_evaluation_values;
    if public.instance.x_folded.evaluation_values.len() != folded_eval_count {
        return None;
    }
    if folded_eval_count == 0 {
        return Some(());
    }
    if typed_beta.len() != cp_layout.ell_np
        || witness.folding_proof.gr1cs_proofs.len() < cp_layout.ell_np
    {
        return None;
    }

    let mut products =
        Vec::<i64>::with_capacity(cp_layout.ell_np * folded_eval_count * T * cp_layout.d);
    for (ell, beta) in typed_beta.iter().enumerate().take(cp_layout.ell_np) {
        let proof = witness.folding_proof.gr1cs_proofs.get(ell)?;
        for eval_idx in 0..folded_eval_count {
            for tensor_row in 0..T {
                let row_elem = RingElement {
                    coeffs: proof.hadamard_proof.evaluation_matrix[eval_idx].data[tensor_row],
                };
                let product = ring_mul_babybear(beta, &row_elem);
                for &coeff in &product.coeffs {
                    out.extend_from_slice(&coeff.to_le_bytes());
                    products.push(coeff);
                }
            }
        }
    }

    for eval_idx in 0..folded_eval_count {
        for tensor_row in 0..T {
            for coeff in 0..cp_layout.d {
                let mut sum_prod = 0i128;
                for ell in 0..cp_layout.ell_np {
                    let idx = (((ell * folded_eval_count + eval_idx) * T + tensor_row)
                        * cp_layout.d)
                        + coeff;
                    sum_prod += products[idx] as i128;
                }
                let target =
                    public.instance.x_folded.evaluation_values[eval_idx].data[tensor_row][coeff];
                let wrap = babybear_sum_wrap(target, sum_prod, q);
                out.extend_from_slice(&wrap.to_le_bytes());
            }
        }
    }
    Some(())
}

fn append_typed_beta_binding_witness(out: &mut Vec<u8>, challenge: &[u8]) -> Option<()> {
    if challenge.len() != TYPED_BETA_CHALLENGE_BYTES {
        return None;
    }
    for &byte in challenge {
        let (d0, d1, quotient) = typed_beta_base5_components(byte);
        for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
            out.extend_from_slice(&((value == d0) as i64).to_le_bytes());
        }
        for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
            out.extend_from_slice(&((value == d1) as i64).to_le_bytes());
        }
        for value in 0..TYPED_BETA_QUOTIENT_SELECTOR_VALUES {
            out.extend_from_slice(&((value == quotient) as i64).to_le_bytes());
        }
    }
    Some(())
}
