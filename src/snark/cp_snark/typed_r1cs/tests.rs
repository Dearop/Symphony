#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_core::{
        derive_challenges_with_scheme, digest_challenge_digest_with_scheme,
        digest_fold_root_with_scheme, digest_fs_root_with_scheme,
        digest_transcript_seed_with_scheme, poseidon_digest_challenge_digest,
        poseidon_digest_fold_root, poseidon_digest_fs_root, poseidon_digest_transcript_seed,
        Digest32, FoldInput, PublicDigestScheme,
    };
    use crate::folding::{FoldedOutputInstance, FoldedOutputWitness, FoldedWitness, FoldingProof};
    use crate::params::SymphonyParams;
    use crate::r1cs::R1CSMatrices;
    use crate::ring::tensor::TensorElement;
    use crate::rok::{BatchedLinearRelation, LinearRelation};

    fn first_unsatisfied_row_mod(r1cs: &R1CSMatrices, z: &[i64], q: u64) -> Option<usize> {
        let az = r1cs.a.mul_vec_mod(z, q);
        let bz = r1cs.b.mul_vec_mod(z, q);
        let cz = r1cs.c.mul_vec_mod(z, q);
        (0..r1cs.num_constraints)
            .find(|&row| centered_mod(az[row] as i128 * bz[row] as i128, q) != cz[row])
    }

    fn instance_and_witness(domain: &[u8], body: &[u8]) -> (R1CSMatrices, Vec<i64>) {
        let input = poseidon_digest_input_elems(domain, body);
        let digest = poseidon2_babybear_digest_elems(domain, &input);
        let (r1cs, layout) = generate_poseidon2_digest_r1cs(domain, input.len());
        let instance = encode_poseidon2_digest_instance(&input, &digest);
        let witness = encode_poseidon2_digest_witness(domain, &input);
        assert_eq!(layout.num_public * 8, instance.len());

        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        (r1cs, z)
    }

    fn digest_from_gadget(domain: &[u8], body: &[u8]) -> Digest32 {
        let input = poseidon_digest_input_elems(domain, body);
        serialize_poseidon_digest_elems(poseidon2_babybear_digest_elems(domain, &input))
    }

    #[test]
    fn poseidon2_software_matches_digest_helpers() {
        let commitments = vec![vec![1, 2, 3], vec![4, 5]];
        let mut fs_body = Vec::new();
        fs_body.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
        for commitment in &commitments {
            fs_body.extend_from_slice(&(commitment.len() as u64).to_le_bytes());
            fs_body.extend_from_slice(commitment);
        }
        assert_eq!(poseidon_fs_root_body(&commitments), fs_body);
        assert_eq!(
            digest_from_gadget(b"fs-root", &fs_body),
            poseidon_digest_fs_root(&commitments)
        );

        let fold_inputs = vec![FoldInput {
            commitment_bytes: vec![7, 8],
            public_input: vec![9],
            eval_values_bytes: vec![10, 11, 12],
        }];
        let mut fold_body = Vec::new();
        fold_body.extend_from_slice(&(fold_inputs.len() as u64).to_le_bytes());
        for input in &fold_inputs {
            fold_body.extend_from_slice(&(input.commitment_bytes.len() as u64).to_le_bytes());
            fold_body.extend_from_slice(&input.commitment_bytes);
            fold_body.extend_from_slice(&(input.public_input.len() as u64).to_le_bytes());
            for &value in &input.public_input {
                fold_body.extend_from_slice(&value.to_le_bytes());
            }
            fold_body.extend_from_slice(&(input.eval_values_bytes.len() as u64).to_le_bytes());
            fold_body.extend_from_slice(&input.eval_values_bytes);
        }
        assert_eq!(poseidon_fold_root_body(&fold_inputs), fold_body);
        assert_eq!(
            digest_from_gadget(b"fold-root", &fold_body),
            poseidon_digest_fold_root(&fold_inputs)
        );

        let challenges = vec![vec![13; 32], vec![14; 32]];
        let mut challenge_body = Vec::new();
        challenge_body.extend_from_slice(&(challenges.len() as u64).to_le_bytes());
        for challenge in &challenges {
            challenge_body.extend_from_slice(&(challenge.len() as u64).to_le_bytes());
            challenge_body.extend_from_slice(challenge);
        }
        assert_eq!(poseidon_challenge_digest_body(&challenges), challenge_body);
        assert_eq!(
            digest_from_gadget(b"challenge-digest", &challenge_body),
            poseidon_digest_challenge_digest(&challenges)
        );

        let public_inputs = vec![vec![3i64], vec![4i64]];
        let mut transcript_body = Vec::new();
        transcript_body.extend_from_slice(&(public_inputs.len() as u64).to_le_bytes());
        for public_input in &public_inputs {
            transcript_body.extend_from_slice(&(public_input.len() as u64).to_le_bytes());
            for &value in public_input {
                transcript_body.extend_from_slice(&value.to_le_bytes());
            }
        }
        transcript_body.extend_from_slice(&5u64.to_le_bytes());
        transcript_body.extend_from_slice(&6u64.to_le_bytes());
        transcript_body.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            poseidon_transcript_seed_body(&public_inputs, 5, 6, 1),
            transcript_body
        );
        assert_eq!(
            digest_from_gadget(b"transcript-seed", &transcript_body),
            poseidon_digest_transcript_seed(&public_inputs, 5, 6, 1)
        );
    }

    #[test]
    fn poseidon_challenge_to_beta_uses_base5_byte_mapping() {
        let mut challenge = [0u8; TYPED_BETA_CHALLENGE_BYTES];
        challenge[0] = 0;
        challenge[1] = 1;
        challenge[2] = 24;
        challenge[3] = 25;
        challenge[4] = 255;
        for (idx, byte) in challenge.iter_mut().enumerate().skip(5) {
            *byte = (idx as u8).wrapping_mul(7);
        }

        let beta = poseidon_challenge_to_beta(&challenge).unwrap();
        assert_eq!(beta.coeffs[0], -2);
        assert_eq!(beta.coeffs[1], -2);
        assert_eq!(beta.coeffs[2], -1);
        assert_eq!(beta.coeffs[3], -2);
        assert_eq!(beta.coeffs[4], 2);
        assert_eq!(beta.coeffs[5], 2);
        assert_eq!(beta.coeffs[6], -2);
        assert_eq!(beta.coeffs[7], -2);
        assert_eq!(beta.coeffs[8], -2);
        assert_eq!(beta.coeffs[9], -1);
        assert!(beta.coeffs.iter().all(|coeff| (-2..=2).contains(coeff)));
        assert!(poseidon_challenge_to_beta(&challenge[..31]).is_none());
    }

    #[test]
    fn poseidon2_digest_r1cs_accepts_honest_witness() {
        let (r1cs, z) = instance_and_witness(b"fs-commit", b"abc");
        assert!(r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn poseidon2_digest_r1cs_rejects_tampered_digest() {
        let input = poseidon_digest_input_elems(b"challenge", b"abc");
        let mut digest = poseidon2_babybear_digest_elems(b"challenge", &input);
        digest[0] += BabyBear::from_u32(1);
        let (r1cs, _layout) = generate_poseidon2_digest_r1cs(b"challenge", input.len());
        let instance = encode_poseidon2_digest_instance(&input, &digest);
        let witness = encode_poseidon2_digest_witness(b"challenge", &input);
        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        assert!(!r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn poseidon2_private_digest_r1cs_accepts_honest_witness() {
        let input = poseidon_digest_input_elems(b"fs-commit", b"private-message");
        let digest = poseidon2_babybear_digest_elems(b"fs-commit", &input);
        let (r1cs, layout) = generate_poseidon2_private_digest_r1cs(b"fs-commit", input.len());
        let instance = encode_poseidon2_private_digest_instance(&digest);
        let witness = encode_poseidon2_private_digest_witness(b"fs-commit", &input);
        assert_eq!(layout.num_public * 8, instance.len());

        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        assert_eq!(z.len(), layout.num_variables);
        assert!(r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn poseidon2_private_digest_r1cs_rejects_tampered_private_input() {
        let input = poseidon_digest_input_elems(b"fold-root", b"fold-body");
        let digest = poseidon2_babybear_digest_elems(b"fold-root", &input);
        let (r1cs, layout) = generate_poseidon2_private_digest_r1cs(b"fold-root", input.len());
        let instance = encode_poseidon2_private_digest_instance(&digest);
        let witness = encode_poseidon2_private_digest_witness(b"fold-root", &input);

        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        z[layout.off_input] += 1;
        assert!(!r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn poseidon2_private_digest_r1cs_rejects_tampered_public_digest() {
        let input = poseidon_digest_input_elems(b"challenge-digest", b"challenge-body");
        let mut digest = poseidon2_babybear_digest_elems(b"challenge-digest", &input);
        digest[0] += BabyBear::from_u32(1);
        let (r1cs, _layout) =
            generate_poseidon2_private_digest_r1cs(b"challenge-digest", input.len());
        let instance = encode_poseidon2_private_digest_instance(&digest);
        let witness = encode_poseidon2_private_digest_witness(b"challenge-digest", &input);

        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        assert!(!r1cs.is_satisfied_mod(&z, BB_P));
    }

    fn original_statement_fixture() -> (
        crate::commitment::AjtaiParams,
        R1CSMatrices,
        Vec<i64>,
        RingVector,
        crate::commitment::Commitment,
    ) {
        let q = 257;
        let mut r1cs = R1CSMatrices::new(2, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 0, 15);
        r1cs.a.insert(1, 0, 1);
        r1cs.b.insert(1, 1, 1);
        r1cs.c.insert(1, 1, 1);

        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 3,
            m: 2,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let public_input = vec![1i64];
        let witness_part = RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ]);
        let full = assemble_full_ring_witness(&public_input, &witness_part);
        let (commitment, _) = ajtai.commit(&full);
        (ajtai, r1cs, public_input, witness_part, commitment)
    }

    fn original_statement_assignment(
        ajtai: &crate::commitment::AjtaiParams,
        r1cs_src: &R1CSMatrices,
        public_input: &[i64],
        witness_part: &RingVector,
        commitment: &crate::commitment::Commitment,
    ) -> (R1CSMatrices, Vec<i64>) {
        let (r1cs, layout) = generate_original_statement_r1cs(ajtai, r1cs_src);
        let instance = encode_original_statement_instance(public_input, commitment, &layout);
        let witness = encode_original_statement_witness(
            public_input,
            witness_part,
            commitment,
            ajtai,
            r1cs_src,
            &layout,
        );
        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        (r1cs, z)
    }

    #[test]
    fn original_statement_r1cs_accepts_valid_ajtai_and_r1cs_witness() {
        let (ajtai, r1cs_src, public_input, witness_part, commitment) =
            original_statement_fixture();
        let (r1cs, z) = original_statement_assignment(
            &ajtai,
            &r1cs_src,
            &public_input,
            &witness_part,
            &commitment,
        );
        assert!(r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn original_statement_r1cs_rejects_tampered_assignment() {
        let (ajtai, r1cs_src, public_input, witness_part, commitment) =
            original_statement_fixture();
        let (r1cs, mut z) = original_statement_assignment(
            &ajtai,
            &r1cs_src,
            &public_input,
            &witness_part,
            &commitment,
        );
        z[r1cs.num_public] += 1;
        assert!(!r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_partial_r1cs_composes_cp_core_with_original_validity() {
        let q = 257;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(q);
        let mut original_r1cs = R1CSMatrices::new(1, 3, 1);
        original_r1cs.a.insert(0, 1, 1);
        original_r1cs.b.insert(0, 2, 1);
        original_r1cs.c.insert(0, 0, 15);

        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 3,
            m: 1,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let public_inputs = vec![vec![1i64]];
        let original_witnesses = vec![RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ])];
        let full = assemble_full_ring_witness(&public_inputs[0], &original_witnesses[0]);
        let (commitment, _) = ajtai.commit(&full);
        let commitments = vec![commitment.clone()];
        let beta = vec![RingElement::from_constant(1)];
        let folded_instance = FoldedInstance {
            commitment,
            public_input: vec![RingElement::from_constant(1)],
            evaluation_values: Vec::new(),
        };

        let (cp_r1cs, cp_layout) = super::super::r1cs::generate_cp_r1cs(
            1,
            params.kappa,
            params.n_in,
            original_r1cs.num_constraints,
            ext_ctx.alpha,
            q,
        );
        let (typed_r1cs, typed_layout) =
            generate_typed_cp_partial_r1cs(&cp_r1cs, &cp_layout, &ajtai, &original_r1cs);
        let instance = super::super::r1cs::encode_cp_instance_r1cs(&folded_instance, &cp_layout);
        let witness = encode_typed_cp_partial_witness(
            &commitments,
            &public_inputs,
            &beta,
            &folded_instance,
            &typed_layout,
            &params.ntt,
            &[],
            &[],
            &ext_ctx.zero(),
            &[],
            ext_ctx.alpha,
            q,
            &original_witnesses,
            &ajtai,
            &original_r1cs,
        );
        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            let arr: [u8; 8] = chunk.try_into().unwrap();
            z.push(i64::from_le_bytes(arr));
        }
        assert_eq!(z.len(), typed_layout.num_variables);
        assert!(typed_r1cs.is_satisfied_mod(&z, BB_P));

        z[typed_layout.off_original_witnesses] += 1;
        assert!(!typed_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_statement_r1cs_binds_public_inputs_to_cp_core() {
        let q = 257;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(q);
        let mut original_r1cs = R1CSMatrices::new(1, 3, 1);
        original_r1cs.a.insert(0, 1, 1);
        original_r1cs.b.insert(0, 2, 1);
        original_r1cs.c.insert(0, 0, 15);

        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 3,
            m: 1,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let public_inputs = vec![vec![1i64]];
        let original_witnesses = vec![RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ])];
        let full = assemble_full_ring_witness(&public_inputs[0], &original_witnesses[0]);
        let (commitment, _) = ajtai.commit(&full);
        let commitments = vec![commitment.clone()];
        let beta = vec![RingElement::from_constant(1)];
        let folded_instance = FoldedInstance {
            commitment,
            public_input: vec![RingElement::from_constant(1)],
            evaluation_values: Vec::new(),
        };

        let (cp_r1cs, cp_layout) = super::super::r1cs::generate_cp_r1cs(
            1,
            params.kappa,
            params.n_in,
            original_r1cs.num_constraints,
            ext_ctx.alpha,
            q,
        );
        let (typed_r1cs, typed_layout) =
            generate_typed_cp_statement_r1cs(&cp_r1cs, &cp_layout, &ajtai, &original_r1cs);
        let instance =
            encode_typed_cp_statement_instance(&folded_instance, &public_inputs, &typed_layout);
        let witness = encode_typed_cp_partial_witness(
            &commitments,
            &public_inputs,
            &beta,
            &folded_instance,
            &typed_layout.partial,
            &params.ntt,
            &[],
            &[],
            &ext_ctx.zero(),
            &[],
            ext_ctx.alpha,
            q,
            &original_witnesses,
            &ajtai,
            &original_r1cs,
        );
        let mut z = Vec::new();
        for chunk in instance.chunks_exact(8).chain(witness.chunks_exact(8)) {
            z.push(i64::from_le_bytes(chunk.try_into().unwrap()));
        }
        assert_eq!(z.len(), typed_layout.num_variables);
        assert!(typed_r1cs.is_satisfied_mod(&z, BB_P));

        let public_input_col = typed_layout.off_public_inputs;
        z[public_input_col] += 1;
        assert!(!typed_r1cs.is_satisfied_mod(&z, BB_P));
    }

    struct TypedCpDigestFixture {
        params: SymphonyParams,
        ajtai: crate::commitment::AjtaiParams,
        original_r1cs: R1CSMatrices,
        digest_r1cs: R1CSMatrices,
        layout: TypedCpDigestR1csLayout,
        audit: TypedCpAuditReport,
        public: crate::cp_relation_core::CpPublicStatement,
        witness: crate::cp_relation_core::CpWitnessBundle,
        z: Vec<i64>,
    }

    fn bytes_to_i64_vec(instance: &[u8], witness: &[u8]) -> Vec<i64> {
        instance
            .chunks_exact(8)
            .chain(witness.chunks_exact(8))
            .map(|chunk| i64::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    fn audit_row_counts_by_kind(
        report: &TypedCpAuditReport,
    ) -> Vec<(TypedCpAuditBlockKind, usize)> {
        [
            TypedCpAuditBlockKind::CpFoldingCore,
            TypedCpAuditBlockKind::ByteConstraints,
            TypedCpAuditBlockKind::PoseidonDigestGadgets,
            TypedCpAuditBlockKind::Gr1csMessageReconstruction,
            TypedCpAuditBlockKind::RangeMonomialSemantics,
            TypedCpAuditBlockKind::ChallengeToBetaBinding,
            TypedCpAuditBlockKind::FoldedOutputDerivation,
            TypedCpAuditBlockKind::AjtaiOpeningChecks,
            TypedCpAuditBlockKind::OriginalR1csValidity,
            TypedCpAuditBlockKind::PublicInputBinding,
        ]
        .into_iter()
        .map(|kind| (kind, report.row_count_by_kind(kind)))
        .collect()
    }

    fn assert_audit_mutation_hits(
        fixture: &TypedCpDigestFixture,
        label: &str,
        mutate: impl FnOnce(&mut Vec<i64>),
        expected: TypedCpAuditBlockKind,
    ) {
        let mut z = fixture.z.clone();
        mutate(&mut z);
        assert!(
            !fixture.digest_r1cs.is_satisfied_mod(&z, BB_P),
            "{label} should make typed CP R1CS unsatisfied"
        );
        let blocks = fixture
            .audit
            .unsatisfied_blocks(&fixture.digest_r1cs, &z, BB_P);
        assert!(
            blocks.iter().any(|block| block.kind == expected),
            "{label} should hit {expected:?}, got {blocks:?}"
        );
    }

    fn assert_software_and_r1cs_reject(
        fixture: &TypedCpDigestFixture,
        label: &str,
        mutate_bundle: impl FnOnce(
            &mut crate::cp_relation_core::CpPublicStatement,
            &mut crate::cp_relation_core::CpWitnessBundle,
        ),
    ) {
        let mut public = fixture.public.clone();
        let mut witness = fixture.witness.clone();
        mutate_bundle(&mut public, &mut witness);
        assert!(
            crate::cp_relation_core::CpFieldRelation::check(
                &public,
                &witness,
                &fixture.ajtai,
                &fixture.original_r1cs,
                fixture.params.b_input(),
            )
            .is_err(),
            "{label} should be rejected by CpFieldRelation"
        );
        let Some(instance) =
            encode_typed_cp_digest_instance(&public, &witness.fs_commitments, &fixture.layout)
        else {
            return;
        };
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(fixture.params.q);
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let witness_bytes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            encode_typed_cp_digest_witness(
                &public,
                &witness,
                &fixture.layout,
                &fixture.params.ntt,
                ext_ctx.alpha,
                fixture.params.q,
                &fixture.ajtai,
                &fixture.original_r1cs,
            )
        }));
        std::panic::set_hook(previous_hook);
        let Ok(Some(witness_bytes)) = witness_bytes else {
            return;
        };
        let z = bytes_to_i64_vec(&instance, &witness_bytes);
        assert!(
            !fixture.digest_r1cs.is_satisfied_mod(&z, BB_P),
            "{label} should be rejected by typed CP R1CS"
        );
    }

    fn partial_col_in_digest_r1cs(
        statement: &TypedCpStatementR1csLayout,
        digest_public_shift: usize,
        partial_col: usize,
    ) -> usize {
        let statement_col = if partial_col < statement.partial.num_public {
            partial_col
        } else {
            partial_col + statement.added_public_inputs
        };
        if statement_col < statement.num_public {
            statement_col
        } else {
            statement_col + digest_public_shift
        }
    }

    fn single_beta_folded_instance(
        commitment: &crate::commitment::Commitment,
        public_input: &[i64],
        beta: &RingElement,
        q: u64,
    ) -> FoldedInstance {
        FoldedInstance {
            commitment: crate::commitment::Commitment {
                value: RingVector::from(
                    commitment
                        .value
                        .elements
                        .iter()
                        .map(|elem| beta.mul(elem, q))
                        .collect::<Vec<_>>(),
                ),
            },
            public_input: public_input
                .iter()
                .map(|&value| beta.mul(&RingElement::from_constant(value), q))
                .collect(),
            evaluation_values: Vec::new(),
        }
    }

    fn zero_gr1cs_hadamard_message(cp_layout: &CpR1csLayout) -> Vec<u8> {
        let mut msg = Vec::with_capacity(gr1cs_hadamard_message_prefix_len(cp_layout));
        msg.extend_from_slice(&(cp_layout.had_num_vars as u64).to_le_bytes());
        for _ in 0..cp_layout.had_num_vars {
            msg.extend_from_slice(&4u64.to_le_bytes());
            for _ in 0..4 {
                msg.extend_from_slice(&0i64.to_le_bytes());
                msg.extend_from_slice(&0i64.to_le_bytes());
            }
        }
        for _ in 0..3 {
            for _ in 0..2 {
                for _ in 0..cp_layout.d {
                    msg.extend_from_slice(&0i64.to_le_bytes());
                }
            }
        }
        msg
    }

    fn synthetic_gr1cs_proof_with_range_shape(
        commitment: &crate::commitment::Commitment,
        ext_ctx: &crate::ring::extension::ExtFieldContext,
    ) -> GR1CSProof {
        let monomial_vectors = vec![vec![
            RingElement::zero(),
            crate::decomposition::monomial::exp_map(1),
            crate::decomposition::monomial::exp_map(-1),
        ]];
        let mon_ajtai = crate::commitment::AjtaiParams::setup_deterministic(
            commitment.value.elements.len(),
            monomial_vectors[0].len(),
            ext_ctx.q,
            &crate::ring::ntt::NttContext::new(ext_ctx.q),
            b"range-proof-monomial",
        );
        let (monomial_commitment, _) =
            mon_ajtai.commit(&RingVector::from(monomial_vectors[0].clone()));
        let monomial_challenges = synthetic_monomial_challenges();
        let monomial_proof = crate::rok::monomial::prove(
            &[monomial_commitment.clone()],
            &monomial_vectors,
            &monomial_challenges,
            ext_ctx,
        );
        GR1CSProof {
            hadamard_proof: crate::rok::hadamard::HadamardProof {
                sumcheck_proof: crate::sumcheck::SumcheckProof {
                    round_messages: Vec::new(),
                },
                evaluation_matrix: [
                    TensorElement::zero(),
                    TensorElement::zero(),
                    TensorElement::zero(),
                ],
            },
            range_proof: crate::rok::range_proof::RangeProof {
                monomial_commitments: vec![monomial_commitment],
                monomial_vectors,
                monomial_proof,
                projected_values: vec![0, 1, -1],
            },
        }
    }

    fn synthetic_monomial_challenges() -> crate::rok::monomial::MonomialChallenges {
        crate::rok::monomial::MonomialChallenges {
            s: vec![
                ExtFieldElement { c0: 2, c1: 1 },
                ExtFieldElement { c0: 3, c1: 2 },
            ],
            alpha: ExtFieldElement { c0: 5, c1: 3 },
            sumcheck_challenges: vec![
                ExtFieldElement { c0: 7, c1: 4 },
                ExtFieldElement { c0: 11, c1: 6 },
            ],
        }
    }

    fn typed_cp_digest_fixture() -> TypedCpDigestFixture {
        let q = 257;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(q);
        let mut original_r1cs = R1CSMatrices::new(1, 3, 1);
        original_r1cs.a.insert(0, 1, 1);
        original_r1cs.b.insert(0, 2, 1);
        original_r1cs.c.insert(0, 0, 15);

        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 3,
            m: 1,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let public_inputs = vec![vec![1i64]];
        let original_witnesses = vec![RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ])];
        let full = assemble_full_ring_witness(&public_inputs[0], &original_witnesses[0]);
        let (commitment, _) = ajtai.commit(&full);
        let linear_relation = LinearRelation {
            commitment: commitment.clone(),
            evaluation_point: Vec::new(),
            evaluation_values: [
                TensorElement::zero(),
                TensorElement::zero(),
                TensorElement::zero(),
            ],
        };
        let batched_relation = BatchedLinearRelation {
            commitments: Vec::new(),
            evaluation_point: Vec::new(),
            evaluation_values: Vec::new(),
        };
        let fs_messages = vec![b"typed-cp-message-0".to_vec()];
        let opening = [7u8; 32];
        let fs_commitment = poseidon2_digest32_from_body(
            b"fs-commit",
            &poseidon_fs_commit_body(&fs_messages[0], &opening),
        );
        let fs_commitments = vec![fs_commitment.to_vec()];
        let commitment_bytes = crate::snark::cp_snark::encode_commitment_to_bytes(&commitment);
        let fold_inputs = vec![FoldInput {
            commitment_bytes,
            public_input: public_inputs[0].clone(),
            eval_values_bytes: fs_messages[0].clone(),
        }];
        let challenges = derive_challenges_with_scheme(
            PublicDigestScheme::Poseidon2BabyBear,
            &public_inputs,
            original_r1cs.num_constraints,
            original_r1cs.num_variables,
            original_r1cs.num_public,
            &fs_commitments,
        );
        let typed_beta = poseidon_challenges_to_betas(&challenges).unwrap();
        let folded_instance =
            single_beta_folded_instance(&commitment, &public_inputs[0], &typed_beta[0], q);
        let folded_output_instance = FoldedOutputInstance {
            folded_instance: folded_instance.clone(),
            linear_relation: linear_relation.clone(),
            batched_relation: batched_relation.clone(),
        };
        let folded_witness = FoldedWitness {
            witness: original_witnesses[0].clone(),
            monomial_vectors: Vec::new(),
        };
        let folded_output_witness = FoldedOutputWitness {
            folded_witness: folded_witness.clone(),
        };
        let cp_public_instance = crate::cp_relation_core::CpPublicInstance {
            fs_root: digest_fs_root_with_scheme(
                PublicDigestScheme::Poseidon2BabyBear,
                &fs_commitments,
            ),
            fold_root: digest_fold_root_with_scheme(
                PublicDigestScheme::Poseidon2BabyBear,
                &fold_inputs,
            ),
            challenge_digest: digest_challenge_digest_with_scheme(
                PublicDigestScheme::Poseidon2BabyBear,
                &challenges,
            ),
            transcript_seed_digest: digest_transcript_seed_with_scheme(
                PublicDigestScheme::Poseidon2BabyBear,
                &public_inputs,
                original_r1cs.num_constraints,
                original_r1cs.num_variables,
                original_r1cs.num_public,
            ),
            x_folded: folded_instance.clone(),
            folded_output: folded_output_instance.clone(),
        };
        let public = crate::cp_relation_core::CpPublicStatement::new(
            cp_public_instance,
            public_inputs.clone(),
            &original_r1cs,
            PublicDigestScheme::Poseidon2BabyBear,
        );
        let folding_proof = FoldingProof {
            commitments: vec![commitment],
            gr1cs_proofs: Vec::new(),
            beta: typed_beta,
            folded_instance: folded_instance.clone(),
            linear_relation,
            batched_relation,
        };
        let witness = crate::cp_relation_core::CpWitnessBundle {
            transcript_bytes: Vec::new(),
            fs_commitments,
            fs_openings: vec![opening.to_vec()],
            fs_messages,
            fold_inputs,
            original_witnesses,
            folded_output: folded_instance,
            folded_output_instance,
            folded_output_witness,
            folded_witness,
            folding_proof,
            shared_challenges: crate::cp_relation_core::CpSharedChallengeData {
                sumcheck_seed_had: Vec::new(),
                alpha: ext_ctx.zero(),
                hadamard_sumcheck_challenges: Vec::new(),
                sumcheck_seed_mon: vec![ext_ctx.zero()],
                monomial_sumcheck_challenges: vec![ext_ctx.zero()],
            },
        };

        let (cp_r1cs, cp_layout) = super::super::r1cs::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            original_r1cs.num_constraints,
            ext_ctx.alpha,
            q,
        );
        let lengths = typed_cp_digest_input_lengths(&public, &witness).unwrap();
        let (digest_r1cs, layout, audit) = generate_typed_cp_digest_r1cs_with_audit(
            &cp_r1cs,
            &cp_layout,
            &ajtai,
            &original_r1cs,
            &lengths,
        );
        let instance =
            encode_typed_cp_digest_instance(&public, &witness.fs_commitments, &layout).unwrap();
        let witness_bytes = encode_typed_cp_digest_witness(
            &public,
            &witness,
            &layout,
            &params.ntt,
            ext_ctx.alpha,
            q,
            &ajtai,
            &original_r1cs,
        )
        .unwrap();
        let z = bytes_to_i64_vec(&instance, &witness_bytes);
        TypedCpDigestFixture {
            params,
            ajtai,
            original_r1cs,
            digest_r1cs,
            layout,
            audit,
            public,
            witness,
            z,
        }
    }

    fn typed_cp_digest_range_shape_fixture() -> TypedCpDigestFixture {
        let q = 257;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(q);
        let mut original_r1cs = R1CSMatrices::new(1, 3, 1);
        original_r1cs.a.insert(0, 1, 1);
        original_r1cs.b.insert(0, 2, 1);
        original_r1cs.c.insert(0, 0, 15);

        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 3,
            m: 1,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let public_inputs = vec![vec![1i64]];
        let original_witnesses = vec![RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ])];
        let full = assemble_full_ring_witness(&public_inputs[0], &original_witnesses[0]);
        let (commitment, _) = ajtai.commit(&full);
        let gr1cs_proof = synthetic_gr1cs_proof_with_range_shape(&commitment, &ext_ctx);
        let gr1cs_message = crate::snark::cp_snark::encode_gr1cs_round_message(&gr1cs_proof);
        let opening = [11u8; 32];
        let fs_commitment = poseidon2_digest32_from_body(
            b"fs-commit",
            &poseidon_fs_commit_body(&gr1cs_message, &opening),
        );
        let fs_commitments = vec![fs_commitment.to_vec()];
        let fold_inputs = vec![FoldInput {
            commitment_bytes: crate::snark::cp_snark::encode_commitment_to_bytes(&commitment),
            public_input: public_inputs[0].clone(),
            eval_values_bytes: gr1cs_message.clone(),
        }];
        let scheme = PublicDigestScheme::Poseidon2BabyBear;
        let challenges = derive_challenges_with_scheme(
            scheme,
            &public_inputs,
            original_r1cs.num_constraints,
            original_r1cs.num_variables,
            original_r1cs.num_public,
            &fs_commitments,
        );
        let typed_beta = poseidon_challenges_to_betas(&challenges).unwrap();
        let mut folded_instance =
            single_beta_folded_instance(&commitment, &public_inputs[0], &typed_beta[0], q);
        folded_instance.evaluation_values = vec![
            TensorElement::zero(),
            TensorElement::zero(),
            TensorElement::zero(),
        ];
        let linear_relation = LinearRelation {
            commitment: commitment.clone(),
            evaluation_point: Vec::new(),
            evaluation_values: [
                TensorElement::zero(),
                TensorElement::zero(),
                TensorElement::zero(),
            ],
        };
        let batched_relation = BatchedLinearRelation {
            commitments: Vec::new(),
            evaluation_point: Vec::new(),
            evaluation_values: Vec::new(),
        };
        let folded_output_instance = FoldedOutputInstance {
            folded_instance: folded_instance.clone(),
            linear_relation: linear_relation.clone(),
            batched_relation: batched_relation.clone(),
        };
        let cp_public_instance = crate::cp_relation_core::CpPublicInstance {
            fs_root: digest_fs_root_with_scheme(scheme, &fs_commitments),
            fold_root: digest_fold_root_with_scheme(scheme, &fold_inputs),
            challenge_digest: digest_challenge_digest_with_scheme(scheme, &challenges),
            transcript_seed_digest: digest_transcript_seed_with_scheme(
                scheme,
                &public_inputs,
                original_r1cs.num_constraints,
                original_r1cs.num_variables,
                original_r1cs.num_public,
            ),
            x_folded: folded_instance.clone(),
            folded_output: folded_output_instance.clone(),
        };
        let public = crate::cp_relation_core::CpPublicStatement::new(
            cp_public_instance,
            public_inputs.clone(),
            &original_r1cs,
            scheme,
        );
        let folded_witness = FoldedWitness {
            witness: original_witnesses[0].clone(),
            monomial_vectors: Vec::new(),
        };
        let witness = crate::cp_relation_core::CpWitnessBundle {
            transcript_bytes: Vec::new(),
            fs_commitments,
            fs_openings: vec![opening.to_vec()],
            fs_messages: vec![gr1cs_message],
            fold_inputs,
            original_witnesses,
            folded_output: folded_instance.clone(),
            folded_output_instance: folded_output_instance.clone(),
            folded_output_witness: FoldedOutputWitness {
                folded_witness: folded_witness.clone(),
            },
            folded_witness,
            folding_proof: FoldingProof {
                commitments: vec![commitment],
                gr1cs_proofs: vec![gr1cs_proof],
                beta: typed_beta,
                folded_instance,
                linear_relation,
                batched_relation,
            },
            shared_challenges: crate::cp_relation_core::CpSharedChallengeData {
                sumcheck_seed_had: Vec::new(),
                alpha: synthetic_monomial_challenges().alpha,
                hadamard_sumcheck_challenges: Vec::new(),
                sumcheck_seed_mon: synthetic_monomial_challenges().s,
                monomial_sumcheck_challenges: synthetic_monomial_challenges().sumcheck_challenges,
            },
        };

        let (cp_r1cs, cp_layout) = super::super::r1cs::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            original_r1cs.num_constraints,
            ext_ctx.alpha,
            q,
        );
        let lengths = typed_cp_digest_input_lengths(&public, &witness).unwrap();
        assert!(lengths.gr1cs_message_shapes[0].range.is_some());
        let (digest_r1cs, layout, audit) = generate_typed_cp_digest_r1cs_with_audit(
            &cp_r1cs,
            &cp_layout,
            &ajtai,
            &original_r1cs,
            &lengths,
        );
        let instance =
            encode_typed_cp_digest_instance(&public, &witness.fs_commitments, &layout).unwrap();
        let witness_bytes = encode_typed_cp_digest_witness(
            &public,
            &witness,
            &layout,
            &params.ntt,
            ext_ctx.alpha,
            q,
            &ajtai,
            &original_r1cs,
        )
        .unwrap();
        let z = bytes_to_i64_vec(&instance, &witness_bytes);
        TypedCpDigestFixture {
            params,
            ajtai,
            original_r1cs,
            digest_r1cs,
            layout,
            audit,
            public,
            witness,
            z,
        }
    }

    fn typed_cp_digest_gr1cs_fixture() -> TypedCpDigestFixture {
        let q = 257;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(q);
        let mut original_r1cs = R1CSMatrices::new(2, 3, 1);
        original_r1cs.a.insert(0, 1, 1);
        original_r1cs.b.insert(0, 2, 1);
        original_r1cs.c.insert(0, 0, 15);
        original_r1cs.a.insert(1, 0, 1);
        original_r1cs.b.insert(1, 1, 1);
        original_r1cs.c.insert(1, 1, 1);

        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 3,
            m: 2,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let (cp_r1cs, cp_layout) = super::super::r1cs::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            original_r1cs.num_constraints,
            ext_ctx.alpha,
            q,
        );
        let public_inputs = vec![vec![1i64]];
        let original_witnesses = vec![RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ])];
        let full = assemble_full_ring_witness(&public_inputs[0], &original_witnesses[0]);
        let (commitment, _) = ajtai.commit(&full);
        let gr1cs_message = zero_gr1cs_hadamard_message(&cp_layout);
        let opening = [9u8; 32];
        let fs_commitment = poseidon2_digest32_from_body(
            b"fs-commit",
            &poseidon_fs_commit_body(&gr1cs_message, &opening),
        );
        let fs_commitments = vec![fs_commitment.to_vec()];
        let fold_inputs = vec![FoldInput {
            commitment_bytes: crate::snark::cp_snark::encode_commitment_to_bytes(&commitment),
            public_input: public_inputs[0].clone(),
            eval_values_bytes: gr1cs_message.clone(),
        }];
        let scheme = PublicDigestScheme::Poseidon2BabyBear;
        let challenges = derive_challenges_with_scheme(
            scheme,
            &public_inputs,
            original_r1cs.num_constraints,
            original_r1cs.num_variables,
            original_r1cs.num_public,
            &fs_commitments,
        );
        let typed_beta = poseidon_challenges_to_betas(&challenges).unwrap();
        let folded_instance =
            single_beta_folded_instance(&commitment, &public_inputs[0], &typed_beta[0], q);
        let linear_relation = LinearRelation {
            commitment: commitment.clone(),
            evaluation_point: Vec::new(),
            evaluation_values: [
                TensorElement::zero(),
                TensorElement::zero(),
                TensorElement::zero(),
            ],
        };
        let batched_relation = BatchedLinearRelation {
            commitments: Vec::new(),
            evaluation_point: Vec::new(),
            evaluation_values: Vec::new(),
        };
        let folded_output_instance = FoldedOutputInstance {
            folded_instance: folded_instance.clone(),
            linear_relation: linear_relation.clone(),
            batched_relation: batched_relation.clone(),
        };
        let cp_public_instance = crate::cp_relation_core::CpPublicInstance {
            fs_root: digest_fs_root_with_scheme(scheme, &fs_commitments),
            fold_root: digest_fold_root_with_scheme(scheme, &fold_inputs),
            challenge_digest: digest_challenge_digest_with_scheme(scheme, &challenges),
            transcript_seed_digest: digest_transcript_seed_with_scheme(
                scheme,
                &public_inputs,
                original_r1cs.num_constraints,
                original_r1cs.num_variables,
                original_r1cs.num_public,
            ),
            x_folded: folded_instance.clone(),
            folded_output: folded_output_instance.clone(),
        };
        let public = crate::cp_relation_core::CpPublicStatement::new(
            cp_public_instance,
            public_inputs.clone(),
            &original_r1cs,
            scheme,
        );
        let folded_witness = FoldedWitness {
            witness: original_witnesses[0].clone(),
            monomial_vectors: Vec::new(),
        };
        let witness = crate::cp_relation_core::CpWitnessBundle {
            transcript_bytes: Vec::new(),
            fs_commitments,
            fs_openings: vec![opening.to_vec()],
            fs_messages: vec![gr1cs_message],
            fold_inputs,
            original_witnesses,
            folded_output: folded_instance.clone(),
            folded_output_instance: folded_output_instance.clone(),
            folded_output_witness: FoldedOutputWitness {
                folded_witness: folded_witness.clone(),
            },
            folded_witness,
            folding_proof: FoldingProof {
                commitments: vec![commitment],
                gr1cs_proofs: Vec::new(),
                beta: typed_beta,
                folded_instance,
                linear_relation,
                batched_relation,
            },
            shared_challenges: crate::cp_relation_core::CpSharedChallengeData {
                sumcheck_seed_had: Vec::new(),
                alpha: ext_ctx.zero(),
                hadamard_sumcheck_challenges: Vec::new(),
                sumcheck_seed_mon: Vec::new(),
                monomial_sumcheck_challenges: Vec::new(),
            },
        };
        let lengths = typed_cp_digest_input_lengths(&public, &witness).unwrap();
        assert!(cp_layout.had_num_vars > 0);
        assert!(lengths.gr1cs_message_bodies[0] >= gr1cs_hadamard_message_prefix_len(&cp_layout));
        let (digest_r1cs, layout, audit) = generate_typed_cp_digest_r1cs_with_audit(
            &cp_r1cs,
            &cp_layout,
            &ajtai,
            &original_r1cs,
            &lengths,
        );
        let instance =
            encode_typed_cp_digest_instance(&public, &witness.fs_commitments, &layout).unwrap();
        let witness_bytes = encode_typed_cp_digest_witness(
            &public,
            &witness,
            &layout,
            &params.ntt,
            ext_ctx.alpha,
            q,
            &ajtai,
            &original_r1cs,
        )
        .unwrap();
        let z = bytes_to_i64_vec(&instance, &witness_bytes);
        TypedCpDigestFixture {
            params,
            ajtai,
            original_r1cs,
            digest_r1cs,
            layout,
            audit,
            public,
            witness,
            z,
        }
    }

    #[test]
    fn typed_cp_audit_report_structure_and_snapshot() {
        let fixture = typed_cp_digest_range_shape_fixture();
        fixture
            .audit
            .validate_against(&fixture.digest_r1cs)
            .expect("audit report must match generated R1CS");
        assert_eq!(fixture.audit.num_public, fixture.digest_r1cs.num_public);
        assert_eq!(
            fixture.audit.num_variables,
            fixture.digest_r1cs.num_variables
        );
        assert_eq!(
            fixture.audit.num_constraints,
            fixture.digest_r1cs.num_constraints
        );
        assert_eq!(
            fixture.audit.blocks.first().map(|block| block.start_row),
            Some(0)
        );
        assert_eq!(
            fixture
                .audit
                .blocks
                .last()
                .map(|block| block.start_row + block.row_count),
            Some(fixture.digest_r1cs.num_constraints)
        );
        for kind in [
            TypedCpAuditBlockKind::CpFoldingCore,
            TypedCpAuditBlockKind::ByteConstraints,
            TypedCpAuditBlockKind::PoseidonDigestGadgets,
            TypedCpAuditBlockKind::Gr1csMessageReconstruction,
            TypedCpAuditBlockKind::RangeMonomialSemantics,
            TypedCpAuditBlockKind::ChallengeToBetaBinding,
            TypedCpAuditBlockKind::FoldedOutputDerivation,
            TypedCpAuditBlockKind::AjtaiOpeningChecks,
            TypedCpAuditBlockKind::OriginalR1csValidity,
            TypedCpAuditBlockKind::PublicInputBinding,
        ] {
            assert!(
                fixture.audit.row_count_by_kind(kind) > 0,
                "{kind:?} must have at least one row"
            );
        }

        let snapshot = audit_row_counts_by_kind(&fixture.audit);
        assert_eq!(
            snapshot,
            vec![
                (TypedCpAuditBlockKind::CpFoldingCore, 11_520),
                (TypedCpAuditBlockKind::ByteConstraints, 138_742),
                (TypedCpAuditBlockKind::PoseidonDigestGadgets, 368_340),
                (TypedCpAuditBlockKind::Gr1csMessageReconstruction, 7_889),
                (TypedCpAuditBlockKind::RangeMonomialSemantics, 2_704),
                (TypedCpAuditBlockKind::ChallengeToBetaBinding, 872),
                (TypedCpAuditBlockKind::FoldedOutputDerivation, 896),
                (TypedCpAuditBlockKind::AjtaiOpeningChecks, 128),
                (TypedCpAuditBlockKind::OriginalR1csValidity, 64),
                (TypedCpAuditBlockKind::PublicInputBinding, 99),
            ]
        );
    }

    #[test]
    fn typed_cp_audit_report_classifies_leaf_and_accumulator_rows() {
        let fixture = typed_cp_digest_range_shape_fixture();
        let split_rows = fixture.audit.split_row_counts();
        let total_split_rows: usize = split_rows.iter().map(|(_, rows)| *rows).sum();
        assert_eq!(total_split_rows, fixture.audit.num_constraints);
        for component in [
            TypedCpSplitComponent::Leaf,
            TypedCpSplitComponent::Accumulator,
            TypedCpSplitComponent::LeafAccumulatorBinding,
        ] {
            assert!(
                fixture.audit.row_count_by_split_component(component) > 0,
                "{component:?} must have at least one row"
            );
        }
        for block in &fixture.audit.blocks {
            assert!(
                split_rows
                    .iter()
                    .any(|(component, _)| *component == block.split_component()),
                "audit block '{}' must be assigned to a split component",
                block.label
            );
        }
    }

    #[test]
    fn typed_cp_audit_report_isolates_targeted_mutation_blocks() {
        let fixture = typed_cp_digest_range_shape_fixture();
        let cp_layout = &fixture.layout.statement.partial.cp_layout;
        let digest_public_shift = fixture.layout.added_digest_public;
        let payload = fixture.layout.range_payload_blocks[0]
            .as_ref()
            .expect("range proof payload block");

        assert_audit_mutation_hits(
            &fixture,
            "CP folding core beta mutation",
            |z| {
                let beta_col = cp_col_in_digest_r1cs(
                    &fixture.layout.statement,
                    digest_public_shift,
                    cp_layout.beta(0, 0),
                );
                z[beta_col] += 1;
            },
            TypedCpAuditBlockKind::CpFoldingCore,
        );
        assert_audit_mutation_hits(
            &fixture,
            "byte range mutation",
            |z| z[fixture.layout.fs_commitment_blocks[0].off_body_bits] = 2,
            TypedCpAuditBlockKind::ByteConstraints,
        );
        assert_audit_mutation_hits(
            &fixture,
            "Poseidon witness mutation",
            |z| z[fixture.layout.fs_commitment_blocks[0].off_private_witness] += 1,
            TypedCpAuditBlockKind::PoseidonDigestGadgets,
        );
        assert_audit_mutation_hits(
            &fixture,
            "GR1CS message mutation",
            |z| {
                let fs_msg = fs_commit_message_body_offset(&fixture.layout.fs_commitment_blocks[0]);
                z[fixture.layout.fs_commitment_blocks[0].off_body_bytes + fs_msg] += 1;
            },
            TypedCpAuditBlockKind::Gr1csMessageReconstruction,
        );
        assert_audit_mutation_hits(
            &fixture,
            "range monomial semantic mutation",
            |z| z[payload.off_monomial_sumcheck_seed] += 1,
            TypedCpAuditBlockKind::RangeMonomialSemantics,
        );
        assert_audit_mutation_hits(
            &fixture,
            "challenge-to-beta mutation",
            |z| z[fixture.layout.off_beta_binding_selectors] += 1,
            TypedCpAuditBlockKind::ChallengeToBetaBinding,
        );
        assert_audit_mutation_hits(
            &fixture,
            "folded output derivation mutation",
            |z| z[fixture.layout.off_folded_eval_products] += 1,
            TypedCpAuditBlockKind::FoldedOutputDerivation,
        );
        assert_audit_mutation_hits(
            &fixture,
            "Ajtai opening mutation",
            |z| {
                let col = partial_col_in_digest_r1cs(
                    &fixture.layout.statement,
                    digest_public_shift,
                    fixture.layout.statement.partial.off_original_ajtai_wraps,
                );
                z[col] += 1;
            },
            TypedCpAuditBlockKind::AjtaiOpeningChecks,
        );
        assert_audit_mutation_hits(
            &fixture,
            "original R1CS mutation",
            |z| {
                let col = partial_col_in_digest_r1cs(
                    &fixture.layout.statement,
                    digest_public_shift,
                    fixture.layout.statement.partial.off_original_r1cs_wraps,
                );
                z[col] += 1;
            },
            TypedCpAuditBlockKind::OriginalR1csValidity,
        );
        assert_audit_mutation_hits(
            &fixture,
            "public input binding mutation",
            |z| z[fixture.layout.statement.off_public_inputs] += 1,
            TypedCpAuditBlockKind::PublicInputBinding,
        );
    }

    #[test]
    fn typed_cp_audit_software_checker_matches_r1cs_mutation_corpus() {
        let fixture = typed_cp_digest_range_shape_fixture();
        assert!(crate::cp_relation_core::CpFieldRelation::check(
            &fixture.public,
            &fixture.witness,
            &fixture.ajtai,
            &fixture.original_r1cs,
            fixture.params.b_input(),
        )
        .is_ok());
        assert!(fixture.digest_r1cs.is_satisfied_mod(&fixture.z, BB_P));

        assert_software_and_r1cs_reject(&fixture, "bad FS opening", |_public, witness| {
            witness.fs_openings[0][0] ^= 1;
        });
        assert_software_and_r1cs_reject(&fixture, "bad FS message", |_public, witness| {
            witness.fs_messages[0][0] ^= 1;
        });
        assert_software_and_r1cs_reject(&fixture, "wrong fold root", |public, _witness| {
            public.instance.fold_root[0] ^= 1;
        });
        assert_software_and_r1cs_reject(&fixture, "wrong challenge digest", |public, _witness| {
            public.instance.challenge_digest[0] ^= 1;
        });
        assert_software_and_r1cs_reject(&fixture, "public input replay", |public, _witness| {
            public.public_inputs[0][0] += 1;
        });
        assert_software_and_r1cs_reject(&fixture, "folded output mismatch", |public, _witness| {
            public.instance.folded_output.folded_instance.public_input[0].coeffs[0] += 1;
        });
        assert_software_and_r1cs_reject(&fixture, "bad Ajtai opening", |_public, witness| {
            witness.folding_proof.commitments[0].value.elements[0].coeffs[0] += 1;
        });
        assert_software_and_r1cs_reject(
            &fixture,
            "invalid original R1CS assignment",
            |public, witness| {
                witness.original_witnesses[0].elements[1] = RingElement::from_constant(6);
                let full = assemble_full_ring_witness(
                    &public.public_inputs[0],
                    &witness.original_witnesses[0],
                );
                let (commitment, _) = fixture.ajtai.commit(&full);
                witness.folding_proof.commitments[0] = commitment;
            },
        );
    }

    #[test]
    fn typed_cp_digest_r1cs_accepts_honest_witness() {
        let fixture = typed_cp_digest_fixture();
        assert_eq!(fixture.z.len(), fixture.layout.num_variables);
        if let Some(row) = first_unsatisfied_row_mod(&fixture.digest_r1cs, &fixture.z, BB_P) {
            let az = fixture.digest_r1cs.a.mul_vec_mod(&fixture.z, BB_P);
            let bz = fixture.digest_r1cs.b.mul_vec_mod(&fixture.z, BB_P);
            let cz = fixture.digest_r1cs.c.mul_vec_mod(&fixture.z, BB_P);
            panic!(
                "first unsatisfied row: {row}, az={}, bz={}, cz={}",
                az[row], bz[row], cz[row]
            );
        }
    }

    #[test]
    fn typed_cp_digest_compressed_fs_r1cs_accepts_private_fs_commitments() {
        let fixture = typed_cp_digest_fixture();
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(fixture.params.q);
        let (cp_r1cs, cp_layout) = super::super::r1cs::generate_cp_r1cs(
            fixture.params.ell_np,
            fixture.params.kappa,
            fixture.params.n_in,
            fixture.original_r1cs.num_constraints,
            ext_ctx.alpha,
            fixture.params.q,
        );
        let lengths = typed_cp_digest_input_lengths(&fixture.public, &fixture.witness).unwrap();
        let (compressed_r1cs, compressed_layout, audit) =
            generate_typed_cp_digest_r1cs_compressed_fs_with_audit(
                &cp_r1cs,
                &cp_layout,
                &fixture.ajtai,
                &fixture.original_r1cs,
                &lengths,
            );
        assert!(!compressed_layout.fs_commitments_are_public);
        assert_eq!(
            compressed_layout.num_public + compressed_layout.fs_commitment_blocks.len() * OUT,
            fixture.layout.num_public
        );
        assert!(
            compressed_layout.fs_commitment_blocks[0].off_public_output
                >= compressed_layout.num_public
        );
        assert!(encode_typed_cp_digest_instance(
            &fixture.public,
            &fixture.witness.fs_commitments,
            &compressed_layout,
        )
        .is_none());

        let instance =
            encode_typed_cp_digest_instance(&fixture.public, &[], &compressed_layout).unwrap();
        let witness_bytes = encode_typed_cp_digest_witness(
            &fixture.public,
            &fixture.witness,
            &compressed_layout,
            &fixture.params.ntt,
            ext_ctx.alpha,
            fixture.params.q,
            &fixture.ajtai,
            &fixture.original_r1cs,
        )
        .unwrap();
        let mut z = bytes_to_i64_vec(&instance, &witness_bytes);
        assert_eq!(z.len(), compressed_layout.num_variables);
        if let Some(row) = first_unsatisfied_row_mod(&compressed_r1cs, &z, BB_P) {
            let az = compressed_r1cs.a.mul_vec_mod(&z, BB_P);
            let bz = compressed_r1cs.b.mul_vec_mod(&z, BB_P);
            let cz = compressed_r1cs.c.mul_vec_mod(&z, BB_P);
            panic!(
                "first compressed FS unsatisfied row: {row}, az={}, bz={}, cz={}",
                az[row], bz[row], cz[row]
            );
        }

        z[compressed_layout.fs_commitment_blocks[0].off_public_output] += 1;
        assert!(!compressed_r1cs.is_satisfied_mod(&z, BB_P));
        let blocks = audit.unsatisfied_blocks(&compressed_r1cs, &z, BB_P);
        assert!(
            blocks
                .iter()
                .any(|block| block.kind == TypedCpAuditBlockKind::PoseidonDigestGadgets),
            "private FS commitment output mutation should hit Poseidon digest binding, got {blocks:?}"
        );
    }

    #[test]
    fn typed_cp_digest_r1cs_rejects_bad_private_digest_inputs() {
        let fixture = typed_cp_digest_fixture();

        let mut z = fixture.z.clone();
        z[fixture.layout.fs_commitment_blocks[0].off_private_witness] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut witness = fixture.witness.clone();
        witness.fs_openings[0][0] ^= 1;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(fixture.params.q);
        assert!(encode_typed_cp_digest_witness(
            &fixture.public,
            &witness,
            &fixture.layout,
            &fixture.params.ntt,
            ext_ctx.alpha,
            fixture.params.q,
            &fixture.ajtai,
            &fixture.original_r1cs,
        )
        .is_none());
    }

    #[test]
    fn typed_cp_digest_witness_encoder_rejects_noncanonical_lengths() {
        let fixture = typed_cp_digest_fixture();
        let mut witness = fixture.witness.clone();
        witness.fs_messages[0].resize(100, 9);
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(fixture.params.q);
        assert!(encode_typed_cp_digest_witness(
            &fixture.public,
            &witness,
            &fixture.layout,
            &fixture.params.ntt,
            ext_ctx.alpha,
            fixture.params.q,
            &fixture.ajtai,
            &fixture.original_r1cs,
        )
        .is_none());

        let mut public = fixture.public.clone();
        public.instance.folded_output.folded_instance.public_input[0].coeffs[0] += 1;
        assert!(typed_cp_digest_input_lengths(&public, &fixture.witness).is_none());
        assert!(encode_typed_cp_digest_instance(
            &public,
            &fixture.witness.fs_commitments,
            &fixture.layout,
        )
        .is_none());
    }

    #[test]
    fn typed_cp_digest_r1cs_rejects_wrong_public_digests_and_replay() {
        let fixture = typed_cp_digest_fixture();
        for offset in [
            fixture.layout.off_fs_commitments,
            fixture.layout.off_fs_root,
            fixture.layout.off_fold_root,
            fixture.layout.off_challenge_digest,
            fixture.layout.off_transcript_seed_digest,
            fixture.layout.statement.off_public_inputs,
        ] {
            let mut z = fixture.z.clone();
            z[offset] += 1;
            assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
        }
    }

    fn body_from_assignment(z: &[i64], block: &TypedCpDigestBlockLayout) -> Vec<u8> {
        (0..block.body_len)
            .map(|idx| {
                u8::try_from(z[block.off_body_bytes + idx])
                    .expect("honest digest body byte must fit in u8")
            })
            .collect()
    }

    fn eval_lin_for_test(z: &[i64], lin: &Lin) -> i64 {
        let acc = lin.0.iter().fold(0i128, |acc, &(idx, coeff)| {
            acc + z[idx] as i128 * coeff as i128
        });
        centered_i128(acc)
    }

    fn assert_block_inputs_match_body(z: &[i64], domain: &[u8], block: &TypedCpDigestBlockLayout) {
        let body = body_from_assignment(z, block);
        let expected = poseidon_digest_input_elems(domain, &body);
        assert_eq!(expected.len(), block.input_len);
        let packed_lins = digest_template_input_lins(domain, block);
        for (lin, elem) in packed_lins.iter().zip(expected.iter()) {
            assert_eq!(eval_lin_for_test(z, lin), elem.as_canonical_u32() as i64);
        }
    }

    #[test]
    fn typed_cp_digest_exact_body_bytes_match_poseidon_packing() {
        let fixture = typed_cp_digest_fixture();
        assert_block_inputs_match_body(
            &fixture.z,
            b"fs-commit",
            &fixture.layout.fs_commitment_blocks[0],
        );
        assert_block_inputs_match_body(&fixture.z, b"fs-root", &fixture.layout.fs_root_block);
        assert_block_inputs_match_body(&fixture.z, b"fold-root", &fixture.layout.fold_root_block);
        assert_block_inputs_match_body(
            &fixture.z,
            b"challenge-digest",
            &fixture.layout.challenge_digest_block,
        );
        assert_block_inputs_match_body(
            &fixture.z,
            b"transcript-seed",
            &fixture.layout.transcript_seed_block,
        );
        assert_block_inputs_match_body(
            &fixture.z,
            b"challenge",
            &fixture.layout.challenge_blocks[0],
        );
    }

    #[test]
    fn typed_cp_digest_r1cs_rejects_tampered_exact_body_bytes_and_bits() {
        let fixture = typed_cp_digest_fixture();
        let fs_commit_block = &fixture.layout.fs_commitment_blocks[0];

        let mut z = fixture.z.clone();
        z[fs_commit_block.off_body_bytes + 8] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fs_commit_block.off_body_bits] = 2;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fs_commit_block.off_body_bytes] = 256;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fs_commit_block.off_private_witness + fs_commit_block.input_len - 1] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_rejects_tampered_root_and_challenge_bodies() {
        let fixture = typed_cp_digest_fixture();

        let mut z = fixture.z.clone();
        z[fixture.layout.fs_root_block.off_body_bytes + 16] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.fold_root_block.off_body_bytes + 8] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.challenge_digest_block.off_body_bytes + 8] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.transcript_seed_block.off_body_bytes + 8] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.challenge_blocks[0].off_body_bytes + 8] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.challenge_blocks[0].off_public_output] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_binds_poseidon_challenge_to_beta() {
        let fixture = typed_cp_digest_fixture();
        let cp_layout = &fixture.layout.statement.partial.cp_layout;
        let digest_public_shift = fixture.layout.added_digest_public;

        let mut z = fixture.z.clone();
        let beta_col = cp_col_in_digest_r1cs(
            &fixture.layout.statement,
            digest_public_shift,
            cp_layout.beta(0, 0),
        );
        z[beta_col] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.off_beta_binding_selectors] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let challenge_byte = challenge_digest_challenge_body_offset(0);
        z[fixture.layout.challenge_digest_block.off_body_bytes + challenge_byte] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.challenge_blocks[0].off_public_output] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_rejects_tampered_structured_body_bindings() {
        let fixture = typed_cp_digest_fixture();
        let lengths = typed_cp_digest_input_lengths(&fixture.public, &fixture.witness).unwrap();
        let cp_layout = &fixture.layout.statement.partial.cp_layout;

        let mut z = fixture.z.clone();
        let fs_message = fs_commit_message_body_offset(&fixture.layout.fs_commitment_blocks[0]);
        z[fixture.layout.fs_commitment_blocks[0].off_body_bytes + fs_message] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let fold_commitment = fold_root_commitment_body_offset(cp_layout, &lengths, 0);
        z[fixture.layout.fold_root_block.off_body_bytes + fold_commitment + 8] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let fold_public_input = fold_root_public_input_body_offset(cp_layout, &lengths, 0);
        z[fixture.layout.fold_root_block.off_body_bytes + fold_public_input] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let transcript_public_input = transcript_seed_public_input_body_offset(cp_layout, 0);
        z[fixture.layout.transcript_seed_block.off_body_bytes + transcript_public_input] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let challenge_public_input =
            challenge_body_transcript_public_input_payload_offset(cp_layout, 0);
        z[fixture.layout.challenge_blocks[0].off_body_bytes + 8 + challenge_public_input] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let challenge_commitment =
            challenge_body_transcript_fs_commitment_payload_offset(cp_layout, 0);
        z[fixture.layout.challenge_blocks[0].off_body_bytes + 8 + challenge_commitment] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let challenge_digest_byte = challenge_digest_challenge_body_offset(0);
        z[fixture.layout.challenge_digest_block.off_body_bytes + challenge_digest_byte] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_binds_range_message_shape_prefixes() {
        let fixture = typed_cp_digest_range_shape_fixture();
        assert_eq!(fixture.z.len(), fixture.layout.num_variables);
        if let Some(row) = first_unsatisfied_row_mod(&fixture.digest_r1cs, &fixture.z, BB_P) {
            let az = fixture.digest_r1cs.a.mul_vec_mod(&fixture.z, BB_P);
            let bz = fixture.digest_r1cs.b.mul_vec_mod(&fixture.z, BB_P);
            let cz = fixture.digest_r1cs.c.mul_vec_mod(&fixture.z, BB_P);
            panic!(
                "first unsatisfied row: {row}, az={}, bz={}, cz={}",
                az[row], bz[row], cz[row]
            );
        }

        let lengths = typed_cp_digest_input_lengths(&fixture.public, &fixture.witness).unwrap();
        let message_shape = &lengths.gr1cs_message_shapes[0];
        let range_shape = message_shape.range.as_ref().unwrap();
        let fs_msg = fs_commit_message_body_offset(&fixture.layout.fs_commitment_blocks[0]);
        let message_base = fixture.layout.fs_commitment_blocks[0].off_body_bytes + fs_msg;
        let range_start = gr1cs_hadamard_section_len(message_shape);

        let mut z = fixture.z.clone();
        z[message_base + range_start] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let monomial_vector_count =
            range_start + 8 + commitment_message_len(range_shape.monomial_commitment_elem_lens[0]);
        let mut z = fixture.z.clone();
        z[message_base + monomial_vector_count] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let monomial_sumcheck_round_count =
            monomial_vector_count + 8 + 8 + range_shape.monomial_vector_lens[0] * D * 8;
        let mut z = fixture.z.clone();
        z[message_base + monomial_sumcheck_round_count] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let payload = fixture.layout.range_payload_blocks[0]
            .as_ref()
            .expect("range proof payload block");
        assert_eq!(
            payload.projected_values_count,
            range_shape.projected_values_count
        );

        let mut z = fixture.z.clone();
        z[payload.off_monomial_commitments] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_commitment_wraps] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_vectors] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_vector_squares] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_sq_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_projected_values] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let monomial_commitment_payload = range_start + 8 + 8;
        let mut z = fixture.z.clone();
        z[message_base + monomial_commitment_payload] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let monomial_vector_payload = monomial_vector_count + 8 + 8;
        let mut z = fixture.z.clone();
        z[message_base + monomial_vector_payload] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let monomial_sumcheck_payload = monomial_sumcheck_round_count + 8 + 8;
        let mut z = fixture.z.clone();
        z[message_base + monomial_sumcheck_payload] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let monomial_evaluation_count = monomial_sumcheck_round_count
            + 8
            + 8
            + range_shape.monomial_sumcheck_round_evals[0] * 2 * 8;
        let monomial_evaluation_payload = monomial_evaluation_count + 8;
        let mut z = fixture.z.clone();
        z[message_base + monomial_evaluation_payload] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let sq_evaluation_count =
            monomial_evaluation_count + 8 + range_shape.monomial_evaluation_rows[0] * D * 8;
        let sq_evaluation_payload = sq_evaluation_count + 8;
        let mut z = fixture.z.clone();
        z[message_base + sq_evaluation_payload] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let projected_values = gr1cs_projected_values_payload_offset(message_shape, range_shape);
        let mut z = fixture.z.clone();
        z[message_base + projected_values] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_enforces_monomial_challenges_and_semantics() {
        let fixture = typed_cp_digest_range_shape_fixture();
        assert_eq!(fixture.z.len(), fixture.layout.num_variables);
        if let Some(row) = first_unsatisfied_row_mod(&fixture.digest_r1cs, &fixture.z, BB_P) {
            let az = fixture.digest_r1cs.a.mul_vec_mod(&fixture.z, BB_P);
            let bz = fixture.digest_r1cs.b.mul_vec_mod(&fixture.z, BB_P);
            let cz = fixture.digest_r1cs.c.mul_vec_mod(&fixture.z, BB_P);
            panic!(
                "first unsatisfied row: {row}, az={}, bz={}, cz={}",
                az[row], bz[row], cz[row]
            );
        }

        let payload = fixture.layout.range_payload_blocks[0]
            .as_ref()
            .expect("range proof payload block");
        let lengths = typed_cp_digest_input_lengths(&fixture.public, &fixture.witness).unwrap();
        let range_shape = lengths.gr1cs_message_shapes[0]
            .range
            .as_ref()
            .expect("range proof shape");
        let verifier_counts = monomial_sumcheck_verifier_counts(range_shape);

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_seed] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_challenges] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_alpha] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_sq_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_aux] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_wraps] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_aux + verifier_counts.aux_count] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[payload.off_monomial_sumcheck_wraps + verifier_counts.wrap_count] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_derives_folded_evaluation_values() {
        let fixture = typed_cp_digest_range_shape_fixture();
        assert_eq!(fixture.layout.folded_evaluation_values, 3);
        assert!(fixture.digest_r1cs.is_satisfied_mod(&fixture.z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.off_folded_evaluations] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.off_folded_eval_products] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        z[fixture.layout.off_folded_eval_wraps] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }

    #[test]
    fn typed_cp_digest_r1cs_binds_hadamard_message_bytes_to_cp_columns() {
        let fixture = typed_cp_digest_gr1cs_fixture();
        assert_eq!(fixture.z.len(), fixture.layout.num_variables);
        if let Some(row) = first_unsatisfied_row_mod(&fixture.digest_r1cs, &fixture.z, BB_P) {
            let az = fixture.digest_r1cs.a.mul_vec_mod(&fixture.z, BB_P);
            let bz = fixture.digest_r1cs.b.mul_vec_mod(&fixture.z, BB_P);
            let cz = fixture.digest_r1cs.c.mul_vec_mod(&fixture.z, BB_P);
            panic!(
                "first unsatisfied row: {row}, az={}, bz={}, cz={}",
                az[row], bz[row], cz[row]
            );
        }

        let cp_layout = &fixture.layout.statement.partial.cp_layout;
        let digest_public_shift = fixture.layout.added_digest_public;

        let mut z = fixture.z.clone();
        let had_eval_col = cp_col_in_digest_r1cs(
            &fixture.layout.statement,
            digest_public_shift,
            cp_layout.had_eval(0, 0, 0, 0),
        );
        z[had_eval_col] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let had_matrix_col = cp_col_in_digest_r1cs(
            &fixture.layout.statement,
            digest_public_shift,
            cp_layout.had_eval_matrix(0, 0, 0, 0),
        );
        z[had_matrix_col] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut z = fixture.z.clone();
        let fs_msg = fs_commit_message_body_offset(&fixture.layout.fs_commitment_blocks[0]);
        z[fixture.layout.fs_commitment_blocks[0].off_body_bytes + fs_msg] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
    }
}
