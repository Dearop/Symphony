#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::Commitment;
    use crate::cp_snark::{CPSnark, IdentityRelation};
    use crate::fiat_shamir::FSCommitment;
    use crate::folding::{
        FoldedInstance, FoldedOutputInstance, FoldedOutputWitness, FoldedWitness,
    };
    use crate::r1cs::R1CSMatrices;
    use crate::ring::extension::ExtFieldElement;
    use crate::ring::tensor::TensorElement;
    use crate::ring::{RingElement, RingVector};
    use crate::rok::{BatchedLinearRelation, LinearRelation};
    use crate::HashCommitment;

    fn test_relation() -> RelationDescription {
        RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: None,
        }
    }

    // --- CP path tests ---

    #[test]
    fn cp_snark_roundtrip() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let proof = WhirSnark::prove(&pk, b"test-instance", b"secret-witness-1234");
        assert!(WhirSnark::verify(&vk, b"test-instance", &proof));
    }

    #[test]
    fn cp_snark_wrong_instance_rejected() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let proof = WhirSnark::prove(&pk, b"instance-A", b"witness");
        assert!(!WhirSnark::verify(&vk, b"instance-B", &proof));
    }

    #[test]
    fn cp_snark_short_instance_rejected() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let proof = WhirSnark::prove(&pk, b"abc", b"witness");
        assert!(!WhirSnark::verify(&vk, b"abc", &proof));
    }

    #[test]
    fn cp_snark_empty_witness() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let proof = WhirSnark::prove(&pk, b"instance", b"");
        assert!(WhirSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn cp_snark_large_witness() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let witness: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let proof = WhirSnark::prove(&pk, b"instance", &witness);
        assert!(WhirSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn standalone_cp_snark_large_messages_roundtrip() {
        let num_messages = 8usize;
        let max_message_size = 128usize;
        let cp = CPSnark::<WhirSnark, HashCommitment>::setup(num_messages, max_message_size);
        let scheme = HashCommitment::new();
        let relation = IdentityRelation;

        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|msg_i| {
                (0..max_message_size)
                    .map(|byte_i| ((byte_i * 31 + msg_i * 17 + 7) % 251) as u8)
                    .collect()
            })
            .collect();
        let (commitments, openings): (Vec<_>, Vec<_>) =
            messages.iter().map(|msg| scheme.commit(msg)).unzip();
        let message_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();

        let proof = cp
            .prove(
                &scheme,
                &message_refs,
                &openings,
                &commitments,
                b"",
                &relation,
            )
            .expect("WHIR standalone CP prove must succeed");

        assert!(cp.verify(&scheme, &commitments, b"", &relation, &proof));
    }

    #[test]
    fn cp_snark_proof_is_succinct() {
        let (pk, _vk) = WhirSnark::setup(&test_relation());
        let witness: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let proof = WhirSnark::prove(&pk, b"instance", &witness);
        // WHIR proof should have a Merkle commitment (not a full witness table)
        assert!(proof.whir_pcs_proof.initial_commitment.is_some());
    }

    // --- Output SNARK tests ---

    #[test]
    fn output_snark_roundtrip() {
        // Build a simple R1CS: x * x = x (satisfied by x=0 or x=1)
        let mut r1cs = R1CSMatrices::new(1, 2, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 1, 1);

        let ctx = WhirContext {
            r1cs,
            q: 2013265921,
            d: 1,
            n_pub: 1,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        };
        let ctx_bytes = serialize::serialize_context(&ctx);

        let relation = RelationDescription {
            num_instance_vars: 1,
            num_witness_vars: 1,
            num_constraints: 1,
            context: Some(ctx_bytes),
        };

        let (pk, vk) = WhirSnark::setup(&relation);

        let instance = 1i64.to_le_bytes();
        let witness = 1i64.to_le_bytes();
        let proof = WhirSnark::prove(&pk, &instance, &witness);
        assert!(proof.is_output);
        assert!(WhirSnark::verify(&vk, &instance, &proof));
    }

    #[test]
    fn output_snark_wrong_instance_rejected() {
        let mut r1cs = R1CSMatrices::new(1, 2, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 1, 1);

        let ctx = WhirContext {
            r1cs,
            q: 2013265921,
            d: 1,
            n_pub: 1,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        };
        let ctx_bytes = serialize::serialize_context(&ctx);

        let relation = RelationDescription {
            num_instance_vars: 1,
            num_witness_vars: 1,
            num_constraints: 1,
            context: Some(ctx_bytes),
        };

        let (pk, vk) = WhirSnark::setup(&relation);
        let instance = 1i64.to_le_bytes();
        let witness = 1i64.to_le_bytes();
        let proof = WhirSnark::prove(&pk, &instance, &witness);

        let wrong_instance = 42i64.to_le_bytes();
        assert!(!WhirSnark::verify(&vk, &wrong_instance, &proof));
    }

    fn typed_output_fixture() -> (
        RelationDescription,
        FoldedOutputInstance,
        FoldedOutputWitness,
    ) {
        // Public x=1, private w=1, constraint x * w = w.
        let mut r1cs = R1CSMatrices::new(1, 2, 1);
        r1cs.a.insert(0, 0, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 1, 1);

        let ctx = WhirContext {
            r1cs,
            q: 2013265921,
            d: 1,
            n_pub: 1,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        };
        let relation = RelationDescription {
            num_instance_vars: 1,
            num_witness_vars: 1,
            num_constraints: 1,
            context: Some(serialize::serialize_context(&ctx)),
        };

        let mut one_eval = TensorElement::zero();
        one_eval.data[0][0] = 1;
        let evals = [one_eval.clone(), one_eval.clone(), one_eval];
        let commitment = Commitment {
            value: RingVector::zero(1),
        };
        let folded_instance = FoldedInstance {
            commitment: commitment.clone(),
            public_input: vec![RingElement::from_constant(1)],
            evaluation_values: evals.to_vec(),
        };
        let folded_witness = FoldedWitness {
            witness: RingVector::from(vec![RingElement::from_constant(1)]),
            monomial_vectors: Vec::new(),
        };
        let output_instance = FoldedOutputInstance {
            folded_instance,
            linear_relation: LinearRelation {
                commitment,
                evaluation_point: Vec::<ExtFieldElement>::new(),
                evaluation_values: evals,
            },
            batched_relation: BatchedLinearRelation {
                commitments: Vec::new(),
                evaluation_point: Vec::new(),
                evaluation_values: Vec::new(),
            },
        };
        let output_witness = FoldedOutputWitness { folded_witness };

        (relation, output_instance, output_witness)
    }

    fn mul_ring_ntt(
        lhs: &RingElement,
        rhs: &RingElement,
        ntt: &crate::ring::ntt::NttContext,
    ) -> RingElement {
        let lhs_ntt = ntt.forward(lhs);
        let rhs_ntt = ntt.forward(rhs);
        ntt.inverse(&ntt.pointwise_mul(&lhs_ntt, &rhs_ntt))
    }

    fn mul_ring_babybear(lhs: &RingElement, rhs: &RingElement) -> RingElement {
        let mut acc = [0i128; D];
        for i in 0..D {
            for j in 0..D {
                let prod = lhs.coeffs[i] as i128 * rhs.coeffs[j] as i128;
                let idx = i + j;
                if idx < D {
                    acc[idx] += prod;
                } else {
                    acc[idx - D] -= prod;
                }
            }
        }
        let mut coeffs = [0i64; D];
        for (out, value) in coeffs.iter_mut().zip(acc) {
            let p = 2_013_265_921i128;
            let mut reduced = value % p;
            if reduced < 0 {
                reduced += p;
            }
            if reduced > p / 2 {
                reduced -= p;
            }
            *out = reduced as i64;
        }
        RingElement { coeffs }
    }

    fn typed_cp_direct_fixture() -> (
        RelationDescription,
        crate::cp_relation_core::CpPublicStatement,
        crate::cp_relation_core::CpWitnessBundle,
    ) {
        let q = 257;
        let params = SymphonyParams {
            q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 1,
            n_bar: 3,
            m: 1,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(q, D),
        };
        let ext_ctx = ExtFieldContext::new(q);
        let mut r1cs = R1CSMatrices::new(1, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 0, 15);

        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), q, params.ntt());
        let public_inputs = vec![vec![1i64]];
        let original_witnesses = vec![RingVector::from(vec![
            RingElement::from_constant(3),
            RingElement::from_constant(5),
        ])];
        let full_witness = crate::commitment::opening::assemble_full_witness(
            &public_inputs[0],
            &original_witnesses[0],
        );
        let (commitment, _) = ajtai.commit(&full_witness);
        let monomial_vector_len = 4;
        let monomial_vectors = vec![vec![RingElement::zero(); monomial_vector_len]; params.k_g()];
        let mon_ajtai = crate::commitment::AjtaiParams::setup_deterministic(
            params.kappa,
            monomial_vector_len,
            q,
            params.ntt(),
            b"range-proof-monomial",
        );
        let mut monomial_commitments = Vec::with_capacity(params.k_g());
        for monomial_vector in &monomial_vectors {
            let (commitment, _) = mon_ajtai.commit(&RingVector::from(monomial_vector.clone()));
            monomial_commitments.push(commitment);
        }
        let shared_challenges = crate::cp_relation_core::CpSharedChallengeData {
            sumcheck_seed_had: Vec::new(),
            alpha: ExtFieldElement { c0: 5, c1: 3 },
            hadamard_sumcheck_challenges: Vec::new(),
            sumcheck_seed_mon: vec![
                ExtFieldElement { c0: 2, c1: 1 },
                ExtFieldElement { c0: 3, c1: 2 },
            ],
            monomial_sumcheck_challenges: vec![
                ExtFieldElement { c0: 11, c1: 6 },
                ExtFieldElement { c0: 13, c1: 7 },
            ],
        };
        let monomial_challenges = crate::rok::monomial::MonomialChallenges {
            s: shared_challenges.sumcheck_seed_mon.clone(),
            alpha: shared_challenges.alpha,
            sumcheck_challenges: shared_challenges.monomial_sumcheck_challenges.clone(),
        };
        let monomial_proof = crate::rok::monomial::prove(
            &monomial_commitments,
            &monomial_vectors,
            &monomial_challenges,
            &ext_ctx,
        );
        let gr1cs_proof = crate::rok::gr1cs::GR1CSProof {
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
                monomial_commitments,
                monomial_vectors,
                monomial_proof,
                projected_values: vec![0; 3],
            },
        };
        let fs_messages: Vec<Vec<u8>> = [gr1cs_proof.clone()]
            .iter()
            .map(crate::snark::cp_snark::encode_gr1cs_round_message)
            .collect();
        let scheme = crate::digest_core::PublicDigestScheme::Poseidon2BabyBear;
        let mut fs_commitments = Vec::with_capacity(fs_messages.len());
        let mut fs_openings = Vec::with_capacity(fs_messages.len());
        for message in &fs_messages {
            let (commitment, opening) = crate::digest_core::fs_commit_with_scheme(scheme, message);
            fs_commitments.push(commitment.to_vec());
            fs_openings.push(opening.to_vec());
        }
        let challenges = crate::digest_core::derive_challenges_with_scheme(
            scheme,
            &public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
            &fs_commitments,
        );
        let typed_beta =
            crate::snark::cp_snark::typed_r1cs::poseidon_challenges_to_betas(&challenges)
                .expect("typed beta");
        let beta = &typed_beta[0];
        let mut folded_commitment = commitment.clone();
        for elem in &mut folded_commitment.value.elements {
            *elem = mul_ring_ntt(elem, beta, params.ntt());
        }
        let folded_public_input = public_inputs[0]
            .iter()
            .map(|&value| mul_ring_ntt(&RingElement::from_constant(value), beta, params.ntt()))
            .collect::<Vec<_>>();
        let mut folded_evaluation_values = vec![TensorElement::zero(); 3];
        for (idx, eval) in gr1cs_proof
            .hadamard_proof
            .evaluation_matrix
            .iter()
            .enumerate()
        {
            for t in 0..crate::params::T {
                let row = RingElement {
                    coeffs: eval.data[t],
                };
                folded_evaluation_values[idx].data[t] = mul_ring_babybear(&row, beta).coeffs;
            }
        }
        let folded_instance = FoldedInstance {
            commitment: folded_commitment,
            public_input: folded_public_input,
            evaluation_values: folded_evaluation_values.clone(),
        };
        let linear_relation = LinearRelation {
            commitment: folded_instance.commitment.clone(),
            evaluation_point: Vec::new(),
            evaluation_values: [
                folded_evaluation_values[0].clone(),
                folded_evaluation_values[1].clone(),
                folded_evaluation_values[2].clone(),
            ],
        };
        let batched_relation = BatchedLinearRelation {
            commitments: Vec::new(),
            evaluation_point: Vec::new(),
            evaluation_values: Vec::new(),
        };
        let folding_proof = crate::folding::FoldingProof {
            commitments: vec![commitment.clone()],
            gr1cs_proofs: vec![gr1cs_proof],
            beta: typed_beta,
            folded_instance: folded_instance.clone(),
            linear_relation,
            batched_relation,
        };
        let folded_witness = FoldedWitness {
            witness: original_witnesses[0].clone(),
            monomial_vectors: Vec::new(),
        };
        let folded_output_instance =
            crate::folding::folded_output_instance_from_proof(&folding_proof);
        let folded_output_witness =
            crate::folding::folded_output_witness_from_folded(&folded_witness);
        let fold_inputs = vec![crate::digest_core::FoldInput {
            commitment_bytes: crate::snark::cp_snark::encode_commitment_to_bytes(&commitment),
            public_input: public_inputs[0].clone(),
            eval_values_bytes: fs_messages[0].clone(),
        }];
        let cp_public_instance = crate::cp_relation_core::CpPublicInstance {
            fs_root: crate::digest_core::digest_fs_root_with_scheme(scheme, &fs_commitments),
            fold_root: crate::digest_core::digest_fold_root_with_scheme(scheme, &fold_inputs),
            challenge_digest: crate::digest_core::digest_challenge_digest_with_scheme(
                scheme,
                &challenges,
            ),
            transcript_seed_digest: crate::digest_core::digest_transcript_seed_with_scheme(
                scheme,
                &public_inputs,
                r1cs.num_constraints,
                r1cs.num_variables,
                r1cs.num_public,
            ),
            x_folded: folded_instance.clone(),
            folded_output: folded_output_instance.clone(),
        };
        let statement = crate::cp_relation_core::CpPublicStatement::new(
            cp_public_instance,
            public_inputs.clone(),
            &r1cs,
            scheme,
        )
        .with_fs_commitments(fs_commitments.clone());
        let witness = crate::cp_relation_core::CpWitnessBundle {
            transcript_bytes: Vec::new(),
            fs_commitments,
            fs_openings,
            fs_messages,
            fold_inputs,
            original_witnesses,
            folded_output: folded_instance,
            folded_output_instance: folded_output_instance.clone(),
            folded_output_witness,
            folded_witness,
            folding_proof,
            shared_challenges: crate::cp_relation_core::CpSharedChallengeData {
                sumcheck_seed_had: shared_challenges.sumcheck_seed_had,
                alpha: shared_challenges.alpha,
                hadamard_sumcheck_challenges: shared_challenges.hadamard_sumcheck_challenges,
                sumcheck_seed_mon: shared_challenges.sumcheck_seed_mon,
                monomial_sumcheck_challenges: shared_challenges.monomial_sumcheck_challenges,
            },
        };
        let (cp_r1cs, cp_layout) = crate::snark::cp_snark::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            r1cs.num_constraints,
            ext_ctx.alpha,
            q,
        );
        let descriptor = crate::snark::TypedCpSetupDescriptor {
            params,
            ajtai,
            original_r1cs: r1cs,
            cp_r1cs,
            cp_layout,
        };
        let relation = WhirSnark::typed_cp_relation_description(&descriptor)
            .expect("typed CP relation description");
        (relation, statement, witness)
    }

    #[test]
    fn typed_output_roundtrip_direct() {
        let (relation, output_instance, output_witness) = typed_output_fixture();
        let (pk, vk) = WhirSnark::setup(&relation);

        assert!(WhirSnark::has_authoritative_typed_output());
        let proof = WhirSnark::prove_typed_output(&pk, &output_instance, &output_witness)
            .expect("typed WHIR output proof");

        assert_eq!(
            WhirSnark::verify_typed_output(&vk, &output_instance, &proof),
            Some(true)
        );

        let mut tampered = output_instance.clone();
        tampered.folded_instance.public_input[0].coeffs[0] = 0;
        assert_eq!(
            WhirSnark::verify_typed_output(&vk, &tampered, &proof),
            Some(false)
        );

        let legacy_instance = 1i64.to_le_bytes();
        let legacy_witness = 1i64.to_le_bytes();
        let legacy_proof = WhirSnark::prove(&pk, &legacy_instance, &legacy_witness);
        assert_eq!(
            WhirSnark::verify_typed_output(&vk, &output_instance, &legacy_proof),
            Some(false)
        );
    }

    #[test]
    fn typed_cp_full_digest_roundtrip_direct_authoritative() {
        let (relation, statement, witness) = typed_cp_direct_fixture();
        let ctx = deserialize_context(relation.context.as_ref().unwrap()).unwrap();
        let typed = ctx.typed_cp.as_ref().unwrap();
        let (r1cs, layout) = typed_cp_digest_r1cs_from_context(&ctx, typed).unwrap();
        let instance = crate::snark::cp_snark::encode_typed_cp_digest_instance(
            &statement,
            &statement.fs_commitments,
            &layout,
        )
        .unwrap();
        let cp_ntt = Some(crate::ring::ntt::NttContext::new(ctx.q));
        let ext_ctx = ExtFieldContext::new(ctx.q);
        let witness_bytes = crate::snark::cp_snark::encode_typed_cp_digest_witness(
            &statement,
            &witness,
            &layout,
            &cp_ntt,
            ext_ctx.alpha,
            ctx.q,
            &typed.ajtai,
            &typed.original_r1cs,
        )
        .unwrap();
        let z = instance
            .chunks_exact(8)
            .chain(witness_bytes.chunks_exact(8))
            .map(|chunk| i64::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        if !r1cs.is_satisfied_mod(&z, 2_013_265_921) {
            let az = r1cs.a.mul_vec_mod(&z, 2_013_265_921);
            let bz = r1cs.b.mul_vec_mod(&z, 2_013_265_921);
            let cz = r1cs.c.mul_vec_mod(&z, 2_013_265_921);
            let row = (0..r1cs.num_constraints)
                .find(|&idx| {
                    ((az[idx] as i128 * bz[idx] as i128 - cz[idx] as i128) % 2_013_265_921i128) != 0
                })
                .unwrap();
            panic!(
                "typed CP fixture first unsatisfied row {row}: az={} bz={} cz={}",
                az[row], bz[row], cz[row]
            );
        }

        let (pk, vk) = WhirSnark::setup(&relation);

        assert_eq!(
            WhirSnark::public_digest_scheme(),
            crate::digest_core::PublicDigestScheme::Poseidon2BabyBear
        );
        assert!(WhirSnark::has_authoritative_typed_cp());

        let proof =
            WhirSnark::prove_typed_cp(&pk, &statement, &witness).expect("full typed CP WHIR proof");
        assert_eq!(
            WhirSnark::verify_typed_cp(&vk, &statement, &proof),
            Some(true)
        );

        let mut tampered_digest = statement.clone();
        tampered_digest.instance.fs_root[0] ^= 1;
        assert_eq!(
            WhirSnark::verify_typed_cp(&vk, &tampered_digest, &proof),
            Some(false)
        );

        let mut tampered_input = statement.clone();
        tampered_input.public_inputs[0][0] += 1;
        assert_eq!(
            WhirSnark::verify_typed_cp(&vk, &tampered_input, &proof),
            Some(false)
        );

        let mut legacy_statement = statement.clone();
        legacy_statement.digest_scheme = crate::digest_core::PublicDigestScheme::Sha256;
        assert!(WhirSnark::prove_typed_cp(&pk, &legacy_statement, &witness).is_none());
        assert_eq!(
            WhirSnark::verify_typed_cp(&vk, &legacy_statement, &proof),
            Some(false)
        );
    }

    #[test]
    fn typed_output_rejects_malformed_relation() {
        let (relation, mut output_instance, output_witness) = typed_output_fixture();
        let (pk, vk) = WhirSnark::setup(&relation);

        let valid_instance = output_instance.clone();
        let valid_proof = WhirSnark::prove_typed_output(&pk, &valid_instance, &output_witness)
            .expect("typed WHIR output proof");

        output_instance.linear_relation.evaluation_values[0].data[0][0] += 1;
        assert!(WhirSnark::prove_typed_output(&pk, &output_instance, &output_witness).is_none());
        assert_eq!(
            WhirSnark::verify_typed_output(&vk, &output_instance, &valid_proof),
            Some(false)
        );
    }

    #[test]
    fn typed_output_rejects_spliced_transcript_instance() {
        let (relation, output_instance, output_witness) = typed_output_fixture();
        let (pk, vk) = WhirSnark::setup(&relation);
        let proof = WhirSnark::prove_typed_output(&pk, &output_instance, &output_witness)
            .expect("typed WHIR output proof");

        let mut spliced = output_instance.clone();
        spliced.batched_relation.commitments.push(Commitment {
            value: RingVector::zero(1),
        });
        spliced
            .batched_relation
            .evaluation_values
            .push(TensorElement::zero());
        assert_eq!(
            WhirSnark::verify_typed_output(&vk, &spliced, &proof),
            Some(false)
        );
    }

    #[test]
    fn output_snark_rejects_forged_az_bz_cz_claims() {
        let mut r1cs = R1CSMatrices::new(1, 2, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 1, 1);

        let ctx = WhirContext {
            r1cs,
            q: 2013265921,
            d: 1,
            n_pub: 1,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        };
        let ctx_bytes = serialize::serialize_context(&ctx);
        let relation = RelationDescription {
            num_instance_vars: 1,
            num_witness_vars: 1,
            num_constraints: 1,
            context: Some(ctx_bytes),
        };

        let (pk, vk) = WhirSnark::setup(&relation);
        let instance = 1i64.to_le_bytes();
        let witness = 1i64.to_le_bytes();
        let mut proof = WhirSnark::prove(&pk, &instance, &witness);
        assert!(WhirSnark::verify(&vk, &instance, &proof));
        assert_eq!(proof.linear_checks.len(), 3);

        // Preserve the R1CS sumcheck final product relation:
        // (Az + d) * Bz - (Cz + d * Bz) == Az * Bz - Cz.
        // The new WHIR linear-binding checks must still reject because these
        // altered claims are no longer derived from the committed z.
        let delta = BabyBear::ONE;
        let bz = proof.evaluations[1];
        proof.evaluations[0] += delta;
        proof.evaluations[2] += delta * bz;

        assert!(!WhirSnark::verify(&vk, &instance, &proof));
    }

    // --- Shared helper tests ---

    #[test]
    fn canonical_whir_proof_payload_is_deterministic_and_binding() {
        let proof = WhirProof {
            sumcheck_rounds_3: vec![[
                BabyBear::from_u32(1),
                BabyBear::from_u32(2),
                BabyBear::from_u32(3),
            ]],
            sumcheck_rounds_4: vec![[
                BabyBear::from_u32(4),
                BabyBear::from_u32(5),
                BabyBear::from_u32(6),
                BabyBear::from_u32(7),
            ]],
            evaluations: [
                BabyBear::from_u32(8),
                BabyBear::from_u32(9),
                BabyBear::from_u32(10),
            ],
            whir_pcs_proof: WhirPcsProof::<F, EF, WhirMmcs>::default(),
            z_eval: BabyBear::from_u32(11),
            linear_checks: vec![WhirLinearCheckProof {
                rounds: vec![[
                    BabyBear::from_u32(12),
                    BabyBear::from_u32(13),
                    BabyBear::from_u32(14),
                ]],
                z_eval: BabyBear::from_u32(15),
            }],
            private_opening_evals: vec![BabyBear::from_u32(16), BabyBear::from_u32(17)],
            family_columnar_subproofs: Vec::new(),
            num_vars: 3,
            is_output: true,
        };

        let encoded = canonical_whir_proof_bytes(&proof);
        assert!(encoded.starts_with(WHIR_PROOF_PAYLOAD_MAGIC));
        assert_eq!(
            &encoded[WHIR_PROOF_PAYLOAD_MAGIC.len()..WHIR_PROOF_PAYLOAD_MAGIC.len() + 2],
            &WHIR_PROOF_PAYLOAD_VERSION.to_le_bytes()
        );
        assert_eq!(encoded, canonical_whir_proof_bytes(&proof));
        let decoded = whir_proof_from_canonical_bytes(&encoded).expect("WHIR payload decodes");
        assert_eq!(canonical_whir_proof_bytes(&decoded), encoded);

        let mut tampered = proof;
        tampered.z_eval += BabyBear::ONE;
        assert_ne!(encoded, canonical_whir_proof_bytes(&tampered));

        let mut bad_kind = encoded.clone();
        bad_kind[WHIR_PROOF_PAYLOAD_MAGIC.len() + 2] = 2;
        assert_eq!(
            whir_proof_from_canonical_bytes(&bad_kind).unwrap_err(),
            WhirProofPayloadError::InvalidProofKind(2)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            whir_proof_from_canonical_bytes(&trailing).unwrap_err(),
            WhirProofPayloadError::TrailingBytes
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            whir_proof_from_canonical_bytes(&truncated).unwrap_err(),
            WhirProofPayloadError::Truncated
        );

        let mut noncanonical = encoded;
        let first_sumcheck_value = WHIR_PROOF_PAYLOAD_MAGIC.len() + 2 + 1 + 8 + 8;
        noncanonical[first_sumcheck_value..first_sumcheck_value + 4]
            .copy_from_slice(&2_013_265_921u32.to_le_bytes());
        assert_eq!(
            whir_proof_from_canonical_bytes(&noncanonical).unwrap_err(),
            WhirProofPayloadError::NonCanonicalBabyBear(2_013_265_921)
        );
    }

    fn synthetic_whir_fixture_proof(is_output: bool) -> WhirProof {
        WhirProof {
            sumcheck_rounds_3: vec![[
                BabyBear::from_u32(1),
                BabyBear::from_u32(2),
                BabyBear::from_u32(3),
            ]],
            sumcheck_rounds_4: vec![[
                BabyBear::from_u32(4),
                BabyBear::from_u32(5),
                BabyBear::from_u32(6),
                BabyBear::from_u32(7),
            ]],
            evaluations: [
                BabyBear::from_u32(8),
                BabyBear::from_u32(9),
                BabyBear::from_u32(10),
            ],
            whir_pcs_proof: WhirPcsProof::<F, EF, WhirMmcs>::default(),
            z_eval: BabyBear::from_u32(11),
            linear_checks: vec![WhirLinearCheckProof {
                rounds: vec![[
                    BabyBear::from_u32(12),
                    BabyBear::from_u32(13),
                    BabyBear::from_u32(14),
                ]],
                z_eval: BabyBear::from_u32(15),
            }],
            private_opening_evals: vec![BabyBear::from_u32(16), BabyBear::from_u32(17)],
            family_columnar_subproofs: Vec::new(),
            num_vars: 3,
            is_output,
        }
    }

    fn whir_public_proof_v2_minimal_fixture_bytes() -> Vec<u8> {
        crate::public_proof::PublicProofEnvelope {
            digest_scheme: crate::digest_core::PublicDigestScheme::Poseidon2BabyBear,
            public_inputs: vec![vec![1]],
            r1cs_num_constraints: 1,
            r1cs_num_variables: 3,
            r1cs_num_public: 1,
            fs_commitments: vec![vec![0x11; 32]],
            fs_root: [0x22; 32],
            fold_root: [0x33; 32],
            challenge_digest: [0x44; 32],
            transcript_seed_digest: [0x55; 32],
            folded_output_bytes: b"folded-output-fixture-v1".to_vec(),
            cp_proof_bytes: canonical_whir_proof_bytes(&synthetic_whir_fixture_proof(false)),
            output_proof_bytes: canonical_whir_proof_bytes(&synthetic_whir_fixture_proof(true)),
        }
        .to_bytes()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn hex_decode(input: &str) -> Vec<u8> {
        let clean = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        assert_eq!(clean.len() % 2, 0, "hex fixture must have even length");
        clean
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("hex high nibble");
                let lo = (pair[1] as char).to_digit(16).expect("hex low nibble");
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    #[test]
    fn whir_public_proof_v2_minimal_golden_fixture_is_stable() {
        let fixture = include_str!("../../../tests/fixtures/public_proof_v2_whir_minimal.hex");
        let expected = hex_decode(fixture);
        let actual = whir_public_proof_v2_minimal_fixture_bytes();
        assert_eq!(expected, actual);

        let envelope =
            crate::public_proof::PublicProofEnvelope::from_bytes(&actual).expect("fixture decodes");
        assert_eq!(
            envelope.digest_scheme,
            crate::digest_core::PublicDigestScheme::Poseidon2BabyBear
        );
        assert_eq!(envelope.public_inputs, vec![vec![1]]);
        assert!(whir_proof_from_canonical_bytes(&envelope.cp_proof_bytes).is_ok());
        assert!(whir_proof_from_canonical_bytes(&envelope.output_proof_bytes).is_ok());
    }

    #[test]
    #[ignore = "prints the golden WHIR public proof v2 fixture hex"]
    fn print_whir_public_proof_v2_minimal_fixture_hex() {
        println!(
            "{}",
            hex_encode(&whir_public_proof_v2_minimal_fixture_bytes())
        );
    }

    #[test]
    fn eq_table_correctness() {
        let tau = vec![BabyBear::from_u32(3), BabyBear::from_u32(5)];
        let table = build_eq_table_bb(&tau, 2);
        let expected_00 = (BabyBear::ONE - tau[0]) * (BabyBear::ONE - tau[1]);
        assert_eq!(table[0], expected_00);
        let expected_11 = tau[0] * tau[1];
        assert_eq!(table[3], expected_11);
    }

    #[test]
    fn mle_eval_consistency() {
        let table = vec![
            BabyBear::from_u32(1),
            BabyBear::from_u32(2),
            BabyBear::from_u32(3),
            BabyBear::from_u32(4),
        ];
        let val = mle_eval_bb(&table, &[BabyBear::ZERO, BabyBear::ZERO]);
        assert_eq!(val, BabyBear::from_u32(1));
        let val = mle_eval_bb(&table, &[BabyBear::ONE, BabyBear::ONE]);
        assert_eq!(val, BabyBear::from_u32(4));
    }

    #[test]
    fn mle_eval_fast_matches_boolean_table_points() {
        let table = (0..8)
            .map(|idx| BabyBear::from_u32(idx + 10))
            .collect::<Vec<_>>();
        for idx in 0..table.len() {
            let point = boolean_point_for_index(idx, 3);
            assert_eq!(mle_eval_bb_fast(&table, &point), table[idx]);
            assert_eq!(
                mle_eval_bb_fast(&table, &point),
                mle_eval_bb(&table, &point)
            );
        }

        let non_boolean = [BabyBear::from_u32(2), BabyBear::ZERO, BabyBear::ONE];
        assert_eq!(
            mle_eval_bb_fast(&table, &non_boolean),
            mle_eval_bb(&table, &non_boolean)
        );
    }

    #[test]
    fn eq_point_eval_matches_table_mle() {
        let tau = vec![
            BabyBear::from_u32(3),
            BabyBear::from_u32(5),
            BabyBear::from_u32(7),
        ];
        let r = vec![
            BabyBear::from_u32(11),
            BabyBear::from_u32(13),
            BabyBear::from_u32(17),
        ];

        let eq_table = build_eq_table_bb(&tau, tau.len());
        let via_table = mle_eval_bb(&eq_table, &r);
        let direct = eval_eq_at_point_bb(&tau, &r);
        assert_eq!(direct, via_table);
    }

    #[test]
    fn lagrange_4_correctness() {
        let evals = [
            BabyBear::from_u32(10),
            BabyBear::from_u32(20),
            BabyBear::from_u32(35),
            BabyBear::from_u32(55),
        ];
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::ZERO), evals[0]);
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::ONE), evals[1]);
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::TWO), evals[2]);
        assert_eq!(
            lagrange_interpolate_4(&evals, BabyBear::from_u32(3)),
            evals[3]
        );
    }

    #[test]
    fn serialize_roundtrip() {
        let mut r1cs = R1CSMatrices::new(2, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(1, 2, -1);

        let ctx = WhirContext {
            r1cs,
            q: 65537,
            d: 64,
            n_pub: 1,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        };
        let bytes = serialize::serialize_context(&ctx);
        let ctx2 = deserialize_context(&bytes).unwrap();
        assert_eq!(ctx2.q, 65537);
        assert_eq!(ctx2.d, 64);
        assert!(ctx2.is_output_snark);
    }
}
