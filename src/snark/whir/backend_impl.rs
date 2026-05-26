impl BackendSnark for WhirSnark {
    type ProvingKey = WhirProvingKey;
    type VerifyingKey = WhirVerifyingKey;
    type Proof = WhirProof;

    fn public_digest_scheme() -> crate::digest_core::PublicDigestScheme {
        crate::digest_core::PublicDigestScheme::Poseidon2BabyBear
    }

    fn has_authoritative_typed_output() -> bool {
        true
    }

    fn has_authoritative_typed_cp() -> bool {
        true
    }

    fn serialize_output_context(
        r1cs: &crate::r1cs::R1CSMatrices,
        q: u64,
        d: usize,
    ) -> Option<Vec<u8>> {
        Some(serialize::serialize_context(&serialize::WhirContext {
            r1cs: r1cs.clone(),
            q,
            d,
            n_pub: r1cs.num_public,
            is_output_snark: true,
            is_cp_snark: false,
            typed_cp: None,
        }))
    }

    fn serialize_cp_context(r1cs: &crate::r1cs::R1CSMatrices, q: u64, d: usize) -> Option<Vec<u8>> {
        Some(serialize::serialize_context(&serialize::WhirContext {
            r1cs: r1cs.clone(),
            q,
            d,
            n_pub: r1cs.num_public,
            is_output_snark: false,
            is_cp_snark: true,
            typed_cp: None,
        }))
    }

    fn serialize_typed_cp_context(
        descriptor: &crate::snark::TypedCpSetupDescriptor,
    ) -> Option<Vec<u8>> {
        let lengths = crate::snark::cp_snark::typed_cp_digest_input_lengths_from_setup(
            descriptor.cp_layout.ell_np,
            descriptor.cp_layout.kappa,
            descriptor.cp_layout.n_in,
            descriptor.params.lambda_pj,
            descriptor.params.ell_h,
            descriptor.params.k_g(),
            &descriptor.original_r1cs,
        )?;
        let (r1cs, _layout) = crate::snark::cp_snark::generate_typed_cp_digest_r1cs(
            &descriptor.cp_r1cs,
            &descriptor.cp_layout,
            &descriptor.ajtai,
            &descriptor.original_r1cs,
            &lengths,
        );
        Some(serialize::serialize_context(&serialize::WhirContext {
            n_pub: r1cs.num_public,
            r1cs,
            q: descriptor.params.q,
            d: descriptor.params.d,
            is_output_snark: false,
            is_cp_snark: true,
            typed_cp: Some(serialize::typed_cp_context_from_descriptor(descriptor)),
        }))
    }

    fn typed_cp_relation_description(
        descriptor: &crate::snark::TypedCpSetupDescriptor,
    ) -> Option<crate::snark::RelationDescription> {
        let key = typed_cp_descriptor_cache_key(descriptor);
        let relation_cache =
            TYPED_CP_RELATION_DESCRIPTION_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(relation) = relation_cache
            .lock()
            .expect("typed CP relation description cache mutex poisoned")
            .get(&key)
            .cloned()
        {
            return Some(relation);
        }

        let lengths = crate::snark::cp_snark::typed_cp_digest_input_lengths_from_setup(
            descriptor.cp_layout.ell_np,
            descriptor.cp_layout.kappa,
            descriptor.cp_layout.n_in,
            descriptor.params.lambda_pj,
            descriptor.params.ell_h,
            descriptor.params.k_g(),
            &descriptor.original_r1cs,
        )?;
        let (r1cs, layout, audit) =
            crate::snark::cp_snark::generate_typed_cp_digest_r1cs_with_audit(
                &descriptor.cp_r1cs,
                &descriptor.cp_layout,
                &descriptor.ajtai,
                &descriptor.original_r1cs,
                &lengths,
            );
        debug_assert!(audit.validate_against(&r1cs).is_ok());
        let ctx = serialize::WhirContext {
            q: descriptor.params.q,
            d: descriptor.params.d,
            n_pub: r1cs.num_public,
            is_output_snark: false,
            is_cp_snark: true,
            typed_cp: Some(serialize::typed_cp_context_from_descriptor(descriptor)),
            r1cs: r1cs.clone(),
        };
        let context_bytes = serialize::serialize_context(&ctx);
        let typed_cache_key = typed_cp_cache_key(&ctx);
        TYPED_CP_RELATION_CACHE
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("typed CP cache mutex poisoned")
            .entry(typed_cache_key)
            .or_insert_with(|| {
                Arc::new(CachedTypedCpRelation {
                    r1cs: r1cs.clone(),
                    layout,
                    audit,
                })
            });
        let relation = crate::snark::RelationDescription {
            num_instance_vars: r1cs.num_public,
            num_witness_vars: r1cs.num_variables - r1cs.num_public,
            num_constraints: r1cs.num_constraints,
            context: Some(context_bytes),
        };
        relation_cache
            .lock()
            .expect("typed CP relation description cache mutex poisoned")
            .entry(key)
            .or_insert_with(|| relation.clone());
        Some(relation)
    }

    fn prove_typed_cp(
        pk: &Self::ProvingKey,
        statement: &crate::cp_relation_core::CpPublicStatement,
        witness: &crate::cp_relation_core::CpWitnessBundle,
    ) -> Option<Self::Proof> {
        let ctx = pk
            .relation
            .context
            .as_ref()
            .and_then(|bytes| deserialize_context(bytes))?;
        if !ctx.is_cp_snark || ctx.is_output_snark {
            return None;
        }

        if let Some(typed) = &ctx.typed_cp {
            if statement.digest_scheme != crate::digest_core::PublicDigestScheme::Poseidon2BabyBear
            {
                return None;
            }
            let typed_relation = typed_cp_relation_from_context(&ctx, typed)?;
            debug_assert!(typed_relation
                .audit
                .validate_against(&typed_relation.r1cs)
                .is_ok());
            if typed_relation.r1cs.num_public != ctx.r1cs.num_public
                || typed_relation.r1cs.num_variables != ctx.r1cs.num_variables
                || typed_relation.r1cs.num_constraints != ctx.r1cs.num_constraints
            {
                return None;
            }
            let cp_instance = crate::snark::cp_snark::encode_typed_cp_digest_instance(
                statement,
                &witness.fs_commitments,
                &typed_relation.layout,
            )?;
            let cp_ntt = Some(crate::ring::ntt::NttContext::new(ctx.q));
            let ext_ctx = crate::ring::extension::ExtFieldContext::new(ctx.q);
            let cp_witness = crate::snark::cp_snark::encode_typed_cp_digest_witness(
                statement,
                witness,
                &typed_relation.layout,
                &cp_ntt,
                ext_ctx.alpha,
                ctx.q,
                &typed.ajtai,
                &typed.original_r1cs,
            )?;
            return Some(prove_cp_r1cs(pk, &cp_instance, &cp_witness, &ctx));
        }

        if statement.digest_scheme != crate::digest_core::PublicDigestScheme::Sha256 {
            return None;
        }

        let legacy_layout = crate::snark::cp_snark::CpR1csLayout::new(
            statement.public_inputs.len(),
            statement.instance.x_folded.commitment.value.elements.len(),
            statement.r1cs_num_public,
            statement.r1cs_num_constraints,
        );
        let layout = legacy_layout.clone();
        if layout.num_instance != ctx.r1cs.num_public {
            return None;
        }

        let cp_public_instance = crate::snark::cp_snark::CpPublicInstance {
            fold_root: statement.instance.fold_root,
            fs_root: statement.instance.fs_root,
            transcript_seed_digest: statement.instance.transcript_seed_digest,
            challenge_digest: statement.instance.challenge_digest,
            folded_instance: statement.instance.x_folded.clone(),
        };
        let cp_instance =
            crate::snark::cp_snark::encode_cp_backend_instance(&cp_public_instance, &layout);
        let cp_ntt = Some(crate::ring::ntt::NttContext::new(ctx.q));
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(ctx.q);
        if legacy_layout.num_variables != ctx.r1cs.num_variables {
            return None;
        }
        let cp_witness = crate::snark::cp_snark::encode_cp_witness_r1cs(
            &witness.folding_proof.commitments,
            &statement.public_inputs,
            &witness.folding_proof.beta,
            &statement.instance.x_folded,
            &layout,
            &cp_ntt,
            &witness.folding_proof.gr1cs_proofs,
            &witness.shared_challenges.sumcheck_seed_had,
            &witness.shared_challenges.alpha,
            &witness.shared_challenges.hadamard_sumcheck_challenges,
            ext_ctx.alpha,
            ctx.q,
        );

        Some(prove_cp_r1cs(pk, &cp_instance, &cp_witness, &ctx))
    }

    fn verify_typed_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::cp_relation_core::CpPublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool> {
        let Some(ctx) = vk
            .relation
            .context
            .as_ref()
            .and_then(|bytes| deserialize_context(bytes))
        else {
            return Some(false);
        };
        if !ctx.is_cp_snark || ctx.is_output_snark {
            return Some(false);
        }

        if let Some(typed) = &ctx.typed_cp {
            if statement.digest_scheme != crate::digest_core::PublicDigestScheme::Poseidon2BabyBear
            {
                return Some(false);
            }
            let Some(typed_relation) = typed_cp_relation_from_context(&ctx, typed) else {
                return Some(false);
            };
            debug_assert!(typed_relation
                .audit
                .validate_against(&typed_relation.r1cs)
                .is_ok());
            if typed_relation.r1cs.num_public != ctx.r1cs.num_public
                || typed_relation.r1cs.num_variables != ctx.r1cs.num_variables
                || typed_relation.r1cs.num_constraints != ctx.r1cs.num_constraints
            {
                return Some(false);
            }
            let Some(cp_instance) = crate::snark::cp_snark::encode_typed_cp_digest_instance(
                statement,
                &statement.fs_commitments,
                &typed_relation.layout,
            ) else {
                return Some(false);
            };
            return Some(verify_cp_r1cs(vk, &cp_instance, proof, &ctx));
        }

        if statement.digest_scheme != crate::digest_core::PublicDigestScheme::Sha256 {
            return Some(false);
        }

        let legacy_layout = crate::snark::cp_snark::CpR1csLayout::new(
            statement.public_inputs.len(),
            statement.instance.x_folded.commitment.value.elements.len(),
            statement.r1cs_num_public,
            statement.r1cs_num_constraints,
        );
        let layout = legacy_layout.clone();
        if layout.num_instance != ctx.r1cs.num_public {
            return Some(false);
        }
        if legacy_layout.num_variables != ctx.r1cs.num_variables {
            return Some(false);
        }

        let cp_public_instance = crate::snark::cp_snark::CpPublicInstance {
            fold_root: statement.instance.fold_root,
            fs_root: statement.instance.fs_root,
            transcript_seed_digest: statement.instance.transcript_seed_digest,
            challenge_digest: statement.instance.challenge_digest,
            folded_instance: statement.instance.x_folded.clone(),
        };
        let cp_instance =
            crate::snark::cp_snark::encode_cp_backend_instance(&cp_public_instance, &layout);
        Some(verify_cp_r1cs(vk, &cp_instance, proof, &ctx))
    }

    fn typed_batched_cp_relation_description(
        shape: &crate::batched_cp::BatchedCpStatementShape,
    ) -> Option<crate::snark::RelationDescription> {
        Some(
            shape
                .structured_relation_description()
                .to_relation_description(),
        )
    }

    fn prove_typed_batched_cp(
        pk: &Self::ProvingKey,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
        witness: &crate::batched_cp::BatchedCpWitnessBundle,
    ) -> Option<Self::Proof> {
        let context = pk.relation.context.as_ref()?;
        let relation = WhirBatchedCpRelationContext::from_context_bytes(context)?;
        if relation.shape() != &statement.shape
            || relation.public_statement_bytes() != statement.canonical_bytes().len()
        {
            return None;
        }
        let bucket = crate::batched_cp::BatchedCpBucket::new(
            witness.items.clone(),
            statement.whir_parameter_digest,
        )
        .ok()?;
        if bucket.shape != statement.shape || bucket.public_statement() != *statement {
            return None;
        }
        let expected_witness = bucket.witness_bundle();
        if expected_witness.witness_oracle_rows != witness.witness_oracle_rows
            || expected_witness.round_message_oracles != witness.round_message_oracles
        {
            return None;
        }
        if let Some(columnar_relation) = relation.columnar_v2() {
            return prove_typed_batched_cp_columnar_v2(pk, columnar_relation, statement, witness);
        }
        if let Some(family_relation) = relation.family_columnar_v2() {
            return prove_typed_batched_cp_family_columnar_v2(
                pk,
                family_relation,
                statement,
                witness,
            );
        }
        let mut table = bytes_to_babybear(
            &witness
                .canonical_product_oracle_bytes(&statement.shape)
                .ok()?,
            0,
        );
        pad_to_power_of_two(&mut table);
        if table.len() < 2 {
            table.resize(2, BabyBear::ZERO);
        }
        let num_vars = table.len().trailing_zeros() as usize;
        let point = typed_batched_cp_opening_point(&pk.seed, &relation, statement, num_vars);
        let z_eval = mle_eval_bb(&table, &point);
        let (known_points, known_evals) =
            typed_batched_cp_public_oracle_claims(&statement.shape, statement, num_vars)?;
        let (semantic_value_points, semantic_value_evals) =
            typed_batched_cp_semantic_packed_value_claims(&relation, statement, num_vars)?;
        let equality_pairs =
            typed_batched_cp_sampled_equalities(&pk.seed, &relation, statement, 64);
        let equality_points = typed_batched_cp_equality_opening_points(&equality_pairs, num_vars)?;
        let linear_constraints = typed_batched_cp_sampled_folded_public_input_linear_constraints(
            &pk.seed, &relation, statement, 8,
        );
        let linear_points = typed_batched_cp_linear_opening_points(&linear_constraints, num_vars)?;
        let ring_mul_constraints = typed_batched_cp_sampled_folded_commitment_ring_mul_constraints(
            &pk.seed, &relation, statement, 2,
        );
        let ring_mul_points =
            typed_batched_cp_ring_mul_opening_points(&ring_mul_constraints, num_vars)?;
        let eval_ring_mul_constraints =
            typed_batched_cp_sampled_folded_evaluation_ring_mul_constraints(
                &pk.seed, &relation, statement, 2,
            );
        let eval_ring_mul_points =
            typed_batched_cp_eval_ring_mul_opening_points(&eval_ring_mul_constraints, num_vars)?;
        let poseidon_r1cs_constraints =
            typed_batched_cp_sampled_poseidon_r1cs_constraints(&pk.seed, &relation, statement, 8);
        let poseidon_r1cs_points =
            typed_batched_cp_poseidon_r1cs_opening_points(&poseidon_r1cs_constraints, num_vars)?;
        let ajtai_constraints =
            typed_batched_cp_sampled_ajtai_opening_constraints(&pk.seed, &relation, statement, 2);
        let ajtai_points = typed_batched_cp_ajtai_opening_points(&ajtai_constraints, num_vars)?;
        let original_r1cs_constraints =
            typed_batched_cp_sampled_original_r1cs_constraints(&pk.seed, &relation, statement, 2);
        let original_r1cs_points =
            typed_batched_cp_original_r1cs_opening_points(&original_r1cs_constraints, num_vars)?;
        let linear_eval_count = linear_points.len();
        let ring_mul_eval_count = ring_mul_points.len();
        let eval_ring_mul_eval_count = eval_ring_mul_points.len();
        let poseidon_r1cs_eval_count = poseidon_r1cs_points.len();
        let ajtai_eval_count = ajtai_points.len();
        let original_r1cs_eval_count = original_r1cs_points.len();
        let mut opening_points = Vec::with_capacity(
            1 + known_points.len()
                + semantic_value_points.len()
                + equality_points.len()
                + linear_points.len()
                + ring_mul_points.len()
                + eval_ring_mul_points.len()
                + poseidon_r1cs_points.len()
                + ajtai_points.len()
                + original_r1cs_points.len(),
        );
        opening_points.push(point);
        opening_points.extend(known_points);
        opening_points.extend(semantic_value_points);
        opening_points.extend(equality_points);
        opening_points.extend(linear_points);
        opening_points.extend(ring_mul_points);
        opening_points.extend(eval_ring_mul_points);
        opening_points.extend(poseidon_r1cs_points);
        opening_points.extend(ajtai_points);
        opening_points.extend(original_r1cs_points);
        let mut expected_evals =
            Vec::with_capacity(1 + known_evals.len() + semantic_value_evals.len());
        expected_evals.push(z_eval);
        expected_evals.extend(known_evals);
        expected_evals.extend(semantic_value_evals);
        let (whir_pcs_proof, evals) =
            whir_commit_and_prove_multi(&pk.seed, num_vars, &table, &opening_points);
        if evals.len() != opening_points.len() || evals[..expected_evals.len()] != expected_evals {
            return None;
        }
        let private_opening_evals = evals[expected_evals.len()..].to_vec();
        let equality_eval_count = equality_pairs.len() * 2;
        if private_opening_evals.len() < equality_eval_count {
            return None;
        }
        let (equality_evals, remaining_evals) = private_opening_evals.split_at(equality_eval_count);
        if remaining_evals.len() < linear_eval_count {
            return None;
        }
        let (linear_evals, remaining_evals) = remaining_evals.split_at(linear_eval_count);
        if remaining_evals.len() < ring_mul_eval_count {
            return None;
        }
        let (ring_mul_evals, remaining_evals) = remaining_evals.split_at(ring_mul_eval_count);
        if remaining_evals.len() < eval_ring_mul_eval_count {
            return None;
        }
        let (eval_ring_mul_evals, remaining_evals) =
            remaining_evals.split_at(eval_ring_mul_eval_count);
        if remaining_evals.len() < poseidon_r1cs_eval_count {
            return None;
        }
        let (poseidon_r1cs_evals, remaining_evals) =
            remaining_evals.split_at(poseidon_r1cs_eval_count);
        if poseidon_r1cs_evals.len() != poseidon_r1cs_eval_count {
            return None;
        }
        if remaining_evals.len() < ajtai_eval_count {
            return None;
        }
        let (ajtai_evals, original_r1cs_evals) = remaining_evals.split_at(ajtai_eval_count);
        if ajtai_evals.len() != ajtai_eval_count {
            return None;
        }
        if original_r1cs_evals.len() != original_r1cs_eval_count {
            return None;
        }
        if !typed_batched_cp_equality_evals_match(&equality_pairs, equality_evals)
            || !typed_batched_cp_folded_public_input_linear_evals_match(
                &linear_constraints,
                linear_evals,
            )
            || !typed_batched_cp_folded_commitment_ring_mul_evals_match(
                &ring_mul_constraints,
                ring_mul_evals,
            )
            || !typed_batched_cp_folded_evaluation_ring_mul_evals_match(
                &eval_ring_mul_constraints,
                eval_ring_mul_evals,
            )
            || !typed_batched_cp_poseidon_r1cs_evals_match(
                &poseidon_r1cs_constraints,
                poseidon_r1cs_evals,
            )
            || !typed_batched_cp_ajtai_opening_evals_match(&ajtai_constraints, ajtai_evals)
            || !typed_batched_cp_original_r1cs_evals_match(
                &original_r1cs_constraints,
                original_r1cs_evals,
            )
        {
            return None;
        }
        Some(WhirProof {
            sumcheck_rounds_3: Vec::new(),
            sumcheck_rounds_4: Vec::new(),
            evaluations: [z_eval, BabyBear::ZERO, BabyBear::ZERO],
            whir_pcs_proof,
            z_eval,
            linear_checks: Vec::new(),
            private_opening_evals,
            family_columnar_subproofs: Vec::new(),
            num_vars,
            is_output: false,
        })
    }

    fn verify_typed_batched_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool> {
        let context = vk.relation.context.as_ref()?;
        let relation = WhirBatchedCpRelationContext::from_context_bytes(context)?;
        if relation.shape() != &statement.shape
            || relation.public_statement_bytes() != statement.canonical_bytes().len()
        {
            return Some(false);
        }
        if proof.is_output
            || !proof.sumcheck_rounds_3.is_empty()
            || !proof.sumcheck_rounds_4.is_empty()
            || !proof.linear_checks.is_empty()
            || proof.evaluations[0] != proof.z_eval
            || proof.evaluations[1] != BabyBear::ZERO
            || proof.evaluations[2] != BabyBear::ZERO
        {
            return Some(false);
        }
        if let Some(columnar_relation) = relation.columnar_v2() {
            return Some(verify_typed_batched_cp_columnar_v2(
                vk,
                columnar_relation,
                statement,
                proof,
            ));
        }
        if let Some(family_relation) = relation.family_columnar_v2() {
            return Some(verify_typed_batched_cp_family_columnar_v2(
                vk,
                family_relation,
                statement,
                proof,
            ));
        }
        if !proof.family_columnar_subproofs.is_empty() {
            return Some(false);
        }
        let expected_num_vars = typed_batched_cp_oracle_num_vars(relation.shape());
        if proof.num_vars != expected_num_vars {
            return Some(false);
        }
        let point =
            typed_batched_cp_opening_point(&vk.seed, &relation, statement, expected_num_vars);
        let Some((known_points, known_evals)) =
            typed_batched_cp_public_oracle_claims(&statement.shape, statement, expected_num_vars)
        else {
            return Some(false);
        };
        let Some((semantic_value_points, semantic_value_evals)) =
            typed_batched_cp_semantic_packed_value_claims(&relation, statement, expected_num_vars)
        else {
            return Some(false);
        };
        let equality_pairs =
            typed_batched_cp_sampled_equalities(&vk.seed, &relation, statement, 64);
        let Some(equality_points) =
            typed_batched_cp_equality_opening_points(&equality_pairs, expected_num_vars)
        else {
            return Some(false);
        };
        let linear_constraints = typed_batched_cp_sampled_folded_public_input_linear_constraints(
            &vk.seed, &relation, statement, 8,
        );
        let Some(linear_points) =
            typed_batched_cp_linear_opening_points(&linear_constraints, expected_num_vars)
        else {
            return Some(false);
        };
        let ring_mul_constraints = typed_batched_cp_sampled_folded_commitment_ring_mul_constraints(
            &vk.seed, &relation, statement, 2,
        );
        let Some(ring_mul_points) =
            typed_batched_cp_ring_mul_opening_points(&ring_mul_constraints, expected_num_vars)
        else {
            return Some(false);
        };
        let eval_ring_mul_constraints =
            typed_batched_cp_sampled_folded_evaluation_ring_mul_constraints(
                &vk.seed, &relation, statement, 2,
            );
        let Some(eval_ring_mul_points) = typed_batched_cp_eval_ring_mul_opening_points(
            &eval_ring_mul_constraints,
            expected_num_vars,
        ) else {
            return Some(false);
        };
        let poseidon_r1cs_constraints =
            typed_batched_cp_sampled_poseidon_r1cs_constraints(&vk.seed, &relation, statement, 8);
        let Some(poseidon_r1cs_points) = typed_batched_cp_poseidon_r1cs_opening_points(
            &poseidon_r1cs_constraints,
            expected_num_vars,
        ) else {
            return Some(false);
        };
        let ajtai_constraints =
            typed_batched_cp_sampled_ajtai_opening_constraints(&vk.seed, &relation, statement, 2);
        let Some(ajtai_points) =
            typed_batched_cp_ajtai_opening_points(&ajtai_constraints, expected_num_vars)
        else {
            return Some(false);
        };
        let original_r1cs_constraints =
            typed_batched_cp_sampled_original_r1cs_constraints(&vk.seed, &relation, statement, 2);
        let Some(original_r1cs_points) = typed_batched_cp_original_r1cs_opening_points(
            &original_r1cs_constraints,
            expected_num_vars,
        ) else {
            return Some(false);
        };
        if proof.private_opening_evals.len()
            != equality_points.len()
                + linear_points.len()
                + ring_mul_points.len()
                + eval_ring_mul_points.len()
                + poseidon_r1cs_points.len()
                + ajtai_points.len()
                + original_r1cs_points.len()
        {
            return Some(false);
        }
        let (equality_evals, remaining_evals) =
            proof.private_opening_evals.split_at(equality_points.len());
        let (linear_evals, remaining_evals) = remaining_evals.split_at(linear_points.len());
        let (ring_mul_evals, remaining_evals) = remaining_evals.split_at(ring_mul_points.len());
        let (eval_ring_mul_evals, remaining_evals) =
            remaining_evals.split_at(eval_ring_mul_points.len());
        let (poseidon_r1cs_evals, ajtai_evals) =
            remaining_evals.split_at(poseidon_r1cs_points.len());
        let (ajtai_evals, original_r1cs_evals) = ajtai_evals.split_at(ajtai_points.len());
        if !typed_batched_cp_equality_evals_match(&equality_pairs, equality_evals)
            || !typed_batched_cp_folded_public_input_linear_evals_match(
                &linear_constraints,
                linear_evals,
            )
            || !typed_batched_cp_folded_commitment_ring_mul_evals_match(
                &ring_mul_constraints,
                ring_mul_evals,
            )
            || !typed_batched_cp_folded_evaluation_ring_mul_evals_match(
                &eval_ring_mul_constraints,
                eval_ring_mul_evals,
            )
            || !typed_batched_cp_poseidon_r1cs_evals_match(
                &poseidon_r1cs_constraints,
                poseidon_r1cs_evals,
            )
            || !typed_batched_cp_ajtai_opening_evals_match(&ajtai_constraints, ajtai_evals)
            || !typed_batched_cp_original_r1cs_evals_match(
                &original_r1cs_constraints,
                original_r1cs_evals,
            )
        {
            return Some(false);
        }
        let mut opening_points = Vec::with_capacity(
            1 + known_points.len()
                + semantic_value_points.len()
                + equality_points.len()
                + linear_points.len(),
        );
        opening_points.push(point);
        opening_points.extend(known_points);
        opening_points.extend(semantic_value_points);
        opening_points.extend(equality_points);
        opening_points.extend(linear_points);
        opening_points.extend(ring_mul_points);
        opening_points.extend(eval_ring_mul_points);
        opening_points.extend(poseidon_r1cs_points);
        opening_points.extend(ajtai_points);
        opening_points.extend(original_r1cs_points);
        let mut opening_evals = Vec::with_capacity(
            1 + known_evals.len() + semantic_value_evals.len() + proof.private_opening_evals.len(),
        );
        opening_evals.push(proof.z_eval);
        opening_evals.extend(known_evals);
        opening_evals.extend(semantic_value_evals);
        opening_evals.extend(proof.private_opening_evals.iter().copied());
        Some(whir_verify_opening_multi(
            &vk.seed,
            expected_num_vars,
            &proof.whir_pcs_proof,
            &opening_points,
            &opening_evals,
        ))
    }

    fn symbt3_relation_description(
        descriptor: &crate::batched_cp::BatchedCpSymbt3SetupDescriptor,
    ) -> Option<crate::snark::RelationDescription> {
        Some(descriptor.relation_description().to_relation_description())
    }

    fn prove_symbt3_batched_cp(
        pk: &Self::ProvingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    ) -> Option<Self::Proof> {
        prove_symbt3_batched_cp_with_profile(pk, statement, witness, None)
    }

    fn verify_symbt3_batched_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool> {
        verify_symbt3_batched_cp_with_profile(vk, statement, proof, None)
    }

    fn prove_typed_output(
        pk: &Self::ProvingKey,
        instance: &FoldedOutputInstance,
        witness: &FoldedOutputWitness,
    ) -> Option<Self::Proof> {
        let ctx = pk
            .relation
            .context
            .as_ref()
            .and_then(|bytes| deserialize_context(bytes))?;
        if !ctx.is_output_snark || ctx.is_cp_snark {
            return None;
        }
        if !validate_typed_output_relation(instance, witness, &ctx) {
            return None;
        }

        let transcript_instance = crate::snark::cp_snark::encode_folded_output_instance(instance);
        let binding_ctx = typed_output_binding_context(&ctx);
        let binding_instance = typed_output_binding_instance();
        Some(prove_output_with_transcript_instance(
            pk,
            &binding_instance,
            &transcript_instance,
            &[],
            &binding_ctx,
        ))
    }

    fn verify_typed_output(
        vk: &Self::VerifyingKey,
        instance: &FoldedOutputInstance,
        proof: &Self::Proof,
    ) -> Option<bool> {
        let ctx = vk
            .relation
            .context
            .as_ref()
            .and_then(|bytes| deserialize_context(bytes))?;
        if !ctx.is_output_snark || ctx.is_cp_snark {
            return None;
        }
        if !validate_typed_output_public_instance(instance, &ctx) {
            return Some(false);
        }

        let transcript_instance = crate::snark::cp_snark::encode_folded_output_instance(instance);
        let binding_ctx = typed_output_binding_context(&ctx);
        let binding_instance = typed_output_binding_instance();
        Some(verify_output_with_transcript_instance(
            vk,
            &binding_instance,
            &transcript_instance,
            proof,
            &binding_ctx,
        ))
    }

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        // Derive a deterministic seed from the relation description
        let mut hasher = Sha256::new();
        hasher.update(b"whir-setup-v2");
        hasher.update((relation.num_instance_vars as u64).to_le_bytes());
        hasher.update((relation.num_witness_vars as u64).to_le_bytes());
        hasher.update((relation.num_constraints as u64).to_le_bytes());
        if let Some(ref ctx_bytes) = relation.context {
            hasher.update((ctx_bytes.len() as u64).to_le_bytes());
            hasher.update(ctx_bytes);
        }
        let seed: [u8; 32] = hasher.finalize().into();

        let context_hash = compute_context_hash(&relation.context);

        (
            WhirProvingKey {
                seed,
                context_hash,
                relation: relation.clone(),
            },
            WhirVerifyingKey {
                seed,
                context_hash,
                relation: relation.clone(),
            },
        )
    }

    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof {
        let current_hash = compute_context_hash(&pk.relation.context);
        assert_eq!(
            current_hash, pk.context_hash,
            "WHIR: context was modified after setup"
        );

        if let Some(ref ctx_bytes) = pk.relation.context {
            if let Some(ctx) = deserialize_context(ctx_bytes) {
                if ctx.is_output_snark {
                    return prove_output(pk, instance, witness, &ctx);
                }
                if ctx.is_cp_snark {
                    return prove_cp_r1cs(pk, instance, witness, &ctx);
                }
            }
        }
        prove_cp(pk, instance, witness)
    }

    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool {
        let current_hash = compute_context_hash(&vk.relation.context);
        if current_hash != vk.context_hash {
            return false;
        }

        if let Some(ref ctx_bytes) = vk.relation.context {
            if let Some(ctx) = deserialize_context(ctx_bytes) {
                if ctx.is_output_snark {
                    return verify_output(vk, instance, proof, &ctx);
                }
                if ctx.is_cp_snark {
                    return verify_cp_r1cs(vk, instance, proof, &ctx);
                }
            }
        }
        verify_cp(vk, instance, proof)
    }
}

fn prove_symbt3_batched_cp_with_profile(
    pk: &WhirProvingKey,
    statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
    witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    mut profile: Option<&mut Symbt3ProverCostProfile>,
) -> Option<WhirProof> {
    let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
        pk.relation.context.as_ref()?,
    )
    .ok()?;
    if !statement.matches_relation(&relation)
        || statement.canonical_bytes().len() != relation.public_statement_bytes()
        || witness.message_oracles.len() != relation.oracle_layout.message_oracles.len()
        || !relation.has_symbt3_i_families()
    {
        return None;
    }

    let claims_start = std::time::Instant::now();
    let claims =
        symbt3_c_table_and_claims(&pk.seed, &relation, statement, Some(witness), None, None)?;
    let claims_ms = elapsed_ms(claims_start);
    if let Some(profile) = profile.as_deref_mut() {
        profile.prove_constraint_construction_ms += claims_ms;
        profile.prove_constraint_batching_ms += claims.eval_profile.verify_sumcheck_rounds_ms;
        profile.prove_field_ops_ms += claims_ms;
        profile.prove_allocations_copies_ms += claims_ms;
    }

    let table = claims.table.as_ref()?;
    let (whir_pcs_proof, evals) = whir_commit_and_prove_multi_with_profile(
        &pk.seed,
        claims.num_vars,
        table,
        &claims.points,
        profile.as_deref_mut(),
    );
    if evals != claims.claimed {
        return None;
    }

    Some(WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: claims.product_sumcheck_rounds,
        evaluations: claims.evaluations,
        whir_pcs_proof,
        z_eval: claims.z_eval,
        linear_checks: Vec::new(),
        private_opening_evals: claims.claimed,
        family_columnar_subproofs: Vec::new(),
        num_vars: claims.num_vars,
        is_output: false,
    })
}

impl WhirSnark {
    /// Prove a SYMBT3 public statement and return coarse prover-cost
    /// attribution for benchmark hygiene.
    #[must_use]
    pub fn profile_symbt3_batched_cp_prover(
        pk: &WhirProvingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    ) -> Option<(WhirProof, Symbt3ProverCostProfile)> {
        let total_start = std::time::Instant::now();
        let mut profile = Symbt3ProverCostProfile::default();
        let proof = prove_symbt3_batched_cp_with_profile(
            pk,
            statement,
            witness,
            Some(&mut profile),
        )?;
        profile.prove_total_ms = elapsed_ms(total_start);
        Some((proof, profile))
    }

    /// Prove through the explicit opt-in K6a NonZK integrity accumulator route
    /// and return benchmark attribution.
    ///
    /// This is a profiling helper for the non-default product-integrity route.
    /// It does not change product `verify_public` routing and does not add
    /// fields to the public proof object.
    #[must_use]
    pub fn profile_public_symbt3_accumulator_non_zk_integrity_prover(
        pk: &WhirProvingKey,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
        accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
        witness: &crate::batched_cp::Symbt3AccumulatorWitness,
    ) -> Option<(WhirProof, Symbt3ProverCostProfile)> {
        let total_start = std::time::Instant::now();
        let mut cost = Symbt3ProverCostProfile::default();
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            pk.relation.context.as_ref()?,
        )
        .ok()?;
        let glue_start = std::time::Instant::now();
        let statement = symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        )?;
        let witness = witness.to_symbt3_witness(&relation)?;
        cost.prove_accumulator_glue_ms += elapsed_ms(glue_start);
        let proof =
            prove_symbt3_batched_cp_with_profile(pk, &statement, &witness, Some(&mut cost))?;
        cost.prove_total_ms = elapsed_ms(total_start);
        Some((proof, cost))
    }

    /// Verify through the explicit opt-in K6a NonZK integrity accumulator route
    /// and return benchmark attribution.
    #[must_use]
    pub fn profile_public_symbt3_accumulator_non_zk_integrity_verifier(
        vk: &WhirVerifyingKey,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
        accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
        proof_kind: crate::batched_cp::ProductProofKind,
        proof: &WhirProof,
    ) -> Option<(bool, Symbt3VerifierCostProfile)> {
        let total_start = std::time::Instant::now();
        let mut cost = Symbt3VerifierCostProfile::default();
        let proof_decode_start = std::time::Instant::now();
        if proof_kind != crate::batched_cp::ProductProofKind::Symbt3AccumulatorNonZkIntegrity
            || proof.is_output
            || !proof.sumcheck_rounds_3.is_empty()
            || !proof.linear_checks.is_empty()
            || !proof.family_columnar_subproofs.is_empty()
        {
            cost.verify_proof_deserialization_ms += elapsed_ms(proof_decode_start);
            cost.verify_total_ms = elapsed_ms(total_start);
            return Some((false, cost));
        }
        cost.verify_proof_deserialization_ms += elapsed_ms(proof_decode_start);

        let decode_start = std::time::Instant::now();
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            vk.relation.context.as_ref()?,
        )
        .ok()?;
        let Some(statement) = symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        ) else {
            cost.verify_accumulator_decoding_ms += elapsed_ms(decode_start);
            cost.verify_total_ms = elapsed_ms(total_start);
            return Some((false, cost));
        };
        let decode_ms = elapsed_ms(decode_start);
        cost.verify_accumulator_decoding_ms += decode_ms;
        cost.verify_public_input_parsing_ms += decode_ms;

        let ok = verify_symbt3_batched_cp_with_profile(vk, &statement, proof, Some(&mut cost))?;
        cost.verify_total_ms = elapsed_ms(total_start);
        Some((ok, cost))
    }

    /// Verify a SYMBT3 development proof and return coarse verifier-cost
    /// attribution for architecture benchmarks.
    #[must_use]
    pub fn profile_symbt3_batched_cp_verifier(
        vk: &WhirVerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        proof: &WhirProof,
    ) -> Option<(bool, Symbt3VerifierCostProfile)> {
        let mut profile = Symbt3VerifierCostProfile::default();
        let ok = verify_symbt3_batched_cp_with_profile(vk, statement, proof, Some(&mut profile))?;
        Some((ok, profile))
    }

    /// Authority-profile gate for SYMBT3.
    ///
    /// This deliberately does not affect product routing. Current SYMBT3
    /// development proofs fail this gate because the profile still requires a
    /// production soundness/ZK posture before promotion.
    #[must_use]
    pub fn verify_symbt3_authority_profile(
        vk: &WhirVerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        proof: &WhirProof,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
    ) -> Option<bool> {
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            vk.relation.context.as_ref()?,
        )
        .ok()?;
        if !profile.accepts_statement_for_product_authority(&relation, statement) {
            return Some(false);
        }
        verify_symbt3_batched_cp_with_profile(vk, statement, proof, None)
    }

    /// Research-only SYMBT3 authority-candidate gate.
    ///
    /// This permits non-ZK, non-product SYMBT3-J2 proofs to pass an
    /// authority-style semantic gate for benchmarks and research comparisons
    /// without making them product-route eligible.
    #[must_use]
    pub fn verify_symbt3_research_authority_candidate(
        vk: &WhirVerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        proof: &WhirProof,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
    ) -> Option<bool> {
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            vk.relation.context.as_ref()?,
        )
        .ok()?;
        if !profile.accepts_statement_for_research_authority_candidate(&relation, statement) {
            return Some(false);
        }
        verify_symbt3_batched_cp_with_profile(vk, statement, proof, None)
    }

    /// Research-only SYMBT3 K3 accumulator-soundness authority-candidate gate helper.
    ///
    /// This enforces the semantic-profile-version-1 K1/K2/K3 policy and
    /// soundness metadata gate, but it remains separate from ProductAuthority
    /// and does not alter product `verify_public` routing. It still verifies
    /// an existing SYMBT3 public statement and proof; it is not the K4 public
    /// accumulator API because it does not accept a `Symbt3AccumulatorInstance`
    /// boundary directly.
    #[must_use]
    pub fn verify_symbt3_accumulator_soundness_authority_candidate(
        vk: &WhirVerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        proof: &WhirProof,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
    ) -> Option<bool> {
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            vk.relation.context.as_ref()?,
        )
        .ok()?;
        if !profile
            .accepts_statement_for_accumulator_soundness_authority_candidate(&relation, statement)
        {
            return Some(false);
        }
        verify_symbt3_batched_cp_with_profile(vk, statement, proof, None)
    }

    /// NonZK: may reveal WHIR-queried private coordinates at query positions.
    ///
    /// Not a zkSNARK. Research-only accumulator soundness path. Requires
    /// `routing_status=ResearchOnly`, `product_eligible=false`, and the K3
    /// `AccumulatorSoundnessAuthorityCandidateV1` profile gate. This is not
    /// product `verify_public` routing.
    #[must_use]
    pub fn prove_public_symbt3_accumulator_research_non_zk(
        pk: &WhirProvingKey,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
        accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
        witness: &crate::batched_cp::Symbt3AccumulatorWitness,
    ) -> Option<WhirProof> {
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            pk.relation.context.as_ref()?,
        )
        .ok()?;
        let statement = symbt3_accumulator_research_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        )?;
        let witness = witness.to_symbt3_witness(&relation)?;
        <WhirSnark as crate::cp_backend_api::CpBackend>::prove_symbt3_batched_cp(
            pk, &statement, &witness,
        )
    }

    /// NonZK: may reveal WHIR-queried private coordinates at query positions.
    ///
    /// Not a zkSNARK. Research-only accumulator soundness path. Requires
    /// `routing_status=ResearchOnly`, `product_eligible=false`, and the K3
    /// `AccumulatorSoundnessAuthorityCandidateV1` profile gate. This is not
    /// product `verify_public` routing.
    #[must_use]
    pub fn verify_public_symbt3_accumulator_research_non_zk(
        vk: &WhirVerifyingKey,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
        accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
        proof: &WhirProof,
    ) -> bool {
        let Some(relation) = vk.relation.context.as_ref().and_then(|context| {
            crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(context).ok()
        }) else {
            return false;
        };
        let Some(statement) = symbt3_accumulator_research_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        ) else {
            return false;
        };
        verify_symbt3_batched_cp_with_profile(vk, &statement, proof, None).unwrap_or(false)
    }

    /// Build a K6a explicit accumulator proof.
    ///
    /// NonZK: may reveal WHIR-queried private coordinates at query positions.
    ///
    /// This is the explicit opt-in K6a product-integrity SYMBT3 accumulator
    /// route. It requires `routing_status=ProductAuthority`,
    /// `product_eligible=true`, `zk_status=NonZkIntegrityOnly`, and the K6a
    /// NonZK product policy. It does **not** alter the default monolithic
    /// typed-CP `verify_public` route and it must not be described as a
    /// privacy-preserving proof.
    #[must_use]
    pub fn prove_public_symbt3_accumulator_non_zk_integrity(
        pk: &WhirProvingKey,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
        accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
        witness: &crate::batched_cp::Symbt3AccumulatorWitness,
    ) -> Option<WhirProof> {
        let relation = crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(
            pk.relation.context.as_ref()?,
        )
        .ok()?;
        let statement = symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        )?;
        let witness = witness.to_symbt3_witness(&relation)?;
        <WhirSnark as crate::cp_backend_api::CpBackend>::prove_symbt3_batched_cp(
            pk, &statement, &witness,
        )
    }

    /// Verify a K6a explicit accumulator proof.
    ///
    /// NonZK: may reveal WHIR-queried private coordinates at query positions.
    ///
    /// This verifies only the explicit opt-in K6a product-integrity route. The
    /// proof-kind discriminator must be
    /// `ProductProofKind::Symbt3AccumulatorNonZkIntegrity`; wrong or legacy
    /// proof kinds fail closed with no monolithic fallback. This function does
    /// **not** dispatch to the default product `verify_public` boundary.
    #[must_use]
    pub fn verify_public_symbt3_accumulator_non_zk_integrity(
        vk: &WhirVerifyingKey,
        profile: &crate::batched_cp::Symbt3AuthorityProfile,
        accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
        proof_kind: crate::batched_cp::ProductProofKind,
        proof: &WhirProof,
    ) -> bool {
        if proof_kind != crate::batched_cp::ProductProofKind::Symbt3AccumulatorNonZkIntegrity {
            return false;
        }
        if proof.is_output
            || !proof.sumcheck_rounds_3.is_empty()
            || !proof.linear_checks.is_empty()
            || !proof.family_columnar_subproofs.is_empty()
        {
            return false;
        }
        let Some(relation) = vk.relation.context.as_ref().and_then(|context| {
            crate::batched_cp::BatchedCpSymbt3RelationDescription::from_context_bytes(context).ok()
        }) else {
            return false;
        };
        let Some(statement) = symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
            profile,
            accumulator_instance,
            &relation,
        ) else {
            return false;
        };
        verify_symbt3_batched_cp_with_profile(vk, &statement, proof, None).unwrap_or(false)
    }
}

fn symbt3_accumulator_research_statement_for_relation(
    profile: &crate::batched_cp::Symbt3AuthorityProfile,
    accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
) -> Option<crate::batched_cp::BatchedCpSymbt3PublicStatement> {
    symbt3_accumulator_statement_for_relation(
        profile,
        accumulator_instance,
        relation,
        Symbt3AccumulatorStatementPolicy::ResearchAccumulatorSoundnessV1,
    )
}

fn symbt3_accumulator_product_non_zk_integrity_statement_for_relation(
    profile: &crate::batched_cp::Symbt3AuthorityProfile,
    accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
) -> Option<crate::batched_cp::BatchedCpSymbt3PublicStatement> {
    symbt3_accumulator_statement_for_relation(
        profile,
        accumulator_instance,
        relation,
        Symbt3AccumulatorStatementPolicy::ProductNonZkIntegrityK6a,
    )
}

#[derive(Debug, Clone, Copy)]
enum Symbt3AccumulatorStatementPolicy {
    ResearchAccumulatorSoundnessV1,
    ProductNonZkIntegrityK6a,
}

fn symbt3_accumulator_statement_for_relation(
    profile: &crate::batched_cp::Symbt3AuthorityProfile,
    accumulator_instance: &crate::batched_cp::Symbt3AccumulatorInstance,
    relation: &crate::batched_cp::BatchedCpSymbt3RelationDescription,
    policy: Symbt3AccumulatorStatementPolicy,
) -> Option<crate::batched_cp::BatchedCpSymbt3PublicStatement> {
    let profile_ok = match policy {
        Symbt3AccumulatorStatementPolicy::ResearchAccumulatorSoundnessV1 => {
            profile.routing_status == crate::batched_cp::Symbt3RoutingStatus::ResearchOnly
                && !profile.product_eligible
                && profile.research_only
                && profile.zk_status == crate::batched_cp::Symbt3ZkStatus::NonZkDevelopment
                && crate::batched_cp::profile_meets_accumulator_soundness_authority(profile)
                && profile.accepts_relation_for_accumulator_soundness_authority_candidate(relation)
        }
        Symbt3AccumulatorStatementPolicy::ProductNonZkIntegrityK6a => {
            profile.routing_status == crate::batched_cp::Symbt3RoutingStatus::ProductAuthority
                && profile.product_eligible
                && !profile.research_only
                && profile.zk_status == crate::batched_cp::Symbt3ZkStatus::NonZkIntegrityOnly
                && crate::batched_cp::product_policy_accepts_non_zk(profile)
                && crate::batched_cp::profile_meets_accumulator_soundness_non_zk_integrity_product(
                    profile,
                )
                && profile.accepts_relation_for_non_zk_integrity_product_authority(relation)
        }
    };
    if !profile_ok
        || profile.semantic_profile_version < 1
        || !accumulator_instance.matches_profile_and_relation(profile, relation)
    {
        return None;
    }
    let statement = accumulator_instance.to_public_statement();
    let statement_ok = match policy {
        Symbt3AccumulatorStatementPolicy::ResearchAccumulatorSoundnessV1 => profile
            .accepts_statement_for_accumulator_soundness_authority_candidate(relation, &statement),
        Symbt3AccumulatorStatementPolicy::ProductNonZkIntegrityK6a => {
            profile.accepts_statement_for_non_zk_integrity_product_authority(relation, &statement)
        }
    };
    if statement_ok {
        Some(statement)
    } else {
        None
    }
}
