struct WhirBatchedCpByteEqualityBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    equalities: Vec<crate::batched_cp::BatchedCpOracleByteEquality>,
}

struct WhirBatchedCpPackedValueBlock {
    values: Vec<crate::batched_cp::BatchedCpOraclePackedValue>,
}

struct WhirBatchedCpFoldedPublicInputLinearBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    constraints: Vec<crate::batched_cp::BatchedCpFoldedPublicInputLinearConstraint>,
}

struct WhirBatchedCpFoldedCommitmentRingMulBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    constraints: Vec<crate::batched_cp::BatchedCpFoldedCommitmentRingMulConstraint>,
}

struct WhirBatchedCpFoldedEvaluationRingMulBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    constraints: Vec<crate::batched_cp::BatchedCpFoldedEvaluationRingMulConstraint>,
}

struct WhirBatchedCpPoseidonR1csBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    surfaces: Vec<crate::batched_cp::BatchedCpPoseidonR1csSurface>,
}

struct WhirBatchedCpAjtaiOpeningBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    constraints: Vec<crate::batched_cp::BatchedCpAjtaiOpeningLinearConstraint>,
}

struct WhirBatchedCpOriginalR1csBlock {
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    label: &'static str,
    constraints: Vec<crate::batched_cp::BatchedCpOriginalR1csConstraint>,
}

#[derive(Debug, Clone)]
struct WhirBatchedCpColumnarV2Check {
    residual_index: usize,
    row: usize,
    kind: crate::batched_cp::BatchedCpSemanticResidualV2Kind,
    columns: Vec<usize>,
}

const COLUMNAR_V2_CHECKS_PER_RESIDUAL: usize = 4;

fn prove_typed_batched_cp_columnar_v2(
    pk: &WhirProvingKey,
    relation: &crate::batched_cp::BatchedCpSemanticColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    witness: &crate::batched_cp::BatchedCpWitnessBundle,
) -> Option<WhirProof> {
    let trace =
        crate::batched_cp::BatchedCpSemanticTraceV2::encode(relation, statement, witness).ok()?;
    if !trace.all_residuals_satisfied() {
        return None;
    }
    let mut table: Vec<BabyBear> = trace
        .flattened_values()
        .into_iter()
        .map(BabyBear::from_u32)
        .collect();
    pad_to_power_of_two(&mut table);
    if table.len() < 2 {
        table.resize(2, BabyBear::ZERO);
    }
    let num_vars = table.len().trailing_zeros() as usize;
    let relation_context = WhirBatchedCpRelationContext::ColumnarV2(relation.clone());
    let point = typed_batched_cp_opening_point(&pk.seed, &relation_context, statement, num_vars);
    let z_eval = mle_eval_bb(&table, &point);
    let checks = typed_batched_cp_columnar_v2_checks(&pk.seed, relation, statement);
    let opening_points = typed_batched_cp_columnar_v2_opening_points(&trace, &checks, num_vars)?;
    let mut all_points = Vec::with_capacity(1 + opening_points.len());
    all_points.push(point);
    all_points.extend(opening_points);
    let (whir_pcs_proof, evals) =
        whir_commit_and_prove_multi(&pk.seed, num_vars, &table, &all_points);
    let private_eval_count: usize = checks.iter().map(|check| check.columns.len()).sum();
    if evals.first().copied() != Some(z_eval) || evals.len() != 1 + private_eval_count {
        return None;
    }
    let private_opening_evals = evals[1..].to_vec();
    if !typed_batched_cp_columnar_v2_evals_match(&checks, &private_opening_evals) {
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

fn verify_typed_batched_cp_columnar_v2(
    vk: &WhirVerifyingKey,
    relation: &crate::batched_cp::BatchedCpSemanticColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    proof: &WhirProof,
) -> bool {
    if !proof.family_columnar_subproofs.is_empty() {
        return false;
    }
    let expected_len =
        relation.columnar_layout.columns.len() * relation.columnar_layout.column_row_count;
    let expected_num_vars = expected_len.next_power_of_two().max(2).trailing_zeros() as usize;
    if proof.num_vars != expected_num_vars {
        return false;
    }
    let checks = typed_batched_cp_columnar_v2_checks(&vk.seed, relation, statement);
    let Some(opening_points) = typed_batched_cp_columnar_v2_opening_points_from_layout(
        &relation.columnar_layout,
        &checks,
        expected_num_vars,
    ) else {
        return false;
    };
    let private_eval_count: usize = checks.iter().map(|check| check.columns.len()).sum();
    if proof.private_opening_evals.len() != private_eval_count
        || !typed_batched_cp_columnar_v2_evals_match(&checks, &proof.private_opening_evals)
    {
        return false;
    }
    let relation_context = WhirBatchedCpRelationContext::ColumnarV2(relation.clone());
    let point =
        typed_batched_cp_opening_point(&vk.seed, &relation_context, statement, expected_num_vars);
    let mut all_points = Vec::with_capacity(1 + opening_points.len());
    all_points.push(point);
    all_points.extend(opening_points);
    let mut all_evals = Vec::with_capacity(1 + proof.private_opening_evals.len());
    all_evals.push(proof.z_eval);
    all_evals.extend(proof.private_opening_evals.iter().copied());
    whir_verify_opening_multi(
        &vk.seed,
        expected_num_vars,
        &proof.whir_pcs_proof,
        &all_points,
        &all_evals,
    )
}

fn prove_typed_batched_cp_family_columnar_v2(
    pk: &WhirProvingKey,
    relation: &crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    witness: &crate::batched_cp::BatchedCpWitnessBundle,
) -> Option<WhirProof> {
    let trace =
        crate::batched_cp::BatchedCpSemanticFamilyTraceV2::encode(relation, statement, witness)
            .ok()?;
    if !trace.all_residuals_satisfied() {
        return None;
    }
    let checks = typed_batched_cp_family_columnar_v2_checks(&pk.seed, relation, statement);
    let mut private_opening_evals = Vec::new();
    let mut family_columnar_subproofs = Vec::new();
    let mut max_num_vars = 0usize;
    for (table_idx, table_layout) in trace.layout.tables.iter().enumerate() {
        let table_checks = checks
            .iter()
            .filter(|check| check.residual_index == table_idx)
            .cloned()
            .collect::<Vec<_>>();
        if table_checks.is_empty() {
            continue;
        }
        let mut table = typed_batched_cp_family_columnar_v2_table_values(&trace, table_idx)?;
        if table.len() < 2 {
            table.resize(2, BabyBear::ZERO);
        }
        let num_vars = table.len().trailing_zeros() as usize;
        debug_assert_eq!(table.len(), 1usize << num_vars);
        max_num_vars = max_num_vars.max(num_vars);
        let point = typed_batched_cp_family_columnar_v2_table_point(
            &pk.seed, relation, statement, table_idx, num_vars,
        );
        let z_eval = mle_eval_bb_fast(&table, &point);
        let opening_points = typed_batched_cp_family_columnar_v2_opening_points_for_table(
            table_layout,
            &table_checks,
            num_vars,
        )?;
        let mut all_points = Vec::with_capacity(1 + opening_points.len());
        all_points.push(point);
        all_points.extend(opening_points);
        let (whir_pcs_proof, evals) =
            whir_commit_and_prove_multi(&pk.seed, num_vars, &table, &all_points);
        let private_eval_count: usize = table_checks.iter().map(|check| check.columns.len()).sum();
        if evals.first().copied() != Some(z_eval) || evals.len() != 1 + private_eval_count {
            return None;
        }
        private_opening_evals.extend_from_slice(&evals[1..]);
        family_columnar_subproofs.push(WhirFamilyColumnarSubproof {
            table_index: table_idx,
            num_vars,
            z_eval,
            whir_pcs_proof,
        });
    }
    if !typed_batched_cp_columnar_v2_evals_match(&checks, &private_opening_evals) {
        return None;
    }
    Some(WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: Vec::new(),
        evaluations: [BabyBear::ZERO, BabyBear::ZERO, BabyBear::ZERO],
        whir_pcs_proof: WhirPcsProof::<F, EF, WhirMmcs>::default(),
        z_eval: BabyBear::ZERO,
        linear_checks: Vec::new(),
        private_opening_evals,
        family_columnar_subproofs,
        num_vars: max_num_vars,
        is_output: false,
    })
}

fn verify_typed_batched_cp_family_columnar_v2(
    vk: &WhirVerifyingKey,
    relation: &crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    proof: &WhirProof,
) -> bool {
    verify_typed_batched_cp_family_columnar_v2_with_stats(vk, relation, statement, proof).0
}

fn verify_typed_batched_cp_family_columnar_v2_with_stats(
    vk: &WhirVerifyingKey,
    relation: &crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    proof: &WhirProof,
) -> (bool, WhirVerifierInfraCacheStats) {
    if proof.family_columnar_subproofs.is_empty() {
        return (false, WhirVerifierInfraCacheStats::default());
    }
    let checks = typed_batched_cp_family_columnar_v2_checks(&vk.seed, relation, statement);
    let private_eval_count: usize = checks.iter().map(|check| check.columns.len()).sum();
    if proof.private_opening_evals.len() != private_eval_count
        || !typed_batched_cp_columnar_v2_evals_match(&checks, &proof.private_opening_evals)
    {
        return (false, WhirVerifierInfraCacheStats::default());
    }
    let expected_subproof_count = relation
        .family_layout
        .tables
        .iter()
        .enumerate()
        .filter(|(table_idx, _)| {
            checks
                .iter()
                .any(|check| check.residual_index == *table_idx)
        })
        .count();
    if proof.family_columnar_subproofs.len() != expected_subproof_count {
        return (false, WhirVerifierInfraCacheStats::default());
    }
    let mut cache = WhirVerifierInfraCache::default();
    let mut eval_offset = 0usize;
    let mut subproof_offset = 0usize;
    let mut max_num_vars = 0usize;
    for (table_idx, table) in relation.family_layout.tables.iter().enumerate() {
        let table_checks = checks
            .iter()
            .filter(|check| check.residual_index == table_idx)
            .cloned()
            .collect::<Vec<_>>();
        if table_checks.is_empty() {
            continue;
        }
        let Some(subproof) = proof.family_columnar_subproofs.get(subproof_offset) else {
            return (false, cache.stats());
        };
        if subproof.table_index != table_idx {
            return (false, cache.stats());
        }
        let expected_len = (table.column_kinds.len() * table.padded_row_count)
            .next_power_of_two()
            .max(2);
        let expected_num_vars = expected_len.trailing_zeros() as usize;
        if subproof.num_vars != expected_num_vars {
            return (false, cache.stats());
        }
        max_num_vars = max_num_vars.max(expected_num_vars);
        let Some(opening_points) = typed_batched_cp_family_columnar_v2_opening_points_for_table(
            table,
            &table_checks,
            expected_num_vars,
        ) else {
            return (false, cache.stats());
        };
        let private_eval_len = table_checks
            .iter()
            .map(|check| check.columns.len())
            .sum::<usize>();
        let Some(private_evals) = proof
            .private_opening_evals
            .get(eval_offset..eval_offset + private_eval_len)
        else {
            return (false, cache.stats());
        };
        let point = typed_batched_cp_family_columnar_v2_table_point(
            &vk.seed,
            relation,
            statement,
            table_idx,
            expected_num_vars,
        );
        let mut all_points = Vec::with_capacity(1 + opening_points.len());
        all_points.push(point);
        all_points.extend(opening_points);
        let mut all_evals = Vec::with_capacity(1 + private_evals.len());
        all_evals.push(subproof.z_eval);
        all_evals.extend(private_evals.iter().copied());
        if !cache.verify_opening_multi(
            &vk.seed,
            expected_num_vars,
            &subproof.whir_pcs_proof,
            &all_points,
            &all_evals,
        ) {
            return (false, cache.stats());
        }
        eval_offset += private_eval_len;
        subproof_offset += 1;
    }
    (
        eval_offset == proof.private_opening_evals.len()
            && subproof_offset == proof.family_columnar_subproofs.len()
            && proof.num_vars == max_num_vars,
        cache.stats(),
    )
}

fn typed_batched_cp_columnar_v2_checks(
    seed: &[u8; 32],
    relation: &crate::batched_cp::BatchedCpSemanticColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
) -> Vec<WhirBatchedCpColumnarV2Check> {
    let relation_id = relation.semantic_relation_id();
    let statement_bytes = statement.canonical_bytes();
    let mut checks = Vec::new();
    for (residual_index, residual) in relation.columnar_layout.residuals.iter().enumerate() {
        if residual.row_count == 0 {
            continue;
        }
        let target_checks = COLUMNAR_V2_CHECKS_PER_RESIDUAL.min(residual.row_count);
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"whir-typed-batched-cp-columnar-v2-residual-v1");
        transcript.extend_from_slice(seed);
        transcript.extend_from_slice(&relation_id);
        transcript.extend_from_slice(&(residual_index as u64).to_le_bytes());
        transcript.push(typed_batched_cp_semantic_family_code(residual.family));
        transcript.extend_from_slice(&(residual.label.len() as u64).to_le_bytes());
        transcript.extend_from_slice(residual.label.as_bytes());
        transcript.extend_from_slice(&(residual.transcript_label.len() as u64).to_le_bytes());
        transcript.extend_from_slice(&residual.transcript_label);
        transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
        transcript.extend_from_slice(&statement_bytes);
        transcript.extend_from_slice(&(residual.row_count as u64).to_le_bytes());
        transcript.extend_from_slice(&(target_checks as u64).to_le_bytes());
        let mut seen = std::collections::BTreeSet::new();
        let mut counter = 0usize;
        while seen.len() < target_checks {
            let challenge = derive_challenge(&transcript, counter, b"columnar-residual-row")
                .as_canonical_u32() as usize;
            seen.insert(challenge % residual.row_count);
            counter += 1;
        }
        let mut columns = vec![residual.left_column];
        columns.extend(residual.aux_columns.iter().copied());
        columns.push(residual.right_column);
        checks.extend(seen.into_iter().map(|row| WhirBatchedCpColumnarV2Check {
            residual_index,
            row,
            kind: residual.kind,
            columns: columns.clone(),
        }));
    }
    checks.sort_by_key(|check| (check.residual_index, check.row));
    checks
}

fn typed_batched_cp_family_columnar_v2_checks(
    seed: &[u8; 32],
    relation: &crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
) -> Vec<WhirBatchedCpColumnarV2Check> {
    let relation_id = relation.semantic_relation_id();
    let statement_bytes = statement.canonical_bytes();
    let mut checks = Vec::new();
    for (table_idx, table) in relation.family_layout.tables.iter().enumerate() {
        if table.row_count == 0 {
            continue;
        }
        let target_checks = COLUMNAR_V2_CHECKS_PER_RESIDUAL.min(table.row_count);
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"whir-typed-batched-cp-family-columnar-v2-residual-v1");
        transcript.extend_from_slice(seed);
        transcript.extend_from_slice(&relation_id);
        transcript.extend_from_slice(&(table_idx as u64).to_le_bytes());
        transcript.push(typed_batched_cp_semantic_family_code(table.family));
        transcript.extend_from_slice(&(table.label.len() as u64).to_le_bytes());
        transcript.extend_from_slice(table.label.as_bytes());
        transcript.extend_from_slice(&(table.transcript_label.len() as u64).to_le_bytes());
        transcript.extend_from_slice(&table.transcript_label);
        transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
        transcript.extend_from_slice(&statement_bytes);
        transcript.extend_from_slice(&(table.row_count as u64).to_le_bytes());
        transcript.extend_from_slice(&(table.padded_row_count as u64).to_le_bytes());
        transcript.extend_from_slice(&(target_checks as u64).to_le_bytes());
        let mut seen = std::collections::BTreeSet::new();
        let mut counter = 0usize;
        while seen.len() < target_checks {
            let challenge = derive_challenge(&transcript, counter, b"family-columnar-residual-row")
                .as_canonical_u32() as usize;
            seen.insert(challenge % table.row_count);
            counter += 1;
        }
        let columns = (0..table.column_kinds.len()).collect::<Vec<_>>();
        checks.extend(seen.into_iter().map(|row| WhirBatchedCpColumnarV2Check {
            residual_index: table_idx,
            row,
            kind: table.kind,
            columns: columns.clone(),
        }));
    }
    checks.sort_by_key(|check| (check.residual_index, check.row));
    checks
}

fn typed_batched_cp_columnar_v2_opening_points(
    trace: &crate::batched_cp::BatchedCpSemanticTraceV2,
    checks: &[WhirBatchedCpColumnarV2Check],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    typed_batched_cp_columnar_v2_opening_points_from_layout(&trace.layout, checks, num_vars)
}

fn typed_batched_cp_family_columnar_v2_table_values(
    trace: &crate::batched_cp::BatchedCpSemanticFamilyTraceV2,
    table_idx: usize,
) -> Option<Vec<BabyBear>> {
    let table = trace.layout.tables.get(table_idx)?;
    let columns = trace.tables.get(table_idx)?;
    if columns.len() != table.column_kinds.len() {
        return None;
    }
    let len = (table.column_kinds.len() * table.padded_row_count)
        .next_power_of_two()
        .max(2);
    let mut values = vec![BabyBear::ZERO; len];
    for (column_idx, column) in columns.iter().enumerate() {
        if column.len() != table.padded_row_count {
            return None;
        }
        let start = column_idx * table.padded_row_count;
        for (row, value) in column.iter().enumerate() {
            values[start + row] = BabyBear::from_u32(*value);
        }
    }
    Some(values)
}

fn typed_batched_cp_family_columnar_v2_table_point(
    seed: &[u8; 32],
    relation: &crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Description,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    table_idx: usize,
    num_vars: usize,
) -> Vec<BabyBear> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-family-columnar-v2-table-point-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(&relation.semantic_relation_id());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(table_idx as u64).to_le_bytes());
    transcript.extend_from_slice(&(num_vars as u64).to_le_bytes());
    (0..num_vars)
        .map(|idx| derive_challenge(&transcript, idx, b"table-point"))
        .collect()
}

fn typed_batched_cp_columnar_v2_opening_points_from_layout(
    layout: &crate::batched_cp::BatchedCpSemanticColumnarV2Layout,
    checks: &[WhirBatchedCpColumnarV2Check],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::with_capacity(checks.iter().map(|check| check.columns.len()).sum());
    for check in checks {
        if check.row >= layout.column_row_count {
            return None;
        }
        for &column in &check.columns {
            if column >= layout.columns.len() {
                return None;
            }
            let index = column
                .checked_mul(layout.column_row_count)?
                .checked_add(check.row)?;
            if index >= max_index {
                return None;
            }
            points.push(boolean_point_for_index(index, num_vars));
        }
    }
    Some(points)
}

fn typed_batched_cp_family_columnar_v2_opening_points_for_table(
    table: &crate::batched_cp::BatchedCpSemanticFamilyColumnarV2Table,
    checks: &[WhirBatchedCpColumnarV2Check],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::with_capacity(checks.iter().map(|check| check.columns.len()).sum());
    for check in checks {
        if check.row >= table.row_count {
            return None;
        }
        for &column in &check.columns {
            if column >= table.column_kinds.len() {
                return None;
            }
            let index = column
                .checked_mul(table.padded_row_count)?
                .checked_add(check.row)?;
            if index >= max_index {
                return None;
            }
            points.push(boolean_point_for_index(index, num_vars));
        }
    }
    Some(points)
}

fn typed_batched_cp_columnar_v2_evals_match(
    checks: &[WhirBatchedCpColumnarV2Check],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for check in checks {
        match check.kind {
            crate::batched_cp::BatchedCpSemanticResidualV2Kind::Equality => {
                if check.columns.len() != 2 {
                    return false;
                }
                let Some(left) = evals.get(pos).copied() else {
                    return false;
                };
                let Some(right) = evals.get(pos + 1).copied() else {
                    return false;
                };
                pos += 2;
                if left != right {
                    return false;
                }
            }
            crate::batched_cp::BatchedCpSemanticResidualV2Kind::Product => {
                if check.columns.len() != 3 {
                    return false;
                }
                let Some(left) = evals.get(pos).copied() else {
                    return false;
                };
                let Some(aux) = evals.get(pos + 1).copied() else {
                    return false;
                };
                let Some(right) = evals.get(pos + 2).copied() else {
                    return false;
                };
                pos += 3;
                if left * aux != right {
                    return false;
                }
            }
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_public_oracle_claims(
    shape: &crate::batched_cp::BatchedCpStatementShape,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    num_vars: usize,
) -> Option<(Vec<Vec<BabyBear>>, Vec<BabyBear>)> {
    let (bytes, known) =
        shape.canonical_product_oracle_public_byte_template_for_statement(statement)?;
    if bytes.len() != known.len() {
        return None;
    }
    let mut points = Vec::new();
    let mut evals = Vec::new();
    for (chunk_index, chunk) in bytes.chunks(field::BYTES_PER_ELEMENT).enumerate() {
        let start = chunk_index * field::BYTES_PER_ELEMENT;
        let end = start + chunk.len();
        if known[start..end].iter().all(|&value| value) {
            let mut value = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u32) << (8 * i);
            }
            points.push(boolean_point_for_index(chunk_index, num_vars));
            evals.push(BabyBear::from_u32(value));
        }
    }
    let sentinel_index = bytes.len().div_ceil(field::BYTES_PER_ELEMENT);
    points.push(boolean_point_for_index(sentinel_index, num_vars));
    evals.push(BabyBear::from_u32(bytes.len() as u32));
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    if sentinel_index >= max_index {
        return None;
    }
    Some((points, evals))
}

fn typed_batched_cp_semantic_packed_value_claims(
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    num_vars: usize,
) -> Option<(Vec<Vec<BabyBear>>, Vec<BabyBear>)> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    let mut evals = Vec::new();
    for block in relation.packed_value_blocks(statement) {
        for value in block.values {
            if value.packed_index >= max_index {
                return None;
            }
            points.push(boolean_point_for_index(value.packed_index, num_vars));
            evals.push(BabyBear::from_u32(value.value));
        }
    }
    Some((points, evals))
}

fn typed_batched_cp_equality_opening_points(
    equalities: &[crate::batched_cp::BatchedCpOracleByteEquality],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::with_capacity(equalities.len() * 2);
    for equality in equalities {
        let left_index = equality.left_offset / field::BYTES_PER_ELEMENT;
        let right_index = equality.right_offset / field::BYTES_PER_ELEMENT;
        if left_index >= max_index || right_index >= max_index {
            return None;
        }
        points.push(boolean_point_for_index(left_index, num_vars));
        points.push(boolean_point_for_index(right_index, num_vars));
    }
    Some(points)
}

fn typed_batched_cp_linear_opening_points(
    constraints: &[crate::batched_cp::BatchedCpFoldedPublicInputLinearConstraint],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    for constraint in constraints {
        for &offset in constraint
            .beta_coeff_offsets
            .iter()
            .chain(constraint.input_scalar_offsets.iter())
            .chain(std::iter::once(&constraint.output_coeff_offset))
        {
            for byte_offset in offset..offset + 8 {
                let packed_index = byte_offset / field::BYTES_PER_ELEMENT;
                if packed_index >= max_index {
                    return None;
                }
                points.push(boolean_point_for_index(packed_index, num_vars));
            }
        }
    }
    Some(points)
}

fn typed_batched_cp_ring_mul_opening_points(
    constraints: &[crate::batched_cp::BatchedCpFoldedCommitmentRingMulConstraint],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    for constraint in constraints {
        for offset in constraint
            .beta_coeff_offsets
            .iter()
            .flatten()
            .chain(constraint.commitment_coeff_offsets.iter().flatten())
            .chain(std::iter::once(&constraint.output_coeff_offset))
        {
            for byte_offset in *offset..*offset + 8 {
                let packed_index = byte_offset / field::BYTES_PER_ELEMENT;
                if packed_index >= max_index {
                    return None;
                }
                points.push(boolean_point_for_index(packed_index, num_vars));
            }
        }
    }
    Some(points)
}

fn typed_batched_cp_eval_ring_mul_opening_points(
    constraints: &[crate::batched_cp::BatchedCpFoldedEvaluationRingMulConstraint],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    for constraint in constraints {
        for offset in constraint
            .beta_coeff_offsets
            .iter()
            .flatten()
            .chain(constraint.evaluation_coeff_offsets.iter().flatten())
            .chain(std::iter::once(&constraint.output_coeff_offset))
        {
            for byte_offset in *offset..*offset + 8 {
                let packed_index = byte_offset / field::BYTES_PER_ELEMENT;
                if packed_index >= max_index {
                    return None;
                }
                points.push(boolean_point_for_index(packed_index, num_vars));
            }
        }
    }
    Some(points)
}

fn typed_batched_cp_poseidon_r1cs_opening_points(
    constraints: &[crate::batched_cp::BatchedCpPoseidonR1csRowConstraint],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    for constraint in constraints {
        for byte_offset in typed_batched_cp_poseidon_r1cs_byte_offsets(constraint)? {
            let packed_index = byte_offset / field::BYTES_PER_ELEMENT;
            if packed_index >= max_index {
                return None;
            }
            points.push(boolean_point_for_index(packed_index, num_vars));
        }
    }
    Some(points)
}

fn typed_batched_cp_sampled_equalities(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpOracleByteEquality> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .byte_equality_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            selected.extend(block.equalities);
        } else {
            selected.extend(typed_batched_cp_sampled_block_equalities(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|equality| (equality.left_offset, equality.right_offset));
    selected
}

fn typed_batched_cp_sampled_folded_public_input_linear_constraints(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpFoldedPublicInputLinearConstraint> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .folded_public_input_linear_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            selected.extend(block.constraints);
        } else {
            selected.extend(typed_batched_cp_sampled_folded_public_input_linear_block(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.output_coeff_offset,
            constraint.input_scalar_offsets.clone(),
            constraint.beta_coeff_offsets.clone(),
        )
    });
    selected
}

fn typed_batched_cp_sampled_folded_commitment_ring_mul_constraints(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpFoldedCommitmentRingMulConstraint> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .folded_commitment_ring_mul_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            selected.extend(block.constraints);
        } else {
            selected.extend(typed_batched_cp_sampled_folded_commitment_ring_mul_block(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.output_coeff_offset,
            constraint.output_coeff_index,
            constraint.commitment_coeff_offsets.clone(),
            constraint.beta_coeff_offsets.clone(),
        )
    });
    selected
}

fn typed_batched_cp_sampled_folded_evaluation_ring_mul_constraints(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpFoldedEvaluationRingMulConstraint> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .folded_evaluation_ring_mul_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            selected.extend(block.constraints);
        } else {
            selected.extend(typed_batched_cp_sampled_folded_evaluation_ring_mul_block(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.output_coeff_offset,
            constraint.output_coeff_index,
            constraint.evaluation_coeff_offsets.clone(),
            constraint.beta_coeff_offsets.clone(),
        )
    });
    selected
}

fn typed_batched_cp_sampled_poseidon_r1cs_constraints(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpPoseidonR1csRowConstraint> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .poseidon_r1cs_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            for surface in block.surfaces {
                selected
                    .extend((0..surface.num_rows).filter_map(|row| surface.row_constraint(row)));
            }
        } else {
            selected.extend(typed_batched_cp_sampled_poseidon_r1cs_block(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|constraint| (constraint.round, constraint.item, constraint.row));
    selected
}

fn typed_batched_cp_sampled_poseidon_r1cs_block(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpPoseidonR1csBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpPoseidonR1csRowConstraint> {
    let total_rows: usize = block.surfaces.iter().map(|surface| surface.num_rows).sum();
    if total_rows == 0 || max_checks == 0 {
        return Vec::new();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-poseidon-r1cs-full-domain-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(block.surfaces.len() as u64).to_le_bytes());
    for surface in &block.surfaces {
        transcript.extend_from_slice(&(surface.round as u64).to_le_bytes());
        transcript.extend_from_slice(&(surface.item as u64).to_le_bytes());
        transcript.extend_from_slice(&(surface.input_len as u64).to_le_bytes());
        transcript.extend_from_slice(&(surface.num_rows as u64).to_le_bytes());
    }
    transcript.extend_from_slice(&(total_rows as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let target_checks = max_checks.min(total_rows);
    let mut selected = Vec::with_capacity(target_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < target_checks {
        let challenge = derive_challenge(&transcript, counter, b"poseidon-r1cs-row-index")
            .as_canonical_u32() as usize;
        let idx = challenge % total_rows;
        if seen.insert(idx) {
            let mut local = idx;
            for surface in &block.surfaces {
                if local < surface.num_rows {
                    if let Some(constraint) = surface.row_constraint(local) {
                        selected.push(constraint);
                    }
                    break;
                }
                local -= surface.num_rows;
            }
        }
        counter += 1;
    }
    selected.sort_by_key(|constraint| (constraint.round, constraint.item, constraint.row));
    selected
}

fn typed_batched_cp_ajtai_opening_points(
    constraints: &[crate::batched_cp::BatchedCpAjtaiOpeningLinearConstraint],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    for constraint in constraints {
        for offset in constraint
            .public_input_offsets
            .iter()
            .chain(constraint.witness_coeff_offsets.iter().flatten())
            .chain(std::iter::once(&constraint.commitment_coeff_offset))
        {
            for byte_offset in *offset..*offset + 8 {
                let packed_index = byte_offset / field::BYTES_PER_ELEMENT;
                if packed_index >= max_index {
                    return None;
                }
                points.push(boolean_point_for_index(packed_index, num_vars));
            }
        }
    }
    Some(points)
}

fn typed_batched_cp_original_r1cs_opening_points(
    constraints: &[crate::batched_cp::BatchedCpOriginalR1csConstraint],
    num_vars: usize,
) -> Option<Vec<Vec<BabyBear>>> {
    let max_index = 1usize.checked_shl(num_vars as u32)?;
    let mut points = Vec::new();
    for constraint in constraints {
        for offset in constraint
            .a_terms
            .iter()
            .chain(constraint.b_terms.iter())
            .chain(constraint.c_terms.iter())
            .map(|(_, offset)| *offset)
        {
            for byte_offset in offset..offset + 8 {
                let packed_index = byte_offset / field::BYTES_PER_ELEMENT;
                if packed_index >= max_index {
                    return None;
                }
                points.push(boolean_point_for_index(packed_index, num_vars));
            }
        }
    }
    Some(points)
}

fn typed_batched_cp_sampled_ajtai_opening_constraints(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpAjtaiOpeningLinearConstraint> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .ajtai_opening_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            selected.extend(block.constraints);
        } else {
            selected.extend(typed_batched_cp_sampled_ajtai_opening_block(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.item,
            constraint.round,
            constraint.row,
            constraint.coeff,
        )
    });
    selected
}

fn typed_batched_cp_sampled_original_r1cs_constraints(
    seed: &[u8; 32],
    relation: &WhirBatchedCpRelationContext,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpOriginalR1csConstraint> {
    let relation_id = relation.relation_id();
    let mut selected = Vec::new();
    for (block_index, block) in relation
        .original_r1cs_blocks(statement)
        .into_iter()
        .enumerate()
    {
        if relation.enforces_full_semantic_blocks() {
            selected.extend(block.constraints);
        } else {
            selected.extend(typed_batched_cp_sampled_original_r1cs_block(
                seed,
                &relation_id,
                statement,
                block_index,
                &block,
                max_checks,
            ));
        }
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.item,
            constraint.original_index,
            constraint.row,
            constraint.coeff,
        )
    });
    selected
}

fn typed_batched_cp_sampled_original_r1cs_block(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpOriginalR1csBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpOriginalR1csConstraint> {
    let all = &block.constraints;
    if all.len() <= max_checks {
        return all.clone();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-original-r1cs-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(all.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let mut selected = Vec::with_capacity(max_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < max_checks {
        let challenge = derive_challenge(&transcript, counter, b"original-r1cs-index")
            .as_canonical_u32() as usize;
        let idx = challenge % all.len();
        if seen.insert(idx) {
            selected.push(all[idx].clone());
        }
        counter += 1;
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.item,
            constraint.original_index,
            constraint.row,
            constraint.coeff,
        )
    });
    selected
}

fn typed_batched_cp_sampled_ajtai_opening_block(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpAjtaiOpeningBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpAjtaiOpeningLinearConstraint> {
    let all = &block.constraints;
    if all.len() <= max_checks {
        return all.clone();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-ajtai-opening-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(all.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let mut selected = Vec::with_capacity(max_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < max_checks {
        let challenge = derive_challenge(&transcript, counter, b"ajtai-opening-index")
            .as_canonical_u32() as usize;
        let idx = challenge % all.len();
        if seen.insert(idx) {
            selected.push(all[idx].clone());
        }
        counter += 1;
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.item,
            constraint.round,
            constraint.row,
            constraint.coeff,
        )
    });
    selected
}

fn typed_batched_cp_sampled_folded_public_input_linear_block(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpFoldedPublicInputLinearBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpFoldedPublicInputLinearConstraint> {
    let all = &block.constraints;
    if all.len() <= max_checks {
        return all.clone();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-folded-public-input-linear-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(all.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let mut selected = Vec::with_capacity(max_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < max_checks {
        let challenge = derive_challenge(&transcript, counter, b"folded-public-input-linear-index")
            .as_canonical_u32() as usize;
        let idx = challenge % all.len();
        if seen.insert(idx) {
            selected.push(all[idx].clone());
        }
        counter += 1;
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.output_coeff_offset,
            constraint.input_scalar_offsets.clone(),
            constraint.beta_coeff_offsets.clone(),
        )
    });
    selected
}

fn typed_batched_cp_sampled_folded_commitment_ring_mul_block(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpFoldedCommitmentRingMulBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpFoldedCommitmentRingMulConstraint> {
    let all = &block.constraints;
    if all.len() <= max_checks {
        return all.clone();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-folded-commitment-ring-mul-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(all.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let mut selected = Vec::with_capacity(max_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < max_checks {
        let challenge = derive_challenge(&transcript, counter, b"folded-commitment-ring-mul-index")
            .as_canonical_u32() as usize;
        let idx = challenge % all.len();
        if seen.insert(idx) {
            selected.push(all[idx].clone());
        }
        counter += 1;
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.output_coeff_offset,
            constraint.output_coeff_index,
            constraint.commitment_coeff_offsets.clone(),
            constraint.beta_coeff_offsets.clone(),
        )
    });
    selected
}

fn typed_batched_cp_sampled_folded_evaluation_ring_mul_block(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpFoldedEvaluationRingMulBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpFoldedEvaluationRingMulConstraint> {
    let all = &block.constraints;
    if all.len() <= max_checks {
        return all.clone();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-folded-evaluation-ring-mul-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(all.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let mut selected = Vec::with_capacity(max_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < max_checks {
        let challenge = derive_challenge(&transcript, counter, b"folded-evaluation-ring-mul-index")
            .as_canonical_u32() as usize;
        let idx = challenge % all.len();
        if seen.insert(idx) {
            selected.push(all[idx].clone());
        }
        counter += 1;
    }
    selected.sort_by_key(|constraint| {
        (
            constraint.output_coeff_offset,
            constraint.output_coeff_index,
            constraint.evaluation_coeff_offsets.clone(),
            constraint.beta_coeff_offsets.clone(),
        )
    });
    selected
}

fn typed_batched_cp_sampled_block_equalities(
    seed: &[u8; 32],
    relation_id: &crate::digest_core::Digest32,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    block_index: usize,
    block: &WhirBatchedCpByteEqualityBlock,
    max_checks: usize,
) -> Vec<crate::batched_cp::BatchedCpOracleByteEquality> {
    let all = &block.equalities;
    if all.len() <= max_checks {
        return all.clone();
    }
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-typed-batched-cp-semantic-byte-equality-v1");
    transcript.extend_from_slice(seed);
    transcript.extend_from_slice(relation_id);
    transcript.extend_from_slice(&(block_index as u64).to_le_bytes());
    transcript.push(typed_batched_cp_semantic_family_code(block.family));
    transcript.extend_from_slice(&(block.label.len() as u64).to_le_bytes());
    transcript.extend_from_slice(block.label.as_bytes());
    let statement_bytes = statement.canonical_bytes();
    transcript.extend_from_slice(&(statement_bytes.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&statement_bytes);
    transcript.extend_from_slice(&(all.len() as u64).to_le_bytes());
    transcript.extend_from_slice(&(max_checks as u64).to_le_bytes());

    let mut selected = Vec::with_capacity(max_checks);
    let mut seen = std::collections::BTreeSet::new();
    let mut counter = 0usize;
    while selected.len() < max_checks {
        let challenge = derive_challenge(&transcript, counter, b"byte-equality-index")
            .as_canonical_u32() as usize;
        let idx = challenge % all.len();
        if seen.insert(idx) {
            selected.push(all[idx]);
        }
        counter += 1;
    }
    selected.sort_by_key(|equality| (equality.left_offset, equality.right_offset));
    selected
}

fn typed_batched_cp_semantic_family_code(
    family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
) -> u8 {
    match family {
        crate::batched_cp::BatchedCpSemanticConstraintFamily::PoseidonDigestCorrectness => 1,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::ManifestMembership => 2,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::RoundMessageBinding => 3,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::ChallengeDerivation => 4,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::ChallengeToBetaBinding => 5,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::FoldedOutputDerivation => 6,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::AjtaiOpeningValidity => 7,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::OriginalR1csValidity => 8,
        crate::batched_cp::BatchedCpSemanticConstraintFamily::ActiveOrDummyPolicy => 9,
    }
}

fn typed_batched_cp_equality_evals_match(
    equalities: &[crate::batched_cp::BatchedCpOracleByteEquality],
    evals: &[BabyBear],
) -> bool {
    if evals.len() != equalities.len() * 2 {
        return false;
    }
    for (idx, equality) in equalities.iter().enumerate() {
        let Some(left) = byte_from_packed_oracle_eval(evals[2 * idx], equality.left_offset) else {
            return false;
        };
        let Some(right) = byte_from_packed_oracle_eval(evals[2 * idx + 1], equality.right_offset)
        else {
            return false;
        };
        if left != right {
            return false;
        }
    }
    true
}

fn typed_batched_cp_folded_public_input_linear_evals_match(
    constraints: &[crate::batched_cp::BatchedCpFoldedPublicInputLinearConstraint],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for constraint in constraints {
        if constraint.beta_coeff_offsets.len() != constraint.input_scalar_offsets.len() {
            return false;
        }
        let mut acc = BabyBear::ZERO;
        for (&beta_offset, &input_offset) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.input_scalar_offsets.iter())
        {
            let Some(beta_coeff) = read_i64_from_packed_oracle_evals(evals, &mut pos, beta_offset)
            else {
                return false;
            };
            let Some(input_scalar) =
                read_i64_from_packed_oracle_evals(evals, &mut pos, input_offset)
            else {
                return false;
            };
            acc +=
                babybear_from_i64_canonical(beta_coeff) * babybear_from_i64_canonical(input_scalar);
        }
        let Some(output_coeff) =
            read_i64_from_packed_oracle_evals(evals, &mut pos, constraint.output_coeff_offset)
        else {
            return false;
        };
        if acc != babybear_from_i64_canonical(output_coeff) {
            return false;
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_folded_commitment_ring_mul_evals_match(
    constraints: &[crate::batched_cp::BatchedCpFoldedCommitmentRingMulConstraint],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for constraint in constraints {
        if constraint.beta_coeff_offsets.len() != constraint.commitment_coeff_offsets.len() {
            return false;
        }
        let mut acc = BabyBear::ZERO;
        for (beta_offsets, commitment_offsets) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.commitment_coeff_offsets.iter())
        {
            let Some(beta) =
                read_babybear_ring_from_packed_oracle_evals(evals, &mut pos, beta_offsets)
            else {
                return false;
            };
            let Some(commitment) =
                read_babybear_ring_from_packed_oracle_evals(evals, &mut pos, commitment_offsets)
            else {
                return false;
            };
            let product = babybear_cyclotomic_mul(&beta, &commitment);
            if constraint.output_coeff_index >= D {
                return false;
            }
            acc += product[constraint.output_coeff_index];
        }
        let Some(output_coeff) =
            read_i64_from_packed_oracle_evals(evals, &mut pos, constraint.output_coeff_offset)
        else {
            return false;
        };
        if acc != babybear_from_i64_canonical(output_coeff) {
            return false;
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_folded_evaluation_ring_mul_evals_match(
    constraints: &[crate::batched_cp::BatchedCpFoldedEvaluationRingMulConstraint],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for constraint in constraints {
        if constraint.beta_coeff_offsets.len() != constraint.evaluation_coeff_offsets.len() {
            return false;
        }
        let mut acc = BabyBear::ZERO;
        for (beta_offsets, evaluation_offsets) in constraint
            .beta_coeff_offsets
            .iter()
            .zip(constraint.evaluation_coeff_offsets.iter())
        {
            let Some(beta) =
                read_babybear_ring_from_packed_oracle_evals(evals, &mut pos, beta_offsets)
            else {
                return false;
            };
            let Some(evaluation) =
                read_babybear_ring_from_packed_oracle_evals(evals, &mut pos, evaluation_offsets)
            else {
                return false;
            };
            let product = babybear_cyclotomic_mul(&beta, &evaluation);
            if constraint.output_coeff_index >= D {
                return false;
            }
            acc += product[constraint.output_coeff_index];
        }
        let Some(output_coeff) =
            read_i64_from_packed_oracle_evals(evals, &mut pos, constraint.output_coeff_offset)
        else {
            return false;
        };
        if acc != babybear_from_i64_canonical(output_coeff) {
            return false;
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_poseidon_r1cs_evals_match(
    constraints: &[crate::batched_cp::BatchedCpPoseidonR1csRowConstraint],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for constraint in constraints {
        let Some((a, b, c)) = typed_batched_cp_poseidon_r1cs_row_eval(constraint, evals, &mut pos)
        else {
            return false;
        };
        if a * b != c {
            return false;
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_ajtai_opening_evals_match(
    constraints: &[crate::batched_cp::BatchedCpAjtaiOpeningLinearConstraint],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for constraint in constraints {
        if constraint.coeff >= D
            || constraint.matrix_row.len()
                != constraint.public_input_offsets.len() + constraint.witness_coeff_offsets.len()
        {
            return false;
        }

        let mut acc = BabyBear::ZERO;
        for (matrix_elem, &public_offset) in constraint
            .matrix_row
            .iter()
            .zip(constraint.public_input_offsets.iter())
        {
            let Some(public_scalar) =
                read_i64_from_packed_oracle_evals(evals, &mut pos, public_offset)
            else {
                return false;
            };
            acc += babybear_from_i64_canonical(matrix_elem.coeffs[constraint.coeff])
                * babybear_from_i64_canonical(public_scalar);
        }

        for (matrix_elem, witness_offsets) in constraint
            .matrix_row
            .iter()
            .skip(constraint.public_input_offsets.len())
            .zip(constraint.witness_coeff_offsets.iter())
        {
            let Some(witness) =
                read_babybear_ring_from_packed_oracle_evals(evals, &mut pos, witness_offsets)
            else {
                return false;
            };
            let product =
                babybear_cyclotomic_mul(&ring_element_to_babybear_array(matrix_elem), &witness);
            acc += product[constraint.coeff];
        }

        let Some(commitment_coeff) =
            read_i64_from_packed_oracle_evals(evals, &mut pos, constraint.commitment_coeff_offset)
        else {
            return false;
        };
        if acc != babybear_from_i64_canonical(commitment_coeff) {
            return false;
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_original_r1cs_evals_match(
    constraints: &[crate::batched_cp::BatchedCpOriginalR1csConstraint],
    evals: &[BabyBear],
) -> bool {
    let mut pos = 0usize;
    for constraint in constraints {
        let Some(a) =
            typed_batched_cp_original_r1cs_linear_eval(&constraint.a_terms, evals, &mut pos)
        else {
            return false;
        };
        let Some(b) =
            typed_batched_cp_original_r1cs_linear_eval(&constraint.b_terms, evals, &mut pos)
        else {
            return false;
        };
        let Some(c) =
            typed_batched_cp_original_r1cs_linear_eval(&constraint.c_terms, evals, &mut pos)
        else {
            return false;
        };
        if a * b != c {
            return false;
        }
    }
    pos == evals.len()
}

fn typed_batched_cp_original_r1cs_linear_eval(
    terms: &[(i64, usize)],
    evals: &[BabyBear],
    pos: &mut usize,
) -> Option<BabyBear> {
    let mut acc = BabyBear::ZERO;
    for &(matrix_coeff, value_offset) in terms {
        let value = read_i64_from_packed_oracle_evals(evals, pos, value_offset)?;
        acc += babybear_from_i64_canonical(matrix_coeff) * babybear_from_i64_canonical(value);
    }
    Some(acc)
}

fn typed_batched_cp_poseidon_r1cs_byte_offsets(
    constraint: &crate::batched_cp::BatchedCpPoseidonR1csRowConstraint,
) -> Option<Vec<usize>> {
    let (r1cs, layout) = crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
        b"fs-commit",
        constraint.input_len,
    );
    let mut offsets = Vec::new();
    for matrix in [&r1cs.a, &r1cs.b, &r1cs.c] {
        for &(_, col, _) in matrix
            .entries
            .iter()
            .filter(|&&(row, _, _)| row == constraint.row)
        {
            if col == layout.off_one {
                continue;
            }
            let offset = typed_batched_cp_poseidon_var_offset(constraint, &layout, col)?;
            offsets.extend(offset..offset + 4);
        }
    }
    Some(offsets)
}

fn typed_batched_cp_poseidon_r1cs_row_eval(
    constraint: &crate::batched_cp::BatchedCpPoseidonR1csRowConstraint,
    evals: &[BabyBear],
    pos: &mut usize,
) -> Option<(BabyBear, BabyBear, BabyBear)> {
    let (r1cs, layout) = crate::snark::cp_snark::generate_poseidon2_private_digest_r1cs(
        b"fs-commit",
        constraint.input_len,
    );
    if constraint.row >= r1cs.num_constraints {
        return None;
    }
    let a = typed_batched_cp_poseidon_lc_eval(&r1cs.a, constraint, &layout, evals, pos)?;
    let b = typed_batched_cp_poseidon_lc_eval(&r1cs.b, constraint, &layout, evals, pos)?;
    let c = typed_batched_cp_poseidon_lc_eval(&r1cs.c, constraint, &layout, evals, pos)?;
    Some((a, b, c))
}

fn typed_batched_cp_poseidon_lc_eval(
    matrix: &crate::r1cs::SparseMatrix,
    constraint: &crate::batched_cp::BatchedCpPoseidonR1csRowConstraint,
    layout: &crate::snark::cp_snark::Poseidon2PrivateDigestR1csLayout,
    evals: &[BabyBear],
    pos: &mut usize,
) -> Option<BabyBear> {
    let mut acc = BabyBear::ZERO;
    for &(_, col, coeff) in matrix
        .entries
        .iter()
        .filter(|&&(row, _, _)| row == constraint.row)
    {
        let value = if col == layout.off_one {
            BabyBear::ONE
        } else {
            let offset = typed_batched_cp_poseidon_var_offset(constraint, layout, col)?;
            read_u32_from_packed_oracle_evals(evals, pos, offset).map(BabyBear::from_u32)?
        };
        acc += babybear_from_i64_canonical(coeff) * value;
    }
    Some(acc)
}

fn typed_batched_cp_poseidon_var_offset(
    constraint: &crate::batched_cp::BatchedCpPoseidonR1csRowConstraint,
    layout: &crate::snark::cp_snark::Poseidon2PrivateDigestR1csLayout,
    col: usize,
) -> Option<usize> {
    if (layout.off_output..layout.off_output + 8).contains(&col) {
        return constraint
            .output_offsets
            .get(col - layout.off_output)
            .copied();
    }
    if (layout.off_input..layout.off_input + layout.input_len).contains(&col) {
        return constraint
            .input_offsets
            .get(col - layout.off_input)
            .copied();
    }
    let aux_start = layout.off_input + layout.input_len;
    if (aux_start..layout.num_variables).contains(&col) {
        return constraint.aux_offsets.get(col - aux_start).copied();
    }
    None
}

fn read_babybear_ring_from_packed_oracle_evals(
    evals: &[BabyBear],
    pos: &mut usize,
    coeff_offsets: &[usize],
) -> Option<[BabyBear; D]> {
    if coeff_offsets.len() != D {
        return None;
    }
    let mut coeffs = [BabyBear::ZERO; D];
    for (idx, out) in coeffs.iter_mut().enumerate() {
        let coeff = read_i64_from_packed_oracle_evals(evals, pos, coeff_offsets[idx])?;
        *out = babybear_from_i64_canonical(coeff);
    }
    Some(coeffs)
}

fn babybear_from_i64_canonical(value: i64) -> BabyBear {
    const BABYBEAR_MODULUS: i128 = 2_013_265_921;
    BabyBear::from_u32((value as i128).rem_euclid(BABYBEAR_MODULUS) as u32)
}

fn ring_element_to_babybear_array(value: &RingElement) -> [BabyBear; D] {
    let mut out = [BabyBear::ZERO; D];
    for (idx, coeff) in value.coeffs.iter().enumerate() {
        out[idx] = babybear_from_i64_canonical(*coeff);
    }
    out
}

fn babybear_cyclotomic_mul(a: &[BabyBear; D], b: &[BabyBear; D]) -> [BabyBear; D] {
    let mut acc = [BabyBear::ZERO; D];
    for (i, &a_i) in a.iter().enumerate() {
        for (j, &b_j) in b.iter().enumerate() {
            let prod = a_i * b_j;
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

fn read_i64_from_packed_oracle_evals(
    evals: &[BabyBear],
    pos: &mut usize,
    byte_offset: usize,
) -> Option<i64> {
    let mut bytes = [0u8; 8];
    for (idx, out) in bytes.iter_mut().enumerate() {
        let eval = *evals.get(*pos)?;
        *pos += 1;
        *out = byte_from_packed_oracle_eval(eval, byte_offset + idx)?;
    }
    Some(i64::from_le_bytes(bytes))
}

fn read_u32_from_packed_oracle_evals(
    evals: &[BabyBear],
    pos: &mut usize,
    byte_offset: usize,
) -> Option<u32> {
    let mut bytes = [0u8; 4];
    for (idx, out) in bytes.iter_mut().enumerate() {
        let eval = *evals.get(*pos)?;
        *pos += 1;
        *out = byte_from_packed_oracle_eval(eval, byte_offset + idx)?;
    }
    Some(u32::from_le_bytes(bytes))
}

fn byte_from_packed_oracle_eval(eval: BabyBear, byte_offset: usize) -> Option<u8> {
    let shift = (byte_offset % field::BYTES_PER_ELEMENT) * 8;
    let value = eval.as_canonical_u32();
    if value >= (1u32 << (8 * field::BYTES_PER_ELEMENT)) {
        return None;
    }
    Some(((value >> shift) & 0xff) as u8)
}

