#[derive(Debug, Clone)]
pub struct Poseidon2DigestR1csLayout {
    pub input_len: usize,
    pub off_one: usize,
    pub off_input: usize,
    pub off_output: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

#[derive(Debug, Clone)]
pub struct Poseidon2PrivateDigestR1csLayout {
    pub input_len: usize,
    pub off_one: usize,
    pub off_output: usize,
    pub off_input: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

#[derive(Debug, Clone)]
pub struct OriginalStatementR1csLayout {
    pub n_public: usize,
    pub n_witness: usize,
    pub kappa: usize,
    pub q: u64,
    pub d: usize,
    pub off_one: usize,
    pub off_public_input: usize,
    pub off_commitment: usize,
    pub off_witness: usize,
    pub off_ajtai_wrap: usize,
    pub off_r1cs_wrap: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

/// Partial typed CP composition checkpoint.
///
/// This combines the existing CP-R1CS folding core with original statement
/// algebra checks. It intentionally does not yet include the Poseidon digest
/// and GR1CS message/fold-root binding gadgets, so it is not authoritative by
/// itself.
#[derive(Debug, Clone)]
pub struct TypedCpPartialR1csLayout {
    pub cp_layout: CpR1csLayout,
    pub original_r1cs_num_constraints: usize,
    pub original_r1cs_num_variables: usize,
    pub off_original_witnesses: usize,
    pub off_original_ajtai_wraps: usize,
    pub off_original_r1cs_wraps: usize,
    pub original_block_size: usize,
    pub original_constraints_per_instance: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

#[derive(Debug, Clone)]
pub struct TypedCpStatementR1csLayout {
    pub partial: TypedCpPartialR1csLayout,
    pub off_public_inputs: usize,
    pub added_public_inputs: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCpDigestInputLengths {
    pub fs_commitment_inputs: Vec<usize>,
    pub fs_commitment_bodies: Vec<usize>,
    pub gr1cs_message_bodies: Vec<usize>,
    pub gr1cs_message_shapes: Vec<TypedCpGr1csMessageShape>,
    pub challenge_inputs: Vec<usize>,
    pub challenge_bodies: Vec<usize>,
    pub fs_root_input: usize,
    pub fs_root_body: usize,
    pub fold_root_input: usize,
    pub fold_root_body: usize,
    pub challenge_digest_input: usize,
    pub challenge_digest_body: usize,
    pub transcript_seed_input: usize,
    pub transcript_seed_body: usize,
    pub folded_evaluation_values: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypedCpGr1csMessageShape {
    pub hadamard_sumcheck_round_evals: Vec<usize>,
    pub hadamard_eval_matrix_rows: Vec<usize>,
    pub range: Option<TypedCpRangeMessageShape>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCpRangeMessageShape {
    pub monomial_commitment_elem_lens: Vec<usize>,
    pub monomial_vector_lens: Vec<usize>,
    pub monomial_sumcheck_round_evals: Vec<usize>,
    pub monomial_evaluation_rows: Vec<usize>,
    pub sq_evaluations_count: usize,
    pub projected_values_count: usize,
}

#[derive(Debug, Clone)]
pub struct TypedCpDigestBlockLayout {
    pub off_public_output: usize,
    pub off_private_witness: usize,
    pub off_body_bytes: usize,
    pub off_body_bits: usize,
    pub input_len: usize,
    pub body_len: usize,
    pub witness_len: usize,
}

#[derive(Debug, Clone)]
pub struct TypedCpDigestR1csLayout {
    pub statement: TypedCpStatementR1csLayout,
    pub fs_commitments_are_public: bool,
    pub fs_commitment_blocks: Vec<TypedCpDigestBlockLayout>,
    pub challenge_blocks: Vec<TypedCpDigestBlockLayout>,
    pub range_payload_blocks: Vec<Option<TypedCpRangePayloadBlockLayout>>,
    pub fs_root_block: TypedCpDigestBlockLayout,
    pub fold_root_block: TypedCpDigestBlockLayout,
    pub challenge_digest_block: TypedCpDigestBlockLayout,
    pub transcript_seed_block: TypedCpDigestBlockLayout,
    pub off_fs_commitments: usize,
    pub off_fs_root: usize,
    pub off_fold_root: usize,
    pub off_challenge_digest: usize,
    pub off_transcript_seed_digest: usize,
    pub off_folded_evaluations: usize,
    pub folded_evaluation_values: usize,
    pub off_folded_eval_products: usize,
    pub off_folded_eval_wraps: usize,
    pub off_beta_binding_selectors: usize,
    pub beta_binding_selector_count: usize,
    pub added_digest_public: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

#[derive(Debug, Clone)]
pub struct TypedCpRangePayloadBlockLayout {
    pub off_monomial_commitments: usize,
    pub monomial_commitment_coeffs_count: usize,
    pub off_monomial_commitment_wraps: usize,
    pub off_monomial_vectors: usize,
    pub monomial_vector_coeffs_count: usize,
    pub off_monomial_vector_squares: usize,
    pub monomial_vector_elements_count: usize,
    pub off_monomial_sumcheck_evaluations: usize,
    pub monomial_sumcheck_evaluation_coeffs_count: usize,
    pub off_monomial_evaluations: usize,
    pub monomial_evaluation_coeffs_count: usize,
    pub off_sq_evaluations: usize,
    pub sq_evaluation_coeffs_count: usize,
    pub off_projected_values: usize,
    pub projected_values_count: usize,
    pub off_monomial_sumcheck_seed: usize,
    pub off_monomial_sumcheck_challenges: usize,
    pub off_monomial_alpha: usize,
    pub off_monomial_sumcheck_aux: usize,
    pub monomial_sumcheck_aux_count: usize,
    pub off_monomial_sumcheck_wraps: usize,
    pub monomial_sumcheck_wrap_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypedCpAuditBlockKind {
    CpFoldingCore,
    ByteConstraints,
    PoseidonDigestGadgets,
    Gr1csMessageReconstruction,
    RangeMonomialSemantics,
    ChallengeToBetaBinding,
    FoldedOutputDerivation,
    AjtaiOpeningChecks,
    OriginalR1csValidity,
    PublicInputBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypedCpSplitComponent {
    Leaf,
    Accumulator,
    LeafAccumulatorBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCpAuditBlock {
    pub kind: TypedCpAuditBlockKind,
    pub label: String,
    pub start_row: usize,
    pub row_count: usize,
    pub cp_field_relation_checks: Vec<String>,
}

impl TypedCpAuditBlock {
    pub fn split_component(&self) -> TypedCpSplitComponent {
        match self.kind {
            TypedCpAuditBlockKind::AjtaiOpeningChecks
            | TypedCpAuditBlockKind::OriginalR1csValidity
            | TypedCpAuditBlockKind::RangeMonomialSemantics => TypedCpSplitComponent::Leaf,
            TypedCpAuditBlockKind::CpFoldingCore
            | TypedCpAuditBlockKind::ChallengeToBetaBinding
            | TypedCpAuditBlockKind::FoldedOutputDerivation
            | TypedCpAuditBlockKind::PublicInputBinding => TypedCpSplitComponent::Accumulator,
            TypedCpAuditBlockKind::PoseidonDigestGadgets => {
                if self.label.contains("fs-commit") {
                    TypedCpSplitComponent::Leaf
                } else {
                    TypedCpSplitComponent::Accumulator
                }
            }
            TypedCpAuditBlockKind::Gr1csMessageReconstruction => {
                if self.label.contains("fs-message-fold-root-byte-equality") {
                    TypedCpSplitComponent::LeafAccumulatorBinding
                } else {
                    TypedCpSplitComponent::Leaf
                }
            }
            TypedCpAuditBlockKind::ByteConstraints => {
                if self.label.contains("fs-commit") {
                    TypedCpSplitComponent::Leaf
                } else if self.label.contains("fs-root")
                    || self.label.contains("fold-root")
                    || self.label.contains("challenge")
                    || self.label.contains("transcript")
                    || self.label.contains("structured")
                {
                    TypedCpSplitComponent::Accumulator
                } else {
                    TypedCpSplitComponent::LeafAccumulatorBinding
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCpAuditReport {
    pub num_public: usize,
    pub num_variables: usize,
    pub num_constraints: usize,
    pub blocks: Vec<TypedCpAuditBlock>,
}

impl TypedCpAuditReport {
    pub fn validate_against(&self, r1cs: &R1CSMatrices) -> Result<(), String> {
        if self.num_public != r1cs.num_public
            || self.num_variables != r1cs.num_variables
            || self.num_constraints != r1cs.num_constraints
        {
            return Err(format!(
                "audit dimensions ({}, {}, {}) do not match R1CS ({}, {}, {})",
                self.num_public,
                self.num_variables,
                self.num_constraints,
                r1cs.num_public,
                r1cs.num_variables,
                r1cs.num_constraints
            ));
        }

        let mut expected_start = 0usize;
        for block in &self.blocks {
            if block.row_count == 0 {
                return Err(format!("audit block '{}' has zero rows", block.label));
            }
            if block.start_row != expected_start {
                return Err(format!(
                    "audit block '{}' starts at {}, expected {}",
                    block.label, block.start_row, expected_start
                ));
            }
            expected_start = expected_start
                .checked_add(block.row_count)
                .ok_or_else(|| "audit row count overflow".to_string())?;
        }
        if expected_start != self.num_constraints {
            return Err(format!(
                "audit blocks cover {expected_start} rows, expected {}",
                self.num_constraints
            ));
        }
        Ok(())
    }

    pub fn block_for_row(&self, row: usize) -> Option<&TypedCpAuditBlock> {
        self.blocks
            .iter()
            .find(|block| (block.start_row..block.start_row + block.row_count).contains(&row))
    }

    pub fn row_count_by_kind(&self, kind: TypedCpAuditBlockKind) -> usize {
        self.blocks
            .iter()
            .filter(|block| block.kind == kind)
            .map(|block| block.row_count)
            .sum()
    }

    pub fn row_count_by_split_component(&self, component: TypedCpSplitComponent) -> usize {
        self.blocks
            .iter()
            .filter(|block| block.split_component() == component)
            .map(|block| block.row_count)
            .sum()
    }

    pub fn split_row_counts(&self) -> Vec<(TypedCpSplitComponent, usize)> {
        [
            TypedCpSplitComponent::Leaf,
            TypedCpSplitComponent::Accumulator,
            TypedCpSplitComponent::LeafAccumulatorBinding,
        ]
        .into_iter()
        .map(|component| (component, self.row_count_by_split_component(component)))
        .collect()
    }

    pub fn unsatisfied_blocks(
        &self,
        r1cs: &R1CSMatrices,
        z: &[i64],
        q: u64,
    ) -> Vec<TypedCpAuditBlock> {
        if self.validate_against(r1cs).is_err() || z.len() != r1cs.num_variables {
            return Vec::new();
        }
        let az = r1cs.a.mul_vec_mod(z, q);
        let bz = r1cs.b.mul_vec_mod(z, q);
        let cz = r1cs.c.mul_vec_mod(z, q);
        let mut seen = BTreeMap::<usize, TypedCpAuditBlock>::new();
        for row in 0..r1cs.num_constraints {
            if centered_mod(az[row] as i128 * bz[row] as i128 - cz[row] as i128, q) != 0 {
                if let Some(block) = self.block_for_row(row) {
                    seen.entry(block.start_row).or_insert_with(|| block.clone());
                }
            }
        }
        seen.into_values().collect()
    }
}

#[derive(Debug, Default)]
struct TypedCpAuditBuilder {
    blocks: Vec<TypedCpAuditBlock>,
}

impl TypedCpAuditBuilder {
    fn push(
        &mut self,
        kind: TypedCpAuditBlockKind,
        label: impl Into<String>,
        start_row: usize,
        end_row: usize,
        cp_field_relation_checks: &[&str],
    ) {
        if end_row <= start_row {
            return;
        }
        self.blocks.push(TypedCpAuditBlock {
            kind,
            label: label.into(),
            start_row,
            row_count: end_row - start_row,
            cp_field_relation_checks: cp_field_relation_checks
                .iter()
                .map(|check| (*check).to_string())
                .collect(),
        });
    }

    fn finish(
        self,
        num_public: usize,
        num_variables: usize,
        num_constraints: usize,
    ) -> TypedCpAuditReport {
        TypedCpAuditReport {
            num_public,
            num_variables,
            num_constraints,
            blocks: self.blocks,
        }
    }
}

fn audit_push(
    audit: &mut Option<&mut TypedCpAuditBuilder>,
    kind: TypedCpAuditBlockKind,
    label: impl Into<String>,
    start_row: usize,
    end_row: usize,
    cp_field_relation_checks: &[&str],
) {
    if let Some(audit) = audit.as_deref_mut() {
        audit.push(kind, label, start_row, end_row, cp_field_relation_checks);
    }
}

#[derive(Debug, Clone, Default)]
struct Lin(Vec<(usize, i64)>);

impl Lin {
    fn zero() -> Self {
        Self(Vec::new())
    }

    fn var(idx: usize) -> Self {
        Self(vec![(idx, 1)])
    }

    fn constant(one: usize, value: u32) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self(vec![(one, centered_coeff(value))])
        }
    }

    fn add(&self, other: &Self) -> Self {
        let mut out = self.0.clone();
        out.extend_from_slice(&other.0);
        Self::normalized(out)
    }

    fn sub(&self, other: &Self) -> Self {
        let mut out = self.0.clone();
        out.extend(other.0.iter().map(|&(idx, coeff)| (idx, -coeff)));
        Self::normalized(out)
    }

    fn scale(&self, coeff: u32) -> Self {
        if coeff == 0 {
            return Self::zero();
        }
        let coeff = coeff as i128;
        Self(
            self.0
                .iter()
                .map(|&(idx, c)| (idx, centered_i128(c as i128 * coeff)))
                .collect(),
        )
    }

    fn normalized(entries: Vec<(usize, i64)>) -> Self {
        let mut acc = BTreeMap::<usize, i128>::new();
        for (idx, coeff) in entries {
            *acc.entry(idx).or_insert(0) += coeff as i128;
        }
        Self(
            acc.into_iter()
                .filter_map(|(idx, coeff)| {
                    let coeff = centered_i128(coeff);
                    (coeff != 0).then_some((idx, coeff))
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone)]
struct Constraint {
    a: Lin,
    b: Lin,
    c: Lin,
}

#[derive(Debug)]
struct Builder {
    constraints: Vec<Constraint>,
    next_var: usize,
    one: usize,
}

impl Builder {
    fn new(num_public: usize, one: usize) -> Self {
        Self {
            constraints: Vec::new(),
            next_var: num_public,
            one,
        }
    }

    fn alloc(&mut self) -> Lin {
        let idx = self.next_var;
        self.next_var += 1;
        Lin::var(idx)
    }

    fn constrain_mul(&mut self, a: Lin, b: Lin, c: Lin) {
        self.constraints.push(Constraint { a, b, c });
    }

    fn constrain_eq(&mut self, lhs: Lin, rhs: Lin) {
        self.constrain_mul(lhs.sub(&rhs), Lin::var(self.one), Lin::zero());
    }

    fn sbox7(&mut self, x: Lin) -> Lin {
        let x2 = self.alloc();
        self.constrain_mul(x.clone(), x.clone(), x2.clone());
        let x4 = self.alloc();
        self.constrain_mul(x2.clone(), x2.clone(), x4.clone());
        let x6 = self.alloc();
        self.constrain_mul(x4, x2, x6.clone());
        let x7 = self.alloc();
        self.constrain_mul(x6, x, x7.clone());
        x7
    }

    fn into_r1cs(self, num_public: usize) -> R1CSMatrices {
        let num_variables = self.next_var;
        self.into_r1cs_with_num_variables(num_public, num_variables)
    }

    fn into_r1cs_with_num_variables(self, num_public: usize, num_variables: usize) -> R1CSMatrices {
        let mut r1cs = R1CSMatrices::new(self.constraints.len(), num_variables, num_public);
        for (row, constraint) in self.constraints.into_iter().enumerate() {
            for (col, coeff) in constraint.a.0 {
                r1cs.a.insert(row, col, coeff);
            }
            for (col, coeff) in constraint.b.0 {
                r1cs.b.insert(row, col, coeff);
            }
            for (col, coeff) in constraint.c.0 {
                r1cs.c.insert(row, col, coeff);
            }
        }
        r1cs
    }
}
