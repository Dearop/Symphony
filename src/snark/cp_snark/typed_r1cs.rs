//! Field-native typed CP R1CS building blocks.
//!
//! This module starts with the circuit-native Poseidon2/BabyBear digest gadget
//! used by the authoritative typed CP relation. It intentionally keeps the
//! authority flag outside this module; callers must only flip that flag after
//! the composed CP relation negative tests pass.

use super::r1cs::{encode_cp_witness_r1cs, CpR1csLayout};
use crate::digest_core::{
    derive_challenges_with_scheme, poseidon_digest_input_elems, serialize_poseidon_digest_elems,
    Digest32, FoldInput, PublicDigestScheme,
};
use crate::folding::FoldedInstance;
use crate::params::{D, T};
use crate::r1cs::R1CSMatrices;
use crate::ring::arith::{centered_mod, mod_inv};
use crate::ring::extension::ExtFieldElement;
use crate::ring::{RingElement, RingVector};
use crate::rok::gr1cs::GR1CSProof;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use rand::distr::StandardUniform;
use rand::{rngs::ChaCha20Rng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const BB_P: u64 = 2_013_265_921;
const WIDTH: usize = 16;
const RATE: usize = 8;
const OUT: usize = 8;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 13;
const TYPED_BETA_CHALLENGE_BYTES: usize = 32;
const TYPED_BETA_DIGIT_SELECTOR_VALUES: usize = 5;
const TYPED_BETA_QUOTIENT_SELECTOR_VALUES: usize = 11;
const TYPED_BETA_SELECTORS_PER_BYTE: usize =
    TYPED_BETA_DIGIT_SELECTOR_VALUES * 2 + TYPED_BETA_QUOTIENT_SELECTOR_VALUES;
const TYPED_BETA_CONSTRAINTS_PER_BYTE: usize = TYPED_BETA_SELECTORS_PER_BYTE + 6;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCpAuditBlock {
    pub kind: TypedCpAuditBlockKind,
    pub label: String,
    pub start_row: usize,
    pub row_count: usize,
    pub cp_field_relation_checks: Vec<String>,
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

#[derive(Debug, Clone)]
struct Poseidon2Constants {
    external_initial: Vec<[u32; WIDTH]>,
    external_terminal: Vec<[u32; WIDTH]>,
    internal: Vec<u32>,
}

fn constants_for_domain(domain: &[u8]) -> Poseidon2Constants {
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"symphony-poseidon2-babybear-public-digest-v1");
    seed_hasher.update((domain.len() as u64).to_le_bytes());
    seed_hasher.update(domain);
    let seed: [u8; 32] = seed_hasher.finalize().into();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let external_initial = (0..HALF_FULL_ROUNDS)
        .map(|_| sample_state(&mut rng))
        .collect();
    let external_terminal = (0..HALF_FULL_ROUNDS)
        .map(|_| sample_state(&mut rng))
        .collect();
    let internal = (0..PARTIAL_ROUNDS)
        .map(|_| sample_babybear(&mut rng))
        .collect();
    Poseidon2Constants {
        external_initial,
        external_terminal,
        internal,
    }
}

fn sample_state(rng: &mut ChaCha20Rng) -> [u32; WIDTH] {
    let elems: [BabyBear; WIDTH] = rng.sample(StandardUniform);
    elems.map(|v| v.as_canonical_u32())
}

fn sample_babybear(rng: &mut ChaCha20Rng) -> u32 {
    let elem: BabyBear = rng.sample(StandardUniform);
    elem.as_canonical_u32()
}

pub fn poseidon2_babybear_digest_elems(domain: &[u8], input: &[BabyBear]) -> [BabyBear; OUT] {
    let constants = constants_for_domain(domain);
    let mut state = [0u32; WIDTH];
    let input: Vec<u32> = input.iter().map(|v| v.as_canonical_u32()).collect();
    sponge_permute_input(&constants, &mut state, &input);
    core::array::from_fn(|idx| BabyBear::from_u32(state[idx]))
}

pub fn generate_poseidon2_digest_r1cs(
    domain: &[u8],
    input_len: usize,
) -> (R1CSMatrices, Poseidon2DigestR1csLayout) {
    let layout = Poseidon2DigestR1csLayout {
        input_len,
        off_one: 0,
        off_input: 1,
        off_output: 1 + input_len,
        num_public: 1 + input_len + OUT,
        num_variables: 0,
    };
    let constants = constants_for_domain(domain);
    let mut builder = Builder::new(layout.num_public, layout.off_one);
    let mut state: [Lin; WIDTH] = core::array::from_fn(|_| Lin::zero());
    let mut pos = 0usize;

    loop {
        let mut absorbed = 0usize;
        for i in 0..RATE {
            if pos < input_len {
                state[i] = Lin::var(layout.off_input + pos);
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    circuit_permutation(&mut builder, &constants, &mut state);
                }
                for (idx, item) in state.iter().enumerate().take(OUT) {
                    builder.constrain_eq(item.clone(), Lin::var(layout.off_output + idx));
                }
                let mut final_layout = layout;
                final_layout.num_variables = builder.next_var;
                return (builder.into_r1cs(final_layout.num_public), final_layout);
            }
        }
        circuit_permutation(&mut builder, &constants, &mut state);
    }
}

pub fn generate_poseidon2_private_digest_r1cs(
    domain: &[u8],
    input_len: usize,
) -> (R1CSMatrices, Poseidon2PrivateDigestR1csLayout) {
    let layout = Poseidon2PrivateDigestR1csLayout {
        input_len,
        off_one: 0,
        off_output: 1,
        off_input: 1 + OUT,
        num_public: 1 + OUT,
        num_variables: 0,
    };
    let constants = constants_for_domain(domain);
    let mut builder = Builder::new(layout.num_public, layout.off_one);
    builder.next_var = layout.off_input + input_len;
    let mut state: [Lin; WIDTH] = core::array::from_fn(|_| Lin::zero());
    let mut pos = 0usize;

    loop {
        let mut absorbed = 0usize;
        for i in 0..RATE {
            if pos < input_len {
                state[i] = Lin::var(layout.off_input + pos);
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    circuit_permutation(&mut builder, &constants, &mut state);
                }
                for (idx, item) in state.iter().enumerate().take(OUT) {
                    builder.constrain_eq(item.clone(), Lin::var(layout.off_output + idx));
                }
                let mut final_layout = layout;
                final_layout.num_variables = builder.next_var;
                return (builder.into_r1cs(final_layout.num_public), final_layout);
            }
        }
        circuit_permutation(&mut builder, &constants, &mut state);
    }
}

fn poseidon2_digest_permutation_count(input_len: usize) -> usize {
    input_len.div_ceil(RATE)
}

fn poseidon2_digest_aux_len(input_len: usize) -> usize {
    let sboxes_per_permutation = 2 * HALF_FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS;
    poseidon2_digest_permutation_count(input_len) * sboxes_per_permutation * 4
}

fn poseidon2_direct_digest_constraints_count(input_len: usize) -> usize {
    poseidon2_digest_aux_len(input_len) + OUT
}

fn digest_template_input_lins(domain: &[u8], block: &TypedCpDigestBlockLayout) -> Vec<Lin> {
    let input_bytes = poseidon_digest_input_byte_template(domain, block.body_len);
    assert_eq!(block.input_len, input_bytes.len().div_ceil(3) + 1);
    assert!(
        input_bytes.len() < BB_P as usize,
        "typed CP digest body is too large for BabyBear length sentinel"
    );

    let mut inputs = Vec::with_capacity(block.input_len);
    for input_idx in 0..block.input_len {
        if input_idx + 1 == block.input_len {
            inputs.push(Lin::constant(0, input_bytes.len() as u32));
            continue;
        }

        let mut input = Lin::zero();
        for byte_offset in 0..3 {
            let source_idx = input_idx * 3 + byte_offset;
            let coeff = 1u32 << (8 * byte_offset);
            match input_bytes.get(source_idx).copied() {
                Some(DigestInputByte::Const(value)) => {
                    input = input.add(&Lin::constant(0, value as u32).scale(coeff));
                }
                Some(DigestInputByte::Body(body_idx)) => {
                    input = input.add(&Lin::var(block.off_body_bytes + body_idx).scale(coeff));
                }
                None => {}
            }
        }
        inputs.push(input);
    }
    inputs
}

fn generate_poseidon2_direct_digest_r1cs(
    domain: &[u8],
    block: &TypedCpDigestBlockLayout,
    num_public: usize,
) -> (R1CSMatrices, usize) {
    let input_lins = digest_template_input_lins(domain, block);
    let constants = constants_for_domain(domain);
    let mut builder = Builder::new(num_public, 0);
    builder.next_var = block.off_private_witness;
    let mut state: [Lin; WIDTH] = core::array::from_fn(|_| Lin::zero());
    let mut pos = 0usize;

    loop {
        let mut absorbed = 0usize;
        for item in state.iter_mut().take(RATE) {
            if pos < input_lins.len() {
                *item = input_lins[pos].clone();
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    circuit_permutation(&mut builder, &constants, &mut state);
                }
                for (idx, item) in state.iter().enumerate().take(OUT) {
                    builder.constrain_eq(item.clone(), Lin::var(block.off_public_output + idx));
                }
                let aux_end = builder.next_var;
                let num_variables = (block.off_body_bits + block.body_len * 8).max(aux_end);
                let r1cs = builder.into_r1cs_with_num_variables(num_public, num_variables);
                return (r1cs, aux_end);
            }
        }
        circuit_permutation(&mut builder, &constants, &mut state);
    }
}

pub fn encode_poseidon2_digest_instance(input: &[BabyBear], digest: &[BabyBear; OUT]) -> Vec<u8> {
    let mut out = Vec::with_capacity((1 + input.len() + OUT) * 8);
    out.extend_from_slice(&1i64.to_le_bytes());
    for elem in input {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    for elem in digest {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    out
}

pub fn encode_poseidon2_private_digest_instance(digest: &[BabyBear; OUT]) -> Vec<u8> {
    let mut out = Vec::with_capacity((1 + OUT) * 8);
    out.extend_from_slice(&1i64.to_le_bytes());
    for elem in digest {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    out
}

pub fn encode_poseidon2_private_digest_witness(domain: &[u8], input: &[BabyBear]) -> Vec<u8> {
    let mut out = Vec::new();
    for elem in input {
        out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
    }
    out.extend_from_slice(&encode_poseidon2_digest_witness(domain, input));
    out
}

pub fn encode_poseidon2_digest_witness(domain: &[u8], input: &[BabyBear]) -> Vec<u8> {
    let constants = constants_for_domain(domain);
    let mut z_values = Vec::<u32>::new();
    let mut state = [0u32; WIDTH];
    let input_u32: Vec<u32> = input.iter().map(|v| v.as_canonical_u32()).collect();
    sponge_permute_input_recording(&constants, &mut state, &input_u32, &mut z_values);

    let mut out = Vec::with_capacity(z_values.len() * 8);
    for value in z_values {
        out.extend_from_slice(&(value as i64).to_le_bytes());
    }
    out
}

fn append_digest_body_binding_witness(out: &mut Vec<u8>, body: &[u8]) {
    for &byte in body {
        out.extend_from_slice(&(byte as i64).to_le_bytes());
    }
    for &byte in body {
        for bit in 0..8 {
            out.extend_from_slice(&(((byte >> bit) & 1) as i64).to_le_bytes());
        }
    }
}

pub fn poseidon2_digest32_from_body(domain: &[u8], body: &[u8]) -> Digest32 {
    let input = poseidon_digest_input_elems(domain, body);
    serialize_poseidon_digest_elems(poseidon2_babybear_digest_elems(domain, &input))
}

fn typed_beta_base5_components(byte: u8) -> (usize, usize, usize) {
    let d0 = (byte % 5) as usize;
    let d1 = ((byte / 5) % 5) as usize;
    let quotient = (byte / 25) as usize;
    debug_assert!(quotient < TYPED_BETA_QUOTIENT_SELECTOR_VALUES);
    (d0, d1, quotient)
}

pub fn poseidon_challenge_to_beta(challenge: &[u8]) -> Option<RingElement> {
    if challenge.len() != TYPED_BETA_CHALLENGE_BYTES || D != TYPED_BETA_CHALLENGE_BYTES * 2 {
        return None;
    }
    let mut coeffs = [0i64; D];
    for (byte_idx, &byte) in challenge.iter().enumerate() {
        let (d0, d1, _) = typed_beta_base5_components(byte);
        coeffs[2 * byte_idx] = d0 as i64 - 2;
        coeffs[2 * byte_idx + 1] = d1 as i64 - 2;
    }
    Some(RingElement { coeffs })
}

pub fn poseidon_challenges_to_betas(challenges: &[Vec<u8>]) -> Option<Vec<RingElement>> {
    challenges
        .iter()
        .map(|challenge| poseidon_challenge_to_beta(challenge))
        .collect()
}

pub fn poseidon_fs_commit_body(message: &[u8], opening: &Digest32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + message.len() + opening.len());
    body.extend_from_slice(&(message.len() as u64).to_le_bytes());
    body.extend_from_slice(message);
    body.extend_from_slice(opening);
    body
}

pub fn poseidon_fs_root_body(commitments: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        body.extend_from_slice(&(commitment.len() as u64).to_le_bytes());
        body.extend_from_slice(commitment);
    }
    body
}

pub fn poseidon_fold_root_body(inputs: &[FoldInput]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    for input in inputs {
        body.extend_from_slice(&(input.commitment_bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(&input.commitment_bytes);
        body.extend_from_slice(&(input.public_input.len() as u64).to_le_bytes());
        for &value in &input.public_input {
            body.extend_from_slice(&value.to_le_bytes());
        }
        body.extend_from_slice(&(input.eval_values_bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(&input.eval_values_bytes);
    }
    body
}

pub fn poseidon_challenge_digest_body(challenges: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(challenges.len() as u64).to_le_bytes());
    for challenge in challenges {
        body.extend_from_slice(&(challenge.len() as u64).to_le_bytes());
        body.extend_from_slice(challenge);
    }
    body
}

pub fn poseidon_transcript_seed_body(
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(public_inputs.len() as u64).to_le_bytes());
    for public_input in public_inputs {
        body.extend_from_slice(&(public_input.len() as u64).to_le_bytes());
        for &value in public_input {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    body.extend_from_slice(&(r1cs_m as u64).to_le_bytes());
    body.extend_from_slice(&(r1cs_n as u64).to_le_bytes());
    body.extend_from_slice(&(r1cs_pub as u64).to_le_bytes());
    body
}

pub fn poseidon_challenge_body(
    index: usize,
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
    fs_commitments: &[Vec<u8>],
) -> Vec<u8> {
    let transcript = crate::cp_relation_core::cp_relation_transcript_bytes(
        public_inputs,
        r1cs_m,
        r1cs_n,
        r1cs_pub,
        fs_commitments,
    );
    let mut body = Vec::with_capacity(8 + transcript.len());
    body.extend_from_slice(&(index as u64).to_le_bytes());
    body.extend_from_slice(&transcript);
    body
}

#[derive(Debug, Clone, Copy)]
enum DigestInputByte {
    Const(u8),
    Body(usize),
}

fn poseidon_digest_input_len(domain: &[u8], body_len: usize) -> usize {
    let byte_len = b"symphony-v2".len() + 8 + domain.len() + 8 + body_len;
    byte_len.div_ceil(3) + 1
}

fn poseidon_digest_input_byte_template(domain: &[u8], body_len: usize) -> Vec<DigestInputByte> {
    let mut bytes = Vec::with_capacity(b"symphony-v2".len() + 8 + domain.len() + 8 + body_len);
    bytes.extend(b"symphony-v2".iter().copied().map(DigestInputByte::Const));
    bytes.extend(
        (domain.len() as u64)
            .to_le_bytes()
            .into_iter()
            .map(DigestInputByte::Const),
    );
    bytes.extend(domain.iter().copied().map(DigestInputByte::Const));
    bytes.extend(
        (body_len as u64)
            .to_le_bytes()
            .into_iter()
            .map(DigestInputByte::Const),
    );
    bytes.extend((0..body_len).map(DigestInputByte::Body));
    bytes
}

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
    let (statement_r1cs, statement_layout) =
        generate_typed_cp_statement_r1cs(cp_r1cs, cp_layout, ajtai, original_r1cs);
    assert_eq!(lengths.fs_commitment_inputs.len(), cp_layout.ell_np);
    assert_eq!(lengths.gr1cs_message_bodies.len(), cp_layout.ell_np);
    assert_eq!(lengths.gr1cs_message_shapes.len(), cp_layout.ell_np);
    assert_eq!(lengths.challenge_inputs.len(), cp_layout.ell_np);
    assert_eq!(lengths.challenge_bodies.len(), cp_layout.ell_np);

    let digest_publics = (lengths.fs_commitment_inputs.len() + 4) * OUT;
    let folded_eval_publics = lengths.folded_evaluation_values * T * D;
    let off_fs_commitments = statement_layout.num_public;
    let off_fs_root = off_fs_commitments + lengths.fs_commitment_inputs.len() * OUT;
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
            false,
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
            format!("poseidon-digest-gadget-{idx}"),
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
    row_offset = insert_fs_root_public_commitment_constraints(
        &mut r1cs,
        row_offset,
        off_fs_commitments,
        lengths.fs_commitment_inputs.len(),
        &digest_blocks[fs_root_idx],
    );
    audit.push(
        TypedCpAuditBlockKind::ByteConstraints,
        "fs-root-public-commitment-limb-binding",
        start,
        row_offset,
        &["FS root binds public FS commitments"],
    );
    let mut audit_ref = Some(&mut audit);
    row_offset = insert_structured_digest_body_constraints(
        &mut r1cs,
        row_offset,
        &statement_layout,
        off_fs_commitments,
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
    if fs_commitments.len() != layout.fs_commitment_blocks.len() {
        return None;
    }
    let mut out = encode_typed_cp_statement_instance(
        &public.instance.x_folded,
        &public.public_inputs,
        &layout.statement,
    );
    for commitment in fs_commitments {
        let commitment: Digest32 = commitment.as_slice().try_into().ok()?;
        for elem in digest32_to_babybear_elems(&commitment)? {
            out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
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
                                     expected_input_len: usize,
                                     expected_body_len: usize|
     -> Option<()> {
        if body.len() != expected_body_len {
            return None;
        }
        let input = poseidon_digest_input_elems(domain, &body);
        if input.len() != expected_input_len {
            return None;
        }
        out.extend_from_slice(&encode_poseidon2_digest_witness(domain, &input));
        append_digest_body_binding_witness(&mut out, &body);
        Some(())
    };

    for ((message, opening), block) in witness
        .fs_messages
        .iter()
        .zip(witness.fs_openings.iter())
        .zip(layout.fs_commitment_blocks.iter())
    {
        let opening: Digest32 = opening.as_slice().try_into().ok()?;
        append_digest_witness(
            b"fs-commit",
            poseidon_fs_commit_body(message, &opening),
            block.input_len,
            block.body_len,
        )?;
    }
    append_digest_witness(
        b"fs-root",
        poseidon_fs_root_body(&witness.fs_commitments),
        layout.fs_root_block.input_len,
        layout.fs_root_block.body_len,
    )?;
    append_digest_witness(
        b"fold-root",
        poseidon_fold_root_body(&witness.fold_inputs),
        layout.fold_root_block.input_len,
        layout.fold_root_block.body_len,
    )?;
    append_digest_witness(
        b"challenge-digest",
        poseidon_challenge_digest_body(&challenges),
        layout.challenge_digest_block.input_len,
        layout.challenge_digest_block.body_len,
    )?;
    append_digest_witness(
        b"transcript-seed",
        poseidon_transcript_seed_body(
            &public.public_inputs,
            public.r1cs_num_constraints,
            public.r1cs_num_variables,
            public.r1cs_num_public,
        ),
        layout.transcript_seed_block.input_len,
        layout.transcript_seed_block.body_len,
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
        if body.len() != block.body_len {
            return None;
        }
        let input = poseidon_digest_input_elems(b"challenge", &body);
        if input.len() != block.input_len {
            return None;
        }
        let digest = poseidon2_babybear_digest_elems(b"challenge", &input);
        let digest_bytes = serialize_poseidon_digest_elems(digest);
        if challenges.get(idx).map(Vec::as_slice) != Some(digest_bytes.as_slice()) {
            return None;
        }
        for elem in digest {
            out.extend_from_slice(&(elem.as_canonical_u32() as i64).to_le_bytes());
        }
        out.extend_from_slice(&encode_poseidon2_digest_witness(b"challenge", &input));
        append_digest_body_binding_witness(&mut out, &body);
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

fn append_monomial_sumcheck_semantic_witness(
    out: &mut Vec<u8>,
    proof: &GR1CSProof,
    shared: &crate::cp_relation_core::CpSharedChallengeData,
    block: &TypedCpRangePayloadBlockLayout,
    q: u64,
) -> Option<()> {
    let range_proof = &proof.range_proof;
    let monomial_proof = &range_proof.monomial_proof;
    let nv = monomial_proof.sumcheck_proof.round_messages.len();
    let k_g = monomial_proof.evaluations.len();
    if shared.sumcheck_seed_mon.len() != nv
        || shared.monomial_sumcheck_challenges.len() != nv
        || monomial_proof.sq_evaluations.len() != k_g
    {
        return None;
    }
    if monomial_proof
        .sumcheck_proof
        .round_messages
        .iter()
        .any(|round| round.evaluations.len() != 5)
    {
        return None;
    }

    for challenge in &shared.sumcheck_seed_mon {
        out.extend_from_slice(&challenge.c0.to_le_bytes());
        out.extend_from_slice(&challenge.c1.to_le_bytes());
    }
    for challenge in &shared.monomial_sumcheck_challenges {
        out.extend_from_slice(&challenge.c0.to_le_bytes());
        out.extend_from_slice(&challenge.c1.to_le_bytes());
    }
    out.extend_from_slice(&shared.alpha.c0.to_le_bytes());
    out.extend_from_slice(&shared.alpha.c1.to_le_bytes());

    let mut aux_values = Vec::<i64>::new();
    let mut wrap_values = Vec::<i64>::new();
    let mut claim = ext_wit_const(0);
    let inv2 = q_inv_const(2, q);
    let inv6 = q_inv_const(6, q);
    let inv24 = q_inv_const(24, q);

    for round in 0..nv {
        let evals = &monomial_proof.sumcheck_proof.round_messages[round].evaluations;
        push_ext_linear_eq_wrap(
            ext_wit_add(ext_wit(evals[0]), ext_wit(evals[1]), q),
            claim,
            q,
            &mut wrap_values,
        )?;

        let e0 = ext_wit(evals[0]);
        let e1 = ext_wit(evals[1]);
        let e2 = ext_wit(evals[2]);
        let e3 = ext_wit(evals[3]);
        let e4 = ext_wit(evals[4]);
        let d1 = ext_wit_sub(e1, e0, q);
        let d2 = ext_wit_scale(
            ext_wit_add(ext_wit_sub(e0, ext_wit_scale(e1, 2, q), q), e2, q),
            inv2,
            q,
        );
        let d3 = ext_wit_scale(
            ext_wit_add(
                ext_wit_add(
                    ext_wit_sub(ext_wit_scale(e1, 3, q), e0, q),
                    ext_wit_scale(e2, -3, q),
                    q,
                ),
                e3,
                q,
            ),
            inv6,
            q,
        );
        let d4 = ext_wit_scale(
            ext_wit_add(
                ext_wit_add(
                    ext_wit_add(
                        ext_wit_sub(e0, ext_wit_scale(e1, 4, q), q),
                        ext_wit_scale(e2, 6, q),
                        q,
                    ),
                    ext_wit_scale(e3, -4, q),
                    q,
                ),
                e4,
                q,
            ),
            inv24,
            q,
        );
        let r = ext_wit(shared.monomial_sumcheck_challenges[round]);
        let m1 = record_ext_mul_value(
            d4,
            ext_wit_sub(r, ext_wit_const(3), q),
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        let m2 = record_ext_mul_value(
            ext_wit_add(m1, d3, q),
            ext_wit_sub(r, ext_wit_const(2), q),
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        let m3 = record_ext_mul_value(
            ext_wit_add(m2, d2, q),
            ext_wit_sub(r, ext_wit_const(1), q),
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        let m4 = record_ext_mul_value(
            ext_wit_add(m3, d1, q),
            r,
            q,
            &mut aux_values,
            &mut wrap_values,
        )?;
        claim = ext_wit_add(m4, e0, q);
    }

    let eq_val = if nv == 0 {
        ext_wit_const(1)
    } else {
        let mut acc = ext_wit_const(0);
        for i in 0..nv {
            let seed = ext_wit(shared.sumcheck_seed_mon[i]);
            let r = ext_wit(shared.monomial_sumcheck_challenges[nv - 1 - i]);
            let sr = record_ext_mul_value(seed, r, q, &mut aux_values, &mut wrap_values)?;
            let factor = ext_wit_add(
                ext_wit_sub(ext_wit_sub(ext_wit_scale(sr, 2, q), seed, q), r, q),
                ext_wit_const(1),
                q,
            );
            if i == 0 {
                acc = factor;
            } else {
                acc = record_ext_mul_value(acc, factor, q, &mut aux_values, &mut wrap_values)?;
            }
        }
        acc
    };

    let total_terms = k_g * D + k_g;
    let mut combined = ext_wit_const(0);
    let mut alpha_power = ext_wit_const(1);
    let alpha = ext_wit(shared.alpha);
    for term_idx in 0..total_terms {
        if term_idx == 1 {
            alpha_power = alpha;
        } else if term_idx > 1 {
            alpha_power =
                record_ext_mul_value(alpha_power, alpha, q, &mut aux_values, &mut wrap_values)?;
        }

        let poly_term = if term_idx < k_g * D {
            let vector = term_idx / D;
            let coeff = term_idx % D;
            let c_val = ext_wit(monomial_proof.evaluations[vector].col(coeff));
            let c_minus_times_plus = record_ext_mul_value(
                ext_wit_sub(c_val, ext_wit_const(1), q),
                ext_wit_add(c_val, ext_wit_const(1), q),
                q,
                &mut aux_values,
                &mut wrap_values,
            )?;
            record_ext_mul_value(
                c_val,
                c_minus_times_plus,
                q,
                &mut aux_values,
                &mut wrap_values,
            )?
        } else {
            let vector = term_idx - k_g * D;
            let sq = ext_wit(monomial_proof.sq_evaluations[vector]);
            record_ext_mul_value(
                sq,
                ext_wit_sub(sq, ext_wit_const(1), q),
                q,
                &mut aux_values,
                &mut wrap_values,
            )?
        };

        let weighted_term = if term_idx == 0 {
            poly_term
        } else {
            record_ext_mul_value(alpha_power, poly_term, q, &mut aux_values, &mut wrap_values)?
        };
        combined = ext_wit_add(combined, weighted_term, q);
    }

    let expected = if nv == 0 {
        combined
    } else {
        record_ext_mul_value(eq_val, combined, q, &mut aux_values, &mut wrap_values)?
    };
    push_ext_linear_eq_wrap(expected, claim, q, &mut wrap_values)?;

    append_monomial_evaluation_binding_witness(
        proof,
        shared,
        q,
        &mut aux_values,
        &mut wrap_values,
    )?;

    if aux_values.len() != block.monomial_sumcheck_aux_count
        || wrap_values.len() != block.monomial_sumcheck_wrap_count
    {
        return None;
    }
    for value in aux_values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for value in wrap_values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Some(())
}

fn append_monomial_evaluation_binding_witness(
    proof: &GR1CSProof,
    shared: &crate::cp_relation_core::CpSharedChallengeData,
    q: u64,
    aux_values: &mut Vec<i64>,
    wrap_values: &mut Vec<i64>,
) -> Option<()> {
    let monomial_proof = &proof.range_proof.monomial_proof;
    let nv = monomial_proof.sumcheck_proof.round_messages.len();
    let table_size = 1usize.checked_shl(nv as u32)?;
    if shared.monomial_sumcheck_challenges.len() != nv {
        return None;
    }

    for (vector_idx, monomial_vector) in proof.range_proof.monomial_vectors.iter().enumerate() {
        let tensor = monomial_proof.evaluations.get(vector_idx)?;
        for coeff in 0..D {
            let mut initial = Vec::with_capacity(table_size);
            for idx in 0..table_size {
                let value = monomial_vector
                    .get(idx)
                    .map(|elem| elem.coeffs[coeff])
                    .unwrap_or(0);
                initial.push(ext_wit(ExtFieldElement { c0: value, c1: 0 }));
            }
            append_mle_binding_witness(
                initial,
                ext_wit(tensor.col(coeff)),
                &shared.monomial_sumcheck_challenges,
                q,
                aux_values,
                wrap_values,
            )?;
        }

        let mut initial_sq = Vec::with_capacity(table_size);
        for idx in 0..table_size {
            let sq_sum = monomial_vector
                .get(idx)
                .map(|elem| elem.coeffs.iter().map(|&coeff| coeff * coeff).sum())
                .unwrap_or(0);
            initial_sq.push(ext_wit(ExtFieldElement { c0: sq_sum, c1: 0 }));
        }
        append_mle_binding_witness(
            initial_sq,
            ext_wit(*monomial_proof.sq_evaluations.get(vector_idx)?),
            &shared.monomial_sumcheck_challenges,
            q,
            aux_values,
            wrap_values,
        )?;
    }
    Some(())
}

fn append_mle_binding_witness(
    mut values: Vec<ExtWitnessValue>,
    claim: ExtWitnessValue,
    challenges: &[ExtFieldElement],
    q: u64,
    aux_values: &mut Vec<i64>,
    wrap_values: &mut Vec<i64>,
) -> Option<()> {
    for challenge in challenges {
        let half = values.len() / 2;
        let r = ext_wit(*challenge);
        let mut next = Vec::with_capacity(half);
        for idx in 0..half {
            let left = values[idx];
            let right = values[half + idx];
            let diff = ext_wit_sub(right, left, q);
            let scaled = record_ext_mul_value(r, diff, q, aux_values, wrap_values)?;
            let folded_expr = ext_wit_add(left, scaled, q);
            let folded_var = ext_wit(folded_expr.reduced);
            aux_values.extend_from_slice(&[folded_var.reduced.c0, folded_var.reduced.c1]);
            push_ext_linear_eq_wrap(folded_expr, folded_var, q, wrap_values)?;
            next.push(folded_var);
        }
        values = next;
    }
    if values.len() != 1 {
        return None;
    }
    push_ext_linear_eq_wrap(values[0], claim, q, wrap_values)
}

#[derive(Clone, Copy)]
struct ExtWitnessValue {
    reduced: ExtFieldElement,
    raw_c0: i128,
    raw_c1: i128,
}

fn ext_wit(value: ExtFieldElement) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: value,
        raw_c0: value.c0 as i128,
        raw_c1: value.c1 as i128,
    }
}

fn ext_wit_const(value: i64) -> ExtWitnessValue {
    ext_wit(ExtFieldElement { c0: value, c1: 0 })
}

fn ext_wit_add(a: ExtWitnessValue, b: ExtWitnessValue, q: u64) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: ExtFieldElement {
            c0: centered_mod(a.reduced.c0 as i128 + b.reduced.c0 as i128, q),
            c1: centered_mod(a.reduced.c1 as i128 + b.reduced.c1 as i128, q),
        },
        raw_c0: a.raw_c0 + b.raw_c0,
        raw_c1: a.raw_c1 + b.raw_c1,
    }
}

fn ext_wit_sub(a: ExtWitnessValue, b: ExtWitnessValue, q: u64) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: ExtFieldElement {
            c0: centered_mod(a.reduced.c0 as i128 - b.reduced.c0 as i128, q),
            c1: centered_mod(a.reduced.c1 as i128 - b.reduced.c1 as i128, q),
        },
        raw_c0: a.raw_c0 - b.raw_c0,
        raw_c1: a.raw_c1 - b.raw_c1,
    }
}

fn ext_wit_scale(a: ExtWitnessValue, coeff: i64, q: u64) -> ExtWitnessValue {
    ExtWitnessValue {
        reduced: ExtFieldElement {
            c0: centered_mod(a.reduced.c0 as i128 * coeff as i128, q),
            c1: centered_mod(a.reduced.c1 as i128 * coeff as i128, q),
        },
        raw_c0: a.raw_c0 * coeff as i128,
        raw_c1: a.raw_c1 * coeff as i128,
    }
}

fn q_wrap(diff: i128, q: u64) -> Option<i64> {
    if diff.rem_euclid(q as i128) != 0 {
        return None;
    }
    i64::try_from(diff / q as i128).ok()
}

fn push_ext_linear_eq_wrap(
    lhs: ExtWitnessValue,
    rhs: ExtWitnessValue,
    q: u64,
    wraps: &mut Vec<i64>,
) -> Option<()> {
    wraps.push(q_wrap(lhs.raw_c0 - rhs.raw_c0, q)?);
    wraps.push(q_wrap(lhs.raw_c1 - rhs.raw_c1, q)?);
    Some(())
}

fn record_ext_mul_value(
    lhs: ExtWitnessValue,
    rhs: ExtWitnessValue,
    q: u64,
    aux_values: &mut Vec<i64>,
    wrap_values: &mut Vec<i64>,
) -> Option<ExtWitnessValue> {
    let qnr = crate::ring::extension::ExtFieldContext::new(q).alpha;
    let p1 = centered_mod(lhs.raw_c0 * rhs.raw_c0, q);
    let p2 = centered_mod(lhs.raw_c1 * rhs.raw_c1, q);
    let c1 = centered_mod(
        (lhs.raw_c0 + lhs.raw_c1) * (rhs.raw_c0 + rhs.raw_c1) - p1 as i128 - p2 as i128,
        q,
    );
    let c0 = centered_mod(p1 as i128 + qnr as i128 * p2 as i128, q);

    aux_values.extend_from_slice(&[p1, p2, c0, c1]);
    wrap_values.push(q_wrap(lhs.raw_c0 * rhs.raw_c0 - p1 as i128, q)?);
    wrap_values.push(q_wrap(lhs.raw_c1 * rhs.raw_c1 - p2 as i128, q)?);
    wrap_values.push(q_wrap(
        (lhs.raw_c0 + lhs.raw_c1) * (rhs.raw_c0 + rhs.raw_c1)
            - c1 as i128
            - p1 as i128
            - p2 as i128,
        q,
    )?);
    wrap_values.push(q_wrap(
        c0 as i128 - p1 as i128 - qnr as i128 * p2 as i128,
        q,
    )?);

    Some(ext_wit(ExtFieldElement { c0, c1 }))
}

fn circuit_permutation(
    builder: &mut Builder,
    constants: &Poseidon2Constants,
    state: &mut [Lin; WIDTH],
) {
    circuit_mds_light(state);
    for round in &constants.external_initial {
        for i in 0..WIDTH {
            state[i] = builder.sbox7(state[i].add(&Lin::constant(builder.one, round[i])));
        }
        circuit_mds_light(state);
    }
    for &rc in &constants.internal {
        state[0] = builder.sbox7(state[0].add(&Lin::constant(builder.one, rc)));
        circuit_internal_linear(state);
    }
    for round in &constants.external_terminal {
        for i in 0..WIDTH {
            state[i] = builder.sbox7(state[i].add(&Lin::constant(builder.one, round[i])));
        }
        circuit_mds_light(state);
    }
}

fn insert_ajtai_opening_lc(
    r1cs: &mut R1CSMatrices,
    row: usize,
    layout: &OriginalStatementR1csLayout,
    ajtai: &crate::commitment::AjtaiParams,
    commitment_row: usize,
    coeff: usize,
) {
    for col in 0..ajtai.n {
        let a = &ajtai.a[commitment_row][col];
        if col < layout.n_public {
            let public_col = layout.off_public_input + col;
            r1cs.a
                .insert(row, public_col, centered_mod(a.coeffs[coeff] as i128, BB_P));
        } else {
            let witness_col = col - layout.n_public;
            for a_coeff in 0..D {
                let (w_coeff, sign) = negacyclic_partner(coeff, a_coeff);
                let z_col = layout.off_witness + witness_col * D + w_coeff;
                r1cs.a.insert(
                    row,
                    z_col,
                    centered_mod(sign * a.coeffs[a_coeff] as i128, BB_P),
                );
            }
        }
    }
    let commitment_col = layout.off_commitment + commitment_row * D + coeff;
    r1cs.a.insert(row, commitment_col, -1);
    let wrap_col = layout.off_ajtai_wrap + commitment_row * D + coeff;
    r1cs.a.insert(row, wrap_col, -(ajtai.q as i64));
    r1cs.b.insert(row, layout.off_one, 1);
}

fn copy_r1cs_block(
    target: &mut R1CSMatrices,
    source: &R1CSMatrices,
    row_offset: usize,
    col_map: &dyn Fn(usize) -> usize,
) {
    for &(row, col, value) in &source.a.entries {
        target.a.insert(row_offset + row, col_map(col), value);
    }
    for &(row, col, value) in &source.b.entries {
        target.b.insert(row_offset + row, col_map(col), value);
    }
    for &(row, col, value) in &source.c.entries {
        target.c.insert(row_offset + row, col_map(col), value);
    }
}

fn insert_digest_body_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    _domain: &[u8],
    block: &TypedCpDigestBlockLayout,
) -> usize {
    for byte_idx in 0..block.body_len {
        let byte_col = block.off_body_bytes + byte_idx;
        r1cs.a.insert(row, byte_col, 1);
        for bit in 0..8 {
            let bit_col = block.off_body_bits + byte_idx * 8 + bit;
            r1cs.a.insert(row, bit_col, -(1i64 << bit));
        }
        r1cs.b.insert(row, 0, 1);
        row += 1;

        for bit in 0..8 {
            let bit_col = block.off_body_bits + byte_idx * 8 + bit;
            r1cs.a.insert(row, bit_col, 1);
            r1cs.b.insert(row, bit_col, 1);
            r1cs.b.insert(row, 0, -1);
            row += 1;
        }
    }

    row
}

fn insert_fs_root_public_commitment_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    off_fs_commitments: usize,
    num_commitments: usize,
    fs_root_block: &TypedCpDigestBlockLayout,
) -> usize {
    let expected_body_len = 8 + num_commitments * (8 + OUT * 4);
    assert_eq!(fs_root_block.body_len, expected_body_len);

    for commitment_idx in 0..num_commitments {
        let body_commitment_offset = 8 + commitment_idx * (8 + OUT * 4) + 8;
        for limb in 0..OUT {
            let public_limb_col = off_fs_commitments + commitment_idx * OUT + limb;
            let body_byte_col = fs_root_block.off_body_bytes + body_commitment_offset + limb * 4;
            r1cs.a.insert(row, public_limb_col, 1);
            r1cs.a.insert(row, body_byte_col, -1);
            r1cs.a.insert(row, body_byte_col + 1, -256);
            r1cs.a.insert(row, body_byte_col + 2, -65_536);
            r1cs.a.insert(row, body_byte_col + 3, -16_777_216);
            r1cs.b.insert(row, 0, 1);
            row += 1;
        }
    }
    row
}

fn structured_digest_body_constraints_count(
    lengths: &TypedCpDigestInputLengths,
    cp_layout: &CpR1csLayout,
    original_r1cs_num_constraints: usize,
    original_r1cs_num_variables: usize,
) -> usize {
    let ell = lengths.fs_commitment_inputs.len();
    let msg_bytes: usize = lengths.gr1cs_message_bodies.iter().sum();
    let fold_commit_limb_constraints = ell * cp_layout.kappa * cp_layout.d;
    let fold_public_input_constraints = ell * cp_layout.n_in;
    let transcript_public_input_constraints = ell * cp_layout.n_in;
    let challenge_output_constraints = ell * OUT;
    let challenge_transcript_public_input_constraints = ell * ell * cp_layout.n_in;
    let challenge_transcript_fs_commitment_constraints = ell * ell * OUT;
    let gr1cs_hadamard_constraints: usize = lengths
        .gr1cs_message_bodies
        .iter()
        .filter(|&&msg_len| msg_len >= gr1cs_hadamard_message_prefix_len(cp_layout))
        .map(|_| gr1cs_hadamard_message_constraints_count(cp_layout))
        .sum();
    let gr1cs_range_shape_constraints: usize = lengths
        .gr1cs_message_shapes
        .iter()
        .filter_map(|shape| shape.range.as_ref())
        .map(gr1cs_range_message_shape_constraints_count)
        .sum();
    let gr1cs_projected_value_payload_constraints: usize = lengths
        .gr1cs_message_shapes
        .iter()
        .filter_map(|shape| shape.range.as_ref())
        .map(|shape| {
            shape
                .monomial_commitment_elem_lens
                .iter()
                .map(|&elem_len| elem_len * D)
                .sum::<usize>()
                + shape
                    .monomial_vector_lens
                    .iter()
                    .map(|&vector_len| vector_len * D)
                    .sum::<usize>()
                + shape
                    .monomial_sumcheck_round_evals
                    .iter()
                    .map(|&eval_count| eval_count * 2)
                    .sum::<usize>()
                + shape
                    .monomial_evaluation_rows
                    .iter()
                    .map(|&rows| rows * D)
                    .sum::<usize>()
                + shape.sq_evaluations_count * 2
                + shape.projected_values_count
        })
        .sum();
    let gr1cs_range_semantic_constraints: usize = lengths
        .gr1cs_message_shapes
        .iter()
        .filter_map(|shape| shape.range.as_ref())
        .map(|shape| {
            let monomial_vector_coeffs: usize = shape
                .monomial_vector_lens
                .iter()
                .map(|&vector_len| vector_len * D)
                .sum();
            let monomial_commitment_coeffs: usize = shape
                .monomial_commitment_elem_lens
                .iter()
                .map(|&elem_len| elem_len * D)
                .sum();
            let monomial_vector_elements: usize = shape.monomial_vector_lens.iter().sum();
            let semantic_counts = monomial_sumcheck_semantic_counts(shape);
            monomial_commitment_coeffs
                + monomial_vector_coeffs
                + monomial_vector_elements
                + shape.projected_values_count
                + semantic_counts.constraint_count
        })
        .sum();
    let structured_length_constraints = ell * 8 // fs-commit message lengths
        + 8 + ell * 8 // fs-root count and commitment lengths
        + 8 + ell * 24 // fold-root count and per-entry lengths
        + 8 + ell * 8 + 3 * 8 // transcript-seed count, input lengths, metadata
        + 8 + ell * 8; // challenge-digest count and per-challenge lengths
    let challenge_static_constraints = ell
        * challenge_body_static_constraints_count(
            cp_layout,
            original_r1cs_num_constraints,
            original_r1cs_num_variables,
        );
    ell * OUT
        + msg_bytes
        + gr1cs_hadamard_constraints
        + gr1cs_range_shape_constraints
        + gr1cs_projected_value_payload_constraints
        + gr1cs_range_semantic_constraints
        + fold_commit_limb_constraints
        + fold_public_input_constraints
        + transcript_public_input_constraints
        + challenge_output_constraints
        + challenge_transcript_public_input_constraints
        + challenge_transcript_fs_commitment_constraints
        + structured_length_constraints
        + challenge_static_constraints
}

fn typed_cp_beta_binding_constraints_count(cp_layout: &CpR1csLayout) -> usize {
    assert_eq!(cp_layout.d, D);
    assert_eq!(D, TYPED_BETA_CHALLENGE_BYTES * 2);
    cp_layout.ell_np * TYPED_BETA_CHALLENGE_BYTES * TYPED_BETA_CONSTRAINTS_PER_BYTE
}

fn beta_binding_selector_base(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
) -> usize {
    off_beta_binding_selectors
        + (ell * TYPED_BETA_CHALLENGE_BYTES + byte_idx) * TYPED_BETA_SELECTORS_PER_BYTE
}

fn beta_binding_d0_selector(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
    value: usize,
) -> usize {
    debug_assert!(value < TYPED_BETA_DIGIT_SELECTOR_VALUES);
    beta_binding_selector_base(off_beta_binding_selectors, ell, byte_idx) + value
}

fn beta_binding_d1_selector(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
    value: usize,
) -> usize {
    debug_assert!(value < TYPED_BETA_DIGIT_SELECTOR_VALUES);
    beta_binding_selector_base(off_beta_binding_selectors, ell, byte_idx)
        + TYPED_BETA_DIGIT_SELECTOR_VALUES
        + value
}

fn beta_binding_q_selector(
    off_beta_binding_selectors: usize,
    ell: usize,
    byte_idx: usize,
    value: usize,
) -> usize {
    debug_assert!(value < TYPED_BETA_QUOTIENT_SELECTOR_VALUES);
    beta_binding_selector_base(off_beta_binding_selectors, ell, byte_idx)
        + TYPED_BETA_DIGIT_SELECTOR_VALUES * 2
        + value
}

fn insert_selector_bool_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    first_selector: usize,
    count: usize,
) -> usize {
    for idx in 0..count {
        let col = first_selector + idx;
        r1cs.a.insert(row, col, 1);
        r1cs.b.insert(row, col, 1);
        r1cs.b.insert(row, 0, -1);
        row += 1;
    }
    row
}

fn insert_selector_sum_one_constraint(
    r1cs: &mut R1CSMatrices,
    row: usize,
    first_selector: usize,
    count: usize,
) -> usize {
    for idx in 0..count {
        r1cs.a.insert(row, first_selector + idx, 1);
    }
    r1cs.a.insert(row, 0, -1);
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_typed_cp_beta_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    challenge_digest_block: &TypedCpDigestBlockLayout,
    off_beta_binding_selectors: usize,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    assert_eq!(cp_layout.d, D);
    assert_eq!(D, TYPED_BETA_CHALLENGE_BYTES * 2);
    assert_eq!(
        challenge_digest_block.body_len,
        8 + cp_layout.ell_np * (8 + TYPED_BETA_CHALLENGE_BYTES)
    );

    for ell in 0..cp_layout.ell_np {
        let challenge_bytes = challenge_digest_challenge_body_offset(ell);
        for byte_idx in 0..TYPED_BETA_CHALLENGE_BYTES {
            let d0_base = beta_binding_d0_selector(off_beta_binding_selectors, ell, byte_idx, 0);
            let d1_base = beta_binding_d1_selector(off_beta_binding_selectors, ell, byte_idx, 0);
            let q_base = beta_binding_q_selector(off_beta_binding_selectors, ell, byte_idx, 0);

            row = insert_selector_bool_constraints(
                r1cs,
                row,
                d0_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_bool_constraints(
                r1cs,
                row,
                d1_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_bool_constraints(
                r1cs,
                row,
                q_base,
                TYPED_BETA_QUOTIENT_SELECTOR_VALUES,
            );
            row = insert_selector_sum_one_constraint(
                r1cs,
                row,
                d0_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_sum_one_constraint(
                r1cs,
                row,
                d1_base,
                TYPED_BETA_DIGIT_SELECTOR_VALUES,
            );
            row = insert_selector_sum_one_constraint(
                r1cs,
                row,
                q_base,
                TYPED_BETA_QUOTIENT_SELECTOR_VALUES,
            );

            let byte_col = challenge_digest_block.off_body_bytes + challenge_bytes + byte_idx;
            r1cs.a.insert(row, byte_col, 1);
            for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
                r1cs.a.insert(row, d0_base + value, -(value as i64));
                r1cs.a.insert(row, d1_base + value, -(5 * value as i64));
            }
            for value in 0..TYPED_BETA_QUOTIENT_SELECTOR_VALUES {
                r1cs.a.insert(row, q_base + value, -(25 * value as i64));
            }
            r1cs.b.insert(row, 0, 1);
            row += 1;

            let beta0 = cp_col_in_digest_r1cs(
                statement,
                digest_public_shift,
                cp_layout.beta(ell, 2 * byte_idx),
            );
            r1cs.a.insert(row, beta0, 1);
            for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
                let mapped = value as i64 - 2;
                r1cs.a.insert(row, d0_base + value, -mapped);
            }
            r1cs.b.insert(row, 0, 1);
            row += 1;

            let beta1 = cp_col_in_digest_r1cs(
                statement,
                digest_public_shift,
                cp_layout.beta(ell, 2 * byte_idx + 1),
            );
            r1cs.a.insert(row, beta1, 1);
            for value in 0..TYPED_BETA_DIGIT_SELECTOR_VALUES {
                let mapped = value as i64 - 2;
                r1cs.a.insert(row, d1_base + value, -mapped);
            }
            r1cs.b.insert(row, 0, 1);
            row += 1;
        }
    }

    row
}

fn folded_eval_product_col(
    off_folded_eval_products: usize,
    cp_layout: &CpR1csLayout,
    folded_eval_count: usize,
    ell: usize,
    eval_idx: usize,
    tensor_row: usize,
    coeff: usize,
) -> usize {
    off_folded_eval_products
        + (((ell * folded_eval_count + eval_idx) * T + tensor_row) * cp_layout.d + coeff)
}

fn folded_eval_public_col(
    off_folded_evaluations: usize,
    cp_layout: &CpR1csLayout,
    eval_idx: usize,
    tensor_row: usize,
    coeff: usize,
) -> usize {
    off_folded_evaluations + (eval_idx * T + tensor_row) * cp_layout.d + coeff
}

fn folded_eval_wrap_col(
    off_folded_eval_wraps: usize,
    cp_layout: &CpR1csLayout,
    eval_idx: usize,
    tensor_row: usize,
    coeff: usize,
) -> usize {
    off_folded_eval_wraps + (eval_idx * T + tensor_row) * cp_layout.d + coeff
}

fn babybear_ntt_coeff_rows() -> Vec<Vec<i64>> {
    let bb_ntt = crate::ring::ntt::NttContext::new(BB_P);
    let mut ntt_coeff = vec![vec![0i64; D]; D];
    for coeff in 0..D {
        let mut basis = [0i64; D];
        basis[coeff] = 1;
        let evals = bb_ntt.forward(&RingElement { coeffs: basis });
        for slot in 0..D {
            ntt_coeff[slot][coeff] = centered_mod(evals[slot] as i128, BB_P);
        }
    }
    ntt_coeff
}

fn folded_evaluation_derivation_constraints_count(
    lengths: &TypedCpDigestInputLengths,
    cp_layout: &CpR1csLayout,
) -> usize {
    cp_layout.ell_np * lengths.folded_evaluation_values * T * cp_layout.d
        + lengths.folded_evaluation_values * T * cp_layout.d
}

#[allow(clippy::too_many_arguments)]
fn insert_folded_evaluation_derivation_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    off_folded_evaluations: usize,
    folded_eval_count: usize,
    off_folded_eval_products: usize,
    off_folded_eval_wraps: usize,
    q: u64,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    assert!(folded_eval_count <= 3);
    let ntt_coeff = babybear_ntt_coeff_rows();
    let q_embed = centered_mod(q as i128, BB_P);

    for ell in 0..cp_layout.ell_np {
        for eval_idx in 0..folded_eval_count {
            for tensor_row in 0..T {
                for coeffs in ntt_coeff.iter().take(cp_layout.d) {
                    for (coeff, &ntt_coeff) in coeffs.iter().enumerate().take(cp_layout.d) {
                        let beta_col = cp_col_in_digest_r1cs(
                            statement,
                            digest_public_shift,
                            cp_layout.beta(ell, coeff),
                        );
                        r1cs.a.insert(row, beta_col, ntt_coeff);

                        let eval_col = cp_col_in_digest_r1cs(
                            statement,
                            digest_public_shift,
                            cp_layout.had_eval_matrix(ell, eval_idx, tensor_row, coeff),
                        );
                        r1cs.b.insert(row, eval_col, ntt_coeff);

                        let prod_col = folded_eval_product_col(
                            off_folded_eval_products,
                            cp_layout,
                            folded_eval_count,
                            ell,
                            eval_idx,
                            tensor_row,
                            coeff,
                        );
                        r1cs.c.insert(row, prod_col, ntt_coeff);
                    }
                    row += 1;
                }
            }
        }
    }

    for eval_idx in 0..folded_eval_count {
        for tensor_row in 0..T {
            for coeff in 0..cp_layout.d {
                r1cs.a.insert(row, 0, 1);
                r1cs.b.insert(
                    row,
                    folded_eval_public_col(
                        off_folded_evaluations,
                        cp_layout,
                        eval_idx,
                        tensor_row,
                        coeff,
                    ),
                    1,
                );
                for ell in 0..cp_layout.ell_np {
                    r1cs.c.insert(
                        row,
                        folded_eval_product_col(
                            off_folded_eval_products,
                            cp_layout,
                            folded_eval_count,
                            ell,
                            eval_idx,
                            tensor_row,
                            coeff,
                        ),
                        1,
                    );
                }
                r1cs.c.insert(
                    row,
                    folded_eval_wrap_col(
                        off_folded_eval_wraps,
                        cp_layout,
                        eval_idx,
                        tensor_row,
                        coeff,
                    ),
                    q_embed,
                );
                row += 1;
            }
        }
    }

    row
}

#[allow(clippy::too_many_arguments)]
fn insert_structured_digest_body_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    off_fs_commitments: usize,
    fs_commitment_blocks: &[TypedCpDigestBlockLayout],
    fs_root_block: &TypedCpDigestBlockLayout,
    fold_root_block: &TypedCpDigestBlockLayout,
    challenge_digest_block: &TypedCpDigestBlockLayout,
    transcript_seed_block: &TypedCpDigestBlockLayout,
    challenge_blocks: &[TypedCpDigestBlockLayout],
    range_payload_blocks: &[Option<TypedCpRangePayloadBlockLayout>],
    lengths: &TypedCpDigestInputLengths,
    digest_public_shift: usize,
    ajtai: &crate::commitment::AjtaiParams,
    audit: &mut Option<&mut TypedCpAuditBuilder>,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;

    let start = row;
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        fs_root_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        fold_root_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        challenge_digest_block.off_body_bytes,
        cp_layout.ell_np as u64,
    );
    audit_push(
        audit,
        TypedCpAuditBlockKind::ByteConstraints,
        "structured-root-counts",
        start,
        row,
        &["FS/fold/challenge/transcript root body length framing"],
    );

    for ell in 0..cp_layout.ell_np {
        let start = row;
        let msg_len = lengths.gr1cs_message_bodies[ell];
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fs_commitment_blocks[ell].off_body_bytes,
            msg_len as u64,
        );

        let fs_root_len_offset = 8 + ell * (8 + OUT * 4);
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fs_root_block.off_body_bytes + fs_root_len_offset,
            (OUT * 4) as u64,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("structured-length-prefixes-{ell}"),
            start,
            row,
            &["canonical structured digest length prefixes"],
        );

        let fs_msg = fs_commit_message_body_offset(&fs_commitment_blocks[ell]);
        let fold_msg = fold_root_eval_message_body_offset(cp_layout, lengths, ell);
        let start = row;
        row = insert_bytes_equal(
            r1cs,
            row,
            fs_commitment_blocks[ell].off_body_bytes + fs_msg,
            fold_root_block.off_body_bytes + fold_msg,
            msg_len,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::Gr1csMessageReconstruction,
            format!("fs-message-fold-root-byte-equality-{ell}"),
            start,
            row,
            &["GR1CS message bytes bind FS commitments and fold root"],
        );
        if msg_len >= gr1cs_hadamard_message_prefix_len(cp_layout) {
            let start = row;
            row = insert_gr1cs_hadamard_message_constraints(
                r1cs,
                row,
                statement,
                digest_public_shift,
                fs_commitment_blocks[ell].off_body_bytes + fs_msg,
                fs_commitment_blocks[ell].off_body_bits + fs_msg * 8,
                ell,
            );
            audit_push(
                audit,
                TypedCpAuditBlockKind::Gr1csMessageReconstruction,
                format!("hadamard-message-reconstruction-{ell}"),
                start,
                row,
                &["Hadamard GR1CS message bytes reconstruct from CP columns"],
            );
        }
        if let Some(range_shape) = lengths.gr1cs_message_shapes[ell].range.as_ref() {
            let start = row;
            row = insert_gr1cs_range_message_shape_constraints(
                r1cs,
                row,
                fs_commitment_blocks[ell].off_body_bytes + fs_msg,
                &lengths.gr1cs_message_shapes[ell],
                range_shape,
                msg_len,
            );
            audit_push(
                audit,
                TypedCpAuditBlockKind::Gr1csMessageReconstruction,
                format!("range-message-shape-{ell}"),
                start,
                row,
                &["range proof serialization shape is canonical"],
            );
            if let Some(range_payload_block) = range_payload_blocks[ell].as_ref() {
                let start = row;
                row = insert_gr1cs_range_payload_constraints(
                    r1cs,
                    row,
                    fs_commitment_blocks[ell].off_body_bytes + fs_msg,
                    fs_commitment_blocks[ell].off_body_bits + fs_msg * 8,
                    &lengths.gr1cs_message_shapes[ell],
                    range_shape,
                    range_payload_block,
                );
                audit_push(
                    audit,
                    TypedCpAuditBlockKind::Gr1csMessageReconstruction,
                    format!("range-message-payload-reconstruction-{ell}"),
                    start,
                    row,
                    &["range proof payload bytes reconstruct from structured variables"],
                );
                let start = row;
                row = insert_gr1cs_range_semantic_constraints(
                    r1cs,
                    row,
                    range_shape,
                    range_payload_block,
                    ajtai,
                );
                audit_push(
                    audit,
                    TypedCpAuditBlockKind::RangeMonomialSemantics,
                    format!("range-monomial-semantics-{ell}"),
                    start,
                    row,
                    &[
                        "range proof monomial commitment opening validity",
                        "monomiality",
                        "monomial sumcheck consistency",
                        "monomial evaluation consistency",
                        "square-evaluation consistency",
                        "projected-value decomposition and reconstruction",
                    ],
                );
            }
        }

        let fold_entry = fold_root_entry_body_offset(cp_layout, lengths, ell);
        let fold_commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fold_root_block.off_body_bytes + fold_entry,
            fold_commitment_len as u64,
        );
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fold_root_block.off_body_bytes
                + fold_root_public_input_body_offset(cp_layout, lengths, ell)
                - 8,
            cp_layout.n_in as u64,
        );
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            fold_root_block.off_body_bytes + fold_msg - 8,
            msg_len as u64,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("fold-root-entry-length-prefixes-{ell}"),
            start,
            row,
            &["fold root entry length framing"],
        );

        let fold_commitment = fold_root_commitment_body_offset(cp_layout, lengths, ell);
        let start = row;
        for i in 0..cp_layout.kappa {
            for j in 0..cp_layout.d {
                let body = fold_root_block.off_body_bytes
                    + fold_commitment
                    + 8
                    + (i * cp_layout.d + j) * 8;
                let cp_col =
                    cp_col_in_digest_r1cs(statement, digest_public_shift, cp_layout.c(ell, i, j));
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    body,
                    fold_root_block.off_body_bits
                        + (body - fold_root_block.off_body_bytes + 7) * 8
                        + 7,
                    cp_col,
                );
            }
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::FoldedOutputDerivation,
            format!("fold-root-commitment-binding-{ell}"),
            start,
            row,
            &["fold root commitment bytes bind CP commitment columns"],
        );

        let fold_public_input = fold_root_public_input_body_offset(cp_layout, lengths, ell);
        let transcript_public_input = transcript_seed_public_input_body_offset(cp_layout, ell);
        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            transcript_seed_block.off_body_bytes + transcript_public_input - 8,
            cp_layout.n_in as u64,
        );
        for slot in 0..cp_layout.n_in {
            let public_col = statement.off_public_inputs + ell * cp_layout.n_in + slot;
            row = insert_i64_limb_bytes_equal_var(
                r1cs,
                row,
                fold_root_block.off_body_bytes + fold_public_input + slot * 8,
                fold_root_block.off_body_bits + (fold_public_input + slot * 8 + 7) * 8 + 7,
                public_col,
            );
            row = insert_i64_limb_bytes_equal_var(
                r1cs,
                row,
                transcript_seed_block.off_body_bytes + transcript_public_input + slot * 8,
                transcript_seed_block.off_body_bits
                    + (transcript_public_input + slot * 8 + 7) * 8
                    + 7,
                public_col,
            );
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::PublicInputBinding,
            format!("public-input-digest-body-binding-{ell}"),
            start,
            row,
            &["public inputs bind fold root, transcript seed, and CP statement"],
        );

        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            challenge_digest_block.off_body_bytes + 8 + ell * (8 + 32),
            (OUT * 4) as u64,
        );
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("challenge-digest-entry-length-{ell}"),
            start,
            row,
            &["challenge digest entry length framing"],
        );
    }

    let transcript_seed_meta = transcript_seed_metadata_body_offset(cp_layout);
    let start = row;
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes + transcript_seed_meta,
        statement.partial.original_r1cs_num_constraints as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes + transcript_seed_meta + 8,
        statement.partial.original_r1cs_num_variables as u64,
    );
    row = insert_u64_bytes_constant(
        r1cs,
        row,
        transcript_seed_block.off_body_bytes + transcript_seed_meta + 16,
        cp_layout.n_in as u64,
    );
    audit_push(
        audit,
        TypedCpAuditBlockKind::PublicInputBinding,
        "transcript-seed-r1cs-metadata-binding",
        start,
        row,
        &["R1CS metadata binds transcript seed digest"],
    );

    for (challenge_idx, challenge_block) in challenge_blocks.iter().enumerate() {
        let start = row;
        row = insert_u64_bytes_constant(
            r1cs,
            row,
            challenge_block.off_body_bytes,
            challenge_idx as u64,
        );
        row = insert_challenge_transcript_static_constraints(r1cs, row, statement, challenge_block);
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("challenge-transcript-static-frame-{challenge_idx}"),
            start,
            row,
            &["challenge transcript static frame is canonical"],
        );

        let challenge_digest_bytes = challenge_digest_challenge_body_offset(challenge_idx);
        let start = row;
        for limb in 0..OUT {
            row = insert_u32_limb_bytes_equal_var(
                r1cs,
                row,
                challenge_digest_block.off_body_bytes + challenge_digest_bytes + limb * 4,
                challenge_block.off_public_output + limb,
            );
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::ChallengeToBetaBinding,
            format!("challenge-output-to-digest-body-{challenge_idx}"),
            start,
            row,
            &["per-round challenge output feeds challenge digest"],
        );

        let start = row;
        for ell in 0..cp_layout.ell_np {
            let transcript_public_input =
                challenge_body_transcript_public_input_payload_offset(cp_layout, ell);
            for slot in 0..cp_layout.n_in {
                let public_col = statement.off_public_inputs + ell * cp_layout.n_in + slot;
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    challenge_block.off_body_bytes + 8 + transcript_public_input + slot * 8,
                    challenge_block.off_body_bits
                        + (8 + transcript_public_input + slot * 8 + 7) * 8
                        + 7,
                    public_col,
                );
            }
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::PublicInputBinding,
            format!("challenge-transcript-public-input-binding-{challenge_idx}"),
            start,
            row,
            &["public inputs bind per-round challenge transcripts"],
        );

        let start = row;
        for commitment_idx in 0..cp_layout.ell_np {
            let transcript_commitment =
                challenge_body_transcript_fs_commitment_payload_offset(cp_layout, commitment_idx);
            for limb in 0..OUT {
                row = insert_u32_limb_bytes_equal_var(
                    r1cs,
                    row,
                    challenge_block.off_body_bytes + 8 + transcript_commitment + limb * 4,
                    off_fs_commitments + commitment_idx * OUT + limb,
                );
            }
        }
        audit_push(
            audit,
            TypedCpAuditBlockKind::ByteConstraints,
            format!("challenge-transcript-fs-commitment-binding-{challenge_idx}"),
            start,
            row,
            &["FS commitments bind per-round challenge transcripts"],
        );
    }

    row
}

fn challenge_body_static_constraints_count(
    cp_layout: &CpR1csLayout,
    original_r1cs_num_constraints: usize,
    original_r1cs_num_variables: usize,
) -> usize {
    let transcript = canonical_challenge_transcript_template(
        cp_layout,
        original_r1cs_num_constraints,
        original_r1cs_num_variables,
    );
    let variable_payload_bytes = cp_layout.ell_np * cp_layout.n_in * 8 + cp_layout.ell_np * OUT * 4;
    8 + transcript.len() - variable_payload_bytes
}

fn insert_challenge_transcript_static_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    challenge_block: &TypedCpDigestBlockLayout,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    let transcript = canonical_challenge_transcript_template(
        cp_layout,
        statement.partial.original_r1cs_num_constraints,
        statement.partial.original_r1cs_num_variables,
    );
    assert_eq!(challenge_block.body_len, 8 + transcript.len());

    for (idx, byte) in transcript.iter().copied().enumerate() {
        if !is_challenge_transcript_variable_payload(cp_layout, idx) {
            row = insert_byte_constant(r1cs, row, challenge_block.off_body_bytes + 8 + idx, byte);
        }
    }
    row
}

fn canonical_challenge_transcript_template(
    cp_layout: &CpR1csLayout,
    original_r1cs_num_constraints: usize,
    original_r1cs_num_variables: usize,
) -> Vec<u8> {
    let public_inputs = vec![vec![0i64; cp_layout.n_in]; cp_layout.ell_np];
    let fs_commitments = vec![vec![0u8; OUT * 4]; cp_layout.ell_np];
    crate::cp_relation_core::cp_relation_transcript_bytes(
        &public_inputs,
        original_r1cs_num_constraints,
        original_r1cs_num_variables,
        cp_layout.n_in,
        &fs_commitments,
    )
}

fn is_challenge_transcript_variable_payload(cp_layout: &CpR1csLayout, offset: usize) -> bool {
    for ell in 0..cp_layout.ell_np {
        let start = challenge_body_transcript_public_input_payload_offset(cp_layout, ell);
        if (start..start + cp_layout.n_in * 8).contains(&offset) {
            return true;
        }
    }
    for commitment_idx in 0..cp_layout.ell_np {
        let start =
            challenge_body_transcript_fs_commitment_payload_offset(cp_layout, commitment_idx);
        if (start..start + OUT * 4).contains(&offset) {
            return true;
        }
    }
    false
}

fn typed_gr1cs_message_shape(
    proof: &GR1CSProof,
    expected_message_len: usize,
) -> Option<TypedCpGr1csMessageShape> {
    if crate::snark::cp_snark::encode_gr1cs_round_message(proof).len() != expected_message_len {
        return None;
    }
    let hadamard_sumcheck_round_evals = proof
        .hadamard_proof
        .sumcheck_proof
        .round_messages
        .iter()
        .map(|round| round.evaluations.len())
        .collect::<Vec<_>>();
    let hadamard_eval_matrix_rows = proof
        .hadamard_proof
        .evaluation_matrix
        .iter()
        .map(|te| te.data.len())
        .collect::<Vec<_>>();
    let range = TypedCpRangeMessageShape {
        monomial_commitment_elem_lens: proof
            .range_proof
            .monomial_commitments
            .iter()
            .map(|commitment| commitment.value.elements.len())
            .collect(),
        monomial_vector_lens: proof
            .range_proof
            .monomial_vectors
            .iter()
            .map(Vec::len)
            .collect(),
        monomial_sumcheck_round_evals: proof
            .range_proof
            .monomial_proof
            .sumcheck_proof
            .round_messages
            .iter()
            .map(|round| round.evaluations.len())
            .collect(),
        monomial_evaluation_rows: proof
            .range_proof
            .monomial_proof
            .evaluations
            .iter()
            .map(|te| te.data.len())
            .collect(),
        sq_evaluations_count: proof.range_proof.monomial_proof.sq_evaluations.len(),
        projected_values_count: proof.range_proof.projected_values.len(),
    };
    Some(TypedCpGr1csMessageShape {
        hadamard_sumcheck_round_evals,
        hadamard_eval_matrix_rows,
        range: Some(range),
    })
}

fn gr1cs_range_message_shape_constraints_count(shape: &TypedCpRangeMessageShape) -> usize {
    8 * (6
        + shape.monomial_commitment_elem_lens.len()
        + shape.monomial_vector_lens.len()
        + shape.monomial_sumcheck_round_evals.len())
}

fn insert_gr1cs_range_message_shape_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    message_byte_col: usize,
    message_shape: &TypedCpGr1csMessageShape,
    range_shape: &TypedCpRangeMessageShape,
    message_len: usize,
) -> usize {
    let mut offset = gr1cs_hadamard_section_len(message_shape);

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_commitment_elem_lens.len() as u64,
    );
    offset += 8;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + offset, elem_len as u64);
        offset += commitment_message_len(elem_len);
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_vector_lens.len() as u64,
    );
    offset += 8;
    for &vector_len in &range_shape.monomial_vector_lens {
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + offset, vector_len as u64);
        offset += 8 + vector_len * D * 8;
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_sumcheck_round_evals.len() as u64,
    );
    offset += 8;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + offset, eval_count as u64);
        offset += 8 + eval_count * 2 * 8;
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.monomial_evaluation_rows.len() as u64,
    );
    offset += 8;
    for &rows in &range_shape.monomial_evaluation_rows {
        offset += rows * D * 8;
    }

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.sq_evaluations_count as u64,
    );
    offset += 8 + range_shape.sq_evaluations_count * 2 * 8;

    row = insert_u64_bytes_constant(
        r1cs,
        row,
        message_byte_col + offset,
        range_shape.projected_values_count as u64,
    );
    offset += 8 + range_shape.projected_values_count * 8;

    debug_assert_eq!(offset, message_len);
    row
}

fn gr1cs_projected_values_payload_offset(
    message_shape: &TypedCpGr1csMessageShape,
    range_shape: &TypedCpRangeMessageShape,
) -> usize {
    let mut offset = gr1cs_hadamard_section_len(message_shape);

    offset += 8;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        offset += commitment_message_len(elem_len);
    }

    offset += 8;
    for &vector_len in &range_shape.monomial_vector_lens {
        offset += 8 + vector_len * D * 8;
    }

    offset += 8;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        offset += 8 + eval_count * 2 * 8;
    }

    offset += 8;
    for &rows in &range_shape.monomial_evaluation_rows {
        offset += rows * D * 8;
    }

    offset += 8 + range_shape.sq_evaluations_count * 2 * 8;
    offset + 8
}

fn insert_gr1cs_range_payload_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    message_byte_col: usize,
    message_bit_col: usize,
    message_shape: &TypedCpGr1csMessageShape,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
) -> usize {
    assert_eq!(
        payload.monomial_commitment_coeffs_count,
        range_shape
            .monomial_commitment_elem_lens
            .iter()
            .map(|&elem_len| elem_len * D)
            .sum::<usize>()
    );
    assert_eq!(
        payload.monomial_vector_coeffs_count,
        range_shape
            .monomial_vector_lens
            .iter()
            .map(|&vector_len| vector_len * D)
            .sum::<usize>()
    );
    assert_eq!(
        payload.monomial_vector_elements_count,
        range_shape.monomial_vector_lens.iter().sum::<usize>()
    );
    assert_eq!(
        payload.monomial_sumcheck_evaluation_coeffs_count,
        range_shape
            .monomial_sumcheck_round_evals
            .iter()
            .map(|&eval_count| eval_count * 2)
            .sum::<usize>()
    );
    assert_eq!(
        payload.monomial_evaluation_coeffs_count,
        range_shape
            .monomial_evaluation_rows
            .iter()
            .map(|&rows| rows * D)
            .sum::<usize>()
    );
    assert_eq!(
        payload.sq_evaluation_coeffs_count,
        range_shape.sq_evaluations_count * 2
    );
    assert_eq!(
        payload.projected_values_count,
        range_shape.projected_values_count
    );

    let mut offset = gr1cs_hadamard_section_len(message_shape);
    let mut var_offset = 0;

    offset += 8;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        offset += 8;
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_commitments + var_offset,
            elem_len * D,
        );
        var_offset += elem_len * D;
        offset += elem_len * D * 8;
    }
    debug_assert_eq!(var_offset, payload.monomial_commitment_coeffs_count);

    offset += 8;
    var_offset = 0;
    for &vector_len in &range_shape.monomial_vector_lens {
        offset += 8;
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_vectors + var_offset,
            vector_len * D,
        );
        var_offset += vector_len * D;
        offset += vector_len * D * 8;
    }
    debug_assert_eq!(var_offset, payload.monomial_vector_coeffs_count);

    offset += 8;
    var_offset = 0;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        offset += 8;
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_sumcheck_evaluations + var_offset,
            eval_count * 2,
        );
        var_offset += eval_count * 2;
        offset += eval_count * 2 * 8;
    }
    debug_assert_eq!(
        var_offset,
        payload.monomial_sumcheck_evaluation_coeffs_count
    );

    offset += 8;
    var_offset = 0;
    for &rows in &range_shape.monomial_evaluation_rows {
        row = insert_i64_payload_bytes_equal_vars(
            r1cs,
            row,
            message_byte_col,
            message_bit_col,
            offset,
            payload.off_monomial_evaluations + var_offset,
            rows * D,
        );
        var_offset += rows * D;
        offset += rows * D * 8;
    }
    debug_assert_eq!(var_offset, payload.monomial_evaluation_coeffs_count);

    offset += 8;
    row = insert_i64_payload_bytes_equal_vars(
        r1cs,
        row,
        message_byte_col,
        message_bit_col,
        offset,
        payload.off_sq_evaluations,
        payload.sq_evaluation_coeffs_count,
    );
    offset += payload.sq_evaluation_coeffs_count * 8;

    offset += 8;
    debug_assert_eq!(
        offset,
        gr1cs_projected_values_payload_offset(message_shape, range_shape)
    );
    for idx in 0..payload.projected_values_count {
        let offset = offset + idx * 8;
        row = insert_i64_limb_bytes_equal_var(
            r1cs,
            row,
            message_byte_col + offset,
            message_bit_col + (offset + 7) * 8 + 7,
            payload.off_projected_values + idx,
        );
    }
    row
}

fn insert_i64_payload_bytes_equal_vars(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    message_byte_col: usize,
    message_bit_col: usize,
    payload_byte_offset: usize,
    var_col: usize,
    count: usize,
) -> usize {
    for idx in 0..count {
        let offset = payload_byte_offset + idx * 8;
        row = insert_i64_limb_bytes_equal_var(
            r1cs,
            row,
            message_byte_col + offset,
            message_bit_col + (offset + 7) * 8 + 7,
            var_col + idx,
        );
    }
    row
}

fn insert_gr1cs_range_semantic_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    ajtai: &crate::commitment::AjtaiParams,
) -> usize {
    assert_eq!(
        payload.monomial_vector_coeffs_count,
        payload.monomial_vector_elements_count * D
    );

    row = insert_monomial_commitment_opening_constraints(r1cs, row, range_shape, payload, ajtai);

    for coeff_idx in 0..payload.monomial_vector_coeffs_count {
        let coeff_col = payload.off_monomial_vectors + coeff_idx;
        let square_col = payload.off_monomial_vector_squares + coeff_idx;
        r1cs.a.insert(row, coeff_col, 1);
        r1cs.b.insert(row, coeff_col, 1);
        r1cs.c.insert(row, square_col, 1);
        row += 1;
    }

    let mut vector_coeff_offset = 0usize;
    for &vector_len in &range_shape.monomial_vector_lens {
        for elem_idx in 0..vector_len {
            let square_start =
                payload.off_monomial_vector_squares + vector_coeff_offset + elem_idx * D;
            for coeff in 0..D {
                r1cs.a.insert(row, square_start + coeff, 1);
                r1cs.b.insert(row, square_start + coeff, 1);
            }
            r1cs.b.insert(row, 0, -1);
            row += 1;
        }
        vector_coeff_offset += vector_len * D;
    }

    for projected_idx in 0..payload.projected_values_count {
        r1cs.a
            .insert(row, payload.off_projected_values + projected_idx, 1);

        let mut coeff_offset = 0usize;
        let mut d_power = 1i128;
        for &vector_len in &range_shape.monomial_vector_lens {
            if projected_idx < vector_len {
                let elem_start = payload.off_monomial_vectors + coeff_offset + projected_idx * D;
                for coeff in 0..D {
                    let weight = monomial_digit_weight(coeff) as i128;
                    if weight != 0 {
                        r1cs.a
                            .insert(row, elem_start + coeff, centered_i128(-d_power * weight));
                    }
                }
            }
            coeff_offset += vector_len * D;
            d_power *= typed_range_d_prime() as i128;
        }
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }

    row = insert_monomial_sumcheck_semantic_constraints(r1cs, row, range_shape, payload, ajtai.q);

    row
}

fn insert_monomial_commitment_opening_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    ajtai: &crate::commitment::AjtaiParams,
) -> usize {
    assert_eq!(
        range_shape.monomial_commitment_elem_lens.len(),
        range_shape.monomial_vector_lens.len(),
        "each monomial vector must have one commitment"
    );

    let mut commitment_coeff_offset = 0usize;
    let mut vector_coeff_offset = 0usize;
    for (&commitment_len, &vector_len) in range_shape
        .monomial_commitment_elem_lens
        .iter()
        .zip(range_shape.monomial_vector_lens.iter())
    {
        assert_eq!(
            commitment_len, ajtai.kappa,
            "monomial commitment must use the parent kappa"
        );
        let mon_ajtai = crate::commitment::AjtaiParams::setup_deterministic(
            ajtai.kappa,
            vector_len,
            ajtai.q,
            &ajtai.ntt,
            b"range-proof-monomial",
        );
        for commitment_row in 0..mon_ajtai.kappa {
            for coeff in 0..D {
                for col in 0..mon_ajtai.n {
                    let a = &mon_ajtai.a[commitment_row][col];
                    for a_coeff in 0..D {
                        let (w_coeff, sign) = negacyclic_partner(coeff, a_coeff);
                        let z_col =
                            payload.off_monomial_vectors + vector_coeff_offset + col * D + w_coeff;
                        r1cs.a.insert(
                            row,
                            z_col,
                            centered_mod(sign * a.coeffs[a_coeff] as i128, BB_P),
                        );
                    }
                }
                r1cs.a.insert(
                    row,
                    payload.off_monomial_commitments + commitment_coeff_offset,
                    -1,
                );
                r1cs.a.insert(
                    row,
                    payload.off_monomial_commitment_wraps + commitment_coeff_offset,
                    -(ajtai.q as i64),
                );
                r1cs.b.insert(row, 0, 1);
                row += 1;
                commitment_coeff_offset += 1;
            }
        }
        vector_coeff_offset += vector_len * D;
    }
    debug_assert_eq!(
        commitment_coeff_offset,
        payload.monomial_commitment_coeffs_count
    );
    debug_assert_eq!(vector_coeff_offset, payload.monomial_vector_coeffs_count);
    row
}

#[derive(Debug, Clone, Copy)]
struct MonomialSumcheckSemanticCounts {
    challenge_len: usize,
    aux_count: usize,
    wrap_count: usize,
    constraint_count: usize,
}

fn monomial_sumcheck_semantic_counts(
    range_shape: &TypedCpRangeMessageShape,
) -> MonomialSumcheckSemanticCounts {
    let verifier = monomial_sumcheck_verifier_counts(range_shape);
    let evaluation_binding = monomial_evaluation_binding_counts(range_shape);
    MonomialSumcheckSemanticCounts {
        challenge_len: verifier.challenge_len,
        aux_count: verifier.aux_count + evaluation_binding.aux_count,
        wrap_count: verifier.wrap_count + evaluation_binding.wrap_count,
        constraint_count: verifier.constraint_count + evaluation_binding.constraint_count,
    }
}

fn monomial_sumcheck_verifier_counts(
    range_shape: &TypedCpRangeMessageShape,
) -> MonomialSumcheckSemanticCounts {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let k_g = range_shape.monomial_evaluation_rows.len();
    let total_terms = k_g * D + k_g;
    let ext_mul_count = 4 * nv
        + if nv > 0 { 2 * nv - 1 } else { 0 }
        + k_g * D * 2
        + k_g
        + total_terms.saturating_sub(2)
        + total_terms.saturating_sub(1)
        + if nv > 0 { 1 } else { 0 };
    let linear_rows = 2 * nv + 2;
    MonomialSumcheckSemanticCounts {
        challenge_len: nv * 2,
        aux_count: ext_mul_count * 4,
        wrap_count: ext_mul_count * 4 + linear_rows,
        constraint_count: ext_mul_count * 4 + linear_rows,
    }
}

fn monomial_evaluation_binding_counts(
    range_shape: &TypedCpRangeMessageShape,
) -> MonomialSumcheckSemanticCounts {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let k_g = range_shape.monomial_evaluation_rows.len();
    let table_size = 1usize
        .checked_shl(nv as u32)
        .expect("typed CP monomial sumcheck round count too large");
    let table_count = k_g * (D + 1);
    let fold_count = table_count * table_size.saturating_sub(1);
    let final_equalities = table_count;
    let linear_rows = 2 * (fold_count + final_equalities);
    MonomialSumcheckSemanticCounts {
        challenge_len: 0,
        aux_count: fold_count * 6,
        wrap_count: fold_count * 4 + linear_rows,
        constraint_count: fold_count * 4 + linear_rows,
    }
}

#[derive(Debug, Clone)]
struct ExtLc {
    c0: Vec<(usize, i64)>,
    c1: Vec<(usize, i64)>,
}

fn ext_zero_lc() -> ExtLc {
    ExtLc {
        c0: Vec::new(),
        c1: Vec::new(),
    }
}

fn ext_one_lc() -> ExtLc {
    ExtLc {
        c0: vec![(0, 1)],
        c1: Vec::new(),
    }
}

fn ext_var_lc(c0: usize, c1: usize) -> ExtLc {
    ExtLc {
        c0: vec![(c0, 1)],
        c1: vec![(c1, 1)],
    }
}

fn ext_const_lc(value: i64) -> ExtLc {
    if value == 0 {
        ext_zero_lc()
    } else {
        ExtLc {
            c0: vec![(0, value)],
            c1: Vec::new(),
        }
    }
}

fn lc_add(lhs: &[(usize, i64)], rhs: &[(usize, i64)]) -> Vec<(usize, i64)> {
    let mut out = lhs.to_vec();
    out.extend_from_slice(rhs);
    normalize_lc(out)
}

fn lc_sub(lhs: &[(usize, i64)], rhs: &[(usize, i64)]) -> Vec<(usize, i64)> {
    let mut out = lhs.to_vec();
    out.extend(rhs.iter().map(|&(idx, coeff)| (idx, -coeff)));
    normalize_lc(out)
}

fn lc_scale(lhs: &[(usize, i64)], coeff: i64) -> Vec<(usize, i64)> {
    if coeff == 0 {
        return Vec::new();
    }
    normalize_lc(
        lhs.iter()
            .map(|&(idx, c)| (idx, centered_i128(c as i128 * coeff as i128)))
            .collect(),
    )
}

fn normalize_lc(entries: Vec<(usize, i64)>) -> Vec<(usize, i64)> {
    let mut acc = BTreeMap::<usize, i128>::new();
    for (idx, coeff) in entries {
        *acc.entry(idx).or_insert(0) += coeff as i128;
    }
    acc.into_iter()
        .filter_map(|(idx, coeff)| {
            let coeff = centered_i128(coeff);
            (coeff != 0).then_some((idx, coeff))
        })
        .collect()
}

fn ext_add_lc(lhs: &ExtLc, rhs: &ExtLc) -> ExtLc {
    ExtLc {
        c0: lc_add(&lhs.c0, &rhs.c0),
        c1: lc_add(&lhs.c1, &rhs.c1),
    }
}

fn ext_sub_lc(lhs: &ExtLc, rhs: &ExtLc) -> ExtLc {
    ExtLc {
        c0: lc_sub(&lhs.c0, &rhs.c0),
        c1: lc_sub(&lhs.c1, &rhs.c1),
    }
}

fn ext_scale_lc(lhs: &ExtLc, coeff: i64) -> ExtLc {
    ExtLc {
        c0: lc_scale(&lhs.c0, coeff),
        c1: lc_scale(&lhs.c1, coeff),
    }
}

fn q_field_const(value: i128, q: u64) -> i64 {
    centered_mod(value, q)
}

fn q_inv_const(value: u64, q: u64) -> i64 {
    q_field_const(mod_inv(value % q, q) as i128, q)
}

fn insert_ext_linear_eq_mod_q(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    lhs: &ExtLc,
    rhs: &ExtLc,
    wrap_col: usize,
    q: u64,
) -> usize {
    let q_embed = centered_mod(q as i128, BB_P);
    for (comp, (lhs_lc, rhs_lc)) in [(&lhs.c0, &rhs.c0), (&lhs.c1, &rhs.c1)]
        .into_iter()
        .enumerate()
    {
        for &(col, coeff) in lhs_lc {
            r1cs.a.insert(row, col, coeff);
        }
        for &(col, coeff) in rhs_lc {
            r1cs.a.insert(row, col, -coeff);
        }
        r1cs.a.insert(row, wrap_col + comp, -q_embed);
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }
    row
}

#[allow(clippy::too_many_arguments)]
fn insert_ext_mul_lc_mod_q(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    lhs: &ExtLc,
    rhs: &ExtLc,
    aux_col: usize,
    wrap_col: usize,
    q: u64,
    qnr: i64,
) -> (usize, ExtLc) {
    let q_embed = centered_mod(q as i128, BB_P);
    let p1 = aux_col;
    let p2 = aux_col + 1;
    let c0 = aux_col + 2;
    let c1 = aux_col + 3;

    for &(col, coeff) in &lhs.c0 {
        r1cs.a.insert(row, col, coeff);
    }
    for &(col, coeff) in &rhs.c0 {
        r1cs.b.insert(row, col, coeff);
    }
    r1cs.c.insert(row, p1, 1);
    r1cs.c.insert(row, wrap_col, q_embed);
    row += 1;

    for &(col, coeff) in &lhs.c1 {
        r1cs.a.insert(row, col, coeff);
    }
    for &(col, coeff) in &rhs.c1 {
        r1cs.b.insert(row, col, coeff);
    }
    r1cs.c.insert(row, p2, 1);
    r1cs.c.insert(row, wrap_col + 1, q_embed);
    row += 1;

    for &(col, coeff) in lhs.c0.iter().chain(lhs.c1.iter()) {
        r1cs.a.insert(row, col, coeff);
    }
    for &(col, coeff) in rhs.c0.iter().chain(rhs.c1.iter()) {
        r1cs.b.insert(row, col, coeff);
    }
    r1cs.c.insert(row, c1, 1);
    r1cs.c.insert(row, p1, 1);
    r1cs.c.insert(row, p2, 1);
    r1cs.c.insert(row, wrap_col + 2, q_embed);
    row += 1;

    r1cs.a.insert(row, 0, 1);
    r1cs.b.insert(row, c0, 1);
    r1cs.c.insert(row, p1, 1);
    r1cs.c.insert(row, p2, qnr);
    r1cs.c.insert(row, wrap_col + 3, q_embed);
    row += 1;

    (row, ext_var_lc(c0, c1))
}

fn monomial_round_eval_col(
    payload: &TypedCpRangePayloadBlockLayout,
    range_shape: &TypedCpRangeMessageShape,
    round: usize,
    point: usize,
    comp: usize,
) -> usize {
    let prev: usize = range_shape
        .monomial_sumcheck_round_evals
        .iter()
        .take(round)
        .map(|&eval_count| eval_count * 2)
        .sum();
    payload.off_monomial_sumcheck_evaluations + prev + point * 2 + comp
}

fn monomial_eval_col(
    payload: &TypedCpRangePayloadBlockLayout,
    range_shape: &TypedCpRangeMessageShape,
    vector: usize,
    coeff: usize,
    comp: usize,
) -> usize {
    let prev: usize = range_shape
        .monomial_evaluation_rows
        .iter()
        .take(vector)
        .map(|&rows| rows * D)
        .sum();
    payload.off_monomial_evaluations + prev + comp * D + coeff
}

fn monomial_sq_eval_col(
    payload: &TypedCpRangePayloadBlockLayout,
    vector: usize,
    comp: usize,
) -> usize {
    payload.off_sq_evaluations + vector * 2 + comp
}

fn insert_monomial_sumcheck_semantic_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    q: u64,
) -> usize {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let k_g = range_shape.monomial_evaluation_rows.len();
    assert!(range_shape
        .monomial_sumcheck_round_evals
        .iter()
        .all(|&eval_count| eval_count == 5));
    assert!(range_shape
        .monomial_evaluation_rows
        .iter()
        .all(|&rows| rows >= 2));
    assert_eq!(range_shape.sq_evaluations_count, k_g);

    let counts = monomial_sumcheck_semantic_counts(range_shape);
    assert_eq!(payload.monomial_sumcheck_aux_count, counts.aux_count);
    assert_eq!(payload.monomial_sumcheck_wrap_count, counts.wrap_count);

    let qnr = crate::ring::extension::ExtFieldContext::new(q).alpha;
    let inv2 = q_inv_const(2, q);
    let inv6 = q_inv_const(6, q);
    let inv24 = q_inv_const(24, q);
    let mut aux_offset = 0usize;
    let mut wrap_offset = 0usize;
    let mut claim = ext_zero_lc();

    let ext_mul = |r1cs: &mut R1CSMatrices,
                   row: usize,
                   lhs: &ExtLc,
                   rhs: &ExtLc,
                   aux_offset: &mut usize,
                   wrap_offset: &mut usize|
     -> (usize, ExtLc) {
        let (row, out) = insert_ext_mul_lc_mod_q(
            r1cs,
            row,
            lhs,
            rhs,
            payload.off_monomial_sumcheck_aux + *aux_offset,
            payload.off_monomial_sumcheck_wraps + *wrap_offset,
            q,
            qnr,
        );
        *aux_offset += 4;
        *wrap_offset += 4;
        (row, out)
    };

    for round in 0..nv {
        let ev = |point: usize| {
            ext_var_lc(
                monomial_round_eval_col(payload, range_shape, round, point, 0),
                monomial_round_eval_col(payload, range_shape, round, point, 1),
            )
        };
        let e0 = ev(0);
        let e1 = ev(1);
        let e2 = ev(2);
        let e3 = ev(3);
        let e4 = ev(4);
        let lhs = ext_add_lc(&e0, &e1);
        row = insert_ext_linear_eq_mod_q(
            r1cs,
            row,
            &lhs,
            &claim,
            payload.off_monomial_sumcheck_wraps + wrap_offset,
            q,
        );
        wrap_offset += 2;

        let d1 = ext_sub_lc(&e1, &e0);
        let d2 = ext_scale_lc(
            &ext_add_lc(&ext_sub_lc(&e0, &ext_scale_lc(&e1, 2)), &e2),
            inv2,
        );
        let d3 = ext_scale_lc(
            &ext_add_lc(
                &ext_add_lc(
                    &ext_sub_lc(&ext_scale_lc(&e1, 3), &e0),
                    &ext_scale_lc(&e2, -3),
                ),
                &e3,
            ),
            inv6,
        );
        let d4 = ext_scale_lc(
            &ext_add_lc(
                &ext_add_lc(
                    &ext_add_lc(
                        &ext_sub_lc(&e0, &ext_scale_lc(&e1, 4)),
                        &ext_scale_lc(&e2, 6),
                    ),
                    &ext_scale_lc(&e3, -4),
                ),
                &e4,
            ),
            inv24,
        );
        let r_chal = ext_var_lc(
            payload.off_monomial_sumcheck_challenges + round * 2,
            payload.off_monomial_sumcheck_challenges + round * 2 + 1,
        );
        let (next_row, m1) = ext_mul(
            r1cs,
            row,
            &d4,
            &ext_sub_lc(&r_chal, &ext_const_lc(3)),
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        let (next_row, m2) = ext_mul(
            r1cs,
            row,
            &ext_add_lc(&m1, &d3),
            &ext_sub_lc(&r_chal, &ext_const_lc(2)),
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        let (next_row, m3) = ext_mul(
            r1cs,
            row,
            &ext_add_lc(&m2, &d2),
            &ext_sub_lc(&r_chal, &ext_const_lc(1)),
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        let (next_row, m4) = ext_mul(
            r1cs,
            row,
            &ext_add_lc(&m3, &d1),
            &r_chal,
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        claim = ext_add_lc(&m4, &e0);
    }

    let eq_val = if nv == 0 {
        ext_one_lc()
    } else {
        let mut factor = ext_zero_lc();
        for i in 0..nv {
            let seed = ext_var_lc(
                payload.off_monomial_sumcheck_seed + i * 2,
                payload.off_monomial_sumcheck_seed + i * 2 + 1,
            );
            let r_idx = nv - 1 - i;
            let challenge = ext_var_lc(
                payload.off_monomial_sumcheck_challenges + r_idx * 2,
                payload.off_monomial_sumcheck_challenges + r_idx * 2 + 1,
            );
            let (next_row, sr) = ext_mul(
                r1cs,
                row,
                &seed,
                &challenge,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            let next_factor = ext_add_lc(
                &ext_sub_lc(&ext_sub_lc(&ext_scale_lc(&sr, 2), &seed), &challenge),
                &ext_one_lc(),
            );
            if i == 0 {
                factor = next_factor;
            } else {
                let (next_row, product) = ext_mul(
                    r1cs,
                    row,
                    &factor,
                    &next_factor,
                    &mut aux_offset,
                    &mut wrap_offset,
                );
                row = next_row;
                factor = product;
            }
        }
        factor
    };

    let alpha = ext_var_lc(payload.off_monomial_alpha, payload.off_monomial_alpha + 1);
    let total_terms = k_g * D + k_g;
    let mut combined = ext_zero_lc();
    let mut alpha_power = ext_one_lc();
    for term_idx in 0..total_terms {
        if term_idx == 1 {
            alpha_power = alpha.clone();
        } else if term_idx > 1 {
            let (next_row, next_power) = ext_mul(
                r1cs,
                row,
                &alpha_power,
                &alpha,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            alpha_power = next_power;
        }

        let poly_term = if term_idx < k_g * D {
            let vector = term_idx / D;
            let coeff = term_idx % D;
            let c_val = ext_var_lc(
                monomial_eval_col(payload, range_shape, vector, coeff, 0),
                monomial_eval_col(payload, range_shape, vector, coeff, 1),
            );
            let (next_row, c_minus_times_plus) = ext_mul(
                r1cs,
                row,
                &ext_sub_lc(&c_val, &ext_one_lc()),
                &ext_add_lc(&c_val, &ext_one_lc()),
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            let (next_row, cubic) = ext_mul(
                r1cs,
                row,
                &c_val,
                &c_minus_times_plus,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            cubic
        } else {
            let vector = term_idx - k_g * D;
            let sq = ext_var_lc(
                monomial_sq_eval_col(payload, vector, 0),
                monomial_sq_eval_col(payload, vector, 1),
            );
            let (next_row, sq_bool) = ext_mul(
                r1cs,
                row,
                &sq,
                &ext_sub_lc(&sq, &ext_one_lc()),
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            sq_bool
        };

        let weighted_term = if term_idx == 0 {
            poly_term
        } else {
            let (next_row, weighted) = ext_mul(
                r1cs,
                row,
                &alpha_power,
                &poly_term,
                &mut aux_offset,
                &mut wrap_offset,
            );
            row = next_row;
            weighted
        };
        combined = ext_add_lc(&combined, &weighted_term);
    }

    let expected = if nv == 0 {
        combined
    } else {
        let (next_row, expected) = ext_mul(
            r1cs,
            row,
            &eq_val,
            &combined,
            &mut aux_offset,
            &mut wrap_offset,
        );
        row = next_row;
        expected
    };
    row = insert_ext_linear_eq_mod_q(
        r1cs,
        row,
        &expected,
        &claim,
        payload.off_monomial_sumcheck_wraps + wrap_offset,
        q,
    );
    wrap_offset += 2;

    row = insert_monomial_evaluation_binding_constraints(
        r1cs,
        row,
        range_shape,
        payload,
        q,
        qnr,
        &mut aux_offset,
        &mut wrap_offset,
    );

    debug_assert_eq!(aux_offset, payload.monomial_sumcheck_aux_count);
    debug_assert_eq!(wrap_offset, payload.monomial_sumcheck_wrap_count);
    row
}

#[allow(clippy::too_many_arguments)]
fn insert_monomial_evaluation_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    range_shape: &TypedCpRangeMessageShape,
    payload: &TypedCpRangePayloadBlockLayout,
    q: u64,
    qnr: i64,
    aux_offset: &mut usize,
    wrap_offset: &mut usize,
) -> usize {
    let nv = range_shape.monomial_sumcheck_round_evals.len();
    let table_size = 1usize
        .checked_shl(nv as u32)
        .expect("typed CP monomial sumcheck round count too large");
    assert_eq!(
        range_shape.monomial_vector_lens.len(),
        range_shape.monomial_evaluation_rows.len()
    );
    assert_eq!(
        range_shape.sq_evaluations_count,
        range_shape.monomial_vector_lens.len()
    );
    assert!(range_shape
        .monomial_vector_lens
        .iter()
        .all(|&vector_len| vector_len <= table_size));

    let mut vector_coeff_offset = 0usize;
    for (vector_idx, &vector_len) in range_shape.monomial_vector_lens.iter().enumerate() {
        for coeff in 0..D {
            let mut initial = Vec::with_capacity(table_size);
            for idx in 0..table_size {
                if idx < vector_len {
                    initial.push(ExtLc {
                        c0: vec![(
                            payload.off_monomial_vectors + vector_coeff_offset + idx * D + coeff,
                            1,
                        )],
                        c1: Vec::new(),
                    });
                } else {
                    initial.push(ext_zero_lc());
                }
            }
            let claim = ext_var_lc(
                monomial_eval_col(payload, range_shape, vector_idx, coeff, 0),
                monomial_eval_col(payload, range_shape, vector_idx, coeff, 1),
            );
            row = insert_mle_binding_constraints(
                r1cs,
                row,
                initial,
                &claim,
                payload,
                q,
                qnr,
                aux_offset,
                wrap_offset,
            );
        }

        let mut initial_sq = Vec::with_capacity(table_size);
        for idx in 0..table_size {
            if idx < vector_len {
                let square_start =
                    payload.off_monomial_vector_squares + vector_coeff_offset + idx * D;
                initial_sq.push(ExtLc {
                    c0: (0..D).map(|coeff| (square_start + coeff, 1)).collect(),
                    c1: Vec::new(),
                });
            } else {
                initial_sq.push(ext_zero_lc());
            }
        }
        let sq_claim = ext_var_lc(
            monomial_sq_eval_col(payload, vector_idx, 0),
            monomial_sq_eval_col(payload, vector_idx, 1),
        );
        row = insert_mle_binding_constraints(
            r1cs,
            row,
            initial_sq,
            &sq_claim,
            payload,
            q,
            qnr,
            aux_offset,
            wrap_offset,
        );

        vector_coeff_offset += vector_len * D;
    }
    row
}

#[allow(clippy::too_many_arguments)]
fn insert_mle_binding_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    mut values: Vec<ExtLc>,
    claim: &ExtLc,
    payload: &TypedCpRangePayloadBlockLayout,
    q: u64,
    qnr: i64,
    aux_offset: &mut usize,
    wrap_offset: &mut usize,
) -> usize {
    let mut round = 0usize;
    while values.len() > 1 {
        let half = values.len() / 2;
        let challenge = ext_var_lc(
            payload.off_monomial_sumcheck_challenges + round * 2,
            payload.off_monomial_sumcheck_challenges + round * 2 + 1,
        );
        let mut next = Vec::with_capacity(half);
        for idx in 0..half {
            let left = &values[idx];
            let right = &values[half + idx];
            let diff = ext_sub_lc(right, left);
            let (next_row, scaled) = insert_ext_mul_lc_mod_q(
                r1cs,
                row,
                &challenge,
                &diff,
                payload.off_monomial_sumcheck_aux + *aux_offset,
                payload.off_monomial_sumcheck_wraps + *wrap_offset,
                q,
                qnr,
            );
            row = next_row;
            *aux_offset += 4;
            *wrap_offset += 4;

            let folded = ext_var_lc(
                payload.off_monomial_sumcheck_aux + *aux_offset,
                payload.off_monomial_sumcheck_aux + *aux_offset + 1,
            );
            row = insert_ext_linear_eq_mod_q(
                r1cs,
                row,
                &ext_add_lc(left, &scaled),
                &folded,
                payload.off_monomial_sumcheck_wraps + *wrap_offset,
                q,
            );
            *aux_offset += 2;
            *wrap_offset += 2;
            next.push(folded);
        }
        values = next;
        round += 1;
    }

    row = insert_ext_linear_eq_mod_q(
        r1cs,
        row,
        &values[0],
        claim,
        payload.off_monomial_sumcheck_wraps + *wrap_offset,
        q,
    );
    *wrap_offset += 2;
    row
}

fn typed_range_d_prime() -> i64 {
    D as i64 - 2
}

fn monomial_digit_weight(coeff: usize) -> i64 {
    if coeff == 0 || coeff == D / 2 {
        0
    } else {
        coeff.min(D - coeff) as i64
    }
}

fn gr1cs_hadamard_section_len(shape: &TypedCpGr1csMessageShape) -> usize {
    let sumcheck_len = 8 + shape
        .hadamard_sumcheck_round_evals
        .iter()
        .map(|&eval_count| 8 + eval_count * 2 * 8)
        .sum::<usize>();
    let eval_matrix_len = shape
        .hadamard_eval_matrix_rows
        .iter()
        .map(|&rows| rows * D * 8)
        .sum::<usize>();
    sumcheck_len + eval_matrix_len
}

fn gr1cs_message_len_from_shape(shape: &TypedCpGr1csMessageShape) -> Option<usize> {
    let mut len = gr1cs_hadamard_section_len(shape);
    let Some(range_shape) = &shape.range else {
        return Some(len);
    };

    len = len.checked_add(8)?;
    for &elem_len in &range_shape.monomial_commitment_elem_lens {
        len = len.checked_add(commitment_message_len(elem_len))?;
    }

    len = len.checked_add(8)?;
    for &vector_len in &range_shape.monomial_vector_lens {
        len = len
            .checked_add(8)?
            .checked_add(vector_len.checked_mul(D)?.checked_mul(8)?)?;
    }

    len = len.checked_add(8)?;
    for &eval_count in &range_shape.monomial_sumcheck_round_evals {
        len = len
            .checked_add(8)?
            .checked_add(eval_count.checked_mul(2)?.checked_mul(8)?)?;
    }

    len = len.checked_add(8)?;
    for &rows in &range_shape.monomial_evaluation_rows {
        len = len.checked_add(rows.checked_mul(D)?.checked_mul(8)?)?;
    }

    len = len.checked_add(8)?.checked_add(
        range_shape
            .sq_evaluations_count
            .checked_mul(2)?
            .checked_mul(8)?,
    )?;
    len = len
        .checked_add(8)?
        .checked_add(range_shape.projected_values_count.checked_mul(8)?)?;
    Some(len)
}

fn commitment_message_len(num_elements: usize) -> usize {
    8 + num_elements * D * 8
}

fn gr1cs_hadamard_message_constraints_count(cp_layout: &CpR1csLayout) -> usize {
    8 + cp_layout.had_num_vars * 8 + cp_layout.had_num_vars * 4 * 2 + 3 * 2 * cp_layout.d
}

fn gr1cs_hadamard_message_prefix_len(cp_layout: &CpR1csLayout) -> usize {
    8 + cp_layout.had_num_vars * (8 + 4 * 2 * 8) + 3 * 2 * cp_layout.d * 8
}

fn gr1cs_hadamard_round_len_offset(round: usize) -> usize {
    8 + round * (8 + 4 * 2 * 8)
}

fn gr1cs_hadamard_eval_offset(round: usize, point: usize, comp: usize) -> usize {
    gr1cs_hadamard_round_len_offset(round) + 8 + (point * 2 + comp) * 8
}

fn gr1cs_hadamard_eval_matrix_offset(
    cp_layout: &CpR1csLayout,
    matrix_idx: usize,
    row: usize,
    col: usize,
) -> usize {
    8 + cp_layout.had_num_vars * (8 + 4 * 2 * 8)
        + (matrix_idx * 2 + row) * cp_layout.d * 8
        + col * 8
}

fn insert_gr1cs_hadamard_message_constraints(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    message_byte_col: usize,
    message_bit_col: usize,
    ell: usize,
) -> usize {
    let cp_layout = &statement.partial.cp_layout;
    row = insert_u64_bytes_constant(r1cs, row, message_byte_col, cp_layout.had_num_vars as u64);

    for round in 0..cp_layout.had_num_vars {
        let round_len = gr1cs_hadamard_round_len_offset(round);
        row = insert_u64_bytes_constant(r1cs, row, message_byte_col + round_len, 4);
        for point in 0..4 {
            for comp in 0..2 {
                let offset = gr1cs_hadamard_eval_offset(round, point, comp);
                let cp_col = cp_col_in_digest_r1cs(
                    statement,
                    digest_public_shift,
                    cp_layout.had_eval(ell, round, point, comp),
                );
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    message_byte_col + offset,
                    message_bit_col + (offset + 7) * 8 + 7,
                    cp_col,
                );
            }
        }
    }

    for matrix_idx in 0..3 {
        for matrix_row in 0..2 {
            for col in 0..cp_layout.d {
                let offset =
                    gr1cs_hadamard_eval_matrix_offset(cp_layout, matrix_idx, matrix_row, col);
                let cp_col = cp_col_in_digest_r1cs(
                    statement,
                    digest_public_shift,
                    cp_layout.had_eval_matrix(ell, matrix_idx, matrix_row, col),
                );
                row = insert_i64_limb_bytes_equal_var(
                    r1cs,
                    row,
                    message_byte_col + offset,
                    message_bit_col + (offset + 7) * 8 + 7,
                    cp_col,
                );
            }
        }
    }

    row
}

fn cp_col_in_digest_r1cs(
    statement: &TypedCpStatementR1csLayout,
    digest_public_shift: usize,
    cp_col: usize,
) -> usize {
    let statement_col = if cp_col < statement.partial.num_public {
        cp_col
    } else {
        cp_col + statement.added_public_inputs
    };
    if statement_col < statement.num_public {
        statement_col
    } else {
        statement_col + digest_public_shift
    }
}

fn insert_i64_limb_bytes_equal_var(
    r1cs: &mut R1CSMatrices,
    row: usize,
    byte_col: usize,
    sign_bit_col: usize,
    var_col: usize,
) -> usize {
    r1cs.a.insert(row, var_col, 1);
    for idx in 0..8 {
        r1cs.a.insert(row, byte_col + idx, -(1i64 << (8 * idx)));
    }
    r1cs.a
        .insert(row, sign_bit_col, centered_mod(1i128 << 64, BB_P));
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_u32_limb_bytes_equal_var(
    r1cs: &mut R1CSMatrices,
    row: usize,
    byte_col: usize,
    var_col: usize,
) -> usize {
    r1cs.a.insert(row, var_col, 1);
    r1cs.a.insert(row, byte_col, -1);
    r1cs.a.insert(row, byte_col + 1, -256);
    r1cs.a.insert(row, byte_col + 2, -65_536);
    r1cs.a.insert(row, byte_col + 3, -16_777_216);
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_u64_bytes_constant(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    byte_col: usize,
    value: u64,
) -> usize {
    for (idx, byte) in value.to_le_bytes().iter().copied().enumerate() {
        r1cs.a.insert(row, byte_col + idx, 1);
        r1cs.a.insert(row, 0, -(byte as i64));
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }
    row
}

fn insert_byte_constant(r1cs: &mut R1CSMatrices, row: usize, byte_col: usize, value: u8) -> usize {
    r1cs.a.insert(row, byte_col, 1);
    r1cs.a.insert(row, 0, -(value as i64));
    r1cs.b.insert(row, 0, 1);
    row + 1
}

fn insert_bytes_equal(
    r1cs: &mut R1CSMatrices,
    mut row: usize,
    left: usize,
    right: usize,
    len: usize,
) -> usize {
    for idx in 0..len {
        r1cs.a.insert(row, left + idx, 1);
        r1cs.a.insert(row, right + idx, -1);
        r1cs.b.insert(row, 0, 1);
        row += 1;
    }
    row
}

fn fs_commit_message_body_offset(_block: &TypedCpDigestBlockLayout) -> usize {
    8
}

fn fold_root_entry_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    let commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
    let mut offset = 8;
    for prev in 0..ell {
        offset +=
            8 + commitment_len + 8 + cp_layout.n_in * 8 + 8 + lengths.gr1cs_message_bodies[prev];
    }
    offset
}

fn fold_root_commitment_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    fold_root_entry_body_offset(cp_layout, lengths, ell) + 8
}

fn fold_root_public_input_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    let commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
    fold_root_entry_body_offset(cp_layout, lengths, ell) + 8 + commitment_len + 8
}

fn fold_root_eval_message_body_offset(
    cp_layout: &CpR1csLayout,
    lengths: &TypedCpDigestInputLengths,
    ell: usize,
) -> usize {
    let commitment_len = 8 + cp_layout.kappa * cp_layout.d * 8;
    fold_root_entry_body_offset(cp_layout, lengths, ell)
        + 8
        + commitment_len
        + 8
        + cp_layout.n_in * 8
        + 8
}

fn transcript_seed_public_input_body_offset(cp_layout: &CpR1csLayout, ell: usize) -> usize {
    let mut offset = 8;
    for _ in 0..ell {
        offset += 8 + cp_layout.n_in * 8;
    }
    offset + 8
}

fn transcript_seed_metadata_body_offset(cp_layout: &CpR1csLayout) -> usize {
    let mut offset = 8;
    for _ in 0..cp_layout.ell_np {
        offset += 8 + cp_layout.n_in * 8;
    }
    offset
}

fn challenge_digest_challenge_body_offset(index: usize) -> usize {
    8 + index * (8 + 32) + 8
}

fn challenge_body_transcript_public_input_payload_offset(
    cp_layout: &CpR1csLayout,
    ell: usize,
) -> usize {
    let mut offset = transcript_header_len();
    for current in 0..=ell {
        let payload = offset + event_header_len(b"public-input");
        if current == ell {
            return payload;
        }
        offset = payload + cp_layout.n_in * 8;
    }
    unreachable!("public input offset loop must return")
}

fn challenge_body_transcript_fs_commitment_payload_offset(
    cp_layout: &CpR1csLayout,
    commitment_idx: usize,
) -> usize {
    let mut offset = transcript_header_len();
    for _ in 0..cp_layout.ell_np {
        offset += event_header_len(b"public-input") + cp_layout.n_in * 8;
    }
    for label in [
        b"r1cs-m".as_slice(),
        b"r1cs-n".as_slice(),
        b"r1cs-pub".as_slice(),
    ] {
        offset += event_header_len(label) + 8;
    }
    for current in 0..=commitment_idx {
        let payload = offset + event_header_len(b"fs-commitment");
        if current == commitment_idx {
            return payload;
        }
        offset = payload + 32;
    }
    unreachable!("FS commitment offset loop must return")
}

fn transcript_header_len() -> usize {
    crate::transcript_core::TRANSCRIPT_MAGIC.len() + 2 + 8 + b"symphony-v1".len() + 8
}

fn event_header_len(label: &[u8]) -> usize {
    1 + 8 + label.len() + 8
}

#[allow(clippy::too_many_arguments)]
fn map_original_col_to_typed_cp(
    col: usize,
    ell: usize,
    cp_layout: &CpR1csLayout,
    original_layout: &OriginalStatementR1csLayout,
    original_witness_size: usize,
    original_ajtai_wrap_size: usize,
    original_r1cs_wrap_size: usize,
    off_original_witnesses: usize,
    off_original_ajtai_wraps: usize,
    off_original_r1cs_wraps: usize,
) -> usize {
    if col == original_layout.off_one {
        return cp_layout.off_one;
    }
    if (original_layout.off_public_input..original_layout.off_commitment).contains(&col) {
        let slot = col - original_layout.off_public_input;
        return cp_layout.x_in(ell, slot, 0);
    }
    let commitment_end = original_layout.off_commitment + original_layout.kappa * D;
    if (original_layout.off_commitment..commitment_end).contains(&col) {
        let local = col - original_layout.off_commitment;
        return cp_layout.c(ell, local / D, local % D);
    }
    let witness_end = original_layout.off_witness + original_witness_size;
    if (original_layout.off_witness..witness_end).contains(&col) {
        return off_original_witnesses
            + ell * original_witness_size
            + (col - original_layout.off_witness);
    }
    let ajtai_wrap_end = original_layout.off_ajtai_wrap + original_ajtai_wrap_size;
    if (original_layout.off_ajtai_wrap..ajtai_wrap_end).contains(&col) {
        return off_original_ajtai_wraps
            + ell * original_ajtai_wrap_size
            + (col - original_layout.off_ajtai_wrap);
    }
    let r1cs_wrap_end = original_layout.off_r1cs_wrap + original_r1cs_wrap_size;
    debug_assert!((original_layout.off_r1cs_wrap..r1cs_wrap_end).contains(&col));
    off_original_r1cs_wraps + ell * original_r1cs_wrap_size + (col - original_layout.off_r1cs_wrap)
}

fn insert_original_r1cs_lc(
    r1cs: &mut R1CSMatrices,
    row: usize,
    layout: &OriginalStatementR1csLayout,
    r1cs_src: &R1CSMatrices,
    constraint: usize,
    coeff: usize,
) {
    insert_original_matrix_row_lc(&mut r1cs.a, row, layout, &r1cs_src.a, constraint, coeff);
    insert_original_matrix_row_lc(&mut r1cs.b, row, layout, &r1cs_src.b, constraint, coeff);
    insert_original_matrix_row_lc(&mut r1cs.c, row, layout, &r1cs_src.c, constraint, coeff);
    let wrap_col = layout.off_r1cs_wrap + constraint * D + coeff;
    r1cs.c.insert(row, wrap_col, layout.q as i64);
}

fn insert_original_matrix_row_lc(
    target: &mut crate::r1cs::SparseMatrix,
    row: usize,
    layout: &OriginalStatementR1csLayout,
    source: &crate::r1cs::SparseMatrix,
    source_row: usize,
    coeff: usize,
) {
    for &(r, col, value) in &source.entries {
        if r != source_row {
            continue;
        }
        if col < layout.n_public {
            if coeff == 0 {
                target.insert(row, layout.off_public_input + col, value);
            }
        } else {
            target.insert(
                row,
                layout.off_witness + (col - layout.n_public) * D + coeff,
                value,
            );
        }
    }
}

fn assemble_full_ring_witness(public_input: &[i64], witness_part: &RingVector) -> RingVector {
    let mut elements = Vec::with_capacity(public_input.len() + witness_part.len());
    elements.extend(public_input.iter().copied().map(RingElement::from_constant));
    elements.extend(witness_part.elements.iter().cloned());
    RingVector::from(elements)
}

fn raw_ajtai_coeff(
    ajtai: &crate::commitment::AjtaiParams,
    full_witness: &RingVector,
    commitment_row: usize,
    coeff: usize,
) -> i128 {
    let mut acc = 0i128;
    for col in 0..ajtai.n {
        let a = &ajtai.a[commitment_row][col];
        let w = &full_witness.elements[col];
        for a_coeff in 0..D {
            let (w_coeff, sign) = negacyclic_partner(coeff, a_coeff);
            acc += sign * a.coeffs[a_coeff] as i128 * w.coeffs[w_coeff] as i128;
        }
    }
    acc
}

fn raw_original_r1cs_row(
    r1cs_src: &R1CSMatrices,
    full_witness: &RingVector,
    constraint: usize,
    coeff: usize,
) -> (i128, i128, i128) {
    let eval = |matrix: &crate::r1cs::SparseMatrix| -> i128 {
        matrix
            .entries
            .iter()
            .filter(|&&(row, _, _)| row == constraint)
            .map(|&(_, col, value)| {
                value as i128 * full_witness.elements[col].coeffs[coeff] as i128
            })
            .sum()
    };
    (eval(&r1cs_src.a), eval(&r1cs_src.b), eval(&r1cs_src.c))
}

fn negacyclic_partner(target_coeff: usize, a_coeff: usize) -> (usize, i128) {
    if target_coeff >= a_coeff {
        (target_coeff - a_coeff, 1)
    } else {
        (D + target_coeff - a_coeff, -1)
    }
}

fn wrap_quotient(diff: i128, q: u64) -> i64 {
    assert_eq!(diff.rem_euclid(q as i128), 0);
    i64::try_from(diff / q as i128).expect("typed CP wrap quotient exceeds i64")
}

fn sponge_permute_input(constants: &Poseidon2Constants, state: &mut [u32; WIDTH], input: &[u32]) {
    let mut pos = 0usize;
    loop {
        let mut absorbed = 0usize;
        for slot in state.iter_mut().take(RATE) {
            if pos < input.len() {
                *slot = input[pos];
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    software_permutation(constants, state);
                }
                return;
            }
        }
        software_permutation(constants, state);
    }
}

fn sponge_permute_input_recording(
    constants: &Poseidon2Constants,
    state: &mut [u32; WIDTH],
    input: &[u32],
    witness_values: &mut Vec<u32>,
) {
    let mut pos = 0usize;
    loop {
        let mut absorbed = 0usize;
        for slot in state.iter_mut().take(RATE) {
            if pos < input.len() {
                *slot = input[pos];
                pos += 1;
                absorbed += 1;
            } else {
                if absorbed != 0 {
                    software_permutation_recording(constants, state, witness_values);
                }
                return;
            }
        }
        software_permutation_recording(constants, state, witness_values);
    }
}

fn software_permutation(constants: &Poseidon2Constants, state: &mut [u32; WIDTH]) {
    software_mds_light(state);
    for round in &constants.external_initial {
        for i in 0..WIDTH {
            state[i] = exp7(add(state[i], round[i]));
        }
        software_mds_light(state);
    }
    for &rc in &constants.internal {
        state[0] = exp7(add(state[0], rc));
        software_internal_linear(state);
    }
    for round in &constants.external_terminal {
        for i in 0..WIDTH {
            state[i] = exp7(add(state[i], round[i]));
        }
        software_mds_light(state);
    }
}

fn software_permutation_recording(
    constants: &Poseidon2Constants,
    state: &mut [u32; WIDTH],
    witness_values: &mut Vec<u32>,
) {
    software_mds_light(state);
    for round in &constants.external_initial {
        for i in 0..WIDTH {
            state[i] = exp7_recording(add(state[i], round[i]), witness_values);
        }
        software_mds_light(state);
    }
    for &rc in &constants.internal {
        state[0] = exp7_recording(add(state[0], rc), witness_values);
        software_internal_linear(state);
    }
    for round in &constants.external_terminal {
        for i in 0..WIDTH {
            state[i] = exp7_recording(add(state[i], round[i]), witness_values);
        }
        software_mds_light(state);
    }
}

fn circuit_mds_light(state: &mut [Lin; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let x = [
            chunk[0].clone(),
            chunk[1].clone(),
            chunk[2].clone(),
            chunk[3].clone(),
        ];
        chunk[0] = x[0].scale(2).add(&x[1].scale(3)).add(&x[2]).add(&x[3]);
        chunk[1] = x[0].add(&x[1].scale(2)).add(&x[2].scale(3)).add(&x[3]);
        chunk[2] = x[0].add(&x[1]).add(&x[2].scale(2)).add(&x[3].scale(3));
        chunk[3] = x[0].scale(3).add(&x[1]).add(&x[2]).add(&x[3].scale(2));
    }
    let sums: [Lin; 4] = core::array::from_fn(|k| {
        let mut acc = Lin::zero();
        for j in (0..WIDTH).step_by(4) {
            acc = acc.add(&state[j + k]);
        }
        acc
    });
    for i in 0..WIDTH {
        state[i] = state[i].add(&sums[i % 4]);
    }
}

fn circuit_internal_linear(state: &mut [Lin; WIDTH]) {
    let mut part_sum = Lin::zero();
    for item in state.iter().take(WIDTH).skip(1) {
        part_sum = part_sum.add(item);
    }
    let full_sum = part_sum.add(&state[0]);
    state[0] = part_sum.sub(&state[0]);
    let diag = internal_diag();
    for i in 1..WIDTH {
        state[i] = full_sum.add(&state[i].scale(diag[i]));
    }
}

fn software_mds_light(state: &mut [u32; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let x = [chunk[0], chunk[1], chunk[2], chunk[3]];
        chunk[0] = add(add(add(mul_small(x[0], 2), mul_small(x[1], 3)), x[2]), x[3]);
        chunk[1] = add(add(add(x[0], mul_small(x[1], 2)), mul_small(x[2], 3)), x[3]);
        chunk[2] = add(add(add(x[0], x[1]), mul_small(x[2], 2)), mul_small(x[3], 3));
        chunk[3] = add(add(add(mul_small(x[0], 3), x[1]), x[2]), mul_small(x[3], 2));
    }
    let sums: [u32; 4] = core::array::from_fn(|k| {
        let mut acc = 0u32;
        for j in (0..WIDTH).step_by(4) {
            acc = add(acc, state[j + k]);
        }
        acc
    });
    for i in 0..WIDTH {
        state[i] = add(state[i], sums[i % 4]);
    }
}

fn software_internal_linear(state: &mut [u32; WIDTH]) {
    let mut part_sum = 0u32;
    for &value in state.iter().skip(1) {
        part_sum = add(part_sum, value);
    }
    let full_sum = add(part_sum, state[0]);
    state[0] = sub(part_sum, state[0]);
    let diag = internal_diag();
    for i in 1..WIDTH {
        state[i] = add(full_sum, mul(state[i], diag[i]));
    }
}

fn internal_diag() -> [u32; WIDTH] {
    [
        sub(0, 2),
        1,
        2,
        inv_pow2(1),
        3,
        4,
        sub(0, inv_pow2(1)),
        sub(0, 3),
        sub(0, 4),
        inv_pow2(8),
        inv_pow2(2),
        inv_pow2(3),
        inv_pow2(27),
        sub(0, inv_pow2(8)),
        sub(0, inv_pow2(4)),
        sub(0, inv_pow2(27)),
    ]
}

fn exp7(x: u32) -> u32 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    let x6 = mul(x4, x2);
    mul(x6, x)
}

fn exp7_recording(x: u32, witness_values: &mut Vec<u32>) -> u32 {
    let x2 = mul(x, x);
    witness_values.push(x2);
    let x4 = mul(x2, x2);
    witness_values.push(x4);
    let x6 = mul(x4, x2);
    witness_values.push(x6);
    let x7 = mul(x6, x);
    witness_values.push(x7);
    x7
}

fn add(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % BB_P) as u32
}

fn sub(a: u32, b: u32) -> u32 {
    ((a as u64 + BB_P - b as u64) % BB_P) as u32
}

fn mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % BB_P) as u32
}

fn mul_small(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % BB_P) as u32
}

fn inv_pow2(exp: u64) -> u32 {
    mod_pow_u64(2, BB_P - 1 - exp) as u32
}

fn mod_pow_u64(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base %= BB_P;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % BB_P;
        }
        base = (base * base) % BB_P;
        exp >>= 1;
    }
    result
}

fn centered_coeff(value: u32) -> i64 {
    if value as u64 > BB_P / 2 {
        value as i64 - BB_P as i64
    } else {
        value as i64
    }
}

fn centered_i128(value: i128) -> i64 {
    let p = BB_P as i128;
    let value = value.rem_euclid(p);
    if value > p / 2 {
        (value - p) as i64
    } else {
        value as i64
    }
}

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
    fn typed_cp_digest_r1cs_rejects_bad_private_digest_inputs() {
        let fixture = typed_cp_digest_fixture();

        let mut z = fixture.z.clone();
        z[fixture.layout.fs_commitment_blocks[0].off_private_witness] += 1;
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));

        let mut witness = fixture.witness.clone();
        witness.fs_openings[0][0] ^= 1;
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(fixture.params.q);
        let witness_bytes = encode_typed_cp_digest_witness(
            &fixture.public,
            &witness,
            &fixture.layout,
            &fixture.params.ntt,
            ext_ctx.alpha,
            fixture.params.q,
            &fixture.ajtai,
            &fixture.original_r1cs,
        )
        .unwrap();
        let instance = encode_typed_cp_digest_instance(
            &fixture.public,
            &fixture.witness.fs_commitments,
            &fixture.layout,
        )
        .unwrap();
        let z = bytes_to_i64_vec(&instance, &witness_bytes);
        assert!(!fixture.digest_r1cs.is_satisfied_mod(&z, BB_P));
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
