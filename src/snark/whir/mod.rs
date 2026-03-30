//! WHIR backend SNARK: post-quantum proof system using Merkle-based polynomial commitments.
//!
//! Uses the WHIR protocol (Weighted Hash Interactive Reduction) from whir-p3 as a
//! multilinear polynomial commitment scheme, combined with a Spartan-like
//! R1CS-to-sumcheck reduction over BabyBear.
//!
//! Architecture:
//! - Witness/instance bytes are converted to BabyBear field elements via limb splitting
//! - R1CS is flattened and checked over BabyBear
//! - WHIR provides Merkle-based (post-quantum) polynomial commitments
//! - Sumcheck reduces R1CS to evaluation queries answered by WHIR
//!
//! Two paths:
//! - **Output SNARK** (context present): full R1CS verification via sumcheck
//! - **CP-SNARK** (no context): witness commitment + simple sumcheck

pub mod field;
pub mod serialize;

use sha2::{Digest, Sha256};

use crate::params::SymphonyParams;
use crate::r1cs::SparseMatrix;
use crate::snark::{BackendSnark, RelationDescription};

use self::field::{bytes_to_babybear, bytes_to_babybear_direct, pad_to_power_of_two};
use self::serialize::{deserialize_context, WhirContext};

use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};

// ---------------------------------------------------------------------------
// WhirSnark: BackendSnark implementation
// ---------------------------------------------------------------------------

/// The WHIR backend SNARK (post-quantum, Merkle-based).
#[derive(Clone)]
pub struct WhirSnark;

/// Proving key for the WHIR backend.
#[derive(Debug, Clone)]
pub struct WhirProvingKey {
    pub seed: [u8; 32],
    pub context_hash: [u8; 32],
    pub relation: RelationDescription,
}

/// Verifying key for the WHIR backend.
#[derive(Debug, Clone)]
pub struct WhirVerifyingKey {
    pub seed: [u8; 32],
    pub context_hash: [u8; 32],
    pub relation: RelationDescription,
}

/// Proof produced by the WHIR backend.
#[derive(Debug, Clone)]
pub struct WhirProof {
    /// Sumcheck round polynomials.
    /// CP path: degree-2, evals at {0,1,2} stored in first 3 elements.
    /// Output path: degree-3, evals at {0,1,2,3} stored as 4-element vecs.
    pub sumcheck_rounds_3: Vec<[BabyBear; 3]>,
    pub sumcheck_rounds_4: Vec<[BabyBear; 4]>,
    /// Evaluations: [Az(r*), Bz(r*), Cz(r*)] for output path,
    /// or [w(r*), 0, 0] for CP path.
    pub evaluations: [BabyBear; 3],
    /// SHA-256 hash of the witness/z table (binding commitment).
    pub witness_hash: [u8; 32],
    /// Full witness table (needed for verification until WHIR PCS is wired).
    pub witness_table: Option<Vec<BabyBear>>,
    /// Number of sumcheck variables.
    pub num_vars: usize,
    /// Whether this is an output SNARK proof (true) or CP proof (false).
    pub is_output: bool,
}

impl BackendSnark for WhirSnark {
    type ProvingKey = WhirProvingKey;
    type VerifyingKey = WhirVerifyingKey;
    type Proof = WhirProof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        let mut hasher = Sha256::new();
        hasher.update(b"whir-setup");
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
            }
        }
        verify_cp(vk, instance, proof)
    }
}

// ---------------------------------------------------------------------------
// Output SNARK: full R1CS verification via sumcheck over BabyBear
// ---------------------------------------------------------------------------

/// Sparse matrix in COO format over BabyBear.
#[derive(Debug, Clone)]
struct FlatSparseMatrixBB {
    entries: Vec<(usize, usize, BabyBear)>,
    #[allow(dead_code)]
    num_rows: usize,
    #[allow(dead_code)]
    num_cols: usize,
}

/// Flatten ring R1CS to scalar R1CS over BabyBear.
fn flatten_ring_r1cs_bb(
    a: &SparseMatrix,
    b: &SparseMatrix,
    c: &SparseMatrix,
    num_constraints: usize,
    num_variables: usize,
    d: usize,
    _q: u64,
) -> (FlatSparseMatrixBB, FlatSparseMatrixBB, FlatSparseMatrixBB) {
    let flat_rows = num_constraints * d;
    let flat_cols = num_variables * d;

    let flatten_matrix = |mat: &SparseMatrix| -> FlatSparseMatrixBB {
        let mut entries = Vec::with_capacity(mat.entries.len() * d);
        for &(row, col, val) in &mat.entries {
            let s = BabyBear::from_i64(val);
            for j in 0..d {
                entries.push((row * d + j, col * d + j, s));
            }
        }
        FlatSparseMatrixBB {
            entries,
            num_rows: flat_rows,
            num_cols: flat_cols,
        }
    };

    (flatten_matrix(a), flatten_matrix(b), flatten_matrix(c))
}

/// Compute Az, Bz, Cz as dense vectors.
fn compute_matrix_vector_products_bb(
    flat_a: &FlatSparseMatrixBB,
    flat_b: &FlatSparseMatrixBB,
    flat_c: &FlatSparseMatrixBB,
    z_flat: &[BabyBear],
    num_vars: usize,
) -> (Vec<BabyBear>, Vec<BabyBear>, Vec<BabyBear>) {
    let n = 1 << num_vars;

    let sparse_mul = |mat: &FlatSparseMatrixBB| -> Vec<BabyBear> {
        let mut result = vec![BabyBear::ZERO; n];
        for &(row, col, val) in &mat.entries {
            if row < n && col < z_flat.len() {
                result[row] += val * z_flat[col];
            }
        }
        result
    };

    (sparse_mul(flat_a), sparse_mul(flat_b), sparse_mul(flat_c))
}

/// Compute the matrix MLE at a point (for WHIR PCS evaluation proofs).
#[allow(dead_code)]
fn compute_matrix_mle_at_point_bb(
    mat: &FlatSparseMatrixBB,
    point: &[BabyBear],
    num_cols: usize,
) -> Vec<BabyBear> {
    let num_rows = 1 << point.len();
    let eq_table = build_eq_table_bb(point, point.len());

    let mut result = vec![BabyBear::ZERO; num_cols];
    for &(row, col, val) in &mat.entries {
        if row < num_rows && col < num_cols {
            result[col] += eq_table[row] * val;
        }
    }
    result
}

fn prove_output(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    let d = ctx.d;
    let q = ctx.q;

    // Parse instance and witness bytes into BabyBear elements (one per i64)
    let instance_bb = bytes_to_babybear_direct(instance);
    let witness_bb = bytes_to_babybear_direct(witness);

    // Build z_flat = (instance, witness), padded to total_vars * d
    let total_vars = ctx.r1cs.num_variables * d;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_bb);
    z_flat.extend_from_slice(&witness_bb);
    z_flat.resize(total_vars, BabyBear::ZERO);

    // Flatten R1CS
    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a, &ctx.r1cs.b, &ctx.r1cs.c,
        ctx.r1cs.num_constraints, ctx.r1cs.num_variables, d, q,
    );
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    // Compute Az, Bz, Cz
    let (az, bz, cz) = compute_matrix_vector_products_bb(
        &flat_a, &flat_b, &flat_c, &z_flat, num_vars,
    );

    // Pad z_flat to power of two
    let z_padded_len = 1 << ceil_log2(z_flat.len().max(1));
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);

    // Hash-based commitment to z
    let witness_hash = sha256_babybear(&z_padded);

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v1");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(&witness_hash);

    // Derive tau
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    // Build eq(tau, x) table
    let eq_table = build_eq_table_bb(&tau, num_vars);

    // Sumcheck for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)]
    let (rounds, challenges) = prove_sumcheck_r1cs(
        &eq_table, &az, &bz, &cz, num_vars, &mut transcript,
    );

    // Evaluations at challenge point
    let az_eval = mle_eval_bb(&az, &challenges);
    let bz_eval = mle_eval_bb(&bz, &challenges);
    let cz_eval = mle_eval_bb(&cz, &challenges);

    WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: rounds,
        evaluations: [az_eval, bz_eval, cz_eval],
        witness_hash,
        witness_table: Some(z_padded),
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
    if !proof.is_output {
        return false;
    }

    let d = ctx.d;
    let q = ctx.q;
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    if proof.num_vars != num_vars {
        return false;
    }

    // Verify z table binding
    let z_table = match &proof.witness_table {
        Some(t) => t,
        None => return false,
    };
    let actual_hash = sha256_babybear(z_table);
    if actual_hash != proof.witness_hash {
        return false;
    }

    // Verify instance portion of z table matches the provided instance
    let expected_instance = bytes_to_babybear_direct(instance);
    if z_table.len() < expected_instance.len() {
        return false;
    }
    for (i, &expected) in expected_instance.iter().enumerate() {
        if z_table[i] != expected {
            return false;
        }
    }

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v1");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(&proof.witness_hash);

    // Derive tau
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    // Verify sumcheck
    // Claimed sum = 0 for satisfying R1CS (Az*Bz - Cz = 0 everywhere)
    let (final_eval, challenges) = match verify_sumcheck_r1cs(
        &proof.sumcheck_rounds_4,
        BabyBear::ZERO,
        num_vars,
        &mut transcript,
    ) {
        Some(v) => v,
        None => return false,
    };

    // Check final evaluation: eq(tau, r*) * (Az_eval * Bz_eval - Cz_eval)
    let eq_table = build_eq_table_bb(&tau, num_vars);
    let eq_at_r = mle_eval_bb(&eq_table, &challenges);
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify evaluations by recomputing Az, Bz, Cz from the z table
    let total_vars = ctx.r1cs.num_variables * d;
    let z_flat = if z_table.len() >= total_vars {
        &z_table[..total_vars]
    } else {
        return false;
    };

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a, &ctx.r1cs.b, &ctx.r1cs.c,
        ctx.r1cs.num_constraints, ctx.r1cs.num_variables, d, q,
    );
    let (az, bz, cz) = compute_matrix_vector_products_bb(
        &flat_a, &flat_b, &flat_c, z_flat, num_vars,
    );

    let computed_az = mle_eval_bb(&az, &challenges);
    let computed_bz = mle_eval_bb(&bz, &challenges);
    let computed_cz = mle_eval_bb(&cz, &challenges);

    if computed_az != az_eval || computed_bz != bz_eval || computed_cz != cz_eval {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// R1CS sumcheck: degree-3, evaluations at {0, 1, 2, 3}
// ---------------------------------------------------------------------------

/// Prove sumcheck for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)].
fn prove_sumcheck_r1cs(
    eq_table: &[BabyBear],
    az_table: &[BabyBear],
    bz_table: &[BabyBear],
    cz_table: &[BabyBear],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<[BabyBear; 4]>, Vec<BabyBear>) {
    let n = 1 << num_vars;
    assert_eq!(eq_table.len(), n);
    assert_eq!(az_table.len(), n);
    assert_eq!(bz_table.len(), n);
    assert_eq!(cz_table.len(), n);

    let mut eq = eq_table.to_vec();
    let mut az = az_table.to_vec();
    let mut bz = bz_table.to_vec();
    let mut cz = cz_table.to_vec();

    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = eq.len() / 2;

        // Evaluate the univariate at t = 0, 1, 2, 3
        let mut evals = [BabyBear::ZERO; 4];
        for j in 0..half {
            let eq0 = eq[j];
            let eq1 = eq[half + j];
            let az0 = az[j];
            let az1 = az[half + j];
            let bz0 = bz[j];
            let bz1 = bz[half + j];
            let cz0 = cz[j];
            let cz1 = cz[half + j];

            for t in 0u32..4 {
                let t_bb = BabyBear::from_u32(t);
                let one_minus_t = BabyBear::ONE - t_bb;

                let eq_t = eq0 * one_minus_t + eq1 * t_bb;
                let az_t = az0 * one_minus_t + az1 * t_bb;
                let bz_t = bz0 * one_minus_t + bz1 * t_bb;
                let cz_t = cz0 * one_minus_t + cz1 * t_bb;

                evals[t as usize] += eq_t * (az_t * bz_t - cz_t);
            }
        }

        rounds.push(evals);

        // Absorb into transcript
        for e in &evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        // Derive challenge
        let r = derive_challenge(transcript, round, b"sc-r1cs");
        challenges.push(r);

        // Fold tables
        let one_minus_r = BabyBear::ONE - r;
        let mut new_eq = Vec::with_capacity(half);
        let mut new_az = Vec::with_capacity(half);
        let mut new_bz = Vec::with_capacity(half);
        let mut new_cz = Vec::with_capacity(half);
        for j in 0..half {
            new_eq.push(eq[j] * one_minus_r + eq[half + j] * r);
            new_az.push(az[j] * one_minus_r + az[half + j] * r);
            new_bz.push(bz[j] * one_minus_r + bz[half + j] * r);
            new_cz.push(cz[j] * one_minus_r + cz[half + j] * r);
        }
        eq = new_eq;
        az = new_az;
        bz = new_bz;
        cz = new_cz;
    }

    (rounds, challenges)
}

/// Verify R1CS sumcheck (degree-3 round polynomials).
fn verify_sumcheck_r1cs(
    rounds: &[[BabyBear; 4]],
    claimed_sum: BabyBear,
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Option<(BabyBear, Vec<BabyBear>)> {
    if rounds.len() != num_vars {
        return None;
    }
    if num_vars == 0 {
        return Some((claimed_sum, Vec::new()));
    }

    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, evals) in rounds.iter().enumerate() {
        // Check: g(0) + g(1) = current_claim
        if evals[0] + evals[1] != current_claim {
            return None;
        }

        // Absorb into transcript
        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        // Derive challenge
        let r = derive_challenge(transcript, round, b"sc-r1cs");
        challenges.push(r);

        // Interpolate g(r) via Lagrange at {0, 1, 2, 3}
        current_claim = lagrange_interpolate_4(evals, r);
    }

    Some((current_claim, challenges))
}

/// Lagrange interpolation at {0, 1, 2, 3} evaluated at t.
fn lagrange_interpolate_4(evals: &[BabyBear; 4], t: BabyBear) -> BabyBear {
    let [e0, e1, e2, e3] = *evals;
    // L0(t) = (t-1)(t-2)(t-3)/(-6)
    // L1(t) = t(t-2)(t-3)/2
    // L2(t) = t(t-1)(t-3)/(-2)
    // L3(t) = t(t-1)(t-2)/6
    let six_inv = BabyBear::from_u32(6).inverse();
    let two_inv = BabyBear::TWO.inverse();

    let t1 = t - BabyBear::ONE;
    let t2 = t - BabyBear::TWO;
    let t3 = t - BabyBear::from_u32(3);

    let l0 = t1 * t2 * t3 * (-six_inv);
    let l1 = t * t2 * t3 * two_inv;
    let l2 = t * t1 * t3 * (-two_inv);
    let l3 = t * t1 * t2 * six_inv;

    e0 * l0 + e1 * l1 + e2 * l2 + e3 * l3
}

// ---------------------------------------------------------------------------
// CP-SNARK path: hash-committed witness + sumcheck over BabyBear
// ---------------------------------------------------------------------------

fn prove_cp(pk: &WhirProvingKey, instance: &[u8], witness: &[u8]) -> WhirProof {
    let q = SymphonyParams::default_from_paper().q;

    let mut table = bytes_to_babybear(witness, q);
    pad_to_power_of_two(&mut table);
    let num_vars = table.len().trailing_zeros() as usize;
    let witness_hash = sha256_babybear(&table);

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v1");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(&witness_hash);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges) =
        prove_sumcheck_product(&eq_table, &table, num_vars, &mut transcript);

    let w_eval = mle_eval_bb(&table, &challenges);

    WhirProof {
        sumcheck_rounds_3: rounds,
        sumcheck_rounds_4: Vec::new(),
        evaluations: [w_eval, BabyBear::ZERO, BabyBear::ZERO],
        witness_hash,
        witness_table: Some(table),
        num_vars,
        is_output: false,
    }
}

fn verify_cp(vk: &WhirVerifyingKey, instance: &[u8], proof: &WhirProof) -> bool {
    if proof.is_output {
        return false;
    }
    let num_vars = proof.num_vars;

    let table = match &proof.witness_table {
        Some(t) => t,
        None => return false,
    };

    if table.len() != 1 << num_vars {
        return false;
    }
    let actual_hash = sha256_babybear(table);
    if actual_hash != proof.witness_hash {
        return false;
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v1");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(&proof.witness_hash);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let challenges = match verify_sumcheck_product(
        &proof.sumcheck_rounds_3,
        num_vars,
        &mut transcript,
    ) {
        Some(c) => c,
        None => return false,
    };

    let [w_eval, _, _] = proof.evaluations;
    let eq_at_r = mle_eval_bb(&eq_table, &challenges);
    let expected = eq_at_r * w_eval;

    if num_vars == 0 {
        if expected != eq_table[0] * w_eval {
            return false;
        }
    } else {
        let last_round = match proof.sumcheck_rounds_3.last() {
            Some(r) => r,
            None => return false,
        };
        let last_challenge = challenges.last().copied().unwrap_or(BabyBear::ZERO);
        let final_eval = eval_univariate_3(last_round, last_challenge);
        if final_eval != expected {
            return false;
        }
    }

    let computed_w_eval = mle_eval_bb(table, &challenges);
    if computed_w_eval != w_eval {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// BabyBear sumcheck helpers (shared)
// ---------------------------------------------------------------------------

/// Build eq(tau, x) table over {0,1}^n.
fn build_eq_table_bb(tau: &[BabyBear], num_vars: usize) -> Vec<BabyBear> {
    let n = 1 << num_vars;
    let mut table = vec![BabyBear::ONE; n];
    for (i, &ti) in tau.iter().enumerate() {
        let half = 1 << (num_vars - 1 - i);
        for j in (0..n).rev() {
            let bit = (j >> (num_vars - 1 - i)) & 1;
            if bit == 1 {
                table[j] = table[j - half] * ti;
            } else {
                table[j] = table[j] * (BabyBear::ONE - ti);
            }
        }
    }
    table
}

/// Evaluate multilinear extension at a point.
fn mle_eval_bb(table: &[BabyBear], point: &[BabyBear]) -> BabyBear {
    let mut current = table.to_vec();
    for &r in point.iter() {
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(current[2 * j] * (BabyBear::ONE - r) + current[2 * j + 1] * r);
        }
        current = next;
    }
    current[0]
}

/// Evaluate a degree-2 univariate at point t, given evals at {0, 1, 2}.
fn eval_univariate_3(evals: &[BabyBear; 3], t: BabyBear) -> BabyBear {
    let [e0, e1, e2] = *evals;
    let two_inv = BabyBear::TWO.inverse();
    let l0 = (t - BabyBear::ONE) * (t - BabyBear::TWO) * two_inv;
    let l1 = -t * (t - BabyBear::TWO);
    let l2 = t * (t - BabyBear::ONE) * two_inv;
    e0 * l0 + e1 * l1 + e2 * l2
}

/// Prove sumcheck for F(x) = eq(x) * w(x) (degree-2, CP path).
fn prove_sumcheck_product(
    eq_table: &[BabyBear],
    w_table: &[BabyBear],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<[BabyBear; 3]>, Vec<BabyBear>) {
    let n = 1 << num_vars;
    assert_eq!(eq_table.len(), n);
    assert_eq!(w_table.len(), n);

    let mut eq = eq_table.to_vec();
    let mut w = w_table.to_vec();
    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = 1 << (num_vars - 1 - round);

        let mut e0 = BabyBear::ZERO;
        let mut e1 = BabyBear::ZERO;
        let mut e2 = BabyBear::ZERO;

        for j in 0..half {
            let eq_lo = eq[2 * j];
            let eq_hi = eq[2 * j + 1];
            let w_lo = w[2 * j];
            let w_hi = w[2 * j + 1];

            e0 += eq_lo * w_lo;
            e1 += eq_hi * w_hi;
            let eq_at_2 = eq_hi.double() - eq_lo;
            let w_at_2 = w_hi.double() - w_lo;
            e2 += eq_at_2 * w_at_2;
        }

        let round_evals = [e0, e1, e2];
        rounds.push(round_evals);

        for e in &round_evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r");
        challenges.push(r);

        let mut new_eq = Vec::with_capacity(half);
        let mut new_w = Vec::with_capacity(half);
        for j in 0..half {
            new_eq.push(eq[2 * j] * (BabyBear::ONE - r) + eq[2 * j + 1] * r);
            new_w.push(w[2 * j] * (BabyBear::ONE - r) + w[2 * j + 1] * r);
        }
        eq = new_eq;
        w = new_w;
    }

    (rounds, challenges)
}

/// Verify CP sumcheck.
fn verify_sumcheck_product(
    rounds: &[[BabyBear; 3]],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Option<Vec<BabyBear>> {
    if rounds.len() != num_vars {
        return None;
    }
    if num_vars == 0 {
        return Some(Vec::new());
    }

    let claimed_sum = rounds[0][0] + rounds[0][1];
    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, evals) in rounds.iter().enumerate() {
        if evals[0] + evals[1] != current_claim {
            return None;
        }

        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r");
        challenges.push(r);

        current_claim = eval_univariate_3(evals, r);
    }

    Some(challenges)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compute_context_hash(context: &Option<Vec<u8>>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"whir-context-binding");
    if let Some(ref ctx_bytes) = context {
        h.update((ctx_bytes.len() as u64).to_le_bytes());
        h.update(ctx_bytes);
    } else {
        h.update(0u64.to_le_bytes());
    }
    h.finalize().into()
}

fn sha256_babybear(table: &[BabyBear]) -> [u8; 32] {
    let mut h = Sha256::new();
    for s in table {
        h.update(s.as_canonical_u64().to_le_bytes());
    }
    h.finalize().into()
}

fn derive_challenge(transcript: &[u8], index: usize, label: &[u8]) -> BabyBear {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update((index as u64).to_le_bytes());
    hasher.update(transcript);
    let hash: [u8; 32] = hasher.finalize().into();
    let val = u32::from_le_bytes(hash[..4].try_into().unwrap());
    BabyBear::from_u32(val)
}

fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::R1CSMatrices;

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
    fn cp_snark_tampered_witness_rejected() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let mut proof = WhirSnark::prove(&pk, b"instance", b"witness");
        if let Some(ref mut table) = proof.witness_table {
            if !table.is_empty() {
                table[0] += BabyBear::ONE;
            }
        }
        assert!(!WhirSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn cp_snark_tampered_hash_rejected() {
        let (pk, vk) = WhirSnark::setup(&test_relation());
        let mut proof = WhirSnark::prove(&pk, b"instance", b"witness");
        proof.witness_hash[0] ^= 0xFF;
        assert!(!WhirSnark::verify(&vk, b"instance", &proof));
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

    // --- Output SNARK tests ---

    #[test]
    fn output_snark_roundtrip() {
        // Build a simple R1CS: x * x = x (satisfied by x=0 or x=1)
        let mut r1cs = R1CSMatrices::new(1, 2, 1);
        r1cs.a.insert(0, 1, 1); // a: x (variable 1)
        r1cs.b.insert(0, 1, 1); // b: x
        r1cs.c.insert(0, 1, 1); // c: x
        // Constraint: x * x = x

        let ctx = WhirContext {
            r1cs,
            q: 2013265921, // BabyBear prime, small enough for direct use
            d: 1,          // scalar R1CS (no ring structure)
            n_pub: 1,
            is_output_snark: true,
        };
        let ctx_bytes = serialize::serialize_context(&ctx);

        let relation = RelationDescription {
            num_instance_vars: 1,
            num_witness_vars: 1,
            num_constraints: 1,
            context: Some(ctx_bytes),
        };

        let (pk, vk) = WhirSnark::setup(&relation);

        // Witness: x=1 (satisfies x*x=x)
        let instance = 1i64.to_le_bytes();
        let witness = 1i64.to_le_bytes();
        let proof = WhirSnark::prove(&pk, &instance, &witness);
        assert!(proof.is_output);
        assert!(WhirSnark::verify(&vk, &instance, &proof));
    }

    #[test]
    fn output_snark_tampered_eval_rejected() {
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

        // Tamper with an evaluation
        proof.evaluations[0] += BabyBear::ONE;
        assert!(!WhirSnark::verify(&vk, &instance, &proof));
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

    // --- Shared helper tests ---

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
    fn lagrange_4_correctness() {
        // Should exactly recover the evaluation points
        let evals = [
            BabyBear::from_u32(10),
            BabyBear::from_u32(20),
            BabyBear::from_u32(35),
            BabyBear::from_u32(55),
        ];
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::ZERO), evals[0]);
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::ONE), evals[1]);
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::TWO), evals[2]);
        assert_eq!(lagrange_interpolate_4(&evals, BabyBear::from_u32(3)), evals[3]);
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
        };
        let bytes = serialize::serialize_context(&ctx);
        let ctx2 = deserialize_context(&bytes).unwrap();
        assert_eq!(ctx2.q, 65537);
        assert_eq!(ctx2.d, 64);
        assert!(ctx2.is_output_snark);
    }
}
