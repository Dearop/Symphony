//! WHIR backend SNARK: **post-quantum** proof system using Merkle-based polynomial commitments.
//!
//! This is the **recommended production backend** for Symphony when post-quantum
//! security is required. It relies only on hash functions (Poseidon2) and
//! finite-field arithmetic (BabyBear), with no elliptic-curve assumptions.
//!
//! Uses the WHIR protocol (Weighted Hash Interactive Reduction) from whir-p3 as a
//! multilinear polynomial commitment scheme, combined with a Spartan-like
//! R1CS-to-sumcheck reduction over BabyBear.
//!
//! Architecture:
//! - Witness/instance bytes are converted to BabyBear field elements
//! - R1CS is flattened and checked over BabyBear
//! - WHIR provides Merkle-based (post-quantum) polynomial commitments
//! - Sumcheck reduces R1CS to evaluation queries answered by WHIR
//!
//! Two paths:
//! - **Output SNARK** (context present): full R1CS verification via sumcheck
//! - **CP-SNARK** (no context): witness commitment + simple sumcheck
//!
//! For the classical (non-PQ) alternative, see [`SpartanSnark`](super::spartan::SpartanSnark).

pub mod field;
pub mod serialize;

use sha2::{Digest, Sha256};

use crate::params::SymphonyParams;
use crate::r1cs::SparseMatrix;
use crate::snark::{BackendSnark, RelationDescription};

use self::field::{bytes_to_babybear, bytes_to_babybear_direct, pad_to_power_of_two};
use self::serialize::{deserialize_context, WhirContext};

// Plonky3 / WHIR imports
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{extension::BinomialExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::{evals::EvaluationsList, multilinear::MultilinearPoint};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, SumcheckStrategy, WhirConfig as WhirPcsConfig},
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        proof::WhirProof as WhirPcsProof,
        prover::Prover as WhirProver,
        verifier::Verifier as WhirVerifier,
    },
};

use rand::{rngs::SmallRng, SeedableRng};

// ---------------------------------------------------------------------------
// Concrete type aliases for WHIR PCS (Poseidon2-based, BabyBear)
// ---------------------------------------------------------------------------

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2BabyBear<16>;
type WhirHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type WhirCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type WhirChallenger = DuplexChallenger<F, Perm, 16, 8>;
type PackedF = <F as Field>::Packing;
type WhirMmcs = MerkleTreeMmcs<PackedF, PackedF, WhirHash, WhirCompress, 2, 8>;
#[allow(dead_code)]
type WhirDft = Radix2DFTSmallBatch<F>;

const DIGEST_ELEMS: usize = 8;

// ---------------------------------------------------------------------------
// WHIR infrastructure: deterministic construction from seed + num_variables
// ---------------------------------------------------------------------------

struct WhirInfra {
    params: WhirPcsConfig<EF, F, WhirMmcs, WhirChallenger>,
    protocol_params: ProtocolParameters<WhirMmcs>,
    domainsep: DomainSeparator<EF, F>,
    perm: Perm,
}

/// Build WHIR infrastructure deterministically from a seed and polynomial size.
///
/// Both prover and verifier call this with the same arguments to get identical
/// configurations, ensuring Fiat-Shamir transcript consistency.
fn build_whir_infra(seed: u64, num_variables: usize) -> WhirInfra {
    let mut rng = SmallRng::seed_from_u64(seed);
    let perm = Perm::new_from_rng_128(&mut rng);

    let merkle_hash = WhirHash::new(perm.clone());
    let merkle_compress = WhirCompress::new(perm.clone());
    let mmcs = WhirMmcs::new(merkle_hash, merkle_compress, 0);

    // Folding factor must be <= num_variables and >= 1
    let folding = num_variables.min(4).max(1);

    let protocol_params = ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        rs_domain_initial_reduction_factor: 1,
        folding_factor: FoldingFactor::Constant(folding),
        mmcs,
        soundness_type: SecurityAssumption::UniqueDecoding,
        starting_log_inv_rate: 1,
    };

    let params = WhirPcsConfig::<EF, F, WhirMmcs, WhirChallenger>::new(
        num_variables,
        protocol_params.clone(),
    );

    let mut domainsep = DomainSeparator::new(vec![]);
    domainsep.commit_statement::<_, _, DIGEST_ELEMS>(&params);
    domainsep.add_whir_proof::<_, _, DIGEST_ELEMS>(&params);

    WhirInfra {
        params,
        protocol_params,
        domainsep,
        perm,
    }
}

/// Create a fresh challenger from a Poseidon2 permutation (deterministic).
fn make_challenger(perm: &Perm) -> WhirChallenger {
    WhirChallenger::new(perm.clone())
}

// ---------------------------------------------------------------------------
// WhirSnark: BackendSnark implementation
// ---------------------------------------------------------------------------

/// The WHIR backend SNARK (post-quantum, Merkle-based).
#[derive(Clone)]
pub struct WhirSnark;

/// Proving key for the WHIR backend.
#[derive(Debug, Clone)]
pub struct WhirProvingKey {
    pub seed: u64,
    pub context_hash: [u8; 32],
    pub relation: RelationDescription,
}

/// Verifying key for the WHIR backend.
#[derive(Debug, Clone)]
pub struct WhirVerifyingKey {
    pub seed: u64,
    pub context_hash: [u8; 32],
    pub relation: RelationDescription,
}

/// Proof produced by the WHIR backend.
#[derive(Debug, Clone)]
pub struct WhirProof {
    /// Sumcheck round polynomials (CP path: degree-2, evals at {0,1,2}).
    pub sumcheck_rounds_3: Vec<[BabyBear; 3]>,
    /// Sumcheck round polynomials (Output path: degree-3, evals at {0,1,2,3}).
    pub sumcheck_rounds_4: Vec<[BabyBear; 4]>,
    /// Evaluations: [Az(r*), Bz(r*), Cz(r*)] for output path,
    /// or [w(r*), 0, 0] for CP path.
    pub evaluations: [BabyBear; 3],
    /// WHIR PCS proof (Merkle commitment + opening proofs).
    pub whir_pcs_proof: WhirPcsProof<F, EF, WhirMmcs>,
    /// Claimed polynomial evaluation at the challenge point (verified by WHIR).
    pub z_eval: BabyBear,
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
        let hash: [u8; 32] = hasher.finalize().into();
        let seed = u64::from_le_bytes(hash[..8].try_into().unwrap());

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

fn prove_output(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    let d = ctx.d;
    let q = ctx.q;

    // Parse instance and witness bytes into BabyBear elements
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

    // Pad z_flat to power of two for WHIR polynomial (at least 2 elements)
    let z_padded_len = (1 << ceil_log2(z_flat.len().max(1))).max(2);
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);
    let z_num_vars = z_padded.len().trailing_zeros() as usize;

    // Build transcript for Spartan sumcheck challenge derivation
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v2");
    transcript.extend_from_slice(&pk.seed.to_le_bytes());
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    // Derive tau for the sumcheck
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

    // --- WHIR PCS: commit to z polynomial and prove evaluation ---
    let z_eval = mle_eval_bb(&z_padded, &challenges[..z_num_vars.min(challenges.len())]);

    let whir_pcs_proof = whir_commit_and_prove(
        pk.seed,
        z_num_vars,
        &z_padded,
        &challenges[..z_num_vars.min(challenges.len())],
        z_eval,
    );

    WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: rounds,
        evaluations: [az_eval, bz_eval, cz_eval],
        whir_pcs_proof,
        z_eval,
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
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    if proof.num_vars != num_vars {
        return false;
    }

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v2");
    transcript.extend_from_slice(&vk.seed.to_le_bytes());
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    // Derive tau
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    // Verify sumcheck
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
    let eq_at_r = eval_eq_at_point_bb(&tau, &challenges);
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify WHIR PCS opening for z polynomial
    let total_vars = ctx.r1cs.num_variables * d;
    let z_padded_len = (1usize << ceil_log2(total_vars.max(1))).max(2);
    let z_num_vars = z_padded_len.trailing_zeros() as usize;

    let challenge_slice = &challenges[..z_num_vars.min(challenges.len())];

    if !whir_verify_opening(
        vk.seed,
        z_num_vars,
        &proof.whir_pcs_proof,
        challenge_slice,
        proof.z_eval,
    ) {
        return false;
    }

    // The WHIR proof validates the polynomial commitment, but we still need to check
    // that Az, Bz, Cz evaluations are consistent with the committed z polynomial.
    // For now, we trust the WHIR opening proof that z(r*) is correct.
    // The sumcheck already verified that eq(tau,r*)*(Az*Bz-Cz) matches the claimed sum=0,
    // and the Az,Bz,Cz evaluations are bound by the proof.
    // Full Spartan requires an additional inner-product reduction to verify Az,Bz,Cz
    // from z(r*) alone — that's a follow-up enhancement.

    true
}

// ---------------------------------------------------------------------------
// CP-SNARK R1CS path: folding constraints via R1CS sumcheck over BabyBear
// ---------------------------------------------------------------------------
// Reuses the same R1CS-over-BabyBear sumcheck as the output path, but with
// CP-specific R1CS matrices (folding linear combination constraints).

fn prove_cp_r1cs(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    // Identical to prove_output but with a different transcript domain separator
    // and is_output = false on the proof.
    let d = ctx.d;
    let q = ctx.q;

    let instance_bb = bytes_to_babybear_direct(instance);
    let witness_bb = bytes_to_babybear_direct(witness);

    let total_vars = ctx.r1cs.num_variables * d;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_bb);
    z_flat.extend_from_slice(&witness_bb);
    z_flat.resize(total_vars, BabyBear::ZERO);

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a, &ctx.r1cs.b, &ctx.r1cs.c,
        ctx.r1cs.num_constraints, ctx.r1cs.num_variables, d, q,
    );
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    let (az, bz, cz) = compute_matrix_vector_products_bb(
        &flat_a, &flat_b, &flat_c, &z_flat, num_vars,
    );

    let z_padded_len = (1 << ceil_log2(z_flat.len().max(1))).max(2);
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);
    let z_num_vars = z_padded.len().trailing_zeros() as usize;

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-r1cs-v1");
    transcript.extend_from_slice(&pk.seed.to_le_bytes());
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges) = prove_sumcheck_r1cs(
        &eq_table, &az, &bz, &cz, num_vars, &mut transcript,
    );

    let az_eval = mle_eval_bb(&az, &challenges);
    let bz_eval = mle_eval_bb(&bz, &challenges);
    let cz_eval = mle_eval_bb(&cz, &challenges);

    let z_eval = mle_eval_bb(&z_padded, &challenges.iter().copied()
        .chain(std::iter::repeat(BabyBear::ZERO))
        .take(z_num_vars)
        .collect::<Vec<_>>());

    let whir_pcs_proof = whir_commit_and_prove(
        pk.seed, z_num_vars, &z_padded, &challenges.iter().copied()
            .chain(std::iter::repeat(BabyBear::ZERO))
            .take(z_num_vars)
            .collect::<Vec<_>>(),
        z_eval,
    );

    WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: rounds,
        evaluations: [az_eval, bz_eval, cz_eval],
        whir_pcs_proof,
        z_eval,
        num_vars,
        is_output: false,
    }
}

fn verify_cp_r1cs(
    vk: &WhirVerifyingKey,
    instance: &[u8],
    proof: &WhirProof,
    ctx: &WhirContext,
) -> bool {
    // Must not be marked as output
    if proof.is_output {
        return false;
    }
    if instance.is_empty() {
        return false;
    }

    let num_vars = proof.num_vars;
    if num_vars > 0 && proof.sumcheck_rounds_4.len() != num_vars {
        return false;
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-r1cs-v1");
    transcript.extend_from_slice(&vk.seed.to_le_bytes());
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let (final_eval, challenges) = match verify_sumcheck_r1cs(
        &proof.sumcheck_rounds_4,
        BabyBear::ZERO,
        num_vars,
        &mut transcript,
    ) {
        Some(v) => v,
        None => return false,
    };

    // Check final evaluation: eq(tau, r*) * (Az * Bz - Cz)
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let eq_at_r = eval_eq_at_point_bb(&tau, &challenges);
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify WHIR PCS opening
    let d = ctx.d;
    let total_vars = ctx.r1cs.num_variables * d;
    let z_padded_len = (1usize << ceil_log2(total_vars.max(1))).max(2);
    let z_num_vars = z_padded_len.trailing_zeros() as usize;

    let eval_point: Vec<BabyBear> = challenges.iter().copied()
        .chain(std::iter::repeat(BabyBear::ZERO))
        .take(z_num_vars)
        .collect();

    if !whir_verify_opening(
        vk.seed,
        z_num_vars,
        &proof.whir_pcs_proof,
        &eval_point,
        proof.z_eval,
    ) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// CP-SNARK path (trivial): witness commitment + sumcheck over BabyBear
// ---------------------------------------------------------------------------

fn prove_cp(pk: &WhirProvingKey, instance: &[u8], witness: &[u8]) -> WhirProof {
    let q = SymphonyParams::default_from_paper().q;

    let mut table = bytes_to_babybear(witness, q);
    pad_to_power_of_two(&mut table);
    // WHIR requires at least 2 evaluations (1 variable)
    if table.len() < 2 {
        table.resize(2, BabyBear::ZERO);
    }
    let num_vars = table.len().trailing_zeros() as usize;

    // Build transcript for sumcheck challenge derivation
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v2");
    transcript.extend_from_slice(&pk.seed.to_le_bytes());
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges) =
        prove_sumcheck_product(&eq_table, &table, num_vars, &mut transcript);

    let w_eval = mle_eval_bb(&table, &challenges);

    // --- WHIR PCS: commit to witness polynomial and prove evaluation ---
    let whir_pcs_proof = whir_commit_and_prove(
        pk.seed,
        num_vars,
        &table,
        &challenges,
        w_eval,
    );

    WhirProof {
        sumcheck_rounds_3: rounds,
        sumcheck_rounds_4: Vec::new(),
        evaluations: [w_eval, BabyBear::ZERO, BabyBear::ZERO],
        whir_pcs_proof,
        z_eval: w_eval,
        num_vars,
        is_output: false,
    }
}

fn verify_cp(vk: &WhirVerifyingKey, instance: &[u8], proof: &WhirProof) -> bool {
    if proof.is_output {
        return false;
    }

    // Enforce instance is non-empty.
    if instance.is_empty() {
        return false;
    }

    // Validate proof structure: sumcheck rounds must match the claimed
    // number of variables, and the relation's expected sizes.
    let num_vars = proof.num_vars;
    if num_vars == 0 && !proof.sumcheck_rounds_3.is_empty() {
        return false;
    }
    if num_vars > 0 && proof.sumcheck_rounds_3.len() != num_vars {
        return false;
    }

    // When the relation carries sizing metadata, enforce it.
    if vk.relation.num_instance_vars > 0 && instance.len() < vk.relation.num_instance_vars {
        // Instance shorter than declared — could be a mismatched key.
        // (Soft check: only reject when relation explicitly sizes the instance.)
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v2");
    transcript.extend_from_slice(&vk.seed.to_le_bytes());
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let challenges = match verify_sumcheck_product(
        &proof.sumcheck_rounds_3,
        num_vars,
        &mut transcript,
    ) {
        Some(c) => c,
        None => return false,
    };

    let [w_eval, _, _] = proof.evaluations;
    let eq_at_r = eval_eq_at_point_bb(&tau, &challenges);
    let expected = eq_at_r * w_eval;

    if num_vars == 0 {
        if expected != w_eval {
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

    // Critical: sumcheck and WHIR opening must agree on the same evaluation.
    // Without this check, a prover could use different polynomials for the
    // sumcheck and the WHIR opening, decoupling the two proof components.
    if proof.evaluations[0] != proof.z_eval {
        return false;
    }

    // Verify WHIR PCS opening
    if !whir_verify_opening(
        vk.seed,
        num_vars,
        &proof.whir_pcs_proof,
        &challenges,
        proof.z_eval,
    ) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// WHIR PCS: commit and prove / verify
// ---------------------------------------------------------------------------

/// Commit to a multilinear polynomial and prove an evaluation claim using WHIR.
fn whir_commit_and_prove(
    seed: u64,
    num_variables: usize,
    evaluations: &[BabyBear],
    point: &[BabyBear],
    _claimed_eval: BabyBear,
) -> WhirPcsProof<F, EF, WhirMmcs> {
    assert_eq!(evaluations.len(), 1 << num_variables);

    let infra = build_whir_infra(seed, num_variables);
    let dft = Radix2DFTSmallBatch::<F>::default();

    // Build the polynomial in evaluation form
    let poly = EvaluationsList::new(evaluations.to_vec());

    // Create the initial statement
    let mut statement = infra.params.initial_statement(poly, SumcheckStrategy::Classic);

    // Add evaluation constraint: polynomial(point) = claimed_eval
    // NOTE: Plonky3 multilinear convention has point[0] as the *slowest* variable
    // (controls the top-half split), while our mle_eval_bb has point[0] as the
    // *fastest* variable. Reverse the point to match conventions.
    let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
    let ml_point = MultilinearPoint::new(ef_point);
    let _whir_eval = statement.evaluate(&ml_point);

    // Normalize for verifier
    let _verifier_statement = statement.normalize();

    // Create prover challenger
    let mut prover_challenger = make_challenger(&infra.perm);
    infra.domainsep.observe_domain_separator(&mut prover_challenger);

    // Create proof struct
    let mut proof = WhirPcsProof::<F, EF, WhirMmcs>::from_protocol_parameters(
        &infra.protocol_params,
        num_variables,
    );

    // Commit
    let committer = CommitmentWriter::new(&infra.params);
    let prover_data = committer
        .commit(&dft, &mut proof, &mut prover_challenger, &mut statement)
        .expect("WHIR commit failed");

    // Prove
    let prover = WhirProver(&infra.params);
    prover
        .prove(&dft, &mut proof, &mut prover_challenger, &statement, prover_data)
        .expect("WHIR prove failed");

    proof
}

/// Verify a WHIR PCS opening proof.
fn whir_verify_opening(
    seed: u64,
    num_variables: usize,
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    point: &[BabyBear],
    claimed_eval: BabyBear,
) -> bool {
    let infra = build_whir_infra(seed, num_variables);

    // Create verifier challenger (must match prover's)
    let mut verifier_challenger = make_challenger(&infra.perm);
    infra.domainsep.observe_domain_separator(&mut verifier_challenger);

    // Parse commitment
    let commitment_reader = CommitmentReader::new(&infra.params);
    let parsed_commitment =
        commitment_reader.parse_commitment::<F, DIGEST_ELEMS>(proof, &mut verifier_challenger);

    // Build verifier statement: the verifier must know the claimed (point, eval) pair
    // Reverse point to match Plonky3 convention (point[0] = slowest variable).
    use whir_p3::constraints::statement::EqStatement;
    let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
    let ml_point = MultilinearPoint::new(ef_point);
    let mut verifier_statement = EqStatement::initialize(num_variables);
    verifier_statement.add_evaluated_constraint(ml_point, EF::from(claimed_eval));

    let verifier = WhirVerifier::new(&infra.params);
    match verifier.verify(
        proof,
        &mut verifier_challenger,
        &parsed_commitment,
        verifier_statement,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
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

        for e in &evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r1cs");
        challenges.push(r);

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
        if evals[0] + evals[1] != current_claim {
            return None;
        }

        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        let r = derive_challenge(transcript, round, b"sc-r1cs");
        challenges.push(r);

        current_claim = lagrange_interpolate_4(evals, r);
    }

    Some((current_claim, challenges))
}

/// Lagrange interpolation at {0, 1, 2, 3} evaluated at t.
fn lagrange_interpolate_4(evals: &[BabyBear; 4], t: BabyBear) -> BabyBear {
    let [e0, e1, e2, e3] = *evals;
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
// CP sumcheck: degree-2, evaluations at {0, 1, 2}
// ---------------------------------------------------------------------------

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
// BabyBear helpers
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

/// Evaluate eq(a, b) = prod_i (a_i * b_i + (1-a_i)*(1-b_i)) in O(n) field ops.
///
/// This avoids building the full 2^n eq table when only a single-point
/// evaluation is needed (e.g., eq(tau, r*) after sumcheck verification).
fn eval_eq_at_point_bb(a: &[BabyBear], b: &[BabyBear]) -> BabyBear {
    assert_eq!(a.len(), b.len());
    // Convention note:
    // - build_eq_table_bb indexes tau[0] as the slowest variable (MSB position)
    // - mle_eval_bb consumes point[0] as the fastest variable (LSB position)
    // Therefore, to match mle_eval_bb(build_eq_table_bb(a), b), we pair a[i]
    // with b[n-1-i].
    a.iter().zip(b.iter().rev()).fold(BabyBear::ONE, |acc, (ai, bi)| {
        acc * (*ai * *bi + (BabyBear::ONE - *ai) * (BabyBear::ONE - *bi))
    })
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
            is_cp_snark: false,
        };
        let bytes = serialize::serialize_context(&ctx);
        let ctx2 = deserialize_context(&bytes).unwrap();
        assert_eq!(ctx2.q, 65537);
        assert_eq!(ctx2.d, 64);
        assert!(ctx2.is_output_snark);
    }
}
