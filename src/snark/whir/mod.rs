//! WHIR backend SNARK and route hub for Symphony's public-verification work.
//!
//! This is the **recommended post-quantum backend** for Symphony when the `whir`
//! feature is enabled. It relies only on hash functions (Poseidon2/WHIR Merkle
//! commitments) and finite-field arithmetic over BabyBear, with no
//! elliptic-curve assumptions.
//!
//! # Route map
//!
//! This module hosts multiple related but distinct public routes:
//!
//! - **Default product public route:** `prove_public` / `verify_public` over the
//!   version-2 public proof boundary. WHIR is authoritative typed CP and typed
//!   output here, and uses Poseidon2/BabyBear public digests.
//! - **Explicit K6a route:** `backend_impl.rs` exposes the opt-in SYMBT3 NonZK
//!   integrity accumulator route.
//! - **Explicit native/N8 accumulation work:** [`native_oracles`] exposes the
//!   native-oracle performance infrastructure and the N8 integrated accumulation
//!   APIs that sit alongside K6a.
//!
//! The explicit K6a and N8 routes do **not** silently replace the default
//! product `verify_public` path. They are separate APIs with their own proof
//! shapes, gates, and maturity levels.
//!
//! # Backend architecture
//!
//! WHIR uses the WHIR protocol (Weighted Hash Interactive Reduction) from
//! `whir-p3` as a multilinear polynomial commitment scheme, combined with a
//! Spartan-like R1CS-to-sumcheck reduction over BabyBear.
//!
//! Shared backend flow:
//! - witness/instance bytes are converted to BabyBear field elements;
//! - R1CS or typed CP constraints are flattened over BabyBear;
//! - WHIR provides Merkle-based polynomial commitments;
//! - sumcheck reduces the target relation to evaluation queries answered by
//!   WHIR.
//!
//! Internal proof paths:
//! - **Output SNARK** (context present): full R1CS verification via sumcheck;
//! - **CP-SNARK** (no context): witness commitment plus the CP-side sumcheck
//!   path used by Symphony's folding/typed-CP pipeline.
//!
//! For the classical (non-PQ) alternative, see
//! [`SpartanSnark`](super::spartan::SpartanSnark).

pub mod canonical_encoding;
pub mod field;
pub mod instrumented_benchmark;
pub mod native_oracles;
pub mod serialize;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use sha2::{Digest, Sha256};

use crate::folding::{FoldedOutputInstance, FoldedOutputWitness};
use crate::params::{SymphonyParams, D};
use crate::r1cs::{R1CSMatrices, SparseMatrix};
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::tensor::TensorElement;
use crate::ring::RingElement;
use crate::snark::{BackendSnark, RelationDescription};

use self::field::{bytes_to_babybear, bytes_to_babybear_direct, pad_to_power_of_two};
use self::serialize::{deserialize_context, WhirContext, WhirTypedCpContext};

// Plonky3 / WHIR imports
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{
    extension::BinomialExtensionField, Field, PrimeCharacteristicRing, PrimeField32, PrimeField64,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::{evals::EvaluationsList, multilinear::MultilinearPoint};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use whir_p3::{
    fiat_shamir::domain_separator::DomainSeparator,
    parameters::{
        FoldingFactor, ProtocolParameters, SecurityAssumption, SumcheckStrategy,
        WhirConfig as WhirPcsConfig,
    },
    whir::{
        committer::{reader::CommitmentReader, writer::CommitmentWriter},
        proof::WhirProof as WhirPcsProof,
        prover::Prover as WhirProver,
        verifier::Verifier as WhirVerifier,
    },
};

use rand::{rngs::ChaCha20Rng, SeedableRng};

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
const WHIR_SECURITY_LEVEL_BITS: usize = 100;
pub const WHIR_PROOF_PAYLOAD_VERSION: u16 = 2;
const WHIR_PROOF_PAYLOAD_MAGIC: &[u8; 8] = b"SYMWHPF\0";

#[derive(Clone)]
struct CachedTypedCpRelation {
    r1cs: crate::r1cs::R1CSMatrices,
    layout: crate::snark::cp_snark::TypedCpDigestR1csLayout,
    audit: crate::snark::cp_snark::TypedCpAuditReport,
}

static TYPED_CP_RELATION_CACHE: OnceLock<Mutex<HashMap<[u8; 32], Arc<CachedTypedCpRelation>>>> =
    OnceLock::new();
static TYPED_CP_RELATION_DESCRIPTION_CACHE: OnceLock<
    Mutex<HashMap<[u8; 32], RelationDescription>>,
> = OnceLock::new();

fn typed_cp_cache_key(ctx: &WhirContext) -> [u8; 32] {
    let bytes = serialize::serialize_context(ctx);
    Sha256::digest(&bytes).into()
}

fn hash_sparse_matrix_for_cache(hasher: &mut Sha256, matrix: &SparseMatrix) {
    hasher.update((matrix.num_rows as u64).to_le_bytes());
    hasher.update((matrix.num_cols as u64).to_le_bytes());
    hasher.update((matrix.entries.len() as u64).to_le_bytes());
    for &(row, col, value) in &matrix.entries {
        hasher.update((row as u64).to_le_bytes());
        hasher.update((col as u64).to_le_bytes());
        hasher.update(value.to_le_bytes());
    }
}

fn typed_cp_descriptor_cache_key(descriptor: &crate::snark::TypedCpSetupDescriptor) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"whir-typed-cp-relation-description-cache-v1");
    hasher.update(descriptor.params.q.to_le_bytes());
    hasher.update((descriptor.params.d as u64).to_le_bytes());
    hasher.update((descriptor.params.lambda_pj as u64).to_le_bytes());
    hasher.update((descriptor.params.ell_h as u64).to_le_bytes());
    hasher.update((descriptor.params.k_g() as u64).to_le_bytes());
    hasher.update((descriptor.cp_layout.ell_np as u64).to_le_bytes());
    hasher.update((descriptor.cp_layout.kappa as u64).to_le_bytes());
    hasher.update((descriptor.cp_layout.n_in as u64).to_le_bytes());
    hasher.update((descriptor.cp_layout.had_num_vars as u64).to_le_bytes());
    hasher.update((descriptor.ajtai.kappa as u64).to_le_bytes());
    hasher.update((descriptor.ajtai.n as u64).to_le_bytes());
    hasher.update(descriptor.ajtai.q.to_le_bytes());
    for row in &descriptor.ajtai.a {
        hasher.update((row.len() as u64).to_le_bytes());
        for elem in row {
            for &coeff in &elem.coeffs {
                hasher.update(coeff.to_le_bytes());
            }
        }
    }
    hasher.update((descriptor.original_r1cs.num_constraints as u64).to_le_bytes());
    hasher.update((descriptor.original_r1cs.num_variables as u64).to_le_bytes());
    hasher.update((descriptor.original_r1cs.num_public as u64).to_le_bytes());
    hash_sparse_matrix_for_cache(&mut hasher, &descriptor.original_r1cs.a);
    hash_sparse_matrix_for_cache(&mut hasher, &descriptor.original_r1cs.b);
    hash_sparse_matrix_for_cache(&mut hasher, &descriptor.original_r1cs.c);
    hasher.finalize().into()
}

#[allow(dead_code)]
fn typed_cp_digest_r1cs_from_context(
    ctx: &WhirContext,
    typed: &WhirTypedCpContext,
) -> Option<(
    crate::r1cs::R1CSMatrices,
    crate::snark::cp_snark::TypedCpDigestR1csLayout,
)> {
    let cached = typed_cp_relation_from_context(ctx, typed)?;
    Some((cached.r1cs.clone(), cached.layout.clone()))
}

fn typed_cp_relation_from_context(
    ctx: &WhirContext,
    typed: &WhirTypedCpContext,
) -> Option<Arc<CachedTypedCpRelation>> {
    let key = typed_cp_cache_key(ctx);
    let cache = TYPED_CP_RELATION_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache
        .lock()
        .expect("typed CP cache mutex poisoned")
        .get(&key)
    {
        return Some(Arc::clone(cached));
    }

    let ext_ctx = ExtFieldContext::new(ctx.q);
    let (cp_r1cs, cp_layout) = crate::snark::cp_snark::generate_cp_r1cs(
        typed.cp_layout.ell_np,
        typed.cp_layout.kappa,
        typed.cp_layout.n_in,
        typed.original_r1cs.num_constraints,
        ext_ctx.alpha,
        ctx.q,
    );
    if cp_layout.num_instance != typed.cp_layout.num_instance
        || cp_layout.num_variables != typed.cp_layout.num_variables
    {
        return None;
    }
    let lengths = crate::snark::cp_snark::typed_cp_digest_input_lengths_from_setup(
        typed.cp_layout.ell_np,
        typed.cp_layout.kappa,
        typed.cp_layout.n_in,
        typed.lambda_pj,
        typed.ell_h,
        typed.k_g,
        &typed.original_r1cs,
    )?;
    let (r1cs, layout, audit) = crate::snark::cp_snark::generate_typed_cp_digest_r1cs_with_audit(
        &cp_r1cs,
        &cp_layout,
        &typed.ajtai,
        &typed.original_r1cs,
        &lengths,
    );
    debug_assert!(audit.validate_against(&r1cs).is_ok());
    let cached = Arc::new(CachedTypedCpRelation {
        r1cs,
        layout,
        audit,
    });
    let mut guard = cache.lock().expect("typed CP cache mutex poisoned");
    let entry = guard.entry(key).or_insert_with(|| Arc::clone(&cached));
    Some(Arc::clone(entry))
}

// ---------------------------------------------------------------------------
// WHIR infrastructure: deterministic construction from seed + num_variables
// ---------------------------------------------------------------------------

struct WhirInfra {
    params: WhirPcsConfig<EF, F, WhirMmcs, WhirChallenger>,
    protocol_params: ProtocolParameters<WhirMmcs>,
    domainsep: DomainSeparator<EF, F>,
    perm: Perm,
}

struct WhirVerifierInfraEntry {
    num_variables: usize,
    infra: WhirInfra,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WhirVerifierInfraCacheStats {
    pub hits: usize,
    pub misses: usize,
}

#[derive(Default)]
struct WhirVerifierInfraCache {
    entries: HashMap<usize, WhirVerifierInfraEntry>,
    stats: WhirVerifierInfraCacheStats,
}

impl WhirVerifierInfraCache {
    fn verify_opening_multi(
        &mut self,
        seed: &[u8; 32],
        num_variables: usize,
        proof: &WhirPcsProof<F, EF, WhirMmcs>,
        points: &[Vec<BabyBear>],
        claimed_evals: &[BabyBear],
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.verify_opening_multi_inner(seed, num_variables, proof, points, claimed_evals)
        }))
        .unwrap_or(false)
    }

    fn verify_opening_multi_inner(
        &mut self,
        seed: &[u8; 32],
        num_variables: usize,
        proof: &WhirPcsProof<F, EF, WhirMmcs>,
        points: &[Vec<BabyBear>],
        claimed_evals: &[BabyBear],
    ) -> bool {
        if points.len() != claimed_evals.len() {
            return false;
        }
        if points.iter().any(|point| point.len() != num_variables) {
            return false;
        }
        let entry = if self.entries.contains_key(&num_variables) {
            self.stats.hits += 1;
            self.entries.get(&num_variables).expect("cache entry")
        } else {
            self.stats.misses += 1;
            let infra = build_whir_infra(seed, num_variables);
            self.entries.insert(
                num_variables,
                WhirVerifierInfraEntry {
                    num_variables,
                    infra,
                },
            );
            self.entries
                .get(&num_variables)
                .expect("inserted cache entry")
        };
        whir_verify_opening_multi_with_entry(entry, proof, points, claimed_evals)
    }

    fn stats(&self) -> WhirVerifierInfraCacheStats {
        self.stats
    }
}

/// Build WHIR infrastructure deterministically from a seed and polynomial size.
///
/// Both prover and verifier call this with the same arguments to get identical
/// configurations, ensuring Fiat-Shamir transcript consistency.
fn build_whir_infra(seed: &[u8; 32], num_variables: usize) -> WhirInfra {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let perm = Perm::new_from_rng_128(&mut rng);

    let merkle_hash = WhirHash::new(perm.clone());
    let merkle_compress = WhirCompress::new(perm.clone());
    let mmcs = WhirMmcs::new(merkle_hash, merkle_compress, 0);

    // Folding factor must be <= num_variables and >= 1
    let folding = num_variables.clamp(1, 4);

    let protocol_params = ProtocolParameters {
        security_level: WHIR_SECURITY_LEVEL_BITS,
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
pub struct WhirLinearCheckProof {
    /// Degree-2 sumcheck proving <M(r, .), z(.)> = claimed Mz(r).
    pub rounds: Vec<[BabyBear; 3]>,
    /// Claimed z evaluation at the linear-check sumcheck point.
    pub z_eval: BabyBear,
}

/// One development-only WHIR PCS subproof for a SYMBT2F family-local table.
#[derive(Debug, Clone)]
pub struct WhirFamilyColumnarSubproof {
    pub table_index: usize,
    pub num_vars: usize,
    pub z_eval: BabyBear,
    pub whir_pcs_proof: WhirPcsProof<F, EF, WhirMmcs>,
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
    /// Linear checks binding output/CP-R1CS Az, Bz, Cz claims to the same
    /// committed z polynomial.
    pub linear_checks: Vec<WhirLinearCheckProof>,
    /// Additional private opening evaluations used by structured non-R1CS
    /// proof paths. For SYMBTC1 these are paired chunk openings whose extracted
    /// bytes must match across duplicated oracle regions.
    pub private_opening_evals: Vec<BabyBear>,
    /// Development-only family-local WHIR PCS subproofs for SYMBT2F.
    ///
    /// Product CP/output paths and non-SYMBT2F typed paths must reject proofs
    /// with this populated.
    pub family_columnar_subproofs: Vec<WhirFamilyColumnarSubproof>,
    /// Number of sumcheck variables.
    pub num_vars: usize,
    /// Whether this is an output SNARK proof (true) or CP proof (false).
    pub is_output: bool,
}

/// Coarse verifier attribution for the non-authoritative SYMBT3 development
/// path. These counters are intended for architecture benchmarks; they are not
/// part of the public proof envelope.
#[derive(Debug, Clone, Default)]
pub struct Symbt3VerifierCostProfile {
    pub verify_total_ms: f64,
    pub verify_accumulator_decoding_ms: f64,
    pub verify_public_input_parsing_ms: f64,
    pub verify_proof_deserialization_ms: f64,
    pub verify_whir_pcs_ms: f64,
    pub verify_merkle_or_pcs_opening_ms: f64,
    pub verify_transcript_ms: f64,
    pub verify_field_ops_ms: f64,
    pub verify_field_extension_ops_ms: f64,
    pub verify_fold_query_eval_ms: f64,
    pub verify_eq_lagrange_eval_ms: f64,
    pub verify_constraint_batching_ms: f64,
    pub verify_sumcheck_rounds_ms: f64,
    pub verify_final_constraint_eval_ms: f64,
    pub verify_final_eval_manifest_ms: f64,
    pub verify_final_eval_source_r1cs_ms: f64,
    pub verify_final_eval_folded_boundary_ms: f64,
    pub verify_final_eval_product_residual_ms: f64,
    pub verify_final_eval_ajtai_ms: f64,
    pub verify_final_eval_range_ms: f64,
    pub verify_final_eval_message_view_ms: f64,
    pub verify_manifest_membership_eval_ms: f64,
    pub verify_message_view_eval_ms: f64,
    pub verify_projection_eval_ms: f64,
    pub verify_monomial_embedding_eval_ms: f64,
    pub verify_representative_eval_ms: f64,
    pub verify_ajtai_eval_ms: f64,
    pub source_r1cs_residual_claims: usize,
    pub source_r1cs_residual_verifier_evaluations: usize,
}

/// Coarse prover attribution for the opt-in SYMBT3 accumulator path.
///
/// These measurements are benchmark/audit counters only. They are not part of
/// the public proof format and do not affect verification semantics.
#[derive(Debug, Clone, Default)]
pub struct Symbt3ProverCostProfile {
    pub prove_total_ms: f64,
    pub prove_accumulator_glue_ms: f64,
    pub prove_oracle_construction_ms: f64,
    pub prove_whir_folding_layers_ms: f64,
    pub prove_merkle_tree_build_ms: f64,
    pub prove_merkle_path_materialization_ms: f64,
    pub prove_constraint_construction_ms: f64,
    pub prove_constraint_batching_ms: f64,
    pub prove_transcript_ms: f64,
    pub prove_field_ops_ms: f64,
    pub prove_field_extension_ops_ms: f64,
    pub prove_allocations_copies_ms: f64,
    pub prove_proof_serialization_ms: f64,
}

/// Private opening slice for one structured batched-CP semantic block.
///
/// This is a development/audit helper for the non-authoritative SYMBTC1 path;
/// it is not part of the public proof format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhirBatchedCpPrivateOpeningSection {
    pub start: usize,
    pub len: usize,
}

impl WhirBatchedCpPrivateOpeningSection {
    #[must_use]
    pub const fn end(self) -> usize {
        self.start + self.len
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Private opening layout for a structured batched-CP WHIR proof.
///
/// The sections are ordered exactly as `WhirProof::private_opening_evals`.
/// This exists so tests and audit tooling can target individual semantic
/// blocks without relying on hard-coded offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirBatchedCpPrivateOpeningProfile {
    pub equality: WhirBatchedCpPrivateOpeningSection,
    pub folded_public_input: WhirBatchedCpPrivateOpeningSection,
    pub folded_commitment: WhirBatchedCpPrivateOpeningSection,
    pub folded_evaluation: WhirBatchedCpPrivateOpeningSection,
    pub poseidon_r1cs: WhirBatchedCpPrivateOpeningSection,
    pub ajtai_opening: WhirBatchedCpPrivateOpeningSection,
    pub original_r1cs: WhirBatchedCpPrivateOpeningSection,
    pub total_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirBatchedCpColumnarV2FamilyOpeningProfile {
    pub family: crate::batched_cp::BatchedCpSemanticConstraintFamily,
    pub residual_count: usize,
    pub sampled_check_count: usize,
    pub subproof_index: Option<usize>,
    pub num_vars: Option<usize>,
    pub padded_row_count: Option<usize>,
    pub section: WhirBatchedCpPrivateOpeningSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhirBatchedCpColumnarV2OpeningProfile {
    pub families: Vec<WhirBatchedCpColumnarV2FamilyOpeningProfile>,
    pub total_len: usize,
}

/// Compute the private-opening section layout for a structured typed batched CP proof.
///
/// This is a debug/development API only. Product public verification consumes
/// only the proof and public statement; it must not use this helper.
pub fn whir_typed_batched_cp_private_opening_profile(
    seed: &[u8; 32],
    relation: &RelationDescription,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
) -> Option<WhirBatchedCpPrivateOpeningProfile> {
    let context = relation.context.as_ref()?;
    let relation = WhirBatchedCpRelationContext::from_context_bytes(context)?;
    if relation.shape() != &statement.shape
        || relation.public_statement_bytes() != statement.canonical_bytes().len()
    {
        return None;
    }
    let num_vars = typed_batched_cp_oracle_num_vars(relation.shape());

    let equality_pairs = typed_batched_cp_sampled_equalities(seed, &relation, statement, 64);
    let equality_len = typed_batched_cp_equality_opening_points(&equality_pairs, num_vars)?.len();

    let linear_constraints = typed_batched_cp_sampled_folded_public_input_linear_constraints(
        seed, &relation, statement, 8,
    );
    let folded_public_input_len =
        typed_batched_cp_linear_opening_points(&linear_constraints, num_vars)?.len();

    let ring_mul_constraints = typed_batched_cp_sampled_folded_commitment_ring_mul_constraints(
        seed, &relation, statement, 2,
    );
    let folded_commitment_len =
        typed_batched_cp_ring_mul_opening_points(&ring_mul_constraints, num_vars)?.len();

    let eval_ring_mul_constraints = typed_batched_cp_sampled_folded_evaluation_ring_mul_constraints(
        seed, &relation, statement, 2,
    );
    let folded_evaluation_len =
        typed_batched_cp_eval_ring_mul_opening_points(&eval_ring_mul_constraints, num_vars)?.len();

    let poseidon_r1cs_constraints =
        typed_batched_cp_sampled_poseidon_r1cs_constraints(seed, &relation, statement, 8);
    let poseidon_r1cs_len =
        typed_batched_cp_poseidon_r1cs_opening_points(&poseidon_r1cs_constraints, num_vars)?.len();

    let ajtai_constraints =
        typed_batched_cp_sampled_ajtai_opening_constraints(seed, &relation, statement, 2);
    let ajtai_opening_len =
        typed_batched_cp_ajtai_opening_points(&ajtai_constraints, num_vars)?.len();

    let original_r1cs_constraints =
        typed_batched_cp_sampled_original_r1cs_constraints(seed, &relation, statement, 2);
    let original_r1cs_len =
        typed_batched_cp_original_r1cs_opening_points(&original_r1cs_constraints, num_vars)?.len();

    let mut start = 0usize;
    let mut next = |len| {
        let section = WhirBatchedCpPrivateOpeningSection { start, len };
        start += len;
        section
    };
    let equality = next(equality_len);
    let folded_public_input = next(folded_public_input_len);
    let folded_commitment = next(folded_commitment_len);
    let folded_evaluation = next(folded_evaluation_len);
    let poseidon_r1cs = next(poseidon_r1cs_len);
    let ajtai_opening = next(ajtai_opening_len);
    let original_r1cs = next(original_r1cs_len);

    Some(WhirBatchedCpPrivateOpeningProfile {
        equality,
        folded_public_input,
        folded_commitment,
        folded_evaluation,
        poseidon_r1cs,
        ajtai_opening,
        original_r1cs,
        total_len: start,
    })
}

/// Compute the private-opening layout for a SYMBT2C columnar batched CP proof.
///
/// This is a debug/development API only. It mirrors the transcript-derived
/// residual checks used by the SYMBT2C prover/verifier and is not part of the
/// public proof envelope.
pub fn whir_typed_batched_cp_columnar_v2_private_opening_profile(
    seed: &[u8; 32],
    relation: &RelationDescription,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
) -> Option<WhirBatchedCpColumnarV2OpeningProfile> {
    let context = relation.context.as_ref()?;
    let relation_context = WhirBatchedCpRelationContext::from_context_bytes(context)?;
    let relation = relation_context.columnar_v2()?;
    if &relation.semantic.shape != &statement.shape
        || relation.public_statement_bytes() != statement.canonical_bytes().len()
    {
        return None;
    }
    let checks = typed_batched_cp_columnar_v2_checks(seed, relation, statement);
    let mut total_len = 0usize;
    let mut families: Vec<WhirBatchedCpColumnarV2FamilyOpeningProfile> = Vec::new();
    for (residual_index, residual) in relation.columnar_layout.residuals.iter().enumerate() {
        let residual_checks: Vec<_> = checks
            .iter()
            .filter(|check| check.residual_index == residual_index)
            .collect();
        if residual_checks.is_empty() {
            continue;
        }
        let len = residual_checks
            .iter()
            .map(|check| check.columns.len())
            .sum::<usize>();
        if let Some(last) = families.last_mut() {
            if last.family == residual.family && last.section.end() == total_len {
                last.residual_count += 1;
                last.sampled_check_count += residual_checks.len();
                last.section.len += len;
                total_len += len;
                continue;
            }
        }
        families.push(WhirBatchedCpColumnarV2FamilyOpeningProfile {
            family: residual.family,
            residual_count: 1,
            sampled_check_count: residual_checks.len(),
            subproof_index: None,
            num_vars: None,
            padded_row_count: None,
            section: WhirBatchedCpPrivateOpeningSection {
                start: total_len,
                len,
            },
        });
        total_len += len;
    }
    Some(WhirBatchedCpColumnarV2OpeningProfile {
        families,
        total_len,
    })
}

/// Compute the private-opening layout for a SYMBT2F family-local columnar
/// batched CP proof.
///
/// This is a debug/development API only. It mirrors the transcript-derived
/// residual checks used by the SYMBT2F prover/verifier and is not part of the
/// public proof envelope.
pub fn whir_typed_batched_cp_family_columnar_v2_private_opening_profile(
    seed: &[u8; 32],
    relation: &RelationDescription,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
) -> Option<WhirBatchedCpColumnarV2OpeningProfile> {
    let context = relation.context.as_ref()?;
    let relation_context = WhirBatchedCpRelationContext::from_context_bytes(context)?;
    let relation = relation_context.family_columnar_v2()?;
    if &relation.semantic.shape != &statement.shape
        || relation.public_statement_bytes() != statement.canonical_bytes().len()
    {
        return None;
    }
    let checks = typed_batched_cp_family_columnar_v2_checks(seed, relation, statement);
    let mut total_len = 0usize;
    let mut families = Vec::new();
    for (table_idx, table) in relation.family_layout.tables.iter().enumerate() {
        let table_checks: Vec<_> = checks
            .iter()
            .filter(|check| check.residual_index == table_idx)
            .collect();
        if table_checks.is_empty() {
            continue;
        }
        let len = table_checks
            .iter()
            .map(|check| check.columns.len())
            .sum::<usize>();
        families.push(WhirBatchedCpColumnarV2FamilyOpeningProfile {
            family: table.family,
            residual_count: 1,
            sampled_check_count: table_checks.len(),
            subproof_index: Some(families.len()),
            num_vars: Some(
                (table.column_kinds.len() * table.padded_row_count)
                    .next_power_of_two()
                    .max(2)
                    .trailing_zeros() as usize,
            ),
            padded_row_count: Some(table.padded_row_count),
            section: WhirBatchedCpPrivateOpeningSection {
                start: total_len,
                len,
            },
        });
        total_len += len;
    }
    Some(WhirBatchedCpColumnarV2OpeningProfile {
        families,
        total_len,
    })
}

/// Verify a SYMBT2F proof and report verifier-infrastructure cache use.
///
/// This is a development/profile API only. Product public verification does
/// not consume SYMBT2F and must not depend on these stats.
pub fn whir_typed_batched_cp_family_columnar_v2_verify_with_cache_stats(
    vk: &WhirVerifyingKey,
    statement: &crate::batched_cp::BatchedCpPublicStatement,
    proof: &WhirProof,
) -> Option<(bool, WhirVerifierInfraCacheStats)> {
    let context = vk.relation.context.as_ref()?;
    let relation_context = WhirBatchedCpRelationContext::from_context_bytes(context)?;
    let relation = relation_context.family_columnar_v2()?;
    if &relation.semantic.shape != &statement.shape
        || relation.public_statement_bytes() != statement.canonical_bytes().len()
    {
        return Some((false, WhirVerifierInfraCacheStats::default()));
    }
    Some(verify_typed_batched_cp_family_columnar_v2_with_stats(
        vk, relation, statement, proof,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhirProofPayloadError {
    BadMagic,
    UnsupportedVersion(u16),
    Truncated,
    TrailingBytes,
    InvalidProofKind(u8),
    LengthOverflow,
    NonCanonicalBabyBear(u32),
    MalformedPcsProof,
}

/// Canonical WHIR backend proof payload bytes for the public proof envelope.
///
/// This is a backend-owned codec for the opaque `cp_proof_bytes` and
/// `output_proof_bytes` fields in the versioned public proof envelope. The
/// Symphony envelope owns proof ordering and length delimiting; WHIR owns the
/// bytes for an individual WHIR proof payload.
#[must_use]
pub fn canonical_whir_proof_bytes(proof: &WhirProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(WHIR_PROOF_PAYLOAD_MAGIC);
    out.extend_from_slice(&WHIR_PROOF_PAYLOAD_VERSION.to_le_bytes());
    out.push(u8::from(proof.is_output));
    out.extend_from_slice(&(proof.num_vars as u64).to_le_bytes());

    write_bb_array3_vec(&mut out, &proof.sumcheck_rounds_3);
    write_bb_array4_vec(&mut out, &proof.sumcheck_rounds_4);
    for value in &proof.evaluations {
        write_bb(&mut out, *value);
    }
    write_bb(&mut out, proof.z_eval);

    out.extend_from_slice(&(proof.linear_checks.len() as u64).to_le_bytes());
    for check in &proof.linear_checks {
        write_bb_array3_vec(&mut out, &check.rounds);
        write_bb(&mut out, check.z_eval);
    }
    out.extend_from_slice(&(proof.private_opening_evals.len() as u64).to_le_bytes());
    for value in &proof.private_opening_evals {
        write_bb(&mut out, *value);
    }

    out.extend_from_slice(&(proof.family_columnar_subproofs.len() as u64).to_le_bytes());
    for subproof in &proof.family_columnar_subproofs {
        out.extend_from_slice(&(subproof.table_index as u64).to_le_bytes());
        out.extend_from_slice(&(subproof.num_vars as u64).to_le_bytes());
        write_bb(&mut out, subproof.z_eval);
        let pcs_bytes =
            serde_json::to_vec(&subproof.whir_pcs_proof).expect("WHIR PCS proof must serialize");
        out.extend_from_slice(&(pcs_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&pcs_bytes);
    }

    let pcs_bytes =
        serde_json::to_vec(&proof.whir_pcs_proof).expect("WHIR PCS proof must serialize");
    out.extend_from_slice(&(pcs_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&pcs_bytes);
    out
}

pub fn whir_proof_from_canonical_bytes(bytes: &[u8]) -> Result<WhirProof, WhirProofPayloadError> {
    let mut reader = WhirProofPayloadReader::new(bytes);
    if reader.read_exact(WHIR_PROOF_PAYLOAD_MAGIC.len())? != WHIR_PROOF_PAYLOAD_MAGIC {
        return Err(WhirProofPayloadError::BadMagic);
    }

    let version = reader.read_u16()?;
    if version != WHIR_PROOF_PAYLOAD_VERSION {
        return Err(WhirProofPayloadError::UnsupportedVersion(version));
    }

    let is_output = match reader.read_u8()? {
        0 => false,
        1 => true,
        other => return Err(WhirProofPayloadError::InvalidProofKind(other)),
    };
    let num_vars = reader.read_len()?;
    let sumcheck_rounds_3 = reader.read_bb_array3_vec()?;
    let sumcheck_rounds_4 = reader.read_bb_array4_vec()?;
    let evaluations = [reader.read_bb()?, reader.read_bb()?, reader.read_bb()?];
    let z_eval = reader.read_bb()?;

    let linear_check_count = reader.read_len()?;
    let mut linear_checks = Vec::with_capacity(linear_check_count);
    for _ in 0..linear_check_count {
        linear_checks.push(WhirLinearCheckProof {
            rounds: reader.read_bb_array3_vec()?,
            z_eval: reader.read_bb()?,
        });
    }
    let private_opening_eval_count = reader.read_len()?;
    let mut private_opening_evals = Vec::with_capacity(private_opening_eval_count);
    for _ in 0..private_opening_eval_count {
        private_opening_evals.push(reader.read_bb()?);
    }

    let family_subproof_count = reader.read_len()?;
    let mut family_columnar_subproofs = Vec::with_capacity(family_subproof_count);
    for _ in 0..family_subproof_count {
        let table_index = reader.read_len()?;
        let num_vars = reader.read_len()?;
        let z_eval = reader.read_bb()?;
        let pcs_bytes = reader.read_bytes()?;
        let whir_pcs_proof = serde_json::from_slice(pcs_bytes)
            .map_err(|_| WhirProofPayloadError::MalformedPcsProof)?;
        family_columnar_subproofs.push(WhirFamilyColumnarSubproof {
            table_index,
            num_vars,
            z_eval,
            whir_pcs_proof,
        });
    }

    let pcs_bytes = reader.read_bytes()?;
    let whir_pcs_proof =
        serde_json::from_slice(pcs_bytes).map_err(|_| WhirProofPayloadError::MalformedPcsProof)?;
    if !reader.is_finished() {
        return Err(WhirProofPayloadError::TrailingBytes);
    }

    Ok(WhirProof {
        sumcheck_rounds_3,
        sumcheck_rounds_4,
        evaluations,
        whir_pcs_proof,
        z_eval,
        linear_checks,
        private_opening_evals,
        family_columnar_subproofs,
        num_vars,
        is_output,
    })
}

fn write_bb(out: &mut Vec<u8>, value: BabyBear) {
    out.extend_from_slice(&value.as_canonical_u32().to_le_bytes());
}

fn write_bb_array3_vec(out: &mut Vec<u8>, values: &[[BabyBear; 3]]) {
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for round in values {
        for value in round {
            write_bb(out, *value);
        }
    }
}

fn write_bb_array4_vec(out: &mut Vec<u8>, values: &[[BabyBear; 4]]) {
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for round in values {
        for value in round {
            write_bb(out, *value);
        }
    }
}

struct WhirProofPayloadReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WhirProofPayloadReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_finished(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], WhirProofPayloadError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(WhirProofPayloadError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(WhirProofPayloadError::Truncated);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, WhirProofPayloadError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, WhirProofPayloadError> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.read_exact(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn read_u32(&mut self) -> Result<u32, WhirProofPayloadError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn read_u64(&mut self) -> Result<u64, WhirProofPayloadError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn read_len(&mut self) -> Result<usize, WhirProofPayloadError> {
        usize::try_from(self.read_u64()?).map_err(|_| WhirProofPayloadError::LengthOverflow)
    }

    fn read_bb(&mut self) -> Result<BabyBear, WhirProofPayloadError> {
        const BABYBEAR_MODULUS: u32 = 2_013_265_921;
        let value = self.read_u32()?;
        if value >= BABYBEAR_MODULUS {
            return Err(WhirProofPayloadError::NonCanonicalBabyBear(value));
        }
        Ok(BabyBear::from_u32(value))
    }

    fn read_bb_array3_vec(&mut self) -> Result<Vec<[BabyBear; 3]>, WhirProofPayloadError> {
        let len = self.read_len()?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push([self.read_bb()?, self.read_bb()?, self.read_bb()?]);
        }
        Ok(values)
    }

    fn read_bb_array4_vec(&mut self) -> Result<Vec<[BabyBear; 4]>, WhirProofPayloadError> {
        let len = self.read_len()?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push([
                self.read_bb()?,
                self.read_bb()?,
                self.read_bb()?,
                self.read_bb()?,
            ]);
        }
        Ok(values)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], WhirProofPayloadError> {
        let len = self.read_len()?;
        self.read_exact(len)
    }
}

include!("symbt3_columns.rs");
include!("backend_impl.rs");
include!("symbt3_verify.rs");
include!("output.rs");
include!("batched_cp_context.rs");
include!("batched_cp_columnar.rs");
include!("core_protocol.rs");
#[cfg(test)]
include!("tests.rs");
