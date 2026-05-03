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
pub const WHIR_PROOF_PAYLOAD_VERSION: u16 = 1;
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
    /// Number of sumcheck variables.
    pub num_vars: usize,
    /// Whether this is an output SNARK proof (true) or CP proof (false).
    pub is_output: bool,
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

fn eval_eq_index_bb(point: &[BabyBear], index: usize) -> BabyBear {
    point
        .iter()
        .enumerate()
        .fold(BabyBear::ONE, |acc, (bit, &r)| {
            let shift = point.len() - 1 - bit;
            if ((index >> shift) & 1) == 1 {
                acc * r
            } else {
                acc * (BabyBear::ONE - r)
            }
        })
}

fn compute_matrix_mle_row_bb(
    mat: &FlatSparseMatrixBB,
    row_point: &[BabyBear],
    num_cols: usize,
) -> Vec<BabyBear> {
    let mut result = vec![BabyBear::ZERO; num_cols];
    let num_rows = 1usize << row_point.len();
    for &(row, col, val) in &mat.entries {
        if row < num_rows && col < num_cols {
            result[col] += eval_eq_index_bb(row_point, row) * val;
        }
    }
    result
}

fn eval_matrix_mle_at_points_bb(
    mat: &FlatSparseMatrixBB,
    row_point: &[BabyBear],
    col_point: &[BabyBear],
    num_cols: usize,
) -> BabyBear {
    let num_rows = 1usize << row_point.len();
    mat.entries
        .iter()
        .filter(|&&(row, col, _)| row < num_rows && col < num_cols)
        .fold(BabyBear::ZERO, |acc, &(row, col, val)| {
            acc + val * eval_eq_index_bb(row_point, row) * eval_eq_index_bb(col_point, col)
        })
}

fn pad_point(point: &[BabyBear], len: usize) -> Vec<BabyBear> {
    point
        .iter()
        .copied()
        .chain(std::iter::repeat(BabyBear::ZERO))
        .take(len)
        .collect()
}

fn sumcheck_point_to_mle_point(point: &[BabyBear], len: usize) -> Vec<BabyBear> {
    let mut padded = pad_point(point, len);
    padded.reverse();
    padded
}

fn boolean_point_for_index(index: usize, len: usize) -> Vec<BabyBear> {
    (0..len)
        .map(|bit| {
            if ((index >> bit) & 1) == 1 {
                BabyBear::ONE
            } else {
                BabyBear::ZERO
            }
        })
        .collect()
}

fn prove_output(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    prove_output_with_transcript_instance(pk, instance, instance, witness, ctx)
}

fn prove_output_with_transcript_instance(
    pk: &WhirProvingKey,
    r1cs_instance: &[u8],
    transcript_instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    let d = ctx.d;
    let q = ctx.q;

    // Parse instance and witness bytes into BabyBear elements
    // Parse only the CP-R1CS public prefix from `instance`.
    // Any trailer bytes are transcript-binding metadata and must not shift the
    // R1CS witness layout.
    let mut instance_bb = bytes_to_babybear_direct(r1cs_instance);
    let expected_instance_len = ctx.r1cs.num_public * d;
    instance_bb.resize(expected_instance_len, BabyBear::ZERO);
    let witness_bb = bytes_to_babybear_direct(witness);

    // Build z_flat = (instance, witness), padded to total_vars * d
    let total_vars = ctx.r1cs.num_variables * d;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_bb);
    z_flat.extend_from_slice(&witness_bb);
    z_flat.resize(total_vars, BabyBear::ZERO);

    // Flatten R1CS
    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        d,
        q,
    );
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    // Compute Az, Bz, Cz
    let (az, bz, cz) =
        compute_matrix_vector_products_bb(&flat_a, &flat_b, &flat_c, &z_flat, num_vars);

    // Pad z_flat to power of two for WHIR polynomial (at least 2 elements)
    let z_padded_len = (1 << ceil_log2(z_flat.len().max(1))).max(2);
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);
    let z_num_vars = z_padded.len().trailing_zeros() as usize;

    // Build transcript for Spartan sumcheck challenge derivation
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v2");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(transcript_instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(transcript_instance);

    // Derive tau for the sumcheck
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    // Build eq(tau, x) table
    let eq_table = build_eq_table_bb(&tau, num_vars);

    // Sumcheck for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)]
    let (rounds, challenges, az_eval, bz_eval, cz_eval, _eq_final) =
        prove_sumcheck_r1cs(&eq_table, &az, &bz, &cz, num_vars, &mut transcript);

    let mut opening_points = Vec::new();
    let main_point = sumcheck_point_to_mle_point(&challenges, z_num_vars);
    let z_eval = mle_eval_bb(&z_padded, &main_point);
    opening_points.push(main_point);

    let (linear_checks, linear_points) = prove_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &z_padded,
        z_num_vars,
        &mut transcript,
    );
    opening_points.extend(linear_points);
    for idx in 0..expected_instance_len {
        opening_points.push(boolean_point_for_index(idx, z_num_vars));
    }

    let (whir_pcs_proof, opening_evals) =
        whir_commit_and_prove_multi(&pk.seed, z_num_vars, &z_padded, &opening_points);
    assert_eq!(opening_evals.first().copied(), Some(z_eval));
    let public_eval_offset = 1 + linear_checks.len();
    for (idx, expected) in instance_bb.iter().copied().enumerate() {
        assert_eq!(
            opening_evals.get(public_eval_offset + idx).copied(),
            Some(expected)
        );
    }

    WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: rounds,
        evaluations: [az_eval, bz_eval, cz_eval],
        whir_pcs_proof,
        z_eval,
        linear_checks,
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
    verify_output_with_transcript_instance(vk, instance, instance, proof, ctx)
}

fn typed_output_binding_context(ctx: &WhirContext) -> WhirContext {
    let mut r1cs = R1CSMatrices::new(1, 1, 1);
    r1cs.a.insert(0, 0, 0);
    WhirContext {
        r1cs,
        q: ctx.q,
        d: 1,
        n_pub: 1,
        is_output_snark: true,
        is_cp_snark: false,
        typed_cp: None,
    }
}

fn typed_output_binding_instance() -> [u8; 8] {
    1i64.to_le_bytes()
}

fn verify_output_with_transcript_instance(
    vk: &WhirVerifyingKey,
    r1cs_instance: &[u8],
    transcript_instance: &[u8],
    proof: &WhirProof,
    ctx: &WhirContext,
) -> bool {
    if !proof.is_output {
        return false;
    }

    let d = ctx.d;
    let mut instance_bb = bytes_to_babybear_direct(r1cs_instance);
    let expected_instance_len = ctx.r1cs.num_public * d;
    instance_bb.resize(expected_instance_len, BabyBear::ZERO);

    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    if proof.num_vars != num_vars {
        return false;
    }

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-output-v2");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(transcript_instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(transcript_instance);

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
    // Recompute eq(tau, r*) by folding the same eq table convention used by prover.
    let mut eq_fold = build_eq_table_bb(&tau, num_vars);
    for &r in &challenges {
        let half = eq_fold.len() / 2;
        let one_minus_r = BabyBear::ONE - r;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(eq_fold[j] * one_minus_r + eq_fold[half + j] * r);
        }
        eq_fold = next;
    }
    let eq_at_r = eq_fold[0];
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify WHIR PCS opening for z polynomial
    let total_vars = ctx.r1cs.num_variables * d;
    let z_padded_len = (1usize << ceil_log2(total_vars.max(1))).max(2);
    let z_num_vars = z_padded_len.trailing_zeros() as usize;

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        d,
        ctx.q,
    );

    let mut opening_points = vec![sumcheck_point_to_mle_point(&challenges, z_num_vars)];
    let mut opening_evals = vec![proof.z_eval];
    if !verify_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &proof.evaluations,
        total_vars,
        z_num_vars,
        &proof.linear_checks,
        &mut transcript,
        &mut opening_points,
        &mut opening_evals,
    ) {
        return false;
    }
    for (idx, expected) in instance_bb.iter().copied().enumerate() {
        opening_points.push(boolean_point_for_index(idx, z_num_vars));
        opening_evals.push(expected);
    }

    whir_verify_opening_multi(
        &vk.seed,
        z_num_vars,
        &proof.whir_pcs_proof,
        &opening_points,
        &opening_evals,
    )
}

// ---------------------------------------------------------------------------
// CP-SNARK R1CS path: folding constraints via R1CS sumcheck over BabyBear
// ---------------------------------------------------------------------------
// Reuses the same R1CS-over-BabyBear sumcheck as the output path, but with
// CP-specific R1CS matrices (folding linear combination constraints).

fn parse_i64_chunks_to_babybear(bytes: &[u8]) -> Vec<BabyBear> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(8));
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let v = i64::from_le_bytes(bytes[i..i + 8].try_into().expect("8-byte chunk"));
        out.push(BabyBear::from_i64(v));
        i += 8;
    }
    if i < bytes.len() {
        let mut buf = [0u8; 8];
        buf[..bytes.len() - i].copy_from_slice(&bytes[i..]);
        let v = i64::from_le_bytes(buf);
        out.push(BabyBear::from_i64(v));
    }
    out
}

fn prove_cp_r1cs(
    pk: &WhirProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &WhirContext,
) -> WhirProof {
    // Identical to prove_output but with a different transcript domain separator
    // and is_output = false on the proof.
    //
    // IMPORTANT: CP-R1CS context is already scalarized over BabyBear.
    // Do NOT multiply dimensions by ring degree `d` again.
    let q = ctx.q;

    // Parse only CP-R1CS public prefix from `instance`; ignore trailer bytes.
    let mut instance_bb = parse_i64_chunks_to_babybear(instance);
    let expected_instance_len = ctx.r1cs.num_public;
    instance_bb.resize(expected_instance_len, BabyBear::ZERO);
    let witness_bb = parse_i64_chunks_to_babybear(witness);

    let total_vars = ctx.r1cs.num_variables;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_bb);
    z_flat.extend_from_slice(&witness_bb);
    z_flat.resize(total_vars, BabyBear::ZERO);

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        1,
        q,
    );
    let num_constraints = ctx.r1cs.num_constraints;
    let num_vars = ceil_log2(num_constraints.max(1));

    let (az, bz, cz) =
        compute_matrix_vector_products_bb(&flat_a, &flat_b, &flat_c, &z_flat, num_vars);
    let z_padded_len = (1 << ceil_log2(z_flat.len().max(1))).max(2);
    let mut z_padded = z_flat;
    z_padded.resize(z_padded_len, BabyBear::ZERO);
    let z_num_vars = z_padded.len().trailing_zeros() as usize;

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-r1cs-v1");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges, az_eval, bz_eval, cz_eval, _eq_final) =
        prove_sumcheck_r1cs(&eq_table, &az, &bz, &cz, num_vars, &mut transcript);

    let mut opening_points = Vec::new();
    let main_point = sumcheck_point_to_mle_point(&challenges, z_num_vars);
    let z_eval = mle_eval_bb(&z_padded, &main_point);
    opening_points.push(main_point);

    let (linear_checks, linear_points) = prove_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &z_padded,
        z_num_vars,
        &mut transcript,
    );
    opening_points.extend(linear_points);

    let (whir_pcs_proof, opening_evals) =
        whir_commit_and_prove_multi(&pk.seed, z_num_vars, &z_padded, &opening_points);
    assert_eq!(opening_evals.first().copied(), Some(z_eval));

    WhirProof {
        sumcheck_rounds_3: Vec::new(),
        sumcheck_rounds_4: rounds,
        evaluations: [az_eval, bz_eval, cz_eval],
        whir_pcs_proof,
        z_eval,
        linear_checks,
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

    // CP-R1CS is already scalarized over BabyBear.
    let expected_num_vars = ceil_log2(ctx.r1cs.num_constraints.max(1));
    if proof.num_vars != expected_num_vars {
        return false;
    }

    let num_vars = proof.num_vars;
    if num_vars > 0 && proof.sumcheck_rounds_4.len() != num_vars {
        return false;
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-r1cs-v1");
    transcript.extend_from_slice(&vk.seed);
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
    // Recompute eq(tau, r*) by folding the same eq table convention used by prover.
    let mut eq_fold = build_eq_table_bb(&tau, num_vars);
    for &r in &challenges {
        let half = eq_fold.len() / 2;
        let one_minus_r = BabyBear::ONE - r;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(eq_fold[j] * one_minus_r + eq_fold[half + j] * r);
        }
        eq_fold = next;
    }
    let eq_at_r = eq_fold[0];
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify WHIR PCS opening.
    // CP witness polynomial length is based on scalar CP-R1CS variable count.
    let total_vars = ctx.r1cs.num_variables;
    let z_padded_len = (1usize << ceil_log2(total_vars.max(1))).max(2);
    let z_num_vars = z_padded_len.trailing_zeros() as usize;

    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs_bb(
        &ctx.r1cs.a,
        &ctx.r1cs.b,
        &ctx.r1cs.c,
        ctx.r1cs.num_constraints,
        ctx.r1cs.num_variables,
        1,
        ctx.q,
    );

    let mut opening_points = vec![sumcheck_point_to_mle_point(&challenges, z_num_vars)];
    let mut opening_evals = vec![proof.z_eval];
    if !verify_linear_bindings(
        [&flat_a, &flat_b, &flat_c],
        &challenges,
        &proof.evaluations,
        total_vars,
        z_num_vars,
        &proof.linear_checks,
        &mut transcript,
        &mut opening_points,
        &mut opening_evals,
    ) {
        return false;
    }
    whir_verify_opening_multi(
        &vk.seed,
        z_num_vars,
        &proof.whir_pcs_proof,
        &opening_points,
        &opening_evals,
    )
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
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    let (rounds, challenges) = prove_sumcheck_product(&eq_table, &table, num_vars, &mut transcript);

    let w_eval = mle_eval_bb(&table, &challenges);

    // --- WHIR PCS: commit to witness polynomial and prove evaluation ---
    let whir_pcs_proof = whir_commit_and_prove(&pk.seed, num_vars, &table, &challenges, w_eval);

    WhirProof {
        sumcheck_rounds_3: rounds,
        sumcheck_rounds_4: Vec::new(),
        evaluations: [w_eval, BabyBear::ZERO, BabyBear::ZERO],
        whir_pcs_proof,
        z_eval: w_eval,
        linear_checks: Vec::new(),
        num_vars,
        is_output: false,
    }
}

fn verify_cp(vk: &WhirVerifyingKey, instance: &[u8], proof: &WhirProof) -> bool {
    if proof.is_output {
        return false;
    }
    if !proof.linear_checks.is_empty() {
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
        return false;
    }

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v2");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);

    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let challenges =
        match verify_sumcheck_product(&proof.sumcheck_rounds_3, num_vars, &mut transcript) {
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
        &vk.seed,
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

fn prove_linear_bindings(
    matrices: [&FlatSparseMatrixBB; 3],
    row_point: &[BabyBear],
    z_table: &[BabyBear],
    z_num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<WhirLinearCheckProof>, Vec<Vec<BabyBear>>) {
    let mut proofs = Vec::with_capacity(3);
    let mut opening_points = Vec::with_capacity(3);
    let num_cols = z_table.len();

    for (i, mat) in matrices.iter().enumerate() {
        transcript.extend_from_slice(b"whir-linear-binding-v1");
        transcript.push(i as u8);
        let row = compute_matrix_mle_row_bb(mat, row_point, num_cols);
        let (rounds, point, z_eval) =
            prove_sumcheck_inner_product(&row, z_table, z_num_vars, transcript);
        proofs.push(WhirLinearCheckProof { rounds, z_eval });
        opening_points.push(sumcheck_point_to_mle_point(&point, z_num_vars));
    }

    (proofs, opening_points)
}

#[allow(clippy::too_many_arguments)]
fn verify_linear_bindings(
    matrices: [&FlatSparseMatrixBB; 3],
    row_point: &[BabyBear],
    claimed_evals: &[BabyBear; 3],
    num_cols: usize,
    z_num_vars: usize,
    proofs: &[WhirLinearCheckProof],
    transcript: &mut Vec<u8>,
    opening_points: &mut Vec<Vec<BabyBear>>,
    opening_evals: &mut Vec<BabyBear>,
) -> bool {
    if proofs.len() != 3 {
        return false;
    }

    for (i, (mat, proof)) in matrices.iter().zip(proofs.iter()).enumerate() {
        transcript.extend_from_slice(b"whir-linear-binding-v1");
        transcript.push(i as u8);
        let (final_eval, point) = match verify_sumcheck_inner_product(
            &proof.rounds,
            claimed_evals[i],
            z_num_vars,
            transcript,
        ) {
            Some(v) => v,
            None => return false,
        };
        let row_eval = eval_matrix_mle_at_points_bb(mat, row_point, &point, num_cols);
        if final_eval != row_eval * proof.z_eval {
            return false;
        }
        opening_points.push(sumcheck_point_to_mle_point(&point, z_num_vars));
        opening_evals.push(proof.z_eval);
    }

    true
}

/// Commit to a multilinear polynomial and prove evaluation claims using WHIR.
fn whir_commit_and_prove_multi(
    seed: &[u8; 32],
    num_variables: usize,
    evaluations: &[BabyBear],
    points: &[Vec<BabyBear>],
) -> (WhirPcsProof<F, EF, WhirMmcs>, Vec<BabyBear>) {
    assert_eq!(evaluations.len(), 1 << num_variables);
    for point in points {
        assert_eq!(point.len(), num_variables);
    }

    let infra = build_whir_infra(seed, num_variables);
    let dft = Radix2DFTSmallBatch::<F>::default();

    // Build the polynomial in evaluation form
    let poly = EvaluationsList::new(evaluations.to_vec());

    // Create the initial statement
    let mut statement = infra
        .params
        .initial_statement(poly, SumcheckStrategy::Classic);

    // Add evaluation constraints. WHIR computes the evaluations internally for
    // the prover; verification receives the returned claimed values explicitly.
    // NOTE: Plonky3 multilinear convention has point[0] as the *slowest* variable
    // (controls the top-half split), while our mle_eval_bb has point[0] as the
    // *fastest* variable. Reverse the point to match conventions.
    let mut claimed_evals = Vec::with_capacity(points.len());
    for point in points {
        let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
        let ml_point = MultilinearPoint::new(ef_point);
        let _whir_eval = statement.evaluate(&ml_point);
        claimed_evals.push(mle_eval_bb(evaluations, point));
    }

    // Normalize for verifier
    let _verifier_statement = statement.normalize();

    // Create prover challenger
    let mut prover_challenger = make_challenger(&infra.perm);
    infra
        .domainsep
        .observe_domain_separator(&mut prover_challenger);

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
        .prove(
            &dft,
            &mut proof,
            &mut prover_challenger,
            &statement,
            prover_data,
        )
        .expect("WHIR prove failed");

    (proof, claimed_evals)
}

/// Verify a WHIR PCS opening proof with one or more evaluation constraints.
fn whir_verify_opening_multi(
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

    let infra = build_whir_infra(seed, num_variables);

    // Create verifier challenger (must match prover's)
    let mut verifier_challenger = make_challenger(&infra.perm);
    infra
        .domainsep
        .observe_domain_separator(&mut verifier_challenger);

    // Parse commitment
    let commitment_reader = CommitmentReader::new(&infra.params);
    let parsed_commitment =
        commitment_reader.parse_commitment::<F, DIGEST_ELEMS>(proof, &mut verifier_challenger);

    // Build verifier statement: the verifier must know each claimed (point,
    // evaluation) pair.
    // Reverse point to match Plonky3 convention (point[0] = slowest variable).
    use whir_p3::constraints::statement::EqStatement;
    let mut verifier_statement = EqStatement::initialize(num_variables);
    for (point, &claimed_eval) in points.iter().zip(claimed_evals.iter()) {
        let ef_point: Vec<EF> = point.iter().rev().map(|&x| EF::from(x)).collect();
        let ml_point = MultilinearPoint::new(ef_point);
        verifier_statement.add_evaluated_constraint(ml_point, EF::from(claimed_eval));
    }

    let verifier = WhirVerifier::new(&infra.params);
    verifier
        .verify(
            proof,
            &mut verifier_challenger,
            &parsed_commitment,
            verifier_statement,
        )
        .is_ok()
}

fn whir_commit_and_prove(
    seed: &[u8; 32],
    num_variables: usize,
    evaluations: &[BabyBear],
    point: &[BabyBear],
    claimed_eval: BabyBear,
) -> WhirPcsProof<F, EF, WhirMmcs> {
    let points = vec![point.to_vec()];
    let (proof, evals) = whir_commit_and_prove_multi(seed, num_variables, evaluations, &points);
    assert_eq!(evals, vec![claimed_eval]);
    proof
}

fn whir_verify_opening(
    seed: &[u8; 32],
    num_variables: usize,
    proof: &WhirPcsProof<F, EF, WhirMmcs>,
    point: &[BabyBear],
    claimed_eval: BabyBear,
) -> bool {
    whir_verify_opening_multi(
        seed,
        num_variables,
        proof,
        &[point.to_vec()],
        &[claimed_eval],
    )
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
) -> (
    Vec<[BabyBear; 4]>,
    Vec<BabyBear>,
    BabyBear,
    BabyBear,
    BabyBear,
    BabyBear,
) {
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

    let final_az = az[0];
    let final_bz = bz[0];
    let final_cz = cz[0];
    let final_eq = eq[0];

    (rounds, challenges, final_az, final_bz, final_cz, final_eq)
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

fn prove_sumcheck_inner_product(
    a_table: &[BabyBear],
    b_table: &[BabyBear],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (Vec<[BabyBear; 3]>, Vec<BabyBear>, BabyBear) {
    let n = 1 << num_vars;
    assert_eq!(a_table.len(), n);
    assert_eq!(b_table.len(), n);

    let mut a = a_table.to_vec();
    let mut b = b_table.to_vec();
    let mut rounds = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = a.len() / 2;
        let mut evals = [BabyBear::ZERO; 3];

        for j in 0..half {
            let a0 = a[j];
            let a1 = a[half + j];
            let b0 = b[j];
            let b1 = b[half + j];
            for t in 0u32..3 {
                let t_bb = BabyBear::from_u32(t);
                let one_minus_t = BabyBear::ONE - t_bb;
                let a_t = a0 * one_minus_t + a1 * t_bb;
                let b_t = b0 * one_minus_t + b1 * t_bb;
                evals[t as usize] += a_t * b_t;
            }
        }

        rounds.push(evals);
        for e in &evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }
        let r = derive_challenge(transcript, round, b"sc-inner");
        challenges.push(r);

        let one_minus_r = BabyBear::ONE - r;
        let mut new_a = Vec::with_capacity(half);
        let mut new_b = Vec::with_capacity(half);
        for j in 0..half {
            new_a.push(a[j] * one_minus_r + a[half + j] * r);
            new_b.push(b[j] * one_minus_r + b[half + j] * r);
        }
        a = new_a;
        b = new_b;
    }

    (rounds, challenges, b[0])
}

fn verify_sumcheck_inner_product(
    rounds: &[[BabyBear; 3]],
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
        let r = derive_challenge(transcript, round, b"sc-inner");
        challenges.push(r);
        current_claim = eval_univariate_3(evals, r);
    }

    Some((current_claim, challenges))
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
                table[j] *= BabyBear::ONE - ti;
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
    a.iter()
        .zip(b.iter().rev())
        .fold(BabyBear::ONE, |acc, (ai, bi)| {
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

fn validate_typed_output_public_instance(
    instance: &FoldedOutputInstance,
    ctx: &WhirContext,
) -> bool {
    if instance.linear_relation.commitment != instance.folded_instance.commitment {
        return false;
    }
    if instance.linear_relation.evaluation_values.to_vec()
        != instance.folded_instance.evaluation_values
    {
        return false;
    }
    if instance.folded_instance.public_input.len() != ctx.r1cs.num_public {
        return false;
    }
    if instance.batched_relation.commitments.len()
        != instance.batched_relation.evaluation_values.len()
    {
        return false;
    }

    true
}

fn validate_typed_output_relation(
    instance: &FoldedOutputInstance,
    witness: &FoldedOutputWitness,
    ctx: &WhirContext,
) -> bool {
    if !validate_typed_output_public_instance(instance, ctx) {
        return false;
    }
    let expected_witness_len = ctx.r1cs.num_variables.saturating_sub(ctx.r1cs.num_public);
    if witness.folded_witness.witness.len() != expected_witness_len {
        return false;
    }
    if instance.batched_relation.commitments.len() != witness.folded_witness.monomial_vectors.len()
        || instance.batched_relation.evaluation_values.len()
            != witness.folded_witness.monomial_vectors.len()
    {
        return false;
    }

    let ext_ctx = ExtFieldContext::new(ctx.q);
    let expected_linear = compute_hadamard_output_evaluations(
        &instance.folded_instance.public_input,
        &witness.folded_witness.witness.elements,
        &instance.linear_relation.evaluation_point,
        ctx,
        &ext_ctx,
    );
    if expected_linear != instance.linear_relation.evaluation_values {
        return false;
    }

    let expected_batched = compute_monomial_output_evaluations(
        &witness.folded_witness.monomial_vectors,
        &instance.batched_relation.evaluation_point,
        ctx,
        &ext_ctx,
    );
    expected_batched == instance.batched_relation.evaluation_values
}

fn compute_hadamard_output_evaluations(
    public_input: &[RingElement],
    witness: &[RingElement],
    point: &[ExtFieldElement],
    ctx: &WhirContext,
    ext_ctx: &ExtFieldContext,
) -> [TensorElement; 3] {
    let mut assignment = Vec::with_capacity(public_input.len() + witness.len());
    assignment.extend_from_slice(public_input);
    assignment.extend_from_slice(witness);

    let table_size = 1usize << ceil_log2(ctx.r1cs.num_constraints.max(1));
    let mut evaluations = [
        TensorElement::zero(),
        TensorElement::zero(),
        TensorElement::zero(),
    ];

    for j in 0..ctx.d.min(D) {
        let col: Vec<i64> = assignment.iter().map(|elem| elem.coeffs[j]).collect();
        let mut rows = [
            ctx.r1cs.a.mul_vec_mod(&col, ctx.q),
            ctx.r1cs.b.mul_vec_mod(&col, ctx.q),
            ctx.r1cs.c.mul_vec_mod(&col, ctx.q),
        ];
        for row in &mut rows {
            row.resize(table_size, 0);
        }
        for (i, row) in rows.iter().enumerate() {
            let val = mle_eval_ext_i64(row, point, ext_ctx);
            evaluations[i].data[0][j] = val.c0;
            evaluations[i].data[1][j] = val.c1;
        }
    }

    evaluations
}

fn compute_monomial_output_evaluations(
    monomial_vectors: &[crate::ring::RingVector],
    point: &[ExtFieldElement],
    ctx: &WhirContext,
    ext_ctx: &ExtFieldContext,
) -> Vec<TensorElement> {
    monomial_vectors
        .iter()
        .map(|vector| {
            let table_size = 1usize << ceil_log2(vector.len().max(1));
            let mut evaluation = TensorElement::zero();
            for j in 0..ctx.d.min(D) {
                let mut table: Vec<i64> =
                    vector.elements.iter().map(|elem| elem.coeffs[j]).collect();
                table.resize(table_size, 0);
                let val = mle_eval_ext_i64(&table, point, ext_ctx);
                evaluation.data[0][j] = val.c0;
                evaluation.data[1][j] = val.c1;
            }
            evaluation
        })
        .collect()
}

fn mle_eval_ext_i64(
    table: &[i64],
    point: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> ExtFieldElement {
    if table.is_empty() {
        return ctx.zero();
    }

    let mut current: Vec<ExtFieldElement> = table
        .iter()
        .map(|&v| ExtFieldElement { c0: v, c1: 0 })
        .collect();
    for r in point.iter().take(ceil_log2(table.len().max(1))) {
        if current.len() == 1 {
            break;
        }
        let half = current.len() / 2;
        let one_minus_r = ctx.sub(&ctx.one(), r);
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            next.push(ctx.add(
                &ctx.mul(&one_minus_r, &current[i]),
                &ctx.mul(r, &current[half + i]),
            ));
        }
        current = next;
    }
    current.first().copied().unwrap_or_else(|| ctx.zero())
}

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
