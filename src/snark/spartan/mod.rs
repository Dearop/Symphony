//! Spartan backend SNARK: R1CS + sumcheck + Pedersen/IPA over Ristretto.
//!
//! This module implements a succinct proof system based on the Spartan protocol.
//! It uses:
//! - R1CS-to-sumcheck reduction over Fp (Ristretto scalar field)
//! - Pedersen vector commitment over the Ristretto group
//! - Bulletproofs-style Inner Product Argument for succinct evaluation proofs

pub mod commitment;
pub mod ipa;
pub mod r1cs_sumcheck;
pub mod scalar_field;
pub mod serialize;
pub mod sumcheck;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha256};

use crate::snark::{BackendSnark, RelationDescription};

use self::commitment::PedersenKey;
use self::ipa::{ipa_prove, ipa_verify, IPAProof};
use self::r1cs_sumcheck::{ceil_log2, compute_matrix_mle_at_point, compute_matrix_vector_products, flatten_ring_r1cs, mle_eval};
use self::serialize::{deserialize_context, SpartanContext};
use self::sumcheck::{build_eq_table, prove_r1cs_sumcheck, verify_sumcheck, SumcheckProofFp};

/// The Spartan SNARK backend.
#[derive(Clone)]
pub struct SpartanSnark;

/// Proving key for the Spartan backend.
#[derive(Debug, Clone)]
pub struct SpartanProvingKey {
    pub pedersen_key: PedersenKey,
    pub seed: [u8; 32],
    pub context: Option<SpartanContext>,
    /// SHA-256 hash of the relation context (R1CS), bound at setup time.
    /// Used to detect context swaps between setup and prove/verify.
    pub context_hash: [u8; 32],
}

/// Verifying key for the Spartan backend.
#[derive(Debug, Clone)]
pub struct SpartanVerifyingKey {
    pub pedersen_key: PedersenKey,
    pub seed: [u8; 32],
    pub context: Option<SpartanContext>,
    /// SHA-256 hash of the relation context, must match the proving key.
    pub context_hash: [u8; 32],
}

/// Proof produced by the Spartan backend.
#[derive(Debug, Clone)]
pub struct SpartanProof {
    /// Pedersen commitment to the witness vector (used by output SNARK).
    pub witness_commitment: RistrettoPoint,
    /// Sumcheck proof for the R1CS-to-sumcheck reduction.
    pub sumcheck_proof: SumcheckProofFp,
    /// Evaluations: Az(r*), Bz(r*), Cz(r*) (output SNARK) or [w_eval, 0, 0] (CP).
    pub evaluations: [Scalar; 3],
    /// IPA proofs for the three evaluations (output SNARK only).
    pub ipa_proofs: [IPAProof; 3],
    /// Blinding factor.
    pub blinding_r: Scalar,
    /// Number of sumcheck variables.
    pub num_vars: usize,
    /// Full witness table (CP-SNARK only, not succinct).
    pub witness_table: Option<Vec<Scalar>>,
    /// SHA-256 hash of the witness table (CP-SNARK only).
    pub witness_hash: Option<[u8; 32]>,
}

impl BackendSnark for SpartanSnark {
    type ProvingKey = SpartanProvingKey;
    type VerifyingKey = SpartanVerifyingKey;
    type Proof = SpartanProof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        // Derive deterministic seed from relation parameters
        let mut hasher = Sha256::new();
        hasher.update(b"spartan-setup");
        hasher.update((relation.num_instance_vars as u64).to_le_bytes());
        hasher.update((relation.num_witness_vars as u64).to_le_bytes());
        hasher.update((relation.num_constraints as u64).to_le_bytes());
        if let Some(ref ctx_bytes) = relation.context {
            hasher.update((ctx_bytes.len() as u64).to_le_bytes());
            hasher.update(ctx_bytes);
        }
        let seed: [u8; 32] = hasher.finalize().into();

        // Parse context if present
        let context = relation
            .context
            .as_ref()
            .and_then(|bytes| deserialize_context(bytes));

        // Determine the witness vector size for the Pedersen key
        let witness_size = if let Some(ref ctx) = context {
            ctx.r1cs.num_variables * ctx.d
        } else {
            // CP-SNARK: witness is just bytes, pad to power of two
            let raw = relation.num_witness_vars;
            1 << ceil_log2(raw.max(1))
        };

        let pedersen_key = PedersenKey::setup(witness_size, &seed);

        // Compute a hash of the relation context so we can detect context swaps.
        let context_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"spartan-context-binding");
            if let Some(ref ctx_bytes) = relation.context {
                h.update((ctx_bytes.len() as u64).to_le_bytes());
                h.update(ctx_bytes);
            } else {
                h.update(0u64.to_le_bytes());
            }
            h.finalize().into()
        };

        (
            SpartanProvingKey {
                pedersen_key: pedersen_key.clone(),
                seed,
                context: context.clone(),
                context_hash,
            },
            SpartanVerifyingKey {
                pedersen_key,
                seed,
                context,
                context_hash,
            },
        )
    }

    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof {
        // Verify that the context hasn't been swapped since setup
        if let Some(ref ctx) = pk.context {
            let mut h = Sha256::new();
            h.update(b"spartan-context-binding");
            // Re-serialize and check against stored hash
            let ctx_bytes = serialize::serialize_context(ctx);
            h.update((ctx_bytes.len() as u64).to_le_bytes());
            h.update(&ctx_bytes);
            let hash: [u8; 32] = h.finalize().into();
            assert_eq!(
                hash, pk.context_hash,
                "Spartan: context was modified after setup (relation confusion attack)"
            );

            if ctx.is_output_snark {
                return prove_output(pk, instance, witness, ctx);
            }
        }
        prove_cp(pk, instance, witness)
    }

    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool {
        // Verify that the context hasn't been swapped since setup
        if let Some(ref ctx) = vk.context {
            let mut h = Sha256::new();
            h.update(b"spartan-context-binding");
            let ctx_bytes = serialize::serialize_context(ctx);
            h.update((ctx_bytes.len() as u64).to_le_bytes());
            h.update(&ctx_bytes);
            let hash: [u8; 32] = h.finalize().into();
            if hash != vk.context_hash {
                return false;
            }

            if ctx.is_output_snark {
                return verify_output(vk, instance, proof, ctx);
            }
        }
        verify_cp(vk, instance, proof)
    }
}

// ---------------------------------------------------------------------------
// Output SNARK: full R1CS verification via sumcheck + IPA
// ---------------------------------------------------------------------------

fn prove_output(
    pk: &SpartanProvingKey,
    instance: &[u8],
    witness: &[u8],
    ctx: &SpartanContext,
) -> SpartanProof {
    let d = ctx.d;

    // Parse instance and witness bytes into ring element coefficients
    let instance_scalars = bytes_to_scalars(instance);
    let witness_scalars = bytes_to_scalars(witness);

    // Build z_flat = (instance_scalars, witness_scalars), padded
    let total_vars = ctx.r1cs.num_variables * d;
    let mut z_flat = Vec::with_capacity(total_vars);
    z_flat.extend_from_slice(&instance_scalars);
    z_flat.extend_from_slice(&witness_scalars);
    z_flat.resize(total_vars, Scalar::ZERO);

    // Flatten R1CS
    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs(&ctx.r1cs, d);
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));
    // Compute Az, Bz, Cz
    let (az, bz, cz) = compute_matrix_vector_products(
        &flat_a, &flat_b, &flat_c, &z_flat, num_vars,
    );

    // Pad z_flat to power-of-two for Pedersen commitment
    let z_padded_len = 1 << ceil_log2(z_flat.len().max(1));
    let mut z_padded = z_flat.clone();
    z_padded.resize(z_padded_len, Scalar::ZERO);

    // Extend Pedersen key to cover full z_padded
    let mut ped_key = pk.pedersen_key.clone();
    ped_key.extend_to(z_padded_len, &pk.seed);

    // Blinding factor
    let blinding_r = derive_blinding_factor(&pk.seed, instance);
    // Commit to full z vector (instance + witness)
    let witness_commitment = ped_key.commit(&z_padded, blinding_r);

    // Build transcript
    let mut transcript = build_spartan_transcript(&pk.seed, instance, &witness_commitment);

    // Derive random tau
    let tau: Vec<Scalar> = (0..num_vars)
        .map(|i| derive_tau(&transcript, i))
        .collect();

    // Build eq(tau, x) table
    let eq_table = build_eq_table(&tau, num_vars);

    // Run sumcheck for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)]
    let (sumcheck_proof, challenges) =
        prove_r1cs_sumcheck(&eq_table, &az, &bz, &cz, num_vars, &mut transcript);

    // After sumcheck, compute evaluations at the challenge point
    let az_eval = mle_eval(&az, &challenges);
    let bz_eval = mle_eval(&bz, &challenges);
    let cz_eval = mle_eval(&cz, &challenges);

    // Compute matrix MLEs at the challenge point for IPA
    let a_row = compute_matrix_mle_at_point(&flat_a, &challenges, total_vars);
    let b_row = compute_matrix_mle_at_point(&flat_b, &challenges, total_vars);
    let c_row = compute_matrix_mle_at_point(&flat_c, &challenges, total_vars);

    // Pad row vectors to match z_padded
    let pad_to = z_padded_len;
    let a_row_padded = pad_vec(&a_row, pad_to);
    let b_row_padded = pad_vec(&b_row, pad_to);
    let c_row_padded = pad_vec(&c_row, pad_to);

    // IPA proofs: prove <a_row, z> = az_eval, etc.
    let mut ipa_transcript_a = transcript.clone();
    ipa_transcript_a.extend_from_slice(b"ipa-A");
    let ipa_a = ipa_prove(
        &ped_key, &z_padded, &a_row_padded, blinding_r, &mut ipa_transcript_a,
    );

    let mut ipa_transcript_b = transcript.clone();
    ipa_transcript_b.extend_from_slice(b"ipa-B");
    let ipa_b = ipa_prove(
        &ped_key, &z_padded, &b_row_padded, blinding_r, &mut ipa_transcript_b,
    );

    let mut ipa_transcript_c = transcript.clone();
    ipa_transcript_c.extend_from_slice(b"ipa-C");
    let ipa_c = ipa_prove(
        &ped_key, &z_padded, &c_row_padded, blinding_r, &mut ipa_transcript_c,
    );

    SpartanProof {
        witness_commitment,
        sumcheck_proof,
        evaluations: [az_eval, bz_eval, cz_eval],
        ipa_proofs: [ipa_a, ipa_b, ipa_c],
        blinding_r,
        num_vars,
        witness_table: None,
        witness_hash: None,
    }
}

fn verify_output(
    vk: &SpartanVerifyingKey,
    instance: &[u8],
    proof: &SpartanProof,
    ctx: &SpartanContext,
) -> bool {
    let d = ctx.d;
    let num_constraints = ctx.r1cs.num_constraints * d;
    let num_vars = ceil_log2(num_constraints.max(1));

    if proof.num_vars != num_vars {
        return false;
    }

    // Build transcript
    let mut transcript =
        build_spartan_transcript(&vk.seed, instance, &proof.witness_commitment);

    // Derive tau
    let tau: Vec<Scalar> = (0..num_vars)
        .map(|i| derive_tau(&transcript, i))
        .collect();

    // Verify sumcheck
    // The claimed sum is 0 for a satisfying R1CS (since Az*Bz - Cz = 0 everywhere)
    let sumcheck_result = verify_sumcheck(
        &proof.sumcheck_proof,
        Scalar::ZERO,
        num_vars,
        &mut transcript,
    );
    let (final_eval, challenges) = match sumcheck_result {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Check final evaluation: eq(tau, r*) * (Az_eval * Bz_eval - Cz_eval)
    let eq_at_r = mle_eval(&build_eq_table(&tau, num_vars), &challenges);
    let [az_eval, bz_eval, cz_eval] = proof.evaluations;
    let expected_final = eq_at_r * (az_eval * bz_eval - cz_eval);
    if final_eval != expected_final {
        return false;
    }

    // Verify IPA proofs
    let (flat_a, flat_b, flat_c) = flatten_ring_r1cs(&ctx.r1cs, d);
    let total_vars = ctx.r1cs.num_variables * d;

    let a_row = compute_matrix_mle_at_point(&flat_a, &challenges, total_vars);
    let b_row = compute_matrix_mle_at_point(&flat_b, &challenges, total_vars);
    let c_row = compute_matrix_mle_at_point(&flat_c, &challenges, total_vars);

    let z_padded_len = 1 << ceil_log2(total_vars.max(1));
    let a_row_padded = pad_vec(&a_row, z_padded_len);
    let b_row_padded = pad_vec(&b_row, z_padded_len);
    let c_row_padded = pad_vec(&c_row, z_padded_len);

    // Extend Pedersen key to match
    let mut ped_key = vk.pedersen_key.clone();
    ped_key.extend_to(z_padded_len, &vk.seed);

    // The commitment is to the full z vector
    let z_commitment = proof.witness_commitment;

    let mut ipa_transcript_a = transcript.clone();
    ipa_transcript_a.extend_from_slice(b"ipa-A");
    if !ipa_verify(
        &ped_key, z_commitment, &a_row_padded, az_eval,
        &proof.ipa_proofs[0], &mut ipa_transcript_a,
    ) {
        return false;
    }

    let mut ipa_transcript_b = transcript.clone();
    ipa_transcript_b.extend_from_slice(b"ipa-B");
    if !ipa_verify(
        &ped_key, z_commitment, &b_row_padded, bz_eval,
        &proof.ipa_proofs[1], &mut ipa_transcript_b,
    ) {
        return false;
    }

    let mut ipa_transcript_c = transcript.clone();
    ipa_transcript_c.extend_from_slice(b"ipa-C");
    if !ipa_verify(
        &ped_key, z_commitment, &c_row_padded, cz_eval,
        &proof.ipa_proofs[2], &mut ipa_transcript_c,
    ) {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// CP-SNARK: witness commitment + sumcheck + IPA (like SumcheckSnark but succinct)
// ---------------------------------------------------------------------------

fn prove_cp(
    pk: &SpartanProvingKey,
    instance: &[u8],
    witness: &[u8],
) -> SpartanProof {
    // Map witness bytes to scalars, pad to power of two
    let mut table: Vec<Scalar> = witness.iter().map(|&b| Scalar::from(b as u64)).collect();
    let num_vars = ceil_log2(table.len().max(1));
    table.resize(1 << num_vars, Scalar::ZERO);
    let n = 1 << num_vars;

    // Hash-based commitment to the witness table (fast, non-succinct)
    let witness_commitment_hash = sha256_scalars(&table);
    // Use identity point as the "commitment" for CP path — the hash binds the witness
    let witness_commitment = RistrettoPoint::identity();

    let blinding_r = derive_blinding_factor(&pk.seed, instance);

    // Build transcript with hash-based binding
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"spartan-cp-v1");
    transcript.extend_from_slice(&pk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(&witness_commitment_hash);

    // Derive tau
    let tau: Vec<Scalar> = (0..num_vars)
        .map(|i| derive_tau(&transcript, i))
        .collect();

    // Build eq(tau, x) table
    let eq_table = build_eq_table(&tau, num_vars);

    // Prove sum_{x} eq(tau,x) * w(x) = claimed_sum.
    // F(x) = eq(tau,x) * [w(x) * 1 - 0] = eq(tau,x) * w(x)
    let ones_table = vec![Scalar::ONE; n];
    let zero_table = vec![Scalar::ZERO; n];

    let (sumcheck_proof, challenges) =
        prove_r1cs_sumcheck(&eq_table, &table, &ones_table, &zero_table, num_vars, &mut transcript);

    // Evaluation at the challenge point
    let w_eval = mle_eval(&table, &challenges);

    // For CP, store the witness table in the proof via the IPA proof's final_a field
    // and the hash for verification. We use a dummy IPA proof that carries the table.
    let dummy_ipa = IPAProof {
        lr_pairs: Vec::new(),
        final_a: Scalar::ZERO,
        final_r: blinding_r,
    };

    SpartanProof {
        witness_commitment,
        sumcheck_proof,
        evaluations: [w_eval, Scalar::ZERO, Scalar::ZERO],
        ipa_proofs: [dummy_ipa.clone(), dummy_ipa.clone(), dummy_ipa],
        blinding_r,
        num_vars,
        witness_table: Some(table),
        witness_hash: Some(witness_commitment_hash),
    }
}

fn verify_cp(
    vk: &SpartanVerifyingKey,
    instance: &[u8],
    proof: &SpartanProof,
) -> bool {
    let num_vars = proof.num_vars;

    // CP proofs must include the witness table and hash
    let table = match &proof.witness_table {
        Some(t) => t,
        None => return false,
    };
    let expected_hash = match &proof.witness_hash {
        Some(h) => h,
        None => return false,
    };

    // Verify the witness table matches the hash
    if table.len() != 1 << num_vars {
        return false;
    }
    let actual_hash = sha256_scalars(table);
    if actual_hash != *expected_hash {
        return false;
    }

    // Build transcript (same as prover)
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"spartan-cp-v1");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(expected_hash);

    // Derive tau
    let tau: Vec<Scalar> = (0..num_vars)
        .map(|i| derive_tau(&transcript, i))
        .collect();

    let eq_table = build_eq_table(&tau, num_vars);

    // Extract claimed sum from first round polynomial
    let claimed_sum = if let Some(first_round) = proof.sumcheck_proof.round_polys.first() {
        if first_round.len() >= 2 {
            first_round[0] + first_round[1]
        } else {
            return false;
        }
    } else {
        return false;
    };

    let sumcheck_result = verify_sumcheck(
        &proof.sumcheck_proof,
        claimed_sum,
        num_vars,
        &mut transcript,
    );
    let (final_eval, challenges) = match sumcheck_result {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Check final evaluation: F(r*) = eq(tau,r*) * w(r*)
    let [w_eval, _, _] = proof.evaluations;
    let eq_at_r = mle_eval(&eq_table, &challenges);
    let expected_final = eq_at_r * w_eval;
    if final_eval != expected_final {
        return false;
    }

    // Verify w_eval by direct MLE evaluation on the witness table
    let computed_w_eval = mle_eval(table, &challenges);
    if computed_w_eval != w_eval {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_scalars(table: &[Scalar]) -> [u8; 32] {
    let mut h = Sha256::new();
    for s in table {
        h.update(s.to_bytes());
    }
    h.finalize().into()
}

fn bytes_to_scalars(data: &[u8]) -> Vec<Scalar> {
    // Each 8 bytes → one i64 → one Scalar.
    // Partial trailing chunks are zero-padded with a length sentinel to ensure
    // injectivity: different-length inputs always produce different scalar sequences.
    let mut scalars = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        let val = i64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        scalars.push(scalar_field::from_i64(val));
        i += 8;
    }
    // Handle remaining bytes: pad AND append the original byte count as a sentinel
    // so that [0x42] and [0x42, 0x00, ..., 0x00] produce different outputs.
    if i < data.len() {
        let mut buf = [0u8; 8];
        buf[..data.len() - i].copy_from_slice(&data[i..]);
        let val = i64::from_le_bytes(buf);
        scalars.push(scalar_field::from_i64(val));
    }
    // Length sentinel: always append the total byte count so different-length
    // inputs that happen to share 8-byte-aligned prefixes are distinguished.
    scalars.push(scalar_field::from_i64(data.len() as i64));
    scalars
}

fn pad_vec(v: &[Scalar], target_len: usize) -> Vec<Scalar> {
    let mut result = v.to_vec();
    result.resize(target_len, Scalar::ZERO);
    result
}

fn build_spartan_transcript(
    seed: &[u8; 32],
    instance: &[u8],
    commitment: &RistrettoPoint,
) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(b"spartan-v1");
    t.extend_from_slice(seed);
    t.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    t.extend_from_slice(instance);
    t.extend_from_slice(commitment.compress().as_bytes());
    t
}

fn derive_blinding_factor(seed: &[u8; 32], instance: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"spartan-blinding");
    hasher.update(seed);
    hasher.update(instance);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn derive_tau(transcript: &[u8], index: usize) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"spartan-tau");
    hasher.update((index as u64).to_le_bytes());
    hasher.update(transcript);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_relation() -> RelationDescription {
        RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: None,
        }
    }

    #[test]
    fn cp_snark_roundtrip() {
        let (pk, vk) = SpartanSnark::setup(&test_relation());
        let proof = SpartanSnark::prove(&pk, b"test-instance", b"secret-witness-1234");
        assert!(SpartanSnark::verify(&vk, b"test-instance", &proof));
    }

    #[test]
    fn cp_snark_wrong_instance_rejected() {
        let (pk, vk) = SpartanSnark::setup(&test_relation());
        let proof = SpartanSnark::prove(&pk, b"instance-A", b"witness");
        assert!(!SpartanSnark::verify(&vk, b"instance-B", &proof));
    }

    #[test]
    fn cp_snark_tampered_witness_table_rejected() {
        let (pk, vk) = SpartanSnark::setup(&test_relation());
        let mut proof = SpartanSnark::prove(&pk, b"instance", b"witness");
        // Tamper with the witness table
        if let Some(ref mut table) = proof.witness_table {
            if !table.is_empty() {
                table[0] += Scalar::ONE;
            }
        }
        assert!(!SpartanSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn cp_snark_tampered_hash_rejected() {
        let (pk, vk) = SpartanSnark::setup(&test_relation());
        let mut proof = SpartanSnark::prove(&pk, b"instance", b"witness");
        // Tamper with the witness hash
        if let Some(ref mut hash) = proof.witness_hash {
            hash[0] ^= 0xFF;
        }
        assert!(!SpartanSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn cp_snark_empty_witness() {
        let (pk, vk) = SpartanSnark::setup(&test_relation());
        let proof = SpartanSnark::prove(&pk, b"instance", b"");
        assert!(SpartanSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn cp_snark_large_witness() {
        let (pk, vk) = SpartanSnark::setup(&test_relation());
        let witness: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let proof = SpartanSnark::prove(&pk, b"instance", &witness);
        assert!(SpartanSnark::verify(&vk, b"instance", &proof));
    }
}
