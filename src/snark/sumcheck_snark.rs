//! Sumcheck-based [`BackendSnark`] implementation (NON-SUCCINCT, testing only).
//!
//! Uses the crate's own sumcheck infrastructure to provide a stronger demo
//! backend than [`DummySnark`](super::DummySnark).
//!
//! # Non-succinctness warning
//!
//! The proof **includes the full witness table** and the verifier performs
//! O(N) passes over it. This is intentional: `SumcheckSnark` exists for
//! integration testing of the Symphony pipeline (e.g., verifying that wrong
//! instances and tampered proofs are rejected).
//!
//! **For succinct CP verification, use [`SpartanSnark`](super::spartan::SpartanSnark).**
//! `SpartanSnark` replaces the witness table with a Pedersen commitment and
//! uses a Bulletproofs-style IPA for evaluation proofs. The verifier never
//! touches the raw witness.
//!
//! # What it provides
//!
//! - **Consistency**: wrong instances, tampered proofs, and modified witnesses
//!   are rejected.
//! - **Completeness**: valid instance/witness pairs always produce accepted
//!   proofs.
//! - **Simplicity**: easy to debug since the witness is directly available.

use sha2::{Digest, Sha256};

use crate::fiat_shamir::transcript::Transcript;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::snark::{BackendSnark, RelationDescription};
use crate::sumcheck::prover as sumcheck_prover;
use crate::sumcheck::verifier as sumcheck_verifier;
use crate::sumcheck::{self, SumcheckClaim, SumcheckProof};

/// Internal prime for extension-field arithmetic inside the proof.
const Q: u64 = 65537;

/// A sumcheck-based SNARK using the crate's own infrastructure.
///
/// Proves knowledge of a witness by running a sumcheck protocol over the
/// multilinear extension of the witness table, bound to the public instance
/// via Fiat-Shamir.
#[derive(Clone)]
pub struct SumcheckSnark;

/// Proving key — contains a seed derived deterministically from the relation.
#[derive(Debug, Clone)]
pub struct SumcheckProvingKey {
    seed: [u8; 32],
}

/// Verifying key — mirrors the proving key.
#[derive(Debug, Clone)]
pub struct SumcheckVerifyingKey {
    seed: [u8; 32],
}

/// Proof produced by [`SumcheckSnark`].
#[derive(Debug, Clone)]
pub struct SumcheckProofData {
    /// SHA-256 commitment to the serialised witness table.
    pub witness_commitment: [u8; 32],
    /// The sumcheck proof for Σ eq(s,b)·w(b) = claimed_sum.
    pub sumcheck_proof: SumcheckProof,
    /// Claimed sum value.
    pub claimed_sum: ExtFieldElement,
    /// Full witness table (needed by the verifier for evaluation checks).
    pub witness_table: Vec<ExtFieldElement>,
    /// Number of sumcheck variables (log₂ of table size).
    pub num_vars: usize,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Map raw bytes to extension-field elements (one element per byte, c1 = 0).
fn bytes_to_table(data: &[u8]) -> Vec<ExtFieldElement> {
    data.iter()
        .map(|&b| ExtFieldElement {
            c0: b as i64,
            c1: 0,
        })
        .collect()
}

/// Serialise a table to bytes (deterministic, for hashing).
fn table_to_bytes(table: &[ExtFieldElement]) -> Vec<u8> {
    let mut out = Vec::with_capacity(table.len() * 16);
    for elem in table {
        out.extend_from_slice(&elem.c0.to_le_bytes());
        out.extend_from_slice(&elem.c1.to_le_bytes());
    }
    out
}

/// SHA-256 hash.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// ⌈log₂(n)⌉, minimum 1.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// Build a Fiat-Shamir transcript seeded with the key, instance, and commitment.
fn build_transcript(seed: &[u8; 32], instance: &[u8], commitment: &[u8; 32]) -> Transcript {
    let mut t = Transcript::new(b"sumcheck-snark-v1");
    t.append_bytes(b"seed", seed);
    t.append_bytes(b"instance", instance);
    t.append_bytes(b"witness-commitment", commitment);
    t
}

/// Derive the random evaluation point **s** and the per-round challenges.
fn derive_challenges(
    transcript: &mut Transcript,
    num_vars: usize,
) -> (Vec<ExtFieldElement>, Vec<ExtFieldElement>) {
    let s: Vec<ExtFieldElement> = (0..num_vars)
        .map(|i| {
            let label = format!("s-{i}");
            transcript.challenge_ext_field(label.as_bytes(), Q)
        })
        .collect();

    let challenges: Vec<ExtFieldElement> = (0..num_vars)
        .map(|i| {
            let label = format!("r-{i}");
            transcript.challenge_ext_field(label.as_bytes(), Q)
        })
        .collect();

    (s, challenges)
}

/// Evaluate the multilinear extension of `table` at a point via iterated
/// folding (MSB-first, matching [`sumcheck_prover::prove_bookkeeping`]).
fn evaluate_mle(
    table: &[ExtFieldElement],
    r: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> ExtFieldElement {
    let n = r.len();
    assert_eq!(table.len(), 1 << n);

    let mut current = table.to_vec();
    for ri in r {
        let half = current.len() / 2;
        let one_minus_ri = ctx.sub(&ctx.one(), ri);
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            let t0 = ctx.mul(&one_minus_ri, &current[j]);
            let t1 = ctx.mul(ri, &current[half + j]);
            next.push(ctx.add(&t0, &t1));
        }
        current = next;
    }

    assert_eq!(current.len(), 1);
    current[0]
}

// ---------------------------------------------------------------------------
// BackendSnark impl
// ---------------------------------------------------------------------------

impl BackendSnark for SumcheckSnark {
    type ProvingKey = SumcheckProvingKey;
    type VerifyingKey = SumcheckVerifyingKey;
    type Proof = SumcheckProofData;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        let mut h = Sha256::new();
        h.update(b"sumcheck-snark-setup");
        h.update((relation.num_instance_vars as u64).to_le_bytes());
        h.update((relation.num_witness_vars as u64).to_le_bytes());
        h.update((relation.num_constraints as u64).to_le_bytes());
        let seed: [u8; 32] = h.finalize().into();

        (SumcheckProvingKey { seed }, SumcheckVerifyingKey { seed })
    }

    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof {
        let ctx = ExtFieldContext::new(Q);

        // Map witness bytes → field elements, pad to next power of two.
        let mut table = bytes_to_table(witness);
        let num_vars = ceil_log2(table.len().max(1));
        table.resize(1 << num_vars, ctx.zero());

        // Commit to the padded table.
        let commitment = sha256(&table_to_bytes(&table));

        // Fiat-Shamir: derive evaluation point s and per-round challenges.
        let mut transcript = build_transcript(&pk.seed, instance, &commitment);
        let (s, challenges) = derive_challenges(&mut transcript, num_vars);

        // Build eq(s, ·) table and compute claimed sum.
        let eq_table = sumcheck_prover::build_eq_table(&s, &ctx);
        let mut claimed_sum = ctx.zero();
        for (eq_val, w_val) in eq_table.iter().zip(table.iter()) {
            claimed_sum = ctx.add(&claimed_sum, &ctx.mul(eq_val, w_val));
        }

        // Run degree-2 sumcheck: Σ_b eq(s,b)·w(b) = claimed_sum.
        let combiner =
            |factors: &[ExtFieldElement], ctx: &ExtFieldContext| ctx.mul(&factors[0], &factors[1]);
        let mut factor_tables = vec![eq_table, table.clone()];
        let sumcheck_proof = sumcheck_prover::prove_bookkeeping(
            &mut factor_tables,
            &combiner,
            num_vars,
            2,
            &challenges,
            &ctx,
        );

        SumcheckProofData {
            witness_commitment: commitment,
            sumcheck_proof,
            claimed_sum,
            witness_table: table,
            num_vars,
        }
    }

    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool {
        let ctx = ExtFieldContext::new(Q);

        // Table size check.
        if proof.witness_table.len() != 1 << proof.num_vars {
            return false;
        }

        // Verify witness commitment.
        if sha256(&table_to_bytes(&proof.witness_table)) != proof.witness_commitment {
            return false;
        }

        // Re-derive challenges.
        let mut transcript = build_transcript(&vk.seed, instance, &proof.witness_commitment);
        let (s, challenges) = derive_challenges(&mut transcript, proof.num_vars);

        // Recompute claimed sum and compare.
        let eq_table = sumcheck_prover::build_eq_table(&s, &ctx);
        let mut expected_sum = ctx.zero();
        for (eq_val, w_val) in eq_table.iter().zip(proof.witness_table.iter()) {
            expected_sum = ctx.add(&expected_sum, &ctx.mul(eq_val, w_val));
        }
        if expected_sum != proof.claimed_sum {
            return false;
        }

        // Verify sumcheck proof.
        let claim = SumcheckClaim {
            num_vars: proof.num_vars,
            degree: 2,
            claimed_sum: proof.claimed_sum,
        };
        let sc_result =
            match sumcheck_verifier::verify(&proof.sumcheck_proof, &claim, &challenges, &ctx) {
                Ok(r) => r,
                Err(_) => return false,
            };

        // Final evaluation consistency check.
        // prove_bookkeeping folds MSB-first with challenges[0..n], so the
        // final point is (x_0 = r[n-1], ..., x_{n-1} = r[0]).
        // eq_eval_ext_sumcheck reverses internally to match this convention.
        let eq_at_point = sumcheck::eq_eval_ext_sumcheck(&s, &challenges, &ctx);
        // evaluate_mle folds MSB-first with the same ordering as prove_bookkeeping.
        let w_at_point = evaluate_mle(&proof.witness_table, &challenges, &ctx);
        let expected_eval = ctx.mul(&eq_at_point, &w_at_point);

        sc_result.claimed_evaluation == expected_eval
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snark::BackendSnark;

    fn test_relation() -> RelationDescription {
        RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: None,
        }
    }

    #[test]
    fn roundtrip() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let proof = SumcheckSnark::prove(&pk, b"test-instance", b"secret-witness-1234");
        assert!(SumcheckSnark::verify(&vk, b"test-instance", &proof));
    }

    #[test]
    fn wrong_instance_rejected() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let proof = SumcheckSnark::prove(&pk, b"instance-A", b"witness");
        assert!(!SumcheckSnark::verify(&vk, b"instance-B", &proof));
    }

    #[test]
    fn tampered_round_message_rejected() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let mut proof = SumcheckSnark::prove(&pk, b"instance", b"witness");
        if let Some(msg) = proof.sumcheck_proof.round_messages.first_mut() {
            if let Some(eval) = msg.evaluations.first_mut() {
                eval.c0 = eval.c0.wrapping_add(1);
            }
        }
        assert!(!SumcheckSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn tampered_commitment_rejected() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let mut proof = SumcheckSnark::prove(&pk, b"instance", b"witness");
        proof.witness_commitment[0] ^= 0xFF;
        assert!(!SumcheckSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn tampered_witness_table_rejected() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let mut proof = SumcheckSnark::prove(&pk, b"instance", b"witness");
        if let Some(elem) = proof.witness_table.first_mut() {
            elem.c0 = elem.c0.wrapping_add(1);
        }
        assert!(!SumcheckSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn different_witnesses_produce_different_commitments() {
        let (pk, _) = SumcheckSnark::setup(&test_relation());
        let p1 = SumcheckSnark::prove(&pk, b"instance", b"witness-A");
        let p2 = SumcheckSnark::prove(&pk, b"instance", b"witness-B");
        assert_ne!(p1.witness_commitment, p2.witness_commitment);
    }

    #[test]
    fn empty_witness() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let proof = SumcheckSnark::prove(&pk, b"instance", b"");
        assert!(SumcheckSnark::verify(&vk, b"instance", &proof));
    }

    #[test]
    fn large_witness() {
        let (pk, vk) = SumcheckSnark::setup(&test_relation());
        let witness: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let proof = SumcheckSnark::prove(&pk, b"instance", &witness);
        assert!(SumcheckSnark::verify(&vk, b"instance", &proof));
    }
}
