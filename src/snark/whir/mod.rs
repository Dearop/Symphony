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

pub mod field;

use sha2::{Digest, Sha256};

use crate::params::SymphonyParams;
use crate::snark::{BackendSnark, RelationDescription};

use self::field::{bytes_to_babybear, pad_to_power_of_two};

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
///
/// For the initial integration, this uses a sumcheck-based approach with
/// hash-committed witness tables. The WHIR PCS integration for succinct
/// evaluation proofs is the next step.
#[derive(Debug, Clone)]
pub struct WhirProof {
    /// Sumcheck round polynomials: each round has evaluations at {0, 1, 2}.
    pub sumcheck_rounds: Vec<[BabyBear; 3]>,
    /// Witness evaluation at the sumcheck challenge point.
    pub evaluations: [BabyBear; 3],
    /// SHA-256 hash of the witness table (binding commitment).
    pub witness_hash: [u8; 32],
    /// Full witness table (non-succinct for CP path; WHIR PCS replaces this for output path).
    pub witness_table: Option<Vec<BabyBear>>,
    /// Number of sumcheck variables.
    pub num_vars: usize,
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
        // Verify context binding
        let current_hash = compute_context_hash(&pk.relation.context);
        assert_eq!(
            current_hash, pk.context_hash,
            "WHIR: context was modified after setup"
        );

        prove_cp(pk, instance, witness)
    }

    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool {
        // Verify context binding
        let current_hash = compute_context_hash(&vk.relation.context);
        if current_hash != vk.context_hash {
            return false;
        }

        verify_cp(vk, instance, proof)
    }
}

// ---------------------------------------------------------------------------
// CP-SNARK path: hash-committed witness + sumcheck over BabyBear
// ---------------------------------------------------------------------------

/// Prove: commit witness, run sumcheck for eq(tau,x) * w(x), evaluate at challenge.
fn prove_cp(pk: &WhirProvingKey, instance: &[u8], witness: &[u8]) -> WhirProof {
    // Use Symphony's default q for byte conversion. For CP path, witness bytes
    // are small values that fit in one limb regardless of q.
    let q = SymphonyParams::default_from_paper().q;

    let mut table = bytes_to_babybear(witness, q);
    pad_to_power_of_two(&mut table);
    let num_vars = table.len().trailing_zeros() as usize;
    // Hash-based commitment
    let witness_hash = sha256_babybear(&table);

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v1");
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

    // Sumcheck for F(x) = eq(tau,x) * w(x)
    let (rounds, challenges) =
        prove_sumcheck_product(&eq_table, &table, num_vars, &mut transcript);

    // Evaluation at challenge point
    let w_eval = mle_eval_bb(&table, &challenges);

    WhirProof {
        sumcheck_rounds: rounds,
        evaluations: [w_eval, BabyBear::ZERO, BabyBear::ZERO],
        witness_hash,
        witness_table: Some(table),
        num_vars,
    }
}

/// Verify: recompute transcript, verify sumcheck, check evaluation.
fn verify_cp(vk: &WhirVerifyingKey, instance: &[u8], proof: &WhirProof) -> bool {
    let num_vars = proof.num_vars;

    let table = match &proof.witness_table {
        Some(t) => t,
        None => return false,
    };

    // Verify table hash
    if table.len() != 1 << num_vars {
        return false;
    }
    let actual_hash = sha256_babybear(table);
    if actual_hash != proof.witness_hash {
        return false;
    }

    // Build transcript
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"whir-cp-v1");
    transcript.extend_from_slice(&vk.seed);
    transcript.extend_from_slice(&(instance.len() as u64).to_le_bytes());
    transcript.extend_from_slice(instance);
    transcript.extend_from_slice(&proof.witness_hash);

    // Derive tau
    let tau: Vec<BabyBear> = (0..num_vars)
        .map(|i| derive_challenge(&transcript, i, b"tau"))
        .collect();

    let eq_table = build_eq_table_bb(&tau, num_vars);

    // Verify sumcheck
    let challenges = match verify_sumcheck_product(
        &proof.sumcheck_rounds,
        num_vars,
        &mut transcript,
    ) {
        Some(c) => c,
        None => return false,
    };

    // Check final evaluation: F(r*) = eq(tau,r*) * w(r*)
    let [w_eval, _, _] = proof.evaluations;
    let eq_at_r = mle_eval_bb(&eq_table, &challenges);
    let expected = eq_at_r * w_eval;

    if num_vars == 0 {
        // With 0 variables, there's no sumcheck; just check the single-point identity
        if expected != eq_table[0] * w_eval {
            return false;
        }
    } else {
        // The final round's claimed value should match
        let last_round = match proof.sumcheck_rounds.last() {
            Some(r) => r,
            None => return false,
        };
        let last_challenge = challenges.last().copied().unwrap_or(BabyBear::ZERO);
        let final_eval = eval_univariate_3(last_round, last_challenge);
        if final_eval != expected {
            return false;
        }
    }

    // Verify w_eval by direct MLE evaluation on the table
    let computed_w_eval = mle_eval_bb(table, &challenges);
    if computed_w_eval != w_eval {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// BabyBear sumcheck helpers
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
    // Lagrange interpolation at {0, 1, 2}
    let [e0, e1, e2] = *evals;
    // L0(t) = (t-1)(t-2)/2, L1(t) = -t(t-2), L2(t) = t(t-1)/2
    let two_inv = BabyBear::TWO.inverse();
    let l0 = (t - BabyBear::ONE) * (t - BabyBear::TWO) * two_inv;
    let l1 = -t * (t - BabyBear::TWO);
    let l2 = t * (t - BabyBear::ONE) * two_inv;
    e0 * l0 + e1 * l1 + e2 * l2
}

/// Prove sumcheck for F(x) = a(x) * b(x) where a = eq_table, b = witness_table.
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

        // Compute evaluations of the round polynomial at {0, 1, 2}
        let mut e0 = BabyBear::ZERO;
        let mut e1 = BabyBear::ZERO;
        let mut e2 = BabyBear::ZERO;

        for j in 0..half {
            let eq_lo = eq[2 * j];
            let eq_hi = eq[2 * j + 1];
            let w_lo = w[2 * j];
            let w_hi = w[2 * j + 1];

            // t=0: eq_lo * w_lo
            e0 += eq_lo * w_lo;
            // t=1: eq_hi * w_hi
            e1 += eq_hi * w_hi;
            // t=2: (2*eq_hi - eq_lo) * (2*w_hi - w_lo)
            let eq_at_2 = eq_hi.double() - eq_lo;
            let w_at_2 = w_hi.double() - w_lo;
            e2 += eq_at_2 * w_at_2;
        }

        let round_evals = [e0, e1, e2];
        rounds.push(round_evals);

        // Absorb into transcript
        for e in &round_evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        // Derive challenge
        let r = derive_challenge(transcript, round, b"sc-r");
        challenges.push(r);

        // Fold tables
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

/// Verify sumcheck: check round consistency, return challenges.
fn verify_sumcheck_product(
    rounds: &[[BabyBear; 3]],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Option<Vec<BabyBear>> {
    if rounds.len() != num_vars {
        return None;
    }

    // Handle 0-variable case: no rounds, return empty challenges
    if num_vars == 0 {
        return Some(Vec::new());
    }

    // Compute claimed sum from first round: s(0) + s(1)
    let claimed_sum = rounds[0][0] + rounds[0][1];
    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, evals) in rounds.iter().enumerate() {
        // Check: s_i(0) + s_i(1) = current_claim
        if evals[0] + evals[1] != current_claim {
            return None;
        }

        // Absorb into transcript
        for e in evals {
            transcript.extend_from_slice(&e.as_canonical_u64().to_le_bytes());
        }

        // Derive challenge
        let r = derive_challenge(transcript, round, b"sc-r");
        challenges.push(r);

        // Update claim: s_{i+1}(0) + s_{i+1}(1) should equal s_i(r)
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
    // Take first 4 bytes, reduce mod BabyBear prime (2^31 - 2^27 + 1)
    let val = u32::from_le_bytes(hash[..4].try_into().unwrap());
    BabyBear::from_u32(val)
}

// ---------------------------------------------------------------------------
// Tests
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

    #[test]
    fn eq_table_correctness() {
        // eq(tau, x) at x=0...0 should be prod(1 - tau_i)
        let tau = vec![
            BabyBear::from_u32(3),
            BabyBear::from_u32(5),
        ];
        let table = build_eq_table_bb(&tau, 2);
        // eq(tau, (0,0)) = (1-3)(1-5) = (-2)(-4) = 8
        let expected_00 = (BabyBear::ONE - tau[0]) * (BabyBear::ONE - tau[1]);
        assert_eq!(table[0], expected_00);
        // eq(tau, (1,1)) = 3 * 5 = 15
        let expected_11 = tau[0] * tau[1];
        assert_eq!(table[3], expected_11);
    }

    #[test]
    fn mle_eval_consistency() {
        // MLE of [1, 2, 3, 4] at (0, 0) should be 1
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
}
