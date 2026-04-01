//! Inner Product Argument (Bulletproofs-style) over Ristretto.
//!
//! Proves that <a, b> = c where:
//! - a is committed in C = sum a_i G_i + r H
//! - b is known to the verifier
//! - c is the claimed inner product

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use super::commitment::PedersenKey;

/// An inner product argument proof.
#[derive(Debug, Clone)]
pub struct IPAProof {
    /// (L_i, R_i) pairs for each halving round.
    pub lr_pairs: Vec<(RistrettoPoint, RistrettoPoint)>,
    /// Final scalar a (after all halvings).
    pub final_a: Scalar,
    /// Final blinding factor.
    pub final_r: Scalar,
}

/// Derive the U generator (for binding the inner product) from the transcript.
/// Must be called identically by prover and verifier before the IPA loop.
fn derive_u_generator(transcript: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha256::new();
    hasher.update(b"spartan-ipa-U-gen");
    hasher.update(transcript);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    let mut hasher2 = Sha256::new();
    hasher2.update(b"spartan-ipa-U-gen-ext");
    hasher2.update(hash);
    let hash2 = hasher2.finalize();
    wide[32..].copy_from_slice(&hash2);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Derive a challenge from the transcript after appending L and R.
fn derive_challenge(transcript: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"spartan-ipa-challenge");
    hasher.update(transcript);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive blinding factors for L and R from the original blinding and round.
fn derive_lr_blindings(original_r: Scalar, round: usize) -> (Scalar, Scalar) {
    let r_bytes = original_r.to_bytes();

    let mut hasher_l = Sha256::new();
    hasher_l.update(b"spartan-ipa-rL");
    hasher_l.update(r_bytes);
    hasher_l.update((round as u64).to_le_bytes());
    let hash_l = hasher_l.finalize();
    let mut wide_l = [0u8; 64];
    wide_l[..32].copy_from_slice(&hash_l);
    let r_l = Scalar::from_bytes_mod_order_wide(&wide_l);

    let mut hasher_r = Sha256::new();
    hasher_r.update(b"spartan-ipa-rR");
    hasher_r.update(r_bytes);
    hasher_r.update((round as u64).to_le_bytes());
    let hash_r = hasher_r.finalize();
    let mut wide_r = [0u8; 64];
    wide_r[..32].copy_from_slice(&hash_r);
    let r_r = Scalar::from_bytes_mod_order_wide(&wide_r);

    (r_l, r_r)
}

/// Prove that <a, b> = claimed_ip, given commitment C = Commit(a, r).
pub fn ipa_prove(
    key: &PedersenKey,
    a: &[Scalar],
    b: &[Scalar],
    r: Scalar,
    transcript: &mut Vec<u8>,
) -> IPAProof {
    let n = a.len();
    assert_eq!(n, b.len());
    assert!(n.is_power_of_two());
    let num_rounds = n.trailing_zeros() as usize;

    // Derive U generator from initial transcript state
    let u_gen = derive_u_generator(transcript);

    let mut a_vec = a.to_vec();
    let mut b_vec = b.to_vec();
    let mut g_vec = key.generators[..n].to_vec();
    let mut r_scalar = r;

    let mut lr_pairs = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let half = a_vec.len() / 2;
        let (a_lo, a_hi) = (&a_vec[..half], &a_vec[half..]);
        let (b_lo, b_hi) = (&b_vec[..half], &b_vec[half..]);
        let (g_lo, g_hi) = (&g_vec[..half], &g_vec[half..]);

        // Cross inner products
        let ip_l: Scalar = a_lo.iter().zip(b_hi.iter()).map(|(a, b)| a * b).sum();
        let ip_r: Scalar = a_hi.iter().zip(b_lo.iter()).map(|(a, b)| a * b).sum();

        // Blinding factors derived from original r
        let (r_l, r_r) = derive_lr_blindings(r, round);

        // L = <a_lo, G_hi> + ip_l * U + r_l * H
        let mut l_point = key.blinding_gen * r_l + u_gen * ip_l;
        for i in 0..half {
            l_point += g_hi[i] * a_lo[i];
        }

        // R = <a_hi, G_lo> + ip_r * U + r_r * H
        let mut r_point = key.blinding_gen * r_r + u_gen * ip_r;
        for i in 0..half {
            r_point += g_lo[i] * a_hi[i];
        }

        lr_pairs.push((l_point, r_point));

        // Append L, R to transcript and derive challenge
        transcript.extend_from_slice(l_point.compress().as_bytes());
        transcript.extend_from_slice(r_point.compress().as_bytes());
        let x = derive_challenge(transcript);
        let x_inv = x.invert();

        // Fold: a' = a_lo * x + a_hi * x_inv
        //        b' = b_lo * x_inv + b_hi * x
        //        G' = G_lo * x_inv + G_hi * x
        let mut new_a = Vec::with_capacity(half);
        let mut new_b = Vec::with_capacity(half);
        let mut new_g = Vec::with_capacity(half);
        for i in 0..half {
            new_a.push(a_lo[i] * x + a_hi[i] * x_inv);
            new_b.push(b_lo[i] * x_inv + b_hi[i] * x);
            new_g.push(g_lo[i] * x_inv + g_hi[i] * x);
        }
        a_vec = new_a;
        b_vec = new_b;
        g_vec = new_g;

        // Update blinding: r' = r + x^2 * r_l + x^{-2} * r_r
        r_scalar = r_scalar + x * x * r_l + x_inv * x_inv * r_r;
    }

    IPAProof {
        lr_pairs,
        final_a: a_vec[0],
        final_r: r_scalar,
    }
}

/// Verify an IPA proof that <a, b> = claimed_ip against commitment C.
pub fn ipa_verify(
    key: &PedersenKey,
    commitment: RistrettoPoint,
    b: &[Scalar],
    claimed_ip: Scalar,
    proof: &IPAProof,
    transcript: &mut Vec<u8>,
) -> bool {
    let n = b.len();
    assert!(n.is_power_of_two());
    let num_rounds = n.trailing_zeros() as usize;

    if proof.lr_pairs.len() != num_rounds {
        return false;
    }

    // Derive U generator from initial transcript state (same as prover)
    let u_gen = derive_u_generator(transcript);

    // P = C + claimed_ip * U
    let mut p = commitment + u_gen * claimed_ip;

    // Collect challenges and accumulate P
    let mut challenges = Vec::with_capacity(num_rounds);
    for round in 0..num_rounds {
        let (l_point, r_point) = proof.lr_pairs[round];

        // Append L, R to transcript
        transcript.extend_from_slice(l_point.compress().as_bytes());
        transcript.extend_from_slice(r_point.compress().as_bytes());
        let x = derive_challenge(transcript);
        let x_inv = x.invert();
        challenges.push(x);

        // P' = L * x^2 + P + R * x^{-2}
        p = l_point * (x * x) + p + r_point * (x_inv * x_inv);
    }

    // Compute folded generator G_final: O(N) group operations (inherent to IPA)
    let (g_final, _s) = compute_g_final(&key.generators[..n], &challenges, num_rounds);

    // Fold b: O(N) scalar operations
    let mut b_vec = b.to_vec();
    for x in &challenges {
        let half = b_vec.len() / 2;
        let x_inv = x.invert();
        let mut new_b = Vec::with_capacity(half);
        for i in 0..half {
            new_b.push(b_vec[i] * x_inv + b_vec[half + i] * *x);
        }
        b_vec = new_b;
    }
    let b_final = b_vec[0];

    // Verify: P == final_a * G_final + final_a * b_final * U + final_r * H
    let expected = g_final * proof.final_a
        + u_gen * (proof.final_a * b_final)
        + key.blinding_gen * proof.final_r;

    p == expected
}

/// IPA verification specialized for eq-structured `b` vectors.
///
/// When `b = eq(eq_point, ·)` (a tensor-product multilinear extension), the
/// folded value `b_final` can be computed in O(log N) instead of expanding the
/// full 2^n eq table and folding it in O(N).
///
/// The generator-side computation (`g_final`) is still O(N) — this is inherent
/// to Bulletproofs-style IPA. But this function eliminates the O(N) allocation
/// and scalar work for the `b` vector.
pub fn ipa_verify_eq(
    key: &PedersenKey,
    commitment: RistrettoPoint,
    eq_point: &[Scalar],
    claimed_ip: Scalar,
    proof: &IPAProof,
    transcript: &mut Vec<u8>,
) -> bool {
    let num_rounds = eq_point.len();
    let n = 1usize << num_rounds;

    if proof.lr_pairs.len() != num_rounds {
        return false;
    }
    if key.generators.len() < n {
        return false;
    }

    let u_gen = derive_u_generator(transcript);
    let mut p = commitment + u_gen * claimed_ip;

    let mut challenges = Vec::with_capacity(num_rounds);
    for round in 0..num_rounds {
        let (l_point, r_point) = proof.lr_pairs[round];
        transcript.extend_from_slice(l_point.compress().as_bytes());
        transcript.extend_from_slice(r_point.compress().as_bytes());
        let x = derive_challenge(transcript);
        let x_inv = x.invert();
        challenges.push(x);
        p = l_point * (x * x) + p + r_point * (x_inv * x_inv);
    }

    // O(N) group operations for g_final (inherent to IPA)
    let (g_final, _s) = compute_g_final(&key.generators[..n], &challenges, num_rounds);

    // O(log N) computation of b_final using eq tensor-product structure:
    // b = eq(r, ·) = ⊗_j (1-r_j, r_j)
    // After IPA folding with challenges x_j:
    //   b_final = prod_j ((1-r_j)*x_j^{-1} + r_j*x_j)
    let b_final = compute_eq_b_final(eq_point, &challenges);

    let expected = g_final * proof.final_a
        + u_gen * (proof.final_a * b_final)
        + key.blinding_gen * proof.final_r;

    p == expected
}

/// Compute the folded eq value directly from the eq point and IPA challenges.
///
/// For b = eq(r, ·) = ⊗_j (1-r_j, r_j), folding with IPA challenge x_j gives:
///   b_final = prod_j ((1-r_j) * x_j^{-1} + r_j * x_j)
///
/// This is O(k) = O(log N) instead of expanding the full 2^k table and folding.
fn compute_eq_b_final(eq_point: &[Scalar], ipa_challenges: &[Scalar]) -> Scalar {
    assert_eq!(eq_point.len(), ipa_challenges.len());
    let mut result = Scalar::ONE;
    for (r_j, x_j) in eq_point.iter().zip(ipa_challenges.iter()) {
        let x_inv = x_j.invert();
        result *= (Scalar::ONE - *r_j) * x_inv + *r_j * *x_j;
    }
    result
}

/// Factor out the s_i / g_final computation shared by both IPA verify variants.
fn compute_g_final(
    generators: &[RistrettoPoint],
    challenges: &[Scalar],
    num_rounds: usize,
) -> (RistrettoPoint, Vec<Scalar>) {
    let n = generators.len();
    let mut s = vec![Scalar::ONE; n];
    for (j, x) in challenges.iter().enumerate() {
        let x_inv = x.invert();
        let stride = 1 << (num_rounds - 1 - j);
        for (i, si) in s.iter_mut().enumerate().take(n) {
            if (i / stride) % 2 == 0 {
                *si *= x_inv;
            } else {
                *si *= *x;
            }
        }
    }

    let mut g_final = generators[0] * s[0];
    for (gi, si) in generators[1..].iter().zip(s[1..].iter()) {
        g_final += gi * si;
    }

    (g_final, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipa_correct_inner_product() {
        let n = 4;
        let key = PedersenKey::setup(n, b"test-ipa");
        let a = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let b = vec![
            Scalar::from(5u64),
            Scalar::from(6u64),
            Scalar::from(7u64),
            Scalar::from(8u64),
        ];
        let r = Scalar::from(99u64);
        let commitment = key.commit(&a, r);
        let claimed_ip: Scalar = a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum();

        let mut transcript_p = b"test-ipa-transcript".to_vec();
        let proof = ipa_prove(&key, &a, &b, r, &mut transcript_p);

        let mut transcript_v = b"test-ipa-transcript".to_vec();
        assert!(ipa_verify(
            &key,
            commitment,
            &b,
            claimed_ip,
            &proof,
            &mut transcript_v
        ));
    }

    #[test]
    fn ipa_wrong_inner_product_rejected() {
        let n = 4;
        let key = PedersenKey::setup(n, b"test-ipa");
        let a = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let b = vec![
            Scalar::from(5u64),
            Scalar::from(6u64),
            Scalar::from(7u64),
            Scalar::from(8u64),
        ];
        let r = Scalar::from(99u64);
        let commitment = key.commit(&a, r);
        let wrong_ip = Scalar::from(999u64);

        let mut transcript_p = b"test-ipa-transcript".to_vec();
        let proof = ipa_prove(&key, &a, &b, r, &mut transcript_p);

        let mut transcript_v = b"test-ipa-transcript".to_vec();
        assert!(!ipa_verify(
            &key,
            commitment,
            &b,
            wrong_ip,
            &proof,
            &mut transcript_v
        ));
    }

    #[test]
    fn ipa_size_2() {
        let n = 2;
        let key = PedersenKey::setup(n, b"test-ipa-2");
        let a = vec![Scalar::from(10u64), Scalar::from(20u64)];
        let b = vec![Scalar::from(3u64), Scalar::from(4u64)];
        let r = Scalar::from(7u64);
        let commitment = key.commit(&a, r);
        let ip: Scalar = a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum();

        let mut transcript_p = b"test".to_vec();
        let proof = ipa_prove(&key, &a, &b, r, &mut transcript_p);

        let mut transcript_v = b"test".to_vec();
        assert!(ipa_verify(&key, commitment, &b, ip, &proof, &mut transcript_v));
    }

    #[test]
    fn ipa_size_8() {
        let n = 8;
        let key = PedersenKey::setup(n, b"test-ipa-8");
        let a: Vec<Scalar> = (1..=8).map(|i| Scalar::from(i as u64)).collect();
        let b: Vec<Scalar> = (1..=8).map(|i| Scalar::from(i as u64 * 2)).collect();
        let r = Scalar::from(42u64);
        let commitment = key.commit(&a, r);
        let ip: Scalar = a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum();

        let mut transcript_p = b"test8".to_vec();
        let proof = ipa_prove(&key, &a, &b, r, &mut transcript_p);

        let mut transcript_v = b"test8".to_vec();
        assert!(ipa_verify(&key, commitment, &b, ip, &proof, &mut transcript_v));
    }

    #[test]
    fn ipa_verify_eq_matches_full_verify() {
        use super::super::sumcheck::build_eq_table;

        let num_vars = 3;
        let n = 1 << num_vars;
        let key = PedersenKey::setup(n, b"test-ipa-eq");

        let a: Vec<Scalar> = (0..n).map(|i| Scalar::from((i * 7 + 3) as u64)).collect();
        let eq_point: Vec<Scalar> = (0..num_vars)
            .map(|i| Scalar::from((i * 11 + 5) as u64))
            .collect();
        let b = build_eq_table(&eq_point, num_vars);
        let r = Scalar::from(77u64);
        let commitment = key.commit(&a, r);
        let ip: Scalar = a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum();

        let mut transcript_p = b"test-eq".to_vec();
        let proof = ipa_prove(&key, &a, &b, r, &mut transcript_p);

        // Verify with full b vector
        let mut transcript_v1 = b"test-eq".to_vec();
        assert!(ipa_verify(&key, commitment, &b, ip, &proof, &mut transcript_v1));

        // Verify with eq_point (structured, no full expansion)
        let mut transcript_v2 = b"test-eq".to_vec();
        assert!(ipa_verify_eq(&key, commitment, &eq_point, ip, &proof, &mut transcript_v2));
    }

    #[test]
    fn ipa_verify_eq_rejects_wrong_ip() {
        use super::super::sumcheck::build_eq_table;

        let num_vars = 3;
        let n = 1 << num_vars;
        let key = PedersenKey::setup(n, b"test-ipa-eq-rej");

        let a: Vec<Scalar> = (0..n).map(|i| Scalar::from((i + 1) as u64)).collect();
        let eq_point: Vec<Scalar> = (0..num_vars)
            .map(|i| Scalar::from((i * 3 + 1) as u64))
            .collect();
        let b = build_eq_table(&eq_point, num_vars);
        let r = Scalar::from(42u64);
        let commitment = key.commit(&a, r);

        let mut transcript_p = b"test-eq-rej".to_vec();
        let proof = ipa_prove(&key, &a, &b, r, &mut transcript_p);

        let wrong_ip = Scalar::from(999u64);
        let mut transcript_v = b"test-eq-rej".to_vec();
        assert!(!ipa_verify_eq(&key, commitment, &eq_point, wrong_ip, &proof, &mut transcript_v));
    }
}
