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

    // Compute folded generator G_final and folded b
    // s_i = prod_j x_j^{e_j(i)} where e_j(i) = x_inv if bit j of i is 0, x if bit j is 1
    let mut s = vec![Scalar::ONE; n];
    for (j, x) in challenges.iter().enumerate() {
        let x_inv = x.invert();
        let stride = 1 << (num_rounds - 1 - j);
        for (i, si) in s.iter_mut().enumerate().take(n) {
            if (i / stride).is_multiple_of(2) {
                *si *= x_inv;
            } else {
                *si *= *x;
            }
        }
    }

    let mut g_final = key.generators[0] * s[0];
    for (gi, si) in key.generators[1..n].iter().zip(s[1..n].iter()) {
        g_final += gi * si;
    }

    // Fold b
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
}
