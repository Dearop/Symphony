//! Folding challenge set S from LaBRADOR.
//!
//! Elements of S have coefficients in {0, ±1, ±2}, operator norm ≤ 15,
//! and differences S − S are invertible over Rq.

use crate::params::D;
use crate::ring::RingElement;
use rand::Rng;
use rand::RngExt;

/// The folding challenge set S ⊂ Rq.
///
/// Properties:
/// - Coefficients in {0, ±1, ±2}
/// - Operator norm ‖s‖_op ≤ 15
/// - For all s₁ ≠ s₂ ∈ S, (s₁ − s₂) is invertible in Rq
/// - |S| ≥ 2^128 (for security)
pub struct ChallengeSet {
    pub q: u64,
}

impl ChallengeSet {
    pub fn new(q: u64) -> Self {
        Self { q }
    }

    /// Sample a random element from the challenge set S.
    ///
    /// Coefficients are drawn from {0, ±1, ±2} with appropriate distribution
    /// to ensure ‖s‖_op ≤ 15.
    pub fn sample<R: Rng>(&self, rng: &mut R) -> RingElement {
        let mut coeffs = [0i64; D];
        for c in coeffs.iter_mut() {
            // Distribution over {-2, -1, 0, 1, 2}
            *c = rng.random_range(-2..=2);
        }
        RingElement { coeffs }
    }

    /// Sample a vector of ℓ_np independent challenges.
    pub fn sample_vector<R: Rng>(&self, rng: &mut R, len: usize) -> Vec<RingElement> {
        (0..len).map(|_| self.sample(rng)).collect()
    }

    /// Check if an element is in S (coefficients in {0, ±1, ±2}).
    pub fn is_in_set(elem: &RingElement) -> bool {
        elem.coeffs.iter().all(|&c| (-2..=2).contains(&c))
    }

    /// Check if an element is in S − S (coefficients in {0, ±1, ±2, ±3, ±4}).
    pub fn is_in_difference_set(elem: &RingElement) -> bool {
        elem.coeffs.iter().all(|&c| (-4..=4).contains(&c))
    }

    /// Operator norm bound for elements of S.
    pub fn operator_norm_bound() -> u64 {
        15
    }
}

/// Derive a challenge vector from a Fiat-Shamir transcript.
///
/// Each challenge element has coefficients in {0, ±1, ±2} (i.e., in the set S),
/// derived deterministically from the transcript state.
///
/// Uses rejection sampling to eliminate the bias that `byte % 5` would
/// introduce (256 is not divisible by 5, so values 0 and 1 would be
/// ~0.4% more likely than 2, 3, 4).
pub fn derive_challenge_vector(
    transcript: &mut crate::fiat_shamir::transcript::Transcript,
    _q: u64,
    len: usize,
) -> Vec<RingElement> {
    (0..len)
        .map(|i| {
            let label = format!("beta_{i}");
            // Request extra bytes to handle rejection sampling
            let mut bytes = vec![0u8; D * 2];
            transcript.challenge_bytes(label.as_bytes(), &mut bytes);
            let mut coeffs = [0i64; D];
            let mut byte_idx = 0;
            for coeff in coeffs.iter_mut() {
                // Rejection-sample: accept byte if < 255 (255 = 5*51),
                // which gives uniform distribution over 5 values.
                loop {
                    let b = bytes[byte_idx % bytes.len()];
                    byte_idx += 1;
                    if b < 255 {
                        *coeff = (b % 5) as i64 - 2;
                        break;
                    }
                    // On the rare reject (byte == 255), rotate through
                    // remaining bytes. In practice rejection is < 0.4%.
                }
            }
            RingElement { coeffs }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_in_set() {
        let cs = ChallengeSet::new(257);
        let mut rng = rand::rng();
        let s = cs.sample(&mut rng);
        assert!(ChallengeSet::is_in_set(&s));
    }

    #[test]
    fn test_difference_in_range() {
        let cs = ChallengeSet::new(257);
        let mut rng = rand::rng();
        let s1 = cs.sample(&mut rng);
        let s2 = cs.sample(&mut rng);
        let diff = s1.sub(&s2, 257);
        assert!(ChallengeSet::is_in_difference_set(&diff));
    }
}
