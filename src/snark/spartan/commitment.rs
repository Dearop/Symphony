//! Pedersen vector commitment over the Ristretto group.
//!
//! C = sum_i v_i * G_i + r * H
//! where G_i are generators and H is a blinding generator.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

/// Pedersen commitment parameters.
#[derive(Debug, Clone)]
pub struct PedersenKey {
    /// Vector of generators G_0, ..., G_{n-1}.
    pub generators: Vec<RistrettoPoint>,
    /// Blinding generator H.
    pub blinding_gen: RistrettoPoint,
}

impl PedersenKey {
    /// Deterministically generate Pedersen parameters from a seed.
    pub fn setup(n: usize, seed: &[u8]) -> Self {
        let mut generators = Vec::with_capacity(n);
        for i in 0..n {
            generators.push(hash_to_point(seed, b"generator", i as u64));
        }
        let blinding_gen = hash_to_point(seed, b"blinding", 0);
        Self {
            generators,
            blinding_gen,
        }
    }

    /// Commit to a vector of scalars with blinding factor r.
    /// C = sum_i values[i] * G_i + r * H
    pub fn commit(&self, values: &[Scalar], r: Scalar) -> RistrettoPoint {
        assert!(
            values.len() <= self.generators.len(),
            "too many values for this key"
        );
        let mut acc = self.blinding_gen * r;
        for (v, g) in values.iter().zip(self.generators.iter()) {
            acc += g * v;
        }
        acc
    }

    /// Extend the key to support n generators (if currently shorter).
    ///
    /// Panics if `n > 2^24` to prevent accidental memory exhaustion.
    pub fn extend_to(&mut self, n: usize, seed: &[u8]) {
        assert!(
            n <= (1 << 24),
            "PedersenKey::extend_to: n={n} exceeds maximum 2^24 generators"
        );
        let current = self.generators.len();
        if n > current {
            for i in current..n {
                self.generators
                    .push(hash_to_point(seed, b"generator", i as u64));
            }
        }
    }
}

/// Hash-to-point: produces a deterministic Ristretto point from (seed, label, index).
fn hash_to_point(seed: &[u8], label: &[u8], index: u64) -> RistrettoPoint {
    let mut hasher = Sha256::new();
    hasher.update(b"spartan-pedersen-");
    hasher.update(label);
    hasher.update(seed);
    hasher.update(index.to_le_bytes());
    let hash = hasher.finalize();

    // Use hash output as input to from_uniform_bytes (needs 64 bytes)
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    // Hash again for the second half
    let mut hasher2 = Sha256::new();
    hasher2.update(b"spartan-pedersen-ext-");
    hasher2.update(hash);
    let hash2 = hasher2.finalize();
    wide[32..].copy_from_slice(&hash2);

    RistrettoPoint::from_uniform_bytes(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_deterministic() {
        let key = PedersenKey::setup(4, b"test-seed");
        let values = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let r = Scalar::from(42u64);
        let c1 = key.commit(&values, r);
        let c2 = key.commit(&values, r);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commit_homomorphic() {
        let key = PedersenKey::setup(2, b"test-seed");
        let v1 = vec![Scalar::from(3u64), Scalar::from(5u64)];
        let v2 = vec![Scalar::from(7u64), Scalar::from(11u64)];
        let r1 = Scalar::from(1u64);
        let r2 = Scalar::from(2u64);

        let c1 = key.commit(&v1, r1);
        let c2 = key.commit(&v2, r2);

        let v_sum: Vec<Scalar> = v1.iter().zip(v2.iter()).map(|(a, b)| a + b).collect();
        let c_sum = key.commit(&v_sum, r1 + r2);

        assert_eq!(c1 + c2, c_sum);
    }

    #[test]
    fn different_values_different_commitments() {
        let key = PedersenKey::setup(2, b"test-seed");
        let r = Scalar::from(1u64);
        let c1 = key.commit(&[Scalar::from(1u64), Scalar::ZERO], r);
        let c2 = key.commit(&[Scalar::from(2u64), Scalar::ZERO], r);
        assert_ne!(c1, c2);
    }

    #[test]
    fn identity_with_zeros() {
        use curve25519_dalek::traits::Identity;
        let key = PedersenKey::setup(2, b"test-seed");
        let c = key.commit(&[Scalar::ZERO, Scalar::ZERO], Scalar::ZERO);
        assert_eq!(c, RistrettoPoint::identity());
    }
}
