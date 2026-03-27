//! SHA-256-based Fiat-Shamir commitment scheme.
//!
//! Commit(m) = (H(r ‖ m), r) where r is 32 bytes of randomness.
//! Straightline-extractable in the random oracle model: the extractor
//! observes the random oracle queries and reads out (r, m) directly.

use sha2::{Sha256, Digest};
use crate::fiat_shamir::FSCommitment;

/// SHA-256-based commitment scheme implementing [`FSCommitment`].
///
/// Security:
/// - **Hiding**: information-theoretic in the random oracle model (r is fresh).
/// - **Binding**: computational, reduces to collision resistance of SHA-256.
/// - **Straightline extractable**: the extractor watches RO queries.
#[derive(Clone, Debug)]
pub struct HashCommitment;

impl HashCommitment {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HashCommitment {
    fn default() -> Self {
        Self::new()
    }
}

impl FSCommitment for HashCommitment {
    type Commitment = [u8; 32];
    type Opening = [u8; 32];

    fn commit(&self, message: &[u8]) -> ([u8; 32], [u8; 32]) {
        use rand::Rng;
        let mut randomness = [0u8; 32];
        rand::rng().fill_bytes(&mut randomness);

        let mut hasher = Sha256::new();
        hasher.update(randomness);
        hasher.update(message);
        let commitment: [u8; 32] = hasher.finalize().into();

        (commitment, randomness)
    }

    fn verify(&self, commitment: &[u8; 32], message: &[u8], opening: &[u8; 32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(opening);
        hasher.update(message);
        let expected: [u8; 32] = hasher.finalize().into();
        expected == *commitment
    }
}
