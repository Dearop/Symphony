//! Fiat-Shamir transform with commit-and-open (Section 5).
//!
//! The key innovation: instead of embedding hashes in the SNARK circuit,
//! the prover commits to each protocol message using Π_cm, and the verifier
//! derives challenges from the committed transcript.

pub mod hash_commitment;
pub mod transcript;

/// Trait for the Fiat-Shamir commitment scheme Π_cm.
///
/// This is NOT the Ajtai commitment — it's a straightline-extractable scheme
/// used to commit to protocol messages in the Fiat-Shamir transform.
/// Both Merkle trees and KZG work here.
pub trait FSCommitment {
    type Commitment: Clone + AsRef<[u8]>;
    type Opening: Clone;

    /// Commit to a message.
    fn commit(&self, message: &[u8]) -> (Self::Commitment, Self::Opening);

    /// Verify a commitment opening.
    fn verify(&self, commitment: &Self::Commitment, message: &[u8], opening: &Self::Opening) -> bool;
}

/// A Fiat-Shamir commitment to a protocol message.
#[derive(Debug, Clone)]
pub struct FSCommitted<C: Clone> {
    pub commitment: C,
    pub round: usize,
}
