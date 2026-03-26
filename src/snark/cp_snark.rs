//! Commit-and-Prove SNARK helpers.
//!
//! The CP-SNARK proves that committed Fiat-Shamir messages form a valid
//! folding proof, WITHOUT encoding the commitment scheme or hash function
//! in the circuit. This is the key to avoiding hash-in-circuit overhead.
//!
//! This module provides encoding/decoding helpers that convert Symphony's
//! structured data (commitments, folded instances, transcripts) into the
//! byte-oriented `(instance, witness)` format expected by [`BackendSnark`].
//!
//! The actual proving and verifying is delegated to the generic backend.

use crate::fiat_shamir::transcript::Transcript;
use crate::folding::FoldedInstance;
use crate::params::D;

/// Description of the CP-SNARK relation.
///
/// Instance: (committed values c_{fs,i}, verifier challenges, folded instance)
/// Witness: (openings to c_{fs,i}, intermediate folding state)
///
/// The CP-SNARK proves:
/// - Knowledge of openings to all Fiat-Shamir commitments
/// - The opened messages form a valid interactive folding transcript
/// - The folded instance is correctly derived from the transcript
#[derive(Debug, Clone)]
pub struct CPRelation {
    /// Number of Fiat-Shamir rounds.
    pub num_rounds: usize,
    /// Size of each committed message.
    pub message_sizes: Vec<usize>,
}

/// Encode the CP-SNARK instance from Fiat-Shamir commitments and transcript.
///
/// The instance is the public part of the CP relation: the commitments
/// themselves plus the deterministically-derived challenges.
pub fn encode_cp_instance(
    fs_commitments: &[Vec<u8>],
    transcript: &mut Transcript,
) -> Vec<u8> {
    let mut instance = Vec::new();

    // Encode number of rounds
    instance.extend_from_slice(&(fs_commitments.len() as u64).to_le_bytes());

    // Encode each commitment
    for comm in fs_commitments {
        instance.extend_from_slice(&(comm.len() as u64).to_le_bytes());
        instance.extend_from_slice(comm);
    }

    // Derive and encode challenges
    for i in 0..fs_commitments.len() {
        let mut challenge = vec![0u8; 32];
        let label = format!("challenge-{i}");
        transcript.challenge_bytes(label.as_bytes(), &mut challenge);
        instance.extend_from_slice(&challenge);
    }

    instance
}

/// Encode the CP-SNARK witness from commitment openings and folding state.
///
/// The witness is the private part: the openings to the FS commitments
/// and the intermediate prover state that shows the transcript is valid.
pub fn encode_cp_witness(
    openings: &[Vec<u8>],
    folding_transcript: &[u8],
) -> Vec<u8> {
    let mut witness = Vec::new();

    // Encode openings
    witness.extend_from_slice(&(openings.len() as u64).to_le_bytes());
    for opening in openings {
        witness.extend_from_slice(&(opening.len() as u64).to_le_bytes());
        witness.extend_from_slice(opening);
    }

    // Encode folding transcript
    witness.extend_from_slice(&(folding_transcript.len() as u64).to_le_bytes());
    witness.extend_from_slice(folding_transcript);

    witness
}

/// Encode a folded instance as bytes for the output SNARK.
///
/// The output SNARK proves that the folded instance satisfies the
/// folded R1CS relation. This encoding serializes the instance into
/// the byte format expected by [`BackendSnark::prove`] / [`BackendSnark::verify`].
pub fn encode_folded_instance(instance: &FoldedInstance) -> Vec<u8> {
    let mut buf = Vec::new();

    // Encode folded commitment
    for elem in &instance.commitment.value.elements {
        for &c in &elem.coeffs {
            buf.extend_from_slice(&c.to_le_bytes());
        }
    }

    // Encode folded public input
    buf.extend_from_slice(&(instance.public_input.len() as u64).to_le_bytes());
    for elem in &instance.public_input {
        for &c in &elem.coeffs {
            buf.extend_from_slice(&c.to_le_bytes());
        }
    }

    // Encode evaluation values
    buf.extend_from_slice(&(instance.evaluation_values.len() as u64).to_le_bytes());
    for te in &instance.evaluation_values {
        for row in &te.data {
            for &v in row.iter().take(D) {
                buf.extend_from_slice(&v.to_le_bytes());
            }
        }
    }

    buf
}

/// Encode a folded witness as bytes for the output SNARK.
pub fn encode_folded_witness(witness: &crate::folding::FoldedWitness) -> Vec<u8> {
    let mut buf = Vec::new();

    // Encode witness ring vector
    for elem in &witness.witness.elements {
        for &c in &elem.coeffs {
            buf.extend_from_slice(&c.to_le_bytes());
        }
    }

    // Encode monomial vectors
    buf.extend_from_slice(&(witness.monomial_vectors.len() as u64).to_le_bytes());
    for mv in &witness.monomial_vectors {
        buf.extend_from_slice(&(mv.elements.len() as u64).to_le_bytes());
        for elem in &mv.elements {
            for &c in &elem.coeffs {
                buf.extend_from_slice(&c.to_le_bytes());
            }
        }
    }

    buf
}
