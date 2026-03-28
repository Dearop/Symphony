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
use crate::folding::{FoldedInstance, FoldingProof};
use crate::params::D;
use crate::ring::extension::ExtFieldElement;
use crate::ring::tensor::TensorElement;
use crate::ring::RingElement;
use crate::rok::gr1cs::GR1CSProof;
use crate::sumcheck::SumcheckProof;

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
/// themselves, the folded instance, plus the deterministically-derived
/// challenges.
pub fn encode_cp_instance(
    fs_commitments: &[Vec<u8>],
    folded_instance: &FoldedInstance,
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

    // Bind the folded instance into the CP relation instance so the CP proof
    // cannot be replayed across different folded outputs.
    let folded_bytes = encode_folded_instance(folded_instance);
    instance.extend_from_slice(&(folded_bytes.len() as u64).to_le_bytes());
    instance.extend_from_slice(&folded_bytes);

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
pub fn encode_cp_witness(openings: &[Vec<u8>], folding_transcript: &[u8]) -> Vec<u8> {
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

fn encode_ext_field_element(buf: &mut Vec<u8>, elem: &ExtFieldElement) {
    buf.extend_from_slice(&elem.c0.to_le_bytes());
    buf.extend_from_slice(&elem.c1.to_le_bytes());
}

fn encode_ring_element(buf: &mut Vec<u8>, elem: &RingElement) {
    for &c in &elem.coeffs {
        buf.extend_from_slice(&c.to_le_bytes());
    }
}

fn encode_tensor_element(buf: &mut Vec<u8>, te: &TensorElement) {
    for row in &te.data {
        for &v in row.iter().take(D) {
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }
}

fn encode_sumcheck_proof(buf: &mut Vec<u8>, proof: &SumcheckProof) {
    buf.extend_from_slice(&(proof.round_messages.len() as u64).to_le_bytes());
    for round in &proof.round_messages {
        buf.extend_from_slice(&(round.evaluations.len() as u64).to_le_bytes());
        for eval in &round.evaluations {
            encode_ext_field_element(buf, eval);
        }
    }
}

fn encode_commitment(buf: &mut Vec<u8>, commitment: &crate::commitment::Commitment) {
    buf.extend_from_slice(&(commitment.value.elements.len() as u64).to_le_bytes());
    for elem in &commitment.value.elements {
        encode_ring_element(buf, elem);
    }
}

fn encode_linear_relation(buf: &mut Vec<u8>, relation: &crate::rok::LinearRelation) {
    encode_commitment(buf, &relation.commitment);
    buf.extend_from_slice(&(relation.evaluation_point.len() as u64).to_le_bytes());
    for elem in &relation.evaluation_point {
        encode_ext_field_element(buf, elem);
    }
    for te in &relation.evaluation_values {
        encode_tensor_element(buf, te);
    }
}

fn encode_batched_relation(buf: &mut Vec<u8>, relation: &crate::rok::BatchedLinearRelation) {
    buf.extend_from_slice(&(relation.commitments.len() as u64).to_le_bytes());
    for commitment in &relation.commitments {
        encode_commitment(buf, commitment);
    }
    buf.extend_from_slice(&(relation.evaluation_point.len() as u64).to_le_bytes());
    for elem in &relation.evaluation_point {
        encode_ext_field_element(buf, elem);
    }
    buf.extend_from_slice(&(relation.evaluation_values.len() as u64).to_le_bytes());
    for te in &relation.evaluation_values {
        encode_tensor_element(buf, te);
    }
}

/// Encode a single GR1CS proof into a deterministic transcript message.
pub fn encode_gr1cs_round_message(proof: &GR1CSProof) -> Vec<u8> {
    let mut buf = Vec::new();

    encode_sumcheck_proof(&mut buf, &proof.hadamard_proof.sumcheck_proof);
    for te in &proof.hadamard_proof.evaluation_matrix {
        encode_tensor_element(&mut buf, te);
    }

    buf.extend_from_slice(&(proof.range_proof.monomial_commitments.len() as u64).to_le_bytes());
    for commitment in &proof.range_proof.monomial_commitments {
        encode_commitment(&mut buf, commitment);
    }

    buf.extend_from_slice(&(proof.range_proof.monomial_vectors.len() as u64).to_le_bytes());
    for monomial_vector in &proof.range_proof.monomial_vectors {
        buf.extend_from_slice(&(monomial_vector.len() as u64).to_le_bytes());
        for elem in monomial_vector {
            encode_ring_element(&mut buf, elem);
        }
    }

    encode_sumcheck_proof(&mut buf, &proof.range_proof.monomial_proof.sumcheck_proof);
    buf.extend_from_slice(
        &(proof.range_proof.monomial_proof.evaluations.len() as u64).to_le_bytes(),
    );
    for te in &proof.range_proof.monomial_proof.evaluations {
        encode_tensor_element(&mut buf, te);
    }
    buf.extend_from_slice(
        &(proof.range_proof.monomial_proof.sq_evaluations.len() as u64).to_le_bytes(),
    );
    for elem in &proof.range_proof.monomial_proof.sq_evaluations {
        encode_ext_field_element(&mut buf, elem);
    }

    buf.extend_from_slice(&(proof.range_proof.projected_values.len() as u64).to_le_bytes());
    for &value in &proof.range_proof.projected_values {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    buf
}

/// Encode the complete folding transcript witness used by the CP relation.
pub fn encode_folding_transcript_witness(proof: &FoldingProof, fs_messages: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&(fs_messages.len() as u64).to_le_bytes());
    for message in fs_messages {
        buf.extend_from_slice(&(message.len() as u64).to_le_bytes());
        buf.extend_from_slice(message);
    }

    buf.extend_from_slice(&(proof.commitments.len() as u64).to_le_bytes());
    for commitment in &proof.commitments {
        encode_commitment(&mut buf, commitment);
    }

    buf.extend_from_slice(&(proof.gr1cs_proofs.len() as u64).to_le_bytes());
    for gr1cs_proof in &proof.gr1cs_proofs {
        let encoded = encode_gr1cs_round_message(gr1cs_proof);
        buf.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        buf.extend_from_slice(&encoded);
    }

    buf.extend_from_slice(&(proof.beta.len() as u64).to_le_bytes());
    for beta_elem in &proof.beta {
        encode_ring_element(&mut buf, beta_elem);
    }

    let folded_bytes = encode_folded_instance(&proof.folded_instance);
    buf.extend_from_slice(&(folded_bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(&folded_bytes);

    encode_linear_relation(&mut buf, &proof.linear_relation);
    encode_batched_relation(&mut buf, &proof.batched_relation);

    buf
}
