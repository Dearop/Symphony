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

use super::r1cs::CpR1csLayout;
use crate::fiat_shamir::transcript::Transcript;
use crate::folding::digest::{Digest32, FoldInput};
use crate::folding::{FoldedInstance, FoldingProof};
use crate::params::D;
use crate::r1cs::R1CSMatrices;
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

/// Typed constant-size CP public instance (Phase 2+).
///
/// All per-instance data is compressed into digests. The verifier sees only
/// this fixed-size structure; the CP-SNARK proves consistency with the full
/// transcript in the witness.
#[derive(Debug, Clone)]
pub struct CpPublicInstance {
    pub fold_root: Digest32,
    pub fs_root: Digest32,
    pub transcript_seed_digest: Digest32,
    pub challenge_digest: Digest32,
    pub folded_instance: FoldedInstance,
}

/// Encode a **constant-size** CP-SNARK instance using compressed digests.
///
/// Phase 2 version: includes `fs_root` and `transcript_seed_digest` alongside
/// `fold_root` and `challenge_digest`. The instance size is independent of k.
///
/// The binding challenge is derived from a SHA-256 hash of all digests and the
/// folded instance — NOT from transcript state. This is what makes the verifier
/// O(1): it never needs to replay FS commitments into a transcript.
pub fn encode_cp_instance_compressed(
    fold_root: &Digest32,
    folded_instance: &FoldedInstance,
    challenge_digest: &Digest32,
    fs_root: &Digest32,
    transcript_seed_digest: &Digest32,
) -> Vec<u8> {
    let folded_bytes = encode_folded_instance(folded_instance);

    let mut instance = Vec::new();

    // fold_root (32 bytes)
    instance.extend_from_slice(fold_root);

    // fs_root (32 bytes) — binds all FS commitments
    instance.extend_from_slice(fs_root);

    // transcript_seed_digest (32 bytes) — binds public inputs + R1CS metadata
    instance.extend_from_slice(transcript_seed_digest);

    // Folded instance (constant size, depends on kappa/n_in/T — NOT on k)
    instance.extend_from_slice(&(folded_bytes.len() as u64).to_le_bytes());
    instance.extend_from_slice(&folded_bytes);

    // challenge_digest (32 bytes)
    instance.extend_from_slice(challenge_digest);

    // Binding challenge: SHA-256 over all digest components.
    // This replaces the transcript-based binding, making verification O(1).
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cp-bind");
    hasher.update(fold_root);
    hasher.update(fs_root);
    hasher.update(transcript_seed_digest);
    hasher.update(challenge_digest);
    hasher.update(&folded_bytes);
    let binding_challenge: [u8; 32] = hasher.finalize().into();
    instance.extend_from_slice(&binding_challenge);

    instance
}

/// Encode the full CP backend instance with R1CS prefix + digest binding trailer.
///
/// The prefix preserves CP-R1CS layout for backends that enforce folding
/// constraints over instance variables. The trailer binds all digest fields so
/// the CP proof is tied to the full constant-size public instance.
pub fn encode_cp_backend_instance(
    cp_public_instance: &CpPublicInstance,
    cp_layout: &CpR1csLayout,
) -> Vec<u8> {
    let mut instance =
        super::r1cs::encode_cp_instance_r1cs(&cp_public_instance.folded_instance, cp_layout);
    let binding = encode_cp_instance_compressed(
        &cp_public_instance.fold_root,
        &cp_public_instance.folded_instance,
        &cp_public_instance.challenge_digest,
        &cp_public_instance.fs_root,
        &cp_public_instance.transcript_seed_digest,
    );
    instance.extend_from_slice(&(binding.len() as u64).to_le_bytes());
    instance.extend_from_slice(&binding);
    instance
}

/// Encode the CP-SNARK witness with all transcript data (Phase 2+).
///
/// The witness contains everything the verifier used to check in O(k):
/// - FS commitments + openings + messages (moved from verifier to CP witness)
/// - fold inputs (moved in Phase 1)
/// - folding transcript
/// - fold_root and fs_root for self-consistency
pub fn encode_cp_witness_compressed(
    openings: &[Vec<u8>],
    folding_transcript: &[u8],
    fold_inputs: &[FoldInput],
    fold_root: &Digest32,
    fs_commitments: &[Vec<u8>],
    fs_messages: &[Vec<u8>],
    fs_root: &Digest32,
) -> Vec<u8> {
    let mut witness = Vec::new();

    // Openings
    witness.extend_from_slice(&(openings.len() as u64).to_le_bytes());
    for opening in openings {
        witness.extend_from_slice(&(opening.len() as u64).to_le_bytes());
        witness.extend_from_slice(opening);
    }

    // Folding transcript
    witness.extend_from_slice(&(folding_transcript.len() as u64).to_le_bytes());
    witness.extend_from_slice(folding_transcript);

    // Fold inputs
    witness.extend_from_slice(&(fold_inputs.len() as u64).to_le_bytes());
    for fi in fold_inputs {
        witness.extend_from_slice(&(fi.commitment_bytes.len() as u64).to_le_bytes());
        witness.extend_from_slice(&fi.commitment_bytes);

        witness.extend_from_slice(&(fi.public_input.len() as u64).to_le_bytes());
        for &v in &fi.public_input {
            witness.extend_from_slice(&v.to_le_bytes());
        }

        witness.extend_from_slice(&(fi.eval_values_bytes.len() as u64).to_le_bytes());
        witness.extend_from_slice(&fi.eval_values_bytes);
    }

    // fold_root for relation self-consistency
    witness.extend_from_slice(fold_root);

    // FS commitments (moved from verifier to CP witness in Phase 2)
    witness.extend_from_slice(&(fs_commitments.len() as u64).to_le_bytes());
    for c in fs_commitments {
        witness.extend_from_slice(&(c.len() as u64).to_le_bytes());
        witness.extend_from_slice(c);
    }

    // FS messages (moved from verifier to CP witness in Phase 2)
    witness.extend_from_slice(&(fs_messages.len() as u64).to_le_bytes());
    for m in fs_messages {
        witness.extend_from_slice(&(m.len() as u64).to_le_bytes());
        witness.extend_from_slice(m);
    }

    // fs_root for self-consistency
    witness.extend_from_slice(fs_root);

    witness
}

/// Serialize a commitment to bytes (for building `FoldInput`s).
pub fn encode_commitment_to_bytes(commitment: &crate::commitment::Commitment) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_commitment(&mut buf, commitment);
    buf
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

/// Serialize output-SNARK context: R1CS matrices + ring parameters.
///
/// This uses the WHIR context format (header "WHIR") so that the WHIR backend
/// can parse it via `deserialize_context`. Other backends ignore context.
pub fn serialize_output_context(r1cs: &R1CSMatrices, q: u64, d: usize) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(b"WHIR");
    buf.extend_from_slice(&q.to_le_bytes());
    buf.extend_from_slice(&(d as u64).to_le_bytes());
    buf.extend_from_slice(&(r1cs.num_public as u64).to_le_bytes());
    buf.push(1); // is_output_snark = true
    buf.push(0); // is_cp_snark = false

    buf.extend_from_slice(&(r1cs.num_constraints as u64).to_le_bytes());
    buf.extend_from_slice(&(r1cs.num_variables as u64).to_le_bytes());
    buf.extend_from_slice(&(r1cs.num_public as u64).to_le_bytes());

    serialize_sparse_matrix_raw(&mut buf, &r1cs.a.entries);
    serialize_sparse_matrix_raw(&mut buf, &r1cs.b.entries);
    serialize_sparse_matrix_raw(&mut buf, &r1cs.c.entries);

    buf
}

/// Serialize CP-SNARK context: R1CS matrices encoding folding constraints.
///
/// Same WHIR context format as `serialize_output_context`, but with
/// `is_output_snark = false` and `is_cp_snark = true`.
pub fn serialize_cp_context(r1cs: &R1CSMatrices, q: u64, d: usize) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(b"WHIR");
    buf.extend_from_slice(&q.to_le_bytes());
    buf.extend_from_slice(&(d as u64).to_le_bytes());
    buf.extend_from_slice(&(r1cs.num_public as u64).to_le_bytes());
    buf.push(0); // is_output_snark = false
    buf.push(1); // is_cp_snark = true

    buf.extend_from_slice(&(r1cs.num_constraints as u64).to_le_bytes());
    buf.extend_from_slice(&(r1cs.num_variables as u64).to_le_bytes());
    buf.extend_from_slice(&(r1cs.num_public as u64).to_le_bytes());

    serialize_sparse_matrix_raw(&mut buf, &r1cs.a.entries);
    serialize_sparse_matrix_raw(&mut buf, &r1cs.b.entries);
    serialize_sparse_matrix_raw(&mut buf, &r1cs.c.entries);

    buf
}

fn serialize_sparse_matrix_raw(buf: &mut Vec<u8>, entries: &[(usize, usize, i64)]) {
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for &(row, col, val) in entries {
        buf.extend_from_slice(&(row as u64).to_le_bytes());
        buf.extend_from_slice(&(col as u64).to_le_bytes());
        buf.extend_from_slice(&val.to_le_bytes());
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
