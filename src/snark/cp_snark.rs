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

#[path = "cp_snark/encoding.rs"]
mod encoding;
#[path = "cp_snark/r1cs.rs"]
mod r1cs;

pub use encoding::{
    encode_commitment_to_bytes, encode_cp_backend_instance, encode_cp_instance,
    encode_cp_instance_compressed, encode_cp_witness, encode_cp_witness_compressed,
    encode_folded_instance, encode_folded_witness, encode_folding_transcript_witness,
    encode_gr1cs_round_message, serialize_cp_context, serialize_output_context, CPRelation,
    CpPublicInstance,
};

pub use r1cs::{
    encode_cp_instance_r1cs, encode_cp_witness_r1cs, generate_cp_r1cs, mod_pow, CpR1csLayout,
};
