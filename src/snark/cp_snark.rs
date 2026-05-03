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
#[cfg(feature = "whir")]
#[path = "cp_snark/typed_r1cs.rs"]
pub mod typed_r1cs;

pub use encoding::{
    encode_commitment_to_bytes, encode_cp_backend_instance, encode_cp_instance,
    encode_cp_instance_compressed, encode_cp_witness, encode_cp_witness_compressed,
    encode_folded_instance, encode_folded_output_instance, encode_folded_output_witness,
    encode_folded_witness, encode_folding_transcript_witness, encode_gr1cs_round_message,
    encode_typed_cp_public_instance, encode_typed_cp_public_statement,
    encode_typed_cp_witness_bundle, serialize_cp_context, serialize_output_context, CPRelation,
    CpPublicInstance,
};

pub use r1cs::{
    encode_cp_instance_r1cs, encode_cp_witness_r1cs, fill_cp_wrap_range_bits, generate_cp_r1cs,
    mod_pow, CpR1csLayout,
};
#[cfg(feature = "whir")]
pub use typed_r1cs::{
    encode_original_statement_instance, encode_original_statement_witness,
    encode_poseidon2_digest_instance, encode_poseidon2_digest_witness,
    encode_poseidon2_private_digest_instance, encode_poseidon2_private_digest_witness,
    encode_typed_cp_digest_instance, encode_typed_cp_digest_witness,
    encode_typed_cp_partial_witness, encode_typed_cp_statement_instance,
    generate_original_statement_r1cs, generate_poseidon2_digest_r1cs,
    generate_poseidon2_private_digest_r1cs, generate_typed_cp_digest_r1cs,
    generate_typed_cp_digest_r1cs_compressed_fs,
    generate_typed_cp_digest_r1cs_compressed_fs_with_audit,
    generate_typed_cp_digest_r1cs_with_audit, generate_typed_cp_partial_r1cs,
    generate_typed_cp_statement_r1cs, poseidon2_babybear_digest_elems, poseidon_challenge_body,
    poseidon_challenge_digest_body, poseidon_fold_root_body, poseidon_fs_commit_body,
    poseidon_fs_root_body, poseidon_transcript_seed_body, typed_cp_digest_input_lengths,
    typed_cp_digest_input_lengths_from_setup, OriginalStatementR1csLayout,
    Poseidon2DigestR1csLayout, Poseidon2PrivateDigestR1csLayout, TypedCpAuditBlock,
    TypedCpAuditBlockKind, TypedCpAuditReport, TypedCpDigestBlockLayout, TypedCpDigestInputLengths,
    TypedCpDigestR1csLayout, TypedCpPartialR1csLayout, TypedCpStatementR1csLayout,
};
