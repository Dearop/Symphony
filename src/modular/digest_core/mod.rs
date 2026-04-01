//! Digest utilities for transcript/CP public bindings.

pub use crate::folding::digest::{Digest32, FoldInput};

/// Digest of all FS commitments.
pub fn digest_fs_root(commitments: &[Vec<u8>]) -> Digest32 {
    crate::folding::digest::digest_fs_commitments(commitments)
}

/// Digest of all fold inputs.
pub fn digest_fold_root(inputs: &[FoldInput]) -> Digest32 {
    crate::folding::digest::digest_fold_inputs(inputs)
}

/// Digest of all derived challenges.
pub fn digest_challenge_digest(challenges: &[Vec<u8>]) -> Digest32 {
    crate::folding::digest::digest_challenges(challenges)
}

/// Digest of transcript seed metadata (public inputs + R1CS dimensions).
pub fn digest_transcript_seed(
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
) -> Digest32 {
    crate::folding::digest::digest_transcript_seed(public_inputs, r1cs_m, r1cs_n, r1cs_pub)
}
