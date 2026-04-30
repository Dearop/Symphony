//! Digest utilities for compressing fold inputs and challenge sequences.
//!
//! These are used by the sublinear verifier path to replace linear-sized
//! public data with constant-sized roots/digests.

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
pub type Digest32 = [u8; 32];

/// Per-instance fold input — the data the verifier no longer sees directly.
///
/// Instead of exposing all fold inputs publicly, the prover computes
/// `fold_root = digest_fold_inputs(inputs)` and the CP witness proves
/// consistency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldInput {
    /// Serialized commitment (from `encode_commitment_to_bytes`).
    pub commitment_bytes: Vec<u8>,
    /// Per-instance public input values.
    pub public_input: Vec<i64>,
    /// Serialized evaluation values (from `encode_eval_values_to_bytes`).
    pub eval_values_bytes: Vec<u8>,
}

/// Hash all fold inputs into a single 32-byte root.
///
/// Encoding is canonical and deterministic:
/// `SHA-256(num_inputs || for each: len(c) || c || len(pi) || pi_le_bytes || len(ev) || ev)`
pub fn digest_fold_inputs(inputs: &[FoldInput]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update((inputs.len() as u64).to_le_bytes());

    for fi in inputs {
        hasher.update((fi.commitment_bytes.len() as u64).to_le_bytes());
        hasher.update(&fi.commitment_bytes);

        hasher.update((fi.public_input.len() as u64).to_le_bytes());
        for &v in &fi.public_input {
            hasher.update(v.to_le_bytes());
        }

        hasher.update((fi.eval_values_bytes.len() as u64).to_le_bytes());
        hasher.update(&fi.eval_values_bytes);
    }

    hasher.finalize().into()
}

/// Hash all Fiat-Shamir commitments into a single 32-byte root.
///
/// `SHA-256(num_commitments || for each: len(c) || c)`
///
/// Used by the sublinear verifier path (Phase 2) to replace
/// linear-sized FS commitment exposure with a constant-size digest.
pub fn digest_fs_commitments(commitments: &[Vec<u8>]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update((commitments.len() as u64).to_le_bytes());
    for c in commitments {
        hasher.update((c.len() as u64).to_le_bytes());
        hasher.update(c);
    }
    hasher.finalize().into()
}

/// Hash the static transcript metadata into a single 32-byte seed digest.
///
/// Binds the proof to a specific statement (public inputs + R1CS dimensions)
/// without the verifier replaying each item into a transcript object.
///
/// `SHA-256("symphony-v1" || num_inputs || for each pi: len || le_bytes
///          || r1cs_m || r1cs_n || r1cs_pub)`
pub fn digest_transcript_seed(
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(b"symphony-v1");

    hasher.update((public_inputs.len() as u64).to_le_bytes());
    for pi in public_inputs {
        hasher.update((pi.len() as u64).to_le_bytes());
        for &v in pi {
            hasher.update(v.to_le_bytes());
        }
    }

    hasher.update((r1cs_m as u64).to_le_bytes());
    hasher.update((r1cs_n as u64).to_le_bytes());
    hasher.update((r1cs_pub as u64).to_le_bytes());

    hasher.finalize().into()
}

/// Hash a sequence of derived challenges into a single 32-byte digest.
///
/// `SHA-256(num_challenges || for each: challenge_bytes)`
pub fn digest_challenges(challenges: &[Vec<u8>]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update((challenges.len() as u64).to_le_bytes());
    for ch in challenges {
        hasher.update(ch);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_fold_inputs_deterministic() {
        let inputs = vec![
            FoldInput {
                commitment_bytes: vec![1, 2, 3],
                public_input: vec![10, 20],
                eval_values_bytes: vec![4, 5],
            },
            FoldInput {
                commitment_bytes: vec![6, 7],
                public_input: vec![30],
                eval_values_bytes: vec![8, 9, 10],
            },
        ];
        let d1 = digest_fold_inputs(&inputs);
        let d2 = digest_fold_inputs(&inputs);
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_fold_inputs_differs_on_change() {
        let inputs_a = vec![FoldInput {
            commitment_bytes: vec![1, 2, 3],
            public_input: vec![10],
            eval_values_bytes: vec![4],
        }];
        let inputs_b = vec![FoldInput {
            commitment_bytes: vec![1, 2, 4], // changed
            public_input: vec![10],
            eval_values_bytes: vec![4],
        }];
        assert_ne!(digest_fold_inputs(&inputs_a), digest_fold_inputs(&inputs_b));
    }

    #[test]
    fn digest_challenges_deterministic() {
        let chs = vec![vec![0u8; 32], vec![1u8; 32]];
        assert_eq!(digest_challenges(&chs), digest_challenges(&chs));
    }

    #[test]
    fn digest_challenges_differs_on_change() {
        let a = vec![vec![0u8; 32]];
        let b = vec![vec![1u8; 32]];
        assert_ne!(digest_challenges(&a), digest_challenges(&b));
    }

    #[test]
    fn digest_fs_commitments_deterministic() {
        let comms = vec![vec![1u8; 32], vec![2u8; 32]];
        assert_eq!(digest_fs_commitments(&comms), digest_fs_commitments(&comms));
    }

    #[test]
    fn digest_fs_commitments_differs_on_change() {
        let a = vec![vec![1u8; 32]];
        let b = vec![vec![2u8; 32]];
        assert_ne!(digest_fs_commitments(&a), digest_fs_commitments(&b));
    }

    #[test]
    fn digest_transcript_seed_deterministic() {
        let pi = vec![vec![10i64, 20], vec![30]];
        let d1 = digest_transcript_seed(&pi, 4, 8, 2);
        let d2 = digest_transcript_seed(&pi, 4, 8, 2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_transcript_seed_differs_on_change() {
        let pi = vec![vec![10i64, 20]];
        let d1 = digest_transcript_seed(&pi, 4, 8, 2);
        let d2 = digest_transcript_seed(&pi, 5, 8, 2);
        assert_ne!(d1, d2);
    }
}
