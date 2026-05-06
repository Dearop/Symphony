//! Digest utilities for transcript/CP public bindings.

pub use crate::folding::digest::{Digest32, FoldInput};
use crate::transcript_core::Sha256ChallengeDeriver;

/// Public digest scheme used by the verifier-facing proof boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDigestScheme {
    /// Legacy/default SHA-256 binding used by existing CP/full-verifier paths.
    Sha256,
    /// Field-native Poseidon2 over BabyBear, serialized as 8 little-endian
    /// canonical BabyBear limbs. This is the intended WHIR typed-CP scheme.
    #[cfg(feature = "whir")]
    Poseidon2BabyBear,
}

/// Digest of all FS commitments.
pub fn digest_fs_root(commitments: &[Vec<u8>]) -> Digest32 {
    crate::folding::digest::digest_fs_commitments(commitments)
}

/// Digest of all FS commitments with an explicit public digest scheme.
pub fn digest_fs_root_with_scheme(scheme: PublicDigestScheme, commitments: &[Vec<u8>]) -> Digest32 {
    match scheme {
        PublicDigestScheme::Sha256 => digest_fs_root(commitments),
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => poseidon_digest_fs_root(commitments),
    }
}

/// Domain-separated digest helper for new public-boundary objects.
#[must_use]
pub fn digest_domain_with_scheme(
    scheme: PublicDigestScheme,
    domain: &[u8],
    body: &[u8],
) -> Digest32 {
    match scheme {
        PublicDigestScheme::Sha256 => {
            use sha2::{Digest, Sha256};

            let mut h = Sha256::new();
            h.update(b"symphony-public-domain-digest-v1");
            h.update((domain.len() as u64).to_le_bytes());
            h.update(domain);
            h.update((body.len() as u64).to_le_bytes());
            h.update(body);
            h.finalize().into()
        }
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => poseidon_babybear::digest_bytes(domain, body),
    }
}

/// Digest of all fold inputs.
pub fn digest_fold_root(inputs: &[FoldInput]) -> Digest32 {
    crate::folding::digest::digest_fold_inputs(inputs)
}

/// Digest of all fold inputs with an explicit public digest scheme.
pub fn digest_fold_root_with_scheme(scheme: PublicDigestScheme, inputs: &[FoldInput]) -> Digest32 {
    match scheme {
        PublicDigestScheme::Sha256 => digest_fold_root(inputs),
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => poseidon_digest_fold_root(inputs),
    }
}

/// Digest of all derived challenges.
pub fn digest_challenge_digest(challenges: &[Vec<u8>]) -> Digest32 {
    crate::folding::digest::digest_challenges(challenges)
}

/// Digest of all derived challenges with an explicit public digest scheme.
pub fn digest_challenge_digest_with_scheme(
    scheme: PublicDigestScheme,
    challenges: &[Vec<u8>],
) -> Digest32 {
    match scheme {
        PublicDigestScheme::Sha256 => digest_challenge_digest(challenges),
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => poseidon_digest_challenge_digest(challenges),
    }
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

/// Digest of transcript seed metadata with an explicit public digest scheme.
pub fn digest_transcript_seed_with_scheme(
    scheme: PublicDigestScheme,
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
) -> Digest32 {
    match scheme {
        PublicDigestScheme::Sha256 => {
            digest_transcript_seed(public_inputs, r1cs_m, r1cs_n, r1cs_pub)
        }
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => {
            poseidon_digest_transcript_seed(public_inputs, r1cs_m, r1cs_n, r1cs_pub)
        }
    }
}

/// Commit to a Fiat-Shamir message under the selected public digest scheme.
#[must_use]
pub fn fs_commit_with_scheme(scheme: PublicDigestScheme, message: &[u8]) -> (Digest32, Digest32) {
    use crate::fiat_shamir::FSCommitment;

    match scheme {
        PublicDigestScheme::Sha256 => {
            let commitment_scheme = crate::fiat_shamir::hash_commitment::HashCommitment::new();
            commitment_scheme.commit(message)
        }
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => {
            use rand::Rng;
            let mut opening = [0u8; 32];
            rand::rng().fill_bytes(&mut opening);
            (poseidon_fs_commitment(message, &opening), opening)
        }
    }
}

/// Verify a Fiat-Shamir commitment under the selected public digest scheme.
#[must_use]
pub fn fs_verify_with_scheme(
    scheme: PublicDigestScheme,
    commitment: &Digest32,
    message: &[u8],
    opening: &Digest32,
) -> bool {
    use crate::fiat_shamir::FSCommitment;

    match scheme {
        PublicDigestScheme::Sha256 => {
            let commitment_scheme = crate::fiat_shamir::hash_commitment::HashCommitment::new();
            commitment_scheme.verify(commitment, message, opening)
        }
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => {
            poseidon_fs_commitment(message, opening) == *commitment
        }
    }
}

/// Derive fixed-width Fiat-Shamir challenges under the selected public digest scheme.
#[must_use]
pub fn derive_challenges_with_scheme(
    scheme: PublicDigestScheme,
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
    fs_commitments: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let transcript = crate::cp_relation_core::cp_relation_transcript_bytes(
        public_inputs,
        r1cs_m,
        r1cs_n,
        r1cs_pub,
        fs_commitments,
    );
    match scheme {
        PublicDigestScheme::Sha256 => {
            let deriver = Sha256ChallengeDeriver;
            deriver.derive_fixed_32(b"symphony-v1", &transcript, fs_commitments.len())
        }
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => (0..fs_commitments.len())
            .map(|idx| {
                let mut body = Vec::with_capacity(transcript.len() + 8);
                body.extend_from_slice(&(idx as u64).to_le_bytes());
                body.extend_from_slice(&transcript);
                poseidon_babybear::digest_bytes(b"challenge", &body).to_vec()
            })
            .collect(),
    }
}

#[cfg(feature = "whir")]
mod poseidon_babybear {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
    use rand::{rngs::ChaCha20Rng, SeedableRng};
    use sha2::{Digest, Sha256};

    use super::{Digest32, FoldInput};

    type PoseidonDigestSponge = PaddingFreeSponge<Poseidon2BabyBear<16>, 16, 8, 8>;

    pub(super) fn digest_bytes(domain: &[u8], body: &[u8]) -> Digest32 {
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(b"symphony-poseidon2-babybear-public-digest-v1");
        seed_hasher.update((domain.len() as u64).to_le_bytes());
        seed_hasher.update(domain);
        let seed: [u8; 32] = seed_hasher.finalize().into();

        let mut rng = ChaCha20Rng::from_seed(seed);
        let perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
        let sponge = PoseidonDigestSponge::new(perm);

        let mut input = Vec::with_capacity(domain.len() + body.len() + 24);
        input.extend_from_slice(b"symphony-v2");
        input.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        input.extend_from_slice(domain);
        input.extend_from_slice(&(body.len() as u64).to_le_bytes());
        input.extend_from_slice(body);

        let elems = bytes_to_babybear(&input);
        let digest_elems: [BabyBear; 8] = sponge.hash_iter(elems);
        serialize_digest(digest_elems)
    }

    pub(crate) fn digest_input_elems(domain: &[u8], body: &[u8]) -> Vec<BabyBear> {
        let mut input = Vec::with_capacity(domain.len() + body.len() + 24);
        input.extend_from_slice(b"symphony-v2");
        input.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        input.extend_from_slice(domain);
        input.extend_from_slice(&(body.len() as u64).to_le_bytes());
        input.extend_from_slice(body);
        bytes_to_babybear(&input)
    }

    pub(crate) fn serialize_digest_elems(digest: [BabyBear; 8]) -> Digest32 {
        serialize_digest(digest)
    }

    pub(super) fn fs_root(commitments: &[Vec<u8>]) -> Digest32 {
        let mut body = Vec::new();
        body.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
        for commitment in commitments {
            body.extend_from_slice(&(commitment.len() as u64).to_le_bytes());
            body.extend_from_slice(commitment);
        }
        digest_bytes(b"fs-root", &body)
    }

    pub(super) fn fold_root(inputs: &[FoldInput]) -> Digest32 {
        let mut body = Vec::new();
        body.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
        for input in inputs {
            body.extend_from_slice(&(input.commitment_bytes.len() as u64).to_le_bytes());
            body.extend_from_slice(&input.commitment_bytes);
            body.extend_from_slice(&(input.public_input.len() as u64).to_le_bytes());
            for &value in &input.public_input {
                body.extend_from_slice(&value.to_le_bytes());
            }
            body.extend_from_slice(&(input.eval_values_bytes.len() as u64).to_le_bytes());
            body.extend_from_slice(&input.eval_values_bytes);
        }
        digest_bytes(b"fold-root", &body)
    }

    pub(super) fn challenge_digest(challenges: &[Vec<u8>]) -> Digest32 {
        let mut body = Vec::new();
        body.extend_from_slice(&(challenges.len() as u64).to_le_bytes());
        for challenge in challenges {
            body.extend_from_slice(&(challenge.len() as u64).to_le_bytes());
            body.extend_from_slice(challenge);
        }
        digest_bytes(b"challenge-digest", &body)
    }

    pub(super) fn transcript_seed(
        public_inputs: &[Vec<i64>],
        r1cs_m: usize,
        r1cs_n: usize,
        r1cs_pub: usize,
    ) -> Digest32 {
        let mut body = Vec::new();
        body.extend_from_slice(&(public_inputs.len() as u64).to_le_bytes());
        for public_input in public_inputs {
            body.extend_from_slice(&(public_input.len() as u64).to_le_bytes());
            for &value in public_input {
                body.extend_from_slice(&value.to_le_bytes());
            }
        }
        body.extend_from_slice(&(r1cs_m as u64).to_le_bytes());
        body.extend_from_slice(&(r1cs_n as u64).to_le_bytes());
        body.extend_from_slice(&(r1cs_pub as u64).to_le_bytes());
        digest_bytes(b"transcript-seed", &body)
    }

    fn bytes_to_babybear(data: &[u8]) -> Vec<BabyBear> {
        let mut result = Vec::with_capacity(data.len() / 3 + 2);
        for chunk in data.chunks(3) {
            let mut value = 0u32;
            for (idx, &byte) in chunk.iter().enumerate() {
                value |= (byte as u32) << (8 * idx);
            }
            result.push(BabyBear::from_u32(value));
        }
        assert!(
            data.len() < (1u64 << 31) as usize,
            "data too large for injective BabyBear digest encoding"
        );
        result.push(BabyBear::from_u32(data.len() as u32));
        result
    }

    fn serialize_digest(digest: [BabyBear; 8]) -> Digest32 {
        let mut out = [0u8; 32];
        for (idx, elem) in digest.iter().enumerate() {
            out[idx * 4..idx * 4 + 4].copy_from_slice(&elem.as_canonical_u32().to_le_bytes());
        }
        out
    }
}

#[cfg(feature = "whir")]
pub(crate) fn poseidon_digest_input_elems(
    domain: &[u8],
    body: &[u8],
) -> Vec<p3_baby_bear::BabyBear> {
    poseidon_babybear::digest_input_elems(domain, body)
}

#[cfg(feature = "whir")]
pub(crate) fn serialize_poseidon_digest_elems(digest: [p3_baby_bear::BabyBear; 8]) -> Digest32 {
    poseidon_babybear::serialize_digest_elems(digest)
}

#[cfg(feature = "whir")]
fn poseidon_fs_commitment(message: &[u8], opening: &Digest32) -> Digest32 {
    let mut body = Vec::with_capacity(8 + message.len() + opening.len());
    body.extend_from_slice(&(message.len() as u64).to_le_bytes());
    body.extend_from_slice(message);
    body.extend_from_slice(opening);
    poseidon_babybear::digest_bytes(b"fs-commit", &body)
}

#[cfg(feature = "whir")]
pub fn poseidon_digest_fs_root(commitments: &[Vec<u8>]) -> Digest32 {
    poseidon_babybear::fs_root(commitments)
}

#[cfg(feature = "whir")]
pub fn poseidon_digest_fold_root(inputs: &[FoldInput]) -> Digest32 {
    poseidon_babybear::fold_root(inputs)
}

#[cfg(feature = "whir")]
pub fn poseidon_digest_challenge_digest(challenges: &[Vec<u8>]) -> Digest32 {
    poseidon_babybear::challenge_digest(challenges)
}

#[cfg(feature = "whir")]
pub fn poseidon_digest_transcript_seed(
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
) -> Digest32 {
    poseidon_babybear::transcript_seed(public_inputs, r1cs_m, r1cs_n, r1cs_pub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_scheme_matches_legacy_helpers() {
        let commitments = vec![vec![1, 2, 3], vec![4, 5]];
        let inputs = vec![FoldInput {
            commitment_bytes: vec![1],
            public_input: vec![2],
            eval_values_bytes: vec![3],
        }];
        let challenges = vec![vec![9; 32]];
        let public_inputs = vec![vec![7]];

        assert_eq!(
            digest_fs_root_with_scheme(PublicDigestScheme::Sha256, &commitments),
            digest_fs_root(&commitments)
        );
        assert_eq!(
            digest_fold_root_with_scheme(PublicDigestScheme::Sha256, &inputs),
            digest_fold_root(&inputs)
        );
        assert_eq!(
            digest_challenge_digest_with_scheme(PublicDigestScheme::Sha256, &challenges),
            digest_challenge_digest(&challenges)
        );
        assert_eq!(
            digest_transcript_seed_with_scheme(PublicDigestScheme::Sha256, &public_inputs, 1, 2, 1),
            digest_transcript_seed(&public_inputs, 1, 2, 1)
        );
    }

    #[cfg(feature = "whir")]
    #[test]
    fn poseidon_scheme_is_deterministic_and_domain_separated() {
        let commitments = vec![vec![1, 2, 3], vec![4, 5]];
        let root_a =
            digest_fs_root_with_scheme(PublicDigestScheme::Poseidon2BabyBear, &commitments);
        let root_b =
            digest_fs_root_with_scheme(PublicDigestScheme::Poseidon2BabyBear, &commitments);
        let transcript = digest_transcript_seed_with_scheme(
            PublicDigestScheme::Poseidon2BabyBear,
            &[vec![1]],
            1,
            2,
            1,
        );

        assert_eq!(root_a, root_b);
        assert_ne!(root_a, transcript);
        assert_ne!(root_a, digest_fs_root(&commitments));
    }
}
