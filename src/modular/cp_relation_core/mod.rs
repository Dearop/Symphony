//! CP relation public/witness model and consistency checks.

use crate::digest_core::{
    digest_challenge_digest, digest_fold_root, digest_fs_root, Digest32, FoldInput,
};
use crate::folding::FoldedInstance;
use crate::snark::cp_snark::encode_folded_instance;
use crate::transcript_core::{CanonicalTranscriptCodec, Sha256ChallengeDeriver, TranscriptCodec};

/// Constant-size CP public instance.
#[derive(Debug, Clone)]
pub struct CpPublicInstance {
    pub fs_root: Digest32,
    pub fold_root: Digest32,
    pub challenge_digest: Digest32,
    pub transcript_seed_digest: Digest32,
    pub x_folded: FoldedInstance,
}

/// CP witness-side bundle used by the CP relation.
#[derive(Debug, Clone)]
pub struct CpWitnessBundle {
    pub transcript_bytes: Vec<u8>,
    pub fs_commitments: Vec<Vec<u8>>,
    pub fs_openings: Vec<Vec<u8>>,
    pub fs_messages: Vec<Vec<u8>>,
    pub fold_inputs: Vec<FoldInput>,
    pub folded_output: FoldedInstance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpRelationError {
    TranscriptParse,
    LengthMismatch,
    FsRootMismatch,
    FoldRootMismatch,
    ChallengeDigestMismatch,
    FoldedOutputMismatch,
}

pub struct CpRelation;

impl CpRelation {
    pub fn check(
        public: &CpPublicInstance,
        witness: &CpWitnessBundle,
    ) -> Result<(), CpRelationError> {
        if witness.fs_commitments.len() != witness.fs_messages.len()
            || witness.fs_commitments.len() != witness.fs_openings.len()
        {
            return Err(CpRelationError::LengthMismatch);
        }

        let codec = CanonicalTranscriptCodec;
        if codec.decode(&witness.transcript_bytes).is_err() {
            return Err(CpRelationError::TranscriptParse);
        }

        if digest_fs_root(&witness.fs_commitments) != public.fs_root {
            return Err(CpRelationError::FsRootMismatch);
        }

        if digest_fold_root(&witness.fold_inputs) != public.fold_root {
            return Err(CpRelationError::FoldRootMismatch);
        }

        let deriver = Sha256ChallengeDeriver;
        let challenges = deriver.derive_fixed_32(
            b"symphony-v1",
            &witness.transcript_bytes,
            witness.fs_commitments.len(),
        );
        if digest_challenge_digest(&challenges) != public.challenge_digest {
            return Err(CpRelationError::ChallengeDigestMismatch);
        }

        if encode_folded_instance(&witness.folded_output)
            != encode_folded_instance(&public.x_folded)
        {
            return Err(CpRelationError::FoldedOutputMismatch);
        }

        Ok(())
    }
}
