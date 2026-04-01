//! Adapter between legacy `SymphonyProof` and modular `ProofBundle`.

use crate::cp_relation_core::{CpPublicInstance, CpWitnessBundle};
use crate::proof_orchestrator::ProofBundle;
use crate::snark::{BackendSnark, ProofWitnessData, SymphonyProof};

/// Convert legacy `SymphonyProof<S>` to `ProofBundle<S, S>`.
pub fn to_proof_bundle<S: BackendSnark>(proof: SymphonyProof<S>) -> ProofBundle<S, S> {
    let cp_public_instance = CpPublicInstance {
        fs_root: proof.fs_root,
        fold_root: proof.fold_root,
        challenge_digest: proof.challenge_digest,
        transcript_seed_digest: proof.transcript_seed_digest,
        x_folded: proof.folded_instance,
    };

    let witness_bundle = CpWitnessBundle {
        transcript_bytes: Vec::new(),
        fs_commitments: proof.witness_data.fs_commitments,
        fs_openings: proof.witness_data.fs_openings,
        fs_messages: proof.witness_data.fs_messages,
        fold_inputs: proof.witness_data.fold_inputs,
        folded_output: cp_public_instance.x_folded.clone(),
    };

    ProofBundle {
        cp_proof: proof.cp_proof,
        output_proof: proof.snark_proof,
        cp_public_instance,
        witness_bundle,
    }
}

pub fn from_proof_bundle<S: BackendSnark>(
    bundle: ProofBundle<S, S>,
    folding_proof: crate::folding::FoldingProof,
) -> SymphonyProof<S> {
    SymphonyProof {
        cp_proof: bundle.cp_proof,
        snark_proof: bundle.output_proof,
        folded_instance: bundle.cp_public_instance.x_folded,
        fold_root: bundle.cp_public_instance.fold_root,
        challenge_digest: bundle.cp_public_instance.challenge_digest,
        fs_root: bundle.cp_public_instance.fs_root,
        transcript_seed_digest: bundle.cp_public_instance.transcript_seed_digest,
        witness_data: ProofWitnessData {
            fs_commitments: bundle.witness_bundle.fs_commitments,
            fs_openings: bundle.witness_bundle.fs_openings,
            fs_messages: bundle.witness_bundle.fs_messages,
            fold_inputs: bundle.witness_bundle.fold_inputs,
            folding_proof,
        },
    }
}
