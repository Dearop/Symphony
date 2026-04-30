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
        folded_output: proof.folded_output,
    };

    let witness_bundle = CpWitnessBundle {
        transcript_bytes: proof.witness_data.transcript_bytes,
        fs_commitments: proof.witness_data.fs_commitments,
        fs_openings: proof.witness_data.fs_openings,
        fs_messages: proof.witness_data.fs_messages,
        fold_inputs: proof.witness_data.fold_inputs,
        original_witnesses: proof.witness_data.original_witnesses,
        folded_output: cp_public_instance.x_folded.clone(),
        folded_output_instance: cp_public_instance.folded_output.clone(),
        folded_output_witness: proof.witness_data.folded_output_witness,
        folded_witness: proof.witness_data.folded_witness,
        folding_proof: proof.witness_data.folding_proof,
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
    _folding_proof: crate::folding::FoldingProof,
) -> SymphonyProof<S> {
    SymphonyProof {
        cp_proof: bundle.cp_proof,
        snark_proof: bundle.output_proof,
        folded_instance: bundle.cp_public_instance.x_folded,
        folded_output: bundle.cp_public_instance.folded_output,
        fold_root: bundle.cp_public_instance.fold_root,
        challenge_digest: bundle.cp_public_instance.challenge_digest,
        fs_root: bundle.cp_public_instance.fs_root,
        transcript_seed_digest: bundle.cp_public_instance.transcript_seed_digest,
        witness_data: ProofWitnessData {
            fs_commitments: bundle.witness_bundle.fs_commitments,
            fs_openings: bundle.witness_bundle.fs_openings,
            fs_messages: bundle.witness_bundle.fs_messages,
            transcript_bytes: bundle.witness_bundle.transcript_bytes,
            fold_inputs: bundle.witness_bundle.fold_inputs,
            original_witnesses: bundle.witness_bundle.original_witnesses,
            folding_proof: bundle.witness_bundle.folding_proof,
            folded_output_witness: bundle.witness_bundle.folded_output_witness,
            folded_witness: bundle.witness_bundle.folded_witness,
        },
    }
}
