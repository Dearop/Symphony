//! CP relation public/witness model and consistency checks.

use crate::commitment::{opening, AjtaiParams};
use crate::digest_core::{
    digest_challenge_digest, digest_fold_root, digest_fs_root, digest_transcript_seed, Digest32,
    FoldInput,
};
use crate::fiat_shamir::hash_commitment::HashCommitment;
use crate::fiat_shamir::FSCommitment;
use crate::folding::{
    folded_output_instance_from_proof, folded_output_witness_from_folded, FoldedInstance,
    FoldedOutputInstance, FoldedOutputWitness,
};
use crate::r1cs::generalized::{check_hadamard, GeneralizedR1CSParams};
use crate::r1cs::R1CSMatrices;
use crate::ring::RingElement;
use crate::snark::cp_snark::{encode_commitment_to_bytes, encode_gr1cs_round_message};
use crate::transcript_core::{
    tags, CanonicalTranscriptCodec, Sha256ChallengeDeriver, TranscriptCodec, TranscriptEvent,
    TranscriptSchema,
};

/// Constant-size CP public instance.
#[derive(Debug, Clone)]
pub struct CpPublicInstance {
    pub fs_root: Digest32,
    pub fold_root: Digest32,
    pub challenge_digest: Digest32,
    pub transcript_seed_digest: Digest32,
    pub x_folded: FoldedInstance,
    pub folded_output: FoldedOutputInstance,
}

/// CP witness-side bundle used by the CP relation.
#[derive(Debug, Clone)]
pub struct CpWitnessBundle {
    pub transcript_bytes: Vec<u8>,
    pub fs_commitments: Vec<Vec<u8>>,
    pub fs_openings: Vec<Vec<u8>>,
    pub fs_messages: Vec<Vec<u8>>,
    pub fold_inputs: Vec<FoldInput>,
    pub original_witnesses: Vec<crate::ring::RingVector>,
    pub folded_output: FoldedInstance,
    pub folded_output_instance: FoldedOutputInstance,
    pub folded_output_witness: FoldedOutputWitness,
    pub folded_witness: crate::folding::FoldedWitness,
    pub folding_proof: crate::folding::FoldingProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpRelationError {
    TranscriptParse,
    LengthMismatch,
    TranscriptSeedMismatch,
    FsRootMismatch,
    FsOpeningMismatch,
    FsMessageMismatch,
    FoldRootMismatch,
    ChallengeDigestMismatch,
    FoldedOutputMismatch,
}

pub struct CpRelation;

fn check_original_witness_validity(
    public_inputs: &[Vec<i64>],
    witness: &CpWitnessBundle,
    ajtai: &AjtaiParams,
    r1cs: &R1CSMatrices,
    input_bound: u64,
) -> Result<(), CpRelationError> {
    if public_inputs.len() != witness.original_witnesses.len()
        || public_inputs.len() != witness.folding_proof.commitments.len()
    {
        return Err(CpRelationError::LengthMismatch);
    }

    let generalized_params = GeneralizedR1CSParams {
        n_in: r1cs.num_public,
        n_w: r1cs.num_variables.saturating_sub(r1cs.num_public),
        ell_h: crate::params::D,
        bound: input_bound,
        matrices: r1cs.clone(),
    };

    for ((commitment, public_input), witness_part) in witness
        .folding_proof
        .commitments
        .iter()
        .zip(public_inputs.iter())
        .zip(witness.original_witnesses.iter())
    {
        if public_input.len() != r1cs.num_public {
            return Err(CpRelationError::FoldedOutputMismatch);
        }
        if witness_part.len() + public_input.len() != ajtai.n {
            return Err(CpRelationError::FoldedOutputMismatch);
        }

        let full_witness = opening::assemble_full_witness(public_input, witness_part);
        if !opening::verify_strict(ajtai, commitment, &full_witness, u128::MAX) {
            return Err(CpRelationError::FoldedOutputMismatch);
        }

        let public_ring: Vec<RingElement> = public_input
            .iter()
            .copied()
            .map(RingElement::from_constant)
            .collect();
        if !check_hadamard(
            &generalized_params,
            &public_ring,
            &witness_part.elements,
            ajtai.q,
        ) {
            return Err(CpRelationError::FoldedOutputMismatch);
        }
    }

    Ok(())
}

fn derive_transcript_public_inputs(
    transcript: &TranscriptSchema,
) -> Result<Vec<Vec<i64>>, CpRelationError> {
    let mut public_inputs = Vec::new();
    for event in &transcript.events {
        if event.tag != tags::PUBLIC_INPUT || event.label.as_slice() != b"public-input" {
            continue;
        }
        if event.payload.len() % 8 != 0 {
            return Err(CpRelationError::TranscriptParse);
        }
        let mut pi = Vec::with_capacity(event.payload.len() / 8);
        for chunk in event.payload.chunks_exact(8) {
            let arr: [u8; 8] = chunk
                .try_into()
                .map_err(|_| CpRelationError::TranscriptParse)?;
            pi.push(i64::from_le_bytes(arr));
        }
        public_inputs.push(pi);
    }
    Ok(public_inputs)
}

fn derive_transcript_r1cs_meta(
    transcript: &TranscriptSchema,
) -> Result<(usize, usize, usize), CpRelationError> {
    let mut m = None;
    let mut n = None;
    let mut n_pub = None;
    for event in &transcript.events {
        if event.tag != tags::R1CS_META || event.payload.len() != 8 {
            continue;
        }
        let arr: [u8; 8] = event
            .payload
            .as_slice()
            .try_into()
            .map_err(|_| CpRelationError::TranscriptParse)?;
        let value = usize::try_from(u64::from_le_bytes(arr))
            .map_err(|_| CpRelationError::TranscriptParse)?;
        match event.label.as_slice() {
            b"r1cs-m" => m = Some(value),
            b"r1cs-n" => n = Some(value),
            b"r1cs-pub" => n_pub = Some(value),
            _ => {}
        }
    }
    match (m, n, n_pub) {
        (Some(m), Some(n), Some(n_pub)) => Ok((m, n, n_pub)),
        _ => Err(CpRelationError::TranscriptParse),
    }
}

pub(crate) fn cp_relation_transcript_bytes(
    public_inputs: &[Vec<i64>],
    r1cs_m: usize,
    r1cs_n: usize,
    r1cs_pub: usize,
    fs_commitments: &[Vec<u8>],
) -> Vec<u8> {
    let mut schema = TranscriptSchema::new(b"symphony-v1");
    for pi in public_inputs {
        let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
        schema.push_event(TranscriptEvent::new(
            tags::PUBLIC_INPUT,
            b"public-input",
            &bytes,
        ));
    }
    schema.push_event(TranscriptEvent::new(
        tags::R1CS_META,
        b"r1cs-m",
        &(r1cs_m as u64).to_le_bytes(),
    ));
    schema.push_event(TranscriptEvent::new(
        tags::R1CS_META,
        b"r1cs-n",
        &(r1cs_n as u64).to_le_bytes(),
    ));
    schema.push_event(TranscriptEvent::new(
        tags::R1CS_META,
        b"r1cs-pub",
        &(r1cs_pub as u64).to_le_bytes(),
    ));
    for comm in fs_commitments {
        schema.push_event(TranscriptEvent::new(
            tags::FS_COMMITMENT,
            b"fs-commitment",
            comm,
        ));
    }
    CanonicalTranscriptCodec.encode(&schema)
}

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
        let transcript = codec
            .decode(&witness.transcript_bytes)
            .map_err(|_| CpRelationError::TranscriptParse)?;

        let public_inputs = derive_transcript_public_inputs(&transcript)?;
        let (r1cs_m, r1cs_n, r1cs_pub) = derive_transcript_r1cs_meta(&transcript)?;
        if digest_transcript_seed(&public_inputs, r1cs_m, r1cs_n, r1cs_pub)
            != public.transcript_seed_digest
        {
            return Err(CpRelationError::TranscriptSeedMismatch);
        }

        let reconstructed_transcript = cp_relation_transcript_bytes(
            &public_inputs,
            r1cs_m,
            r1cs_n,
            r1cs_pub,
            &witness.fs_commitments,
        );
        if reconstructed_transcript != witness.transcript_bytes {
            return Err(CpRelationError::TranscriptParse);
        }

        if digest_fs_root(&witness.fs_commitments) != public.fs_root {
            return Err(CpRelationError::FsRootMismatch);
        }

        let scheme = HashCommitment::new();
        for ((commitment, opening_bytes), message) in witness
            .fs_commitments
            .iter()
            .zip(witness.fs_openings.iter())
            .zip(witness.fs_messages.iter())
        {
            let commitment_arr: [u8; 32] = commitment
                .as_slice()
                .try_into()
                .map_err(|_| CpRelationError::FsOpeningMismatch)?;
            let opening_arr: [u8; 32] = opening_bytes
                .as_slice()
                .try_into()
                .map_err(|_| CpRelationError::FsOpeningMismatch)?;
            if !scheme.verify(&commitment_arr, message, &opening_arr) {
                return Err(CpRelationError::FsOpeningMismatch);
            }
        }

        let expected_messages: Vec<Vec<u8>> = witness
            .folding_proof
            .gr1cs_proofs
            .iter()
            .map(encode_gr1cs_round_message)
            .collect();
        if expected_messages != witness.fs_messages {
            return Err(CpRelationError::FsMessageMismatch);
        }

        let expected_fold_inputs: Vec<FoldInput> = witness
            .folding_proof
            .commitments
            .iter()
            .zip(public_inputs.iter())
            .zip(witness.folding_proof.gr1cs_proofs.iter())
            .map(|((c, pi), gr1cs)| FoldInput {
                commitment_bytes: encode_commitment_to_bytes(c),
                public_input: pi.clone(),
                eval_values_bytes: encode_gr1cs_round_message(gr1cs),
            })
            .collect();
        if expected_fold_inputs != witness.fold_inputs
            || digest_fold_root(&witness.fold_inputs) != public.fold_root
        {
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

        let expected_folded_output = folded_output_instance_from_proof(&witness.folding_proof);
        let expected_folded_output_witness =
            folded_output_witness_from_folded(&witness.folded_witness);
        if witness.folded_output != public.x_folded
            || public.folded_output.folded_instance != public.x_folded
            || witness.folded_output_instance.folded_instance != public.x_folded
            || witness.folded_output_instance != public.folded_output
            || witness.folded_output_witness.folded_witness != witness.folded_witness
            || expected_folded_output != public.folded_output
            || expected_folded_output != witness.folded_output_instance
            || expected_folded_output_witness != witness.folded_output_witness
        {
            return Err(CpRelationError::FoldedOutputMismatch);
        }

        Ok(())
    }

    pub fn check_with_algebra(
        public: &CpPublicInstance,
        witness: &CpWitnessBundle,
        ajtai: &AjtaiParams,
        r1cs: &R1CSMatrices,
        input_bound: u64,
    ) -> Result<(), CpRelationError> {
        Self::check(public, witness)?;
        let codec = CanonicalTranscriptCodec;
        let transcript = codec
            .decode(&witness.transcript_bytes)
            .map_err(|_| CpRelationError::TranscriptParse)?;
        let public_inputs = derive_transcript_public_inputs(&transcript)?;
        check_original_witness_validity(&public_inputs, witness, ajtai, r1cs, input_bound)?;
        Ok(())
    }
}
