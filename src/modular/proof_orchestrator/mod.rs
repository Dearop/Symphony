//! End-to-end proving/verifying flow with split CP/output backends.

use std::collections::HashMap;
use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::cp_backend_api::CpBackend;
use crate::cp_relation_core::{CpPublicInstance, CpWitnessBundle};
use crate::digest_core::{
    digest_challenge_digest, digest_fold_root, digest_fs_root, digest_transcript_seed, FoldInput,
};
use crate::fiat_shamir::hash_commitment::HashCommitment;
use crate::fiat_shamir::FSCommitment;
use crate::folding_core::{FoldSemantics, Statement, SymphonyFoldSemantics};
use crate::output_backend_api::OutputBackend;
use crate::params::SymphonyParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::ExtFieldContext;
use crate::ring::RingVector;
use crate::rok::range_proof::RangeProofParams;
use crate::snark::cp_snark::{self, CpR1csLayout};
use crate::snark::RelationDescription;
use crate::transcript_core::{
    tags, CanonicalTranscriptCodec, Sha256ChallengeDeriver, TranscriptCodec, TranscriptEvent,
    TranscriptSchema,
};

/// Generic proof bundle using separate CP and output backends.
#[derive(Debug, Clone)]
pub struct ProofBundle<CPB: CpBackend, OB: OutputBackend> {
    pub cp_proof: CPB::Proof,
    pub output_proof: OB::Proof,
    pub cp_public_instance: CpPublicInstance,
    pub witness_bundle: CpWitnessBundle,
}

pub struct Prover<CPB: CpBackend, OB: OutputBackend> {
    pub params: SymphonyParams,
    pub ajtai: crate::commitment::AjtaiParams,
    pub cp_pk: CPB::ProvingKey,
    pub output_pk: OB::ProvingKey,
    /// Cache of output proving keys keyed by serialized output context bytes.
    pub output_pk_cache: std::sync::Mutex<HashMap<Vec<u8>, OB::ProvingKey>>,
    pub cp_layout: CpR1csLayout,
    _marker: PhantomData<(CPB, OB)>,
}

pub struct Verifier<CPB: CpBackend, OB: OutputBackend> {
    pub params: SymphonyParams,
    pub ajtai: crate::commitment::AjtaiParams,
    pub cp_vk: CPB::VerifyingKey,
    pub output_vk: OB::VerifyingKey,
    /// Cache of output verifying keys keyed by serialized output context bytes.
    pub output_vk_cache: std::sync::Mutex<HashMap<Vec<u8>, OB::VerifyingKey>>,
    pub cp_layout: CpR1csLayout,
    _marker: PhantomData<(CPB, OB)>,
}

/// Encode the CP backend instance as:
/// `[cp_r1cs_instance || len(cp_public_binding) || cp_public_binding]`.
///
/// The first prefix preserves CP-R1CS index layout; the trailer binds the
/// full constant-size CP public instance (all four digests + folded output).
pub fn encode_cp_backend_instance(
    cp_public_instance: &CpPublicInstance,
    cp_layout: &CpR1csLayout,
) -> Vec<u8> {
    let mut instance = cp_snark::encode_cp_instance_r1cs(&cp_public_instance.x_folded, cp_layout);
    let binding = cp_snark::encode_cp_instance_compressed(
        &cp_public_instance.fold_root,
        &cp_public_instance.x_folded,
        &cp_public_instance.challenge_digest,
        &cp_public_instance.fs_root,
        &cp_public_instance.transcript_seed_digest,
    );
    instance.extend_from_slice(&(binding.len() as u64).to_le_bytes());
    instance.extend_from_slice(&binding);
    instance
}

fn range_proof_params(params: &SymphonyParams) -> RangeProofParams {
    RangeProofParams {
        lambda_pj: params.lambda_pj,
        ell_h: params.ell_h,
        d_prime: (params.d as i64) - 2,
        k_g: params.k_g(),
        input_bound: params.b_input(),
    }
}

fn build_transcript_bytes(
    public_inputs: &[Vec<i64>],
    r1cs: &R1CSMatrices,
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
        &(r1cs.num_constraints as u64).to_le_bytes(),
    ));
    schema.push_event(TranscriptEvent::new(
        tags::R1CS_META,
        b"r1cs-n",
        &(r1cs.num_variables as u64).to_le_bytes(),
    ));
    schema.push_event(TranscriptEvent::new(
        tags::R1CS_META,
        b"r1cs-pub",
        &(r1cs.num_public as u64).to_le_bytes(),
    ));

    for fs_comm in fs_commitments {
        schema.push_event(TranscriptEvent::new(
            tags::FS_COMMITMENT,
            b"fs-commitment",
            fs_comm,
        ));
    }

    CanonicalTranscriptCodec.encode(&schema)
}

impl<CPB: CpBackend, OB: OutputBackend> Prover<CPB, OB> {
    fn output_pk_for_context(&self, output_context: Vec<u8>) -> OB::ProvingKey {
        if let Some(pk) = self
            .output_pk_cache
            .lock()
            .expect("output_pk_cache mutex poisoned")
            .get(&output_context)
            .cloned()
        {
            return pk;
        }

        let relation = RelationDescription {
            num_instance_vars: self.params.n(),
            num_witness_vars: self.params.n(),
            num_constraints: self.params.m,
            context: Some(output_context.clone()),
        };
        let (pk, _) = OB::setup(&relation);

        self.output_pk_cache
            .lock()
            .expect("output_pk_cache mutex poisoned")
            .insert(output_context, pk.clone());
        pk
    }

    pub fn setup(params: SymphonyParams) -> (Self, Verifier<CPB, OB>) {
        params.validate();
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), params.q, params.ntt());

        let ext_ctx = ExtFieldContext::new(params.q);
        let (cp_r1cs, cp_layout) = cp_snark::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            params.m,
            ext_ctx.alpha,
            params.q,
        );
        let cp_context = cp_snark::serialize_cp_context(&cp_r1cs, params.q, params.d as usize);
        let cp_relation = RelationDescription {
            num_instance_vars: cp_layout.num_instance,
            num_witness_vars: cp_layout.num_variables - cp_layout.num_instance,
            num_constraints: cp_r1cs.num_constraints,
            context: Some(cp_context),
        };
        let (cp_pk, cp_vk) = CPB::setup(&cp_relation);

        let output_relation = RelationDescription {
            num_instance_vars: params.n(),
            num_witness_vars: params.n(),
            num_constraints: params.m,
            context: None,
        };
        let (output_pk, output_vk) = OB::setup(&output_relation);

        (
            Self {
                params: params.clone(),
                ajtai: ajtai.clone(),
                cp_pk,
                output_pk,
                output_pk_cache: std::sync::Mutex::new(HashMap::new()),
                cp_layout: cp_layout.clone(),
                _marker: PhantomData,
            },
            Verifier {
                params,
                ajtai,
                cp_vk,
                output_vk,
                output_vk_cache: std::sync::Mutex::new(HashMap::new()),
                cp_layout,
                _marker: PhantomData,
            },
        )
    }

    pub fn commit_witness(&self, witness: &RingVector) -> (Commitment, crate::commitment::Opening) {
        self.ajtai.commit(witness)
    }

    pub fn prove(
        &self,
        statements: &[(Commitment, Vec<i64>, RingVector)],
        r1cs: &R1CSMatrices,
    ) -> ProofBundle<CPB, OB> {
        let rp = range_proof_params(&self.params);
        let ext_ctx = ExtFieldContext::new(self.params.q);

        let fold_statements: Vec<Statement> = statements
            .iter()
            .map(|(c, pi, w)| Statement {
                commitment: c.clone(),
                public_input: pi.clone(),
                witness: w.clone(),
            })
            .collect();

        let semantics = SymphonyFoldSemantics;
        let (folding_proof, folded_witness, shared_challenges) =
            semantics.fold(&fold_statements, r1cs, &self.ajtai, &rp, &ext_ctx);

        let fs_messages: Vec<Vec<u8>> = folding_proof
            .gr1cs_proofs
            .iter()
            .map(cp_snark::encode_gr1cs_round_message)
            .collect();
        let fs_scheme = HashCommitment::new();
        let mut fs_commitments = Vec::with_capacity(fs_messages.len());
        let mut fs_openings = Vec::with_capacity(fs_messages.len());
        for message in &fs_messages {
            let (commitment, opening) = fs_scheme.commit(message);
            fs_commitments.push(commitment.to_vec());
            fs_openings.push(opening.to_vec());
        }

        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();
        let transcript_seed_digest = digest_transcript_seed(
            &public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
        );
        let fs_root = digest_fs_root(&fs_commitments);

        let fold_inputs: Vec<FoldInput> = statements
            .iter()
            .enumerate()
            .map(|(i, (c, pi, _))| FoldInput {
                commitment_bytes: cp_snark::encode_commitment_to_bytes(c),
                public_input: pi.clone(),
                eval_values_bytes: folding_proof
                    .gr1cs_proofs
                    .get(i)
                    .map(cp_snark::encode_gr1cs_round_message)
                    .unwrap_or_default(),
            })
            .collect();
        let fold_root = digest_fold_root(&fold_inputs);

        let transcript_bytes = build_transcript_bytes(&public_inputs, r1cs, &fs_commitments);
        let deriver = Sha256ChallengeDeriver;
        let challenges =
            deriver.derive_fixed_32(b"symphony-v1", &transcript_bytes, fs_commitments.len());
        let challenge_digest = digest_challenge_digest(&challenges);

        let cp_public_instance = CpPublicInstance {
            fs_root,
            fold_root,
            challenge_digest,
            transcript_seed_digest,
            x_folded: folding_proof.folded_instance.clone(),
        };

        let cp_instance = encode_cp_backend_instance(&cp_public_instance, &self.cp_layout);
        let commitments_for_cp: Vec<_> = folding_proof.commitments.clone();
        let cp_ntt = Some(crate::ring::ntt::NttContext::new(2013265921));
        let cp_witness = cp_snark::encode_cp_witness_r1cs(
            &commitments_for_cp,
            &public_inputs,
            &folding_proof.beta,
            &folding_proof.folded_instance,
            &self.cp_layout,
            &cp_ntt,
            &folding_proof.gr1cs_proofs,
            &shared_challenges.sumcheck_seed_had,
            &shared_challenges.alpha,
            &shared_challenges.hadamard_sumcheck_challenges,
            ext_ctx.alpha,
            self.params.q,
        );

        let cp_proof = CPB::prove(&self.cp_pk, &cp_instance, &cp_witness);

        let output_instance = cp_snark::encode_folded_instance(&folding_proof.folded_instance);
        let output_witness = cp_snark::encode_folded_witness(&folded_witness);

        let d = self.params.d as usize;
        let instance_elems = output_instance.len() / 8;
        let witness_elems = output_witness.len() / 8;
        let total_elems = instance_elems + witness_elems;
        let total_flat = r1cs.num_variables * d;

        let output_pk = if total_elems <= total_flat {
            let output_context = cp_snark::serialize_output_context(r1cs, self.params.q, d);
            self.output_pk_for_context(output_context)
        } else {
            self.output_pk.clone()
        };

        let output_proof = OB::prove(&output_pk, &output_instance, &output_witness);

        ProofBundle {
            cp_proof,
            output_proof,
            cp_public_instance: cp_public_instance.clone(),
            witness_bundle: CpWitnessBundle {
                transcript_bytes,
                fs_commitments,
                fs_openings,
                fs_messages,
                fold_inputs,
                folded_output: cp_public_instance.x_folded,
            },
        }
    }
}

impl<CPB: CpBackend, OB: OutputBackend> Verifier<CPB, OB> {
    fn output_vk_for_context(&self, output_context: Vec<u8>) -> OB::VerifyingKey {
        if let Some(vk) = self
            .output_vk_cache
            .lock()
            .expect("output_vk_cache mutex poisoned")
            .get(&output_context)
            .cloned()
        {
            return vk;
        }

        let relation = RelationDescription {
            num_instance_vars: self.params.n(),
            num_witness_vars: self.params.n(),
            num_constraints: self.params.m,
            context: Some(output_context.clone()),
        };
        let (_, vk) = OB::setup(&relation);

        self.output_vk_cache
            .lock()
            .expect("output_vk_cache mutex poisoned")
            .insert(output_context, vk.clone());
        vk
    }

    /// Verify a modular proof bundle against public inputs.
    ///
    /// **Design note:** This method does *not* call [`CpRelation::check`] explicitly.
    /// Instead, the CP relation consistency is enforced implicitly by the backend proof:
    /// [`encode_cp_backend_instance`] embeds all four digests (`fs_root`, `fold_root`,
    /// `challenge_digest`, `transcript_seed_digest`) plus the folded instance into the
    /// CP backend instance. The CP backend proof then binds these values — any
    /// inconsistency between digests and the underlying witness data will cause the
    /// backend verification to fail.
    ///
    /// [`CpRelation::check`] remains available as a standalone audit/debugging tool
    /// for inspecting proof internals without running full backend verification.
    #[must_use]
    pub fn verify(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &ProofBundle<CPB, OB>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        let expected_tsd = digest_transcript_seed(
            public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
        );
        if expected_tsd != proof.cp_public_instance.transcript_seed_digest {
            return false;
        }

        let cp_instance = encode_cp_backend_instance(&proof.cp_public_instance, &self.cp_layout);
        if !CPB::verify(&self.cp_vk, &cp_instance, &proof.cp_proof) {
            return false;
        }

        let output_instance = cp_snark::encode_folded_instance(&proof.cp_public_instance.x_folded);
        let d = self.params.d as usize;
        let instance_elems = output_instance.len() / 8;
        let total_flat = r1cs.num_variables * d;

        let output_vk = if instance_elems <= total_flat {
            let output_context = cp_snark::serialize_output_context(r1cs, self.params.q, d);
            self.output_vk_for_context(output_context)
        } else {
            self.output_vk.clone()
        };

        OB::verify(&output_vk, &output_instance, &proof.output_proof)
    }
}
