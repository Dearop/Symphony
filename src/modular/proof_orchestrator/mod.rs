//! End-to-end proving/verifying flow with split CP/output backends.

use std::collections::HashMap;
use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::cp_backend_api::CpBackend;
use crate::cp_relation_core::{
    CpPublicInstance, CpPublicStatement, CpSharedChallengeData, CpWitnessBundle,
};
use crate::digest_core::{
    derive_challenges_with_scheme, digest_challenge_digest_with_scheme,
    digest_fold_root_with_scheme, digest_fs_root_with_scheme, digest_transcript_seed_with_scheme,
    fs_commit_with_scheme, FoldInput, PublicDigestScheme,
};
use crate::folding_core::{FoldSemantics, Statement, SymphonyFoldSemantics};
use crate::output_backend_api::OutputBackend;
use crate::params::SymphonyParams;
use crate::public_proof::PublicProofEnvelope;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::ExtFieldContext;
use crate::ring::RingVector;
use crate::rok::range_proof::RangeProofParams;
use crate::snark::cp_snark::{self, CpR1csLayout};
use crate::snark::{RelationDescription, TypedCpSetupDescriptor};
use crate::transcript_core::{
    tags, CanonicalTranscriptCodec, TranscriptCodec, TranscriptEvent, TranscriptSchema,
};

/// Generic proof bundle using separate CP and output backends.
#[derive(Debug, Clone)]
pub struct ProofBundle<CPB: CpBackend, OB: OutputBackend> {
    pub cp_proof: CPB::Proof,
    pub output_proof: OB::Proof,
    pub cp_public_instance: CpPublicInstance,
    pub witness_bundle: CpWitnessBundle,
}

/// Canonical public-only modular proof bundle.
///
/// This is the verifier-facing Symphony proof boundary. It contains exactly
/// backend CP/output proofs, public Fiat-Shamir commitments, public
/// roots/digests binding hidden CP witness data, and the typed folded output
/// instance.
///
/// It deliberately contains no CP witness bundle: no FS openings/messages, no
/// fold inputs, no folding proof, no original witnesses, and no folded witness.
/// Verification must rely on authoritative typed CP/output backend proofs and
/// public digests only.
#[derive(Debug, Clone)]
pub struct ProofBundleV2<CPB: CpBackend, OB: OutputBackend> {
    /// CP backend proof proving the typed CP public instance.
    pub cp_proof: CPB::Proof,
    /// Output backend proof proving the folded output relation.
    pub output_proof: OB::Proof,
    /// Public Fiat-Shamir commitments `{c_fs,i}`.
    pub fs_commitments: Vec<Vec<u8>>,
    /// Public typed folded output instance.
    pub folded_output: crate::folding::FoldedOutputInstance,
    /// Digest of `fs_commitments`.
    pub fs_root: crate::digest_core::Digest32,
    /// Digest binding the hidden per-instance fold inputs.
    pub fold_root: crate::digest_core::Digest32,
    /// Digest of the derived Fiat-Shamir challenge sequence.
    pub challenge_digest: crate::digest_core::Digest32,
    /// Digest of public inputs and relation metadata.
    pub transcript_seed_digest: crate::digest_core::Digest32,
}

/// Product-facing name for the public-only proof boundary.
pub type PublicProofBundle<CPB, OB> = ProofBundleV2<CPB, OB>;

/// Stage where public-only v2 verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicVerificationFailure {
    /// Backend-independent public digest/boundary checks failed.
    PublicBoundary,
    /// The selected CP backend is not authoritative for typed public CP.
    TypedCpNotAuthoritative,
    /// The selected CP backend did not provide a typed CP relation.
    TypedCpRelationUnavailable,
    /// The typed CP backend proof rejected.
    TypedCpProof,
    /// The selected output backend is not authoritative for typed output.
    TypedOutputNotAuthoritative,
    /// The selected output backend did not provide a typed output context.
    TypedOutputContextUnavailable,
    /// The typed output backend proof rejected.
    TypedOutputProof,
}

impl<CPB: CpBackend, OB: OutputBackend> ProofBundle<CPB, OB> {
    /// Drop witness-side/debug data and keep only the public v2 proof boundary.
    #[must_use]
    pub fn to_v2(&self) -> ProofBundleV2<CPB, OB> {
        ProofBundleV2 {
            cp_proof: self.cp_proof.clone(),
            output_proof: self.output_proof.clone(),
            fs_commitments: self.witness_bundle.fs_commitments.clone(),
            folded_output: self.cp_public_instance.folded_output.clone(),
            fs_root: self.cp_public_instance.fs_root,
            fold_root: self.cp_public_instance.fold_root,
            challenge_digest: self.cp_public_instance.challenge_digest,
            transcript_seed_digest: self.cp_public_instance.transcript_seed_digest,
        }
    }
}

impl<CPB: CpBackend, OB: OutputBackend> ProofBundleV2<CPB, OB> {
    /// Reconstruct the typed CP public instance bound by this public proof.
    #[must_use]
    pub fn cp_public_instance(&self) -> CpPublicInstance {
        CpPublicInstance {
            fs_root: self.fs_root,
            fold_root: self.fold_root,
            challenge_digest: self.challenge_digest,
            transcript_seed_digest: self.transcript_seed_digest,
            x_folded: self.folded_output.folded_instance.clone(),
            folded_output: self.folded_output.clone(),
        }
    }

    /// Reconstruct the expanded typed CP public statement for SNARK-friendly
    /// CP backends that take public inputs directly instead of proving a SHA
    /// transcript-seed digest internally.
    #[must_use]
    pub fn cp_public_statement(
        &self,
        public_inputs: &[Vec<i64>],
        r1cs: &R1CSMatrices,
        digest_scheme: PublicDigestScheme,
    ) -> CpPublicStatement {
        CpPublicStatement::new(
            self.cp_public_instance(),
            public_inputs.to_vec(),
            r1cs,
            digest_scheme,
        )
        .with_fs_commitments(self.fs_commitments.clone())
    }

    /// Check backend-independent public-boundary digests.
    ///
    /// This does not verify backend proofs. It only checks the transcript seed
    /// and FS commitment root that every public verifier can recompute.
    #[must_use]
    pub fn public_boundary_is_well_formed(
        &self,
        public_inputs: &[Vec<i64>],
        r1cs: &R1CSMatrices,
    ) -> bool {
        self.public_boundary_is_well_formed_with_scheme(
            PublicDigestScheme::Sha256,
            public_inputs,
            r1cs,
        )
    }

    /// Check public-boundary digests under a backend-selected digest scheme.
    #[must_use]
    pub fn public_boundary_is_well_formed_with_scheme(
        &self,
        scheme: PublicDigestScheme,
        public_inputs: &[Vec<i64>],
        r1cs: &R1CSMatrices,
    ) -> bool {
        let expected_tsd = digest_transcript_seed_with_scheme(
            scheme,
            public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
        );
        expected_tsd == self.transcript_seed_digest
            && digest_fs_root_with_scheme(scheme, &self.fs_commitments) == self.fs_root
    }

    /// Build the canonical versioned public proof envelope bytes.
    ///
    /// Backend proof payloads are supplied as already-canonical backend bytes
    /// and are length-delimited by the envelope.
    #[must_use]
    pub fn canonical_public_envelope_bytes(
        &self,
        scheme: PublicDigestScheme,
        public_inputs: &[Vec<i64>],
        r1cs: &R1CSMatrices,
        cp_proof_bytes: &[u8],
        output_proof_bytes: &[u8],
    ) -> Vec<u8> {
        PublicProofEnvelope {
            digest_scheme: scheme,
            public_inputs: public_inputs.to_vec(),
            r1cs_num_constraints: r1cs.num_constraints,
            r1cs_num_variables: r1cs.num_variables,
            r1cs_num_public: r1cs.num_public,
            fs_commitments: self.fs_commitments.clone(),
            fs_root: self.fs_root,
            fold_root: self.fold_root,
            challenge_digest: self.challenge_digest,
            transcript_seed_digest: self.transcript_seed_digest,
            folded_output_bytes: cp_snark::encode_folded_output_instance(&self.folded_output),
            cp_proof_bytes: cp_proof_bytes.to_vec(),
            output_proof_bytes: output_proof_bytes.to_vec(),
        }
        .to_bytes()
    }
}

pub struct Prover<CPB: CpBackend, OB: OutputBackend> {
    pub params: SymphonyParams,
    pub ajtai: crate::commitment::AjtaiParams,
    pub cp_pk: CPB::ProvingKey,
    pub output_pk: OB::ProvingKey,
    /// Cache of typed CP proving keys keyed by serialized typed CP context bytes.
    pub cp_pk_cache: std::sync::Mutex<HashMap<Vec<u8>, CPB::ProvingKey>>,
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
    /// Cache of typed CP verifying keys keyed by serialized typed CP context bytes.
    pub cp_vk_cache: std::sync::Mutex<HashMap<Vec<u8>, CPB::VerifyingKey>>,
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
    fn cp_pk_for_relation(&self, relation: RelationDescription) -> CPB::ProvingKey {
        let key = relation.context.clone().unwrap_or_default();
        if let Some(pk) = self
            .cp_pk_cache
            .lock()
            .expect("cp_pk_cache mutex poisoned")
            .get(&key)
            .cloned()
        {
            return pk;
        }

        let (pk, _) = CPB::setup(&relation);
        self.cp_pk_cache
            .lock()
            .expect("cp_pk_cache mutex poisoned")
            .insert(key, pk.clone());
        pk
    }

    fn typed_cp_descriptor(&self, r1cs: &R1CSMatrices) -> TypedCpSetupDescriptor {
        let ext_ctx = ExtFieldContext::new(self.params.q);
        let (cp_r1cs, cp_layout) = cp_snark::generate_cp_r1cs(
            self.params.ell_np,
            self.params.kappa,
            self.params.n_in,
            self.params.m,
            ext_ctx.alpha,
            self.params.q,
        );
        TypedCpSetupDescriptor {
            params: self.params.clone(),
            ajtai: self.ajtai.clone(),
            original_r1cs: r1cs.clone(),
            cp_r1cs,
            cp_layout,
        }
    }

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
        let cp_relation = RelationDescription {
            num_instance_vars: cp_layout.num_instance,
            num_witness_vars: cp_layout.num_variables - cp_layout.num_instance,
            num_constraints: cp_r1cs.num_constraints,
            context: CPB::serialize_cp_context(&cp_r1cs, params.q, params.d),
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
                cp_pk_cache: std::sync::Mutex::new(HashMap::new()),
                output_pk_cache: std::sync::Mutex::new(HashMap::new()),
                cp_layout: cp_layout.clone(),
                _marker: PhantomData,
            },
            Verifier {
                params,
                ajtai,
                cp_vk,
                output_vk,
                cp_vk_cache: std::sync::Mutex::new(HashMap::new()),
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
        #[cfg(feature = "whir")]
        let (mut folding_proof, mut folded_witness, shared_challenges) =
            semantics.fold(&fold_statements, r1cs, &self.ajtai, &rp, &ext_ctx);
        #[cfg(not(feature = "whir"))]
        let (folding_proof, folded_witness, shared_challenges) =
            semantics.fold(&fold_statements, r1cs, &self.ajtai, &rp, &ext_ctx);

        let fs_messages: Vec<Vec<u8>> = folding_proof
            .gr1cs_proofs
            .iter()
            .map(cp_snark::encode_gr1cs_round_message)
            .collect();
        let digest_scheme = CPB::public_digest_scheme();
        let mut fs_commitments = Vec::with_capacity(fs_messages.len());
        let mut fs_openings = Vec::with_capacity(fs_messages.len());
        for message in &fs_messages {
            let (commitment, opening) = fs_commit_with_scheme(digest_scheme, message);
            fs_commitments.push(commitment.to_vec());
            fs_openings.push(opening.to_vec());
        }

        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|(_, pi, _)| pi.clone()).collect();
        let transcript_seed_digest = digest_transcript_seed_with_scheme(
            digest_scheme,
            &public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
        );
        let fs_root = digest_fs_root_with_scheme(digest_scheme, &fs_commitments);

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
        let fold_root = digest_fold_root_with_scheme(digest_scheme, &fold_inputs);

        let transcript_bytes = build_transcript_bytes(&public_inputs, r1cs, &fs_commitments);
        let challenges = derive_challenges_with_scheme(
            digest_scheme,
            &public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
            &fs_commitments,
        );
        let challenge_digest = digest_challenge_digest_with_scheme(digest_scheme, &challenges);

        #[cfg(feature = "whir")]
        if digest_scheme == PublicDigestScheme::Poseidon2BabyBear {
            let typed_beta =
                crate::snark::cp_snark::typed_r1cs::poseidon_challenges_to_betas(&challenges)
                    .expect("Poseidon2/BabyBear challenge output must map to typed CP beta");
            assert_eq!(
                typed_beta.len(),
                folding_proof.gr1cs_proofs.len(),
                "typed CP beta count must match folding proof arity",
            );
            folding_proof.beta = typed_beta;
            let original_witnesses: Vec<_> = statements.iter().map(|(_, _, w)| w.clone()).collect();
            folded_witness = crate::folding::retarget_folding_proof_to_current_beta(
                &mut folding_proof,
                &public_inputs,
                &original_witnesses,
                self.params.q,
                self.params.ntt(),
            )
            .expect("typed CP beta must retarget folded state consistently");
        }

        let folded_output_instance =
            crate::folding::folded_output_instance_from_proof(&folding_proof);
        let folded_output_witness =
            crate::folding::folded_output_witness_from_folded(&folded_witness);

        let cp_public_instance = CpPublicInstance {
            fs_root,
            fold_root,
            challenge_digest,
            transcript_seed_digest,
            x_folded: folding_proof.folded_instance.clone(),
            folded_output: folded_output_instance.clone(),
        };

        let cp_instance = encode_cp_backend_instance(&cp_public_instance, &self.cp_layout);
        let commitments_for_cp: Vec<_> = folding_proof.commitments.clone();
        let cp_ntt = Some(crate::ring::ntt::NttContext::new(self.params.q));
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

        let typed_cp_witness = CpWitnessBundle {
            transcript_bytes: transcript_bytes.clone(),
            fs_commitments: fs_commitments.clone(),
            fs_openings: fs_openings.clone(),
            fs_messages: fs_messages.clone(),
            fold_inputs: fold_inputs.clone(),
            original_witnesses: statements.iter().map(|(_, _, w)| w.clone()).collect(),
            folded_output: cp_public_instance.x_folded.clone(),
            folded_output_instance: folded_output_instance.clone(),
            folded_output_witness: folded_output_witness.clone(),
            folded_witness: folded_witness.clone(),
            folding_proof: folding_proof.clone(),
            shared_challenges: CpSharedChallengeData {
                sumcheck_seed_had: shared_challenges.sumcheck_seed_had.clone(),
                alpha: shared_challenges.alpha,
                hadamard_sumcheck_challenges: shared_challenges
                    .hadamard_sumcheck_challenges
                    .clone(),
                sumcheck_seed_mon: shared_challenges.sumcheck_seed_mon.clone(),
                monomial_sumcheck_challenges: shared_challenges
                    .monomial_sumcheck_challenges
                    .clone(),
            },
        };
        let cp_public_statement = CpPublicStatement::new(
            cp_public_instance.clone(),
            public_inputs.clone(),
            r1cs,
            digest_scheme,
        )
        .with_fs_commitments(fs_commitments.clone());

        let cp_proof = if CPB::has_authoritative_typed_cp() {
            let cp_relation = CPB::typed_cp_relation_description(&self.typed_cp_descriptor(r1cs))
                .expect("authoritative typed CP backend did not provide a typed relation");
            let cp_pk = self.cp_pk_for_relation(cp_relation);
            CPB::prove_typed_cp(&cp_pk, &cp_public_statement, &typed_cp_witness)
                .expect("authoritative typed CP backend rejected the typed CP witness")
        } else {
            CPB::prove(&self.cp_pk, &cp_instance, &cp_witness)
        };

        let output_instance = cp_snark::encode_folded_instance(&folding_proof.folded_instance);
        let output_witness = cp_snark::encode_folded_witness(&folded_witness);

        let d = self.params.d;
        let instance_elems = output_instance.len() / 8;
        let witness_elems = output_witness.len() / 8;
        let total_elems = instance_elems + witness_elems;
        let total_flat = r1cs.num_variables * d;

        let output_proof = if let Some(output_context) =
            OB::serialize_output_context(r1cs, self.params.q, d)
        {
            let output_pk = self.output_pk_for_context(output_context);
            if OB::has_authoritative_typed_output() {
                OB::prove_typed_output(&output_pk, &folded_output_instance, &folded_output_witness)
                    .expect("authoritative typed output backend rejected folded output relation")
            } else if total_elems <= total_flat {
                OB::prove(&output_pk, &output_instance, &output_witness)
            } else {
                OB::prove(&self.output_pk, &output_instance, &output_witness)
            }
        } else {
            OB::prove(&self.output_pk, &output_instance, &output_witness)
        };

        ProofBundle {
            cp_proof,
            output_proof,
            cp_public_instance: cp_public_instance.clone(),
            witness_bundle: typed_cp_witness,
        }
    }

    /// Generate a public-only v2 modular proof bundle.
    ///
    /// Compatibility alias: product-facing callers should prefer
    /// [`Self::prove_public`]. The returned bundle drops witness-side data
    /// before crossing the public API boundary.
    #[must_use]
    pub fn prove_v2(
        &self,
        statements: &[(Commitment, Vec<i64>, RingVector)],
        r1cs: &R1CSMatrices,
    ) -> ProofBundleV2<CPB, OB> {
        self.prove(statements, r1cs).to_v2()
    }

    /// Generate the canonical public-only proof.
    ///
    /// This is the product-facing API. The returned bundle contains only
    /// public verifier data and backend proofs; it does not expose a CP witness
    /// bundle, FS openings/messages, fold inputs, original witnesses, folding
    /// proof internals, or folded witnesses.
    #[must_use]
    pub fn prove_public(
        &self,
        statements: &[(Commitment, Vec<i64>, RingVector)],
        r1cs: &R1CSMatrices,
    ) -> PublicProofBundle<CPB, OB> {
        self.prove_v2(statements, r1cs)
    }
}

impl<CPB: CpBackend, OB: OutputBackend> Verifier<CPB, OB> {
    fn cp_vk_for_relation(&self, relation: RelationDescription) -> CPB::VerifyingKey {
        let key = relation.context.clone().unwrap_or_default();
        if let Some(vk) = self
            .cp_vk_cache
            .lock()
            .expect("cp_vk_cache mutex poisoned")
            .get(&key)
            .cloned()
        {
            return vk;
        }

        let (_, vk) = CPB::setup(&relation);
        self.cp_vk_cache
            .lock()
            .expect("cp_vk_cache mutex poisoned")
            .insert(key, vk.clone());
        vk
    }

    fn typed_cp_descriptor(&self, r1cs: &R1CSMatrices) -> TypedCpSetupDescriptor {
        let ext_ctx = ExtFieldContext::new(self.params.q);
        let (cp_r1cs, cp_layout) = cp_snark::generate_cp_r1cs(
            self.params.ell_np,
            self.params.kappa,
            self.params.n_in,
            self.params.m,
            ext_ctx.alpha,
            self.params.q,
        );
        TypedCpSetupDescriptor {
            params: self.params.clone(),
            ajtai: self.ajtai.clone(),
            original_r1cs: r1cs.clone(),
            cp_r1cs,
            cp_layout,
        }
    }

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
    /// The verifier checks the transcript-seed digest, verifies the CP/output
    /// backend proofs, and then runs explicit witness-side consistency checks
    /// over the carried folding/transcript data.
    ///
    /// [`CpRelation::check`] remains available as a standalone audit/debugging tool,
    /// but this verifier does not rely on backend proof verification alone.
    #[must_use]
    pub fn verify(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &ProofBundle<CPB, OB>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        let expected_tsd = digest_transcript_seed_with_scheme(
            CPB::public_digest_scheme(),
            public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
        );
        if expected_tsd != proof.cp_public_instance.transcript_seed_digest {
            return false;
        }

        let typed_cp_statement = CpPublicStatement::new(
            proof.cp_public_instance.clone(),
            public_inputs.to_vec(),
            r1cs,
            CPB::public_digest_scheme(),
        )
        .with_fs_commitments(proof.witness_bundle.fs_commitments.clone());
        let cp_relation_ok = if CPB::public_digest_scheme() == PublicDigestScheme::Sha256 {
            crate::cp_relation_core::CpRelation::check_with_algebra(
                &proof.cp_public_instance,
                &proof.witness_bundle,
                &self.ajtai,
                r1cs,
                self.params.b_input(),
            )
        } else {
            crate::cp_relation_core::CpFieldRelation::check(
                &typed_cp_statement,
                &proof.witness_bundle,
                &self.ajtai,
                r1cs,
                self.params.b_input(),
            )
        };
        if cp_relation_ok.is_err() {
            return false;
        }

        let cp_instance = encode_cp_backend_instance(&proof.cp_public_instance, &self.cp_layout);
        let cp_backend_ok = if CPB::has_authoritative_typed_cp() {
            let Some(cp_relation) =
                CPB::typed_cp_relation_description(&self.typed_cp_descriptor(r1cs))
            else {
                return false;
            };
            let cp_vk = self.cp_vk_for_relation(cp_relation);
            CPB::verify_typed_cp(&cp_vk, &typed_cp_statement, &proof.cp_proof) == Some(true)
        } else {
            CPB::verify(&self.cp_vk, &cp_instance, &proof.cp_proof)
        };
        if !cp_backend_ok {
            return false;
        }

        let output_instance = cp_snark::encode_folded_instance(&proof.cp_public_instance.x_folded);
        let d = self.params.d;
        let instance_elems = output_instance.len() / 8;
        let total_flat = r1cs.num_variables * d;

        let output_backend_ok =
            if let Some(output_context) = OB::serialize_output_context(r1cs, self.params.q, d) {
                let output_vk = self.output_vk_for_context(output_context);
                if OB::has_authoritative_typed_output() {
                    OB::verify_typed_output(
                        &output_vk,
                        &proof.cp_public_instance.folded_output,
                        &proof.output_proof,
                    )
                    .unwrap_or(false)
                } else if instance_elems <= total_flat {
                    OB::verify(&output_vk, &output_instance, &proof.output_proof)
                } else {
                    OB::verify(&self.output_vk, &output_instance, &proof.output_proof)
                }
            } else {
                OB::verify(&self.output_vk, &output_instance, &proof.output_proof)
            };

        if !output_backend_ok {
            return false;
        }

        if CPB::public_digest_scheme() != PublicDigestScheme::Sha256 {
            return true;
        }

        crate::snark::verify_explicit_soundness(
            &self.params,
            &self.ajtai,
            public_inputs,
            &proof.witness_bundle.original_witnesses,
            &proof.witness_bundle.fs_commitments,
            &proof.witness_bundle.fs_openings,
            &proof.witness_bundle.fs_messages,
            &proof.witness_bundle.fold_inputs,
            &proof.witness_bundle.folding_proof,
            &proof.cp_public_instance.x_folded,
            &proof.witness_bundle.folded_witness,
            &proof.cp_public_instance.fs_root,
            &proof.cp_public_instance.fold_root,
            &proof.cp_public_instance.challenge_digest,
            &proof.cp_public_instance.transcript_seed_digest,
            r1cs,
            crate::snark::ExplicitSoundnessAssumptions {
                transcript_seed_checked: true,
                cp_relation_checked: true,
            },
        )
    }

    /// Verify a public-only v2 modular proof bundle.
    ///
    /// This path never accesses FS openings/messages, original witnesses,
    /// folding proofs, folded witnesses, or fold inputs. It fails closed unless
    /// both selected backends advertise authoritative typed verification.
    ///
    /// Compatibility alias: product-facing callers should prefer
    /// [`Self::verify_public`]. WHIR public routing uses Poseidon2/BabyBear and
    /// must not fall back to SHA-256 or witness-side checks.
    #[must_use]
    pub fn verify_v2(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &ProofBundleV2<CPB, OB>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        self.verify_public_attribution(public_inputs, proof, r1cs)
            .is_ok()
    }

    /// Verify a public-only v2 modular proof bundle and report the first
    /// failing public-verifier stage.
    ///
    /// This uses the same public-only route as [`Self::verify_public`]. It is
    /// intended for tests and benchmarks that need actionable failure
    /// diagnostics without falling back to witness-side compatibility checks.
    pub fn verify_public_attribution(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &ProofBundleV2<CPB, OB>,
        r1cs: &R1CSMatrices,
    ) -> Result<(), PublicVerificationFailure> {
        if !proof.public_boundary_is_well_formed_with_scheme(
            CPB::public_digest_scheme(),
            public_inputs,
            r1cs,
        ) {
            return Err(PublicVerificationFailure::PublicBoundary);
        }

        if !CPB::has_authoritative_typed_cp() {
            return Err(PublicVerificationFailure::TypedCpNotAuthoritative);
        }
        let cp_public_statement =
            proof.cp_public_statement(public_inputs, r1cs, CPB::public_digest_scheme());
        let Some(cp_relation) = CPB::typed_cp_relation_description(&self.typed_cp_descriptor(r1cs))
        else {
            return Err(PublicVerificationFailure::TypedCpRelationUnavailable);
        };
        let cp_vk = self.cp_vk_for_relation(cp_relation);
        if CPB::verify_typed_cp(&cp_vk, &cp_public_statement, &proof.cp_proof) != Some(true) {
            return Err(PublicVerificationFailure::TypedCpProof);
        }

        if !OB::has_authoritative_typed_output() {
            return Err(PublicVerificationFailure::TypedOutputNotAuthoritative);
        }
        let d = self.params.d;
        let Some(output_context) = OB::serialize_output_context(r1cs, self.params.q, d) else {
            return Err(PublicVerificationFailure::TypedOutputContextUnavailable);
        };
        let output_vk = self.output_vk_for_context(output_context);
        if OB::verify_typed_output(&output_vk, &proof.folded_output, &proof.output_proof)
            != Some(true)
        {
            return Err(PublicVerificationFailure::TypedOutputProof);
        }

        Ok(())
    }

    /// Verify the canonical public-only proof.
    ///
    /// This is the product-facing API. It must remain public-only: no witness
    /// bundle, no FS openings/messages, no fold inputs, no explicit soundness
    /// fallback, and no legacy SHA fallback for WHIR. Verification fails closed
    /// unless both selected backends advertise authoritative typed verification.
    #[must_use]
    pub fn verify_public(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &PublicProofBundle<CPB, OB>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        self.verify_v2(public_inputs, proof, r1cs)
    }
}
