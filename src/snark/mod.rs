//! SNARK construction (Construction 6.1) — the commit-and-prove compiler.
//!
//! The SNARK statement never embeds Fiat-Shamir hashing logic.
//!
//! Setup: choose Π_cm (Merkle or KZG), setup CP-SNARK, setup backend SNARK.
//!
//! Prover:
//!   1. Run non-interactive folding (Fiat-Shamir applied)
//!   2. At each round, commit to messages with Π_cm
//!   3. Obtain folded instance and witness
//!   4. Generate output proof π for the folded statement
//!   5. Generate CP-SNARK proof π_cp for folding correctness
//!   6. Output π* = (π_cp, π, {c_{fs,i}}, x_o)
//!
//! Verifier:
//!   1. Recompute transcript seed digest from public inputs + relation metadata
//!   2. Check Π_cp.Verify(π_cp) over full CP public binding digests
//!   3. Check Π_out.Verify(π) for the folded statement
//!   4. Run explicit witness-side consistency checks over the carried folding /
//!      transcript data

pub mod cp_snark;
pub mod prover;
pub mod spartan;
pub mod sumcheck_snark;
#[cfg(feature = "whir")]
pub mod whir;

use std::collections::HashMap;
use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::cp_relation_core::{
    CpPublicInstance as TypedCpPublicInstance, CpPublicStatement,
    CpWitnessBundle as TypedCpWitnessBundle,
};
use crate::digest_core::{
    digest_fs_root_with_scheme, digest_transcript_seed_with_scheme, PublicDigestScheme,
};
use crate::folding::digest::Digest32;
use crate::folding::{FoldedInstance, FoldedOutputInstance, FoldedOutputWitness};
use crate::params::SymphonyParams;
use crate::public_proof::PublicProofEnvelope;
use crate::r1cs::R1CSMatrices;
use crate::ring::RingVector;

/// Backend setup material for an authoritative typed CP relation.
///
/// Unlike the legacy CP-R1CS, the field-native typed CP relation depends on
/// the original R1CS matrices and Ajtai commitment parameters, not only on
/// global dimensions. Backends that can build a verifier-enforced typed CP
/// relation may serialize this descriptor into their relation context.
#[derive(Debug, Clone)]
pub struct TypedCpSetupDescriptor {
    pub params: SymphonyParams,
    pub ajtai: crate::commitment::AjtaiParams,
    pub original_r1cs: R1CSMatrices,
    pub cp_r1cs: R1CSMatrices,
    pub cp_layout: cp_snark::CpR1csLayout,
}

/// Backend SNARK trait — Symphony is generic over the final proof system.
///
/// Concrete backends shipped with this crate:
/// - **`WhirSnark`** (feature `whir`): post-quantum, Merkle-based PCS (Poseidon2 +
///   BabyBear). Recommended for production.
/// - **`SpartanSnark`**: classical, Pedersen + Bulletproofs-style IPA over Ristretto.
///   **Not post-quantum** — useful for comparison and legacy compatibility.
/// - **`SumcheckSnark`**: non-succinct, testing-only (full witness in proof).
/// - **`DummySnark`**: trivially accepts all proofs; for pipeline wiring tests only.
///
/// Both the CP-SNARK (proving folding correctness) and the output SNARK
/// (proving the folded statement) use this trait. They may use the same
/// or different concrete implementations.
pub trait BackendSnark {
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: Clone + std::fmt::Debug;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey);
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof;
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool;

    /// Public-boundary digest scheme used by product-facing public verification.
    ///
    /// Backends should keep the default SHA-256 scheme until their typed CP
    /// verifier proves the field-native public relation. WHIR switches to the
    /// Poseidon2/BabyBear scheme only at that security milestone.
    fn public_digest_scheme() -> PublicDigestScheme {
        PublicDigestScheme::Sha256
    }

    /// Optional backend-specific serializer for an output-statement context.
    fn serialize_output_context(_r1cs: &R1CSMatrices, _q: u64, _d: usize) -> Option<Vec<u8>> {
        None
    }

    /// Whether this backend treats [`FoldedOutputInstance`] / [`FoldedOutputWitness`]
    /// as the authoritative final folded R1CS relation when an output context is
    /// present.
    ///
    /// This flag is intentionally narrower than CP authority: it proves the
    /// final folded statement and binds the typed folded output object. The CP
    /// backend remains responsible for proving that the folded output was
    /// derived correctly from the original statements. Backends returning `true`
    /// must fail closed if typed output proving or verification returns `None`.
    fn has_authoritative_typed_output() -> bool {
        false
    }

    /// Whether this backend treats [`CpPublicStatement`] / [`TypedCpWitnessBundle`]
    /// as the authoritative CP relation.
    ///
    /// Backends returning `true` must prove the full CP relation checked by
    /// [`crate::cp_relation_core::CpRelation::check_with_algebra`] inside the
    /// backend proof. Verifiers for the public-only v2 path fail closed when
    /// this flag is `false`; they must not fall back to witness-side relation
    /// checks.
    fn has_authoritative_typed_cp() -> bool {
        false
    }

    /// Optional backend-specific serializer for a CP relation context.
    fn serialize_cp_context(_r1cs: &R1CSMatrices, _q: u64, _d: usize) -> Option<Vec<u8>> {
        None
    }

    /// Optional backend-specific serializer for a typed CP relation context.
    ///
    /// This raw byte hook is retained for compatibility and development
    /// tooling. Product public routing should prefer
    /// [`Self::typed_cp_relation_description`] so setup receives explicit
    /// dimensions as well as backend context bytes. Returning `Some` here does
    /// not imply public authority; `has_authoritative_typed_cp()` is the
    /// security gate.
    fn serialize_typed_cp_context(_descriptor: &TypedCpSetupDescriptor) -> Option<Vec<u8>> {
        None
    }

    /// Optional backend-specific typed CP relation description.
    ///
    /// This is the product-routing hook for authoritative typed CP because
    /// setup needs public/witness/constraint dimensions as well as backend
    /// context bytes. It is still ignored unless
    /// [`Self::has_authoritative_typed_cp`] returns true.
    fn typed_cp_relation_description(
        _descriptor: &TypedCpSetupDescriptor,
    ) -> Option<RelationDescription> {
        None
    }

    /// Optional typed CP proving path.
    fn prove_typed_cp(
        _pk: &Self::ProvingKey,
        _statement: &CpPublicStatement,
        _witness: &TypedCpWitnessBundle,
    ) -> Option<Self::Proof> {
        None
    }

    /// Optional typed CP verification path.
    fn verify_typed_cp(
        _vk: &Self::VerifyingKey,
        _statement: &CpPublicStatement,
        _proof: &Self::Proof,
    ) -> Option<bool> {
        None
    }

    /// Optional structured batched typed-CP relation description.
    ///
    /// This P3/P4 hook is intentionally separate from the authoritative
    /// monolithic typed CP path. Returning `Some` here must not affect product
    /// public routing until the structured WHIR path has equivalent negative
    /// coverage and is explicitly promoted.
    fn typed_batched_cp_relation_description(
        _shape: &crate::batched_cp::BatchedCpStatementShape,
    ) -> Option<RelationDescription> {
        None
    }

    /// Optional structured batched typed-CP proving path.
    fn prove_typed_batched_cp(
        _pk: &Self::ProvingKey,
        _statement: &crate::batched_cp::BatchedCpPublicStatement,
        _witness: &crate::batched_cp::BatchedCpWitnessBundle,
    ) -> Option<Self::Proof> {
        None
    }

    /// Optional structured batched typed-CP verification path.
    fn verify_typed_batched_cp(
        _vk: &Self::VerifyingKey,
        _statement: &crate::batched_cp::BatchedCpPublicStatement,
        _proof: &Self::Proof,
    ) -> Option<bool> {
        None
    }

    /// Optional SYMBT3 CP-aware batched typed-CP relation description.
    ///
    /// This is a development hook for the next WHIR CP architecture. Returning
    /// `Some` here must not affect product public routing until the SYMBT3 path
    /// has equivalent negative coverage and is explicitly promoted.
    fn symbt3_relation_description(
        _descriptor: &crate::batched_cp::BatchedCpSymbt3SetupDescriptor,
    ) -> Option<RelationDescription> {
        None
    }

    /// Optional SYMBT3 proving path. Initial foundation implementations may
    /// return `None` until algebraic CP blocks are enforced.
    fn prove_symbt3_batched_cp(
        _pk: &Self::ProvingKey,
        _statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        _witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    ) -> Option<Self::Proof> {
        None
    }

    /// Optional SYMBT3 verification path.
    fn verify_symbt3_batched_cp(
        _vk: &Self::VerifyingKey,
        _statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        _proof: &Self::Proof,
    ) -> Option<bool> {
        None
    }

    /// Optional typed folded-output proving path.
    fn prove_typed_output(
        _pk: &Self::ProvingKey,
        _instance: &FoldedOutputInstance,
        _witness: &FoldedOutputWitness,
    ) -> Option<Self::Proof> {
        None
    }

    /// Optional typed folded-output verification path.
    fn verify_typed_output(
        _vk: &Self::VerifyingKey,
        _instance: &FoldedOutputInstance,
        _proof: &Self::Proof,
    ) -> Option<bool> {
        None
    }
}

/// Description of the relation to be proven by the backend SNARK.
#[derive(Debug, Clone)]
pub struct RelationDescription {
    pub num_instance_vars: usize,
    pub num_witness_vars: usize,
    pub num_constraints: usize,
    /// Optional backend-specific context (e.g., serialized R1CS for Spartan).
    pub context: Option<Vec<u8>>,
}

/// A complete Symphony proof, generic over the backend SNARK `S`.
///
/// Stage 1 note: the proof still stores the legacy `folded_instance` field for
/// compatibility, but the intended typed public output boundary is now also
/// available as `folded_output`.
#[derive(Debug, Clone)]
pub struct SymphonyProof<S: BackendSnark> {
    // -- Verifier-visible fields (O(1) total size) --
    /// CP-SNARK proof π_cp (proves folding correctness).
    pub cp_proof: S::Proof,
    /// Output SNARK proof π (proves the folded statement).
    pub snark_proof: S::Proof,
    /// Legacy folded instance projection kept for backwards compatibility.
    pub folded_instance: FoldedInstance,
    /// Typed public folded-output boundary for the eventual output relation `R_o`.
    pub folded_output: FoldedOutputInstance,
    /// SHA-256 digest binding all per-instance fold inputs.
    pub fold_root: Digest32,
    /// SHA-256 digest of the derived challenge sequence.
    pub challenge_digest: Digest32,
    /// SHA-256 digest of all FS commitments.
    pub fs_root: Digest32,
    /// SHA-256 digest of static transcript metadata (public inputs + R1CS dims).
    pub transcript_seed_digest: Digest32,

    // -- Witness data (O(k), carried in the proof object) --
    /// Full witness data needed for serialization, explicit soundness checks,
    /// and backend-independent verification fallback.
    pub witness_data: ProofWitnessData,
}

impl<S: BackendSnark> SymphonyProof<S> {
    /// Naming-consistent accessor for the output proof.
    ///
    /// The stored field is `snark_proof` for backwards compatibility.
    pub fn output_proof(&self) -> &S::Proof {
        &self.snark_proof
    }

    /// Drop all witness-side/debug data and keep only the public v2 proof
    /// boundary.
    #[must_use]
    pub fn to_v2(&self) -> SymphonyProofV2<S> {
        SymphonyProofV2 {
            cp_proof: self.cp_proof.clone(),
            output_proof: self.snark_proof.clone(),
            fs_commitments: self.witness_data.fs_commitments.clone(),
            folded_output: self.folded_output.clone(),
            fs_root: self.fs_root,
            fold_root: self.fold_root,
            challenge_digest: self.challenge_digest,
            transcript_seed_digest: self.transcript_seed_digest,
        }
    }
}

/// Canonical public-only Symphony proof.
///
/// This is the verifier-facing Symphony proof boundary. It carries exactly
/// backend proofs, public Fiat-Shamir commitments, public roots/digests binding
/// hidden CP witness data, and the typed folded output instance. It does not
/// contain FS openings/messages, original witnesses, folding proofs, folded
/// witnesses, fold inputs, or any verifier-visible witness bundle.
#[derive(Debug, Clone)]
pub struct SymphonyProofV2<S: BackendSnark> {
    /// CP backend proof proving the typed CP public instance.
    pub cp_proof: S::Proof,
    /// Output backend proof proving the folded output relation.
    pub output_proof: S::Proof,
    /// Public Fiat-Shamir commitments `{c_fs,i}`.
    pub fs_commitments: Vec<Vec<u8>>,
    /// Public typed folded output instance.
    pub folded_output: FoldedOutputInstance,
    /// Digest of `fs_commitments`.
    pub fs_root: Digest32,
    /// Digest binding the hidden per-instance fold inputs.
    pub fold_root: Digest32,
    /// Digest of the derived Fiat-Shamir challenge sequence.
    pub challenge_digest: Digest32,
    /// Digest of public inputs and relation metadata.
    pub transcript_seed_digest: Digest32,
}

/// Product-facing name for the public-only proof boundary.
pub type PublicSymphonyProof<S> = SymphonyProofV2<S>;

impl<S: BackendSnark> SymphonyProofV2<S> {
    /// Reconstruct the typed CP public instance bound by this public proof.
    #[must_use]
    pub fn typed_cp_public_instance(&self) -> TypedCpPublicInstance {
        TypedCpPublicInstance {
            fs_root: self.fs_root,
            fold_root: self.fold_root,
            challenge_digest: self.challenge_digest,
            transcript_seed_digest: self.transcript_seed_digest,
            x_folded: self.folded_output.folded_instance.clone(),
            folded_output: self.folded_output.clone(),
        }
    }

    /// Reconstruct the expanded typed CP public statement for field-native CP
    /// backends that use public inputs directly.
    #[must_use]
    pub fn typed_cp_public_statement(
        &self,
        public_inputs: &[Vec<i64>],
        r1cs: &R1CSMatrices,
        digest_scheme: PublicDigestScheme,
    ) -> CpPublicStatement {
        CpPublicStatement::new(
            self.typed_cp_public_instance(),
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

/// O(k) witness data bundled with the proof for serialization and explicit
/// verification.
///
/// In the current implementation, verifiers may inspect these fields to
/// perform backend-independent soundness checks in addition to backend proof
/// verification.
#[derive(Debug, Clone)]
pub struct ProofWitnessData {
    /// Fiat-Shamir commitments {c_{fs,i}}.
    pub fs_commitments: Vec<Vec<u8>>,
    /// FS commitment openings.
    pub fs_openings: Vec<Vec<u8>>,
    /// FS committed messages (deterministic folding round encodings).
    pub fs_messages: Vec<Vec<u8>>,
    /// Canonical transcript bytes used for challenge derivation.
    pub transcript_bytes: Vec<u8>,
    /// Per-instance fold inputs.
    pub fold_inputs: Vec<crate::folding::digest::FoldInput>,
    /// Original witness parts for each proved statement.
    pub original_witnesses: Vec<RingVector>,
    /// Full folding proof.
    pub folding_proof: crate::folding::FoldingProof,
    /// Shared GR1CS challenge material needed to reconstruct CP-R1CS witnesses.
    pub shared_challenges: crate::cp_relation_core::CpSharedChallengeData,
    /// Typed folded-output private witness boundary.
    pub folded_output_witness: crate::folding::FoldedOutputWitness,
    /// Folded witness used by the output-statement check.
    pub folded_witness: crate::folding::FoldedWitness,
}

pub(crate) fn range_proof_params(
    params: &SymphonyParams,
) -> crate::rok::range_proof::RangeProofParams {
    crate::rok::range_proof::RangeProofParams {
        lambda_pj: params.lambda_pj,
        ell_h: params.ell_h,
        d_prime: (params.d as i64) - 2,
        k_g: params.k_g(),
        input_bound: params.b_input(),
    }
}

pub(crate) fn build_canonical_transcript_bytes(
    public_inputs: &[Vec<i64>],
    r1cs: &R1CSMatrices,
    fs_commitments: &[Vec<u8>],
) -> Vec<u8> {
    use crate::transcript_core::{
        tags, CanonicalTranscriptCodec, TranscriptCodec, TranscriptEvent, TranscriptSchema,
    };

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

    for comm in fs_commitments {
        schema.push_event(TranscriptEvent::new(
            tags::FS_COMMITMENT,
            b"fs-commitment",
            comm,
        ));
    }

    CanonicalTranscriptCodec.encode(&schema)
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExplicitSoundnessAssumptions {
    pub transcript_seed_checked: bool,
    pub cp_relation_checked: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_explicit_soundness(
    params: &SymphonyParams,
    ajtai: &crate::commitment::AjtaiParams,
    public_inputs: &[Vec<i64>],
    original_witnesses: &[RingVector],
    fs_commitments: &[Vec<u8>],
    fs_openings: &[Vec<u8>],
    fs_messages: &[Vec<u8>],
    fold_inputs: &[crate::folding::digest::FoldInput],
    folding_proof: &crate::folding::FoldingProof,
    folded_instance: &FoldedInstance,
    folded_witness: &crate::folding::FoldedWitness,
    fs_root: &Digest32,
    fold_root: &Digest32,
    challenge_digest: &Digest32,
    transcript_seed_digest: &Digest32,
    r1cs: &R1CSMatrices,
    assumptions: ExplicitSoundnessAssumptions,
) -> bool {
    macro_rules! fail {
        ($msg:expr) => {{
            if std::env::var("SYMPHONY_DEBUG_VERIFY").ok().as_deref() == Some("1") {
                eprintln!("[verify_explicit_soundness] {}", $msg);
            }
            return false;
        }};
    }
    use crate::fiat_shamir::hash_commitment::HashCommitment;
    use crate::fiat_shamir::FSCommitment;
    use crate::folding::digest::{
        digest_challenges, digest_fold_inputs, digest_fs_commitments, digest_transcript_seed,
        FoldInput,
    };
    use crate::r1cs::generalized::{check_hadamard, GeneralizedR1CSParams};
    use crate::ring::RingElement;
    use crate::transcript_core::{ChallengeDeriver, Sha256ChallengeDeriver};

    if public_inputs.len() != original_witnesses.len()
        || public_inputs.len() != folding_proof.commitments.len()
        || (!assumptions.cp_relation_checked
            && (fs_commitments.len() != fs_openings.len()
                || fs_commitments.len() != fs_messages.len()
                || fs_messages.len() != folding_proof.gr1cs_proofs.len()))
    {
        fail!("length-mismatch-top");
    }

    let scheme = HashCommitment::new();
    let generalized_params = GeneralizedR1CSParams {
        n_in: r1cs.num_public,
        n_w: r1cs.num_variables.saturating_sub(r1cs.num_public),
        ell_h: params.ell_h,
        bound: params.b_input(),
        matrices: r1cs.clone(),
    };

    if !assumptions.cp_relation_checked {
        for (((commitment, public_input), witness_part), fold_input) in folding_proof
            .commitments
            .iter()
            .zip(public_inputs.iter())
            .zip(original_witnesses.iter())
            .zip(fold_inputs.iter())
        {
            if public_input.len() != r1cs.num_public {
                fail!("public-input-len");
            }
            if witness_part.len() + public_input.len() != ajtai.n {
                fail!("full-witness-len");
            }

            let full_witness =
                crate::commitment::opening::assemble_full_witness(public_input, witness_part);

            if !crate::commitment::opening::verify_strict(
                ajtai,
                commitment,
                &full_witness,
                u128::MAX,
            ) {
                fail!("ajtai-open");
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
                params.q,
            ) {
                fail!("hadamard-original");
            }

            if crate::snark::cp_snark::encode_commitment_to_bytes(commitment)
                != fold_input.commitment_bytes
                || &fold_input.public_input != public_input
            {
                fail!("fold-input-prefix");
            }
        }
    }

    if !assumptions.cp_relation_checked {
        for ((commitment, opening_bytes), message) in fs_commitments
            .iter()
            .zip(fs_openings.iter())
            .zip(fs_messages.iter())
        {
            let Ok(opening): Result<[u8; 32], _> = opening_bytes.as_slice().try_into() else {
                fail!("fs-opening-bytes");
            };
            let Ok(commitment_arr): Result<[u8; 32], _> = commitment.as_slice().try_into() else {
                fail!("fs-commitment-bytes");
            };
            if !scheme.verify(&commitment_arr, message, &opening) {
                fail!("fs-commitment-open");
            }
        }

        let expected_messages: Vec<Vec<u8>> = folding_proof
            .gr1cs_proofs
            .iter()
            .map(crate::snark::cp_snark::encode_gr1cs_round_message)
            .collect();
        if expected_messages != fs_messages {
            fail!("fs-messages-mismatch");
        }
    }

    if !assumptions.cp_relation_checked {
        if digest_fs_commitments(fs_commitments) != *fs_root {
            fail!("fs-root");
        }
        if digest_fold_inputs(fold_inputs) != *fold_root {
            fail!("fold-root");
        }
    }
    if !assumptions.transcript_seed_checked
        && digest_transcript_seed(
            public_inputs,
            r1cs.num_constraints,
            r1cs.num_variables,
            r1cs.num_public,
        ) != *transcript_seed_digest
    {
        fail!("tsd");
    }

    let transcript_bytes = build_canonical_transcript_bytes(public_inputs, r1cs, fs_commitments);
    let deriver = Sha256ChallengeDeriver;
    let challenges =
        deriver.derive_challenges(b"symphony-v1", &transcript_bytes, fs_commitments.len(), 32);
    if !assumptions.cp_relation_checked && digest_challenges(&challenges) != *challenge_digest {
        fail!("challenge-digest");
    }

    if !assumptions.cp_relation_checked {
        let expected_fold_inputs: Vec<FoldInput> = folding_proof
            .commitments
            .iter()
            .zip(public_inputs.iter())
            .zip(folding_proof.gr1cs_proofs.iter())
            .map(|((c, pi), gr1cs)| FoldInput {
                commitment_bytes: crate::snark::cp_snark::encode_commitment_to_bytes(c),
                public_input: pi.clone(),
                eval_values_bytes: crate::snark::cp_snark::encode_gr1cs_round_message(gr1cs),
            })
            .collect();
        if expected_fold_inputs != fold_inputs
            || digest_fold_inputs(&expected_fold_inputs) != *fold_root
        {
            fail!("expected-fold-inputs");
        }
    }

    let ext_ctx = crate::ring::extension::ExtFieldContext::new(params.q);
    let rp = range_proof_params(params);
    let verified_fold =
        match crate::folding::verify(folding_proof, public_inputs, r1cs, ajtai, &rp, &ext_ctx) {
            Ok(fi) => fi,
            Err(_) => fail!("folding-verify"),
        };

    let q = params.q;
    let (recomputed_public_input, recomputed_folded_witness) =
        match crate::folding::recompute_folded_witness_state(
            folding_proof,
            public_inputs,
            original_witnesses,
            q,
            &ajtai.ntt,
        ) {
            Ok(v) => v,
            Err(_) => fail!("recomputed-folded-state"),
        };

    let recomputed_evals =
        match crate::folding::recompute_folded_evaluation_values(folding_proof, q, &ajtai.ntt) {
            Ok(v) => v,
            Err(_) => fail!("recomputed-folded-evals"),
        };

    if recomputed_public_input != folded_instance.public_input
        || recomputed_evals != folded_instance.evaluation_values
        || &recomputed_folded_witness != folded_witness
    {
        fail!("recomputed-folded-mismatch");
    }

    if !crate::commitment::opening::verify_folded_opening(
        ajtai,
        &folded_instance.commitment,
        &recomputed_public_input,
        &recomputed_folded_witness,
        u128::MAX,
    ) {
        fail!("folded-ajtai-open");
    }

    if crate::snark::cp_snark::encode_folded_instance(&verified_fold)
        != crate::snark::cp_snark::encode_folded_instance(folded_instance)
    {
        fail!("verified-folded-instance");
    }

    true
}

/// The main prover: batch-proves many R1CS statements.
///
/// Generic over `S: BackendSnark` — the same backend is used for both
/// the CP-SNARK and the output SNARK. Use different instantiations
/// of `SymphonyProver` if you need different backends.
pub struct SymphonyProver<S: BackendSnark> {
    pub params: SymphonyParams,
    pub ajtai: crate::commitment::AjtaiParams,
    /// Proving key for the CP-SNARK relation.
    pub cp_pk: S::ProvingKey,
    /// Proving key for the output (folded statement) relation.
    pub snark_pk: S::ProvingKey,
    /// Cache of typed CP proving keys keyed by serialized typed CP context bytes.
    pub cp_pk_cache: std::sync::Mutex<HashMap<Vec<u8>, S::ProvingKey>>,
    /// Cache of output proving keys keyed by serialized output context bytes.
    pub snark_pk_cache: std::sync::Mutex<HashMap<Vec<u8>, S::ProvingKey>>,
    /// CP R1CS layout (used for R1CS-aware backends like WHIR).
    pub cp_layout: cp_snark::CpR1csLayout,
    _marker: PhantomData<S>,
}

/// The main verifier.
pub struct SymphonyVerifier<S: BackendSnark> {
    pub params: SymphonyParams,
    pub ajtai: crate::commitment::AjtaiParams,
    /// Verifying key for the CP-SNARK relation.
    pub cp_vk: S::VerifyingKey,
    /// Verifying key for the output (folded statement) relation.
    pub snark_vk: S::VerifyingKey,
    /// Cache of typed CP verifying keys keyed by serialized typed CP context bytes.
    pub cp_vk_cache: std::sync::Mutex<HashMap<Vec<u8>, S::VerifyingKey>>,
    /// Cache of output verifying keys keyed by serialized output context bytes.
    pub snark_vk_cache: std::sync::Mutex<HashMap<Vec<u8>, S::VerifyingKey>>,
    /// CP R1CS layout (used for R1CS-aware backends like WHIR).
    pub cp_layout: cp_snark::CpR1csLayout,
    _marker: PhantomData<S>,
}

impl<S: BackendSnark> SymphonyProver<S> {
    pub(crate) fn cp_pk_for_relation(&self, relation: RelationDescription) -> S::ProvingKey {
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

        let (pk, _) = S::setup(&relation);
        self.cp_pk_cache
            .lock()
            .expect("cp_pk_cache mutex poisoned")
            .insert(key, pk.clone());
        pk
    }

    pub(crate) fn snark_pk_for_context(&self, output_context: Vec<u8>) -> S::ProvingKey {
        if let Some(pk) = self
            .snark_pk_cache
            .lock()
            .expect("snark_pk_cache mutex poisoned")
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
        let (pk, _) = S::setup(&relation);

        self.snark_pk_cache
            .lock()
            .expect("snark_pk_cache mutex poisoned")
            .insert(output_context, pk.clone());
        pk
    }

    /// Setup: generate MSIS matrix and SNARK parameters.
    ///
    /// Calls `S::setup` twice: once for the CP-SNARK relation (folding
    /// correctness) and once for the output relation (folded R1CS).
    pub fn setup(params: SymphonyParams) -> (Self, SymphonyVerifier<S>) {
        params.validate();
        let ajtai =
            crate::commitment::AjtaiParams::setup(params.kappa, params.n(), params.q, params.ntt());

        // Generate CP R1CS encoding folding linear combination constraints.
        // The CP-SNARK proves c* = Σ beta·c and x* = Σ beta·x (ring arithmetic).
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(params.q);
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
            context: S::serialize_cp_context(&cp_r1cs, params.q, params.d),
        };
        let (cp_pk, cp_vk) = S::setup(&cp_relation);

        let snark_relation = RelationDescription {
            num_instance_vars: params.n(),
            num_witness_vars: params.n(),
            num_constraints: params.m,
            context: None,
        };
        let (snark_pk, snark_vk) = S::setup(&snark_relation);

        let verifier = SymphonyVerifier {
            params: params.clone(),
            ajtai: ajtai.clone(),
            cp_vk,
            snark_vk,
            cp_vk_cache: std::sync::Mutex::new(HashMap::new()),
            snark_vk_cache: std::sync::Mutex::new(HashMap::new()),
            cp_layout: cp_layout.clone(),
            _marker: PhantomData,
        };
        let prover = Self {
            params,
            ajtai,
            cp_pk,
            snark_pk,
            cp_pk_cache: std::sync::Mutex::new(HashMap::new()),
            snark_pk_cache: std::sync::Mutex::new(HashMap::new()),
            cp_layout,
            _marker: PhantomData,
        };
        (prover, verifier)
    }

    /// Commit to a single R1CS witness (streaming-friendly).
    pub fn commit_witness(&self, witness: &RingVector) -> (Commitment, crate::commitment::Opening) {
        self.ajtai.commit(witness)
    }

    /// Generate the full SNARK proof.
    pub fn prove(
        &self,
        statements: &[(Commitment, Vec<i64>, RingVector)],
        r1cs: &R1CSMatrices,
    ) -> SymphonyProof<S> {
        prover::generate_proof::<S>(
            &self.params,
            &self.ajtai,
            &self.cp_pk,
            &|relation| self.cp_pk_for_relation(relation),
            &self.snark_pk,
            &|ctx| self.snark_pk_for_context(ctx),
            &self.cp_layout,
            statements,
            r1cs,
        )
    }

    /// Generate a public-only v2 proof.
    ///
    /// Proving still constructs witness-side data internally to feed the CP
    /// backend, but the returned proof drops that data before it crosses the
    /// public API boundary.
    ///
    /// Compatibility alias: product-facing callers should prefer
    /// [`Self::prove_public`].
    #[must_use]
    pub fn prove_v2(
        &self,
        statements: &[(Commitment, Vec<i64>, RingVector)],
        r1cs: &R1CSMatrices,
    ) -> SymphonyProofV2<S> {
        self.prove(statements, r1cs).to_v2()
    }

    /// Generate the canonical public-only proof.
    ///
    /// This is the product-facing API. The returned proof contains only public
    /// verifier data and backend proofs; it does not expose witness-side CP
    /// data, FS openings/messages, fold inputs, original witnesses, folding
    /// proof internals, or folded witnesses.
    #[must_use]
    pub fn prove_public(
        &self,
        statements: &[(Commitment, Vec<i64>, RingVector)],
        r1cs: &R1CSMatrices,
    ) -> PublicSymphonyProof<S> {
        self.prove_v2(statements, r1cs)
    }
}

impl<S: BackendSnark> SymphonyVerifier<S> {
    pub(crate) fn cp_vk_for_relation(&self, relation: RelationDescription) -> S::VerifyingKey {
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

        let (_, vk) = S::setup(&relation);
        self.cp_vk_cache
            .lock()
            .expect("cp_vk_cache mutex poisoned")
            .insert(key, vk.clone());
        vk
    }

    fn typed_cp_descriptor(&self, r1cs: &R1CSMatrices) -> TypedCpSetupDescriptor {
        let ext_ctx = crate::ring::extension::ExtFieldContext::new(self.params.q);
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

    pub(crate) fn snark_vk_for_context(&self, output_context: Vec<u8>) -> S::VerifyingKey {
        if let Some(vk) = self
            .snark_vk_cache
            .lock()
            .expect("snark_vk_cache mutex poisoned")
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
        let (_, vk) = S::setup(&relation);

        self.snark_vk_cache
            .lock()
            .expect("snark_vk_cache mutex poisoned")
            .insert(output_context, vk.clone());
        vk
    }

    /// Verify a Symphony proof against public inputs.
    ///
    /// Verification proceeds in three layers:
    /// 1. check `transcript_seed_digest` against the supplied public inputs,
    /// 2. verify the backend CP proof,
    /// 3. verify the backend output proof and then run explicit witness-side
    ///    consistency checks over the carried proof data.
    ///
    /// The current verifier therefore includes an O(k) explicit soundness pass
    /// over witness-side transcript/folding data in addition to backend proof
    /// verification.
    ///
    /// Timing: when `SYMPHONY_TIMING=1` is set, prints per-stage durations to stderr.
    #[must_use]
    pub fn verify(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &SymphonyProof<S>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        let timing = std::env::var("SYMPHONY_TIMING").is_ok_and(|v| v == "1");
        let t0 = std::time::Instant::now();

        // ---------------------------------------------------------------
        // Step 1: Verify transcript_seed_digest — O(|public_inputs|)
        //
        // The transcript seed binds the proof to the specific public inputs
        // and R1CS dimensions. This is the only O(|public_inputs|) work the
        // verifier performs; everything else is O(1) + backend verification.
        // ---------------------------------------------------------------
        {
            let expected_tsd = digest_transcript_seed_with_scheme(
                S::public_digest_scheme(),
                public_inputs,
                r1cs.num_constraints,
                r1cs.num_variables,
                r1cs.num_public,
            );
            if expected_tsd != proof.transcript_seed_digest {
                return false;
            }
        }
        let t_transcript = t0.elapsed();

        // ---------------------------------------------------------------
        // Step 2: Verify CP-SNARK — O(log N) via backend
        //
        // Phase A: proves the folding linear combination
        //   c*[i] = Σ beta[ℓ] · c_ℓ[i]   (commitment folding)
        //   x*[s] = Σ beta[ℓ] · x_in[ℓ][s]  (public input folding)
        //
        // The verifier builds the CP backend instance using:
        // - R1CS-compatible folded instance prefix
        // - digest-binding trailer (fold_root, fs_root, transcript_seed_digest, challenge_digest)
        // and calls `S::verify`.
        // ---------------------------------------------------------------
        let t_cp_start = std::time::Instant::now();

        let typed_cp_public_instance = TypedCpPublicInstance {
            fs_root: proof.fs_root,
            fold_root: proof.fold_root,
            challenge_digest: proof.challenge_digest,
            transcript_seed_digest: proof.transcript_seed_digest,
            x_folded: proof.folded_instance.clone(),
            folded_output: proof.folded_output.clone(),
        };
        let typed_cp_witness = TypedCpWitnessBundle {
            transcript_bytes: proof.witness_data.transcript_bytes.clone(),
            fs_commitments: proof.witness_data.fs_commitments.clone(),
            fs_openings: proof.witness_data.fs_openings.clone(),
            fs_messages: proof.witness_data.fs_messages.clone(),
            fold_inputs: proof.witness_data.fold_inputs.clone(),
            original_witnesses: proof.witness_data.original_witnesses.clone(),
            folded_output: proof.folded_instance.clone(),
            folded_output_instance: proof.folded_output.clone(),
            folded_output_witness: proof.witness_data.folded_output_witness.clone(),
            folded_witness: proof.witness_data.folded_witness.clone(),
            folding_proof: proof.witness_data.folding_proof.clone(),
            shared_challenges: proof.witness_data.shared_challenges.clone(),
        };
        let typed_cp_public_statement = CpPublicStatement::new(
            typed_cp_public_instance.clone(),
            public_inputs.to_vec(),
            r1cs,
            S::public_digest_scheme(),
        )
        .with_fs_commitments(proof.witness_data.fs_commitments.clone());
        let cp_relation_ok = if S::public_digest_scheme() == PublicDigestScheme::Sha256 {
            crate::cp_relation_core::CpRelation::check_with_algebra(
                &typed_cp_public_instance,
                &typed_cp_witness,
                &self.ajtai,
                r1cs,
                self.params.b_input(),
            )
        } else {
            crate::cp_relation_core::CpFieldRelation::check(
                &typed_cp_public_statement,
                &typed_cp_witness,
                &self.ajtai,
                r1cs,
                self.params.b_input(),
            )
        };
        if cp_relation_ok.is_err() {
            return false;
        }

        let cp_public_instance = cp_snark::CpPublicInstance {
            fold_root: proof.fold_root,
            fs_root: proof.fs_root,
            transcript_seed_digest: proof.transcript_seed_digest,
            challenge_digest: proof.challenge_digest,
            folded_instance: proof.folded_instance.clone(),
        };
        let cp_instance =
            cp_snark::encode_cp_backend_instance(&cp_public_instance, &self.cp_layout);
        let cp_backend_ok = if S::has_authoritative_typed_cp() {
            let Some(cp_relation) =
                S::typed_cp_relation_description(&self.typed_cp_descriptor(r1cs))
            else {
                return false;
            };
            let cp_vk = self.cp_vk_for_relation(cp_relation);
            S::verify_typed_cp(&cp_vk, &typed_cp_public_statement, &proof.cp_proof) == Some(true)
        } else {
            S::verify(&self.cp_vk, &cp_instance, &proof.cp_proof)
        };
        if !cp_backend_ok {
            return false;
        }
        let t_cp = t_cp_start.elapsed();

        // ---------------------------------------------------------------
        // Step 3: Verify output SNARK — O(log N) via backend
        //
        // Proves the folded R1CS statement is satisfied.
        // ---------------------------------------------------------------
        let t_output_start = std::time::Instant::now();
        let snark_instance = cp_snark::encode_folded_instance(&proof.folded_instance);

        let d = self.params.d;
        let instance_elems = snark_instance.len() / 8;
        let total_flat = r1cs.num_variables * d;

        let output_backend_ok =
            if let Some(output_context) = S::serialize_output_context(r1cs, self.params.q, d) {
                let output_vk = self.snark_vk_for_context(output_context);
                if S::has_authoritative_typed_output() {
                    S::verify_typed_output(&output_vk, &proof.folded_output, &proof.snark_proof)
                        .unwrap_or(false)
                } else if instance_elems <= total_flat {
                    S::verify(&output_vk, &snark_instance, &proof.snark_proof)
                } else {
                    S::verify(&self.snark_vk, &snark_instance, &proof.snark_proof)
                }
            } else {
                S::verify(&self.snark_vk, &snark_instance, &proof.snark_proof)
            };
        if !output_backend_ok {
            return false;
        }

        if S::public_digest_scheme() != PublicDigestScheme::Sha256 {
            let t_output = t_output_start.elapsed();
            if timing {
                let t_total = t0.elapsed();
                eprintln!(
                    "[symphony-verify] transcript={:.3}ms cp_verify={:.3}ms output_verify={:.3}ms total={:.3}ms",
                    t_transcript.as_secs_f64() * 1000.0,
                    t_cp.as_secs_f64() * 1000.0,
                    t_output.as_secs_f64() * 1000.0,
                    t_total.as_secs_f64() * 1000.0,
                );
            }
            return true;
        }

        let explicit_ok = verify_explicit_soundness(
            &self.params,
            &self.ajtai,
            public_inputs,
            &proof.witness_data.original_witnesses,
            &proof.witness_data.fs_commitments,
            &proof.witness_data.fs_openings,
            &proof.witness_data.fs_messages,
            &proof.witness_data.fold_inputs,
            &proof.witness_data.folding_proof,
            &proof.folded_instance,
            &proof.witness_data.folded_witness,
            &proof.fs_root,
            &proof.fold_root,
            &proof.challenge_digest,
            &proof.transcript_seed_digest,
            r1cs,
            ExplicitSoundnessAssumptions {
                transcript_seed_checked: true,
                cp_relation_checked: true,
            },
        );
        if !explicit_ok {
            return false;
        }
        let t_output = t_output_start.elapsed();

        if timing {
            let t_total = t0.elapsed();
            eprintln!(
                "[symphony-verify] transcript={:.3}ms cp_verify={:.3}ms output_verify={:.3}ms total={:.3}ms",
                t_transcript.as_secs_f64() * 1000.0,
                t_cp.as_secs_f64() * 1000.0,
                t_output.as_secs_f64() * 1000.0,
                t_total.as_secs_f64() * 1000.0,
            );
        }

        true
    }

    /// Verify a public-only v2 proof.
    ///
    /// This path uses only public inputs, public FS commitments/digests, the
    /// folded output instance, and backend proofs. It deliberately does not run
    /// [`verify_explicit_soundness`] or inspect witness-side CP data. Backends
    /// must explicitly advertise authoritative typed CP and output support.
    ///
    /// Compatibility alias: product-facing callers should prefer
    /// [`Self::verify_public`]. For WHIR, this path uses the backend-selected
    /// Poseidon2/BabyBear digest scheme and never falls back to SHA-256 or
    /// legacy witness-side verification.
    #[must_use]
    pub fn verify_v2(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &SymphonyProofV2<S>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        if !proof.public_boundary_is_well_formed_with_scheme(
            S::public_digest_scheme(),
            public_inputs,
            r1cs,
        ) {
            return false;
        }

        if !S::has_authoritative_typed_cp() {
            return false;
        }
        let typed_cp_public_statement =
            proof.typed_cp_public_statement(public_inputs, r1cs, S::public_digest_scheme());
        let Some(cp_relation) = S::typed_cp_relation_description(&self.typed_cp_descriptor(r1cs))
        else {
            return false;
        };
        let cp_vk = self.cp_vk_for_relation(cp_relation);
        if S::verify_typed_cp(&cp_vk, &typed_cp_public_statement, &proof.cp_proof) != Some(true) {
            return false;
        }

        if !S::has_authoritative_typed_output() {
            return false;
        }
        let d = self.params.d;
        let Some(output_context) = S::serialize_output_context(r1cs, self.params.q, d) else {
            return false;
        };
        let output_vk = self.snark_vk_for_context(output_context);
        S::verify_typed_output(&output_vk, &proof.folded_output, &proof.output_proof) == Some(true)
    }

    /// Verify the canonical public-only proof.
    ///
    /// This is the product-facing API. It must remain public-only: no witness
    /// bundle, no FS openings/messages, no fold inputs, no explicit soundness
    /// fallback, and no legacy SHA fallback for WHIR. Verification fails closed
    /// unless the backend advertises authoritative typed CP and typed output
    /// verification.
    #[must_use]
    pub fn verify_public(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &PublicSymphonyProof<S>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        self.verify_v2(public_inputs, proof, r1cs)
    }
}

// ---------------------------------------------------------------------------
// DummySnark: a trivial BackendSnark for testing
// ---------------------------------------------------------------------------

/// A trivial SNARK implementation that accepts all proofs.
///
/// # Security
///
/// **`DummySnark` provides ZERO soundness.** It accepts any proof with the correct
/// prefix tag, regardless of instance or witness. It exists solely for testing
/// pipeline wiring and API integration.
///
/// **DO NOT use in production.** Replace with `SpartanSnark`, `SumcheckSnark`,
/// or a real backend (LaBRADOR, WHIR, HyperPlonk+KZG).
pub struct DummySnark;

#[derive(Debug, Clone)]
pub struct DummyProvingKey {
    pub relation: RelationDescription,
}

#[derive(Debug, Clone)]
pub struct DummyVerifyingKey {
    pub relation: RelationDescription,
}

#[derive(Debug, Clone)]
pub struct DummyProof {
    /// Tagged bytes so the verifier can distinguish empty from actual proofs.
    pub data: Vec<u8>,
}

impl BackendSnark for DummySnark {
    type ProvingKey = DummyProvingKey;
    type VerifyingKey = DummyVerifyingKey;
    type Proof = DummyProof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        (
            DummyProvingKey {
                relation: relation.clone(),
            },
            DummyVerifyingKey {
                relation: relation.clone(),
            },
        )
    }

    fn prove(pk: &Self::ProvingKey, instance: &[u8], _witness: &[u8]) -> Self::Proof {
        let mut data = b"dummy-proof:".to_vec();
        data.extend_from_slice(&(pk.relation.num_constraints as u64).to_le_bytes());
        data.extend_from_slice(&(instance.len() as u64).to_le_bytes());
        DummyProof { data }
    }

    fn verify(_vk: &Self::VerifyingKey, _instance: &[u8], proof: &Self::Proof) -> bool {
        proof.data.starts_with(b"dummy-proof:")
    }
}

/// Convenience type alias using the dummy backend (for testing).
pub type DummySymphonyProof = SymphonyProof<DummySnark>;
pub type DummySymphonyProver = SymphonyProver<DummySnark>;
pub type DummySymphonyVerifier = SymphonyVerifier<DummySnark>;
