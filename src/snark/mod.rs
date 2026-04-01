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

pub mod cp_snark;
pub mod prover;
pub mod spartan;
pub mod sumcheck_snark;
#[cfg(feature = "whir")]
pub mod whir;

use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::folding::digest::Digest32;
use crate::folding::FoldedInstance;
use crate::params::SymphonyParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::RingVector;

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
/// The verifier reads only top-level O(1) fields:
/// - `cp_proof`
/// - `snark_proof` (output proof)
/// - `folded_instance`
/// - `fold_root`, `challenge_digest`, `fs_root`, `transcript_seed_digest`
///
/// All O(k) transcript/folding objects remain in `witness_data`.
#[derive(Debug, Clone)]
pub struct SymphonyProof<S: BackendSnark> {
    // -- Verifier-visible fields (O(1) total size) --
    /// CP-SNARK proof π_cp (proves folding correctness).
    pub cp_proof: S::Proof,
    /// Output SNARK proof π (proves the folded statement).
    pub snark_proof: S::Proof,
    /// The folded instance x_o.
    pub folded_instance: FoldedInstance,
    /// SHA-256 digest binding all per-instance fold inputs.
    pub fold_root: Digest32,
    /// SHA-256 digest of the derived challenge sequence.
    pub challenge_digest: Digest32,
    /// SHA-256 digest of all FS commitments.
    pub fs_root: Digest32,
    /// SHA-256 digest of static transcript metadata (public inputs + R1CS dims).
    pub transcript_seed_digest: Digest32,

    // -- Witness data (O(k), not read by verifier) --
    /// Full witness data needed for serialization and CP relation verification.
    /// The verifier never inspects this; the CP-SNARK proves its consistency.
    pub witness_data: ProofWitnessData,
}

impl<S: BackendSnark> SymphonyProof<S> {
    /// Naming-consistent accessor for the output proof.
    ///
    /// The stored field is `snark_proof` for backwards compatibility.
    pub fn output_proof(&self) -> &S::Proof {
        &self.snark_proof
    }
}

/// O(k) witness data bundled with the proof for serialization.
///
/// The verifier does not read any of these fields — the CP-SNARK proves
/// their consistency with the constant-size digests.
#[derive(Debug, Clone)]
pub struct ProofWitnessData {
    /// Fiat-Shamir commitments {c_{fs,i}}.
    pub fs_commitments: Vec<Vec<u8>>,
    /// FS commitment openings.
    pub fs_openings: Vec<Vec<u8>>,
    /// FS committed messages (deterministic folding round encodings).
    pub fs_messages: Vec<Vec<u8>>,
    /// Per-instance fold inputs.
    pub fold_inputs: Vec<crate::folding::digest::FoldInput>,
    /// Full folding proof.
    pub folding_proof: crate::folding::FoldingProof,
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
    /// CP R1CS layout (used for R1CS-aware backends like WHIR).
    pub cp_layout: cp_snark::CpR1csLayout,
    _marker: PhantomData<S>,
}

impl<S: BackendSnark> SymphonyProver<S> {
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
        );
        let cp_context = cp_snark::serialize_cp_context(&cp_r1cs, params.q, params.d as usize);
        let cp_relation = RelationDescription {
            num_instance_vars: cp_layout.num_instance,
            num_witness_vars: cp_layout.num_variables - cp_layout.num_instance,
            num_constraints: cp_r1cs.num_constraints,
            context: Some(cp_context),
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
            cp_layout: cp_layout.clone(),
            _marker: PhantomData,
        };
        let prover = Self {
            params,
            ajtai,
            cp_pk,
            snark_pk,
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
            &self.snark_pk,
            &self.cp_layout,
            statements,
            r1cs,
        )
    }
}

impl<S: BackendSnark> SymphonyVerifier<S> {
    /// Verify a Symphony proof against public inputs.
    ///
    /// **O(1) + O(log N)** in the number of folding rounds k:
    /// 1. Check transcript_seed_digest matches public inputs — O(|public_inputs|)
    /// 2. Verify CP-SNARK (proves folding correctness) — O(log N) via backend
    /// 3. Verify output SNARK (proves folded statement) — O(log N) via backend
    ///
    /// All O(k) checks (FS commitment replay, challenge derivation, fold input
    /// verification, commitment opening) are proven by the CP-SNARK.
    ///
    /// Timing: when `SYMPHONY_TIMING=1` is set, prints per-stage durations to stderr.
    #[must_use]
    pub fn verify(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &SymphonyProof<S>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        let timing = std::env::var("SYMPHONY_TIMING").map_or(false, |v| v == "1");
        let t0 = std::time::Instant::now();

        // ---------------------------------------------------------------
        // Step 1: Verify transcript_seed_digest — O(|public_inputs|)
        //
        // The transcript seed binds the proof to the specific public inputs
        // and R1CS dimensions. This is the only O(|public_inputs|) work the
        // verifier performs; everything else is O(1) + backend verification.
        // ---------------------------------------------------------------
        {
            let expected_tsd = crate::folding::digest::digest_transcript_seed(
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

        let cp_public_instance = cp_snark::CpPublicInstance {
            fold_root: proof.fold_root,
            fs_root: proof.fs_root,
            transcript_seed_digest: proof.transcript_seed_digest,
            challenge_digest: proof.challenge_digest,
            folded_instance: proof.folded_instance.clone(),
        };
        let cp_instance =
            cp_snark::encode_cp_backend_instance(&cp_public_instance, &self.cp_layout);
        if !S::verify(&self.cp_vk, &cp_instance, &proof.cp_proof) {
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

        let d = self.params.d as usize;
        let instance_elems = snark_instance.len() / 8;
        let total_flat = r1cs.num_variables * d;

        let output_vk = if instance_elems <= total_flat {
            let output_context = cp_snark::serialize_output_context(r1cs, self.params.q, d);
            let output_relation = RelationDescription {
                num_instance_vars: self.params.n(),
                num_witness_vars: self.params.n(),
                num_constraints: self.params.m,
                context: Some(output_context),
            };
            let (_, vk) = S::setup(&output_relation);
            vk
        } else {
            self.snark_vk.clone()
        };
        if !S::verify(&output_vk, &snark_instance, &proof.snark_proof) {
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
