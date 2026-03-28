//! SNARK construction (Construction 6.1) — the commit-and-prove compiler.
//!
//! The SNARK statement never embeds the Fiat-Shamir hash.
//!
//! Setup: choose Π_cm (Merkle or KZG), setup CP-SNARK, setup backend SNARK.
//!
//! Prover:
//!   1. Run non-interactive folding (Fiat-Shamir applied)
//!   2. At each round, commit to messages with Π_cm
//!   3. Obtain folded instance and witness
//!   4. Generate SNARK proof π for the folded statement
//!   5. Generate CP-SNARK proof π_cp for folding correctness
//!   6. Output π* = (π_cp, π, {c_{fs,i}}, x_o)
//!
//! Verifier:
//!   1. Recompute challenges from (x, {c_{fs,i}}) and H
//!   2. Check Π_cp.Verify(π_cp) — proves folding WITHOUT hash-in-circuit
//!   3. Check Π_snark.Verify(π) — proves the folded statement

pub mod cp_snark;
pub mod prover;
pub mod sumcheck_snark;

use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::folding::FoldedInstance;
use crate::params::SymphonyParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::RingVector;

/// Backend SNARK trait — Symphony is generic over the final proof system.
///
/// Possible backends:
/// - Post-quantum: LaBRADOR, WHIR (50–100KB proofs)
/// - Pairing-based: HyperPlonk + KZG (< 50KB proofs, not PQ)
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
}

/// A complete Symphony proof, generic over the backend SNARK `S`.
///
/// Contains two sub-proofs:
/// - `cp_proof`: proves that the Fiat-Shamir commitments open to a valid
///   folding transcript (the CP-SNARK proof π_cp)
/// - `snark_proof`: proves the folded R1CS statement (the output SNARK proof π)
#[derive(Debug, Clone)]
pub struct SymphonyProof<S: BackendSnark> {
    /// CP-SNARK proof π_cp (proves folding correctness).
    pub cp_proof: S::Proof,
    /// Output SNARK proof π (proves the folded statement).
    pub snark_proof: S::Proof,
    /// Fiat-Shamir commitments {c_{fs,i}}.
    pub fs_commitments: Vec<Vec<u8>>,
    /// The folded instance x_o.
    pub folded_instance: FoldedInstance,
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
    _marker: PhantomData<S>,
}

impl<S: BackendSnark> SymphonyProver<S> {
    /// Setup: generate MSIS matrix and SNARK parameters.
    ///
    /// Calls `S::setup` twice: once for the CP-SNARK relation (folding
    /// correctness) and once for the output relation (folded R1CS).
    pub fn setup(params: SymphonyParams) -> (Self, SymphonyVerifier<S>) {
        let ajtai = crate::commitment::AjtaiParams::setup(params.kappa, params.n(), params.q);

        let cp_relation = RelationDescription {
            num_instance_vars: params.ell_np,
            num_witness_vars: params.ell_np * params.m,
            num_constraints: params.ell_np,
        };
        let (cp_pk, cp_vk) = S::setup(&cp_relation);

        let snark_relation = RelationDescription {
            num_instance_vars: params.n(),
            num_witness_vars: params.n(),
            num_constraints: params.m,
        };
        let (snark_pk, snark_vk) = S::setup(&snark_relation);

        let verifier = SymphonyVerifier {
            params: params.clone(),
            ajtai: ajtai.clone(),
            cp_vk,
            snark_vk,
            _marker: PhantomData,
        };
        let prover = Self {
            params,
            ajtai,
            cp_pk,
            snark_pk,
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
            statements,
            r1cs,
        )
    }
}

impl<S: BackendSnark> SymphonyVerifier<S> {
    /// Verify a Symphony proof against public inputs.
    ///
    /// Internally:
    /// 1. Bind public inputs and R1CS metadata to the transcript
    /// 2. Recompute challenges from (x, {c_{fs,i}}) and H
    /// 3. Check Π_cp.Verify(π_cp) — proves folding correctness without hash-in-circuit
    /// 4. Check Π_snark.Verify(π) — proves the folded statement
    pub fn verify(
        &self,
        public_inputs: &[Vec<i64>],
        proof: &SymphonyProof<S>,
        r1cs: &R1CSMatrices,
    ) -> bool {
        // Step 1: Recompute challenges from transcript
        let mut transcript = crate::fiat_shamir::transcript::Transcript::new(b"symphony-v1");

        // Bind public inputs to the transcript so they cannot be swapped
        for pi in public_inputs {
            let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
            transcript.append_bytes(b"public-input", &bytes);
        }

        // Bind R1CS metadata
        transcript.append_bytes(b"r1cs-m", &(r1cs.num_constraints as u64).to_le_bytes());
        transcript.append_bytes(b"r1cs-n", &(r1cs.num_variables as u64).to_le_bytes());
        transcript.append_bytes(b"r1cs-pub", &(r1cs.num_public as u64).to_le_bytes());

        for fs_comm in &proof.fs_commitments {
            transcript.append_bytes(b"fs-commitment", fs_comm);
        }

        // Step 2: Verify CP-SNARK
        let cp_instance = cp_snark::encode_cp_instance(
            &proof.fs_commitments,
            &proof.folded_instance,
            &mut transcript,
        );
        if !S::verify(&self.cp_vk, &cp_instance, &proof.cp_proof) {
            return false;
        }

        // Step 3: Verify backend SNARK proof for the folded statement
        let snark_instance = cp_snark::encode_folded_instance(&proof.folded_instance);
        if !S::verify(&self.snark_vk, &snark_instance, &proof.snark_proof) {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// DummySnark: a trivial BackendSnark for testing
// ---------------------------------------------------------------------------

/// A trivial SNARK implementation that accepts all proofs.
///
/// **Not secure** — use only for testing the pipeline wiring.
/// Replace with a real backend (LaBRADOR, WHIR, HyperPlonk+KZG) for production.
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
