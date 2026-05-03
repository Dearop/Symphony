//! Symphony: Scalable SNARKs from lattice-based high-arity folding.
//!
//! This crate implements the Symphony construction from "Symphony: Scalable SNARKs
//! in the Random Oracle Model from Lattice-Based High-Arity Folding" (Chen, 2025).
//!
//! Symphony replaces hash-based Merkle tree commitments in ZK systems with
//! module-Ajtai lattice commitments combined with a high-arity folding scheme
//! and a commit-and-prove compiler that never places Fiat-Shamir hashes inside
//! the proven statement.
//!
//! # Backend SNARK
//!
//! The [`snark::BackendSnark`] trait abstracts the proof system used for both
//! the CP-SNARK (folding correctness) and the output SNARK (folded statement).
//! Implement this trait to plug in a concrete backend:
//!
//! - **Post-quantum:** LaBRADOR, WHIR (50–100 KB proofs)
//! - **Pairing-based:** HyperPlonk + KZG (< 50 KB proofs, not PQ)
//!
//! [`snark::DummySnark`] and [`snark::sumcheck_snark::SumcheckSnark`] are
//! provided for testing and integration checks.

pub mod commitment;
pub mod cp_snark;
pub mod decomposition;
pub mod fiat_shamir;
pub mod folding;
pub mod modular;
pub mod params;
pub mod r1cs;
pub mod ring;
pub mod rok;
pub mod snark;
pub mod sumcheck;

// Preserve existing crate-level module paths while keeping implementation grouped.
pub use modular::adapter_symphony;
pub use modular::cp_backend_api;
pub use modular::cp_relation_core;
pub use modular::digest_core;
pub use modular::folding_core;
pub use modular::output_backend_api;
pub use modular::proof_orchestrator;
pub use modular::public_proof;
pub use modular::transcript_core;

pub use commitment::{AjtaiParams, Commitment};
pub use cp_relation_core::{
    CpPublicInstance as ModularCpPublicInstance, CpPublicStatement, CpWitnessBundle,
};
pub use cp_snark::{CPProof, CPSnark, CommittedRelation};
pub use fiat_shamir::hash_commitment::HashCommitment;
pub use params::SymphonyParams;
pub use proof_orchestrator::{
    ProofBundle, ProofBundleV2, Prover as ModularProver, PublicProofBundle,
    Verifier as ModularVerifier,
};
pub use public_proof::{
    PublicProofEnvelope, PublicProofEnvelopeError, PUBLIC_PROOF_ENVELOPE_VERSION,
};
pub use r1cs::R1CSMatrices;
pub use snark::spartan::{SpartanProof, SpartanProvingKey, SpartanSnark, SpartanVerifyingKey};
pub use snark::sumcheck_snark::{
    SumcheckProofData, SumcheckProvingKey, SumcheckSnark, SumcheckVerifyingKey,
};
#[cfg(feature = "whir")]
pub use snark::whir::{
    canonical_whir_proof_bytes, whir_proof_from_canonical_bytes, WhirProof, WhirProofPayloadError,
    WhirProvingKey, WhirSnark, WhirVerifyingKey, WHIR_PROOF_PAYLOAD_VERSION,
};
pub use snark::{
    BackendSnark, PublicSymphonyProof, SymphonyProof, SymphonyProofV2, SymphonyProver,
    SymphonyVerifier,
};
pub use snark::{DummySnark, DummySymphonyProof, DummySymphonyProver, DummySymphonyVerifier};
