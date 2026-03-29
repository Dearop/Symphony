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
pub mod params;
pub mod r1cs;
pub mod ring;
pub mod rok;
pub mod snark;
pub mod sumcheck;

pub use commitment::{AjtaiParams, Commitment};
pub use cp_snark::{CPProof, CPSnark, CommittedRelation};
pub use fiat_shamir::hash_commitment::HashCommitment;
pub use params::SymphonyParams;
pub use r1cs::R1CSMatrices;
pub use snark::sumcheck_snark::{
    SumcheckProofData, SumcheckProvingKey, SumcheckSnark, SumcheckVerifyingKey,
};
pub use snark::{BackendSnark, SymphonyProof, SymphonyProver, SymphonyVerifier};
pub use snark::{DummySnark, DummySymphonyProof, DummySymphonyProver, DummySymphonyVerifier};
pub use snark::spartan::{SpartanSnark, SpartanProof, SpartanProvingKey, SpartanVerifyingKey};
#[cfg(feature = "whir")]
pub use snark::whir::{WhirSnark, WhirProof, WhirProvingKey, WhirVerifyingKey};
