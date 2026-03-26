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
//! A [`snark::DummySnark`] is provided for testing.

pub mod ring;
pub mod commitment;
pub mod decomposition;
pub mod sumcheck;
pub mod rok;
pub mod folding;
pub mod fiat_shamir;
pub mod snark;
pub mod r1cs;
pub mod params;

pub use params::SymphonyParams;
pub use commitment::{AjtaiParams, Commitment};
pub use r1cs::R1CSMatrices;
pub use snark::{BackendSnark, SymphonyProver, SymphonyVerifier, SymphonyProof};
pub use snark::{DummySnark, DummySymphonyProver, DummySymphonyVerifier, DummySymphonyProof};
