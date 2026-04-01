//! Reductions of Knowledge (RoK) — the protocol building blocks.

pub mod gr1cs;
pub mod hadamard;
pub mod monomial;
pub mod range_proof;

use crate::commitment::Commitment;
use crate::ring::extension::ExtFieldElement;
use crate::ring::tensor::TensorElement;

/// Canonical 3-component tensor evaluation tuple used by Hadamard relations.
pub type EvaluationTriple = [TensorElement; 3];

/// A linear relation instance: commitment c with evaluation point r
/// and evaluation values v ∈ E^3.
#[derive(Debug, Clone)]
pub struct LinearRelation {
    /// Main commitment bound by the relation.
    pub commitment: Commitment,
    /// Evaluation point in extension field coordinates.
    pub evaluation_point: Vec<ExtFieldElement>,
    /// Three tensor evaluations corresponding to the Hadamard checks.
    pub evaluation_values: EvaluationTriple,
}

/// A batched linear relation (output of range proof / folding).
#[derive(Debug, Clone)]
pub struct BatchedLinearRelation {
    /// Batched commitments opened at a shared point.
    pub commitments: Vec<Commitment>,
    /// Shared evaluation point.
    pub evaluation_point: Vec<ExtFieldElement>,
    /// Batched evaluation values.
    pub evaluation_values: Vec<TensorElement>,
}
