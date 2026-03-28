//! Reductions of Knowledge (RoK) — the protocol building blocks.

pub mod gr1cs;
pub mod hadamard;
pub mod monomial;
pub mod range_proof;

use crate::commitment::Commitment;
use crate::ring::extension::ExtFieldElement;
use crate::ring::tensor::TensorElement;

/// A linear relation instance: commitment c with evaluation point r
/// and evaluation values v ∈ E^3.
#[derive(Debug, Clone)]
pub struct LinearRelation {
    pub commitment: Commitment,
    pub evaluation_point: Vec<ExtFieldElement>,
    pub evaluation_values: [TensorElement; 3],
}

/// A batched linear relation (output of range proof / folding).
#[derive(Debug, Clone)]
pub struct BatchedLinearRelation {
    pub commitments: Vec<Commitment>,
    pub evaluation_point: Vec<ExtFieldElement>,
    pub evaluation_values: Vec<TensorElement>,
}
