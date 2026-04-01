//! Generic folding-domain types and fold semantics interface.

use crate::commitment::AjtaiParams;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::ExtFieldContext;
use crate::rok::gr1cs::GR1CSChallenges;
use crate::rok::range_proof::RangeProofParams;

pub type Statement = crate::folding::FoldingStatement;
pub use crate::folding::{FoldedInstance, FoldedWitness, FoldingProof};

/// Backend-independent folding semantics.
pub trait FoldSemantics {
    fn fold(
        &self,
        statements: &[Statement],
        r1cs: &R1CSMatrices,
        ajtai: &AjtaiParams,
        range_params: &RangeProofParams,
        ctx: &ExtFieldContext,
    ) -> (FoldingProof, FoldedWitness, GR1CSChallenges);
}

/// Adapter using Symphony's current folding implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SymphonyFoldSemantics;

impl FoldSemantics for SymphonyFoldSemantics {
    fn fold(
        &self,
        statements: &[Statement],
        r1cs: &R1CSMatrices,
        ajtai: &AjtaiParams,
        range_params: &RangeProofParams,
        ctx: &ExtFieldContext,
    ) -> (FoldingProof, FoldedWitness, GR1CSChallenges) {
        crate::folding::prove(statements, r1cs, ajtai, range_params, ctx)
    }
}
