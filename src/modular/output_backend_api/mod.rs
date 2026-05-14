//! Backend-agnostic folded-output proving API.

use crate::snark::{BackendSnark, RelationDescription};

pub trait OutputBackend {
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: Clone + std::fmt::Debug;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey);
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof;
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool;
    fn serialize_output_context(
        r1cs: &crate::r1cs::R1CSMatrices,
        q: u64,
        d: usize,
    ) -> Option<Vec<u8>>;
    /// Security gate for public folded-output verification.
    ///
    /// Typed output helper hooks are ignored by public routing unless this
    /// returns true.
    fn has_authoritative_typed_output() -> bool {
        false
    }
    fn prove_typed_output(
        pk: &Self::ProvingKey,
        instance: &crate::folding::FoldedOutputInstance,
        witness: &crate::folding::FoldedOutputWitness,
    ) -> Option<Self::Proof>;
    fn verify_typed_output(
        vk: &Self::VerifyingKey,
        instance: &crate::folding::FoldedOutputInstance,
        proof: &Self::Proof,
    ) -> Option<bool>;
}

impl<T: BackendSnark> OutputBackend for T {
    type ProvingKey = T::ProvingKey;
    type VerifyingKey = T::VerifyingKey;
    type Proof = T::Proof;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey) {
        T::setup(relation)
    }

    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof {
        T::prove(pk, instance, witness)
    }

    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool {
        T::verify(vk, instance, proof)
    }

    fn serialize_output_context(
        r1cs: &crate::r1cs::R1CSMatrices,
        q: u64,
        d: usize,
    ) -> Option<Vec<u8>> {
        T::serialize_output_context(r1cs, q, d)
    }

    fn has_authoritative_typed_output() -> bool {
        T::has_authoritative_typed_output()
    }

    fn prove_typed_output(
        pk: &Self::ProvingKey,
        instance: &crate::folding::FoldedOutputInstance,
        witness: &crate::folding::FoldedOutputWitness,
    ) -> Option<Self::Proof> {
        T::prove_typed_output(pk, instance, witness)
    }

    fn verify_typed_output(
        vk: &Self::VerifyingKey,
        instance: &crate::folding::FoldedOutputInstance,
        proof: &Self::Proof,
    ) -> Option<bool> {
        T::verify_typed_output(vk, instance, proof)
    }
}
