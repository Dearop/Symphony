//! Backend-agnostic CP proving API.

use crate::snark::{BackendSnark, RelationDescription};

pub trait CpBackend {
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: Clone + std::fmt::Debug;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey);
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof;
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool;
    fn serialize_cp_context(r1cs: &crate::r1cs::R1CSMatrices, q: u64, d: usize) -> Option<Vec<u8>>;
    fn has_authoritative_typed_cp() -> bool {
        false
    }
    fn prove_typed_cp(
        pk: &Self::ProvingKey,
        instance: &crate::cp_relation_core::CpPublicInstance,
        witness: &crate::cp_relation_core::CpWitnessBundle,
    ) -> Option<Self::Proof>;
    fn verify_typed_cp(
        vk: &Self::VerifyingKey,
        instance: &crate::cp_relation_core::CpPublicInstance,
        proof: &Self::Proof,
    ) -> Option<bool>;
}

impl<T: BackendSnark> CpBackend for T {
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

    fn serialize_cp_context(r1cs: &crate::r1cs::R1CSMatrices, q: u64, d: usize) -> Option<Vec<u8>> {
        T::serialize_cp_context(r1cs, q, d)
    }

    fn has_authoritative_typed_cp() -> bool {
        T::has_authoritative_typed_cp()
    }

    fn prove_typed_cp(
        pk: &Self::ProvingKey,
        instance: &crate::cp_relation_core::CpPublicInstance,
        witness: &crate::cp_relation_core::CpWitnessBundle,
    ) -> Option<Self::Proof> {
        T::prove_typed_cp(pk, instance, witness)
    }

    fn verify_typed_cp(
        vk: &Self::VerifyingKey,
        instance: &crate::cp_relation_core::CpPublicInstance,
        proof: &Self::Proof,
    ) -> Option<bool> {
        T::verify_typed_cp(vk, instance, proof)
    }
}
