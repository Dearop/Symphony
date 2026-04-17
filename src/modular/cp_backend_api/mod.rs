//! Backend-agnostic CP proving API.

use crate::snark::{BackendSnark, RelationDescription};

pub trait CpBackend {
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: Clone + std::fmt::Debug;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey);
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof;
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool;
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
}
