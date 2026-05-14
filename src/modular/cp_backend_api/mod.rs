//! Backend-agnostic CP proving API.

use crate::snark::{BackendSnark, RelationDescription};

pub trait CpBackend {
    type ProvingKey: Clone;
    type VerifyingKey: Clone;
    type Proof: Clone + std::fmt::Debug;

    fn setup(relation: &RelationDescription) -> (Self::ProvingKey, Self::VerifyingKey);
    fn prove(pk: &Self::ProvingKey, instance: &[u8], witness: &[u8]) -> Self::Proof;
    fn verify(vk: &Self::VerifyingKey, instance: &[u8], proof: &Self::Proof) -> bool;
    fn public_digest_scheme() -> crate::digest_core::PublicDigestScheme {
        crate::digest_core::PublicDigestScheme::Sha256
    }
    fn serialize_cp_context(r1cs: &crate::r1cs::R1CSMatrices, q: u64, d: usize) -> Option<Vec<u8>>;
    /// Compatibility/development raw typed-CP context serializer.
    ///
    /// Product public routing should prefer [`Self::typed_cp_relation_description`],
    /// and this hook is ignored unless [`Self::has_authoritative_typed_cp`]
    /// advertises public authority.
    fn serialize_typed_cp_context(
        descriptor: &crate::snark::TypedCpSetupDescriptor,
    ) -> Option<Vec<u8>> {
        let _ = descriptor;
        None
    }
    /// Product-routing typed-CP relation descriptor.
    ///
    /// Returning a descriptor is not enough to make a backend authoritative;
    /// public verification also requires [`Self::has_authoritative_typed_cp`].
    fn typed_cp_relation_description(
        descriptor: &crate::snark::TypedCpSetupDescriptor,
    ) -> Option<RelationDescription> {
        let _ = descriptor;
        None
    }
    fn has_authoritative_typed_cp() -> bool {
        false
    }
    fn prove_typed_cp(
        pk: &Self::ProvingKey,
        statement: &crate::cp_relation_core::CpPublicStatement,
        witness: &crate::cp_relation_core::CpWitnessBundle,
    ) -> Option<Self::Proof>;
    fn verify_typed_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::cp_relation_core::CpPublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool>;
    fn typed_batched_cp_relation_description(
        shape: &crate::batched_cp::BatchedCpStatementShape,
    ) -> Option<RelationDescription> {
        let _ = shape;
        None
    }
    fn prove_typed_batched_cp(
        pk: &Self::ProvingKey,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
        witness: &crate::batched_cp::BatchedCpWitnessBundle,
    ) -> Option<Self::Proof>;
    fn verify_typed_batched_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool>;
    fn symbt3_relation_description(
        descriptor: &crate::batched_cp::BatchedCpSymbt3SetupDescriptor,
    ) -> Option<RelationDescription> {
        let _ = descriptor;
        None
    }
    fn prove_symbt3_batched_cp(
        pk: &Self::ProvingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    ) -> Option<Self::Proof>;
    fn verify_symbt3_batched_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
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

    fn public_digest_scheme() -> crate::digest_core::PublicDigestScheme {
        T::public_digest_scheme()
    }

    fn serialize_cp_context(r1cs: &crate::r1cs::R1CSMatrices, q: u64, d: usize) -> Option<Vec<u8>> {
        T::serialize_cp_context(r1cs, q, d)
    }

    fn serialize_typed_cp_context(
        descriptor: &crate::snark::TypedCpSetupDescriptor,
    ) -> Option<Vec<u8>> {
        T::serialize_typed_cp_context(descriptor)
    }

    fn typed_cp_relation_description(
        descriptor: &crate::snark::TypedCpSetupDescriptor,
    ) -> Option<RelationDescription> {
        T::typed_cp_relation_description(descriptor)
    }

    fn has_authoritative_typed_cp() -> bool {
        T::has_authoritative_typed_cp()
    }

    fn prove_typed_cp(
        pk: &Self::ProvingKey,
        statement: &crate::cp_relation_core::CpPublicStatement,
        witness: &crate::cp_relation_core::CpWitnessBundle,
    ) -> Option<Self::Proof> {
        T::prove_typed_cp(pk, statement, witness)
    }

    fn verify_typed_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::cp_relation_core::CpPublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool> {
        T::verify_typed_cp(vk, statement, proof)
    }

    fn typed_batched_cp_relation_description(
        shape: &crate::batched_cp::BatchedCpStatementShape,
    ) -> Option<RelationDescription> {
        T::typed_batched_cp_relation_description(shape)
    }

    fn prove_typed_batched_cp(
        pk: &Self::ProvingKey,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
        witness: &crate::batched_cp::BatchedCpWitnessBundle,
    ) -> Option<Self::Proof> {
        T::prove_typed_batched_cp(pk, statement, witness)
    }

    fn verify_typed_batched_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::batched_cp::BatchedCpPublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool> {
        T::verify_typed_batched_cp(vk, statement, proof)
    }

    fn symbt3_relation_description(
        descriptor: &crate::batched_cp::BatchedCpSymbt3SetupDescriptor,
    ) -> Option<RelationDescription> {
        T::symbt3_relation_description(descriptor)
    }

    fn prove_symbt3_batched_cp(
        pk: &Self::ProvingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        witness: &crate::batched_cp::BatchedCpSymbt3Witness,
    ) -> Option<Self::Proof> {
        T::prove_symbt3_batched_cp(pk, statement, witness)
    }

    fn verify_symbt3_batched_cp(
        vk: &Self::VerifyingKey,
        statement: &crate::batched_cp::BatchedCpSymbt3PublicStatement,
        proof: &Self::Proof,
    ) -> Option<bool> {
        T::verify_symbt3_batched_cp(vk, statement, proof)
    }
}
