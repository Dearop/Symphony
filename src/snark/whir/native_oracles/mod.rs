//! Native multi-oracle WHIR evaluation envelope.
//!
//! N1 is an infrastructure layer: it keeps one logical proof envelope while
//! allowing multiple named WHIR/PCS oracles to be opened and checked under a
//! shared descriptor transcript.
//!
//! Implementation is split across `frag_*.rs` files that are `include!`d into this
//! module (single namespace, no cross-fragment visibility issues). Regenerate with
//! `scripts/split_native_oracles_v3.py` if you have a monolithic source snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

pub use crate::batched_cp::Symbt3AccumulatorWitness;

use crate::batched_cp::{
    derive_symbt3_public_statement_digest, symbt3_accumulator_coordinates_digest,
    BatchedCpSymbt3PublicStatement, BatchedCpSymbt3RelationDescription, ProductProofKind,
    Symbt3AccumulatorInstance, Symbt3AuthorityProfile, Symbt3TypedMessageOracle,
};
use crate::folding::digest::Digest32;
use crate::snark::BackendSnark;

use super::{
    canonical_encoding::{
        digest_bytes, push_babybear, push_babybear_vec, push_bool, push_bytes, push_digest,
        push_i64_slice, push_optional_digest, push_optional_u32, push_u32, push_u64,
    },
    canonical_whir_proof_bytes, derive_challenge, mle_eval_bb, whir_commit_and_prove_multi,
    whir_commit_initial_root_only, whir_verify_opening_multi, WhirMmcs, WhirPcsProof, WhirProof,
    WhirProvingKey, WhirSnark, WhirVerifyingKey, EF, F,
};

include!("frag_constants.rs");
include!("frag_policies.rs");
include!("frag_core_types.rs");
include!("frag_tuple_leaf.rs");
include!("frag_serialization.rs");
include!("frag_digests.rs");
include!("frag_benchmark.rs");
include!("frag_manifest.rs");
include!("frag_message.rs");
include!("frag_folding_integrity.rs");
include!("frag_accumulator_types.rs");
include!("frag_n7b_types.rs");
include!("frag_n8_types.rs");
include!("frag_adapter.rs");
include!("frag_n7b_binding.rs");
include!("frag_n8_impl.rs");
include!("frag_n8_accumulation.rs");
include!("frag_accumulator_digest.rs");
include!("frag_n7b_prove.rs");
include!("frag_n8_witness.rs");
include!("frag_core_canonical.rs");
include!("frag_prove.rs");
include!("frag_verify.rs");
include!("frag_accumulator_helpers.rs");
include!("frag_encoding.rs");

#[cfg(test)]
mod tests;
