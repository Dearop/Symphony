//! Field-native typed CP R1CS building blocks.
//!
//! This module starts with the circuit-native Poseidon2/BabyBear digest gadget
//! used by the authoritative typed CP relation. It intentionally keeps the
//! authority flag outside this module; callers must only flip that flag after
//! the composed CP relation negative tests pass.

use super::r1cs::{encode_cp_witness_r1cs, CpR1csLayout};
use crate::digest_core::{
    derive_challenges_with_scheme, poseidon_digest_input_elems, serialize_poseidon_digest_elems,
    Digest32, FoldInput, PublicDigestScheme,
};
use crate::folding::FoldedInstance;
use crate::params::{D, T};
use crate::r1cs::R1CSMatrices;
use crate::ring::arith::{centered_mod, mod_inv};
use crate::ring::extension::ExtFieldElement;
use crate::ring::{RingElement, RingVector};
use crate::rok::gr1cs::GR1CSProof;
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use rand::distr::StandardUniform;
use rand::{rngs::ChaCha20Rng, RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const BB_P: u64 = 2_013_265_921;
const WIDTH: usize = 16;
const RATE: usize = 8;
const OUT: usize = 8;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 13;
const TYPED_BETA_CHALLENGE_BYTES: usize = 32;
const TYPED_BETA_DIGIT_SELECTOR_VALUES: usize = 5;
const TYPED_BETA_QUOTIENT_SELECTOR_VALUES: usize = 11;
const TYPED_BETA_SELECTORS_PER_BYTE: usize =
    TYPED_BETA_DIGIT_SELECTOR_VALUES * 2 + TYPED_BETA_QUOTIENT_SELECTOR_VALUES;
const TYPED_BETA_CONSTRAINTS_PER_BYTE: usize = TYPED_BETA_SELECTORS_PER_BYTE + 6;

include!("typed_r1cs/layouts.rs");
include!("typed_r1cs/poseidon.rs");
include!("typed_r1cs/statement.rs");
include!("typed_r1cs/digest_builder.rs");
include!("typed_r1cs/encoding_witness.rs");
include!("typed_r1cs/monomial_witness.rs");
include!("typed_r1cs/digest_constraints.rs");
include!("typed_r1cs/gr1cs_range.rs");
include!("typed_r1cs/monomial_constraints.rs");
include!("typed_r1cs/helpers.rs");
#[cfg(test)]
include!("typed_r1cs/tests.rs");
