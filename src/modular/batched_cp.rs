//! Structured same-shape batched CP relation foundation.
//!
//! This module is deliberately non-authoritative today. It defines the product
//! domain objects P3/P4 needs without changing the current monolithic typed CP
//! public verifier route.

use std::collections::{BTreeMap, BTreeSet};

use crate::commitment::AjtaiParams;
use crate::cp_relation_core::{
    CpFieldRelation, CpPublicStatement, CpRelationError, CpWitnessBundle,
};
use crate::digest_core::{digest_domain_with_scheme, Digest32, PublicDigestScheme};
use crate::params::{D, T};
use crate::r1cs::R1CSMatrices;
use crate::ring::{RingElement, RingVector};
use crate::snark::RelationDescription;

const STRUCTURED_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBTC1\0";
const SEMANTIC_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBTCS1";
const SEMANTIC_V2_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBTC2\0";
const SEMANTIC_COLUMNAR_V2_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBT2C\0";
const SEMANTIC_FAMILY_COLUMNAR_V2_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBT2F\0";
const SYMBT3_RELATION_CONTEXT_MAGIC: &[u8; 8] = b"SYMBT3\0\0";
const SEMANTIC_COLUMNAR_V2_LAYOUT_VERSION: u64 = 1;
const SYMBT3_LAYOUT_VERSION: u64 = 10;
const SYMBT3_CHALLENGE_SCHEDULE_VERSION: u64 = 2;
const SYMBT3_RING_ACTION_VERSION: u64 = 1;
const SYMBT3_AJTAI_COMMIT_LAYOUT_VERSION: u64 = 1;
const SYMBT3_R1CS_EVALUATOR_LAYOUT_VERSION: u64 = 1;
const SYMBT3_GR1CS_RESIDUAL_LAYOUT_VERSION: u64 = 1;
const SYMBT3_FOLDED_GR1CS_PRODUCT_RESIDUAL_LAYOUT_VERSION: u64 = 1;
const SYMBT3_ALGEBRA_LAW_VERSION: u64 = 1;
const SYMBT3_AJTAI_LINEAR_ALGEBRA_LAYOUT_VERSION: u64 = 1;
const SYMBT3_AJTAI_NORM_RANGE_LAYOUT_VERSION: u64 = 2;
const SYMBT3_PROJECTION_LAYOUT_VERSION: u64 = 2;
const SYMBT3_RANGE_LAYOUT_VERSION: u64 = 2;
const SYMBT3_MONOMIAL_EMBEDDING_LAYOUT_VERSION: u64 = 1;
const SYMBT3_REPRESENTATIVE_LAYOUT_VERSION: u64 = 1;
const SYMBT3_BATCH_MANIFEST_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MANIFEST_ORACLE_LAYOUT_VERSION: u64 = 1;
const SYMBT3_SOURCE_COLUMN_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_SEMANTIC_LAYOUT_VERSION: u64 = 2;
const SYMBT3_ROUND_MESSAGE_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_SECTION_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_VIEW_LAYOUT_VERSION: u64 = 1;
const SYMBT3_MESSAGE_COORDINATE_MAP_VERSION: u64 = 1;
const SYMBT3_AUTHORITY_PROFILE_VERSION: u64 = 2;
const SYMBT2F_MAX_SECTION_EQUALITY_ROWS: usize = 8192;

include!("batched_cp/types.rs");
include!("batched_cp/shape.rs");
include!("batched_cp/symbt3_layouts.rs");
include!("batched_cp/columnar_layouts.rs");
include!("batched_cp/relation_contexts.rs");
include!("batched_cp/evaluator.rs");
include!("batched_cp/symbt3_public.rs");
include!("batched_cp/semantic_codes.rs");
include!("batched_cp/serialization.rs");
