//! Shared length-prefixed canonical byte encoding for WHIR/SYMBT3 digests.

use p3_baby_bear::BabyBear;
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

use crate::folding::digest::Digest32;

#[must_use]
pub fn digest_bytes(bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn push_digest(out: &mut Vec<u8>, digest: &Digest32) {
    out.extend_from_slice(digest);
}

pub fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn push_i64_slice(out: &mut Vec<u8>, values: &[i64]) {
    push_u64(out, values.len() as u64);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn push_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

pub fn push_optional_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            push_bool(out, true);
            push_u32(out, value);
        }
        None => push_bool(out, false),
    }
}

pub fn push_optional_digest(out: &mut Vec<u8>, value: Option<&Digest32>) {
    match value {
        Some(value) => {
            push_bool(out, true);
            push_digest(out, value);
        }
        None => push_bool(out, false),
    }
}

pub fn push_babybear(out: &mut Vec<u8>, value: BabyBear) {
    out.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
}

pub fn push_babybear_vec(out: &mut Vec<u8>, values: &[BabyBear]) {
    push_u64(out, values.len() as u64);
    for &value in values {
        push_babybear(out, value);
    }
}
