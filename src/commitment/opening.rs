//! Strict, relaxed, and fine-grained opening verification.

use crate::commitment::{AjtaiParams, Commitment};
use crate::ring::{RingElement, RingVector};

/// Relaxed opening proof: A·f = s·c with s ∈ S − S and s·m = f.
#[derive(Debug, Clone)]
pub struct RelaxedOpening {
    pub f: RingVector,
    pub s: RingElement,
}

/// Verify a strict opening: A·f = c and ‖f‖_2 < B_bnd.
#[must_use]
pub fn verify_strict(params: &AjtaiParams, c: &Commitment, f: &RingVector, b_bnd_sq: u128) -> bool {
    params.verify_open(c, f, b_bnd_sq)
}

/// Verify a relaxed opening: A·f = s·c and s·m = f and ‖f‖_2 ≤ B_rbnd and s ∈ S−S.
#[must_use]
pub fn verify_relaxed(
    params: &AjtaiParams,
    c: &Commitment,
    m: &RingVector,
    opening: &RelaxedOpening,
    b_rbnd_sq: u128,
) -> bool {
    if opening.f.norm_sq() > b_rbnd_sq {
        return false;
    }

    let sm = m.ring_scalar_mul_ntt(&opening.s, &params.ntt);
    if sm.elements != opening.f.elements {
        return false;
    }

    let af = params.mul_vec_ntt(&opening.f);
    let sc: Vec<RingElement> = c
        .value
        .elements
        .iter()
        .map(|ci| ci.mul_ntt(&opening.s, &params.ntt))
        .collect();

    af.elements.iter().zip(sc.iter()).all(|(a, b)| a == b)
}

/// Verify a fine-grained opening: A·f = c and for all sub-blocks, ‖F_{i,j}‖_2 ≤ B.
#[must_use]
pub fn verify_fine_grained(
    params: &AjtaiParams,
    c: &Commitment,
    f: &RingVector,
    block_len: usize,
    block_bound_sq: u128,
) -> bool {
    if params.mul_vec_ntt(f).elements != c.value.elements {
        return false;
    }

    for chunk in f.elements.chunks(block_len) {
        let block_norm_sq: u128 = chunk.iter().map(|e| e.norm_sq()).sum();
        if block_norm_sq > block_bound_sq {
            return false;
        }
    }

    true
}
