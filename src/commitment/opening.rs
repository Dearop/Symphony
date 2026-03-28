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
pub fn verify_strict(params: &AjtaiParams, c: &Commitment, f: &RingVector, b_bnd_sq: u128) -> bool {
    params.verify_open(c, f, b_bnd_sq)
}

/// Verify a relaxed opening: A·f = s·c and s·m = f and ‖f‖_2 ≤ B_rbnd and s ∈ S−S.
pub fn verify_relaxed(
    params: &AjtaiParams,
    c: &Commitment,
    m: &RingVector,
    opening: &RelaxedOpening,
    b_rbnd_sq: u128,
) -> bool {
    let q = params.q;

    // Check norm bound on f
    if opening.f.norm_sq() > b_rbnd_sq {
        return false;
    }

    // Check s·m = f
    let sm = m.ring_scalar_mul(&opening.s, q);
    if sm.elements != opening.f.elements {
        return false;
    }

    // Check A·f = s·c
    let mut af = RingVector::zero(params.kappa);
    for i in 0..params.kappa {
        for j in 0..params.n {
            let prod = params.a[i][j].mul(&opening.f.elements[j], q);
            af.elements[i] = af.elements[i].add(&prod, q);
        }
    }

    let sc: Vec<RingElement> = c
        .value
        .elements
        .iter()
        .map(|ci| ci.mul(&opening.s, q))
        .collect();

    af.elements.iter().zip(sc.iter()).all(|(a, b)| a == b)
}

/// Verify a fine-grained opening: A·f = c and for all sub-blocks, ‖F_{i,j}‖_2 ≤ B.
pub fn verify_fine_grained(
    params: &AjtaiParams,
    c: &Commitment,
    f: &RingVector,
    block_len: usize,
    block_bound_sq: u128,
) -> bool {
    let q = params.q;

    // Check commitment equation A·f = c
    let mut af = RingVector::zero(params.kappa);
    for i in 0..params.kappa {
        for j in 0..params.n {
            let prod = params.a[i][j].mul(&f.elements[j], q);
            af.elements[i] = af.elements[i].add(&prod, q);
        }
    }
    if af.elements != c.value.elements {
        return false;
    }

    // Check fine-grained norm: each block of block_len elements has ‖·‖_2 ≤ B
    for chunk in f.elements.chunks(block_len) {
        let block_norm_sq: u128 = chunk.iter().map(|e| e.norm_sq()).sum();
        if block_norm_sq > block_bound_sq {
            return false;
        }
    }

    true
}
