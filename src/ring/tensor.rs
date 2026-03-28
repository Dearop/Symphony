//! Tensor ring E = K ⊗_{Fq} Rq.
//!
//! An element of E is a T × D matrix over Zq, interpretable as:
//! - K^D (each column is a K-element) — useful for sumcheck
//! - Rq^T (each row is an Rq-element) — useful for folding

use crate::params::{D, T};
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::RingElement;

/// Element of the tensor ring E = K ⊗ Rq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TensorElement {
    /// T rows, D columns — matrix over Zq.
    pub data: [[i64; D]; T],
}

impl TensorElement {
    pub fn zero() -> Self {
        Self { data: [[0; D]; T] }
    }

    /// View as Rq^T: extract the i-th row as a RingElement.
    pub fn row(&self, i: usize) -> RingElement {
        assert!(i < T);
        RingElement {
            coeffs: self.data[i],
        }
    }

    /// View as K^D: extract the j-th column as an ExtFieldElement.
    pub fn col(&self, j: usize) -> ExtFieldElement {
        assert!(j < D);
        ExtFieldElement {
            c0: self.data[0][j],
            c1: if T > 1 { self.data[1][j] } else { 0 },
        }
    }

    /// Construct from T ring elements (row view).
    pub fn from_rows(rows: &[RingElement; T]) -> Self {
        let mut data = [[0i64; D]; T];
        for t in 0..T {
            data[t] = rows[t].coeffs;
        }
        Self { data }
    }

    /// Construct from D extension field elements (column view).
    pub fn from_cols(cols: &[ExtFieldElement; D]) -> Self {
        let mut data = [[0i64; D]; T];
        for j in 0..D {
            data[0][j] = cols[j].c0;
            if T > 1 {
                data[1][j] = cols[j].c1;
            }
        }
        Self { data }
    }

    /// Addition over Zq.
    pub fn add(&self, other: &Self, q: u64) -> Self {
        let q_half = (q / 2) as i64;
        let mut data = [[0i64; D]; T];
        for ((out_row, self_row), other_row) in
            data.iter_mut().zip(self.data.iter()).zip(other.data.iter())
        {
            for ((out, &s), &o) in out_row
                .iter_mut()
                .zip(self_row.iter())
                .zip(other_row.iter())
            {
                let sum = s as i128 + o as i128;
                let mut r = (sum % q as i128) as i64;
                if r > q_half {
                    r -= q as i64;
                } else if r < -q_half {
                    r += q as i64;
                }
                *out = r;
            }
        }
        Self { data }
    }

    /// Scalar multiplication by an extension field element (K-scalar).
    pub fn k_scalar_mul(&self, scalar: &ExtFieldElement, ctx: &ExtFieldContext) -> Self {
        let mut data = [[0i64; D]; T];
        let (row0, rest) = data.split_first_mut().unwrap();
        for (j, d0) in row0.iter_mut().enumerate() {
            let col = self.col(j);
            let prod = ctx.mul(&col, scalar);
            *d0 = prod.c0;
            if T > 1 {
                rest[0][j] = prod.c1;
            }
        }
        Self { data }
    }

    /// Infinity norm: max absolute value across all entries.
    pub fn norm_inf(&self) -> u64 {
        self.data
            .iter()
            .flat_map(|row| row.iter())
            .map(|c| c.unsigned_abs())
            .max()
            .unwrap_or(0)
    }

    /// Squared Euclidean norm: sum of squares of all entries.
    pub fn norm_sq(&self) -> u128 {
        self.data
            .iter()
            .flat_map(|row| row.iter())
            .map(|c| (*c as i128 * *c as i128) as u128)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_row_col_roundtrip() {
        let r0 = RingElement::from_constant(1);
        let r1 = RingElement::from_constant(2);
        let te = TensorElement::from_rows(&[r0.clone(), r1.clone()]);
        assert_eq!(te.row(0), r0);
        assert_eq!(te.row(1), r1);

        let col0 = te.col(0);
        assert_eq!(col0.c0, 1);
        assert_eq!(col0.c1, 2);
    }
}
