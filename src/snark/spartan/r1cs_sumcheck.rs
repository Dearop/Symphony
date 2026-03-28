//! R1CS-to-sumcheck reduction for the Spartan protocol.
//!
//! Flattens the ring R1CS (over Rq with D=64 coefficients per element)
//! into a scalar-field R1CS over Fp, then builds sumcheck evaluation tables.

use curve25519_dalek::scalar::Scalar;

use super::scalar_field;
use crate::r1cs::{R1CSMatrices, SparseMatrix};

/// Sparse matrix in COO format over Fp.
#[derive(Debug, Clone)]
pub struct FlatSparseMatrix {
    /// (row, col, value) triples.
    pub entries: Vec<(usize, usize, Scalar)>,
    pub num_rows: usize,
    pub num_cols: usize,
}

/// Flatten a ring R1CS into scalar R1CS over Fp.
///
/// Each ring constraint k with D coefficients becomes D scalar constraints.
/// Each ring variable col with D coefficients becomes D scalar variables.
///
/// The flattened constraint at row (k*D + j) involves columns (col*D + j)
/// with the same scalar coefficient as the original ring constraint.
pub fn flatten_ring_r1cs(
    r1cs: &R1CSMatrices,
    d: usize,
) -> (FlatSparseMatrix, FlatSparseMatrix, FlatSparseMatrix) {
    let flat_rows = r1cs.num_constraints * d;
    let flat_cols = r1cs.num_variables * d;

    let flatten_matrix = |mat: &SparseMatrix| -> FlatSparseMatrix {
        let mut entries = Vec::with_capacity(mat.entries.len() * d);
        for &(row, col, val) in &mat.entries {
            let s = scalar_field::from_i64(val);
            for j in 0..d {
                entries.push((row * d + j, col * d + j, s));
            }
        }
        FlatSparseMatrix {
            entries,
            num_rows: flat_rows,
            num_cols: flat_cols,
        }
    };

    (
        flatten_matrix(&r1cs.a),
        flatten_matrix(&r1cs.b),
        flatten_matrix(&r1cs.c),
    )
}

/// Compute Az, Bz, Cz as dense vectors (evaluations over the boolean hypercube).
///
/// The input z_flat is the flattened witness vector of length n*D.
/// Output vectors are of length m*D, padded to the next power of two.
pub fn compute_matrix_vector_products(
    flat_a: &FlatSparseMatrix,
    flat_b: &FlatSparseMatrix,
    flat_c: &FlatSparseMatrix,
    z_flat: &[Scalar],
    num_vars: usize,
) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
    let n = 1 << num_vars;

    let sparse_mul = |mat: &FlatSparseMatrix| -> Vec<Scalar> {
        let mut result = vec![Scalar::ZERO; n];
        for &(row, col, ref val) in &mat.entries {
            if row < n && col < z_flat.len() {
                result[row] += val * z_flat[col];
            }
        }
        result
    };

    (sparse_mul(flat_a), sparse_mul(flat_b), sparse_mul(flat_c))
}

/// Compute the multilinear extension of a matrix row, evaluated at a point.
///
/// For a sparse matrix M, compute the vector v where:
///   v[col] = sum_{row} eq(point, row_bits) * M[row, col]
///
/// This is used after the sumcheck to extract the "row" of the matrix
/// at the challenge point for the IPA verification.
pub fn compute_matrix_mle_at_point(
    mat: &FlatSparseMatrix,
    point: &[Scalar],
    num_cols: usize,
) -> Vec<Scalar> {
    let num_rows = 1 << point.len();
    let eq_table = super::sumcheck::build_eq_table(point, point.len());

    let mut result = vec![Scalar::ZERO; num_cols];
    for &(row, col, ref val) in &mat.entries {
        if row < num_rows && col < num_cols {
            result[col] += eq_table[row] * val;
        }
    }
    result
}

/// Evaluate the MLE of a table at a given point.
///
/// table[i] for i in {0,1}^n. The MLE is evaluated at `point` in F^n.
pub fn mle_eval(table: &[Scalar], point: &[Scalar]) -> Scalar {
    let n = point.len();
    assert_eq!(table.len(), 1 << n);

    let mut current = table.to_vec();
    for r in point {
        let half = current.len() / 2;
        let one_minus_r = Scalar::ONE - r;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            next.push(current[j] * one_minus_r + current[half + j] * r);
        }
        current = next;
    }

    current[0]
}

/// Ceil(log2(n)), minimum 1.
pub fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::R1CSMatrices;

    #[test]
    fn flatten_simple_r1cs() {
        // 1 constraint, 3 variables, D=2 for simplicity conceptually
        // But we use the actual D=64 from the crate
        let d = 64;
        let mut r1cs = R1CSMatrices::new(1, 2, 1);
        r1cs.a.insert(0, 0, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 0, 1);

        let (flat_a, flat_b, flat_c) = flatten_ring_r1cs(&r1cs, d);
        assert_eq!(flat_a.num_rows, d);
        assert_eq!(flat_a.num_cols, 2 * d);
        assert_eq!(flat_a.entries.len(), d); // 1 entry * d coefficients
        assert_eq!(flat_b.entries.len(), d);
        assert_eq!(flat_c.entries.len(), d);
    }

    #[test]
    fn mle_eval_basic() {
        // Table [1, 2, 3, 4] on {0,1}^2
        let table = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        // Evaluate at (0, 0) -> should give table[0] = 1
        let val = mle_eval(&table, &[Scalar::ZERO, Scalar::ZERO]);
        assert_eq!(val, Scalar::from(1u64));

        // Evaluate at (1, 1) -> should give table[3] = 4
        let val = mle_eval(&table, &[Scalar::ONE, Scalar::ONE]);
        assert_eq!(val, Scalar::from(4u64));
    }

    #[test]
    fn ceil_log2_values() {
        assert_eq!(ceil_log2(1), 1);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(256), 8);
    }
}
