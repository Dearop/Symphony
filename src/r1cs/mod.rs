//! R1CS relation definitions and sparse matrix representation.

pub mod conversion;
pub mod generalized;

use crate::ring::arith::centered_mod;

/// Sparse matrix in COO (coordinate) format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatrix {
    /// (row, col, value) triples.
    pub entries: Vec<(usize, usize, i64)>,
    pub num_rows: usize,
    pub num_cols: usize,
}

impl SparseMatrix {
    pub fn new(num_rows: usize, num_cols: usize) -> Self {
        Self {
            entries: Vec::new(),
            num_rows,
            num_cols,
        }
    }

    /// Add a non-zero entry.
    pub fn insert(&mut self, row: usize, col: usize, value: i64) {
        assert!(row < self.num_rows && col < self.num_cols);
        if value != 0 {
            self.entries.push((row, col, value));
        }
    }

    /// Sparse matrix-vector multiply: y = M · x (over the integers).
    ///
    /// Panics if any result overflows i64. Use `mul_vec_mod` for modular arithmetic.
    pub fn mul_vec(&self, x: &[i64]) -> Vec<i64> {
        assert_eq!(x.len(), self.num_cols);
        let mut y = vec![0i128; self.num_rows];
        for &(r, c, v) in &self.entries {
            y[r] += v as i128 * x[c] as i128;
        }
        y.into_iter()
            .map(|v| {
                i64::try_from(v).expect(
                    "SparseMatrix::mul_vec overflow: result exceeds i64; use mul_vec_mod instead",
                )
            })
            .collect()
    }

    /// Sparse matrix-vector multiply with modular reduction.
    pub fn mul_vec_mod(&self, x: &[i64], q: u64) -> Vec<i64> {
        assert_eq!(x.len(), self.num_cols);
        let mut y = vec![0i64; self.num_rows];
        for &(r, c, v) in &self.entries {
            let sum = y[r] as i128 + v as i128 * x[c] as i128;
            y[r] = centered_mod(sum, q);
        }
        y
    }

    /// Number of non-zero entries.
    pub fn nnz(&self) -> usize {
        self.entries.len()
    }
}

/// R1CS matrices M_1, M_2, M_3 (called A, B, C in standard notation).
///
/// An R1CS instance is satisfiable iff:
/// (M_1 · z) ∘ (M_2 · z) = M_3 · z
/// where z = (x, w) is the full assignment (public input x, witness w).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1CSMatrices {
    /// Matrix M_1 (typically called A).
    pub a: SparseMatrix,
    /// Matrix M_2 (typically called B).
    pub b: SparseMatrix,
    /// Matrix M_3 (typically called C).
    pub c: SparseMatrix,
    /// Number of constraints (rows).
    pub num_constraints: usize,
    /// Total number of variables (public + witness).
    pub num_variables: usize,
    /// Number of public input variables.
    pub num_public: usize,
}

impl R1CSMatrices {
    pub fn new(num_constraints: usize, num_variables: usize, num_public: usize) -> Self {
        Self {
            a: SparseMatrix::new(num_constraints, num_variables),
            b: SparseMatrix::new(num_constraints, num_variables),
            c: SparseMatrix::new(num_constraints, num_variables),
            num_constraints,
            num_variables,
            num_public,
        }
    }

    /// Check if a full assignment z = (x, w) satisfies the R1CS: (Az) ∘ (Bz) = Cz
    /// over the integers.
    ///
    /// For modular R1CS (over Zq), use `is_satisfied_mod` instead.
    pub fn is_satisfied(&self, z: &[i64]) -> bool {
        assert_eq!(z.len(), self.num_variables);
        let az = self.a.mul_vec(z);
        let bz = self.b.mul_vec(z);
        let cz = self.c.mul_vec(z);
        for i in 0..self.num_constraints {
            if (az[i] as i128) * (bz[i] as i128) != cz[i] as i128 {
                return false;
            }
        }
        true
    }

    /// Check satisfaction modulo q.
    pub fn is_satisfied_mod(&self, z: &[i64], q: u64) -> bool {
        assert_eq!(z.len(), self.num_variables);
        let az = self.a.mul_vec_mod(z, q);
        let bz = self.b.mul_vec_mod(z, q);
        let cz = self.c.mul_vec_mod(z, q);
        (0..self.num_constraints).all(|i| centered_mod(az[i] as i128 * bz[i] as i128, q) == cz[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_r1cs() {
        // x * x = y  (1 constraint, 3 vars: [1, x, y])
        let mut r1cs = R1CSMatrices::new(1, 3, 1);
        r1cs.a.insert(0, 1, 1); // A selects x
        r1cs.b.insert(0, 1, 1); // B selects x
        r1cs.c.insert(0, 2, 1); // C selects y

        // z = [1, 3, 9] should satisfy: 3 * 3 = 9
        assert!(r1cs.is_satisfied(&[1, 3, 9]));
        // z = [1, 3, 10] should not
        assert!(!r1cs.is_satisfied(&[1, 3, 10]));
    }
}
