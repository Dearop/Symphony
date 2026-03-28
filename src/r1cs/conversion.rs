//! Conversion from standard R1CS to generalized committed R1CS.
//!
//! Given original R1CS matrices M̄_i ∈ Z^{m × n̄}, the generalized matrices are:
//!   M_i = M̄_i ⊗ [1, b, ..., b^{k_cs - 1}]   (Kronecker product)
//!   n = n̄ · k_cs
//!
//! Each witness w ∈ Zq^{n̄} is decomposed via decomp_{b, k_cs}(w) to get
//! a low-norm witness of length n.

use crate::decomposition;
use crate::r1cs::{R1CSMatrices, SparseMatrix};

/// Convert a standard R1CS to a generalized (Kronecker-expanded) R1CS.
///
/// M_i := M̄_i ⊗ g^T where g = (1, b, b^2, ..., b^{k-1}).
pub fn kronecker_expand(original: &R1CSMatrices, b: i64, k_cs: usize) -> R1CSMatrices {
    let new_num_vars = original.num_variables * k_cs;
    let new_num_public = original.num_public * k_cs;
    let gadget = decomposition::gadget_vector(b, k_cs);

    let expand_matrix = |m: &SparseMatrix| -> SparseMatrix {
        let mut expanded = SparseMatrix::new(m.num_rows, new_num_vars);
        for &(row, col, val) in &m.entries {
            // Original entry M̄[row, col] = val becomes:
            // M[row, col*k_cs + j] = val * g[j]  for j = 0..k_cs
            for (j, &gj) in gadget.iter().enumerate() {
                expanded.insert(row, col * k_cs + j, val * gj);
            }
        }
        expanded
    };

    R1CSMatrices {
        a: expand_matrix(&original.a),
        b: expand_matrix(&original.b),
        c: expand_matrix(&original.c),
        num_constraints: original.num_constraints,
        num_variables: new_num_vars,
        num_public: new_num_public,
    }
}

/// Decompose a standard witness into a low-norm witness.
///
/// Each w_i ∈ Zq is replaced by decomp_{b, k_cs}(w_i) ∈ Z^{k_cs} with ‖·‖_∞ ≤ b/2.
pub fn decompose_witness(witness: &[i64], b: i64, k_cs: usize) -> Vec<i64> {
    decomposition::decompose_vector(witness, b, k_cs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kronecker_expansion_preserves_satisfaction() {
        // Simple R1CS: x * x = y with z = [1, x, y]
        let mut original = R1CSMatrices::new(1, 3, 1);
        original.a.insert(0, 1, 1);
        original.b.insert(0, 1, 1);
        original.c.insert(0, 2, 1);

        let b = 16i64;
        let k_cs = 4;
        let expanded = kronecker_expand(&original, b, k_cs);

        // Original: z = [1, 5, 25]
        // Decomposed: each element becomes k_cs digits
        let z_orig = [1i64, 5, 25];
        let z_expanded: Vec<i64> = z_orig
            .iter()
            .flat_map(|&v| crate::decomposition::decompose(v, b, k_cs))
            .collect();

        // Check: Az_exp * Bz_exp = Cz_exp
        let az = expanded.a.mul_vec(&z_expanded);
        let bz = expanded.b.mul_vec(&z_expanded);
        let cz = expanded.c.mul_vec(&z_expanded);
        assert_eq!(az[0] * bz[0], cz[0]);
    }
}
