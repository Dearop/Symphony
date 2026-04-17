//! R1CS constraint system tests.

mod common;

use common::Q;
use symphony::r1cs::R1CSMatrices;

mod r1cs_conversion {
    use super::*;
    use symphony::r1cs::conversion;

    #[test]
    fn kronecker_expansion_panics_on_overflow() {
        let mut original = R1CSMatrices::new(1, 2, 1);
        original.a.insert(0, 0, i64::MAX / 2);
        original.b.insert(0, 0, 1);
        original.c.insert(0, 0, 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            conversion::kronecker_expand(&original, i64::MAX, 2);
        }));
        assert!(
            result.is_err(),
            "kronecker expansion should panic on overflow"
        );
    }

    #[test]
    fn kronecker_expansion_larger() {
        let (r1cs, z) = common::multi_r1cs();
        assert!(r1cs.is_satisfied_mod(&z, Q));

        let k_cs = 2;
        let base = 16;
        let expanded = conversion::kronecker_expand(&r1cs, base, k_cs);
        let decomposed = conversion::decompose_witness(&z, base, k_cs);

        let az = expanded.a.mul_vec_mod(&decomposed, Q);
        let bz = expanded.b.mul_vec_mod(&decomposed, Q);
        let cz = expanded.c.mul_vec_mod(&decomposed, Q);

        let q_half = (Q / 2) as i64;
        for i in 0..expanded.num_constraints {
            let mut prod = ((az[i] as i128 * bz[i] as i128) % Q as i128) as i64;
            if prod > q_half {
                prod -= Q as i64;
            }
            if prod < -q_half {
                prod += Q as i64;
            }
            assert_eq!(prod, cz[i], "Kronecker R1CS not satisfied at row {i}");
        }
    }
}

mod r1cs_extended {
    use super::*;
    use symphony::r1cs::SparseMatrix;

    #[test]
    fn mul_vec_panics_on_overflow() {
        let mut m = SparseMatrix::new(1, 2);
        m.insert(0, 0, i64::MAX);
        m.insert(0, 1, i64::MAX);
        let x = vec![i64::MAX, i64::MAX];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            m.mul_vec(&x);
        }));
        assert!(
            result.is_err(),
            "mul_vec should panic on overflow instead of silent truncation"
        );
    }

    #[test]
    fn mul_vec_normal_operation() {
        let mut m = SparseMatrix::new(1, 2);
        m.insert(0, 0, 3);
        m.insert(0, 1, 5);
        let x = vec![7i64, 11];
        let y = m.mul_vec(&x);
        assert_eq!(y[0], 3 * 7 + 5 * 11);
    }

    #[test]
    fn is_satisfied_mod_with_reduction() {
        let q = 257u64;
        let mut r1cs = R1CSMatrices::new(1, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 2, 1);
        let x_val = 100i64;
        let y_val = ((x_val as i128 * x_val as i128) % q as i128) as i64;
        let y_centered = if y_val > (q / 2) as i64 {
            y_val - q as i64
        } else {
            y_val
        };
        let z = vec![1, x_val, y_centered];
        assert!(r1cs.is_satisfied_mod(&z, q));
        assert!(!r1cs.is_satisfied(&z));
    }

    #[test]
    fn modular_satisfaction() {
        let mut r1cs = R1CSMatrices::new(1, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 2, 1);
        assert!(r1cs.is_satisfied_mod(&[1, 20, 143], Q));
        assert!(!r1cs.is_satisfied_mod(&[1, 20, 144], Q));
    }

    #[test]
    fn multi_constraint_system() {
        let mut r1cs = R1CSMatrices::new(2, 5, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 4, 1);
        r1cs.a.insert(1, 1, 1);
        r1cs.b.insert(1, 0, 1);
        r1cs.c.insert(1, 1, 1);
        assert!(r1cs.is_satisfied(&[1, 3, 5, 8, 15]));
    }

    #[test]
    fn sparse_matrix_nnz() {
        let (r1cs, _) = common::multi_r1cs();
        assert_eq!(r1cs.a.nnz(), 2);
        assert_eq!(r1cs.b.nnz(), 2);
        assert_eq!(r1cs.c.nnz(), 2);
    }

    #[test]
    fn empty_r1cs_trivially_satisfied() {
        let r1cs = R1CSMatrices::new(0, 2, 1);
        assert!(r1cs.is_satisfied(&[1, 5]));
    }

    #[test]
    fn single_constraint_system() {
        // a * b = c: x1 * x2 = x3
        let mut r1cs = R1CSMatrices::new(1, 4, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 3, 1);
        // z = [1, 3, 7, 21]  => 3 * 7 = 21
        assert!(r1cs.is_satisfied(&[1, 3, 7, 21]));
        // z = [1, 3, 7, 20]  => 3 * 7 != 20
        assert!(!r1cs.is_satisfied(&[1, 3, 7, 20]));
    }

    #[test]
    fn five_constraint_chain() {
        // Chain: x1*x1=x2, x2*x1=x3, x3*x1=x4, x4*x1=x5, x5*x1=x6
        // For x1=2: x2=4, x3=8, x4=16, x5=32, x6=64
        let n = 7; // 1 public + 6 vars
        let m = 5;
        let mut r1cs = R1CSMatrices::new(m, n, 1);
        for i in 0..m {
            r1cs.a.insert(i, if i == 0 { 1 } else { i + 1 }, 1);
            r1cs.b.insert(i, 1, 1);
            r1cs.c.insert(i, i + 2, 1);
        }
        assert!(r1cs.is_satisfied(&[1, 2, 4, 8, 16, 32, 64]));
        assert!(!r1cs.is_satisfied(&[1, 2, 4, 8, 16, 32, 63]));
    }

    #[test]
    fn wrong_witness_detected_modular() {
        let mut r1cs = R1CSMatrices::new(1, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 1, 1);
        r1cs.c.insert(0, 2, 1);
        // 5 * 5 = 25 (correct)
        assert!(r1cs.is_satisfied_mod(&[1, 5, 25], Q));
        // 5 * 5 != 26 (wrong)
        assert!(!r1cs.is_satisfied_mod(&[1, 5, 26], Q));
    }

    #[test]
    fn linear_combination_coefficients() {
        // 2*x1 + 3*x2 = x3  (linear, b = identity)
        let mut r1cs = R1CSMatrices::new(1, 4, 1);
        r1cs.a.insert(0, 1, 2);
        r1cs.a.insert(0, 2, 3);
        r1cs.b.insert(0, 0, 1); // multiply by the constant 1
        r1cs.c.insert(0, 3, 1);
        // z = [1, 4, 5, 23]  => (2*4 + 3*5) * 1 = 23
        assert!(r1cs.is_satisfied(&[1, 4, 5, 23]));
        assert!(!r1cs.is_satisfied(&[1, 4, 5, 22]));
    }

    #[test]
    fn max_variables_small() {
        // 10 constraints, 20 variables — larger but still tractable
        let m = 10;
        let n = 20;
        let mut r1cs = R1CSMatrices::new(m, n, 1);
        // Each constraint: x_{2i+1} * x_{2i+2} = 0 (trivially by setting all to 0)
        for i in 0..m {
            r1cs.a.insert(i, 2 * i + 1, 1);
            r1cs.b.insert(i, (2 * i + 2).min(n - 1), 1);
            r1cs.c.insert(i, 0, 0); // c = 0
        }
        let z = vec![1i64; n]; // all 1 means a*b = 1, c = 0 => fails
        assert!(!r1cs.is_satisfied(&z));

        let mut z_zero = vec![0i64; n];
        z_zero[0] = 1; // public input
        assert!(r1cs.is_satisfied(&z_zero));
    }

    #[test]
    fn dimension_check_in_sparse_mul() {
        let r1cs = R1CSMatrices::new(2, 4, 1);
        // Correct dimensions
        let result = r1cs.a.mul_vec_mod(&[1, 2, 3, 4], Q);
        assert_eq!(result.len(), 2);
    }
}
