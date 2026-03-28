//! R1CS constraint system tests.

mod common;

use common::Q;
use symphony::r1cs::R1CSMatrices;

mod r1cs_conversion {
    use super::*;
    use symphony::r1cs::conversion;

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
}
