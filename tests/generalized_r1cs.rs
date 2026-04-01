//! Tests for the generalized committed R1CS check_hadamard.

mod common;

use common::Q;
use symphony::params::D;
use symphony::r1cs::generalized::{check_hadamard, GeneralizedR1CSParams};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::RingElement;

mod check_hadamard_tests {
    use super::*;

    /// Build GeneralizedR1CSParams from an R1CS and split sizes.
    fn make_params(r1cs: R1CSMatrices, n_in: usize, n_w: usize) -> GeneralizedR1CSParams {
        GeneralizedR1CSParams {
            n_in,
            n_w,
            ell_h: D,
            bound: 1024,
            matrices: r1cs,
        }
    }

    /// Convert a scalar witness vector into ring elements (constant polynomials).
    fn to_ring_elements(vals: &[i64]) -> Vec<RingElement> {
        vals.iter()
            .map(|&v| RingElement::from_constant(v))
            .collect()
    }

    #[test]
    fn satisfying_simple() {
        // x1 * x1 = x2, with z = [1, 3, 9]
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public; // 1
        let n_w = r1cs.num_variables - n_in;
        let params = make_params(r1cs, n_in, n_w);

        let public_input = to_ring_elements(&z[..n_in]);
        let witness = to_ring_elements(&z[n_in..]);

        assert!(check_hadamard(&params, &public_input, &witness, Q));
    }

    #[test]
    fn unsatisfying_perturbed_witness() {
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let n_w = r1cs.num_variables - n_in;
        let params = make_params(r1cs, n_in, n_w);

        let public_input = to_ring_elements(&z[..n_in]);
        // Perturb: change 9 to 10 (3*3 != 10)
        let mut bad_z = z[n_in..].to_vec();
        let last = &bad_z.len() - 1;
        bad_z[last] += 1;
        let witness = to_ring_elements(&bad_z);

        assert!(!check_hadamard(&params, &public_input, &witness, Q));
    }

    #[test]
    fn satisfying_multi_constraint() {
        // Multi-constraint R1CS: z = [1, 3, 5, 15]
        let (r1cs, z) = common::multi_r1cs();
        let n_in = r1cs.num_public;
        let n_w = r1cs.num_variables - n_in;
        let params = make_params(r1cs, n_in, n_w);

        let public_input = to_ring_elements(&z[..n_in]);
        let witness = to_ring_elements(&z[n_in..]);

        assert!(check_hadamard(&params, &public_input, &witness, Q));
    }

    #[test]
    fn all_zero_witness() {
        // Trivial R1CS: 0 * 0 = 0 (empty constraint that's always satisfied)
        let m = 1;
        let n = 2;
        let r1cs = R1CSMatrices::new(m, n, 1);
        // All-zero matrices: A*z = 0, B*z = 0, C*z = 0, so 0*0 = 0
        let params = make_params(r1cs, 1, 1);

        let public_input = to_ring_elements(&[0]);
        let witness = to_ring_elements(&[0]);

        assert!(check_hadamard(&params, &public_input, &witness, Q));
    }

    #[test]
    fn params_n_consistency() {
        let (r1cs, _) = common::simple_r1cs();
        let params = make_params(r1cs, 1, 2);
        assert_eq!(params.n(), 3);

        let (r1cs2, _) = common::multi_r1cs();
        let params2 = make_params(r1cs2, 1, 3);
        assert_eq!(params2.n(), 4);
    }

    #[test]
    #[should_panic]
    fn dimension_mismatch_panics() {
        let (r1cs, z) = common::simple_r1cs();
        let n_in = r1cs.num_public;
        let n_w = r1cs.num_variables - n_in;
        let params = make_params(r1cs, n_in, n_w);

        // Pass wrong-length public input
        let bad_public = to_ring_elements(&[1, 2, 3]);
        let witness = to_ring_elements(&z[n_in..]);
        check_hadamard(&params, &bad_public, &witness, Q);
    }
}
