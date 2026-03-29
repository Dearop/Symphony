//! Gadget decomposition and monomial embedding tests.

mod common;

use common::Q;
use symphony::params::D;

// =========================================================================
// Core decomposition
// =========================================================================
mod decomposition_core {
    use super::*;
    use symphony::decomposition;
    use symphony::decomposition::monomial;

    #[test]
    fn recompose_all_small_values() {
        for v in -50..=50 {
            let digits = decomposition::decompose(v, 16, 4);
            assert_eq!(decomposition::recompose(&digits, 16), v);
        }
    }

    #[test]
    fn monomial_embedding_full_range() {
        let ntt = symphony::ring::ntt::NttContext::new(Q);
        for a in -(D as i64 / 2 - 1)..=(D as i64 / 2 - 1) {
            let g = monomial::exp_map(a);
            assert!(monomial::is_monomial(&g), "exp_map({a}) is not a monomial");
            assert!(
                monomial::verify_monomial_property(a, &ntt),
                "monomial property failed for a={a}",
            );
        }
    }

    #[test]
    fn monomial_decompose_reconstruct() {
        let base = 62i64;
        let k = 2;
        for v in -100..=100 {
            let digits = monomial::monomial_decompose(v, base, k);
            let reconstructed = digits[0] + digits[1] * base;
            assert_eq!(reconstructed, v, "failed for v={v}");
        }
    }

    #[test]
    fn gadget_vector() {
        let g = decomposition::gadget_vector(16, 4);
        assert_eq!(g, vec![1, 16, 256, 4096]);
    }
}

// =========================================================================
// Decomposition edge cases
// =========================================================================
mod decomposition_edge_cases {
    use symphony::decomposition;

    #[test]
    fn decompose_zero() {
        let digits = decomposition::decompose(0, 16, 4);
        assert!(digits.iter().all(|&d| d == 0));
        assert_eq!(decomposition::recompose(&digits, 16), 0);
    }

    #[test]
    fn decompose_negative() {
        for v in [-1, -15, -100, -255] {
            let digits = decomposition::decompose(v, 16, 4);
            assert_eq!(decomposition::recompose(&digits, 16), v);
        }
    }

    #[test]
    fn decompose_vector_roundtrip() {
        let vals = vec![10, -20, 0, 50, -100];
        let decomposed = decomposition::decompose_vector(&vals, 16, 4);
        assert_eq!(decomposed.len(), vals.len() * 4);
        for (i, &v) in vals.iter().enumerate() {
            let chunk = &decomposed[i * 4..(i + 1) * 4];
            assert_eq!(decomposition::recompose(chunk, 16), v);
        }
    }

    #[test]
    fn decompose_digits_bounded_by_half_base() {
        for v in -200..=200 {
            let digits = decomposition::decompose(v, 16, 4);
            for &d in &digits {
                assert!(d.abs() <= 8, "digit {d} exceeds base/2 for v={v}");
            }
        }
    }
}

// =========================================================================
// Recompose overflow fix (audit M3)
// =========================================================================
mod recompose_overflow_fix {
    use symphony::decomposition;

    #[test]
    fn recompose_small_values_still_works() {
        for v in -1000..=1000 {
            let digits = decomposition::decompose(v, 16, 4);
            assert_eq!(decomposition::recompose(&digits, 16), v);
        }
    }

    #[test]
    fn recompose_zero_digits() {
        let digits = vec![0i64; 4];
        assert_eq!(decomposition::recompose(&digits, 16), 0);
    }

    #[test]
    fn recompose_single_digit() {
        assert_eq!(decomposition::recompose(&[7], 16), 7);
        assert_eq!(decomposition::recompose(&[-3], 10), -3);
    }

    #[test]
    fn gadget_vector_small_base() {
        let g = decomposition::gadget_vector(2, 8);
        assert_eq!(g, vec![1, 2, 4, 8, 16, 32, 64, 128]);
    }
}

// =========================================================================
// Property-based decomposition tests
// =========================================================================
mod decomposition_proptest {
    use proptest::prelude::*;
    use symphony::decomposition;

    proptest! {
        #[test]
        fn roundtrip_base16(v in -10_000i64..=10_000) {
            let digits = decomposition::decompose(v, 16, 6);
            prop_assert_eq!(decomposition::recompose(&digits, 16), v);
        }

        #[test]
        fn roundtrip_base4(v in -500i64..=500) {
            let digits = decomposition::decompose(v, 4, 8);
            prop_assert_eq!(decomposition::recompose(&digits, 4), v);
        }

        #[test]
        fn digits_bounded(v in -10_000i64..=10_000) {
            let base = 16i64;
            let digits = decomposition::decompose(v, base, 6);
            for &d in &digits {
                prop_assert!(d.abs() <= base / 2, "digit {} exceeds base/2 for v={}", d, v);
            }
        }

        #[test]
        fn vector_roundtrip(vals in prop::collection::vec(-500i64..=500, 1..20)) {
            let decomposed = decomposition::decompose_vector(&vals, 16, 4);
            prop_assert_eq!(decomposed.len(), vals.len() * 4);
            for (i, &v) in vals.iter().enumerate() {
                let chunk = &decomposed[i * 4..(i + 1) * 4];
                prop_assert_eq!(decomposition::recompose(chunk, 16), v);
            }
        }
    }
}
