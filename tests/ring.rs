//! Ring algebra tests: cyclotomic ring Rq, extension field K, NTT, tensor elements.

mod common;

use common::Q;
use symphony::params::D;
use symphony::ring::extension::{ExtFieldContext, ExtFieldElement};
use symphony::ring::{RingElement, RingVector};

use proptest::prelude::*;

fn ctx() -> ExtFieldContext {
    common::ctx()
}

// =========================================================================
// Ring algebra fundamentals
// =========================================================================
mod ring_algebra {
    use super::*;

    #[test]
    fn commutativity() {
        let a = RingElement::from_constant(7);
        let b = RingElement::monomial(3);
        assert_eq!(a.mul(&b, Q), b.mul(&a, Q));
    }

    #[test]
    fn associativity() {
        let a = RingElement::from_constant(2);
        let b = RingElement::monomial(1);
        let c = RingElement::from_constant(5);
        let ab_c = a.mul(&b, Q).mul(&c, Q);
        let a_bc = a.mul(&b.mul(&c, Q), Q);
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn distributivity() {
        let a = RingElement::from_constant(3);
        let b = RingElement::monomial(2);
        let c = RingElement::from_constant(4);
        let lhs = a.mul(&b.add(&c, Q), Q);
        let rhs = a.mul(&b, Q).add(&a.mul(&c, Q), Q);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn multiplicative_identity() {
        let a = RingElement::monomial(5);
        let one = RingElement::from_constant(1);
        assert_eq!(a.mul(&one, Q), a);
    }

    #[test]
    fn additive_identity() {
        let a = RingElement::from_constant(42);
        let zero = RingElement::zero();
        assert_eq!(a.add(&zero, Q), a);
    }

    #[test]
    fn ntt_matches_schoolbook_various() {
        use symphony::ring::ntt::NttContext;
        let ntt = NttContext::new(Q);
        for k in 0..D {
            let a = RingElement::monomial(k);
            let b = RingElement::from_constant(3);
            assert_eq!(ntt.ring_mul(&a, &b), a.mul(&b, Q));
        }
    }

    #[test]
    fn cyclotomic_x_d_equals_neg_one() {
        let x = RingElement::monomial(1);
        let mut power = RingElement::from_constant(1);
        for _ in 0..D {
            power = power.mul(&x, Q);
        }
        assert_eq!(power, RingElement::from_constant(-1));
    }

    #[test]
    fn ring_vector_inner_product() {
        let a = RingVector {
            elements: vec![RingElement::from_constant(2), RingElement::from_constant(3)],
        };
        let b = RingVector {
            elements: vec![RingElement::from_constant(4), RingElement::from_constant(5)],
        };
        let ip = a.inner_product(&b, Q);
        assert_eq!(ip.ct(), 23);
    }

    #[test]
    fn ext_field_inverse_all_units() {
        let ctx = ctx();
        for c0 in 1..10i64 {
            for c1 in 0..5i64 {
                let a = ExtFieldElement { c0, c1 };
                if let Some(inv) = ctx.inv(&a) {
                    assert_eq!(ctx.mul(&a, &inv), ctx.one());
                }
            }
        }
    }

    #[test]
    fn ext_field_distributivity() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 3, c1: 7 };
        let b = ExtFieldElement { c0: 11, c1: 2 };
        let c = ExtFieldElement { c0: 5, c1: 9 };
        let lhs = ctx.mul(&a, &ctx.add(&b, &c));
        let rhs = ctx.add(&ctx.mul(&a, &b), &ctx.mul(&a, &c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn tensor_row_col_consistency() {
        use symphony::ring::tensor::TensorElement;
        let r0 = RingElement::from_constant(3);
        let r1 = RingElement::from_constant(7);
        let te = TensorElement::from_rows(&[r0, r1]);
        for j in 0..D {
            let col = te.col(j);
            assert_eq!(col.c0, te.data[0][j]);
            assert_eq!(col.c1, te.data[1][j]);
        }
    }
}

// =========================================================================
// Ring edge cases
// =========================================================================
mod ring_edge_cases {
    use super::*;

    #[test]
    fn mul_by_zero() {
        let a = RingElement::monomial(7);
        let zero = RingElement::zero();
        assert_eq!(a.mul(&zero, Q), zero);
    }

    #[test]
    fn sub_self_is_zero() {
        let a = RingElement::from_constant(42);
        assert_eq!(a.sub(&a, Q), RingElement::zero());
    }

    #[test]
    fn scalar_mul_agrees_with_ring_mul() {
        let a = RingElement::monomial(3);
        let scalar = 17i64;
        let via_scalar = a.scalar_mul(scalar, Q);
        let via_ring = a.mul(&RingElement::from_constant(scalar), Q);
        assert_eq!(via_scalar, via_ring);
    }

    #[test]
    fn scalar_mul_by_neg_one() {
        let a = RingElement::from_constant(10);
        let neg = a.scalar_mul(-1, Q);
        assert_eq!(neg.ct(), -10);
        assert_eq!(a.add(&neg, Q), RingElement::zero());
    }

    #[test]
    fn norm_inf_of_monomial() {
        let m = RingElement::monomial(5);
        assert_eq!(m.norm_inf(), 1);
    }

    #[test]
    fn norm_sq_of_constant() {
        let c = RingElement::from_constant(7);
        assert_eq!(c.norm_sq(), 49);
    }

    #[test]
    fn norm_sq_of_vector() {
        let v = RingVector {
            elements: vec![RingElement::from_constant(3), RingElement::from_constant(4)],
        };
        assert_eq!(v.norm_sq(), 25);
    }

    #[test]
    fn cf_and_cf_inv_roundtrip() {
        let a = RingElement::monomial(10);
        let coeffs = *a.cf();
        let b = RingElement::cf_inv(coeffs);
        assert_eq!(a, b);
    }

    #[test]
    fn add_near_modular_boundary() {
        let a = RingElement::from_constant((Q / 2) as i64);
        let b = RingElement::from_constant(1);
        let sum = a.add(&b, Q);
        assert_eq!(sum.ct(), (Q / 2 + 1) as i64 - Q as i64);
    }

    #[test]
    fn ring_vector_add() {
        let a = RingVector {
            elements: vec![
                RingElement::from_constant(10),
                RingElement::from_constant(20),
            ],
        };
        let b = RingVector {
            elements: vec![
                RingElement::from_constant(30),
                RingElement::from_constant(40),
            ],
        };
        let sum = a.add(&b, Q);
        assert_eq!(sum.elements[0].ct(), 40);
        assert_eq!(sum.elements[1].ct(), 60);
    }

    #[test]
    fn ring_vector_scalar_mul() {
        let v = RingVector {
            elements: vec![RingElement::from_constant(5), RingElement::from_constant(7)],
        };
        let s = RingElement::from_constant(3);
        let scaled = v.ring_scalar_mul(&s, Q);
        assert_eq!(scaled.elements[0].ct(), 15);
        assert_eq!(scaled.elements[1].ct(), 21);
    }

    #[test]
    fn monomial_times_monomial() {
        let x3 = RingElement::monomial(3);
        let x5 = RingElement::monomial(5);
        let prod = x3.mul(&x5, Q);
        assert_eq!(prod, RingElement::monomial(8));
    }

    #[test]
    fn monomial_wrap_around() {
        let x = RingElement::monomial(D - 1);
        let prod = x.mul(&x, Q);
        let expected = RingElement::monomial(D - 2).scalar_mul(-1, Q);
        assert_eq!(prod, expected);
    }
}

// =========================================================================
// Extension field edge cases
// =========================================================================
mod ext_field_edge_cases {
    use super::*;

    #[test]
    fn mul_by_zero() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 5, c1: 3 };
        let result = ctx.mul(&a, &ctx.zero());
        assert_eq!(result, ctx.zero());
    }

    #[test]
    fn mul_by_one() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 5, c1: 3 };
        assert_eq!(ctx.mul(&a, &ctx.one()), a);
    }

    #[test]
    fn sub_self_is_zero() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 42, c1: 17 };
        assert_eq!(ctx.sub(&a, &a), ctx.zero());
    }

    #[test]
    fn add_commutativity() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 3, c1: 7 };
        let b = ExtFieldElement { c0: 11, c1: 2 };
        assert_eq!(ctx.add(&a, &b), ctx.add(&b, &a));
    }

    #[test]
    fn mul_commutativity() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 3, c1: 7 };
        let b = ExtFieldElement { c0: 11, c1: 2 };
        assert_eq!(ctx.mul(&a, &b), ctx.mul(&b, &a));
    }

    #[test]
    fn mul_associativity() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 3, c1: 7 };
        let b = ExtFieldElement { c0: 11, c1: 2 };
        let c = ExtFieldElement { c0: 5, c1: 9 };
        assert_eq!(ctx.mul(&a, &ctx.mul(&b, &c)), ctx.mul(&ctx.mul(&a, &b), &c));
    }

    #[test]
    fn scalar_mul_consistency() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 5, c1: 3 };
        let s = 7i64;
        let via_scalar = ctx.scalar_mul(&a, s);
        let via_mul = ctx.mul(&a, &ExtFieldElement { c0: s, c1: 0 });
        assert_eq!(via_scalar, via_mul);
    }

    #[test]
    fn inv_of_one() {
        let ctx = ctx();
        let inv = ctx.inv(&ctx.one()).unwrap();
        assert_eq!(inv, ctx.one());
    }

    #[test]
    fn inv_of_zero_is_none() {
        let ctx = ctx();
        assert!(ctx.inv(&ctx.zero()).is_none());
    }

    #[test]
    fn double_inverse_is_identity() {
        let ctx = ctx();
        let a = ExtFieldElement { c0: 13, c1: 7 };
        let inv1 = ctx.inv(&a).unwrap();
        let inv2 = ctx.inv(&inv1).unwrap();
        assert_eq!(a, inv2);
    }
}

// =========================================================================
// Extension field overflow fix (audit C2)
// =========================================================================
mod ext_field_overflow_fix {
    use super::*;
    use symphony::params::SymphonyParams;

    #[test]
    fn mul_with_large_coefficients() {
        let p = SymphonyParams::default_from_paper();
        let ctx = ExtFieldContext::new(p.q);
        let q_half = (p.q / 2) as i64;
        let a = ExtFieldElement {
            c0: q_half,
            c1: q_half,
        };
        let b = ExtFieldElement {
            c0: q_half,
            c1: q_half,
        };
        let result = ctx.mul(&a, &b);
        assert!(result.c0.unsigned_abs() <= p.q / 2);
        assert!(result.c1.unsigned_abs() <= p.q / 2);
    }

    #[test]
    fn mul_inverse_with_large_q() {
        let p = SymphonyParams::default_from_paper();
        let ctx = ExtFieldContext::new(p.q);
        let a = ExtFieldElement {
            c0: 12345,
            c1: 67890,
        };
        let a_inv = ctx.inv(&a).unwrap();
        let product = ctx.mul(&a, &a_inv);
        assert_eq!(product, ctx.one());
    }

    #[test]
    fn mul_associativity_large_q() {
        let p = SymphonyParams::default_from_paper();
        let ctx = ExtFieldContext::new(p.q);
        let a = ExtFieldElement {
            c0: 99999,
            c1: 88888,
        };
        let b = ExtFieldElement {
            c0: 77777,
            c1: 66666,
        };
        let c = ExtFieldElement {
            c0: 55555,
            c1: 44444,
        };
        let ab_c = ctx.mul(&ctx.mul(&a, &b), &c);
        let a_bc = ctx.mul(&a, &ctx.mul(&b, &c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn mul_no_overflow_near_q_half() {
        let p = SymphonyParams::default_from_paper();
        let q = p.q;
        let ctx = ExtFieldContext::new(q);
        let q_half = (q / 2) as i64;
        let a = ExtFieldElement {
            c0: q_half - 1,
            c1: q_half - 1,
        };
        let b = ExtFieldElement {
            c0: q_half - 1,
            c1: q_half - 1,
        };
        let result = ctx.mul(&a, &b);
        if let Some(b_inv) = ctx.inv(&b) {
            let roundtrip = ctx.mul(&result, &b_inv);
            assert_eq!(roundtrip, a, "mul with large q should be consistent");
        }
    }

    #[test]
    fn mul_associativity_varied_signs() {
        let p = SymphonyParams::default_from_paper();
        let ctx = ExtFieldContext::new(p.q);
        let a = ExtFieldElement {
            c0: 123456789,
            c1: -987654321,
        };
        let b = ExtFieldElement {
            c0: -111222333,
            c1: 444555666,
        };
        let c = ExtFieldElement {
            c0: 777888999,
            c1: -101010101,
        };
        let ab_c = ctx.mul(&ctx.mul(&a, &b), &c);
        let a_bc = ctx.mul(&a, &ctx.mul(&b, &c));
        assert_eq!(
            ab_c, a_bc,
            "multiplication should be associative with large values"
        );
    }
}

// =========================================================================
// NTT extended
// =========================================================================
mod ntt_extended {
    use super::*;
    use symphony::ring::ntt::NttContext;

    #[test]
    fn ntt_roundtrip_linear_coeffs() {
        let q = 12289u64;
        let ctx = NttContext::new(q);
        let mut coeffs = [0i64; D];
        for i in 0..D {
            coeffs[i] = (i as i64 * 37 + 13) % (q as i64 / 2);
        }
        let a = RingElement { coeffs };
        let a_ntt = ctx.forward(&a);
        let a_back = ctx.inverse(&a_ntt);
        assert_eq!(a, a_back, "NTT roundtrip should be exact");
    }

    #[test]
    fn ntt_friendly_primes_accepted() {
        let _ctx1 = NttContext::new(12289u64);
        let _ctx2 = NttContext::new(257u64);
    }

    #[test]
    fn ntt_roundtrip_random_poly() {
        let ntt = NttContext::new(Q);
        let mut a = RingElement::zero();
        for i in 0..D {
            a.coeffs[i] = (i as i64 * 7 + 3) % (Q as i64 / 2);
        }
        let forward = ntt.forward(&a);
        let back = ntt.inverse(&forward);
        assert_eq!(back, a);
    }

    #[test]
    fn ntt_mul_two_nontrivial_polys() {
        let ntt = NttContext::new(Q);
        let mut a = RingElement::zero();
        a.coeffs[0] = 1;
        a.coeffs[1] = 2;
        a.coeffs[2] = 3;
        let mut b = RingElement::zero();
        b.coeffs[0] = 4;
        b.coeffs[1] = 5;
        let ntt_result = ntt.ring_mul(&a, &b);
        let schoolbook = a.mul(&b, Q);
        assert_eq!(ntt_result, schoolbook);
    }

    #[test]
    fn ntt_mul_commutative() {
        let ntt = NttContext::new(Q);
        let a = RingElement::monomial(3);
        let b = RingElement::monomial(10);
        assert_eq!(ntt.ring_mul(&a, &b), ntt.ring_mul(&b, &a));
    }

    #[test]
    fn pointwise_mul_len() {
        let ntt = NttContext::new(Q);
        let a = ntt.forward(&RingElement::from_constant(1));
        let b = ntt.forward(&RingElement::from_constant(1));
        let c = ntt.pointwise_mul(&a, &b);
        assert_eq!(c.len(), D);
    }
}

// =========================================================================
// Tensor element tests
// =========================================================================
mod tensor_extended {
    use super::*;
    use symphony::ring::tensor::TensorElement;

    #[test]
    fn zero_tensor() {
        let t = TensorElement::zero();
        for row in 0..2 {
            for col in 0..D {
                assert_eq!(t.data[row][col], 0);
            }
        }
    }

    #[test]
    fn from_rows_then_row_roundtrip() {
        let r0 = RingElement::from_constant(5);
        let r1 = RingElement::monomial(3);
        let te = TensorElement::from_rows(&[r0.clone(), r1.clone()]);
        assert_eq!(te.row(0), r0);
        assert_eq!(te.row(1), r1);
    }

    #[test]
    fn add_tensors() {
        let a = TensorElement::from_rows(&[
            RingElement::from_constant(1),
            RingElement::from_constant(2),
        ]);
        let b = TensorElement::from_rows(&[
            RingElement::from_constant(3),
            RingElement::from_constant(4),
        ]);
        let sum = a.add(&b, Q);
        assert_eq!(sum.row(0).ct(), 4);
        assert_eq!(sum.row(1).ct(), 6);
    }

    #[test]
    fn norm_sq_tensor() {
        let te = TensorElement::from_rows(&[
            RingElement::from_constant(3),
            RingElement::from_constant(4),
        ]);
        assert_eq!(te.norm_sq(), 25);
    }

    #[test]
    fn k_scalar_mul() {
        let te = TensorElement::from_rows(&[
            RingElement::from_constant(2),
            RingElement::from_constant(3),
        ]);
        let k = ExtFieldElement { c0: 5, c1: 0 };
        let result = te.k_scalar_mul(&k, &ctx());
        assert_eq!(result.row(0).ct(), 10);
        assert_eq!(result.row(1).ct(), 15);
    }
}

// =========================================================================
// Property-based tests (proptest)
// =========================================================================
mod ring_proptest {
    use super::*;

    fn arb_ring_element() -> impl Strategy<Value = RingElement> {
        prop::array::uniform(-(Q as i64 / 2)..=(Q as i64 / 2))
            .prop_map(|coeffs| RingElement { coeffs })
    }

    proptest! {
        #[test]
        fn add_commutative(a in arb_ring_element(), b in arb_ring_element()) {
            prop_assert_eq!(a.add(&b, Q), b.add(&a, Q));
        }

        #[test]
        fn add_associative(a in arb_ring_element(), b in arb_ring_element(), c in arb_ring_element()) {
            let ab_c = a.add(&b, Q).add(&c, Q);
            let a_bc = a.add(&b.add(&c, Q), Q);
            prop_assert_eq!(ab_c, a_bc);
        }

        #[test]
        fn mul_commutative(a in arb_ring_element(), b in arb_ring_element()) {
            prop_assert_eq!(a.mul(&b, Q), b.mul(&a, Q));
        }

        #[test]
        fn mul_associative(a in arb_ring_element(), b in arb_ring_element(), c in arb_ring_element()) {
            let ab_c = a.mul(&b, Q).mul(&c, Q);
            let a_bc = a.mul(&b.mul(&c, Q), Q);
            prop_assert_eq!(ab_c, a_bc);
        }

        #[test]
        fn mul_distributive(a in arb_ring_element(), b in arb_ring_element(), c in arb_ring_element()) {
            let lhs = a.mul(&b.add(&c, Q), Q);
            let rhs = a.mul(&b, Q).add(&a.mul(&c, Q), Q);
            prop_assert_eq!(lhs, rhs);
        }

        #[test]
        fn add_zero_identity(a in arb_ring_element()) {
            prop_assert_eq!(a.add(&RingElement::zero(), Q), a.clone());
        }

        #[test]
        fn mul_one_identity(a in arb_ring_element()) {
            let one = RingElement::from_constant(1);
            prop_assert_eq!(a.mul(&one, Q), a.clone());
        }

        #[test]
        fn sub_self_is_zero(a in arb_ring_element()) {
            prop_assert_eq!(a.sub(&a, Q), RingElement::zero());
        }

        #[test]
        fn scalar_mul_matches_ring_mul(a in arb_ring_element(), s in -(Q as i64 / 2)..=(Q as i64 / 2)) {
            let via_scalar = a.scalar_mul(s, Q);
            let via_ring = a.mul(&RingElement::from_constant(s), Q);
            prop_assert_eq!(via_scalar, via_ring);
        }

        #[test]
        fn norm_sq_is_zero_iff_zero(a in arb_ring_element()) {
            if a == RingElement::zero() {
                prop_assert_eq!(a.norm_sq(), 0);
            } else {
                prop_assert!(a.norm_sq() > 0);
            }
        }
    }
}

mod ext_field_proptest {
    use super::*;

    fn arb_ext_field() -> impl Strategy<Value = ExtFieldElement> {
        let range = -(Q as i64 / 2)..=(Q as i64 / 2);
        (range.clone(), range).prop_map(|(c0, c1)| ExtFieldElement { c0, c1 })
    }

    proptest! {
        #[test]
        fn add_commutative(a in arb_ext_field(), b in arb_ext_field()) {
            let ctx = ctx();
            prop_assert_eq!(ctx.add(&a, &b), ctx.add(&b, &a));
        }

        #[test]
        fn mul_commutative(a in arb_ext_field(), b in arb_ext_field()) {
            let ctx = ctx();
            prop_assert_eq!(ctx.mul(&a, &b), ctx.mul(&b, &a));
        }

        #[test]
        fn mul_associative(a in arb_ext_field(), b in arb_ext_field(), c in arb_ext_field()) {
            let ctx = ctx();
            let ab_c = ctx.mul(&ctx.mul(&a, &b), &c);
            let a_bc = ctx.mul(&a, &ctx.mul(&b, &c));
            prop_assert_eq!(ab_c, a_bc);
        }

        #[test]
        fn distributive(a in arb_ext_field(), b in arb_ext_field(), c in arb_ext_field()) {
            let ctx = ctx();
            let lhs = ctx.mul(&a, &ctx.add(&b, &c));
            let rhs = ctx.add(&ctx.mul(&a, &b), &ctx.mul(&a, &c));
            prop_assert_eq!(lhs, rhs);
        }

        #[test]
        fn inverse_roundtrip(a in arb_ext_field()) {
            let ctx = ctx();
            if let Some(inv) = ctx.inv(&a) {
                prop_assert_eq!(ctx.mul(&a, &inv), ctx.one());
            }
        }
    }
}

// =========================================================================
// Parameter safety (audit C1)
// =========================================================================
mod params_q_cap {
    use super::*;
    use symphony::params::SymphonyParams;

    #[test]
    fn default_q_fits_in_i64() {
        let p = SymphonyParams::default_from_paper();
        assert!(
            p.q <= i64::MAX as u64,
            "q = {} exceeds i64::MAX = {}",
            p.q,
            i64::MAX
        );
    }

    #[test]
    fn default_q_below_2_pow_61() {
        let p = SymphonyParams::default_from_paper();
        assert!(p.q < (1u64 << 61), "q = {} should be below 2^61", p.q);
    }

    #[test]
    fn default_q_is_ntt_compatible() {
        let p = SymphonyParams::default_from_paper();
        assert_eq!(p.q % 128, 1, "q must be 1 mod 2d = 128");
    }

    #[test]
    fn ring_mul_safe_with_default_q() {
        let p = SymphonyParams::default_from_paper();
        let a = RingElement::from_constant((p.q / 2) as i64);
        let b = RingElement::from_constant((p.q / 2) as i64);
        let _ = a.mul(&b, p.q);
    }
}

// =========================================================================
// Parameter validation
// =========================================================================
mod params_validation {
    use super::*;
    use symphony::params::SymphonyParams;

    #[test]
    fn setup_panics_when_d_wrong() {
        use symphony::proof_orchestrator::Prover;
        use symphony::snark::DummySnark;
        let bad_params = SymphonyParams {
            q: 257,
            d: 32,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 16,
            k_cs: 16,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(257, D),
        };
        let result = std::panic::catch_unwind(|| {
            Prover::<DummySnark, DummySnark>::setup(bad_params);
        });
        assert!(result.is_err(), "setup() should panic when d != D");
    }

    #[test]
    fn validate_rejects_non_prime_q() {
        let params = SymphonyParams {
            q: 128,
            d: D,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 16,
            k_cs: 16,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(128, D),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
        assert!(result.is_err(), "validate should reject non-prime q");
    }

    #[test]
    fn validate_rejects_q_not_1_mod_2d() {
        let params = SymphonyParams {
            q: 127,
            d: D,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 16,
            k_cs: 16,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(127, D),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
        assert!(
            result.is_err(),
            "validate should reject q not congruent to 1 mod 2d"
        );
    }

    #[test]
    fn validate_rejects_b_less_than_2() {
        let p = SymphonyParams::default_from_paper();
        let params = SymphonyParams {
            q: p.q,
            d: D,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 1,
            k_cs: 16,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(p.q, D),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
        assert!(result.is_err(), "validate should reject b < 2");
    }

    #[test]
    fn validate_rejects_k_cs_zero() {
        let p = SymphonyParams::default_from_paper();
        let params = SymphonyParams {
            q: p.q,
            d: D,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 16,
            k_cs: 0,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(p.q, D),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| params.validate()));
        assert!(result.is_err(), "validate should reject k_cs == 0");
    }

    #[test]
    fn validate_accepts_good_params() {
        let params = SymphonyParams::default_from_paper();
        assert_eq!(params.q % (2 * D as u64), 1);
        assert!(params.q < (1u64 << 61));
    }

    #[test]
    fn norm_bounds_derived_from_beta_sis() {
        let params = SymphonyParams::default_from_paper();
        let beta_sis = params.beta_sis();
        let b_rbnd = params.b_rbnd();
        let b_bnd = params.b_bnd();
        assert_eq!(b_rbnd, beta_sis / 60);
        assert_eq!(b_bnd, b_rbnd / 2);
        assert!(beta_sis > b_rbnd);
        assert!(b_rbnd > b_bnd);
        assert!(b_bnd > 0);
    }

    #[test]
    fn default_params_fully_valid() {
        let params = SymphonyParams::default_from_paper();
        params.validate();
        assert!(params.b_rbnd() > 0);
        assert!(params.b_bnd() > 0);
        assert!(params.beta_sis() > params.b_rbnd());
        use symphony::ring::ntt::NttContext;
        let _ntt = NttContext::new(params.q);
    }
}
