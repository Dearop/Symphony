//! Ajtai commitment scheme tests: binding, hiding, homomorphic properties.

mod common;

use common::Q;
use symphony::commitment::AjtaiParams;
use symphony::ring::{RingElement, RingVector};

// =========================================================================
// Core commitment
// =========================================================================
mod commitment_core {
    use super::*;
    use symphony::commitment::opening;

    #[test]
    fn commit_verify_roundtrip() {
        let ajtai = AjtaiParams::setup(2, 4, Q);
        let w = RingVector {
            elements: vec![RingElement::from_constant(1); 4],
        };
        let (c, _) = ajtai.commit(&w);
        assert!(ajtai.verify_open(&c, &w, u128::MAX));
    }

    #[test]
    fn wrong_witness_rejected() {
        let ajtai = AjtaiParams::setup(2, 4, Q);
        let w = RingVector {
            elements: vec![RingElement::from_constant(1); 4],
        };
        let (c, _) = ajtai.commit(&w);
        let bad_w = RingVector {
            elements: vec![RingElement::from_constant(2); 4],
        };
        assert!(!ajtai.verify_open(&c, &bad_w, u128::MAX));
    }

    #[test]
    fn norm_bound_enforced() {
        let ajtai = AjtaiParams::setup(2, 4, Q);
        let w = RingVector {
            elements: vec![RingElement::from_constant(100); 4],
        };
        let (c, _) = ajtai.commit(&w);
        assert!(!ajtai.verify_open(&c, &w, 100));
        assert!(ajtai.verify_open(&c, &w, u128::MAX));
    }

    #[test]
    fn zero_witness_commits_to_zero() {
        let ajtai = AjtaiParams::setup(3, 5, Q);
        let w = RingVector::zero(5);
        let (c, _) = ajtai.commit(&w);
        for elem in &c.value.elements {
            assert_eq!(*elem, RingElement::zero());
        }
    }

    #[test]
    fn strict_opening() {
        let ajtai = AjtaiParams::setup(2, 3, Q);
        let w = RingVector {
            elements: vec![RingElement::from_constant(1); 3],
        };
        let (c, _) = ajtai.commit(&w);
        assert!(opening::verify_strict(&ajtai, &c, &w, u128::MAX));
        assert!(!opening::verify_strict(&ajtai, &c, &w, 1));
    }

    #[test]
    fn relaxed_opening() {
        let ajtai = AjtaiParams::setup(2, 3, Q);
        let m = RingVector {
            elements: vec![RingElement::from_constant(2); 3],
        };
        let s = RingElement::from_constant(1);
        let f = m.ring_scalar_mul(&s, Q);
        let (c, _) = ajtai.commit(&m);

        let relaxed = opening::RelaxedOpening { f, s };
        assert!(opening::verify_relaxed(&ajtai, &c, &m, &relaxed, u128::MAX));
    }

    #[test]
    fn relaxed_opening_wrong_scalar_rejected() {
        let ajtai = AjtaiParams::setup(2, 3, Q);
        let m = RingVector {
            elements: vec![RingElement::from_constant(2); 3],
        };
        let s = RingElement::from_constant(1);
        let f = m.ring_scalar_mul(&s, Q);
        let (c, _) = ajtai.commit(&m);

        let bad_s = RingElement::from_constant(2);
        let bad_relaxed = opening::RelaxedOpening { f, s: bad_s };
        assert!(!opening::verify_relaxed(&ajtai, &c, &m, &bad_relaxed, u128::MAX));
    }

    #[test]
    fn fine_grained_opening() {
        let ajtai = AjtaiParams::setup(2, 4, Q);
        let w = RingVector {
            elements: vec![RingElement::from_constant(1); 4],
        };
        let (c, _) = ajtai.commit(&w);
        assert!(opening::verify_fine_grained(&ajtai, &c, &w, 2, u128::MAX));
        assert!(!opening::verify_fine_grained(&ajtai, &c, &w, 2, 1));
    }
}

// =========================================================================
// Homomorphic properties
// =========================================================================
mod commitment_advanced {
    use super::*;

    #[test]
    fn linearity_over_witnesses() {
        let ajtai = AjtaiParams::setup(3, 4, Q);
        let w1 = RingVector {
            elements: vec![RingElement::from_constant(2); 4],
        };
        let w2 = RingVector {
            elements: vec![RingElement::from_constant(3); 4],
        };
        let w_sum = w1.add(&w2, Q);

        let (c1, _) = ajtai.commit(&w1);
        let (c2, _) = ajtai.commit(&w2);
        let (c_sum, _) = ajtai.commit(&w_sum);

        let c1_plus_c2 = c1.value.add(&c2.value, Q);
        assert_eq!(c1_plus_c2.elements, c_sum.value.elements);
    }

    #[test]
    fn scalar_mul_on_commitment() {
        let ajtai = AjtaiParams::setup(2, 3, Q);
        let w = RingVector {
            elements: vec![RingElement::from_constant(5); 3],
        };
        let s = RingElement::from_constant(7);
        let ws = w.ring_scalar_mul(&s, Q);

        let (c_w, _) = ajtai.commit(&w);
        let (c_ws, _) = ajtai.commit(&ws);

        let sc_w = c_w.value.ring_scalar_mul(&s, Q);
        assert_eq!(sc_w.elements, c_ws.value.elements);
    }

    #[test]
    fn different_kappa_values() {
        for kappa in 1..=5 {
            let ajtai = AjtaiParams::setup(kappa, 3, Q);
            let w = RingVector {
                elements: vec![RingElement::from_constant(1); 3],
            };
            let (c, _) = ajtai.commit(&w);
            assert_eq!(c.value.len(), kappa);
            assert!(ajtai.verify_open(&c, &w, u128::MAX));
        }
    }
}
