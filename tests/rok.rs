//! Reductions of Knowledge tests: Πmon, Πhad, Πrg, Πgr1cs.

mod common;

use common::Q;
use symphony::commitment::AjtaiParams;
use symphony::params::D;
use symphony::r1cs::R1CSMatrices;
use symphony::ring::extension::{ExtFieldContext, ExtFieldElement};
use symphony::ring::{RingElement, RingVector};

fn ctx() -> ExtFieldContext {
    common::ctx()
}

fn simple_r1cs() -> (R1CSMatrices, Vec<i64>) {
    common::simple_r1cs()
}

fn multi_r1cs() -> (R1CSMatrices, Vec<i64>) {
    common::multi_r1cs()
}

// =========================================================================
// Πmon — monomial check
// =========================================================================
mod monomial_check {
    use super::*;
    use symphony::decomposition::monomial::{exp_map, is_monomial};
    use symphony::rok::monomial::{self, MonomialChallenges};

    fn mon_challenges(num_vars: usize) -> MonomialChallenges {
        MonomialChallenges {
            s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
        }
    }

    #[test]
    fn single_layer_length_8() {
        let ctx = ctx();
        let n = 8;
        let g: Vec<RingElement> = (0..n as i64)
            .map(|i| exp_map(i.min(D as i64 / 2 - 1)))
            .collect();
        for gi in &g {
            assert!(is_monomial(gi));
        }

        let ajtai = AjtaiParams::setup(2, n, Q);
        let ring_vec = RingVector { elements: g.clone() };
        let (commitment, _) = ajtai.commit(&ring_vec);

        let challenges = mon_challenges(3); // log2(8) = 3
        let proof = monomial::prove(&[commitment.clone()], &[g], &challenges, &ctx);
        let result = monomial::verify(&[commitment], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πmon (n=8) failed: {:?}", result.err());
    }

    #[test]
    fn two_layers_length_4() {
        let ctx = ctx();
        let n = 4;
        let g1: Vec<RingElement> = vec![exp_map(1), exp_map(-2), exp_map(0), exp_map(3)];
        let g2: Vec<RingElement> = vec![exp_map(-1), exp_map(0), exp_map(5), exp_map(-3)];
        for gi in g1.iter().chain(g2.iter()) {
            assert!(is_monomial(gi));
        }

        let ajtai = AjtaiParams::setup(2, n, Q);
        let (c1, _) = ajtai.commit(&RingVector { elements: g1.clone() });
        let (c2, _) = ajtai.commit(&RingVector { elements: g2.clone() });

        let challenges = mon_challenges(2);
        let proof = monomial::prove(&[c1.clone(), c2.clone()], &[g1, g2], &challenges, &ctx);
        let result = monomial::verify(&[c1, c2], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πmon (k_g=2, n=4) failed: {:?}", result.err());
    }

    #[test]
    fn non_monomial_detected_by_cubic_check() {
        let ctx = ctx();
        let n = 2;
        // Coefficient = 2 is outside {-1, 0, 1}, so the cubic check
        // c*(c-1)*(c+1) = 2*1*3 = 6 ≠ 0 will cause a nonzero sumcheck sum.
        let mut bad = RingElement::zero();
        bad.coeffs[0] = 2;
        assert!(!is_monomial(&bad));

        let g = vec![bad, exp_map(1)];
        let ajtai = AjtaiParams::setup(2, n, Q);
        let (c, _) = ajtai.commit(&RingVector { elements: g.clone() });

        let challenges = mon_challenges(1);
        let proof = monomial::prove(&[c.clone()], &[g], &challenges, &ctx);
        let result = monomial::verify(&[c], &proof, &challenges, &ctx);
        assert!(result.is_err(), "coefficient outside {{-1,0,1}} should be rejected by Πmon");
    }

    #[test]
    fn non_monomial_negative_coefficient_detected() {
        let ctx = ctx();
        let n = 2;
        let mut bad = RingElement::zero();
        bad.coeffs[3] = 5; // 5 is well outside {-1,0,1}
        assert!(!is_monomial(&bad));

        let g = vec![exp_map(0), bad];
        let ajtai = AjtaiParams::setup(2, n, Q);
        let (c, _) = ajtai.commit(&RingVector { elements: g.clone() });

        let challenges = mon_challenges(1);
        let proof = monomial::prove(&[c.clone()], &[g], &challenges, &ctx);
        let result = monomial::verify(&[c], &proof, &challenges, &ctx);
        assert!(result.is_err(), "coefficient = 5 should be rejected by Πmon");
    }
}

// =========================================================================
// Πhad — Hadamard check
// =========================================================================
mod hadamard_check {
    use super::*;
    use symphony::rok::hadamard::{self, HadamardChallenges};

    fn had_challenges(num_vars: usize) -> HadamardChallenges {
        HadamardChallenges {
            s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
        }
    }

    fn build_witness_matrix(z: &[i64], n: usize) -> Vec<Vec<i64>> {
        let mut wm = Vec::with_capacity(D);
        for j in 0..D {
            if j == 0 { wm.push(z.to_vec()); }
            else { wm.push(vec![0i64; n]); }
        }
        wm
    }

    #[test]
    fn valid_r1cs_accepted_4_constraints() {
        let ctx = ctx();
        let (r1cs, z) = multi_r1cs();
        assert!(r1cs.is_satisfied_mod(&z, Q));

        let wm = build_witness_matrix(&z, z.len());
        let ajtai = AjtaiParams::setup(2, z.len(), Q);
        let ring_w = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&ring_w);

        let challenges = had_challenges(2);
        let proof = hadamard::prove(&c, &wm, &r1cs, &challenges, &ctx);
        let result = hadamard::verify(&c, &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πhad (m=4) failed: {:?}", result.err());
    }

    #[test]
    fn wrong_witness_rejected() {
        let ctx = ctx();
        let (r1cs, _) = simple_r1cs();
        let bad_z = vec![1i64, 3, 10]; // 3*3 ≠ 10
        assert!(!r1cs.is_satisfied_mod(&bad_z, Q));

        let wm = build_witness_matrix(&bad_z, bad_z.len());
        let ajtai = AjtaiParams::setup(2, bad_z.len(), Q);
        let ring_w = RingVector {
            elements: bad_z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&ring_w);

        let challenges = had_challenges(1);
        let proof = hadamard::prove(&c, &wm, &r1cs, &challenges, &ctx);
        let result = hadamard::verify(&c, &proof, &challenges, &ctx);
        // With overwhelming probability over the random challenges, a bad
        // witness produces a nonzero sumcheck sum, so verify should fail.
        assert!(result.is_err(), "bad witness should be rejected by Πhad");
    }
}

// =========================================================================
// Πrg — range proof
// =========================================================================
mod range_proof {
    use super::*;
    use symphony::rok::monomial::MonomialChallenges;
    use symphony::rok::range_proof::{self, ProjectionMatrix, RangeProofChallenges, RangeProofParams};

    #[test]
    fn larger_witness() {
        let ctx = ctx();
        let n = 4;
        let ajtai = AjtaiParams::setup(2, n, Q);
        let witness = RingVector {
            elements: vec![
                RingElement::from_constant(5),
                RingElement::from_constant(-3),
                RingElement::from_constant(1),
                RingElement::from_constant(-7),
            ],
        };
        let (c, _) = ajtai.commit(&witness);

        let params = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };
        let proj = ProjectionMatrix::sample(4, D, b"test-seed-for-larger-witness!");
        // n_blocks = n*D / ell_h = 4*64/64 = 4, projected_len = 4 * lambda_pj = 16
        // padded to 16 (already power of 2), num_vars = 4
        let num_vars = 4;
        let challenges = RangeProofChallenges {
            projection: proj,
            monomial_challenges: MonomialChallenges {
                s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
                alpha: ExtFieldElement { c0: 3, c1: 2 },
                sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
            },
        };
        let proof = range_proof::prove(&c, &witness, &ajtai, &params, &challenges, &ctx);
        let result = range_proof::verify(&c, &proof, &params, &challenges, &ctx);
        assert!(result.is_ok(), "Πrg (n=4) failed: {:?}", result.err());
    }

    #[test]
    fn projection_preserves_dimensions() {
        let proj = ProjectionMatrix::sample(8, 16, b"seed-for-projection-dim-test");
        let coeffs = vec![1i64; 32];
        let result = proj.apply_structured(&coeffs, 2);
        assert_eq!(result.len(), 2 * 8);
    }
}

// =========================================================================
// Πgr1cs — single-instance reduction
// =========================================================================
mod gr1cs {
    use super::*;
    use symphony::rok::gr1cs::{self, GR1CSChallenges};
    use symphony::rok::range_proof::{ProjectionMatrix, RangeProofParams};

    fn gr1cs_challenges(num_vars_had: usize, num_vars_mon: usize) -> GR1CSChallenges {
        GR1CSChallenges {
            projection: ProjectionMatrix::sample(4, D, b"gr1cs-test-seed-1234567890ab"),
            sumcheck_seed_had: (0..num_vars_had).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            hadamard_sumcheck_challenges: (0..num_vars_had).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
            sumcheck_seed_mon: (0..num_vars_mon).map(|i| ExtFieldElement { c0: 11 + i as i64, c1: 4 }).collect(),
            monomial_sumcheck_challenges: (0..num_vars_mon).map(|i| ExtFieldElement { c0: 13 + i as i64, c1: 5 }).collect(),
        }
    }

    #[test]
    fn prove_verify_simple() {
        let ctx = ctx();
        let (r1cs, z) = simple_r1cs();
        assert!(r1cs.is_satisfied_mod(&z, Q));

        let n_in = 1;
        let public_input = &z[..n_in];
        let witness_elems: Vec<RingElement> = z[n_in..].iter().map(|&v| RingElement::from_constant(v)).collect();
        let witness = RingVector { elements: witness_elems };

        let ajtai = AjtaiParams::setup(2, r1cs.num_variables, Q);
        let full_ring_w = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&full_ring_w);

        let range_params = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };

        // num_vars_had = log2(2) = 1, num_vars_mon needs to match projected vector length
        // n_blocks = 3*64/64 = 3, projected_len = 3*4 = 12, padded to 16, num_vars_mon = 4
        let challenges = gr1cs_challenges(1, 4);

        let proof = gr1cs::prove(&c, public_input, &witness, &r1cs, &ajtai, &range_params, &challenges, &ctx);
        let result = gr1cs::verify(&c, public_input, &proof, &r1cs, &range_params, &challenges, &ctx);
        assert!(result.is_ok(), "Πgr1cs failed: {:?}", result.err());
    }
}

// =========================================================================
// Generalized R1CS
// =========================================================================
mod generalized_r1cs {
    use super::*;
    use symphony::r1cs::generalized::{self, GeneralizedR1CSParams};

    #[test]
    fn check_hadamard_valid() {
        let (matrices, z) = simple_r1cs();
        let params = GeneralizedR1CSParams {
            n_in: 1,
            n_w: 2,
            ell_h: D,
            bound: 1024,
            matrices,
        };
        let public_input = vec![RingElement::from_constant(z[0])];
        let witness: Vec<RingElement> = z[1..].iter().map(|&v| RingElement::from_constant(v)).collect();
        assert!(generalized::check_hadamard(&params, &public_input, &witness, Q));
    }

    #[test]
    fn check_hadamard_invalid() {
        let (matrices, _) = simple_r1cs();
        let params = GeneralizedR1CSParams {
            n_in: 1,
            n_w: 2,
            ell_h: D,
            bound: 1024,
            matrices,
        };
        let public_input = vec![RingElement::from_constant(1)];
        let witness = vec![
            RingElement::from_constant(3),
            RingElement::from_constant(10), // 3*3 ≠ 10
        ];
        assert!(!generalized::check_hadamard(&params, &public_input, &witness, Q));
    }
}

// =========================================================================
// Πhad — extended Hadamard tests
// =========================================================================
mod hadamard_extended {
    use super::*;
    use symphony::rok::hadamard::{self, HadamardChallenges};

    fn build_witness_matrix(z: &[i64], n: usize) -> Vec<Vec<i64>> {
        let mut wm = Vec::with_capacity(D);
        for j in 0..D {
            if j == 0 { wm.push(z.to_vec()); }
            else { wm.push(vec![0i64; n]); }
        }
        wm
    }

    #[test]
    fn single_constraint_r1cs() {
        let ctx = ctx();
        // x * x = y padded to 2 rows
        let (r1cs, z) = simple_r1cs();
        assert!(r1cs.is_satisfied_mod(&z, Q));

        let wm = build_witness_matrix(&z, z.len());
        let ajtai = AjtaiParams::setup(2, z.len(), Q);
        let ring_w = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&ring_w);

        let challenges = HadamardChallenges {
            s: vec![ExtFieldElement { c0: 3, c1: 1 }],
            alpha: ExtFieldElement { c0: 7, c1: 0 },
            sumcheck_challenges: vec![ExtFieldElement { c0: 11, c1: 2 }],
        };
        let proof = hadamard::prove(&c, &wm, &r1cs, &challenges, &ctx);
        let result = hadamard::verify(&c, &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Single constraint Πhad failed: {:?}", result.err());
    }

    #[test]
    fn eight_constraint_r1cs() {
        let ctx = ctx();
        let m = 8;
        let n = 8;
        let mut r1cs = R1CSMatrices::new(m, n, 1);
        // row 0: z[1] * z[2] = z[3]
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 3, 1);
        // rows 1..7: trivial 0*0=0
        let z = vec![1i64, 2, 3, 6, 0, 0, 0, 0];
        assert!(r1cs.is_satisfied_mod(&z, Q));

        let wm = build_witness_matrix(&z, n);
        let ajtai = AjtaiParams::setup(2, n, Q);
        let ring_w = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = ajtai.commit(&ring_w);

        let num_vars = 3; // log2(8)
        let challenges = HadamardChallenges {
            s: (0..num_vars).map(|i| ExtFieldElement { c0: 3 + i as i64, c1: 1 }).collect(),
            alpha: ExtFieldElement { c0: 7, c1: 2 },
            sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 11 + i as i64, c1: 3 }).collect(),
        };
        let proof = hadamard::prove(&c, &wm, &r1cs, &challenges, &ctx);
        let result = hadamard::verify(&c, &proof, &challenges, &ctx);
        assert!(result.is_ok(), "8-constraint Πhad failed: {:?}", result.err());
    }
}

// =========================================================================
// Πmon — extended monomial tests
// =========================================================================
mod monomial_extended {
    use super::*;
    use symphony::decomposition::monomial::{exp_map, is_monomial};
    use symphony::rok::monomial::{self, MonomialChallenges};

    fn mon_challenges(num_vars: usize) -> MonomialChallenges {
        MonomialChallenges {
            s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
        }
    }

    #[test]
    fn all_zero_vector() {
        let ctx = ctx();
        let n = 4;
        let g = vec![RingElement::zero(); n];
        for gi in &g {
            assert!(is_monomial(gi));
        }

        let ajtai = AjtaiParams::setup(2, n, Q);
        let (c, _) = ajtai.commit(&RingVector { elements: g.clone() });

        let challenges = mon_challenges(2);
        let proof = monomial::prove(&[c.clone()], &[g], &challenges, &ctx);
        let result = monomial::verify(&[c], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "All-zero monomial failed: {:?}", result.err());
    }

    #[test]
    fn all_identity_monomials() {
        let ctx = ctx();
        let n = 4;
        let g = vec![exp_map(0); n]; // all ±X^0 = ±1
        for gi in &g {
            assert!(is_monomial(gi));
        }

        let ajtai = AjtaiParams::setup(2, n, Q);
        let (c, _) = ajtai.commit(&RingVector { elements: g.clone() });

        let challenges = mon_challenges(2);
        let proof = monomial::prove(&[c.clone()], &[g], &challenges, &ctx);
        let result = monomial::verify(&[c], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "All-identity monomial failed: {:?}", result.err());
    }

    #[test]
    fn length_16_vectors() {
        let ctx = ctx();
        let n = 16;
        let g: Vec<RingElement> = (0..n as i64)
            .map(|i| exp_map((i % (D as i64 / 2 - 1)) - D as i64 / 4))
            .collect();

        let ajtai = AjtaiParams::setup(2, n, Q);
        let (c, _) = ajtai.commit(&RingVector { elements: g.clone() });

        let challenges = mon_challenges(4); // log2(16)
        let proof = monomial::prove(&[c.clone()], &[g], &challenges, &ctx);
        let result = monomial::verify(&[c], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πmon (n=16) failed: {:?}", result.err());
    }

    #[test]
    fn three_layers() {
        let ctx = ctx();
        let n = 4;
        let layers: Vec<Vec<RingElement>> = (0..3)
            .map(|layer| {
                (0..n as i64)
                    .map(|i| exp_map((i + layer * 3) % (D as i64 / 2 - 1)))
                    .collect()
            })
            .collect();

        let ajtai = AjtaiParams::setup(2, n, Q);
        let commitments: Vec<_> = layers.iter()
            .map(|g| ajtai.commit(&RingVector { elements: g.clone() }).0)
            .collect();

        let challenges = mon_challenges(2);
        let proof = monomial::prove(
            &commitments,
            &layers,
            &challenges,
            &ctx,
        );
        let result = monomial::verify(&commitments, &proof, &challenges, &ctx);
        assert!(result.is_ok(), "3-layer Πmon failed: {:?}", result.err());
    }
}

// =========================================================================
// Generalized R1CS — extended tests
// =========================================================================
mod generalized_r1cs_extended {
    use super::*;
    use symphony::r1cs::generalized::{self, GeneralizedR1CSParams};

    #[test]
    fn multivariate_witness() {
        // x * y = z over Rq with ring witnesses having multiple nonzero coefficients
        let mut matrices = R1CSMatrices::new(1, 3, 1);
        matrices.a.insert(0, 1, 1);
        matrices.b.insert(0, 2, 1);
        matrices.c.insert(0, 0, 1); // z[0] acts as "product" slot
        let params = GeneralizedR1CSParams {
            n_in: 0,
            n_w: 3,
            ell_h: D,
            bound: 1024,
            matrices,
        };
        // 2 * 3 = 6 in every coefficient position
        let witness = vec![
            RingElement::from_constant(6),
            RingElement::from_constant(2),
            RingElement::from_constant(3),
        ];
        assert!(generalized::check_hadamard(&params, &[], &witness, Q));
    }

    #[test]
    fn wrong_product_detected() {
        let mut matrices = R1CSMatrices::new(1, 3, 1);
        matrices.a.insert(0, 1, 1);
        matrices.b.insert(0, 2, 1);
        matrices.c.insert(0, 0, 1);
        let params = GeneralizedR1CSParams {
            n_in: 0,
            n_w: 3,
            ell_h: D,
            bound: 1024,
            matrices,
        };
        let witness = vec![
            RingElement::from_constant(7), // wrong: 2*3=6 ≠ 7
            RingElement::from_constant(2),
            RingElement::from_constant(3),
        ];
        assert!(!generalized::check_hadamard(&params, &[], &witness, Q));
    }
}

// =========================================================================
// Integer log2 fix — power-of-two edge cases
// =========================================================================
mod integer_log2_fix {
    use super::*;
    use symphony::rok::hadamard::{self, HadamardChallenges};
    use symphony::rok::monomial::{self, MonomialChallenges};
    use symphony::decomposition::monomial::exp_map;

    #[test]
    fn hadamard_power_of_two_constraints() {
        let ctx = ctx();
        // Test with exact powers of 2: 2, 4, 8
        for &m in &[2usize, 4, 8] {
            let n = m;
            let mut r1cs = R1CSMatrices::new(m, n, 1);
            r1cs.a.insert(0, 1, 1);
            r1cs.b.insert(0, 1, 1);
            r1cs.c.insert(0, 1, 1); // trivial: x*x = x for x=1
            let mut z = vec![0i64; n];
            z[0] = 1;
            z[1] = 1;
            assert!(r1cs.is_satisfied_mod(&z, Q));

            let num_vars = if m <= 1 { 0 } else { (usize::BITS - (m - 1).leading_zeros()) as usize };
            let mut wm = Vec::with_capacity(D);
            for j in 0..D {
                if j == 0 { wm.push(z.clone()); }
                else { wm.push(vec![0i64; n]); }
            }

            let ajtai = AjtaiParams::setup(2, n, Q);
            let ring_w = RingVector {
                elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
            };
            let (c, _) = ajtai.commit(&ring_w);

            let challenges = HadamardChallenges {
                s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
                alpha: ExtFieldElement { c0: 3, c1: 2 },
                sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
            };

            let proof = hadamard::prove(&c, &wm, &r1cs, &challenges, &ctx);
            let result = hadamard::verify(&c, &proof, &challenges, &ctx);
            assert!(result.is_ok(), "Πhad (m={m}) failed with integer log2: {:?}", result.err());
        }
    }

    #[test]
    fn monomial_power_of_two_lengths() {
        let ctx = ctx();
        for &n in &[2usize, 4, 8, 16] {
            let g: Vec<RingElement> = (0..n as i64).map(|i| exp_map(i % 30)).collect();

            let ajtai = AjtaiParams::setup(2, n, Q);
            let (c, _) = ajtai.commit(&RingVector { elements: g.clone() });

            let num_vars = if n <= 1 { 0 } else { (usize::BITS - (n - 1).leading_zeros()) as usize };
            let challenges = MonomialChallenges {
                s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
                alpha: ExtFieldElement { c0: 3, c1: 2 },
                sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
            };

            let proof = monomial::prove(&[c.clone()], &[g], &challenges, &ctx);
            let result = monomial::verify(&[c], &proof, &challenges, &ctx);
            assert!(result.is_ok(), "Πmon (n={n}) failed with integer log2: {:?}", result.err());
        }
    }
}

// =========================================================================
// Range proof exact tolerance fix
// =========================================================================
mod range_proof_tolerance_fix {
    use super::*;
    use symphony::rok::monomial::MonomialChallenges;
    use symphony::rok::range_proof::{self, ProjectionMatrix, RangeProofChallenges, RangeProofParams};

    #[test]
    fn exact_projection_match_accepted() {
        let ctx = ctx();
        let n = 2;
        let ajtai = AjtaiParams::setup(2, n, Q);
        let witness = RingVector {
            elements: vec![
                RingElement::from_constant(1),
                RingElement::from_constant(-1),
            ],
        };
        let (c, _) = ajtai.commit(&witness);

        let params = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };
        let proj = ProjectionMatrix::sample(4, D, b"exact-tol-test-seed-12345678");
        let num_vars = 3;
        let challenges = RangeProofChallenges {
            projection: proj,
            monomial_challenges: MonomialChallenges {
                s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
                alpha: ExtFieldElement { c0: 3, c1: 2 },
                sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
            },
        };

        let proof = range_proof::prove(&c, &witness, &ajtai, &params, &challenges, &ctx);
        let result = range_proof::verify(&c, &proof, &params, &challenges, &ctx);
        assert!(result.is_ok(), "honest range proof should pass exact check: {:?}", result.err());
    }

    #[test]
    fn tampered_projected_values_rejected() {
        let ctx = ctx();
        let n = 2;
        let ajtai = AjtaiParams::setup(2, n, Q);
        let witness = RingVector {
            elements: vec![
                RingElement::from_constant(1),
                RingElement::from_constant(-1),
            ],
        };
        let (c, _) = ajtai.commit(&witness);

        let params = RangeProofParams {
            lambda_pj: 4,
            ell_h: D,
            d_prime: 62,
            k_g: 2,
            input_bound: 1024,
        };
        let proj = ProjectionMatrix::sample(4, D, b"tamper-tol-test-seed-1234567");
        let num_vars = 3;
        let challenges = RangeProofChallenges {
            projection: proj,
            monomial_challenges: MonomialChallenges {
                s: (0..num_vars).map(|i| ExtFieldElement { c0: 5 + i as i64, c1: 1 }).collect(),
                alpha: ExtFieldElement { c0: 3, c1: 2 },
                sumcheck_challenges: (0..num_vars).map(|i| ExtFieldElement { c0: 7 + i as i64, c1: 3 }).collect(),
            },
        };

        let mut proof = range_proof::prove(&c, &witness, &ajtai, &params, &challenges, &ctx);
        // Tamper with a projected value by adding 1
        if !proof.projected_values.is_empty() {
            proof.projected_values[0] += 1;
        }
        let result = range_proof::verify(&c, &proof, &params, &challenges, &ctx);
        assert!(result.is_err(), "tampered projected value should be rejected with exact tolerance");
    }
}
