//! SNARK pipeline tests: encoding, DummySnark pipeline, audit fixes.

mod common;

use common::Q;
use symphony::commitment::Commitment;
use symphony::params::{SymphonyParams, D};
use symphony::r1cs::R1CSMatrices;
use symphony::ring::{RingElement, RingVector};

fn multi_r1cs() -> (R1CSMatrices, Vec<i64>) {
    common::multi_r1cs()
}

fn make_statement_raw(
    z: &[i64],
    n_in: usize,
    ajtai: &symphony::commitment::AjtaiParams,
) -> symphony::folding::FoldingStatement {
    let full_ring = RingVector {
        elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
    };
    let (c, _) = ajtai.commit(&full_ring);
    let witness_part = RingVector {
        elements: z[n_in..]
            .iter()
            .map(|&v| RingElement::from_constant(v))
            .collect(),
    };
    symphony::folding::FoldingStatement {
        commitment: c,
        public_input: z[..n_in].to_vec(),
        witness: witness_part,
    }
}

// =========================================================================
// CP-SNARK encoding
// =========================================================================
mod cp_snark_encoding {
    use super::*;
    use symphony::fiat_shamir::transcript::Transcript;
    use symphony::folding::digest::{digest_challenges, digest_fold_inputs, Digest32, FoldInput};
    use symphony::folding::{
        FoldedInstance, FoldedOutputInstance, FoldedOutputWitness, FoldedWitness,
    };
    use symphony::ring::tensor::TensorElement;
    use symphony::snark::cp_snark;

    fn dummy_folded_instance() -> FoldedInstance {
        FoldedInstance {
            commitment: Commitment {
                value: RingVector::zero(1),
            },
            public_input: vec![RingElement::from_constant(0)],
            evaluation_values: vec![TensorElement::zero()],
        }
    }

    fn dummy_folded_output_instance() -> FoldedOutputInstance {
        FoldedOutputInstance {
            folded_instance: dummy_folded_instance(),
            linear_relation: symphony::rok::LinearRelation {
                commitment: Commitment {
                    value: RingVector::zero(1),
                },
                evaluation_point: vec![],
                evaluation_values: [
                    TensorElement::zero(),
                    TensorElement::zero(),
                    TensorElement::zero(),
                ],
            },
            batched_relation: symphony::rok::BatchedLinearRelation {
                commitments: vec![],
                evaluation_point: vec![],
                evaluation_values: vec![],
            },
        }
    }

    #[test]
    fn encode_cp_instance_deterministic() {
        let comms = vec![b"comm-0".to_vec(), b"comm-1".to_vec()];
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let folded = dummy_folded_instance();
        let e1 = cp_snark::encode_cp_instance(&comms, &folded, &mut t1);
        let e2 = cp_snark::encode_cp_instance(&comms, &folded, &mut t2);
        assert_eq!(e1, e2);
        assert!(!e1.is_empty());
    }

    #[test]
    fn compressed_cp_instance_is_constant_size() {
        let folded = dummy_folded_instance();
        let fold_root: Digest32 = [0u8; 32];
        let challenge_digest: Digest32 = [1u8; 32];
        let fs_root: Digest32 = [2u8; 32];
        let tsd: Digest32 = [3u8; 32];

        // Encode with different digest values — size must be identical
        let e1 = cp_snark::encode_cp_instance_compressed(
            &fold_root,
            &folded,
            &challenge_digest,
            &fs_root,
            &tsd,
        );

        let fs_root_2: Digest32 = [99u8; 32];
        let tsd_2: Digest32 = [88u8; 32];
        let e2 = cp_snark::encode_cp_instance_compressed(
            &fold_root,
            &folded,
            &challenge_digest,
            &fs_root_2,
            &tsd_2,
        );

        // The encoded instances must be the same length regardless of k
        assert_eq!(
            e1.len(),
            e2.len(),
            "compressed CP instance size must not depend on k"
        );
    }

    #[test]
    fn compressed_cp_instance_deterministic() {
        let folded = dummy_folded_instance();
        let fold_root: Digest32 = [42u8; 32];
        let challenge_digest: Digest32 = [7u8; 32];
        let fs_root: Digest32 = [2u8; 32];
        let tsd: Digest32 = [3u8; 32];

        let e1 = cp_snark::encode_cp_instance_compressed(
            &fold_root,
            &folded,
            &challenge_digest,
            &fs_root,
            &tsd,
        );
        let e2 = cp_snark::encode_cp_instance_compressed(
            &fold_root,
            &folded,
            &challenge_digest,
            &fs_root,
            &tsd,
        );
        assert_eq!(e1, e2);
    }

    #[test]
    fn fold_root_is_binding() {
        let inputs_a = vec![FoldInput {
            commitment_bytes: vec![1, 2, 3],
            public_input: vec![10, 20],
            eval_values_bytes: vec![4, 5],
        }];
        let inputs_b = vec![FoldInput {
            commitment_bytes: vec![1, 2, 4], // one byte changed
            public_input: vec![10, 20],
            eval_values_bytes: vec![4, 5],
        }];
        assert_ne!(
            digest_fold_inputs(&inputs_a),
            digest_fold_inputs(&inputs_b),
            "fold_root must change when any fold input changes"
        );
    }

    #[test]
    fn challenge_digest_is_binding() {
        let a = vec![vec![0u8; 32], vec![1u8; 32]];
        let b = vec![vec![0u8; 32], vec![2u8; 32]]; // second challenge changed
        assert_ne!(
            digest_challenges(&a),
            digest_challenges(&b),
            "challenge_digest must change when any challenge changes"
        );
    }

    #[test]
    fn encode_cp_witness_nonempty() {
        let openings = vec![b"opening-0".to_vec()];
        let transcript = b"transcript-data";
        let encoded = cp_snark::encode_cp_witness(&openings, transcript);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_instance_nonempty() {
        let fi = FoldedInstance {
            commitment: Commitment {
                value: RingVector::zero(2),
            },
            public_input: vec![RingElement::from_constant(1)],
            evaluation_values: vec![TensorElement::zero()],
        };
        let encoded = cp_snark::encode_folded_instance(&fi);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_witness_nonempty() {
        let fw = FoldedWitness {
            witness: RingVector::zero(3),
            monomial_vectors: vec![RingVector::zero(2)],
        };
        let encoded = cp_snark::encode_folded_witness(&fw);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_output_instance_nonempty() {
        let foi = dummy_folded_output_instance();
        let encoded = cp_snark::encode_folded_output_instance(&foi);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_output_witness_nonempty() {
        let fow = FoldedOutputWitness {
            folded_witness: FoldedWitness {
                witness: RingVector::zero(3),
                monomial_vectors: vec![RingVector::zero(2)],
            },
        };
        let encoded = cp_snark::encode_folded_output_witness(&fow);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn encode_folded_output_instance_is_binding() {
        let mut a = dummy_folded_output_instance();
        let mut b = dummy_folded_output_instance();
        b.linear_relation.evaluation_values[0].data[0][0] = 7;
        assert_ne!(
            cp_snark::encode_folded_output_instance(&a),
            cp_snark::encode_folded_output_instance(&b)
        );

        a.batched_relation
            .evaluation_point
            .push(symphony::ring::extension::ExtFieldElement { c0: 1, c1: 2 });
        assert_ne!(
            cp_snark::encode_folded_output_instance(&a),
            cp_snark::encode_folded_output_instance(&dummy_folded_output_instance())
        );
    }
}

// =========================================================================
// CP R1CS generator tests (Phase A)
// =========================================================================
mod cp_r1cs_tests {
    use symphony::params::D;
    use symphony::snark::cp_snark::{self, CpR1csLayout};

    const BB_P: u64 = 2013265921; // BabyBear modulus

    /// Negacyclic convolution (schoolbook) over BabyBear.
    /// Computes (a · b) mod (X^D + 1) with coefficients mod BB_P.
    fn ring_mul_bb(a: &[i64], b: &[i64]) -> Vec<i64> {
        assert_eq!(a.len(), D);
        assert_eq!(b.len(), D);
        let mut out = vec![0i64; D];
        for (k, &a_coeff) in a.iter().enumerate().take(D) {
            for (m, &b_coeff) in b.iter().enumerate().take(D) {
                let prod = ((a_coeff as i128 * b_coeff as i128) % BB_P as i128) as i64;
                let idx = k + m;
                if idx < D {
                    out[idx] = ((out[idx] as i128 + prod as i128) % BB_P as i128) as i64;
                } else {
                    // Negacyclic: X^D = -1
                    let idx2 = idx - D;
                    out[idx2] =
                        ((out[idx2] as i128 - prod as i128).rem_euclid(BB_P as i128)) as i64;
                }
            }
        }
        // Normalize to [0, BB_P)
        for v in &mut out {
            *v = ((*v as i128).rem_euclid(BB_P as i128)) as i64;
        }
        out
    }

    fn centered_mod_bb(value: i128) -> i64 {
        let p = BB_P as i128;
        let reduced = value.rem_euclid(p);
        if reduced > p / 2 {
            (reduced - p) as i64
        } else {
            reduced as i64
        }
    }

    /// Build a z-vector for the Phase A CP R1CS and check satisfaction.
    #[test]
    fn cp_r1cs_phase_a_satisfied_with_valid_folding() {
        let ell_np = 2;
        let kappa = 2;
        let n_in = 1;

        // m=0 generates Phase A constraints only (no Hadamard sumcheck)
        let (r1cs, layout) = cp_snark::generate_cp_r1cs(ell_np, kappa, n_in, 0, -1, BB_P);

        // Create simple ring elements (small values, no overflow issues)
        let mut beta = vec![vec![0i64; D]; ell_np];
        beta[0][0] = 3; // beta[0] = constant 3
        beta[1][0] = 5; // beta[1] = constant 5

        let mut c = vec![vec![vec![0i64; D]; kappa]; ell_np];
        c[0][0][0] = 7;
        c[0][0][1] = 2; // c_0[0] = 7 + 2X
        c[0][1][0] = 1; // c_0[1] = 1
        c[1][0][0] = 11;
        c[1][0][2] = 1; // c_1[0] = 11 + X^2
        c[1][1][0] = 4;
        c[1][1][1] = 3; // c_1[1] = 4 + 3X

        let mut x_in = vec![vec![vec![0i64; D]; n_in]; ell_np];
        x_in[0][0][0] = 10; // x_0[0] = 10
        x_in[1][0][0] = 20; // x_1[0] = 20

        // Compute ring products mod BabyBear
        let mut prod_c = vec![vec![vec![0i64; D]; kappa]; ell_np];
        let mut prod_x = vec![vec![vec![0i64; D]; n_in]; ell_np];
        for ell in 0..ell_np {
            for i in 0..kappa {
                prod_c[ell][i] = ring_mul_bb(&beta[ell], &c[ell][i]);
            }
            for s in 0..n_in {
                prod_x[ell][s] = ring_mul_bb(&beta[ell], &x_in[ell][s]);
            }
        }

        // Compute sums: c* = Σ_ℓ prod_c[ℓ], x* = Σ_ℓ prod_x[ℓ]
        let mut c_star = vec![vec![0i64; D]; kappa];
        let mut x_star = vec![vec![0i64; D]; n_in];
        for ell in 0..ell_np {
            for i in 0..kappa {
                for j in 0..D {
                    c_star[i][j] = ((c_star[i][j] as i128 + prod_c[ell][i][j] as i128)
                        .rem_euclid(BB_P as i128)) as i64;
                }
            }
            for s in 0..n_in {
                for j in 0..D {
                    x_star[s][j] = ((x_star[s][j] as i128 + prod_x[ell][s][j] as i128)
                        .rem_euclid(BB_P as i128)) as i64;
                }
            }
        }

        // Build z-vector
        let mut z = vec![0i64; layout.num_variables];
        z[layout.off_one] = 1;

        for i in 0..kappa {
            for j in 0..D {
                z[layout.c_star(i, j)] = c_star[i][j];
            }
        }
        for s in 0..n_in {
            for j in 0..D {
                z[layout.x_star(s, j)] = x_star[s][j];
            }
        }
        for ell in 0..ell_np {
            for j in 0..D {
                z[layout.beta(ell, j)] = beta[ell][j];
            }
            for i in 0..kappa {
                for j in 0..D {
                    z[layout.c(ell, i, j)] = c[ell][i][j];
                }
            }
            for s in 0..n_in {
                for j in 0..D {
                    z[layout.x_in(ell, s, j)] = x_in[ell][s][j];
                }
            }
            for i in 0..kappa {
                for j in 0..D {
                    z[layout.prod_c(ell, i, j)] = prod_c[ell][i][j];
                }
            }
            for s in 0..n_in {
                for j in 0..D {
                    z[layout.prod_x(ell, s, j)] = prod_x[ell][s][j];
                }
            }
        }

        cp_snark::fill_cp_wrap_range_bits(&mut z, &layout);

        // Verify R1CS satisfaction over BabyBear
        assert!(
            r1cs.is_satisfied_mod(&z, BB_P),
            "CP R1CS should be satisfied with valid folding linear combination"
        );
    }

    #[test]
    fn cp_r1cs_rejects_wrong_folded_commitment() {
        let ell_np = 2;
        let kappa = 1;
        let n_in = 1;

        let (r1cs, layout) = cp_snark::generate_cp_r1cs(ell_np, kappa, n_in, 0, -1, BB_P);

        // Same setup as above but simpler
        let beta = vec![
            vec![1i64; 1]
                .into_iter()
                .chain(vec![0; D - 1])
                .collect::<Vec<_>>();
            ell_np
        ];
        let c: Vec<Vec<Vec<i64>>> = (0..ell_np)
            .map(|ell| {
                vec![{
                    let mut v = vec![0i64; D];
                    v[0] = (ell + 1) as i64;
                    v
                }]
            })
            .collect();
        let x_in: Vec<Vec<Vec<i64>>> = (0..ell_np)
            .map(|ell| {
                vec![{
                    let mut v = vec![0i64; D];
                    v[0] = (ell + 10) as i64;
                    v
                }]
            })
            .collect();

        // Compute correct products
        let mut prod_c = vec![vec![vec![0i64; D]; kappa]; ell_np];
        let mut prod_x = vec![vec![vec![0i64; D]; n_in]; ell_np];
        for ell in 0..ell_np {
            prod_c[ell][0] = ring_mul_bb(&beta[ell], &c[ell][0]);
            prod_x[ell][0] = ring_mul_bb(&beta[ell], &x_in[ell][0]);
        }

        let mut c_star = vec![0i64; D];
        for prod in prod_c.iter().take(ell_np) {
            for j in 0..D {
                c_star[j] =
                    ((c_star[j] as i128 + prod[0][j] as i128).rem_euclid(BB_P as i128)) as i64;
            }
        }
        let mut x_star = vec![0i64; D];
        for prod in prod_x.iter().take(ell_np) {
            for j in 0..D {
                x_star[j] =
                    ((x_star[j] as i128 + prod[0][j] as i128).rem_euclid(BB_P as i128)) as i64;
            }
        }

        // Build z with WRONG c_star (flip first coefficient)
        let mut z = vec![0i64; layout.num_variables];
        z[layout.off_one] = 1;
        c_star[0] = (c_star[0] + 1) % BB_P as i64; // TAMPER
        for j in 0..D {
            z[layout.c_star(0, j)] = c_star[j];
            z[layout.x_star(0, j)] = x_star[j];
        }
        for ell in 0..ell_np {
            for j in 0..D {
                z[layout.beta(ell, j)] = beta[ell][j];
                z[layout.c(ell, 0, j)] = c[ell][0][j];
                z[layout.x_in(ell, 0, j)] = x_in[ell][0][j];
                z[layout.prod_c(ell, 0, j)] = prod_c[ell][0][j];
                z[layout.prod_x(ell, 0, j)] = prod_x[ell][0][j];
            }
        }
        cp_snark::fill_cp_wrap_range_bits(&mut z, &layout);

        assert!(
            !r1cs.is_satisfied_mod(&z, BB_P),
            "CP R1CS should reject tampered folded commitment"
        );
    }

    #[test]
    fn cp_r1cs_rejects_unbounded_phase_a_wrap_forgery() {
        let q_modulus = 257u64;
        let (r1cs, layout) = cp_snark::generate_cp_r1cs(1, 1, 0, 0, -1, q_modulus);

        let mut beta = vec![0i64; D];
        beta[0] = 1;
        let mut c = vec![0i64; D];
        c[0] = 7;
        let prod = ring_mul_bb(&beta, &c);

        let mut z = vec![0i64; layout.num_variables];
        z[layout.off_one] = 1;
        for j in 0..D {
            z[layout.beta(0, j)] = beta[j];
            z[layout.c(0, 0, j)] = c[j];
            z[layout.prod_c(0, 0, j)] = prod[j];
            z[layout.c_star(0, j)] = prod[j];
        }
        cp_snark::fill_cp_wrap_range_bits(&mut z, &layout);
        assert!(r1cs.is_satisfied_mod(&z, BB_P));

        let malicious_wrap = -(1i64 << 24);
        z[layout.c_star(0, 0)] =
            centered_mod_bb(prod[0] as i128 + q_modulus as i128 * malicious_wrap as i128);
        z[layout.sum_wrap_c(0, 0)] = malicious_wrap;
        for wrap_idx in 0..layout.num_wrap_vars {
            for bit in 0..layout.wrap_bits_per_var {
                z[layout.wrap_bit(wrap_idx, bit)] = 0;
            }
        }

        assert!(
            !r1cs.is_satisfied_mod(&z, BB_P),
            "Phase-A range constraints must reject the free-wrap folded commitment forgery"
        );

        assert!(
            -malicious_wrap >= (1i64 << layout.wrap_negative_bits),
            "out-of-range Phase-A wraps must not be witness-encodable"
        );
    }

    #[test]
    fn cp_r1cs_layout_sizes_are_reasonable() {
        let layout = CpR1csLayout::new(2, 2, 1, 4);
        // Instance: 1 (one) + 2*64 (c*) + 1*64 (x*) = 193
        assert_eq!(layout.num_instance, 1 + 2 * D + D);
        // Total vars should include all witness + aux
        assert!(layout.num_variables > layout.num_instance);
    }

    // --- Phase B integration test ---

    /// Extension field multiplication over BabyBear:
    /// (a0 + a1*Y)(b0 + b1*Y) = (a0*b0 + QNR*a1*b1) + (a0*b1 + a1*b0)*Y
    fn ext_mul(a: (i64, i64), b: (i64, i64), qnr: i64) -> (i64, i64) {
        let p = BB_P as i128;
        let c0 =
            ((a.0 as i128 * b.0 as i128 + qnr as i128 * a.1 as i128 * b.1 as i128) % p + p) % p;
        let c1 = ((a.0 as i128 * b.1 as i128 + a.1 as i128 * b.0 as i128) % p + p) % p;
        (c0 as i64, c1 as i64)
    }

    fn ext_add(a: (i64, i64), b: (i64, i64)) -> (i64, i64) {
        let p = BB_P as i128;
        (
            ((a.0 as i128 + b.0 as i128) % p) as i64,
            ((a.1 as i128 + b.1 as i128) % p) as i64,
        )
    }

    fn ext_sub(a: (i64, i64), b: (i64, i64)) -> (i64, i64) {
        let p = BB_P as i128;
        (
            ((a.0 as i128 - b.0 as i128 + p) % p) as i64,
            ((a.1 as i128 - b.1 as i128 + p) % p) as i64,
        )
    }

    fn ext_scale(a: (i64, i64), s: i64) -> (i64, i64) {
        let p = BB_P as i128;
        (
            ((a.0 as i128 * s as i128).rem_euclid(p)) as i64,
            ((a.1 as i128 * s as i128).rem_euclid(p)) as i64,
        )
    }

    /// Fill a K-mul's aux variables in the z-vector: p1, p2, c0, c1
    fn fill_ext_mul_aux(z: &mut [i64], aux_base: usize, a: (i64, i64), b: (i64, i64), qnr: i64) {
        let p = BB_P as i128;
        let p1 = ((a.0 as i128 * b.0 as i128).rem_euclid(p)) as i64;
        let p2 = ((a.1 as i128 * b.1 as i128).rem_euclid(p)) as i64;
        let c = ext_mul(a, b, qnr);
        z[aux_base] = p1;
        z[aux_base + 1] = p2;
        z[aux_base + 2] = c.0;
        z[aux_base + 3] = c.1;
    }

    #[test]
    fn cp_r1cs_phase_b_hadamard_sumcheck_satisfied() {
        // Phase B test: construct a valid degree-3 sumcheck with 2 variables,
        // and verify the full R1CS (Phase A + Phase B) is satisfied.
        let ell_np = 1; // 1 instance for simplicity
        let kappa = 1;
        let n_in = 1;
        let m = 4; // => had_num_vars = 2

        let qnr: i64 = -1;

        let (r1cs, layout) = cp_snark::generate_cp_r1cs(ell_np, kappa, n_in, m, qnr, BB_P);
        let had_nv = layout.had_num_vars;
        assert_eq!(had_nv, 2);

        let mut z = vec![0i64; layout.num_variables];
        z[layout.off_one] = 1;

        // --- Phase A: trivial folding (beta=1, c=c*, x_in=x*) ---
        let beta_val = [1i64, 0, 0, 0]; // constant 1
        let c_val = [3i64, 0, 0, 0]; // constant 3
        let x_val = 5i64;

        // c* = beta * c = 1 * 3 = 3
        z[layout.c_star(0, 0)] = 3;
        z[layout.x_star(0, 0)] = 5;
        for j in 0..D {
            z[layout.beta(0, j)] = if j < 4 { beta_val[j] } else { 0 };
            z[layout.c(0, 0, j)] = if j < 4 { c_val[j] } else { 0 };
        }
        z[layout.x_in(0, 0, 0)] = x_val;

        // prod_c = beta * c (ring mul in BabyBear)
        let prod_c = ring_mul_bb(
            &(0..D)
                .map(|j| if j < 4 { beta_val[j] } else { 0 })
                .collect::<Vec<_>>(),
            &(0..D)
                .map(|j| if j < 4 { c_val[j] } else { 0 })
                .collect::<Vec<_>>(),
        );
        for j in 0..D {
            z[layout.prod_c(0, 0, j)] = prod_c[j];
        }

        let x_ring: Vec<i64> = std::iter::once(x_val)
            .chain(std::iter::repeat(0))
            .take(D)
            .collect();
        let prod_x = ring_mul_bb(
            &(0..D)
                .map(|j| if j < 4 { beta_val[j] } else { 0 })
                .collect::<Vec<_>>(),
            &x_ring,
        );
        for j in 0..D {
            z[layout.prod_x(0, 0, j)] = prod_x[j];
        }

        // --- Phase B: construct a valid Hadamard sumcheck ---
        // We need: claimed_sum = 0, 2 rounds, and a final check.
        // Pick simple challenges and seed.
        let challenges: [(i64, i64); 2] = [(3, 0), (7, 0)]; // simple scalars
        let seed: [(i64, i64); 2] = [(2, 0), (5, 0)];
        let alpha: (i64, i64) = (11, 0);

        // Set challenges and seed in z-vector
        for i in 0..had_nv {
            z[layout.had_challenge(0, i, 0)] = challenges[i].0;
            z[layout.had_challenge(0, i, 1)] = challenges[i].1;
            z[layout.had_seed(0, i, 0)] = seed[i].0;
            z[layout.had_seed(0, i, 1)] = seed[i].1;
        }
        z[layout.had_alpha(0, 0)] = alpha.0;
        z[layout.had_alpha(0, 1)] = alpha.1;

        // Construct evaluation matrix U[3][2][D] and compute the combined sum.
        // Use simple values: U[0,j] = (j+1, 0), U[1,j] = (j+2, 0), U[2,j] = (j+1)*(j+2)
        // so that U[0,j]*U[1,j] - U[2,j] = 0 for all j.
        // This means combined = 0, and eq*combined = 0.
        // So claimed_eval = 0 = claimed_sum. The sumcheck is trivially valid
        // if all round evaluations are zero.
        for j in 0..D {
            let u0 = ((j + 1) as i64, 0i64);
            let u1 = ((j + 2) as i64, 0i64);
            let u2 = ext_mul(u0, u1, qnr); // U[2,j] = U[0,j]*U[1,j]
            z[layout.had_eval_matrix(0, 0, 0, j)] = u0.0;
            z[layout.had_eval_matrix(0, 0, 1, j)] = u0.1;
            z[layout.had_eval_matrix(0, 1, 0, j)] = u1.0;
            z[layout.had_eval_matrix(0, 1, 1, j)] = u1.1;
            z[layout.had_eval_matrix(0, 2, 0, j)] = u2.0;
            z[layout.had_eval_matrix(0, 2, 1, j)] = u2.1;
        }

        // With combined=0 and claimed_eval=0, every sumcheck round must have
        // evals[0]+evals[1]=claim, and the Horner result = claim for next round.
        // Since claim starts at 0 and stays 0 (all evals are zero), this is trivial.
        // All had_eval slots default to 0 which satisfies 0+0=0.

        // But we need to compute the aux variables for the K-muls.
        // The eq evaluation involves s*r products and chain multiplications.
        // With all sumcheck evals = 0, the Horner products are all 0.
        // The eq factors are: f_i = 2*sr - s - r + 1
        //   f_0 = 2*(seed[0]*challenges[1]) - seed[0] - challenges[1] + 1
        //     (note: challenges are reversed for eq evaluation)
        //   r_rev[0] = challenges[1], r_rev[1] = challenges[0]

        let mut aux_idx = 0usize;
        let aux = |idx: usize, sub: usize| layout.had_aux(0, idx, sub);

        // 3 K-muls per round (Horner) — all inputs are 0, so all products are 0.
        for _ in 0..had_nv {
            // 3 K-muls, all zero — aux already initialized to 0.
            aux_idx += 3;
        }

        // eq(s, r_rev) evaluation
        let mut factor_vals: Vec<(i64, i64)> = Vec::new();
        for (i, &si) in seed.iter().enumerate().take(had_nv) {
            let ri = had_nv - 1 - i;
            let ri_val = challenges[ri];
            let sr = ext_mul(si, ri_val, qnr);
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), si, ri_val, qnr);
            aux_idx += 1;

            let f = ext_add(ext_sub(ext_scale(sr, 2), ext_add(si, ri_val)), (1, 0));
            factor_vals.push(f);
        }

        // Chain multiply factors
        let mut eq_val = factor_vals[0];
        for &factor in factor_vals.iter().take(had_nv).skip(1) {
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), eq_val, factor, qnr);
            eq_val = ext_mul(eq_val, factor, qnr);
            aux_idx += 1;
        }

        // U products: D K-muls
        for j in 0..D {
            let u0 = ((j + 1) as i64, 0i64);
            let u1 = ((j + 2) as i64, 0i64);
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), u0, u1, qnr);
            aux_idx += 1;
        }

        // Combined sum: (D-1) alpha*diff muls + (D-2) alpha power muls
        let mut alpha_pow = alpha;
        for j in 1..D {
            let u0 = ((j + 1) as i64, 0i64);
            let u1 = ((j + 2) as i64, 0i64);
            let u2 = ext_mul(u0, u1, qnr);
            let diff = ext_sub(ext_mul(u0, u1, qnr), u2); // = 0
                                                          // alpha^j * diff = alpha^j * 0 = 0
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), alpha_pow, diff, qnr);
            aux_idx += 1;

            if j + 1 < D {
                // alpha^{j+1} = alpha^j * alpha
                fill_ext_mul_aux(&mut z, aux(aux_idx, 0), alpha_pow, alpha, qnr);
                alpha_pow = ext_mul(alpha_pow, alpha, qnr);
                aux_idx += 1;
            }
        }

        // Final: eq_val * combined (combined = 0)
        let combined = (0i64, 0i64);
        fill_ext_mul_aux(&mut z, aux(aux_idx, 0), eq_val, combined, qnr);
        aux_idx += 1;

        let _ = aux_idx;

        cp_snark::fill_cp_wrap_range_bits(&mut z, &layout);

        assert!(
            r1cs.is_satisfied_mod(&z, BB_P),
            "CP R1CS Phase B should be satisfied with valid Hadamard sumcheck"
        );
    }
}

// =========================================================================
// Modular pipeline tests
// =========================================================================
mod modular_pipeline {
    use super::*;
    use symphony::proof_orchestrator::Prover;
    use symphony::snark::{cp_snark, BackendSnark, DummySnark};

    fn small_params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn make_statement<B: BackendSnark>(
        prover: &Prover<B, B>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    #[test]
    fn dummy_end_to_end_prove_verify() {
        let params = small_params();
        let (prover, verifier) = Prover::<DummySnark, DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);

        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn dummy_proof_contains_expected_structure() {
        let params = small_params();
        let (prover, _) = Prover::<DummySnark, DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let proof = prover.prove(&statements, &r1cs);

        assert!(!proof.witness_bundle.fs_commitments.is_empty());
        assert!(!proof.cp_proof.data.is_empty());
        assert!(!proof.output_proof.data.is_empty());
    }

    #[test]
    fn dummy_tampered_cp_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = Prover::<DummySnark, DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);
        proof.cp_proof.data = b"garbage".to_vec();

        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn dummy_tampered_output_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = Prover::<DummySnark, DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);
        proof.output_proof.data = b"garbage".to_vec();

        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn challenge_digest_tampering_changes_cp_instance() {
        let params = small_params();
        let (prover, _) = Prover::<DummySnark, DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let proof = prover.prove(&statements, &r1cs);

        let original_instance = cp_snark::encode_cp_instance_compressed(
            &proof.cp_public_instance.fold_root,
            &proof.cp_public_instance.x_folded,
            &proof.cp_public_instance.challenge_digest,
            &proof.cp_public_instance.fs_root,
            &proof.cp_public_instance.transcript_seed_digest,
        );
        let mut tampered_cd = proof.cp_public_instance.challenge_digest;
        tampered_cd[0] ^= 0xff;
        let tampered_instance = cp_snark::encode_cp_instance_compressed(
            &proof.cp_public_instance.fold_root,
            &proof.cp_public_instance.x_folded,
            &tampered_cd,
            &proof.cp_public_instance.fs_root,
            &proof.cp_public_instance.transcript_seed_digest,
        );

        assert_ne!(original_instance, tampered_instance);
    }
}

// =========================================================================
// Real backend checks through modular orchestrator
// =========================================================================
mod modular_sumcheck_backend {
    use super::*;
    use symphony::proof_orchestrator::Prover;
    use symphony::SumcheckSnark;

    fn params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn make_statement(
        prover: &Prover<SumcheckSnark, SumcheckSnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    #[test]
    fn end_to_end() {
        let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn tampered_cp_rejected() {
        let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);
        proof.cp_proof.witness_commitment[0] ^= 0xFF;

        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn tampered_output_rejected() {
        let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);
        proof.output_proof.witness_commitment[0] ^= 0xFF;

        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn wrong_public_inputs_rejected() {
        let (prover, verifier) = Prover::<SumcheckSnark, SumcheckSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let proof = prover.prove(&statements, &r1cs);

        let wrong_pis = vec![vec![999i64], vec![999i64]];
        assert!(!verifier.verify(&wrong_pis, &proof, &r1cs));
    }
}

#[test]
#[ignore] // slow: validates the direct Spartan typed folded-output path.
fn spartan_typed_output_roundtrip_direct() {
    use symphony::folding::{folded_output_instance_from_proof, folded_output_witness_from_folded};
    use symphony::snark::spartan::{serialize, SpartanSnark};
    use symphony::snark::{BackendSnark, RelationDescription};

    let params = SymphonyParams {
        q: Q,
        d: D,
        kappa: 2,
        ell_np: 2,
        ell_h: D,
        lambda_pj: 4,
        n_bar: 4,
        m: 4,
        b: 16,
        k_cs: 1,
        n_in: 1,
        ntt: SymphonyParams::try_ntt(Q, D),
    };
    let (r1cs, z) = multi_r1cs();
    let n_in = r1cs.num_public;
    let ext_ctx = symphony::ring::extension::ExtFieldContext::new(Q);
    let rp = symphony::rok::range_proof::RangeProofParams {
        lambda_pj: params.lambda_pj,
        ell_h: params.ell_h,
        d_prime: (params.d as i64) - 2,
        k_g: params.k_g(),
        input_bound: params.b_input(),
    };
    let ajtai =
        symphony::commitment::AjtaiParams::setup(params.kappa, params.n(), params.q, params.ntt());

    let s1 = make_statement_raw(&z, n_in, &ajtai);
    let s2 = make_statement_raw(&z, n_in, &ajtai);
    let fold_statements = vec![s1, s2];
    let (folding_proof, folded_witness, _) =
        symphony::folding::prove(&fold_statements, &r1cs, &ajtai, &rp, &ext_ctx);

    let folded_output = folded_output_instance_from_proof(&folding_proof);
    let folded_output_witness = folded_output_witness_from_folded(&folded_witness);
    assert_eq!(
        folded_output.linear_relation.commitment,
        folded_output.folded_instance.commitment
    );
    assert_eq!(
        folded_output.linear_relation.evaluation_values.to_vec(),
        folded_output.folded_instance.evaluation_values
    );

    let ctx = serialize::serialize_context(&serialize::SpartanContext {
        r1cs: r1cs.clone(),
        q: params.q,
        d: params.d,
        n_pub: r1cs.num_public,
        is_output_snark: true,
    });
    let relation = RelationDescription {
        num_instance_vars: params.n(),
        num_witness_vars: params.n(),
        num_constraints: params.m,
        context: Some(ctx),
    };
    let (pk, vk) = SpartanSnark::setup(&relation);

    let proof = SpartanSnark::prove_typed_output(&pk, &folded_output, &folded_output_witness)
        .expect("typed output proof");

    assert!(
        SpartanSnark::verify_typed_output(&vk, &folded_output, &proof).expect("typed verify path")
    );

    let legacy_instance =
        symphony::snark::cp_snark::encode_folded_instance(&folded_output.folded_instance);
    let legacy_witness =
        symphony::snark::cp_snark::encode_folded_witness(&folded_output_witness.folded_witness);
    let legacy_proof = SpartanSnark::prove(&pk, &legacy_instance, &legacy_witness);
    assert!(
        !SpartanSnark::verify_typed_output(&vk, &folded_output, &legacy_proof)
            .expect("typed verify path")
    );

    let mut invalid_relation = folded_output.clone();
    invalid_relation.linear_relation.evaluation_values[0].data[0][0] += 1;
    assert!(
        SpartanSnark::prove_typed_output(&pk, &invalid_relation, &folded_output_witness).is_none()
    );

    let mut invalid_witness = folded_output_witness.clone();
    invalid_witness.folded_witness.witness.elements[0].coeffs[0] += 1;
    assert!(SpartanSnark::prove_typed_output(&pk, &folded_output, &invalid_witness).is_none());

    let mut tampered = folded_output.clone();
    tampered.linear_relation.evaluation_values[0].data[0][0] += 1;
    assert!(!SpartanSnark::verify_typed_output(&vk, &tampered, &proof).expect("typed verify path"));

    let mut missing_summary = proof.clone();
    missing_summary.typed_output_witness_summary = None;
    assert!(
        !SpartanSnark::verify_typed_output(&vk, &folded_output, &missing_summary)
            .expect("typed verify path")
    );

    let mut bad_summary = proof.clone();
    bad_summary
        .typed_output_witness_summary
        .as_mut()
        .expect("summary present")
        .folded_witness_len += 1;
    assert!(
        !SpartanSnark::verify_typed_output(&vk, &folded_output, &bad_summary)
            .expect("typed verify path")
    );
}
mod modular_spartan_backend {
    use super::*;
    use symphony::proof_orchestrator::Prover;
    use symphony::SpartanSnark;

    fn params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn make_statement(
        prover: &Prover<SpartanSnark, SpartanSnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    #[test]
    #[ignore]
    fn end_to_end() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn tampered_cp_witness_rejected() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.witness_commitment +=
            curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&[1u8; 64]);
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn tampered_output_sumcheck_rejected() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        if let Some(round) = proof.output_proof.sumcheck_proof.round_polys.first_mut() {
            if !round.is_empty() {
                round[0] += curve25519_dalek::scalar::Scalar::ONE;
            }
        }
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }
}

#[cfg(feature = "whir")]
mod modular_whir_backend {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use symphony::digest_core::PublicDigestScheme;
    use symphony::folding_core::{FoldSemantics, Statement, SymphonyFoldSemantics};
    use symphony::proof_orchestrator::{ProofBundleV2, Prover, PublicProofBundle, Verifier};
    use symphony::public_proof::PublicProofEnvelope;
    use symphony::snark::cp_snark;
    use symphony::snark::whir::{
        canonical_whir_proof_bytes, whir_proof_from_canonical_bytes, WhirSnark,
    };

    type WhirPublicProof = PublicProofBundle<WhirSnark, WhirSnark>;
    type WhirVerifier = Verifier<WhirSnark, WhirSnark>;

    fn params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 2,
            ell_h: D,
            lambda_pj: 4,
            n_bar: 4,
            m: 4,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn public_params() -> SymphonyParams {
        SymphonyParams {
            q: Q,
            d: D,
            kappa: 2,
            ell_np: 1,
            ell_h: D,
            lambda_pj: 1,
            n_bar: 3,
            m: 1,
            b: 16,
            k_cs: 1,
            n_in: 1,
            ntt: SymphonyParams::try_ntt(Q, D),
        }
    }

    fn public_r1cs() -> (R1CSMatrices, Vec<i64>) {
        let mut r1cs = R1CSMatrices::new(1, 3, 1);
        r1cs.a.insert(0, 1, 1);
        r1cs.b.insert(0, 2, 1);
        r1cs.c.insert(0, 0, 15);
        (r1cs, vec![1, 3, 5])
    }

    fn make_statement(
        prover: &Prover<WhirSnark, WhirSnark>,
        z: &[i64],
        n_in: usize,
    ) -> (Commitment, Vec<i64>, RingVector) {
        let full_ring = RingVector {
            elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
        };
        let (c, _) = prover.commit_witness(&full_ring);
        let witness_part = RingVector {
            elements: z[n_in..]
                .iter()
                .map(|&v| RingElement::from_constant(v))
                .collect(),
        };
        (c, z[..n_in].to_vec(), witness_part)
    }

    fn assert_public_accepts(
        label: &str,
        verifier: &WhirVerifier,
        public_inputs: &[Vec<i64>],
        proof: &WhirPublicProof,
        r1cs: &R1CSMatrices,
    ) {
        assert!(
            verifier.verify_public(public_inputs, proof, r1cs),
            "{label} should verify"
        );
    }

    fn assert_public_rejects(
        label: &str,
        verifier: &WhirVerifier,
        public_inputs: &[Vec<i64>],
        proof: &WhirPublicProof,
        r1cs: &R1CSMatrices,
    ) {
        assert!(
            !verifier.verify_public(public_inputs, proof, r1cs),
            "{label} should reject"
        );
    }

    fn mutate_digest_byte(digest: &mut [u8; 32]) {
        digest[0] ^= 1;
    }

    fn mutate_commitment_byte(fs_commitments: &mut [Vec<u8>]) {
        fs_commitments[0][0] ^= 1;
    }

    fn mutate_folded_output_public_input(proof: &mut WhirPublicProof) {
        proof.folded_output.folded_instance.public_input[0].coeffs[0] += 1;
    }

    fn mutate_folded_output_commitment(proof: &mut WhirPublicProof) {
        proof
            .folded_output
            .folded_instance
            .commitment
            .value
            .elements[0]
            .coeffs[0] += 1;
    }

    fn mutate_folded_output_evaluation(proof: &mut WhirPublicProof) {
        proof.folded_output.folded_instance.evaluation_values[0].data[0][0] += 1;
    }

    fn mutate_whir_proof(proof: &mut symphony::WhirProof) {
        proof.z_eval += p3_baby_bear::BabyBear::ONE;
    }

    fn assert_public_envelope_decodes(
        proof: &WhirPublicProof,
        public_inputs: &[Vec<i64>],
        r1cs: &R1CSMatrices,
    ) {
        let cp_proof_bytes = canonical_whir_proof_bytes(&proof.cp_proof);
        let output_proof_bytes = canonical_whir_proof_bytes(&proof.output_proof);
        let envelope_bytes = proof.canonical_public_envelope_bytes(
            PublicDigestScheme::Poseidon2BabyBear,
            public_inputs,
            r1cs,
            &cp_proof_bytes,
            &output_proof_bytes,
        );
        let envelope =
            PublicProofEnvelope::from_bytes(&envelope_bytes).expect("public envelope decodes");
        assert_eq!(
            envelope.digest_scheme,
            PublicDigestScheme::Poseidon2BabyBear
        );
        assert_eq!(envelope.public_inputs, public_inputs);
        assert_eq!(envelope.r1cs_num_constraints, r1cs.num_constraints);
        assert_eq!(envelope.r1cs_num_variables, r1cs.num_variables);
        assert_eq!(envelope.r1cs_num_public, r1cs.num_public);
        assert_eq!(envelope.fs_commitments, proof.fs_commitments);
        assert_eq!(envelope.fs_root, proof.fs_root);
        assert_eq!(envelope.fold_root, proof.fold_root);
        assert_eq!(envelope.challenge_digest, proof.challenge_digest);
        assert_eq!(
            envelope.transcript_seed_digest,
            proof.transcript_seed_digest
        );
        assert_eq!(envelope.cp_proof_bytes, cp_proof_bytes);
        assert_eq!(envelope.output_proof_bytes, output_proof_bytes);
        assert!(whir_proof_from_canonical_bytes(&envelope.cp_proof_bytes).is_ok());
        assert!(whir_proof_from_canonical_bytes(&envelope.output_proof_bytes).is_ok());
    }

    #[test]
    fn public_verify_whir_whir_succeeds_and_rejects_tampering() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(public_params());
        let (r1cs, z_a) = public_r1cs();
        let z_b = vec![2, 6, 5];
        let n_in = r1cs.num_public;
        let statements_a = vec![make_statement(&prover, &z_a, n_in)];
        let public_inputs_a: Vec<Vec<i64>> = statements_a.iter().map(|s| s.1.clone()).collect();
        let statements_b = vec![make_statement(&prover, &z_b, n_in)];
        let public_inputs_b: Vec<Vec<i64>> = statements_b.iter().map(|s| s.1.clone()).collect();

        let proof_a = prover.prove_public(&statements_a, &r1cs);
        let proof_b = prover.prove_public(&statements_b, &r1cs);
        assert_public_accepts(
            "honest proof A",
            &verifier,
            &public_inputs_a,
            &proof_a,
            &r1cs,
        );
        assert_public_accepts(
            "honest proof B",
            &verifier,
            &public_inputs_b,
            &proof_b,
            &r1cs,
        );
        assert_public_envelope_decodes(&proof_a, &public_inputs_a, &r1cs);

        let ProofBundleV2 {
            cp_proof: _,
            output_proof: _,
            fs_commitments: _,
            folded_output: _,
            fs_root: _,
            fold_root: _,
            challenge_digest: _,
            transcript_seed_digest: _,
        } = proof_a.clone();

        let mut tampered = proof_a.clone();
        mutate_commitment_byte(&mut tampered.fs_commitments);
        assert_public_rejects(
            "flipped FS commitment byte",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.fs_commitments.pop();
        assert_public_rejects(
            "removed FS commitment",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.fs_commitments.push(vec![0u8; 32]);
        assert_public_rejects(
            "appended FS commitment",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_digest_byte(&mut tampered.fs_root);
        assert_public_rejects(
            "flipped fs_root",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_digest_byte(&mut tampered.fold_root);
        assert_public_rejects(
            "flipped fold_root",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_digest_byte(&mut tampered.challenge_digest);
        assert_public_rejects(
            "flipped challenge_digest",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_digest_byte(&mut tampered.transcript_seed_digest);
        assert_public_rejects(
            "flipped transcript_seed_digest",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_folded_output_public_input(&mut tampered);
        assert_public_rejects(
            "mutated folded public input",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_folded_output_commitment(&mut tampered);
        assert_public_rejects(
            "mutated folded commitment coefficient",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_folded_output_evaluation(&mut tampered);
        assert_public_rejects(
            "mutated folded evaluation coordinate",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_whir_proof(&mut tampered.cp_proof);
        assert_public_rejects(
            "mutated CP proof z_eval",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        mutate_whir_proof(&mut tampered.output_proof);
        assert_public_rejects(
            "mutated output proof z_eval",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        assert_public_rejects(
            "proof A with public inputs B",
            &verifier,
            &public_inputs_b,
            &proof_a,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.fs_commitments = proof_b.fs_commitments.clone();
        assert_public_rejects(
            "spliced FS commitments",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.fs_root = proof_b.fs_root;
        tampered.fold_root = proof_b.fold_root;
        tampered.challenge_digest = proof_b.challenge_digest;
        tampered.transcript_seed_digest = proof_b.transcript_seed_digest;
        assert_public_rejects(
            "spliced public digest tuple",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.folded_output = proof_b.folded_output.clone();
        assert_public_rejects(
            "spliced folded output",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.cp_proof = proof_b.cp_proof.clone();
        assert_public_rejects(
            "spliced CP proof",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        let mut tampered = proof_a.clone();
        tampered.output_proof = proof_b.output_proof.clone();
        assert_public_rejects(
            "spliced output proof",
            &verifier,
            &public_inputs_a,
            &tampered,
            &r1cs,
        );

        assert_public_rejects("empty public inputs", &verifier, &[], &proof_a, &r1cs);

        let mut too_many_public_inputs = public_inputs_a.clone();
        too_many_public_inputs.push(public_inputs_b[0].clone());
        assert_public_rejects(
            "too many public input vectors",
            &verifier,
            &too_many_public_inputs,
            &proof_a,
            &r1cs,
        );

        let empty_arity_public_inputs = vec![vec![]];
        assert_public_rejects(
            "empty public input vector",
            &verifier,
            &empty_arity_public_inputs,
            &proof_a,
            &r1cs,
        );

        let extra_arity_public_inputs = vec![vec![public_inputs_a[0][0], 99]];
        assert_public_rejects(
            "extra public input value",
            &verifier,
            &extra_arity_public_inputs,
            &proof_a,
            &r1cs,
        );

        let mut wrong_public_arity_r1cs = r1cs.clone();
        wrong_public_arity_r1cs.num_public += 1;
        assert_public_rejects(
            "wrong R1CS public arity",
            &verifier,
            &public_inputs_a,
            &proof_a,
            &wrong_public_arity_r1cs,
        );

        let mut wrong_dimensions_r1cs = r1cs.clone();
        wrong_dimensions_r1cs.num_variables += 1;
        assert_public_rejects(
            "wrong R1CS dimensions",
            &verifier,
            &public_inputs_a,
            &proof_a,
            &wrong_dimensions_r1cs,
        );

        let mut changed_coefficients_r1cs = r1cs.clone();
        changed_coefficients_r1cs.c.entries.clear();
        changed_coefficients_r1cs.c.insert(0, 0, 14);
        assert_public_rejects(
            "same dimensions with changed constraint coefficient",
            &verifier,
            &public_inputs_a,
            &proof_a,
            &changed_coefficients_r1cs,
        );

        let mut wrong_ell_params = public_params();
        wrong_ell_params.ell_np = 2;
        let (_, wrong_ell_verifier) = Prover::<WhirSnark, WhirSnark>::setup(wrong_ell_params);
        assert_public_rejects(
            "verifier configured for wrong ell_np",
            &wrong_ell_verifier,
            &public_inputs_a,
            &proof_a,
            &r1cs,
        );
    }

    #[test]
    fn public_verify_multi_statement() {
        let mut params = public_params();
        params.ell_np = 2;
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params.clone());
        let (r1cs, z_a) = public_r1cs();
        let z_b = vec![2, 6, 5];
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z_a, n_in),
            make_statement(&prover, &z_b, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let full_proof = prover.prove(&statements, &r1cs);
        let proof = full_proof.to_v2();

        if let Err(stage) = verifier.verify_public_attribution(&public_inputs, &proof, &r1cs) {
            let ext_ctx = symphony::ring::extension::ExtFieldContext::new(params.q);
            let (cp_r1cs, cp_layout) = cp_snark::generate_cp_r1cs(
                params.ell_np,
                params.kappa,
                params.n_in,
                params.m,
                ext_ctx.alpha,
                params.q,
            );
            let lengths = cp_snark::typed_cp_digest_input_lengths_from_setup(
                params.ell_np,
                params.kappa,
                params.n_in,
                params.lambda_pj,
                params.ell_h,
                params.k_g(),
                &r1cs,
            )
            .expect("typed CP lengths");
            let (typed_r1cs, layout, audit) = cp_snark::generate_typed_cp_digest_r1cs_with_audit(
                &cp_r1cs,
                &cp_layout,
                &prover.ajtai,
                &r1cs,
                &lengths,
            );
            let statement = proof.cp_public_statement(
                &public_inputs,
                &r1cs,
                symphony::digest_core::PublicDigestScheme::Poseidon2BabyBear,
            );
            let instance = cp_snark::encode_typed_cp_digest_instance(
                &statement,
                &proof.fs_commitments,
                &layout,
            )
            .expect("typed CP instance");
            let cp_ntt = Some(symphony::ring::ntt::NttContext::new(params.q));
            let witness_bytes = cp_snark::encode_typed_cp_digest_witness(
                &statement,
                &full_proof.witness_bundle,
                &layout,
                &cp_ntt,
                ext_ctx.alpha,
                params.q,
                &prover.ajtai,
                &r1cs,
            )
            .expect("typed CP witness");
            let z = instance
                .chunks_exact(8)
                .chain(witness_bytes.chunks_exact(8))
                .map(|chunk| i64::from_le_bytes(chunk.try_into().expect("8-byte chunk")))
                .collect::<Vec<_>>();
            let blocks = audit.unsatisfied_blocks(&typed_r1cs, &z, 2_013_265_921);
            let first_row = if typed_r1cs.is_satisfied_mod(&z, 2_013_265_921) {
                None
            } else {
                let az = typed_r1cs.a.mul_vec_mod(&z, 2_013_265_921);
                let bz = typed_r1cs.b.mul_vec_mod(&z, 2_013_265_921);
                let cz = typed_r1cs.c.mul_vec_mod(&z, 2_013_265_921);
                (0..typed_r1cs.num_constraints).find_map(|row| {
                    let lhs = symphony::ring::arith::centered_mod(
                        az[row] as i128 * bz[row] as i128,
                        2_013_265_921,
                    );
                    (lhs != cz[row]).then_some((
                        row,
                        lhs,
                        cz[row],
                        audit.block_for_row(row).cloned(),
                    ))
                })
            };
            panic!(
                "multi-statement WHIR public proof rejected at {stage:?}; unsatisfied_blocks={blocks:?}; first_row={first_row:?}"
            );
        }
        assert_public_accepts(
            "multi-statement public proof",
            &verifier,
            &public_inputs,
            &proof,
            &r1cs,
        );
    }

    #[test]
    fn cp_backend_roundtrip_on_encoded_cp_instance() {
        let params = params();
        let (prover, _verifier) = Prover::<WhirSnark, WhirSnark>::setup(params.clone());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];

        let rp = symphony::rok::range_proof::RangeProofParams {
            lambda_pj: params.lambda_pj,
            ell_h: params.ell_h,
            d_prime: (params.d as i64) - 2,
            k_g: params.k_g(),
            input_bound: params.b_input(),
        };
        let ext_ctx = symphony::ring::extension::ExtFieldContext::new(params.q);

        let fold_statements: Vec<Statement> = statements
            .iter()
            .map(|(c, pi, w)| Statement {
                commitment: c.clone(),
                public_input: pi.clone(),
                witness: w.clone(),
            })
            .collect();

        let semantics = SymphonyFoldSemantics;
        let (folding_proof, _folded_witness, shared_challenges) =
            semantics.fold(&fold_statements, &r1cs, &prover.ajtai, &rp, &ext_ctx);

        let (cp_r1cs, cp_layout) = cp_snark::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            params.m,
            ext_ctx.alpha,
            params.q,
        );
        let cp_context = cp_snark::serialize_cp_context(&cp_r1cs, params.q, params.d as usize);
        let cp_relation = symphony::snark::RelationDescription {
            num_instance_vars: cp_layout.num_instance,
            num_witness_vars: cp_layout.num_variables - cp_layout.num_instance,
            num_constraints: cp_r1cs.num_constraints,
            context: Some(cp_context),
        };

        let cp_public_instance = symphony::cp_relation_core::CpPublicInstance {
            fs_root: [0u8; 32],
            fold_root: [0u8; 32],
            challenge_digest: [0u8; 32],
            transcript_seed_digest: [0u8; 32],
            x_folded: folding_proof.folded_instance.clone(),
            folded_output: symphony::folding::folded_output_instance_from_proof(&folding_proof),
        };
        let cp_instance = symphony::proof_orchestrator::encode_cp_backend_instance(
            &cp_public_instance,
            &cp_layout,
        );

        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let commitments_for_cp: Vec<_> = folding_proof.commitments.clone();
        let cp_ntt = Some(symphony::ring::ntt::NttContext::new(2013265921));
        let cp_witness = cp_snark::encode_cp_witness_r1cs(
            &commitments_for_cp,
            &public_inputs,
            &folding_proof.beta,
            &folding_proof.folded_instance,
            &cp_layout,
            &cp_ntt,
            &folding_proof.gr1cs_proofs,
            &shared_challenges.sumcheck_seed_had,
            &shared_challenges.alpha,
            &shared_challenges.hadamard_sumcheck_challenges,
            ext_ctx.alpha,
            params.q,
        );

        use symphony::snark::BackendSnark;
        let (pk, vk) = WhirSnark::setup(&cp_relation);
        let cp_proof = WhirSnark::prove(&pk, &cp_instance, &cp_witness);
        assert!(WhirSnark::verify(&vk, &cp_instance, &cp_proof));
    }

    #[test]
    fn cp_witness_satisfies_cp_r1cs_in_modular_whir_path() {
        let params = params();
        let (prover, _verifier) = Prover::<WhirSnark, WhirSnark>::setup(params.clone());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = [
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];

        let rp = symphony::rok::range_proof::RangeProofParams {
            lambda_pj: params.lambda_pj,
            ell_h: params.ell_h,
            d_prime: (params.d as i64) - 2,
            k_g: params.k_g(),
            input_bound: params.b_input(),
        };
        let ext_ctx = symphony::ring::extension::ExtFieldContext::new(params.q);

        let fold_statements: Vec<Statement> = statements
            .iter()
            .map(|(c, pi, w)| Statement {
                commitment: c.clone(),
                public_input: pi.clone(),
                witness: w.clone(),
            })
            .collect();

        let semantics = SymphonyFoldSemantics;
        let (folding_proof, _folded_witness, shared_challenges) =
            semantics.fold(&fold_statements, &r1cs, &prover.ajtai, &rp, &ext_ctx);

        let (cp_r1cs, cp_layout) = cp_snark::generate_cp_r1cs(
            params.ell_np,
            params.kappa,
            params.n_in,
            params.m,
            ext_ctx.alpha,
            params.q,
        );

        let cp_public_instance = symphony::cp_relation_core::CpPublicInstance {
            fs_root: [0u8; 32],
            fold_root: [0u8; 32],
            challenge_digest: [0u8; 32],
            transcript_seed_digest: [0u8; 32],
            x_folded: folding_proof.folded_instance.clone(),
            folded_output: symphony::folding::folded_output_instance_from_proof(&folding_proof),
        };

        let cp_instance = symphony::proof_orchestrator::encode_cp_backend_instance(
            &cp_public_instance,
            &cp_layout,
        );

        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let commitments_for_cp: Vec<_> = folding_proof.commitments.clone();
        let cp_ntt = Some(symphony::ring::ntt::NttContext::new(2013265921));
        let cp_witness = cp_snark::encode_cp_witness_r1cs(
            &commitments_for_cp,
            &public_inputs,
            &folding_proof.beta,
            &folding_proof.folded_instance,
            &cp_layout,
            &cp_ntt,
            &folding_proof.gr1cs_proofs,
            &shared_challenges.sumcheck_seed_had,
            &shared_challenges.alpha,
            &shared_challenges.hadamard_sumcheck_challenges,
            ext_ctx.alpha,
            params.q,
        );

        // Reconstruct full assignment z = instance_prefix || witness.
        let mut z_full = vec![0i64; cp_layout.num_variables];
        for (i, chunk) in cp_instance[..(cp_layout.num_instance * 8)]
            .chunks_exact(8)
            .enumerate()
        {
            z_full[i] = i64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        for (i, chunk) in cp_witness.chunks_exact(8).enumerate() {
            z_full[cp_layout.num_instance + i] =
                i64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }

        if !cp_r1cs.is_satisfied_mod(&z_full, 2013265921) {
            let az = cp_r1cs.a.mul_vec_mod(&z_full, 2013265921);
            let bz = cp_r1cs.b.mul_vec_mod(&z_full, 2013265921);
            let cz = cp_r1cs.c.mul_vec_mod(&z_full, 2013265921);

            // Extra diagnostics for first product block.
            let d = cp_layout.d;
            let mut beta0 = vec![0i64; d];
            let mut c00 = vec![0i64; d];
            let mut prod00 = vec![0i64; d];
            for j in 0..d {
                beta0[j] = z_full[cp_layout.beta(0, j)];
                c00[j] = z_full[cp_layout.c(0, 0, j)];
                prod00[j] = z_full[cp_layout.prod_c(0, 0, j)];
            }
            let p = 2013265921i128;
            let mut exp = vec![0i64; d];
            for (i, &beta_i) in beta0.iter().enumerate().take(d) {
                for (j, &c_j) in c00.iter().enumerate().take(d) {
                    let prod = beta_i as i128 * c_j as i128;
                    let idx = i + j;
                    if idx < d {
                        exp[idx] = ((exp[idx] as i128 + prod).rem_euclid(p)) as i64;
                    } else {
                        exp[idx - d] = ((exp[idx - d] as i128 - prod).rem_euclid(p)) as i64;
                    }
                }
            }

            if let Some((row, (&a, (&b, &c)))) = az
                .iter()
                .zip(bz.iter().zip(cz.iter()))
                .enumerate()
                .find(|(_, (&a, (&b, &c)))| {
                    let lhs =
                        symphony::ring::arith::centered_mod(a as i128 * b as i128, 2013265921);
                    lhs != c
                })
            {
                let lhs = symphony::ring::arith::centered_mod(a as i128 * b as i128, 2013265921);
                let phase_a_rows = params.ell_np * (params.kappa + params.n_in) * params.d as usize
                    + (params.kappa + params.n_in) * params.d as usize;
                let phase = if row < phase_a_rows {
                    "phase-a"
                } else {
                    "phase-b"
                };
                panic!(
                    "Modular+WHIR CP witness does not satisfy generated CP-R1CS: first_row={row} ({phase}) az={a} bz={b} lhs={lhs} cz={c}; beta0[:4]={:?} c00[:4]={:?} prod00[:4]={:?} exp[:4]={:?}"
                    , &beta0[..4], &c00[..4], &prod00[..4], &exp[..4]
                );
            } else {
                panic!("Modular+WHIR CP witness does not satisfy generated CP-R1CS: no first row");
            }
        }
    }

    #[test]
    #[ignore]
    fn end_to_end() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn tampered_cp_rejected() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.z_eval += p3_baby_bear::BabyBear::ONE;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore]
    fn tampered_output_rejected() {
        let (prover, verifier) = Prover::<WhirSnark, WhirSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
            make_statement(&prover, &z, n_in),
            make_statement(&prover, &z, n_in),
        ];
        let public_inputs: Vec<Vec<i64>> = statements.iter().map(|s| s.1.clone()).collect();
        let mut proof = prover.prove(&statements, &r1cs);

        proof.output_proof.evaluations[0] += p3_baby_bear::BabyBear::ONE;
        assert!(!verifier.verify(&public_inputs, &proof, &r1cs));
    }
}
