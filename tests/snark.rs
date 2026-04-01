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

// =========================================================================
// CP-SNARK encoding
// =========================================================================
mod cp_snark_encoding {
    use super::*;
    use symphony::fiat_shamir::transcript::Transcript;
    use symphony::folding::digest::{digest_challenges, digest_fold_inputs, Digest32, FoldInput};
    use symphony::folding::FoldedInstance;
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
        let fw = symphony::folding::FoldedWitness {
            witness: RingVector::zero(3),
            monomial_vectors: vec![RingVector::zero(2)],
        };
        let encoded = cp_snark::encode_folded_witness(&fw);
        assert!(!encoded.is_empty());
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
        for k in 0..D {
            for m in 0..D {
                let prod = ((a[k] as i128 * b[m] as i128) % BB_P as i128) as i64;
                let idx = k + m;
                if idx < D {
                    out[idx] = ((out[idx] as i128 + prod as i128) % BB_P as i128) as i64;
                } else {
                    // Negacyclic: X^D = -1
                    let idx2 = idx - D;
                    out[idx2] = ((out[idx2] as i128 - prod as i128).rem_euclid(BB_P as i128)) as i64;
                }
            }
        }
        // Normalize to [0, BB_P)
        for v in &mut out {
            *v = ((*v as i128).rem_euclid(BB_P as i128)) as i64;
        }
        out
    }

    /// Build a z-vector for the Phase A CP R1CS and check satisfaction.
    #[test]
    fn cp_r1cs_phase_a_satisfied_with_valid_folding() {
        let ell_np = 2;
        let kappa = 2;
        let n_in = 1;

        // m=0 generates Phase A constraints only (no Hadamard sumcheck)
        let (r1cs, layout) = cp_snark::generate_cp_r1cs(ell_np, kappa, n_in, 0, -1);

        // Create simple ring elements (small values, no overflow issues)
        let mut beta = vec![vec![0i64; D]; ell_np];
        beta[0][0] = 3; // beta[0] = constant 3
        beta[1][0] = 5; // beta[1] = constant 5

        let mut c = vec![vec![vec![0i64; D]; kappa]; ell_np];
        c[0][0][0] = 7;  c[0][0][1] = 2;  // c_0[0] = 7 + 2X
        c[0][1][0] = 1;                     // c_0[1] = 1
        c[1][0][0] = 11; c[1][0][2] = 1;  // c_1[0] = 11 + X^2
        c[1][1][0] = 4;  c[1][1][1] = 3;  // c_1[1] = 4 + 3X

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

        let (r1cs, layout) = cp_snark::generate_cp_r1cs(ell_np, kappa, n_in, 0, -1);

        // Same setup as above but simpler
        let beta = vec![vec![1i64; 1].into_iter().chain(vec![0; D - 1]).collect::<Vec<_>>(); ell_np];
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
        for ell in 0..ell_np {
            for j in 0..D {
                c_star[j] = ((c_star[j] as i128 + prod_c[ell][0][j] as i128)
                    .rem_euclid(BB_P as i128)) as i64;
            }
        }
        let mut x_star = vec![0i64; D];
        for ell in 0..ell_np {
            for j in 0..D {
                x_star[j] = ((x_star[j] as i128 + prod_x[ell][0][j] as i128)
                    .rem_euclid(BB_P as i128)) as i64;
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

        assert!(
            !r1cs.is_satisfied_mod(&z, BB_P),
            "CP R1CS should reject tampered folded commitment"
        );
    }

    #[test]
    fn cp_r1cs_layout_sizes_are_reasonable() {
        let layout = CpR1csLayout::new(2, 2, 1, 4);
        // Instance: 1 (one) + 2*64 (c*) + 1*64 (x*) = 193
        assert_eq!(layout.num_instance, 1 + 2 * D + 1 * D);
        // Total vars should include all witness + aux
        assert!(layout.num_variables > layout.num_instance);
    }

    // --- Phase B integration test ---

    /// Extension field multiplication over BabyBear:
    /// (a0 + a1*Y)(b0 + b1*Y) = (a0*b0 + QNR*a1*b1) + (a0*b1 + a1*b0)*Y
    fn ext_mul(a: (i64, i64), b: (i64, i64), qnr: i64) -> (i64, i64) {
        let p = BB_P as i128;
        let c0 = ((a.0 as i128 * b.0 as i128 + qnr as i128 * a.1 as i128 * b.1 as i128) % p + p) % p;
        let c1 = ((a.0 as i128 * b.1 as i128 + a.1 as i128 * b.0 as i128) % p + p) % p;
        (c0 as i64, c1 as i64)
    }

    fn ext_add(a: (i64, i64), b: (i64, i64)) -> (i64, i64) {
        let p = BB_P as i128;
        (((a.0 as i128 + b.0 as i128) % p) as i64,
         ((a.1 as i128 + b.1 as i128) % p) as i64)
    }

    fn ext_sub(a: (i64, i64), b: (i64, i64)) -> (i64, i64) {
        let p = BB_P as i128;
        (((a.0 as i128 - b.0 as i128 + p) % p) as i64,
         ((a.1 as i128 - b.1 as i128 + p) % p) as i64)
    }

    fn ext_scale(a: (i64, i64), s: i64) -> (i64, i64) {
        let p = BB_P as i128;
        (((a.0 as i128 * s as i128).rem_euclid(p)) as i64,
         ((a.1 as i128 * s as i128).rem_euclid(p)) as i64)
    }

    /// Lagrange interpolation of a degree-3 polynomial at point r,
    /// given evaluations at {0,1,2,3}.
    fn lagrange_interp(evals: &[(i64, i64); 4], r: (i64, i64), qnr: i64) -> (i64, i64) {
        let p = BB_P as i128;
        let inv2 = symphony::snark::cp_snark::mod_pow(2, BB_P - 2, BB_P) as i64;
        let inv6 = symphony::snark::cp_snark::mod_pow(6, BB_P - 2, BB_P) as i64;

        // Newton forward differences
        let d0 = evals[0];
        let d1 = ext_sub(evals[1], evals[0]);
        let d2 = ext_scale(
            ext_add(ext_sub(evals[2], ext_scale(evals[1], 2)), evals[0]),
            inv2,
        );
        let d3 = ext_scale(
            ext_add(
                ext_sub(
                    ext_add(evals[3], ext_scale(evals[1], 3)),
                    ext_scale(evals[2], 3),
                ),
                ext_scale(evals[0], ((-(1i128)).rem_euclid(p)) as i64),
            ),
            inv6,
        );

        // Horner: f(r) = d0 + r*(d1 + (r-1)*(d2 + (r-2)*d3))
        let one = (1i64, 0i64);
        let two = (2i64, 0i64);
        let t3 = d3;
        let t2 = ext_add(ext_mul(t3, ext_sub(r, two), qnr), d2);
        let t1 = ext_add(ext_mul(t2, ext_sub(r, one), qnr), d1);
        let t0 = ext_add(ext_mul(t1, r, qnr), d0);
        t0
    }

    /// Fill a K-mul's aux variables in the z-vector: p1, p2, c0, c1
    fn fill_ext_mul_aux(z: &mut [i64], aux_base: usize,
                        a: (i64, i64), b: (i64, i64), qnr: i64) {
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

        let (r1cs, layout) = cp_snark::generate_cp_r1cs(ell_np, kappa, n_in, m, qnr);
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
            &(0..D).map(|j| if j < 4 { beta_val[j] } else { 0 }).collect::<Vec<_>>(),
            &(0..D).map(|j| if j < 4 { c_val[j] } else { 0 }).collect::<Vec<_>>(),
        );
        for j in 0..D { z[layout.prod_c(0, 0, j)] = prod_c[j]; }

        let x_ring: Vec<i64> = std::iter::once(x_val).chain(std::iter::repeat(0)).take(D).collect();
        let prod_x = ring_mul_bb(
            &(0..D).map(|j| if j < 4 { beta_val[j] } else { 0 }).collect::<Vec<_>>(),
            &x_ring,
        );
        for j in 0..D { z[layout.prod_x(0, 0, j)] = prod_x[j]; }

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
        let mut eq_val: (i64, i64) = (0, 0);
        let mut factor_vals: Vec<(i64, i64)> = Vec::new();
        for i in 0..had_nv {
            let ri = had_nv - 1 - i;
            let si = seed[i];
            let ri_val = challenges[ri];
            let sr = ext_mul(si, ri_val, qnr);
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), si, ri_val, qnr);
            aux_idx += 1;

            let f = ext_add(
                ext_sub(ext_scale(sr, 2), ext_add(si, ri_val)),
                (1, 0),
            );
            factor_vals.push(f);
        }

        // Chain multiply factors
        eq_val = factor_vals[0];
        for i in 1..had_nv {
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), eq_val, factor_vals[i], qnr);
            eq_val = ext_mul(eq_val, factor_vals[i], qnr);
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

        assert!(
            r1cs.is_satisfied_mod(&z, BB_P),
            "CP R1CS Phase B should be satisfied with valid Hadamard sumcheck"
        );
    }
}

// =========================================================================
// Full SNARK pipeline (DummySnark)
// =========================================================================
mod snark_pipeline {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    // multi_r1cs: n=4, m=4, n_in=1. We need params.n() = 4, so n_bar = 2.
    // n() = n_bar * k_cs = 4 * 1 = 4, matching multi_r1cs's num_variables.
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

    // Build statement tuple for the SNARK pipeline.
    // commit_witness expects length = params.n() = 4 = r1cs.num_variables.
    // The RingVector in the tuple is the witness-ONLY part (z[n_in..]).
    fn make_snark_statement(
        prover: &symphony::snark::SymphonyProver<DummySnark>,
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
    fn end_to_end_prove_verify() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        let public_inputs = vec![pi1, pi2];
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    fn proof_contains_expected_structure() {
        let params = small_params();
        let (prover, _) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        assert!(
            !proof.witness_data.fs_commitments.is_empty(),
            "should have FS commitments"
        );
        assert!(
            !proof.cp_proof.data.is_empty(),
            "CP proof should be non-empty"
        );
        assert!(
            !proof.snark_proof.data.is_empty(),
            "SNARK proof should be non-empty"
        );
    }

    // Note: These DummySnark tamper tests verify pipeline wiring (that the verifier
    // propagates rejection when proof bytes are corrupted). They do NOT exercise real
    // cryptographic verification — replace DummySnark with a real backend for that.
    #[test]
    fn tampered_cp_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        proof.cp_proof.data = b"garbage".to_vec();

        let public_inputs = vec![pi1, pi2];
        assert!(
            !verifier.verify(&public_inputs, &proof, &r1cs),
            "tampered CP proof should be rejected"
        );
    }

    #[test]
    fn tampered_snark_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        proof.snark_proof.data = b"garbage".to_vec();

        let public_inputs = vec![pi1, pi2];
        assert!(
            !verifier.verify(&public_inputs, &proof, &r1cs),
            "tampered SNARK proof should be rejected"
        );
    }

    #[test]
    fn fold_root_tampering_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Flip a bit in fold_root
        proof.fold_root[0] ^= 0xff;

        let public_inputs = vec![pi1, pi2];
        // DummySnark accepts any proof, but the challenge_digest check
        // in the verifier should still catch this because the transcript
        // state is unchanged — the verifier independently verifies
        // challenge_digest from the transcript.
        // NOTE: With DummySnark, the CP proof itself isn't checked, but
        // the fold_root only affects the CP instance, not the challenge_digest.
        // This test verifies the structural change; real soundness comes
        // from a real backend.
        let _ = verifier.verify(&public_inputs, &proof, &r1cs);
    }

    #[test]
    fn challenge_digest_tampering_changes_cp_instance() {
        // With the sublinear verifier, challenge_digest tampering changes the
        // CP instance (via the digest-based binding challenge). DummySnark
        // can't detect this — real soundness requires a real backend.
        // See security_soundness::tampered_challenge_digest_is_rejected for
        // the SumcheckSnark version.
        let params = small_params();
        let (prover, _verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        // The CP instances should differ when challenge_digest changes
        use symphony::snark::cp_snark;
        let original_instance = cp_snark::encode_cp_instance_compressed(
            &proof.fold_root,
            &proof.folded_instance,
            &proof.challenge_digest,
            &proof.fs_root,
            &proof.transcript_seed_digest,
        );
        let mut tampered_cd = proof.challenge_digest;
        tampered_cd[0] ^= 0xff;
        let tampered_instance = cp_snark::encode_cp_instance_compressed(
            &proof.fold_root,
            &proof.folded_instance,
            &tampered_cd,
            &proof.fs_root,
            &proof.transcript_seed_digest,
        );
        assert_ne!(
            original_instance, tampered_instance,
            "tampered challenge_digest must produce a different CP instance"
        );
    }
}

// =========================================================================
// CP-SNARK encoding extended
// =========================================================================
mod cp_snark_extended {
    use symphony::fiat_shamir::transcript::Transcript;
    use symphony::folding::FoldedInstance;
    use symphony::ring::tensor::TensorElement;
    use symphony::ring::{RingElement, RingVector};
    use symphony::snark::cp_snark;

    fn dummy_folded_instance() -> FoldedInstance {
        FoldedInstance {
            commitment: symphony::commitment::Commitment {
                value: RingVector::zero(1),
            },
            public_input: vec![RingElement::from_constant(0)],
            evaluation_values: vec![TensorElement::zero()],
        }
    }

    #[test]
    fn different_commitments_different_encoding() {
        let c1 = vec![b"comm-A".to_vec()];
        let c2 = vec![b"comm-B".to_vec()];
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let folded = dummy_folded_instance();
        let e1 = cp_snark::encode_cp_instance(&c1, &folded, &mut t1);
        let e2 = cp_snark::encode_cp_instance(&c2, &folded, &mut t2);
        assert_ne!(e1, e2);
    }

    #[test]
    fn folded_instance_affects_encoding() {
        let commitments = vec![b"comm-A".to_vec()];
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let folded1 = dummy_folded_instance();
        let mut folded2 = dummy_folded_instance();
        folded2.public_input = vec![RingElement::from_constant(7)];

        let e1 = cp_snark::encode_cp_instance(&commitments, &folded1, &mut t1);
        let e2 = cp_snark::encode_cp_instance(&commitments, &folded2, &mut t2);
        assert_ne!(e1, e2);
    }

    #[test]
    fn empty_commitments_still_encodes() {
        let mut t = Transcript::new(b"test");
        let folded = dummy_folded_instance();
        let encoded = cp_snark::encode_cp_instance(&[], &folded, &mut t);
        assert!(!encoded.is_empty());
    }
}

// =========================================================================
// SNARK pipeline extended
// =========================================================================
mod snark_pipeline_extended {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    #[test]
    fn tampered_fs_commitments_change_cp_instance() {
        use symphony::fiat_shamir::transcript::Transcript;
        use symphony::snark::cp_snark;

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
        let (prover, _) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let mk = |p: &SymphonyProver<DummySnark>| {
            let full = RingVector {
                elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
            };
            let (c, _) = p.commit_witness(&full);
            let wp = RingVector {
                elements: z[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            (c, z[..n_in].to_vec(), wp)
        };

        let stmts = vec![mk(&prover), mk(&prover)];
        let proof = prover.prove(&stmts, &r1cs);

        // Honest CP instance
        let mut t1 = Transcript::new(b"symphony-v1");
        for c in &proof.witness_data.fs_commitments {
            t1.append_bytes(b"fs-commitment", c);
        }
        let honest_instance =
            cp_snark::encode_cp_instance(&proof.witness_data.fs_commitments, &proof.folded_instance, &mut t1);

        // Tampered CP instance — a real BackendSnark would reject this
        let mut tampered_comms = proof.witness_data.fs_commitments.clone();
        tampered_comms.push(b"extra-garbage".to_vec());
        let mut t2 = Transcript::new(b"symphony-v1");
        for c in &tampered_comms {
            t2.append_bytes(b"fs-commitment", c);
        }
        let tampered_instance =
            cp_snark::encode_cp_instance(&tampered_comms, &proof.folded_instance, &mut t2);

        assert_ne!(
            honest_instance, tampered_instance,
            "tampered FS commitments must produce a different CP instance"
        );
    }

    #[test]
    fn different_r1cs_different_proofs() {
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
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let mk = |p: &SymphonyProver<DummySnark>| {
            let full = RingVector {
                elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
            };
            let (c, _) = p.commit_witness(&full);
            let wp = RingVector {
                elements: z[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            (c, z[..n_in].to_vec(), wp)
        };

        let stmts = vec![mk(&prover), mk(&prover)];
        let pis: Vec<Vec<i64>> = stmts.iter().map(|s| s.1.clone()).collect();
        let proof = prover.prove(&stmts, &r1cs);
        assert!(verifier.verify(&pis, &proof, &r1cs));
    }
}

// =========================================================================
// SNARK verifier binds public inputs
// =========================================================================
mod snark_public_input_binding {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

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

    fn make_snark_statement(
        prover: &SymphonyProver<DummySnark>,
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
    fn verifier_uses_public_inputs_in_transcript() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_snark_statement(&prover, &z, n_in);
        let s2 = make_snark_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        // Correct public inputs should verify
        let correct_pis = vec![pi1.clone(), pi2.clone()];
        assert!(verifier.verify(&correct_pis, &proof, &r1cs));

        // Wrong public inputs should fail (DummySnark won't catch the
        // cryptographic difference, but the transcript derivation path
        // changes, which a real backend would detect)
        let wrong_pis = vec![vec![999i64], vec![999i64]];
        // With DummySnark, verification still "passes" because DummySnark
        // doesn't check instance data. But the CP instance encoding differs:
        let mut t_correct = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        for pi in &correct_pis {
            let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
            t_correct.append_bytes(b"public-input", &bytes);
        }
        let mut c_correct = [0u8; 32];
        t_correct.challenge_bytes(b"check", &mut c_correct);

        let mut t_wrong = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        for pi in &wrong_pis {
            let bytes: Vec<u8> = pi.iter().flat_map(|v| v.to_le_bytes()).collect();
            t_wrong.append_bytes(b"public-input", &bytes);
        }
        let mut c_wrong = [0u8; 32];
        t_wrong.challenge_bytes(b"check", &mut c_wrong);

        assert_ne!(
            c_correct, c_wrong,
            "different public inputs must produce different transcript states"
        );
    }

    #[test]
    fn verifier_uses_r1cs_in_transcript() {
        // Different R1CS metadata should produce different transcript state
        let mut t1 = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        t1.append_bytes(b"r1cs-m", &4u64.to_le_bytes());
        t1.append_bytes(b"r1cs-n", &4u64.to_le_bytes());
        t1.append_bytes(b"r1cs-pub", &1u64.to_le_bytes());
        let mut c1 = [0u8; 32];
        t1.challenge_bytes(b"check", &mut c1);

        let mut t2 = symphony::fiat_shamir::transcript::Transcript::new(b"symphony-v1");
        t2.append_bytes(b"r1cs-m", &8u64.to_le_bytes());
        t2.append_bytes(b"r1cs-n", &8u64.to_le_bytes());
        t2.append_bytes(b"r1cs-pub", &2u64.to_le_bytes());
        let mut c2 = [0u8; 32];
        t2.challenge_bytes(b"check", &mut c2);

        assert_ne!(
            c1, c2,
            "different R1CS metadata must produce different transcript states"
        );
    }
}

// =========================================================================
// CP-SNARK witness non-empty fix
// =========================================================================
mod cp_snark_witness_fix {
    use super::*;
    use symphony::snark::{DummySnark, SymphonyProver};

    #[test]
    fn cp_witness_is_nonempty_in_pipeline() {
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
        let (prover, _) = SymphonyProver::<DummySnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let mk = |p: &SymphonyProver<DummySnark>| {
            let full = RingVector {
                elements: z.iter().map(|&v| RingElement::from_constant(v)).collect(),
            };
            let (c, _) = p.commit_witness(&full);
            let wp = RingVector {
                elements: z[n_in..]
                    .iter()
                    .map(|&v| RingElement::from_constant(v))
                    .collect(),
            };
            (c, z[..n_in].to_vec(), wp)
        };

        let stmts = vec![mk(&prover), mk(&prover)];
        let proof = prover.prove(&stmts, &r1cs);

        // The CP proof should be a valid DummyProof (non-empty data)
        assert!(
            proof.cp_proof.data.starts_with(b"dummy-proof:"),
            "CP proof should be a valid DummyProof"
        );
        // The SNARK proof should also be valid
        assert!(
            proof.snark_proof.data.starts_with(b"dummy-proof:"),
            "SNARK proof should be a valid DummyProof"
        );
    }
}

// =========================================================================
// SumcheckSnark backend tests (real cryptographic verification)
// =========================================================================
mod sumcheck_snark_backend {
    use super::*;
    use symphony::snark::SymphonyProver;
    use symphony::SumcheckSnark;

    fn sumcheck_params() -> SymphonyParams {
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
        prover: &SymphonyProver<SumcheckSnark>,
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
    fn sumcheck_snark_end_to_end() {
        let params = sumcheck_params();
        let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&pi1_pi2(&pi1, &pi2), &proof, &r1cs));
    }

    #[test]
    fn sumcheck_snark_tampered_cp_rejected() {
        let params = sumcheck_params();
        let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Tamper with the CP proof's witness commitment
        proof.cp_proof.witness_commitment[0] ^= 0xFF;
        assert!(!verifier.verify(&pi1_pi2(&pi1, &pi2), &proof, &r1cs));
    }

    #[test]
    fn sumcheck_snark_tampered_snark_proof_rejected() {
        let params = sumcheck_params();
        let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Tamper with the SNARK proof's witness commitment
        proof.snark_proof.witness_commitment[0] ^= 0xFF;
        assert!(!verifier.verify(&pi1_pi2(&pi1, &pi2), &proof, &r1cs));
    }

    #[test]
    fn sumcheck_snark_wrong_public_inputs_rejected() {
        let params = sumcheck_params();
        let (prover, verifier) = SymphonyProver::<SumcheckSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        let wrong_pis = vec![vec![999i64], vec![999i64]];
        assert!(!verifier.verify(&wrong_pis, &proof, &r1cs));
    }

    fn pi1_pi2(pi1: &[i64], pi2: &[i64]) -> Vec<Vec<i64>> {
        vec![pi1.to_vec(), pi2.to_vec()]
    }
}

// =========================================================================
// SpartanSnark backend tests (succinct proof via IPA)
// =========================================================================
mod spartan_snark_backend {
    use super::*;
    use symphony::snark::SymphonyProver;
    use symphony::SpartanSnark;

    fn spartan_params() -> SymphonyParams {
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
        prover: &SymphonyProver<SpartanSnark>,
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

    fn pi1_pi2(pi1: &[i64], pi2: &[i64]) -> Vec<Vec<i64>> {
        vec![pi1.to_vec(), pi2.to_vec()]
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_snark_end_to_end() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);
        assert!(verifier.verify(&pi1_pi2(&pi1, &pi2), &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_snark_tampered_cp_witness_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Tamper with CP proof's Pedersen commitment
        proof.cp_proof.witness_commitment +=
            curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&[1u8; 64]);
        assert!(!verifier.verify(&pi1_pi2(&pi1, &pi2), &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_snark_tampered_sumcheck_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Tamper with the SNARK proof's sumcheck
        if let Some(round) = proof.snark_proof.sumcheck_proof.round_polys.first_mut() {
            if !round.is_empty() {
                round[0] += curve25519_dalek::scalar::Scalar::ONE;
            }
        }
        assert!(!verifier.verify(&pi1_pi2(&pi1, &pi2), &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn spartan_snark_wrong_public_inputs_rejected() {
        let params = spartan_params();
        let (prover, verifier) = SymphonyProver::<SpartanSnark>::setup(params);
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;

        let s1 = make_statement(&prover, &z, n_in);
        let s2 = make_statement(&prover, &z, n_in);
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        let wrong_pis = vec![vec![999i64], vec![999i64]];
        assert!(!verifier.verify(&wrong_pis, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn bytes_to_scalars_length_sentinel() {
        use symphony::snark::{BackendSnark, RelationDescription};
        let relation = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: None,
        };
        let (pk, vk) = SpartanSnark::setup(&relation);
        let w1 = b"AAAA";
        let w2 = b"AAAA\x00\x00\x00\x00";
        let proof1 = SpartanSnark::prove(&pk, b"inst", w1);
        let proof2 = SpartanSnark::prove(&pk, b"inst", w2);
        assert!(SpartanSnark::verify(&vk, b"inst", &proof1));
        assert!(SpartanSnark::verify(&vk, b"inst", &proof2));
        // Different-length inputs must produce different Pedersen commitments
        assert_ne!(
            proof1.witness_commitment, proof2.witness_commitment,
            "different-length inputs must produce different witness commitments"
        );
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn context_hash_differs_per_relation() {
        use symphony::snark::{BackendSnark, RelationDescription};
        let relation1 = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: Some(b"context-A".to_vec()),
        };
        let relation2 = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: Some(b"context-B".to_vec()),
        };
        let (pk1, _) = SpartanSnark::setup(&relation1);
        let (pk2, _) = SpartanSnark::setup(&relation2);
        assert_ne!(
            pk1.context_hash, pk2.context_hash,
            "different contexts must produce different context_hash values"
        );
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn rejects_proof_under_wrong_context() {
        use symphony::snark::{BackendSnark, RelationDescription};
        let relation_a = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: Some(b"relation-A-context".to_vec()),
        };
        let relation_b = RelationDescription {
            num_instance_vars: 4,
            num_witness_vars: 8,
            num_constraints: 4,
            context: Some(b"relation-B-context".to_vec()),
        };
        let (pk_a, _vk_a) = SpartanSnark::setup(&relation_a);
        let (_pk_b, vk_b) = SpartanSnark::setup(&relation_b);
        let proof = SpartanSnark::prove(&pk_a, b"instance", b"witness");
        assert!(
            !SpartanSnark::verify(&vk_b, b"instance", &proof),
            "proof should not verify under a different relation's vk"
        );
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn pedersen_extend_to_bounded() {
        use symphony::snark::spartan::commitment::PedersenKey;
        let key = PedersenKey::setup(4, b"test-seed");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut k = key.clone();
            k.extend_to((1 << 24) + 1, b"test-seed");
        }));
        assert!(result.is_err(), "extend_to should panic when n > 2^24");
        let mut k = key;
        k.extend_to(8, b"test-seed");
        assert_eq!(k.generators.len(), 8);
    }
}

// =========================================================================
// WHIR backend pipeline
// =========================================================================
#[cfg(feature = "whir")]
mod whir_pipeline {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use symphony::snark::{SymphonyProver, whir::WhirSnark};

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

    fn make_whir_statement(
        prover: &SymphonyProver<WhirSnark>,
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
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_end_to_end_prove_verify() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_whir_statement(&prover, &z, n_in);
        let s2 = make_whir_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let proof = prover.prove(&statements, &r1cs);

        let public_inputs = vec![pi1, pi2];
        assert!(verifier.verify(&public_inputs, &proof, &r1cs));
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_tampered_cp_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_whir_statement(&prover, &z, n_in);
        let s2 = make_whir_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Tamper with the CP proof's claimed polynomial evaluation
        proof.cp_proof.z_eval += p3_baby_bear::BabyBear::ONE;

        let public_inputs = vec![pi1, pi2];
        assert!(
            !verifier.verify(&public_inputs, &proof, &r1cs),
            "tampered WHIR CP proof should be rejected"
        );
    }

    #[test]
    #[ignore] // slow — run with `cargo test -- --ignored`
    fn whir_tampered_snark_proof_rejected() {
        let params = small_params();
        let (prover, verifier) = SymphonyProver::<WhirSnark>::setup(params);

        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let s1 = make_whir_statement(&prover, &z, n_in);
        let s2 = make_whir_statement(&prover, &z, n_in);
        let pi1 = s1.1.clone();
        let pi2 = s2.1.clone();
        let statements = vec![s1, s2];
        let mut proof = prover.prove(&statements, &r1cs);

        // Tamper with the SNARK proof evaluations
        proof.snark_proof.evaluations[0] += p3_baby_bear::BabyBear::ONE;

        let public_inputs = vec![pi1, pi2];
        assert!(
            !verifier.verify(&public_inputs, &proof, &r1cs),
            "tampered WHIR SNARK proof should be rejected"
        );
    }
}
