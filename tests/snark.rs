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
        let mut eq_val: (i64, i64) = (0, 0);
        let mut factor_vals: Vec<(i64, i64)> = Vec::new();
        for i in 0..had_nv {
            let ri = had_nv - 1 - i;
            let si = seed[i];
            let ri_val = challenges[ri];
            let sr = ext_mul(si, ri_val, qnr);
            fill_ext_mul_aux(&mut z, aux(aux_idx, 0), si, ri_val, qnr);
            aux_idx += 1;

            let f = ext_add(ext_sub(ext_scale(sr, 2), ext_add(si, ri_val)), (1, 0));
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
        let statements = vec![
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
        let statements = vec![
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
        let statements = vec![
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
        let statements = vec![
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
    fn tampered_cp_witness_rejected() {
        let (prover, verifier) = Prover::<SpartanSnark, SpartanSnark>::setup(params());
        let (r1cs, z) = multi_r1cs();
        let n_in = r1cs.num_public;
        let statements = vec![
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
    use symphony::proof_orchestrator::Prover;
    use symphony::snark::whir::WhirSnark;

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
