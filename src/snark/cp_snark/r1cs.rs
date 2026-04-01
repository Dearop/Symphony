//! R1CS-compatible CP-SNARK encoding and relation construction.

use crate::folding::FoldedInstance;
use crate::params::D;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::ExtFieldElement;
use crate::ring::RingElement;
use crate::rok::gr1cs::GR1CSProof;

// ---------------------------------------------------------------------------
// R1CS-compatible CP instance/witness encoding (for WHIR CP R1CS path)
// ---------------------------------------------------------------------------

/// Encode the CP-SNARK instance for the R1CS path.
///
/// The instance contains the folded commitment and public input coefficients,
/// matching the `CpR1csLayout` z-vector instance region.
///
/// Layout: `[one=1] [c*[0..κ-1] coefficients] [x*[0..n_in-1] coefficients]`
/// All values as i64 (8 bytes LE), interpreted as BabyBear elements by WHIR.
pub fn encode_cp_instance_r1cs(folded_instance: &FoldedInstance, layout: &CpR1csLayout) -> Vec<u8> {
    let mut buf = Vec::with_capacity(layout.num_instance * 8);

    // z[0] = 1 (constant one)
    buf.extend_from_slice(&1i64.to_le_bytes());

    // c*[i][j] — folded commitment coefficients
    for i in 0..layout.kappa {
        if i < folded_instance.commitment.value.elements.len() {
            for &coeff in &folded_instance.commitment.value.elements[i].coeffs {
                buf.extend_from_slice(&coeff.to_le_bytes());
            }
        } else {
            for _ in 0..layout.d {
                buf.extend_from_slice(&0i64.to_le_bytes());
            }
        }
    }

    // x*[s][j] — folded public input coefficients
    for s in 0..layout.n_in {
        if s < folded_instance.public_input.len() {
            for &coeff in &folded_instance.public_input[s].coeffs {
                buf.extend_from_slice(&coeff.to_le_bytes());
            }
        } else {
            for _ in 0..layout.d {
                buf.extend_from_slice(&0i64.to_le_bytes());
            }
        }
    }

    buf
}

/// Encode the CP-SNARK witness for the R1CS path.
///
/// The witness contains:
/// - **Phase A**: per-instance commitment/public input coefficients, beta vector,
///   and auxiliary ring product variables.
/// - **Phase B**: per-instance Hadamard sumcheck data (evaluations, challenges,
///   seed, alpha, evaluation matrix) and auxiliary K-mul intermediate results.
///
/// Layout: `[Phase A: beta, c, x_in, prod_c, prod_x] [Phase B: had_data per instance]`
pub fn encode_cp_witness_r1cs(
    commitments: &[crate::commitment::Commitment],
    public_inputs: &[Vec<i64>],
    beta: &[RingElement],
    _folded_instance: &FoldedInstance,
    layout: &CpR1csLayout,
    ntt: &Option<crate::ring::ntt::NttContext>,
    gr1cs_proofs: &[GR1CSProof],
    had_seed: &[ExtFieldElement],
    had_alpha: &ExtFieldElement,
    had_challenges: &[ExtFieldElement],
    qnr: i64,
    _q: u64,
) -> Vec<u8> {
    let d = layout.d;
    let ell_np = layout.ell_np;
    let kappa = layout.kappa;
    let n_in = layout.n_in;

    let num_witness = layout.num_variables - layout.num_instance;
    let mut buf = Vec::with_capacity(num_witness * 8);

    // beta[ℓ][j]
    for ell in 0..ell_np {
        if ell < beta.len() {
            for &coeff in &beta[ell].coeffs {
                buf.extend_from_slice(&coeff.to_le_bytes());
            }
        } else {
            for _ in 0..d {
                buf.extend_from_slice(&0i64.to_le_bytes());
            }
        }
    }

    // c[ℓ][i][j] — per-instance commitment coefficients
    for ell in 0..ell_np {
        for i in 0..kappa {
            if ell < commitments.len() && i < commitments[ell].value.elements.len() {
                for &coeff in &commitments[ell].value.elements[i].coeffs {
                    buf.extend_from_slice(&coeff.to_le_bytes());
                }
            } else {
                for _ in 0..d {
                    buf.extend_from_slice(&0i64.to_le_bytes());
                }
            }
        }
    }

    // x_in[ℓ][s][j] — per-instance public input coefficients
    for ell in 0..ell_np {
        for s in 0..n_in {
            if ell < public_inputs.len() && s < public_inputs[ell].len() {
                // Public inputs are scalar i64 values; encode as ring constant
                let val = public_inputs[ell][s];
                buf.extend_from_slice(&val.to_le_bytes());
                for _ in 1..d {
                    buf.extend_from_slice(&0i64.to_le_bytes());
                }
            } else {
                for _ in 0..d {
                    buf.extend_from_slice(&0i64.to_le_bytes());
                }
            }
        }
    }

    // prod_c[ℓ][i][j] — ring products beta[ℓ] · c[ℓ][i]
    for ell in 0..ell_np {
        for i in 0..kappa {
            if ell < beta.len()
                && ell < commitments.len()
                && i < commitments[ell].value.elements.len()
            {
                let ntt_ctx = ntt
                    .as_ref()
                    .expect("NTT context required for CP R1CS witness");
                let prod = beta[ell].mul_ntt(&commitments[ell].value.elements[i], ntt_ctx);
                for &coeff in &prod.coeffs {
                    buf.extend_from_slice(&coeff.to_le_bytes());
                }
            } else {
                for _ in 0..d {
                    buf.extend_from_slice(&0i64.to_le_bytes());
                }
            }
        }
    }

    // prod_x[ℓ][s][j] — ring products beta[ℓ] · x_in[ℓ][s]
    for ell in 0..ell_np {
        for s in 0..n_in {
            if ell < beta.len() && ell < public_inputs.len() && s < public_inputs[ell].len() {
                let x_ring = RingElement::from_constant(public_inputs[ell][s]);
                let ntt_ctx = ntt
                    .as_ref()
                    .expect("NTT context required for CP R1CS witness");
                let prod = beta[ell].mul_ntt(&x_ring, ntt_ctx);
                for &coeff in &prod.coeffs {
                    buf.extend_from_slice(&coeff.to_le_bytes());
                }
            } else {
                for _ in 0..d {
                    buf.extend_from_slice(&0i64.to_le_bytes());
                }
            }
        }
    }

    // ===================================================================
    // Phase B: Hadamard sumcheck witness data per instance
    // ===================================================================
    let had_nv = layout.had_num_vars;

    // BabyBear modulus for reducing K-mul intermediates.
    let bb_p = 2013265921u64;
    // Helper: reduce a value mod BabyBear to centered representation.
    let bb_red = |v: i128| -> i64 {
        let r = v.rem_euclid(bb_p as i128);
        if r > bb_p as i128 / 2 {
            r as i64 - bb_p as i64
        } else {
            r as i64
        }
    };

    // K-multiplication helper: compute Karatsuba intermediates (p1, p2, c0, c1)
    // for (a0+a1·Y)·(b0+b1·Y) in Fq² reduced to BabyBear.
    let kmul = |a0: i64, a1: i64, b0: i64, b1: i64| -> (i64, i64, i64, i64) {
        let p1 = bb_red(a0 as i128 * b0 as i128);
        let p2 = bb_red(a1 as i128 * b1 as i128);
        let c0 = bb_red(p1 as i128 + qnr as i128 * p2 as i128);
        let p3 = bb_red((a0 as i128 + a1 as i128) * (b0 as i128 + b1 as i128));
        let c1 = bb_red(p3 as i128 - p1 as i128 - p2 as i128);
        (p1, p2, c0, c1)
    };

    // Newton forward difference coefficients (in BabyBear).
    let inv2 = mod_pow(2, bb_p - 2, bb_p) as i64;
    let inv6 = mod_pow(6, bb_p - 2, bb_p) as i64;

    for ell in 0..ell_np {
        if had_nv == 0 || ell >= gr1cs_proofs.len() {
            // No Hadamard data for this instance — fill with zeros.
            for _ in 0..layout.had_block_size {
                buf.extend_from_slice(&0i64.to_le_bytes());
            }
            continue;
        }

        let proof = &gr1cs_proofs[ell];
        let sc = &proof.hadamard_proof.sumcheck_proof;

        // --- Write sumcheck evaluations: had_evals[round][point][comp] ---
        for round_i in 0..had_nv {
            for pt in 0..4 {
                if round_i < sc.round_messages.len()
                    && pt < sc.round_messages[round_i].evaluations.len()
                {
                    let ev = &sc.round_messages[round_i].evaluations[pt];
                    buf.extend_from_slice(&bb_red(ev.c0 as i128).to_le_bytes());
                    buf.extend_from_slice(&bb_red(ev.c1 as i128).to_le_bytes());
                } else {
                    buf.extend_from_slice(&0i64.to_le_bytes());
                    buf.extend_from_slice(&0i64.to_le_bytes());
                }
            }
        }

        // --- Write sumcheck challenges: had_challenges[round][comp] ---
        for round_i in 0..had_nv {
            if round_i < had_challenges.len() {
                buf.extend_from_slice(&bb_red(had_challenges[round_i].c0 as i128).to_le_bytes());
                buf.extend_from_slice(&bb_red(had_challenges[round_i].c1 as i128).to_le_bytes());
            } else {
                buf.extend_from_slice(&0i64.to_le_bytes());
                buf.extend_from_slice(&0i64.to_le_bytes());
            }
        }

        // --- Write sumcheck seed: had_seed[round][comp] ---
        for round_i in 0..had_nv {
            if round_i < had_seed.len() {
                buf.extend_from_slice(&bb_red(had_seed[round_i].c0 as i128).to_le_bytes());
                buf.extend_from_slice(&bb_red(had_seed[round_i].c1 as i128).to_le_bytes());
            } else {
                buf.extend_from_slice(&0i64.to_le_bytes());
                buf.extend_from_slice(&0i64.to_le_bytes());
            }
        }

        // --- Write alpha combiner ---
        buf.extend_from_slice(&bb_red(had_alpha.c0 as i128).to_le_bytes());
        buf.extend_from_slice(&bb_red(had_alpha.c1 as i128).to_le_bytes());

        // --- Write evaluation matrix: U[matrix_idx][row][col] ---
        // matrix_idx ∈ {0,1,2}, row ∈ {0,1} (K-components c0,c1), col ∈ {0..D-1}
        let eval_matrix = &proof.hadamard_proof.evaluation_matrix;
        for mi in 0..3 {
            // row 0 (c0): data[0][j] for j in 0..D
            for j in 0..d {
                buf.extend_from_slice(&bb_red(eval_matrix[mi].data[0][j] as i128).to_le_bytes());
            }
            // row 1 (c1): data[1][j] if T > 1, else 0
            for j in 0..d {
                let val = if eval_matrix[mi].data.len() > 1 {
                    eval_matrix[mi].data[1][j]
                } else {
                    0
                };
                buf.extend_from_slice(&bb_red(val as i128).to_le_bytes());
            }
        }

        // --- Compute and write auxiliary K-mul results ---
        // We must replay the exact R1CS computation to produce (p1, p2, c0, c1)
        // for each K-multiplication in the same order as generate_cp_r1cs.

        // Extract evaluation data for this instance.
        let ev = |round: usize, pt: usize| -> (i64, i64) {
            if round < sc.round_messages.len() && pt < sc.round_messages[round].evaluations.len() {
                let e = &sc.round_messages[round].evaluations[pt];
                (bb_red(e.c0 as i128), bb_red(e.c1 as i128))
            } else {
                (0, 0)
            }
        };
        let rc = |round: usize| -> (i64, i64) {
            if round < had_challenges.len() {
                (
                    bb_red(had_challenges[round].c0 as i128),
                    bb_red(had_challenges[round].c1 as i128),
                )
            } else {
                (0, 0)
            }
        };
        let seed = |round: usize| -> (i64, i64) {
            if round < had_seed.len() {
                (
                    bb_red(had_seed[round].c0 as i128),
                    bb_red(had_seed[round].c1 as i128),
                )
            } else {
                (0, 0)
            }
        };
        let alpha_k = (bb_red(had_alpha.c0 as i128), bb_red(had_alpha.c1 as i128));
        let u_val = |mi: usize, comp: usize, j: usize| -> i64 {
            if comp == 0 {
                bb_red(eval_matrix[mi].data[0][j] as i128)
            } else if eval_matrix[mi].data.len() > 1 {
                bb_red(eval_matrix[mi].data[1][j] as i128)
            } else {
                0
            }
        };

        // Newton coefficients in BabyBear:
        // d3 = inv6 * (-e0 + 3*e1 - 3*e2 + e3)
        // d2 = inv2 * (e0 - 2*e1 + e2)
        // d1 = e1 - e0
        // d0 = e0
        let newton_d3 = |round: usize, comp: usize| -> i64 {
            let e = |pt: usize| -> i64 {
                if comp == 0 {
                    ev(round, pt).0
                } else {
                    ev(round, pt).1
                }
            };
            bb_red(
                inv6 as i128
                    * bb_red(-(e(0) as i128) + 3 * e(1) as i128 - 3 * e(2) as i128 + e(3) as i128)
                        as i128,
            )
        };
        let newton_d2 = |round: usize, comp: usize| -> i64 {
            let e = |pt: usize| -> i64 {
                if comp == 0 {
                    ev(round, pt).0
                } else {
                    ev(round, pt).1
                }
            };
            bb_red(inv2 as i128 * bb_red(e(0) as i128 - 2 * e(1) as i128 + e(2) as i128) as i128)
        };
        let newton_d1 = |round: usize, comp: usize| -> i64 {
            let e = |pt: usize| -> i64 {
                if comp == 0 {
                    ev(round, pt).0
                } else {
                    ev(round, pt).1
                }
            };
            bb_red(e(1) as i128 - e(0) as i128)
        };

        // -- Sumcheck Horner K-muls (3 per round) --
        // Track claim across rounds for verification.
        let mut _claim = (0i64, 0i64); // not needed for aux, but helpful for clarity

        for round_i in 0..had_nv {
            let (r0, r1) = rc(round_i);
            let d3_0 = newton_d3(round_i, 0);
            let d3_1 = newton_d3(round_i, 1);
            let d2_0 = newton_d2(round_i, 0);
            let d2_1 = newton_d2(round_i, 1);
            let d1_0 = newton_d1(round_i, 0);
            let d1_1 = newton_d1(round_i, 1);

            // K-mul 1: m1 = d3 * (r - 2)
            let r_minus_2_0 = bb_red(r0 as i128 - 2);
            let (p1, p2, c0, c1) = kmul(d3_0, d3_1, r_minus_2_0, r1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&c0.to_le_bytes());
            buf.extend_from_slice(&c1.to_le_bytes());

            // t2 = m1 + d2
            let t2_0 = bb_red(c0 as i128 + d2_0 as i128);
            let t2_1 = bb_red(c1 as i128 + d2_1 as i128);

            // K-mul 2: m2 = t2 * (r - 1)
            let r_minus_1_0 = bb_red(r0 as i128 - 1);
            let (p1, p2, c0, c1) = kmul(t2_0, t2_1, r_minus_1_0, r1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&c0.to_le_bytes());
            buf.extend_from_slice(&c1.to_le_bytes());

            // t1 = m2 + d1
            let t1_0 = bb_red(c0 as i128 + d1_0 as i128);
            let t1_1 = bb_red(c1 as i128 + d1_1 as i128);

            // K-mul 3: m3 = t1 * r
            let (p1, p2, c0, c1) = kmul(t1_0, t1_1, r0, r1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&c0.to_le_bytes());
            buf.extend_from_slice(&c1.to_le_bytes());

            // claim_{i+1} = m3 + d0 = (c0 + e0_0, c1 + e0_1)
            let e0_0 = ev(round_i, 0).0;
            let e0_1 = ev(round_i, 0).1;
            _claim = (
                bb_red(c0 as i128 + e0_0 as i128),
                bb_red(c1 as i128 + e0_1 as i128),
            );
        }

        // -- eq(s, r) evaluation K-muls --
        // nv factor muls (s_i * r_{nv-1-i}) + (nv-1) chain muls
        let mut factor_vals: Vec<(i64, i64)> = Vec::with_capacity(had_nv);
        for i in 0..had_nv {
            let (s0, s1) = seed(i);
            let ri = had_nv - 1 - i;
            let (r0, r1) = rc(ri);

            // K-mul: sr = s_i * r_{nv-1-i}
            let (p1, p2, sr_c0, sr_c1) = kmul(s0, s1, r0, r1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&sr_c0.to_le_bytes());
            buf.extend_from_slice(&sr_c1.to_le_bytes());

            // f_i = 2*sr - s - r + 1 (per component)
            let f0 = bb_red(2 * sr_c0 as i128 - s0 as i128 - r0 as i128 + 1);
            let f1 = bb_red(2 * sr_c1 as i128 - s1 as i128 - r1 as i128);
            factor_vals.push((f0, f1));
        }

        // Chain-multiply: eq = f_0 * f_1 * ... * f_{nv-1}
        let mut eq_val = factor_vals[0];
        for i in 1..had_nv {
            let (p1, p2, c0, c1) = kmul(eq_val.0, eq_val.1, factor_vals[i].0, factor_vals[i].1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&c0.to_le_bytes());
            buf.extend_from_slice(&c1.to_le_bytes());
            eq_val = (c0, c1);
        }

        // -- U products: u_prod_j = U[0,j] * U[1,j] for j in 0..D --
        let mut uprod_vals: Vec<(i64, i64)> = Vec::with_capacity(d);
        for j in 0..d {
            let u0_c0 = u_val(0, 0, j);
            let u0_c1 = u_val(0, 1, j);
            let u1_c0 = u_val(1, 0, j);
            let u1_c1 = u_val(1, 1, j);
            let (p1, p2, c0, c1) = kmul(u0_c0, u0_c1, u1_c0, u1_c1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&c0.to_le_bytes());
            buf.extend_from_slice(&c1.to_le_bytes());
            uprod_vals.push((c0, c1));
        }

        // -- Combined sum: Σ_j α^j * (U[0,j]*U[1,j] - U[2,j]) --
        // j=0: combined = diff_0 (α^0 = 1, no mul needed)
        let mut combined = (
            bb_red(uprod_vals[0].0 as i128 - u_val(2, 0, 0) as i128),
            bb_red(uprod_vals[0].1 as i128 - u_val(2, 1, 0) as i128),
        );

        let mut alpha_pow = alpha_k; // α^1
        for j in 1..d {
            // diff_j = uprod_j - U[2,j]
            let diff_0 = bb_red(uprod_vals[j].0 as i128 - u_val(2, 0, j) as i128);
            let diff_1 = bb_red(uprod_vals[j].1 as i128 - u_val(2, 1, j) as i128);

            // α^j * diff_j
            let (p1, p2, c0, c1) = kmul(alpha_pow.0, alpha_pow.1, diff_0, diff_1);
            buf.extend_from_slice(&p1.to_le_bytes());
            buf.extend_from_slice(&p2.to_le_bytes());
            buf.extend_from_slice(&c0.to_le_bytes());
            buf.extend_from_slice(&c1.to_le_bytes());
            combined = (
                bb_red(combined.0 as i128 + c0 as i128),
                bb_red(combined.1 as i128 + c1 as i128),
            );

            // α^{j+1} = α^j * α (for next iteration, not needed after last)
            if j + 1 < d {
                let (p1, p2, c0, c1) = kmul(alpha_pow.0, alpha_pow.1, alpha_k.0, alpha_k.1);
                buf.extend_from_slice(&p1.to_le_bytes());
                buf.extend_from_slice(&p2.to_le_bytes());
                buf.extend_from_slice(&c0.to_le_bytes());
                buf.extend_from_slice(&c1.to_le_bytes());
                alpha_pow = (c0, c1);
            }
        }

        // -- Final: eq_val * combined --
        let (p1, p2, c0, c1) = kmul(eq_val.0, eq_val.1, combined.0, combined.1);
        buf.extend_from_slice(&p1.to_le_bytes());
        buf.extend_from_slice(&p2.to_le_bytes());
        buf.extend_from_slice(&c0.to_le_bytes());
        buf.extend_from_slice(&c1.to_le_bytes());
    }

    buf
}

// ---------------------------------------------------------------------------
// Phase A CP R1CS: folding linear combination constraints
// ---------------------------------------------------------------------------

/// Parameters describing the CP R1CS z-vector layout.
///
/// All variables are BabyBear scalars. Ring elements of degree D occupy D
/// consecutive slots. Extension field elements (K = Fq²) occupy 2 slots (c0, c1).
/// The z-vector is: `z = (instance || witness)`.
#[derive(Debug, Clone)]
pub struct CpR1csLayout {
    /// Ring polynomial degree (= D = 64).
    pub d: usize,
    /// Number of folding instances (ℓ_np).
    pub ell_np: usize,
    /// Number of commitment components (κ = kappa).
    pub kappa: usize,
    /// Number of public input slots per instance.
    pub n_in: usize,
    /// Number of Hadamard sumcheck variables = ceil(log2(m)).
    pub had_num_vars: usize,

    // --- Offsets into z-vector ---
    /// Offset of the constant-one variable (always 0).
    pub off_one: usize,
    /// Offset of c*[i][j]: starts at 1, length κ·D.
    pub off_c_star: usize,
    /// Offset of x*[i][j]: length n_in·D.
    pub off_x_star: usize,
    /// Total instance variables.
    pub num_instance: usize,

    // --- Phase A witness ---
    pub off_beta: usize,
    pub off_c: usize,
    pub off_x_in: usize,
    pub off_prod_c: usize,
    pub off_prod_x: usize,

    // --- Phase B witness: Hadamard data per instance ---
    // For each instance ℓ: sumcheck evaluations, challenges, seed, alpha,
    // evaluation matrix, and auxiliary multiplication results.
    /// Start of Phase B Hadamard witness block.
    pub off_had: usize,
    /// Size of one instance's Hadamard witness block.
    pub had_block_size: usize,

    /// Total variables (instance + witness).
    pub num_variables: usize,
    /// Number of auxiliary K-mul results in Phase B per instance.
    pub had_aux_per_instance: usize,
}

impl CpR1csLayout {
    pub fn new(ell_np: usize, kappa: usize, n_in: usize, m: usize) -> Self {
        let d = D;
        let had_num_vars = if m <= 1 {
            0
        } else {
            (usize::BITS - (m - 1).leading_zeros()) as usize
        };

        // Instance: one + c*[κ·D] + x*[n_in·D]
        let off_one = 0;
        let off_c_star = 1;
        let off_x_star = off_c_star + kappa * d;
        let num_instance = off_x_star + n_in * d;

        // Phase A witness
        let off_beta = num_instance;
        let off_c = off_beta + ell_np * d;
        let off_x_in = off_c + ell_np * kappa * d;
        let off_prod_c = off_x_in + ell_np * n_in * d;
        let off_prod_x = off_prod_c + ell_np * kappa * d;

        // Phase B: per-instance Hadamard witness
        // Each instance has:
        //   had_evals[num_vars][4 * 2]       -- sumcheck evaluations (4 K-values per round)
        //   had_challenges[num_vars * 2]      -- sumcheck challenges (K-values)
        //   had_seed[num_vars * 2]            -- sumcheck seed s (K-values)
        //   had_alpha[2]                      -- combiner alpha
        //   had_eval_matrix[3 * 2 * D]        -- evaluation matrix (3 TensorElements)
        //   had_aux[...]                      -- auxiliary K-mul results
        //
        // Auxiliary K-mul count per instance:
        //   Sumcheck rounds: 3 K-muls per round (Horner) = 3*num_vars
        //   eq evaluation: 2*num_vars (products) + (num_vars-1) (chain) = 3*num_vars - 1
        //   Combined sum: D (U products) + (D-1) (alpha powers) + D (alpha*diff) = 3D - 1
        //   Final: 1 (eq * combined)
        //   Total: 3*num_vars + 3*num_vars - 1 + 3*D - 1 + 1 = 6*num_vars + 3*D - 1
        // K-mul count per instance:
        //   Sumcheck: 3 per round = 3*nv
        //   eq: nv (s*r) + (nv-1) (chain) = 2*nv - 1
        //   U products: D
        //   Combined: (D-1) alpha*diff + (D-2) alpha powers = 2*D - 3
        //   Final: 1
        //   Total: 3*nv + 2*nv - 1 + D + 2*D - 3 + 1 = 5*nv + 3*D - 3
        let had_kmuls_per_instance = if had_num_vars > 0 {
            5 * had_num_vars + 3 * d - 3
        } else {
            0
        };
        let had_aux_per_instance = had_kmuls_per_instance;
        // Each K-mul needs 4 aux values: p1, p2, c0, c1
        let had_data_per_instance = had_num_vars * 4 * 2   // evals
            + had_num_vars * 2     // challenges
            + had_num_vars * 2     // seed
            + 2                    // alpha
            + 3 * 2 * d           // eval_matrix
            + had_aux_per_instance * 4; // 4 aux values per K-mul (p1, p2, c0, c1)
        let had_block_size = had_data_per_instance;

        let off_had = off_prod_x + ell_np * n_in * d;
        let num_variables = off_had + ell_np * had_block_size;

        Self {
            d,
            ell_np,
            kappa,
            n_in,
            had_num_vars,
            off_one,
            off_c_star,
            off_x_star,
            num_instance,
            off_beta,
            off_c,
            off_x_in,
            off_prod_c,
            off_prod_x,
            off_had,
            had_block_size,
            num_variables,
            had_aux_per_instance,
        }
    }

    // --- Phase A accessors ---

    pub fn beta(&self, ell: usize, j: usize) -> usize {
        self.off_beta + ell * self.d + j
    }
    pub fn c(&self, ell: usize, i: usize, j: usize) -> usize {
        self.off_c + (ell * self.kappa + i) * self.d + j
    }
    pub fn x_in(&self, ell: usize, slot: usize, j: usize) -> usize {
        self.off_x_in + (ell * self.n_in + slot) * self.d + j
    }
    pub fn c_star(&self, i: usize, j: usize) -> usize {
        self.off_c_star + i * self.d + j
    }
    pub fn x_star(&self, slot: usize, j: usize) -> usize {
        self.off_x_star + slot * self.d + j
    }
    pub fn prod_c(&self, ell: usize, i: usize, j: usize) -> usize {
        self.off_prod_c + (ell * self.kappa + i) * self.d + j
    }
    pub fn prod_x(&self, ell: usize, slot: usize, j: usize) -> usize {
        self.off_prod_x + (ell * self.n_in + slot) * self.d + j
    }

    // --- Phase B accessors ---
    // Within instance ℓ's Hadamard block:

    fn had_base(&self, ell: usize) -> usize {
        self.off_had + ell * self.had_block_size
    }
    /// Sumcheck evaluation [round][point], component comp (0=c0, 1=c1).
    pub fn had_eval(&self, ell: usize, round: usize, point: usize, comp: usize) -> usize {
        self.had_base(ell) + (round * 4 + point) * 2 + comp
    }
    /// Sumcheck challenge [round], component comp.
    pub fn had_challenge(&self, ell: usize, round: usize, comp: usize) -> usize {
        self.had_base(ell) + self.had_num_vars * 4 * 2 + round * 2 + comp
    }
    /// Sumcheck seed s[round], component comp.
    pub fn had_seed(&self, ell: usize, round: usize, comp: usize) -> usize {
        self.had_base(ell) + self.had_num_vars * 4 * 2 + self.had_num_vars * 2 + round * 2 + comp
    }
    /// Alpha combiner, component comp.
    pub fn had_alpha(&self, ell: usize, comp: usize) -> usize {
        self.had_base(ell) + self.had_num_vars * 4 * 2 + self.had_num_vars * 2 * 2 + comp
    }
    /// Evaluation matrix U[matrix_idx][row][col] where row∈{0,1}=comp, col∈{0..D-1}.
    pub fn had_eval_matrix(&self, ell: usize, matrix_idx: usize, row: usize, col: usize) -> usize {
        let base = self.had_base(ell) + self.had_num_vars * 4 * 2 + self.had_num_vars * 2 * 2 + 2;
        base + (matrix_idx * 2 + row) * self.d + col
    }
    /// Auxiliary K-mul variables [idx], sub ∈ {0=p1, 1=p2, 2=c0, 3=c1}.
    pub fn had_aux(&self, ell: usize, idx: usize, sub: usize) -> usize {
        let base = self.had_base(ell)
            + self.had_num_vars * 4 * 2
            + self.had_num_vars * 2 * 2
            + 2
            + 3 * 2 * self.d;
        base + idx * 4 + sub
    }
}

/// Generate the Phase A CP R1CS: folding linear combination constraints.
///
/// Encodes `c*[i] = Σ_ℓ beta[ℓ] · c_ℓ[i]` and `x*[s] = Σ_ℓ beta[ℓ] · x_in[ℓ][s]`
/// as R1CS over BabyBear using negacyclic convolution (schoolbook).
///
/// Each ring multiplication `a · b mod (X^D + 1)` produces coefficient j as:
///   (a·b)[j] = Σ_{k=0}^{j} a[k]·b[j-k] - Σ_{k=j+1}^{D-1} a[k]·b[D+j-k]
///
/// For each (ℓ, i, j), this is a bilinear form in (beta[ℓ], c_ℓ[i]) coefficients,
/// encoded as D R1CS constraints (one per cross-product contributing to coeff j).
///
/// Returns `(R1CSMatrices, CpR1csLayout)`.
/// Generate the full CP R1CS (Phase A + Phase B).
///
/// `qnr` is the quadratic non-residue used in the extension field K = Fq[Y]/(Y² - qnr).
/// It must match the value from `ExtFieldContext::alpha`.
pub fn generate_cp_r1cs(
    ell_np: usize,
    kappa: usize,
    n_in: usize,
    m: usize,
    qnr: i64,
) -> (R1CSMatrices, CpR1csLayout) {
    let layout = CpR1csLayout::new(ell_np, kappa, n_in, m);
    let d = layout.d;

    let had_nv = layout.had_num_vars;

    // Count constraints:
    // Phase A:
    //   Ring mul: (ℓ_np·(κ + n_in)) · D
    //   Sum:      (κ + n_in) · D
    let num_ring_muls = ell_np * (kappa + n_in);
    let phase_a_constraints = num_ring_muls * d + (kappa + n_in) * d;
    // Phase B (per instance):
    //   Sumcheck rounds: had_nv * (2 + 3*3) = had_nv * 11
    //     - 2 linear checks (evals[0]+evals[1]==claim, one per K-component)
    //     - 3 K-muls for Horner, each = 3 BB constraints (Karatsuba)
    //   eq evaluation: (3*had_nv - 1) * 3 BB constraints (if had_nv > 0)
    //   Combined sum: (3*D - 1) * 3 BB constraints
    //   Final eq*combined: 1 * 3 BB constraints
    //   Final equality: 2 checks
    // Phase B: full Hadamard sumcheck verification.
    // Per instance:
    //   Sumcheck rounds: had_nv × (2 addition + 3×4 K-mul) = had_nv × 14
    //   eq(s,r): had_nv s*r muls + (had_nv-1) chain = (2*had_nv - 1) × 4
    //   U products: D × 4
    //   Combined sum: (D-1) α^j*diff muls + (D-2) α power muls = (2D-3) × 4
    //   Final mul: 4
    //   Final equality: 2
    let phase_b_per_instance = if had_nv > 0 {
        had_nv * 14 + (2 * had_nv - 1) * 4 + d * 4 + (2 * d - 3) * 4 + 4 + 2
    } else {
        0
    };
    let phase_b_constraints = ell_np * phase_b_per_instance;
    let num_constraints = phase_a_constraints + phase_b_constraints;

    let mut r1cs = R1CSMatrices::new(num_constraints, layout.num_variables, layout.num_instance);

    let mut row = 0;

    // --- Ring multiplication constraints ---
    // For each ring product beta[ℓ] · c_ℓ[i], constrain prod_c[ℓ][i]:
    //   prod_c[ℓ][i][j] = Σ_{k=0}^{j} beta[ℓ][k]·c_ℓ[i][j-k]
    //                    - Σ_{k=j+1}^{D-1} beta[ℓ][k]·c_ℓ[i][D+j-k]
    //
    // In R1CS: for each j, this is encoded as
    //   (Σ_k sign(k,j) · beta[ℓ][k]) · (one) ≠ what we want...
    //
    // Actually, the bilinear form can't be captured in one R1CS row since
    // it involves sums of products. Instead we use the auxiliary prod variables:
    //
    // We express the negacyclic convolution coefficient as a single R1CS constraint:
    //   A_row · z = Σ_k coeff_A[k] · beta[ℓ][k]    (linear combo of beta coeffs)
    //   B_row · z = Σ_k coeff_B[k] · c_ℓ[i][k]      (linear combo of c coeffs)
    //
    // But this only works if the bilinear form factors into (linear in a)(linear in b).
    // The negacyclic convolution coefficient IS a sum of products — it doesn't factor.
    //
    // So we must use schoolbook with one constraint per cross-product. But that's D²
    // constraints per ring mul, which is expensive.
    //
    // Alternative: NTT approach. In the NTT domain, negacyclic convolution is pointwise.
    // So NTT(a·b)[j] = NTT(a)[j] · NTT(b)[j], which IS a single product — one R1CS row.
    //
    // The NTT transform is linear, so we bake it into the A and B matrices:
    //   A_row[k] = ψ^k · ω^{jk}  for each beta[ℓ] coeff k  (computes NTT(beta)[j])
    //   B_row[k] = ψ^k · ω^{jk}  for each c_ℓ[i] coeff k   (computes NTT(c)[j])
    //   C_row[k] = ψ^k · ω^{jk}  for each prod[ℓ][i] coeff k (computes NTT(prod)[j])
    //
    // This gives D constraints per ring mul (one per NTT slot).

    // Compute negacyclic NTT twiddle factors over i64 (representing BabyBear).
    // We need ψ = primitive 2D-th root of unity in BabyBear.
    // BabyBear p = 2013265921, group order p-1 = 2^27 * 15.
    // Generator g = 31 (primitive root of BabyBear).
    // ψ = g^((p-1)/(2D)) = 31^((2013265921-1)/128)
    let p: u64 = 2013265921; // BabyBear modulus
    let two_d = 2 * d;
    let exp = (p - 1) / two_d as u64;
    let psi = mod_pow(31, exp, p); // primitive 2D-th root of unity
    let omega = mod_mul(psi, psi, p); // ω = ψ², primitive D-th root

    // Precompute NTT row coefficients: for slot j, coeff k, the twiddle is ψ^k · ω^{jk}
    // ntt_coeff[j][k] = ψ^k · ω^{jk} mod p
    let mut ntt_coeff = vec![vec![0i64; d]; d];
    for j in 0..d {
        let mut psi_k = 1u64; // ψ^k
        for k in 0..d {
            let omega_jk = mod_pow(omega, (j * k) as u64 % (p - 1), p);
            let val = mod_mul(psi_k, omega_jk, p);
            // Convert to centered representation for R1CS entry
            ntt_coeff[j][k] = if val > p / 2 {
                val as i64 - p as i64
            } else {
                val as i64
            };
            psi_k = mod_mul(psi_k, psi, p);
        }
    }

    // Commitment ring products: prod_c[ℓ][i] = beta[ℓ] · c_ℓ[i]
    for ell in 0..ell_np {
        for i in 0..kappa {
            for j in 0..d {
                // A: NTT of beta[ℓ], slot j
                for k in 0..d {
                    r1cs.a.insert(row, layout.beta(ell, k), ntt_coeff[j][k]);
                }
                // B: NTT of c_ℓ[i], slot j
                for k in 0..d {
                    r1cs.b.insert(row, layout.c(ell, i, k), ntt_coeff[j][k]);
                }
                // C: NTT of prod_c[ℓ][i], slot j
                for k in 0..d {
                    r1cs.c
                        .insert(row, layout.prod_c(ell, i, k), ntt_coeff[j][k]);
                }
                row += 1;
            }
        }
    }

    // Public input ring products: prod_x[ℓ][s] = beta[ℓ] · x_in[ℓ][s]
    for ell in 0..ell_np {
        for s in 0..n_in {
            for j in 0..d {
                for k in 0..d {
                    r1cs.a.insert(row, layout.beta(ell, k), ntt_coeff[j][k]);
                }
                for k in 0..d {
                    r1cs.b.insert(row, layout.x_in(ell, s, k), ntt_coeff[j][k]);
                }
                for k in 0..d {
                    r1cs.c
                        .insert(row, layout.prod_x(ell, s, k), ntt_coeff[j][k]);
                }
                row += 1;
            }
        }
    }

    // --- Sum constraints ---
    // c*[i][j] = Σ_ℓ prod_c[ℓ][i][j]
    // Encoded as: (one) · (c*[i][j]) = Σ_ℓ prod_c[ℓ][i][j]
    for i in 0..kappa {
        for j in 0..d {
            r1cs.a.insert(row, layout.off_one, 1);
            r1cs.b.insert(row, layout.c_star(i, j), 1);
            for ell in 0..ell_np {
                r1cs.c.insert(row, layout.prod_c(ell, i, j), 1);
            }
            row += 1;
        }
    }

    // x*[s][j] = Σ_ℓ prod_x[ℓ][s][j]
    for s in 0..n_in {
        for j in 0..d {
            r1cs.a.insert(row, layout.off_one, 1);
            r1cs.b.insert(row, layout.x_star(s, j), 1);
            for ell in 0..ell_np {
                r1cs.c.insert(row, layout.prod_x(ell, s, j), 1);
            }
            row += 1;
        }
    }

    // ===================================================================
    // Phase B: Hadamard sumcheck verification constraints
    // ===================================================================
    // For each instance ℓ, we verify the degree-3 sumcheck and the final
    // evaluation consistency check. All arithmetic is over K = Fq² which
    // we encode as pairs of BabyBear values.
    //
    // K-multiplication (a0+a1·Y)(b0+b1·Y) = (a0·b0 + QNR·a1·b1, a0·b1 + a1·b0)
    // uses Karatsuba: 3 base-field muls.
    //   p1 = a0·b0, p2 = a1·b1, p3 = (a0+a1)·(b0+b1)
    //   c0 = p1 + QNR·p2, c1 = p3 - p1 - p2

    // The QNR for the extension field K = Fq[Y]/(Y² - qnr) is baked into
    // the R1CS as a constant coefficient in the Karatsuba K-mul constraints:
    //   c0 = p1 + qnr*p2, c1 = p3 - p1 - p2

    // --- Phase B helper: generalized K-multiplication ---
    // Adds 4 R1CS constraints for c = a * b in K = Fq².
    // a and b are specified as lists of (variable, coefficient) pairs for each
    // component (c0 and c1). This allows multiplying arbitrary linear combinations.
    //
    // aux = (p1_var, p2_var, c0_var, c1_var)
    // Row 0: A_c0 * B_c0 = p1
    // Row 1: A_c1 * B_c1 = p2
    // Row 2: (A_c0 + A_c1) * (B_c0 + B_c1) = c1 + p1 + p2
    // Row 3: 1 * c0 = p1 + QNR * p2
    fn ext_mul_lc(
        r1cs: &mut R1CSMatrices,
        row: &mut usize,
        one_var: usize,
        qnr: i64,
        a_c0: &[(usize, i64)],
        a_c1: &[(usize, i64)],
        b_c0: &[(usize, i64)],
        b_c1: &[(usize, i64)],
        aux: (usize, usize, usize, usize),
    ) {
        let (p1, p2, c0, c1) = aux;

        // Row 0: Σ a_c0 * Σ b_c0 = p1
        for &(v, c) in a_c0 {
            r1cs.a.insert(*row, v, c);
        }
        for &(v, c) in b_c0 {
            r1cs.b.insert(*row, v, c);
        }
        r1cs.c.insert(*row, p1, 1);
        *row += 1;

        // Row 1: Σ a_c1 * Σ b_c1 = p2
        for &(v, c) in a_c1 {
            r1cs.a.insert(*row, v, c);
        }
        for &(v, c) in b_c1 {
            r1cs.b.insert(*row, v, c);
        }
        r1cs.c.insert(*row, p2, 1);
        *row += 1;

        // Row 2: (Σ a_c0 + Σ a_c1) * (Σ b_c0 + Σ b_c1) = c1 + p1 + p2
        for &(v, c) in a_c0 {
            r1cs.a.insert(*row, v, c);
        }
        for &(v, c) in a_c1 {
            r1cs.a.insert(*row, v, c);
        }
        for &(v, c) in b_c0 {
            r1cs.b.insert(*row, v, c);
        }
        for &(v, c) in b_c1 {
            r1cs.b.insert(*row, v, c);
        }
        r1cs.c.insert(*row, c1, 1);
        r1cs.c.insert(*row, p1, 1);
        r1cs.c.insert(*row, p2, 1);
        *row += 1;

        // Row 3: 1 * c0 = p1 + QNR * p2
        r1cs.a.insert(*row, one_var, 1);
        r1cs.b.insert(*row, c0, 1);
        r1cs.c.insert(*row, p1, 1);
        r1cs.c.insert(*row, p2, qnr);
        *row += 1;
    }

    // Precompute BabyBear modular inverses for Newton coefficients.
    let bb_p: u64 = 2013265921;
    let inv2 = mod_pow(2, bb_p - 2, bb_p) as i64;
    let inv6 = mod_pow(6, bb_p - 2, bb_p) as i64;
    let neg_inv6 = ((-(inv6 as i128)).rem_euclid(bb_p as i128)) as i64;
    let three_inv6 = ((3i128 * inv6 as i128).rem_euclid(bb_p as i128)) as i64;
    let neg3_inv6 = ((-(3i128 * inv6 as i128)).rem_euclid(bb_p as i128)) as i64;
    let neg2_inv2 = ((-(2i128 * inv2 as i128)).rem_euclid(bb_p as i128)) as i64;

    if had_nv > 0 {
        for ell in 0..ell_np {
            let mut aux_idx = 0usize;
            let mut alloc_kmul = || -> (usize, usize, usize, usize) {
                let t = (
                    layout.had_aux(ell, aux_idx, 0),
                    layout.had_aux(ell, aux_idx, 1),
                    layout.had_aux(ell, aux_idx, 2),
                    layout.had_aux(ell, aux_idx, 3),
                );
                aux_idx += 1;
                t
            };

            // Track claim as list of (var, coeff) pairs per component.
            // claim = Σ terms. Starts at zero (empty list).
            let mut claim_c0: Vec<(usize, i64)> = vec![];
            let mut claim_c1: Vec<(usize, i64)> = vec![];

            // --- Sumcheck round verification ---
            for round_i in 0..had_nv {
                let ev = |pt: usize, comp: usize| layout.had_eval(ell, round_i, pt, comp);
                let rc = |comp: usize| layout.had_challenge(ell, round_i, comp);

                // Addition check: evals[0] + evals[1] == claim (2 constraints)
                for comp in 0..2 {
                    r1cs.a.insert(row, layout.off_one, 1);
                    r1cs.b.insert(row, ev(0, comp), 1);
                    r1cs.b.insert(row, ev(1, comp), 1);
                    for &(v, c) in if comp == 0 { &claim_c0 } else { &claim_c1 } {
                        r1cs.c.insert(row, v, c);
                    }
                    row += 1;
                }

                // Newton forward differences (linear in evals):
                // d3 = inv6 * (-e0 + 3*e1 - 3*e2 + e3)
                // d2 = inv2 * (e0 - 2*e1 + e2)
                // d1 = e1 - e0
                // d0 = e0
                let d3 = |comp: usize| -> Vec<(usize, i64)> {
                    vec![
                        (ev(0, comp), neg_inv6),
                        (ev(1, comp), three_inv6),
                        (ev(2, comp), neg3_inv6),
                        (ev(3, comp), inv6),
                    ]
                };
                let d2 = |comp: usize| -> Vec<(usize, i64)> {
                    vec![
                        (ev(0, comp), inv2),
                        (ev(1, comp), neg2_inv2),
                        (ev(2, comp), inv2),
                    ]
                };
                let d1 = |comp: usize| -> Vec<(usize, i64)> {
                    vec![(ev(1, comp), 1), (ev(0, comp), -1)]
                };

                // Horner: t3=d3, t2=t3*(r-2)+d2, t1=t2*(r-1)+d1, f(r)=t1*r+d0

                // K-mul 1: mul1 = d3 * (r - 2)
                let m1 = alloc_kmul();
                let r_minus_2_c0: Vec<(usize, i64)> = vec![(rc(0), 1), (layout.off_one, -2)];
                let r_c1: Vec<(usize, i64)> = vec![(rc(1), 1)];
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &d3(0),
                    &d3(1),
                    &r_minus_2_c0,
                    &r_c1,
                    m1,
                );

                // t2 = mul1 + d2 (linear combination for next multiplication)
                let mut t2_c0: Vec<(usize, i64)> = vec![(m1.2, 1)];
                t2_c0.extend_from_slice(&d2(0));
                let mut t2_c1: Vec<(usize, i64)> = vec![(m1.3, 1)];
                t2_c1.extend_from_slice(&d2(1));

                // K-mul 2: mul2 = t2 * (r - 1)
                let m2 = alloc_kmul();
                let r_minus_1_c0: Vec<(usize, i64)> = vec![(rc(0), 1), (layout.off_one, -1)];
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &t2_c0,
                    &t2_c1,
                    &r_minus_1_c0,
                    &r_c1,
                    m2,
                );

                // t1 = mul2 + d1
                let mut t1_c0: Vec<(usize, i64)> = vec![(m2.2, 1)];
                t1_c0.extend_from_slice(&d1(0));
                let mut t1_c1: Vec<(usize, i64)> = vec![(m2.3, 1)];
                t1_c1.extend_from_slice(&d1(1));

                // K-mul 3: mul3 = t1 * r
                let m3 = alloc_kmul();
                let r_c0_lc: Vec<(usize, i64)> = vec![(rc(0), 1)];
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &t1_c0,
                    &t1_c1,
                    &r_c0_lc,
                    &r_c1,
                    m3,
                );

                // claim_{i+1} = mul3 + d0 = mul3 + e0
                claim_c0 = vec![(m3.2, 1), (ev(0, 0), 1)];
                claim_c1 = vec![(m3.3, 1), (ev(0, 1), 1)];
            }

            // --- eq(s, r) evaluation ---
            // eq(s, r) = Π_{i=0}^{nv-1} (s_i * r_i + (1 - s_i)(1 - r_i))
            // Each factor f_i = s_i*r_i + 1 - s_i - r_i + s_i*r_i = 2*s_i*r_i - s_i - r_i + 1
            // So f_i = 2*(s_i*r_i) - s_i - r_i + 1, needing 1 K-mul for s_i*r_i.
            // Then the product of all factors needs (nv-1) K-muls.
            // Total: nv + (nv-1) = 2*nv - 1 K-muls.

            // First, compute each factor's K-mul (s_i * r_i)
            let mut factor_vars: Vec<(Vec<(usize, i64)>, Vec<(usize, i64)>)> = Vec::new();
            for i in 0..had_nv {
                let s_c0 = vec![(layout.had_seed(ell, i, 0), 1)];
                let s_c1 = vec![(layout.had_seed(ell, i, 1), 1)];
                // challenges are stored in reverse for eq evaluation (r_rev)
                let ri = had_nv - 1 - i;
                let r_c0_i = vec![(layout.had_challenge(ell, ri, 0), 1)];
                let r_c1_i = vec![(layout.had_challenge(ell, ri, 1), 1)];

                let sr = alloc_kmul();
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &s_c0,
                    &s_c1,
                    &r_c0_i,
                    &r_c1_i,
                    sr,
                );

                // f_i = 2*sr - s - r + 1 (per component)
                let f_c0: Vec<(usize, i64)> = vec![
                    (sr.2, 2),
                    (layout.had_seed(ell, i, 0), -1),
                    (layout.had_challenge(ell, ri, 0), -1),
                    (layout.off_one, 1),
                ];
                let f_c1: Vec<(usize, i64)> = vec![
                    (sr.3, 2),
                    (layout.had_seed(ell, i, 1), -1),
                    (layout.had_challenge(ell, ri, 1), -1),
                ];
                factor_vars.push((f_c0, f_c1));
            }

            // Chain-multiply factors: eq_val = f_0 * f_1 * ... * f_{nv-1}
            let mut eq_c0 = factor_vars[0].0.clone();
            let mut eq_c1 = factor_vars[0].1.clone();
            for i in 1..had_nv {
                let m = alloc_kmul();
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &eq_c0,
                    &eq_c1,
                    &factor_vars[i].0,
                    &factor_vars[i].1,
                    m,
                );
                eq_c0 = vec![(m.2, 1)];
                eq_c1 = vec![(m.3, 1)];
            }

            // --- Combined sum: Σ_j α^j * (U[0,j]*U[1,j] - U[2,j]) ---
            // Compute alpha powers incrementally, U products, and accumulate.
            // α^0 = 1 (constant), α^1 = α, α^{j+1} = α^j * α

            let alpha_c0 = vec![(layout.had_alpha(ell, 0), 1)];
            let alpha_c1 = vec![(layout.had_alpha(ell, 1), 1)];

            // Compute all D U-products: u_prod_j = U[0,j] * U[1,j]
            let mut uprod_c0: Vec<Vec<(usize, i64)>> = Vec::new();
            let mut uprod_c1: Vec<Vec<(usize, i64)>> = Vec::new();
            for j in 0..d {
                let u0j_c0 = vec![(layout.had_eval_matrix(ell, 0, 0, j), 1)];
                let u0j_c1 = vec![(layout.had_eval_matrix(ell, 0, 1, j), 1)];
                let u1j_c0 = vec![(layout.had_eval_matrix(ell, 1, 0, j), 1)];
                let u1j_c1 = vec![(layout.had_eval_matrix(ell, 1, 1, j), 1)];
                let m = alloc_kmul();
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &u0j_c0,
                    &u0j_c1,
                    &u1j_c0,
                    &u1j_c1,
                    m,
                );
                uprod_c0.push(vec![(m.2, 1)]);
                uprod_c1.push(vec![(m.3, 1)]);
            }

            // diff_j = U[0,j]*U[1,j] - U[2,j]
            // For j=0: term_0 = α^0 * diff_0 = diff_0 (α^0 = 1)
            let mut combined_c0: Vec<(usize, i64)> = uprod_c0[0].clone();
            combined_c0.push((layout.had_eval_matrix(ell, 2, 0, 0), -1));
            let mut combined_c1: Vec<(usize, i64)> = uprod_c1[0].clone();
            combined_c1.push((layout.had_eval_matrix(ell, 2, 1, 0), -1));

            // For j >= 1: accumulate α^j * diff_j
            let mut alpha_pow_c0 = alpha_c0.clone();
            let mut alpha_pow_c1 = alpha_c1.clone();
            for j in 1..d {
                // diff_j = uprod_j - U[2,j]
                let mut diff_c0 = uprod_c0[j].clone();
                diff_c0.push((layout.had_eval_matrix(ell, 2, 0, j), -1));
                let mut diff_c1 = uprod_c1[j].clone();
                diff_c1.push((layout.had_eval_matrix(ell, 2, 1, j), -1));

                // α^j * diff_j
                let m = alloc_kmul();
                ext_mul_lc(
                    &mut r1cs,
                    &mut row,
                    layout.off_one,
                    qnr,
                    &alpha_pow_c0,
                    &alpha_pow_c1,
                    &diff_c0,
                    &diff_c1,
                    m,
                );
                combined_c0.push((m.2, 1));
                combined_c1.push((m.3, 1));

                // α^{j+1} = α^j * α (for next iteration, not needed after last)
                if j + 1 < d {
                    let m2 = alloc_kmul();
                    ext_mul_lc(
                        &mut r1cs,
                        &mut row,
                        layout.off_one,
                        qnr,
                        &alpha_pow_c0,
                        &alpha_pow_c1,
                        &alpha_c0,
                        &alpha_c1,
                        m2,
                    );
                    alpha_pow_c0 = vec![(m2.2, 1)];
                    alpha_pow_c1 = vec![(m2.3, 1)];
                }
            }

            // --- Final: eq_val * combined == claimed_eval ---
            let final_m = alloc_kmul();
            ext_mul_lc(
                &mut r1cs,
                &mut row,
                layout.off_one,
                qnr,
                &eq_c0,
                &eq_c1,
                &combined_c0,
                &combined_c1,
                final_m,
            );

            // Equality check: final_result == claimed_eval
            // claimed_eval = claim after all rounds = claim_c0, claim_c1
            // final_result = (final_m.2, final_m.3)
            // Check: 1 * final_m.c0 == claim_c0, 1 * final_m.c1 == claim_c1
            for comp in 0..2 {
                r1cs.a.insert(row, layout.off_one, 1);
                r1cs.b
                    .insert(row, if comp == 0 { final_m.2 } else { final_m.3 }, 1);
                for &(v, c) in if comp == 0 { &claim_c0 } else { &claim_c1 } {
                    r1cs.c.insert(row, v, c);
                }
                row += 1;
            }

            let _ = aux_idx;
        }
    }

    assert_eq!(row, num_constraints);

    (r1cs, layout)
}

/// Modular exponentiation: base^exp mod m.
pub fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut result = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, m);
        }
        exp >>= 1;
        base = mod_mul(base, base, m);
    }
    result
}

/// Modular multiplication using u128 to avoid overflow.
fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}
