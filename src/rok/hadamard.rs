//! Πhad: Hadamard relation → Linear relation (Figure 1).
//!
//! Reduces (M₁F) ∘ (M₂F) = M₃F to a linear evaluation instance
//! via degree-3 sumcheck over K.

use crate::commitment::Commitment;
use crate::params::D;
use crate::r1cs::R1CSMatrices;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::tensor::TensorElement;
use crate::rok::LinearRelation;
use crate::sumcheck::prover;
use crate::sumcheck::{self, SumcheckClaim, SumcheckProof};

/// Proof for the Hadamard-to-linear reduction.
#[derive(Debug, Clone)]
pub struct HadamardProof {
    pub sumcheck_proof: SumcheckProof,
    /// Evaluation matrix U ∈ K^{3×d}: U[i][j] = g_i,j(r) at the sumcheck point r.
    pub evaluation_matrix: [TensorElement; 3],
}

/// Prover challenges for Πhad.
pub struct HadamardChallenges {
    /// Sumcheck seed s ∈ K^{log m}.
    pub s: Vec<ExtFieldElement>,
    /// Random combiner α ∈ K.
    pub alpha: ExtFieldElement,
    /// Verifier challenges for each sumcheck round.
    pub sumcheck_challenges: Vec<ExtFieldElement>,
}

/// Run the Πhad prover.
///
/// `witness_matrix[j]` is a length-n vector: the j-th coefficient of each ring element
/// in the full assignment F = [X_in, W].
pub fn prove(
    _commitment: &Commitment,
    witness_matrix: &[Vec<i64>],
    r1cs: &R1CSMatrices,
    challenges: &HadamardChallenges,
    ctx: &ExtFieldContext,
) -> HadamardProof {
    let m = r1cs.num_constraints;
    let num_vars = if m <= 1 {
        0
    } else {
        (usize::BITS - (m - 1).leading_zeros()) as usize
    };
    let table_size = 1 << num_vars;
    let q = ctx.q;

    // Compute g_i,j(b) = (M_i × col_j(F))[b] for i∈{1,2,3}, j∈[D], b∈[m].
    // g_evals[i][b][j] where i ∈ 0..3, b ∈ 0..m, j ∈ 0..D.
    let mut g_evals: Vec<Vec<Vec<i64>>> = vec![vec![vec![0i64; D]; table_size]; 3];
    for j in 0..D.min(witness_matrix.len()) {
        let col = &witness_matrix[j];
        let g1j = r1cs.a.mul_vec_mod(col, q);
        let g2j = r1cs.b.mul_vec_mod(col, q);
        let g3j = r1cs.c.mul_vec_mod(col, q);
        for b in 0..m.min(table_size) {
            g_evals[0][b][j] = g1j[b];
            g_evals[1][b][j] = g2j[b];
            g_evals[2][b][j] = g3j[b];
        }
    }

    // Pre-compute α powers: [1, α, α², ..., α^{D-1}]
    let mut alpha_powers = Vec::with_capacity(D);
    let mut power = ctx.one();
    for _ in 0..D {
        alpha_powers.push(power);
        power = ctx.mul(&power, &challenges.alpha);
    }

    // Build bookkeeping tables for the sumcheck factors.
    // The polynomial is: f(X) = eq(s, X) · Σ_j α^{j-1} · (g1j(X) · g2j(X) − g3j(X))
    // Degree 3: eq is degree 1, g1j·g2j is degree 2, g3j is degree 1.
    //
    // Factor tables:
    //   factor 0: eq(s, b)
    //   factor 1+3j:   g_{1,j}(b)    for j = 0..D
    //   factor 1+3j+1: g_{2,j}(b)
    //   factor 1+3j+2: g_{3,j}(b)
    //
    // However, maintaining 3D+1 tables is expensive. Instead, we pre-combine
    // across j into a "virtual" degree-2 polynomial per hypercube point.
    //
    // We use a specialized combiner that maintains g tables per j and combines them.

    // Build eq table
    let eq_table = prover::build_eq_table(&challenges.s, ctx);

    // Build per-j g tables and immediately combine into aggregate tables:
    //   agg1[b] = Σ_j α^{j-1} · g1j(b)·g2j(b)   (quadratic in the multilinear extension sense, but scalar at each point)
    //   agg2[b] = Σ_j α^{j-1} · g3j(b)
    //
    // Wait, this doesn't work for the bookkeeping approach since agg1 is not multilinear.
    //
    // Correct approach: maintain separate g1j, g2j, g3j tables per j and fold independently.
    // To keep memory reasonable, we process the sumcheck round-by-round.

    // Since the tables are indexed by the hypercube and we need to fold per-round,
    // let's store g_tables[j][i][b] = g_{i+1, j}(b) as ExtFieldElements
    // and combine in the round polynomial computation.

    let mut eq_tab = eq_table;
    let mut g_tabs: Vec<[Vec<ExtFieldElement>; 3]> = (0..D)
        .map(|j| {
            let mut tabs = [
                Vec::with_capacity(table_size),
                Vec::with_capacity(table_size),
                Vec::with_capacity(table_size),
            ];
            for (g0_row, (g1_row, g2_row)) in g_evals[0]
                .iter()
                .zip(g_evals[1].iter().zip(g_evals[2].iter()))
            {
                tabs[0].push(ExtFieldElement {
                    c0: g0_row[j],
                    c1: 0,
                });
                tabs[1].push(ExtFieldElement {
                    c0: g1_row[j],
                    c1: 0,
                });
                tabs[2].push(ExtFieldElement {
                    c0: g2_row[j],
                    c1: 0,
                });
            }
            tabs
        })
        .collect();

    // Run sumcheck round by round
    let mut round_messages = Vec::with_capacity(num_vars);

    for round in 0..num_vars {
        let half = 1 << (num_vars - round - 1);
        let mut evals = vec![ctx.zero(); 4]; // degree 3 → 4 evaluation points

        for eval_idx in 0..4u32 {
            let t = ExtFieldElement {
                c0: eval_idx as i64,
                c1: 0,
            };
            let one_minus_t = ctx.sub(&ctx.one(), &t);

            let mut sum = ctx.zero();
            for rest_idx in 0..half {
                let idx0 = rest_idx;
                let idx1 = half + rest_idx;

                // Interpolate eq
                let eq_val = ctx.add(
                    &ctx.mul(&one_minus_t, &eq_tab[idx0]),
                    &ctx.mul(&t, &eq_tab[idx1]),
                );

                // Sum over j: α^{j-1} · (g1j_interp · g2j_interp - g3j_interp)
                let mut combined = ctx.zero();
                for j in 0..D {
                    let g1 = ctx.add(
                        &ctx.mul(&one_minus_t, &g_tabs[j][0][idx0]),
                        &ctx.mul(&t, &g_tabs[j][0][idx1]),
                    );
                    let g2 = ctx.add(
                        &ctx.mul(&one_minus_t, &g_tabs[j][1][idx0]),
                        &ctx.mul(&t, &g_tabs[j][1][idx1]),
                    );
                    let g3 = ctx.add(
                        &ctx.mul(&one_minus_t, &g_tabs[j][2][idx0]),
                        &ctx.mul(&t, &g_tabs[j][2][idx1]),
                    );
                    let prod = ctx.mul(&g1, &g2);
                    let diff = ctx.sub(&prod, &g3);
                    let term = ctx.mul(&alpha_powers[j], &diff);
                    combined = ctx.add(&combined, &term);
                }

                let val = ctx.mul(&eq_val, &combined);
                sum = ctx.add(&sum, &val);
            }

            evals[eval_idx as usize] = sum;
        }

        round_messages.push(crate::sumcheck::SumcheckRoundMessage { evaluations: evals });

        // Fold all tables with this round's challenge
        let r = challenges.sumcheck_challenges[round];
        let one_minus_r = ctx.sub(&ctx.one(), &r);
        let fold = |v0: &ExtFieldElement, v1: &ExtFieldElement| -> ExtFieldElement {
            ctx.add(&ctx.mul(&one_minus_r, v0), &ctx.mul(&r, v1))
        };

        let mut new_eq = Vec::with_capacity(half);
        for rest_idx in 0..half {
            new_eq.push(fold(&eq_tab[rest_idx], &eq_tab[half + rest_idx]));
        }
        eq_tab = new_eq;

        for g_tab in &mut g_tabs {
            for tab in g_tab {
                let mut new_tab = Vec::with_capacity(half);
                for rest_idx in 0..half {
                    new_tab.push(fold(&tab[rest_idx], &tab[half + rest_idx]));
                }
                *tab = new_tab;
            }
        }
    }

    let sumcheck_proof = SumcheckProof { round_messages };

    // After sumcheck, each table is folded to a single value.
    // U[i][j] = g_{i+1,j} evaluated at the sumcheck point r.
    let mut evaluation_matrix = [
        TensorElement::zero(),
        TensorElement::zero(),
        TensorElement::zero(),
    ];
    for (j, g_tab) in g_tabs.iter().enumerate() {
        for (i, tab) in g_tab.iter().enumerate() {
            assert_eq!(tab.len(), 1);
            let val = tab[0];
            evaluation_matrix[i].data[0][j] = val.c0;
            if crate::params::T > 1 {
                evaluation_matrix[i].data[1][j] = val.c1;
            }
        }
    }

    HadamardProof {
        sumcheck_proof,
        evaluation_matrix,
    }
}

/// Run the Πhad verifier.
pub fn verify(
    commitment: &Commitment,
    proof: &HadamardProof,
    challenges: &HadamardChallenges,
    ctx: &ExtFieldContext,
) -> Result<LinearRelation, HadamardError> {
    let num_vars = proof.sumcheck_proof.round_messages.len();

    let claim = SumcheckClaim {
        num_vars,
        degree: 3,
        claimed_sum: ctx.zero(),
    };

    let sumcheck_result = crate::sumcheck::verifier::verify(
        &proof.sumcheck_proof,
        &claim,
        &challenges.sumcheck_challenges,
        ctx,
    )
    .map_err(|_| HadamardError::SumcheckFailed)?;

    // Verify consistency: the claimed evaluation at the sumcheck point must equal
    // eq(s, r) · Σ_j α^{j-1} · (U[0,j] · U[1,j] − U[2,j])
    let eq_val =
        sumcheck::eq_eval_ext_sumcheck(&challenges.s, &sumcheck_result.evaluation_point, ctx);

    let mut alpha_power = ctx.one();
    let mut combined = ctx.zero();
    for j in 0..D {
        let u1 = proof.evaluation_matrix[0].col(j);
        let u2 = proof.evaluation_matrix[1].col(j);
        let u3 = proof.evaluation_matrix[2].col(j);
        let prod = ctx.mul(&u1, &u2);
        let diff = ctx.sub(&prod, &u3);
        let term = ctx.mul(&alpha_power, &diff);
        combined = ctx.add(&combined, &term);
        alpha_power = ctx.mul(&alpha_power, &challenges.alpha);
    }
    let expected = ctx.mul(&eq_val, &combined);

    if expected != sumcheck_result.claimed_evaluation {
        return Err(HadamardError::EvaluationInconsistent);
    }

    Ok(LinearRelation {
        commitment: commitment.clone(),
        evaluation_point: sumcheck_result.evaluation_point,
        evaluation_values: proof.evaluation_matrix.clone(),
    })
}

#[derive(Debug)]
pub enum HadamardError {
    SumcheckFailed,
    EvaluationInconsistent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::AjtaiParams;
    use crate::r1cs::R1CSMatrices;
    use crate::ring::RingVector;

    #[test]
    fn test_hadamard_prove_verify() {
        let q = 257u64;
        let ctx = ExtFieldContext::new(q);

        // Simple R1CS: x * x = y with 2 constraints (padded to power of 2)
        // z = [1, x, y] = [1, 3, 9]
        let m = 2; // must be power of 2
        let n = 3;
        let mut r1cs = R1CSMatrices::new(m, n, 1);
        r1cs.a.insert(0, 1, 1); // A selects x
        r1cs.b.insert(0, 1, 1); // B selects x
        r1cs.c.insert(0, 2, 1); // C selects y
                                // Row 1: trivial constraint 0*0 = 0 (padding)

        let z = vec![1i64, 3, 9];
        assert!(r1cs.is_satisfied_mod(&z, q));

        // Build witness matrix: D rows, each row is the same z
        // (in the full system, each row would be a different coefficient position)
        let mut witness_matrix = Vec::with_capacity(D);
        for j in 0..D {
            if j == 0 {
                witness_matrix.push(z.clone());
            } else {
                witness_matrix.push(vec![0i64; n]);
            }
        }

        // Create dummy commitment
        let kappa = 2;
        let ajtai = AjtaiParams::setup(kappa, n, q);
        let ring_witness = RingVector {
            elements: z
                .iter()
                .map(|&v| crate::ring::RingElement::from_constant(v))
                .collect(),
        };
        let (commitment, _) = ajtai.commit(&ring_witness);

        let challenges = HadamardChallenges {
            s: vec![ExtFieldElement { c0: 5, c1: 1 }],
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: vec![ExtFieldElement { c0: 7, c1: 3 }],
        };

        let proof = prove(&commitment, &witness_matrix, &r1cs, &challenges, &ctx);
        let result = verify(&commitment, &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πhad verify failed: {:?}", result.err());
    }

    #[test]
    fn test_hadamard_multi_constraint() {
        let q = 257u64;
        let ctx = ExtFieldContext::new(q);

        // R1CS with 4 constraints (num_vars = 2): exercises bit-order logic
        // z = [1, x, y, xy] = [1, 3, 5, 15]
        // Row 0: x * y = xy  → A selects x, B selects y, C selects xy
        // Row 1: x * 1 = x   → A selects x, B selects 1, C selects x
        // Rows 2-3: padding (0*0 = 0)
        let m = 4;
        let n = 4;
        let mut r1cs = R1CSMatrices::new(m, n, 1);
        r1cs.a.insert(0, 1, 1); // row 0: A selects x
        r1cs.b.insert(0, 2, 1); // row 0: B selects y
        r1cs.c.insert(0, 3, 1); // row 0: C selects xy
        r1cs.a.insert(1, 1, 1); // row 1: A selects x
        r1cs.b.insert(1, 0, 1); // row 1: B selects 1
        r1cs.c.insert(1, 1, 1); // row 1: C selects x

        let z = vec![1i64, 3, 5, 15];
        assert!(r1cs.is_satisfied_mod(&z, q));

        let mut witness_matrix = Vec::with_capacity(D);
        for j in 0..D {
            if j == 0 {
                witness_matrix.push(z.clone());
            } else {
                witness_matrix.push(vec![0i64; n]);
            }
        }

        let kappa = 2;
        let ajtai = AjtaiParams::setup(kappa, n, q);
        let ring_witness = RingVector {
            elements: z
                .iter()
                .map(|&v| crate::ring::RingElement::from_constant(v))
                .collect(),
        };
        let (commitment, _) = ajtai.commit(&ring_witness);

        // num_vars = log2(4) = 2 — this exercises the bit-order reversal
        let num_vars = 2;
        let challenges = HadamardChallenges {
            s: (0..num_vars)
                .map(|i| ExtFieldElement {
                    c0: 5 + i as i64,
                    c1: 1,
                })
                .collect(),
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: (0..num_vars)
                .map(|i| ExtFieldElement {
                    c0: 7 + i as i64,
                    c1: 3,
                })
                .collect(),
        };

        let proof = prove(&commitment, &witness_matrix, &r1cs, &challenges, &ctx);
        let result = verify(&commitment, &proof, &challenges, &ctx);
        assert!(
            result.is_ok(),
            "Πhad verify (num_vars=2) failed: {:?}",
            result.err()
        );
    }
}
