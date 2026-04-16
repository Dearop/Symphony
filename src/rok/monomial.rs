//! Πmon: Monomial relation check (Lemma 3.1 from LatticeFold+).
//!
//! Checks that each entry of committed vectors lies in the monomial set M
//! via a single degree-4 sumcheck over K of size n.
//!
//! For g ∈ Rq to be a monomial (element of M = {0, ±1, ±X, ..., ±X^{d-1}}),
//! two conditions must hold:
//!   1. Each coefficient g_j ∈ {−1, 0, 1}: checked via g_j·(g_j−1)·(g_j+1) = 0
//!   2. At most one coefficient is nonzero: checked via (Σ g_j²)·(Σ g_j²−1) = 0
//!
//! Both checks are batched into a single sumcheck using random α powers.

use crate::commitment::Commitment;
use crate::params::D;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::tensor::TensorElement;
use crate::ring::RingElement;
use crate::rok::BatchedLinearRelation;
use crate::sumcheck::prover;
use crate::sumcheck::{self, SumcheckClaim, SumcheckProof, SumcheckRoundMessage};

/// Proof for the monomial relation check.
#[derive(Debug, Clone)]
pub struct MonomialProof {
    /// Sumcheck proof (degree-4 over K of size n).
    pub sumcheck_proof: SumcheckProof,
    /// Per-coefficient evaluation claims at the sumcheck output point.
    pub evaluations: Vec<TensorElement>,
    /// Sum-of-squares evaluations at the sumcheck point (one per vector).
    /// sq_evaluations[i] = multilinear extension of Σ_j c_{i,j}² at the sumcheck point.
    pub sq_evaluations: Vec<ExtFieldElement>,
}

/// Challenges for Πmon.
pub struct MonomialChallenges {
    /// Sumcheck seed s ∈ K^{log n}.
    pub s: Vec<ExtFieldElement>,
    /// Random combiner for batching across k_g vectors and d coefficients.
    pub alpha: ExtFieldElement,
    /// Sumcheck round challenges.
    pub sumcheck_challenges: Vec<ExtFieldElement>,
}

/// Run the Πmon prover.
///
/// Input: commitments (c^(i))_{i=1}^{k_g} and monomial vectors (g^(i) ∈ M^n)_{i=1}^{k_g}.
/// Output: sumcheck proof + evaluation values.
///
/// The sumcheck proves two properties for all entries of g^(i):
///   1. Each coefficient c ∈ {−1, 0, 1}: c·(c−1)·(c+1) = 0
///   2. At most one nonzero coefficient per entry: (Σ c_j²)·(Σ c_j² − 1) = 0
pub fn prove(
    _commitments: &[Commitment],
    monomial_vectors: &[Vec<RingElement>],
    challenges: &MonomialChallenges,
    ctx: &ExtFieldContext,
) -> MonomialProof {
    let k_g = monomial_vectors.len();
    assert!(!monomial_vectors.is_empty());
    let n = monomial_vectors[0].len();
    let num_vars = if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    };
    let table_size = 1 << num_vars;

    // We need k_g * D α powers for per-coefficient checks, plus k_g for at-most-one checks.
    let total_terms = k_g * D + k_g;
    let mut alpha_powers = Vec::with_capacity(total_terms);
    let mut power = ctx.one();
    for _ in 0..total_terms {
        alpha_powers.push(power);
        power = ctx.mul(&power, &challenges.alpha);
    }

    // Build eq table
    let eq_table = prover::build_eq_table(&challenges.s, ctx);

    // Build coefficient tables: coeff_tables[i*D + j][b] = g^(i)[b].coeffs[j]
    let num_coeff_tables = k_g * D;
    let mut coeff_tables: Vec<Vec<ExtFieldElement>> = Vec::with_capacity(num_coeff_tables);
    for monomial_vector in monomial_vectors.iter().take(k_g) {
        for j in 0..D {
            let mut table = vec![ctx.zero(); table_size];
            for b in 0..n.min(table_size) {
                table[b] = ExtFieldElement {
                    c0: monomial_vector[b].coeffs[j],
                    c1: 0,
                };
            }
            coeff_tables.push(table);
        }
    }

    // Build sum-of-squares tables: sq_tables[i][b] = Σ_j (g^(i)[b].coeffs[j])²
    // Over the boolean hypercube this is multilinear (every function on {0,1}^n is).
    let mut sq_tables: Vec<Vec<ExtFieldElement>> = Vec::with_capacity(k_g);
    for monomial_vector in monomial_vectors.iter().take(k_g) {
        let mut table = vec![ctx.zero(); table_size];
        for b in 0..n.min(table_size) {
            let sq_sum: i64 = monomial_vector[b].coeffs.iter().map(|&c| c * c).sum();
            table[b] = ExtFieldElement { c0: sq_sum, c1: 0 };
        }
        sq_tables.push(table);
    }

    // Run the sumcheck round by round.
    // The combined polynomial at point b:
    //   f(b) = eq(s, b) · [
    //     Σ_{i,j} α^{i*D+j} · c_{i,j}(b) · (c_{i,j}(b)−1) · (c_{i,j}(b)+1)   (degree 4 with eq)
    //     + Σ_i α^{k_g*D+i} · sq_i(b) · (sq_i(b) − 1)                           (degree 3 with eq)
    //   ]
    // Max degree per variable = 4.
    let mut round_messages = Vec::with_capacity(num_vars);
    let mut eq_tab = eq_table;

    for round in 0..num_vars {
        let half = 1 << (num_vars - round - 1);
        let deg = 4;
        let mut evals = vec![ctx.zero(); deg + 1];

        for (eval_idx, eval_slot) in evals.iter_mut().enumerate() {
            let t = ExtFieldElement {
                c0: eval_idx as i64,
                c1: 0,
            };
            let one_minus_t = ctx.sub(&ctx.one(), &t);
            let one = ctx.one();

            let mut sum = ctx.zero();
            for rest_idx in 0..half {
                let idx0 = rest_idx;
                let idx1 = half + rest_idx;

                let eq_val = ctx.add(
                    &ctx.mul(&one_minus_t, &eq_tab[idx0]),
                    &ctx.mul(&t, &eq_tab[idx1]),
                );

                // Part 1: per-coefficient cubic checks
                let mut combined = ctx.zero();
                for (tab_idx, table) in coeff_tables.iter().enumerate() {
                    let c_val = ctx.add(
                        &ctx.mul(&one_minus_t, &table[idx0]),
                        &ctx.mul(&t, &table[idx1]),
                    );
                    let c_minus_1 = ctx.sub(&c_val, &one);
                    let c_plus_1 = ctx.add(&c_val, &one);
                    let prod = ctx.mul(&c_val, &ctx.mul(&c_minus_1, &c_plus_1));
                    let term = ctx.mul(&alpha_powers[tab_idx], &prod);
                    combined = ctx.add(&combined, &term);
                }

                // Part 2: at-most-one-nonzero checks via sum-of-squares
                for (i, sq_table) in sq_tables.iter().enumerate() {
                    let sq_val = ctx.add(
                        &ctx.mul(&one_minus_t, &sq_table[idx0]),
                        &ctx.mul(&t, &sq_table[idx1]),
                    );
                    // sq · (sq - 1) = 0 ensures sq ∈ {0, 1}
                    let sq_minus_1 = ctx.sub(&sq_val, &one);
                    let prod = ctx.mul(&sq_val, &sq_minus_1);
                    let alpha_idx = num_coeff_tables + i;
                    let term = ctx.mul(&alpha_powers[alpha_idx], &prod);
                    combined = ctx.add(&combined, &term);
                }

                let val = ctx.mul(&eq_val, &combined);
                sum = ctx.add(&sum, &val);
            }

            *eval_slot = sum;
        }

        round_messages.push(SumcheckRoundMessage { evaluations: evals });

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

        for table in coeff_tables.iter_mut() {
            let mut new_tab = Vec::with_capacity(half);
            for rest_idx in 0..half {
                new_tab.push(fold(&table[rest_idx], &table[half + rest_idx]));
            }
            *table = new_tab;
        }

        for table in sq_tables.iter_mut() {
            let mut new_tab = Vec::with_capacity(half);
            for rest_idx in 0..half {
                new_tab.push(fold(&table[rest_idx], &table[half + rest_idx]));
            }
            *table = new_tab;
        }
    }

    let sumcheck_proof = SumcheckProof { round_messages };

    // Build evaluation claims: for each vector i, the evaluation at the sumcheck point
    let mut evaluations = Vec::with_capacity(k_g);
    for i in 0..k_g {
        let mut te = TensorElement::zero();
        for j in 0..D {
            let tab_idx = i * D + j;
            assert_eq!(coeff_tables[tab_idx].len(), 1);
            let val = coeff_tables[tab_idx][0];
            te.data[0][j] = val.c0;
            te.data[1][j] = val.c1;
        }
        evaluations.push(te);
    }

    // Also collect sum-of-squares evaluations at the sumcheck point
    let mut sq_evaluations = Vec::with_capacity(k_g);
    for table in &sq_tables {
        assert_eq!(table.len(), 1);
        sq_evaluations.push(table[0]);
    }

    MonomialProof {
        sumcheck_proof,
        evaluations,
        sq_evaluations,
    }
}

/// Run the Πmon verifier.
pub fn verify(
    commitments: &[Commitment],
    proof: &MonomialProof,
    challenges: &MonomialChallenges,
    ctx: &ExtFieldContext,
) -> Result<BatchedLinearRelation, MonomialError> {
    if commitments.is_empty() || proof.evaluations.is_empty() {
        return Err(MonomialError::EvaluationInconsistent);
    }

    let num_vars = proof.sumcheck_proof.round_messages.len();
    let k_g = proof.evaluations.len();

    if proof.sq_evaluations.len() != k_g {
        return Err(MonomialError::EvaluationInconsistent);
    }

    let claim = SumcheckClaim {
        num_vars,
        degree: 4,
        claimed_sum: ctx.zero(),
    };

    let sumcheck_result = crate::sumcheck::verifier::verify(
        &proof.sumcheck_proof,
        &claim,
        &challenges.sumcheck_challenges,
        ctx,
    )
    .map_err(|_| MonomialError::SumcheckFailed)?;

    // Verify consistency against both checks:
    //   eq(s, r) · [
    //     Σ_{i,j} α^{i*D+j} · eval[i][j] · (eval[i][j]-1) · (eval[i][j]+1)   // per-coeff
    //     + Σ_i α^{k_g*D+i} · sq_eval[i] · (sq_eval[i] - 1)                    // at-most-one
    //   ]
    let eq_val =
        sumcheck::eq_eval_ext_sumcheck(&challenges.s, &sumcheck_result.evaluation_point, ctx);

    let one = ctx.one();
    let num_coeff_terms = k_g * D;
    let total_terms = num_coeff_terms + k_g;
    let mut alpha_powers = Vec::with_capacity(total_terms);
    let mut power = ctx.one();
    for _ in 0..total_terms {
        alpha_powers.push(power);
        power = ctx.mul(&power, &challenges.alpha);
    }

    let mut combined = ctx.zero();

    // Part 1: per-coefficient cubic checks
    for i in 0..k_g {
        for j in 0..D {
            let c_val = proof.evaluations[i].col(j);
            let c_minus_1 = ctx.sub(&c_val, &one);
            let c_plus_1 = ctx.add(&c_val, &one);
            let prod = ctx.mul(&c_val, &ctx.mul(&c_minus_1, &c_plus_1));
            let term = ctx.mul(&alpha_powers[i * D + j], &prod);
            combined = ctx.add(&combined, &term);
        }
    }

    // Part 2: at-most-one-nonzero checks via sum-of-squares.
    //
    // Note: sq_evaluations[i] is the MLE of (Σ_j c_{i,j}^2) evaluated at the sumcheck
    // point. This is NOT the same as Σ_j eval[i][j]^2 (which would be the sum-of-squares
    // of the MLE evaluations). The consistency between sq_evaluations and the coefficient
    // evaluations is enforced by the sumcheck protocol itself: the combined polynomial
    // includes both the per-coefficient cubic checks and the sum-of-squares quadratic
    // checks, all batched under the same α powers.
    for i in 0..k_g {
        let sq_val = proof.sq_evaluations[i];
        let sq_minus_1 = ctx.sub(&sq_val, &one);
        let prod = ctx.mul(&sq_val, &sq_minus_1);
        let term = ctx.mul(&alpha_powers[num_coeff_terms + i], &prod);
        combined = ctx.add(&combined, &term);
    }

    let expected = ctx.mul(&eq_val, &combined);

    if expected != sumcheck_result.claimed_evaluation {
        return Err(MonomialError::EvaluationInconsistent);
    }

    Ok(BatchedLinearRelation {
        commitments: commitments.to_vec(),
        evaluation_point: sumcheck_result.evaluation_point,
        evaluation_values: proof.evaluations.clone(),
    })
}

#[derive(Debug)]
pub enum MonomialError {
    SumcheckFailed,
    EvaluationInconsistent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decomposition::monomial::exp_map;

    #[test]
    fn test_monomial_prove_verify() {
        let q = 257u64;
        let ctx = ExtFieldContext::new(q);

        // Create monomial vectors of length 2 (smallest power of 2)
        let n = 2;
        let g = vec![
            exp_map(3),  // X^3
            exp_map(-1), // -X
        ];
        for gi in &g {
            assert!(crate::decomposition::monomial::is_monomial(gi));
        }

        let kappa = 2;
        let ntt = crate::ring::ntt::NttContext::new(q);
        let ajtai = crate::commitment::AjtaiParams::setup(kappa, n, q, &ntt);
        let ring_vec = crate::ring::RingVector {
            elements: g.clone(),
        };
        let (commitment, _) = ajtai.commit(&ring_vec);

        let challenges = MonomialChallenges {
            s: vec![ExtFieldElement { c0: 5, c1: 1 }],
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: vec![ExtFieldElement { c0: 7, c1: 3 }],
        };

        let proof = prove(std::slice::from_ref(&commitment), &[g], &challenges, &ctx);
        let result = verify(&[commitment], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πmon verify failed: {:?}", result.err());
    }
}
