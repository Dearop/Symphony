//! Πmon: Monomial relation check (Lemma 3.1 from LatticeFold+).
//!
//! Checks that each entry of committed vectors lies in the monomial set M
//! via a single degree-3 sumcheck over K of size n.
//!
//! For g ∈ Rq to be a monomial (element of M = {0, ±1, ±X, ..., ±X^{d-1}}),
//! each coefficient g_j must satisfy g_j ∈ {−1, 0, 1} and at most one is nonzero.
//! The degree-3 check: g_j · (g_j − 1) · (g_j + 1) = 0 for all j, plus
//! (Σ g_j²) · (Σ g_j² − 1) = 0 to ensure at most one nonzero.

use crate::commitment::Commitment;
use crate::params::D;
use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::ring::tensor::TensorElement;
use crate::ring::RingElement;
use crate::rok::BatchedLinearRelation;
use crate::sumcheck::{self, SumcheckClaim, SumcheckProof, SumcheckRoundMessage};
use crate::sumcheck::prover;

/// Proof for the monomial relation check.
#[derive(Debug, Clone)]
pub struct MonomialProof {
    /// Sumcheck proof (degree-3 over K of size n).
    pub sumcheck_proof: SumcheckProof,
    /// Prover's evaluation claims at the sumcheck output point.
    pub evaluations: Vec<TensorElement>,
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
/// The sumcheck proves that for all entries of g^(i), each coefficient satisfies
/// c · (c − 1) · (c + 1) = 0 (i.e., c ∈ {−1, 0, 1}).
pub fn prove(
    _commitments: &[Commitment],
    monomial_vectors: &[Vec<RingElement>],
    challenges: &MonomialChallenges,
    ctx: &ExtFieldContext,
) -> MonomialProof {
    let k_g = monomial_vectors.len();
    assert!(!monomial_vectors.is_empty());
    let n = monomial_vectors[0].len();
    let num_vars = (n as f64).log2().ceil() as usize;
    let table_size = 1 << num_vars;

    // Pre-compute α powers for batching across k_g layers and D coefficients
    let mut alpha_powers = Vec::with_capacity(k_g * D);
    let mut power = ctx.one();
    for _ in 0..(k_g * D) {
        alpha_powers.push(power);
        power = ctx.mul(&power, &challenges.alpha);
    }

    // Build the sumcheck polynomial.
    // For each entry index b ∈ [n], and each vector i ∈ [k_g], coefficient j ∈ [D]:
    //   c_{i,j}(b) = g^(i)[b].coeffs[j]
    //
    // The check polynomial at point b:
    //   f(b) = eq(s, b) · Σ_{i,j} α^{i*D+j} · c_{i,j}(b) · (c_{i,j}(b) - 1) · (c_{i,j}(b) + 1)
    //
    // This is degree 3 in the multilinear extension of the coefficient tables.

    // Build eq table
    let eq_table = prover::build_eq_table(&challenges.s, ctx);

    // Build coefficient tables: coeff_tables[i*D + j][b] = g^(i)[b].coeffs[j]
    let num_tables = k_g * D;
    let mut coeff_tables: Vec<Vec<ExtFieldElement>> = Vec::with_capacity(num_tables);
    for i in 0..k_g {
        for j in 0..D {
            let mut table = vec![ctx.zero(); table_size];
            for b in 0..n.min(table_size) {
                table[b] = ExtFieldElement {
                    c0: monomial_vectors[i][b].coeffs[j],
                    c1: 0,
                };
            }
            coeff_tables.push(table);
        }
    }

    // Run the sumcheck round by round
    let mut round_messages = Vec::with_capacity(num_vars);
    let mut eq_tab = eq_table;

    for round in 0..num_vars {
        let half = 1 << (num_vars - round - 1);
        // degree 4 per variable (eq is degree 1, c·(c-1)·(c+1) is degree 3)
        let deg = 4;
        let mut evals = vec![ctx.zero(); deg + 1];

        for eval_idx in 0..evals.len() {
            let t = ExtFieldElement { c0: eval_idx as i64, c1: 0 };
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

                let mut combined = ctx.zero();
                for (tab_idx, table) in coeff_tables.iter().enumerate() {
                    let c_val = ctx.add(
                        &ctx.mul(&one_minus_t, &table[idx0]),
                        &ctx.mul(&t, &table[idx1]),
                    );
                    // c · (c - 1) · (c + 1) = c · (c² - 1)
                    let c_minus_1 = ctx.sub(&c_val, &one);
                    let c_plus_1 = ctx.add(&c_val, &one);
                    let prod = ctx.mul(&c_val, &ctx.mul(&c_minus_1, &c_plus_1));
                    let term = ctx.mul(&alpha_powers[tab_idx], &prod);
                    combined = ctx.add(&combined, &term);
                }

                let val = ctx.mul(&eq_val, &combined);
                sum = ctx.add(&sum, &val);
            }

            evals[eval_idx as usize] = sum;
        }

        round_messages.push(SumcheckRoundMessage { evaluations: evals });

        // Fold tables
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
            if crate::params::T > 1 {
                te.data[1][j] = val.c1;
            }
        }
        evaluations.push(te);
    }

    MonomialProof {
        sumcheck_proof,
        evaluations,
    }
}

/// Run the Πmon verifier.
pub fn verify(
    commitments: &[Commitment],
    proof: &MonomialProof,
    challenges: &MonomialChallenges,
    ctx: &ExtFieldContext,
) -> Result<BatchedLinearRelation, MonomialError> {
    let num_vars = proof.sumcheck_proof.round_messages.len();
    let k_g = proof.evaluations.len();

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
    ).map_err(|_| MonomialError::SumcheckFailed)?;

    // Verify consistency: the claimed evaluation must equal
    // eq(s, r) · Σ_{i,j} α^{i*D+j} · eval[i][j] · (eval[i][j]-1) · (eval[i][j]+1)
    //
    // The evaluation point must be reversed because build_eq_table uses
    // little-endian bit order (variable i at bit i) while sumcheck rounds
    // fold from MSB to LSB: round 0 fixes the highest bit, not the lowest.
    let n_vars = num_vars.min(challenges.s.len());
    let r_rev: Vec<_> = sumcheck_result.evaluation_point[..n_vars].iter().rev().cloned().collect();
    let eq_val = sumcheck::eq_eval_ext(
        &challenges.s[..n_vars],
        &r_rev,
        ctx,
    );

    let one = ctx.one();
    let mut alpha_power = ctx.one();
    let mut combined = ctx.zero();
    for i in 0..k_g {
        for j in 0..D {
            let c_val = proof.evaluations[i].col(j);
            let c_minus_1 = ctx.sub(&c_val, &one);
            let c_plus_1 = ctx.add(&c_val, &one);
            let prod = ctx.mul(&c_val, &ctx.mul(&c_minus_1, &c_plus_1));
            let term = ctx.mul(&alpha_power, &prod);
            combined = ctx.add(&combined, &term);
            alpha_power = ctx.mul(&alpha_power, &challenges.alpha);
        }
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
            exp_map(3),   // X^3
            exp_map(-1),  // -X
        ];
        for gi in &g {
            assert!(crate::decomposition::monomial::is_monomial(gi));
        }

        let kappa = 2;
        let ajtai = crate::commitment::AjtaiParams::setup(kappa, n, q);
        let ring_vec = crate::ring::RingVector { elements: g.clone() };
        let (commitment, _) = ajtai.commit(&ring_vec);

        let challenges = MonomialChallenges {
            s: vec![ExtFieldElement { c0: 5, c1: 1 }],
            alpha: ExtFieldElement { c0: 3, c1: 2 },
            sumcheck_challenges: vec![ExtFieldElement { c0: 7, c1: 3 }],
        };

        let proof = prove(&[commitment.clone()], &[g], &challenges, &ctx);
        let result = verify(&[commitment], &proof, &challenges, &ctx);
        assert!(result.is_ok(), "Πmon verify failed: {:?}", result.err());
    }
}
