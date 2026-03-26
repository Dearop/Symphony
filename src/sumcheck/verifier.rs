//! Sumcheck verifier.

use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::sumcheck::{SumcheckClaim, SumcheckProof, SumcheckResult};

/// Verify a sumcheck proof. Returns the evaluation point and claimed evaluation
/// if the proof passes all round checks.
pub fn verify(
    proof: &SumcheckProof,
    claim: &SumcheckClaim,
    challenges: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> Result<SumcheckResult, SumcheckError> {
    if proof.round_messages.len() != claim.num_vars {
        return Err(SumcheckError::WrongNumberOfRounds);
    }
    if challenges.len() != claim.num_vars {
        return Err(SumcheckError::WrongNumberOfChallenges);
    }

    let mut current_claim = claim.claimed_sum;

    for (round, msg) in proof.round_messages.iter().enumerate() {
        if msg.evaluations.len() != claim.degree + 1 {
            return Err(SumcheckError::WrongDegree { round });
        }

        // Check: p_i(0) + p_i(1) = current_claim
        let sum = ctx.add(&msg.evaluations[0], &msg.evaluations[1]);
        if sum != current_claim {
            return Err(SumcheckError::SumCheckFailed { round });
        }

        // Evaluate p_i at the verifier's challenge r_i
        // Using Lagrange interpolation over {0, 1, ..., degree}
        current_claim = evaluate_univariate(&msg.evaluations, &challenges[round], ctx);
    }

    Ok(SumcheckResult {
        evaluation_point: challenges.to_vec(),
        claimed_evaluation: current_claim,
    })
}

/// Evaluate a univariate polynomial (given by evaluations at 0, 1, ..., d) at point r.
/// Uses Lagrange interpolation.
fn evaluate_univariate(
    evals: &[ExtFieldElement],
    r: &ExtFieldElement,
    ctx: &ExtFieldContext,
) -> ExtFieldElement {
    let n = evals.len();
    let mut result = ctx.zero();

    for i in 0..n {
        let mut basis = ctx.one();
        for j in 0..n {
            if i == j {
                continue;
            }
            let i_elem = ExtFieldElement {
                c0: i as i64,
                c1: 0,
            };
            let j_elem = ExtFieldElement {
                c0: j as i64,
                c1: 0,
            };
            // basis *= (r - j) / (i - j)
            let num = ctx.sub(r, &j_elem);
            let den = ctx.sub(&i_elem, &j_elem);
            let den_inv = ctx.inv(&den).expect("distinct evaluation points");
            basis = ctx.mul(&basis, &ctx.mul(&num, &den_inv));
        }
        result = ctx.add(&result, &ctx.mul(&evals[i], &basis));
    }

    result
}

#[derive(Debug)]
pub enum SumcheckError {
    WrongNumberOfRounds,
    WrongNumberOfChallenges,
    WrongDegree { round: usize },
    SumCheckFailed { round: usize },
}
