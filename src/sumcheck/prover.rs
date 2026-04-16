//! Sumcheck prover, including a bookkeeping-table-based approach and streaming variant.

use crate::ring::extension::{ExtFieldContext, ExtFieldElement};
use crate::sumcheck::{SumcheckClaim, SumcheckProof, SumcheckRoundMessage};

/// Trait for providing polynomial evaluations to the sumcheck prover.
///
/// Implementations can be either:
/// - Materialized: all evaluations stored in memory
/// - Streaming: evaluations computed on-the-fly (Remark 4.1 / [Baw+25])
pub trait SumcheckPolynomial {
    /// Evaluate the polynomial at a partial assignment.
    fn evaluate_partial_sum(
        &self,
        fixed: &[ExtFieldElement],
        eval_point: &ExtFieldElement,
        ctx: &ExtFieldContext,
    ) -> ExtFieldElement;

    /// Compute the round polynomial: for the current round variable X_i,
    /// return evaluations at 0, 1, ..., degree.
    fn compute_round_polynomial(
        &self,
        round: usize,
        challenges_so_far: &[ExtFieldElement],
        degree: usize,
        ctx: &ExtFieldContext,
    ) -> Vec<ExtFieldElement>;
}

/// Run the sumcheck prover given a polynomial oracle.
pub fn prove<P: SumcheckPolynomial>(
    poly: &P,
    claim: &SumcheckClaim,
    challenges: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> SumcheckProof {
    assert_eq!(
        challenges.len(),
        claim.num_vars,
        "must provide one verifier challenge per round"
    );

    let mut round_messages = Vec::with_capacity(claim.num_vars);
    let mut challenges_so_far = Vec::with_capacity(claim.num_vars);

    for (round, &challenge) in challenges.iter().enumerate() {
        let evaluations =
            poly.compute_round_polynomial(round, &challenges_so_far, claim.degree, ctx);
        round_messages.push(SumcheckRoundMessage { evaluations });
        challenges_so_far.push(challenge);
    }

    SumcheckProof { round_messages }
}

/// Bookkeeping-table-based sumcheck prover for degree-d polynomials.
///
/// Maintains separate tables for each multilinear factor and a combiner function
/// that multiplies/combines them to form the degree-d polynomial.
///
/// `factor_tables[k][b]` is the evaluation of the k-th multilinear factor at point b
/// (indexed over the boolean hypercube of remaining variables).
///
/// `combiner` takes one value from each factor and produces the polynomial evaluation.
pub fn prove_bookkeeping(
    factor_tables: &mut [Vec<ExtFieldElement>],
    combiner: &dyn Fn(&[ExtFieldElement], &ExtFieldContext) -> ExtFieldElement,
    num_vars: usize,
    degree: usize,
    challenges: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> SumcheckProof {
    assert_eq!(challenges.len(), num_vars);

    let mut round_messages = Vec::with_capacity(num_vars);
    let mut factor_vals = vec![ctx.zero(); factor_tables.len()];

    for (round, &r) in challenges.iter().enumerate() {
        let half = 1 << (num_vars - round - 1);
        let mut evals = vec![ctx.zero(); degree + 1];

        for (eval_idx, eval) in evals.iter_mut().enumerate() {
            let t = ExtFieldElement {
                c0: eval_idx as i64,
                c1: 0,
            };
            let one_minus_t = ctx.sub(&ctx.one(), &t);

            let mut sum = ctx.zero();
            for rest_idx in 0..half {
                let idx0 = rest_idx;
                let idx1 = half + rest_idx;

                for (k, table) in factor_tables.iter().enumerate() {
                    let v0 = table[idx0];
                    let v1 = table[idx1];
                    factor_vals[k] = match eval_idx {
                        0 => v0,
                        1 => v1,
                        _ => ctx.add(&ctx.mul(&one_minus_t, &v0), &ctx.mul(&t, &v1)),
                    };
                }

                let val = combiner(&factor_vals, ctx);
                sum = ctx.add(&sum, &val);
            }

            *eval = sum;
        }

        round_messages.push(SumcheckRoundMessage { evaluations: evals });

        // Fold tables with the challenge for this round
        let one_minus_r = ctx.sub(&ctx.one(), &r);
        for table in factor_tables.iter_mut() {
            let mut new_table = Vec::with_capacity(half);
            for rest_idx in 0..half {
                let v0 = table[rest_idx];
                let v1 = table[half + rest_idx];
                let folded = ctx.add(&ctx.mul(&one_minus_r, &v0), &ctx.mul(&r, &v1));
                new_table.push(folded);
            }
            *table = new_table;
        }
    }

    SumcheckProof { round_messages }
}

/// Build the eq(s, ·) bookkeeping table over {0,1}^n.
pub fn build_eq_table(s: &[ExtFieldElement], ctx: &ExtFieldContext) -> Vec<ExtFieldElement> {
    let n = s.len();
    let size = 1 << n;
    let mut table = vec![ctx.one(); size];

    // eq(s, b) = Π_i (s_i · b_i + (1-s_i)(1-b_i))
    // Build incrementally: after processing variable i, entries 0..2^{i+1}
    // hold eq evaluated over all combinations of variables 0..i.
    // Bit i of the index corresponds to variable i (little-endian).
    for (i, si) in s.iter().enumerate() {
        let stride = 1 << i;
        let one_minus_si = ctx.sub(&ctx.one(), si);
        for j in (0..stride).rev() {
            let base = table[j];
            table[j + stride] = ctx.mul(&base, si); // b_i = 1
            table[j] = ctx.mul(&base, &one_minus_si); // b_i = 0
        }
    }

    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumcheck;

    #[test]
    fn test_eq_table() {
        let ctx = ExtFieldContext::new(257);
        let s = vec![
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 7, c1: 0 },
        ];
        let table = build_eq_table(&s, &ctx);
        assert_eq!(table.len(), 4);

        for (idx, actual) in table.iter().enumerate().take(4) {
            let bits = sumcheck::index_to_bits(idx, 2);
            let expected = sumcheck::eq_eval(&s, &bits, &ctx);
            assert_eq!(*actual, expected, "mismatch at idx={idx}");
        }
    }

    #[test]
    fn test_bookkeeping_sumcheck_degree1() {
        let ctx = ExtFieldContext::new(257);
        let n = 2;

        // Sumcheck of f(b) = eq(s, b) · g(b) where g is multilinear
        let s = vec![
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 7, c1: 0 },
        ];
        let g_table = vec![
            ExtFieldElement { c0: 1, c1: 0 },
            ExtFieldElement { c0: 2, c1: 0 },
            ExtFieldElement { c0: 3, c1: 0 },
            ExtFieldElement { c0: 4, c1: 0 },
        ];

        let eq_table = build_eq_table(&s, &ctx);

        // Compute claimed sum directly
        let mut claimed_sum = ctx.zero();
        for idx in 0..4 {
            let val = ctx.mul(&eq_table[idx], &g_table[idx]);
            claimed_sum = ctx.add(&claimed_sum, &val);
        }

        let challenges = vec![
            ExtFieldElement { c0: 5, c1: 1 },
            ExtFieldElement { c0: 11, c1: 2 },
        ];

        let combiner = |factors: &[ExtFieldElement], ctx: &ExtFieldContext| -> ExtFieldElement {
            ctx.mul(&factors[0], &factors[1])
        };

        let mut tables = vec![eq_table, g_table];
        let proof = prove_bookkeeping(&mut tables, &combiner, n, 2, &challenges, &ctx);

        // Verify
        let claim = sumcheck::SumcheckClaim {
            num_vars: n,
            degree: 2,
            claimed_sum,
        };
        let result = sumcheck::verifier::verify(&proof, &claim, &challenges, &ctx);
        assert!(
            result.is_ok(),
            "sumcheck verification failed: {:?}",
            result.err()
        );
    }
}
