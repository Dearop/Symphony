//! Sumcheck protocol over the extension field K.

pub mod prover;
pub mod verifier;

use crate::ring::extension::{ExtFieldContext, ExtFieldElement};

/// A single round message in the sumcheck protocol:
/// a univariate polynomial of degree ≤ deg evaluated at a few points.
#[derive(Debug, Clone)]
pub struct SumcheckRoundMessage {
    /// Evaluations of the round polynomial at 0, 1, ..., degree.
    pub evaluations: Vec<ExtFieldElement>,
}

/// Complete sumcheck proof (all round messages).
#[derive(Debug, Clone)]
pub struct SumcheckProof {
    pub round_messages: Vec<SumcheckRoundMessage>,
}

/// Sumcheck claim: the prover claims that
/// Σ_{b ∈ {0,1}^n} f(b) = claimed_sum
#[derive(Debug, Clone)]
pub struct SumcheckClaim {
    /// Number of variables (sumcheck runs for this many rounds).
    pub num_vars: usize,
    /// Maximum degree of the polynomial in each variable.
    pub degree: usize,
    /// The claimed sum.
    pub claimed_sum: ExtFieldElement,
}

/// Result of sumcheck verification: the evaluation point and the claimed evaluation.
#[derive(Debug, Clone)]
pub struct SumcheckResult {
    /// The random evaluation point r chosen during verification.
    pub evaluation_point: Vec<ExtFieldElement>,
    /// The claimed value f(r).
    pub claimed_evaluation: ExtFieldElement,
}

/// Evaluate the multilinear equality polynomial eq(s, x) = Π_{i} (s_i · x_i + (1 - s_i)(1 - x_i))
/// at a specific point in the boolean hypercube.
///
/// For b ∈ {0,1}^n, eq(s, b) = Π_i s_i^{b_i} · (1 - s_i)^{1 - b_i}.
pub fn eq_eval(s: &[ExtFieldElement], b: &[bool], ctx: &ExtFieldContext) -> ExtFieldElement {
    assert_eq!(s.len(), b.len());
    let one = ctx.one();
    let mut result = ctx.one();
    for (si, &bi) in s.iter().zip(b.iter()) {
        let factor = if bi { *si } else { ctx.sub(&one, si) };
        result = ctx.mul(&result, &factor);
    }
    result
}

/// Evaluate eq(s, r) where r ∈ K^n (both arguments are field elements).
pub fn eq_eval_ext(
    s: &[ExtFieldElement],
    r: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> ExtFieldElement {
    assert_eq!(s.len(), r.len());
    let one = ctx.one();
    let mut result = ctx.one();
    for (si, ri) in s.iter().zip(r.iter()) {
        // eq_i = s_i · r_i + (1 - s_i)(1 - r_i)
        let sr = ctx.mul(si, ri);
        let one_minus_s = ctx.sub(&one, si);
        let one_minus_r = ctx.sub(&one, ri);
        let complement = ctx.mul(&one_minus_s, &one_minus_r);
        let factor = ctx.add(&sr, &complement);
        result = ctx.mul(&result, &factor);
    }
    result
}

/// Evaluate eq(s, r) where r comes from a sumcheck that folds MSB-first.
///
/// `build_eq_table` uses little-endian bit order, but sumcheck rounds fold
/// from MSB to LSB. This helper reverses the evaluation point before calling
/// `eq_eval_ext` so callers don't need to do it manually.
pub fn eq_eval_ext_sumcheck(
    s: &[ExtFieldElement],
    sumcheck_point: &[ExtFieldElement],
    ctx: &ExtFieldContext,
) -> ExtFieldElement {
    let n = s.len().min(sumcheck_point.len());
    let r_rev: Vec<_> = sumcheck_point[..n].iter().rev().cloned().collect();
    eq_eval_ext(&s[..n], &r_rev, ctx)
}

/// Convert a usize index to a boolean vector of given length (little-endian).
pub fn index_to_bits(idx: usize, num_bits: usize) -> Vec<bool> {
    (0..num_bits).map(|i| (idx >> i) & 1 == 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_eval_identity() {
        let ctx = ExtFieldContext::new(257);
        let s = vec![
            ExtFieldElement { c0: 1, c1: 0 },
            ExtFieldElement { c0: 0, c1: 0 },
        ];
        // eq(s, (1,0)) should be s[0] * (1 - s[1]) = 1
        assert_eq!(eq_eval(&s, &[true, false], &ctx), ctx.one());
        // eq(s, (0,0)) should be (1 - s[0]) * (1 - s[1]) = 0
        assert_eq!(eq_eval(&s, &[false, false], &ctx), ctx.zero());
    }

    #[test]
    fn test_eq_sums_to_one() {
        let ctx = ExtFieldContext::new(257);
        let s = vec![
            ExtFieldElement { c0: 3, c1: 1 },
            ExtFieldElement { c0: 7, c1: 2 },
        ];
        let mut total = ctx.zero();
        for idx in 0..4 {
            let bits = index_to_bits(idx, 2);
            total = ctx.add(&total, &eq_eval(&s, &bits, &ctx));
        }
        assert_eq!(total, ctx.one());
    }
}
