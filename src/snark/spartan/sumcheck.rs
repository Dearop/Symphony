//! Self-contained sumcheck protocol over Fp (Ristretto scalar field).
//!
//! This is separate from the crate's K=Fq^2 sumcheck to avoid modifying
//! existing code. The sumcheck proves:
//!   sum_{x in {0,1}^n} F(x) = claimed_sum
//! where F is a degree-d multivariate polynomial.

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

/// Proof produced by the sumcheck protocol.
#[derive(Debug, Clone)]
pub struct SumcheckProofFp {
    /// For each round i, the evaluations of the univariate polynomial
    /// g_i(X_i) at X_i = 0, 1, ..., degree.
    pub round_polys: Vec<Vec<Scalar>>,
}

/// Run the sumcheck prover for F(x) = eq(tau,x) * [Az(x)*Bz(x) - Cz(x)].
///
/// `eq_table`, `az_table`, `bz_table`, `cz_table` are each of length 2^num_vars,
/// holding the evaluations over the boolean hypercube.
///
/// Returns (proof, challenges) where challenges are the verifier's random points.
pub fn prove_r1cs_sumcheck(
    eq_table: &[Scalar],
    az_table: &[Scalar],
    bz_table: &[Scalar],
    cz_table: &[Scalar],
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> (SumcheckProofFp, Vec<Scalar>) {
    let n = 1 << num_vars;
    assert_eq!(eq_table.len(), n);
    assert_eq!(az_table.len(), n);
    assert_eq!(bz_table.len(), n);
    assert_eq!(cz_table.len(), n);

    let mut eq = eq_table.to_vec();
    let mut az = az_table.to_vec();
    let mut bz = bz_table.to_vec();
    let mut cz = cz_table.to_vec();

    let mut round_polys = Vec::with_capacity(num_vars);
    let mut challenges = Vec::with_capacity(num_vars);

    for _round in 0..num_vars {
        let half = eq.len() / 2;

        // Compute the univariate polynomial g(X) = sum_{x'} F(X, x')
        // F(x) = eq * (az * bz - cz), degree 3 in each variable.
        // We need evaluations at X = 0, 1, 2, 3.
        let mut evals = vec![Scalar::ZERO; 4];
        for j in 0..half {
            // Values at x_i = 0 (index j) and x_i = 1 (index half + j)
            let eq0 = eq[j];
            let eq1 = eq[half + j];
            let az0 = az[j];
            let az1 = az[half + j];
            let bz0 = bz[j];
            let bz1 = bz[half + j];
            let cz0 = cz[j];
            let cz1 = cz[half + j];

            // Evaluate at t = 0, 1, 2, 3
            for t in 0u64..4 {
                let t_scalar = Scalar::from(t);
                let one_minus_t = Scalar::ONE - t_scalar;

                let eq_t = eq0 * one_minus_t + eq1 * t_scalar;
                let az_t = az0 * one_minus_t + az1 * t_scalar;
                let bz_t = bz0 * one_minus_t + bz1 * t_scalar;
                let cz_t = cz0 * one_minus_t + cz1 * t_scalar;

                evals[t as usize] += eq_t * (az_t * bz_t - cz_t);
            }
        }

        // Append round polynomial to transcript
        for eval in &evals {
            transcript.extend_from_slice(&eval.to_bytes());
        }
        round_polys.push(evals);

        // Derive challenge
        let r = derive_challenge(transcript, _round);
        challenges.push(r);

        // Fold tables
        let one_minus_r = Scalar::ONE - r;
        let mut new_eq = Vec::with_capacity(half);
        let mut new_az = Vec::with_capacity(half);
        let mut new_bz = Vec::with_capacity(half);
        let mut new_cz = Vec::with_capacity(half);
        for j in 0..half {
            new_eq.push(eq[j] * one_minus_r + eq[half + j] * r);
            new_az.push(az[j] * one_minus_r + az[half + j] * r);
            new_bz.push(bz[j] * one_minus_r + bz[half + j] * r);
            new_cz.push(cz[j] * one_minus_r + cz[half + j] * r);
        }
        eq = new_eq;
        az = new_az;
        bz = new_bz;
        cz = new_cz;
    }

    (SumcheckProofFp { round_polys }, challenges)
}

/// Verify a sumcheck proof.
///
/// Returns `Ok((final_eval, challenges))` if the proof structure is consistent,
/// where `final_eval` is the claimed evaluation at the challenge point.
/// The caller must check the final evaluation against the oracle.
pub fn verify_sumcheck(
    proof: &SumcheckProofFp,
    claimed_sum: Scalar,
    num_vars: usize,
    transcript: &mut Vec<u8>,
) -> Result<(Scalar, Vec<Scalar>), &'static str> {
    if proof.round_polys.len() != num_vars {
        return Err("wrong number of rounds");
    }

    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(num_vars);

    for (round, poly) in proof.round_polys.iter().enumerate() {
        if poly.len() != 4 {
            return Err("wrong polynomial degree");
        }

        // Check: g(0) + g(1) = current_claim
        if poly[0] + poly[1] != current_claim {
            return Err("round sum check failed");
        }

        // Append to transcript (same as prover)
        for eval in poly {
            transcript.extend_from_slice(&eval.to_bytes());
        }

        // Derive challenge
        let r = derive_challenge(transcript, round);
        challenges.push(r);

        // Interpolate g(r) via Lagrange interpolation at {0, 1, 2, 3}
        current_claim = lagrange_interpolate(poly, r);
    }

    Ok((current_claim, challenges))
}

/// Lagrange interpolation of a polynomial given evaluations at {0, 1, ..., n-1}.
fn lagrange_interpolate(evals: &[Scalar], point: Scalar) -> Scalar {
    let n = evals.len();
    let mut result = Scalar::ZERO;

    for (i, eval) in evals.iter().enumerate().take(n) {
        let mut basis = Scalar::ONE;
        let xi = Scalar::from(i as u64);
        for j in 0..n {
            if i != j {
                let xj = Scalar::from(j as u64);
                basis *= (point - xj) * (xi - xj).invert();
            }
        }
        result += eval * basis;
    }

    result
}

/// Derive a Fiat-Shamir challenge from the transcript.
fn derive_challenge(transcript: &[u8], round: usize) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"spartan-sumcheck-challenge");
    hasher.update((round as u64).to_le_bytes());
    hasher.update(transcript);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Build the eq(tau, x) table for all x in {0,1}^n.
///
/// eq(tau, x) = prod_{i=0}^{n-1} (tau_i * x_i + (1 - tau_i) * (1 - x_i))
pub fn build_eq_table(tau: &[Scalar], num_vars: usize) -> Vec<Scalar> {
    let mut table = vec![Scalar::ONE];

    for ti in tau.iter().take(num_vars) {
        let old_len = table.len();
        table.resize(old_len * 2, Scalar::ZERO);
        for j in (0..old_len).rev() {
            table[2 * j + 1] = table[j] * ti;
            table[2 * j] = table[j] * (Scalar::ONE - ti);
        }
    }

    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_table_basic() {
        let tau = vec![Scalar::ZERO, Scalar::ZERO];
        let table = build_eq_table(&tau, 2);
        // eq((0,0), x) = 1 only when x = (0,0)
        assert_eq!(table[0], Scalar::ONE);
        assert_eq!(table[1], Scalar::ZERO);
        assert_eq!(table[2], Scalar::ZERO);
        assert_eq!(table[3], Scalar::ZERO);
    }

    #[test]
    fn eq_table_identity() {
        let tau = vec![Scalar::ONE, Scalar::ZERO];
        let table = build_eq_table(&tau, 2);
        // eq((1,0), x) = 1 only when x = (1,0) which is index 2
        assert_eq!(table[0], Scalar::ZERO);
        assert_eq!(table[1], Scalar::ZERO);
        assert_eq!(table[2], Scalar::ONE);
        assert_eq!(table[3], Scalar::ZERO);
    }

    #[test]
    fn sumcheck_degree3_simple() {
        // Test with a trivial case: all tables are 1s on {0,1}^2
        // F(x) = 1 * (1*1 - 1) = 0, sum = 0
        let num_vars = 2;
        let n = 1 << num_vars;
        let eq = vec![Scalar::ONE; n];
        let az = vec![Scalar::ONE; n];
        let bz = vec![Scalar::ONE; n];
        let cz = vec![Scalar::ONE; n];

        let mut transcript_p = Vec::new();
        let (proof, _challenges_p) =
            prove_r1cs_sumcheck(&eq, &az, &bz, &cz, num_vars, &mut transcript_p);

        let mut transcript_v = Vec::new();
        let result = verify_sumcheck(&proof, Scalar::ZERO, num_vars, &mut transcript_v);
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_claimed_sum_rejected() {
        let num_vars = 2;
        let n = 1 << num_vars;
        let eq = vec![Scalar::ONE; n];
        let az = vec![Scalar::ONE; n];
        let bz = vec![Scalar::ONE; n];
        let cz = vec![Scalar::ONE; n];

        let mut transcript_p = Vec::new();
        let (proof, _) = prove_r1cs_sumcheck(&eq, &az, &bz, &cz, num_vars, &mut transcript_p);

        let mut transcript_v = Vec::new();
        let result = verify_sumcheck(&proof, Scalar::ONE, num_vars, &mut transcript_v);
        assert!(result.is_err());
    }
}
