//! Monomial embedding: Exp() mapping and table polynomial t(X).
//!
//! The monomial set M = {0, 1, X, X^2, ..., X^{d-1}} ⊆ Rq.
//!
//! Key property (Lemma 2.1): for all a ∈ (−d/2, d/2) and b ∈ Exp(a),
//! ct(b · t(X)) = a.

use crate::params::D;
use crate::ring::RingElement;

/// The table polynomial t(X) = Σ_{i ∈ [1, d/2)} i · (X^i + X^{d−i}).
///
/// Since X^d = −1, we have X^{−i} = −X^{d−i}, but the paper defines
/// X^{−i} = X^{d−i} since we work modulo X^d + 1.
pub fn table_polynomial(_q: u64) -> RingElement {
    let mut coeffs = [0i64; D];
    let half_d = D / 2;
    // ct(X^a · t(X)) = a requires negated coefficients because X^d = -1.
    // X^a · (i · X^{d-a}) = i · X^d = -i, so we need coefficients -i
    // to get ct(X^a · t(X)) = +a.
    for i in 1..half_d {
        coeffs[i] = -(i as i64);
        coeffs[D - i] = -(i as i64);
    }
    RingElement { coeffs }
}

/// The monomial embedding Exp(a) for a ∈ (−d/2, d/2).
///
/// Exp(a) = sgn(a) · X^{|a|}   for a ≠ 0
/// Exp(0) ∈ {0, 1, X^{d/2}}    (multi-valued at zero)
///
/// Returns one canonical representative.
pub fn exp_map(a: i64) -> RingElement {
    let half_d = (D / 2) as i64;
    assert!(
        a > -half_d && a < half_d,
        "exp_map: a={a} out of range (−{half_d}, {half_d})"
    );

    if a == 0 {
        // Convention: Exp(0) = 0 (the zero ring element)
        return RingElement::zero();
    }

    let abs_a = a.unsigned_abs() as usize;
    let sign = if a > 0 { 1i64 } else { -1i64 };

    let mut coeffs = [0i64; D];
    coeffs[abs_a] = sign;
    RingElement { coeffs }
}

/// Verify the monomial property: ct(Exp(a) · t(X)) = a.
pub fn verify_monomial_property(a: i64, q: u64) -> bool {
    if a == 0 {
        // Exp(0) = 0, so ct(0 · t(X)) = 0
        return true;
    }
    let b = exp_map(a);
    let t = table_polynomial(q);
    let product = b.mul(&t, q);
    product.ct() == a
}

/// Check if a ring element is in the monomial set M.
pub fn is_monomial(f: &RingElement) -> bool {
    let nonzero: Vec<_> = f
        .coeffs
        .iter()
        .enumerate()
        .filter(|(_, &c)| c != 0)
        .collect();
    match nonzero.len() {
        0 => true, // zero is in M
        1 => {
            let (_, &c) = nonzero[0];
            c == 1 || c == -1
        }
        _ => false,
    }
}

/// Decompose a value into monomial layers for the range proof.
///
/// Given H with entries in some range, decompose into k_g layers H^(1), ..., H^(k_g)
/// where H = H^(1) + d'·H^(2) + ... + d'^{k_g-1}·H^(k_g) and ‖H^(i)‖_∞ ≤ d'/2.
pub fn monomial_decompose(value: i64, d_prime: i64, k_g: usize) -> Vec<i64> {
    crate::decomposition::decompose(value, d_prime, k_g)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_Q: u64 = 257;

    #[test]
    fn test_table_polynomial() {
        let t = table_polynomial(TEST_Q);
        assert_eq!(t.coeffs[0], 0);
        assert_eq!(t.coeffs[1], -1);
        assert_eq!(t.coeffs[D - 1], -1);
        assert_eq!(t.coeffs[2], -2);
    }

    #[test]
    fn test_monomial_property() {
        for a in -((D as i64) / 2 - 1)..((D as i64) / 2) {
            assert!(
                verify_monomial_property(a, TEST_Q),
                "monomial property failed for a={a}"
            );
        }
    }

    #[test]
    fn test_is_monomial() {
        assert!(is_monomial(&RingElement::zero()));
        assert!(is_monomial(&RingElement::monomial(0)));
        assert!(is_monomial(&RingElement::monomial(5)));
        assert!(!is_monomial(&RingElement::from_constant(2)));
    }
}
