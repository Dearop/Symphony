//! Gadget decomposition for converting arbitrary Zq witnesses to low-norm witnesses.

pub mod monomial;

/// Gadget decomposition: decompose f into k digits in base b with ‖digit‖_∞ ≤ b/2.
///
/// For each element f_i, produce g_i ∈ Z^k such that:
/// f_i = <g_i, (1, b, b^2, ..., b^{k-1})>
///
/// Paper uses b = 16, k_cs = 16.
pub fn decompose(value: i64, b: i64, k: usize) -> Vec<i64> {
    let mut digits = Vec::with_capacity(k);
    let mut remaining = value;
    let half_b = b / 2;

    for _ in 0..k {
        let mut digit = remaining % b;
        if digit > half_b {
            digit -= b;
            remaining += b;
        } else if digit < -half_b {
            digit += b;
            remaining -= b;
        }
        digits.push(digit);
        remaining /= b;
    }

    digits
}

/// Decompose an entire vector element-wise.
pub fn decompose_vector(values: &[i64], b: i64, k: usize) -> Vec<i64> {
    values.iter().flat_map(|&v| decompose(v, b, k)).collect()
}

/// Recompose: reconstruct value from digits and base.
///
/// Panics if the result overflows i64.
pub fn recompose(digits: &[i64], b: i64) -> i64 {
    let mut result = 0i128;
    let mut power = 1i128;
    for &d in digits {
        result = result
            .checked_add(d as i128 * power)
            .expect("recompose overflow");
        power = power
            .checked_mul(b as i128)
            .expect("recompose overflow: b^k exceeds i128");
    }
    i64::try_from(result).expect("recompose result exceeds i64 range")
}

/// Gadget vector g = (1, b, b^2, ..., b^{k-1}).
pub fn gadget_vector(b: i64, k: usize) -> Vec<i64> {
    let mut g = Vec::with_capacity(k);
    let mut power = 1i64;
    for _ in 0..k {
        g.push(power);
        power = power
            .checked_mul(b)
            .expect("gadget_vector overflow: b^i exceeds i64; reduce base or decomposition depth");
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompose_recompose() {
        let b = 16;
        let k = 16;
        for val in [-12345i64, 0, 1, 42, 999999, -1] {
            let digits = decompose(val, b, k);
            assert_eq!(digits.len(), k);
            assert!(digits.iter().all(|&d| d.abs() <= b / 2));
            assert_eq!(recompose(&digits, b), val);
        }
    }

    #[test]
    fn test_decompose_vector() {
        let b = 16;
        let k = 4;
        let vals = vec![100, -200, 50];
        let decomposed = decompose_vector(&vals, b, k);
        assert_eq!(decomposed.len(), vals.len() * k);
        for (i, &v) in vals.iter().enumerate() {
            let chunk = &decomposed[i * k..(i + 1) * k];
            assert_eq!(recompose(chunk, b), v);
        }
    }
}
