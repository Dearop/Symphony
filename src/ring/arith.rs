//! Shared modular arithmetic primitives.
//!
//! Consolidates `mod_pow`, `mod_inv`, and centered reduction used
//! throughout the crate to avoid duplicating these low-level helpers.

/// Centered modular reduction: maps `x` into [−q/2, q/2).
#[inline]
pub fn centered_mod(x: i128, q: u64) -> i64 {
    let q = q as i128;
    let q_half = (q / 2) as i64;
    let mut r = (x % q) as i64;
    if r > q_half {
        r -= q as i64;
    } else if r < -q_half {
        r += q as i64;
    }
    r
}

/// Modular exponentiation: `base^exp mod modulus`.
pub fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let m = modulus as u128;
    base %= modulus;
    let mut b = base as u128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % m;
        }
        exp >>= 1;
        b = (b * b) % m;
    }
    result as u64
}

/// Modular multiplicative inverse via extended Euclidean algorithm.
///
/// Returns `a^{-1} mod m`. Panics if `gcd(a, m) != 1`.
pub fn mod_inv(a: u64, m: u64) -> u64 {
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }
    ((old_s % m as i128 + m as i128) % m as i128) as u64
}
