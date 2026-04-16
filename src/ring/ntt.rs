//! Number-Theoretic Transform for O(d log d) ring multiplication.
//!
//! Since d = 64, this is a small fixed-size NTT. The prime q must satisfy
//! q ≡ 1 (mod 2d) for the existence of primitive 2d-th roots of unity.

use crate::params::D;
use crate::ring::RingElement;
use super::arith::{mod_pow, mod_inv};

/// Precomputed NTT tables for a specific modulus q.
#[derive(Debug, Clone)]
pub struct NttContext {
    /// The prime modulus.
    pub q: u64,
    /// Primitive 2d-th root of unity ω in Zq.
    pub omega: u64,
    /// Precomputed powers of ω for the forward transform.
    pub forward_twiddles: [u64; D],
    /// Precomputed powers of ω^{-1} for the inverse transform.
    pub inverse_twiddles: [u64; D],
    /// Multiplicative inverse of d modulo q.
    pub d_inv: u64,
}

impl NttContext {
    /// Create NTT context for the given prime q.
    /// q must satisfy q ≡ 1 (mod 2d).
    pub fn new(q: u64) -> Self {
        assert!(q % (2 * D as u64) == 1, "q must be 1 mod 2d for NTT");

        let omega = find_primitive_root(q, 2 * D as u64);
        let omega_inv = mod_inv(omega, q);
        let d_inv = mod_inv(D as u64, q);

        let mut forward_twiddles = [0u64; D];
        let mut inverse_twiddles = [0u64; D];
        let mut w = 1u64;
        let mut w_inv = 1u64;
        for i in 0..D {
            forward_twiddles[i] = w;
            inverse_twiddles[i] = w_inv;
            w = ((w as u128 * omega as u128) % q as u128) as u64;
            w_inv = ((w_inv as u128 * omega_inv as u128) % q as u128) as u64;
        }

        Self {
            q,
            omega,
            forward_twiddles,
            inverse_twiddles,
            d_inv,
        }
    }

    /// Forward NTT: convert from coefficient to evaluation representation.
    /// Computes the "negacyclic NTT" suitable for multiplication mod X^d + 1.
    pub fn forward(&self, a: &RingElement) -> [u64; D] {
        let mut vals = [0u64; D];
        // Convert from centered to positive representation (branchless).
        let q = self.q;
        for (v, &c) in vals.iter_mut().zip(a.coeffs.iter()) {
            *v = ((c as i128 + q as i128) % q as i128) as u64;
        }

        // Pre-multiply by powers of ω (for negacyclic convolution)
        for (v, &tw) in vals.iter_mut().zip(self.forward_twiddles.iter()) {
            *v = ((*v as u128 * tw as u128) % self.q as u128) as u64;
        }

        // Standard radix-2 DIT NTT
        self.ntt_core(&mut vals, false);
        vals
    }

    /// Inverse NTT: convert from evaluation to coefficient representation.
    pub fn inverse(&self, vals: &[u64; D]) -> RingElement {
        let mut a = *vals;

        // Inverse NTT core
        self.ntt_core(&mut a, true);

        // Post-multiply by powers of ω^{-1} and scale by d^{-1}
        let q = self.q;
        let mut coeffs = [0i64; D];
        for i in 0..D {
            let v = ((a[i] as u128 * self.inverse_twiddles[i] as u128) % q as u128) as u64;
            let v = ((v as u128 * self.d_inv as u128) % q as u128) as u64;
            // Convert to centered representation
            coeffs[i] = if v > q / 2 {
                v as i64 - q as i64
            } else {
                v as i64
            };
        }

        RingElement { coeffs }
    }

    /// Pointwise multiplication in NTT domain.
    pub fn pointwise_mul(&self, a: &[u64; D], b: &[u64; D]) -> [u64; D] {
        let mut c = [0u64; D];
        for i in 0..D {
            c[i] = ((a[i] as u128 * b[i] as u128) % self.q as u128) as u64;
        }
        c
    }

    /// Pointwise addition in NTT domain.
    pub fn pointwise_add(&self, a: &[u64; D], b: &[u64; D]) -> [u64; D] {
        let mut c = [0u64; D];
        for i in 0..D {
            c[i] = (a[i] + b[i]) % self.q;
        }
        c
    }

    /// NTT-accelerated ring multiplication.
    pub fn ring_mul(&self, a: &RingElement, b: &RingElement) -> RingElement {
        let a_ntt = self.forward(a);
        let b_ntt = self.forward(b);
        let c_ntt = self.pointwise_mul(&a_ntt, &b_ntt);
        self.inverse(&c_ntt)
    }

    /// Radix-2 NTT/INTT core (in-place).
    fn ntt_core(&self, a: &mut [u64; D], inverse: bool) {
        let n = D;
        let q = self.q;

        // Bit-reversal permutation.
        // Note: the swap condition `i < j` depends only on indices (not coefficient
        // values), so this is constant-time with respect to secret data.
        let mut j = 0usize;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if i < j {
                a.swap(i, j);
            }
        }

        // Cooley-Tukey butterfly
        let mut len = 2;
        while len <= n {
            let half = len / 2;
            // The step for twiddle factor selection depends on direction
            let w_step = if inverse {
                // For inverse, we use a generator of the appropriate subgroup
                mod_pow(mod_inv(self.omega, q), (2 * D as u64) / len as u64, q)
            } else {
                mod_pow(self.omega, (2 * D as u64) / len as u64, q)
            };

            for start in (0..n).step_by(len) {
                let mut w = 1u64;
                for j in 0..half {
                    let u = a[start + j];
                    let v = ((a[start + j + half] as u128 * w as u128) % q as u128) as u64;
                    a[start + j] = (u + v) % q;
                    a[start + j + half] = (u + q - v) % q;
                    w = ((w as u128 * w_step as u128) % q as u128) as u64;
                }
            }
            len <<= 1;
        }
    }
}

/// Find a primitive n-th root of unity modulo q.
/// Requires n to be a power of 2 (for the order check via n/2).
fn find_primitive_root(q: u64, n: u64) -> u64 {
    assert!(n.is_power_of_two(), "n must be a power of 2, got {n}");
    assert!((q - 1).is_multiple_of(n));
    let cofactor = (q - 1) / n;
    for g in 2..q {
        let candidate = mod_pow(g, cofactor, q);
        if candidate != 1 && mod_pow(candidate, n / 2, q) != 1 && mod_pow(candidate, n, q) == 1 {
            return candidate;
        }
    }
    panic!("no primitive {n}-th root of unity found mod {q}");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small NTT-friendly prime: 12289 = 3 * 2^12 + 1, supports up to d = 2^12
    const TEST_Q: u64 = 12289;

    #[test]
    fn test_ntt_roundtrip() {
        let ctx = NttContext::new(TEST_Q);
        let a = RingElement::from_constant(42);
        let a_ntt = ctx.forward(&a);
        let a_back = ctx.inverse(&a_ntt);
        assert_eq!(a, a_back);
    }

    #[test]
    fn test_ntt_mul_matches_schoolbook() {
        let ctx = NttContext::new(TEST_Q);
        let a = RingElement {
            coeffs: {
                let mut c = [0i64; D];
                c[0] = 3;
                c[1] = 5;
                c[2] = -2;
                c
            },
        };
        let b = RingElement {
            coeffs: {
                let mut c = [0i64; D];
                c[0] = 7;
                c[1] = -1;
                c
            },
        };
        let schoolbook = a.mul(&b, TEST_Q);
        let ntt_result = ctx.ring_mul(&a, &b);
        assert_eq!(schoolbook, ntt_result);
    }
}
