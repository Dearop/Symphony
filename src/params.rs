//! Global parameters matching Table 1 of the Symphony paper.

use crate::ring::ntt::NttContext;

/// Ring dimension d = 64 (power-of-two cyclotomic ring X^64 + 1).
pub const D: usize = 64;

/// Extension field degree t = 2 (K = Fq^2).
pub const T: usize = 2;

/// Top-level parameters for a Symphony instance (Table 1).
#[derive(Debug, Clone)]
pub struct SymphonyParams {
    /// 64-bit prime modulus. Must satisfy q ≡ 1 (mod 2d) for NTT compatibility.
    pub q: u64,
    /// Ring dimension (default 64).
    pub d: usize,
    /// MSIS rank (default 12).
    pub kappa: usize,
    /// Folding arity (default 1024).
    pub ell_np: usize,
    /// Projection input block length (default 2^14).
    pub ell_h: usize,
    /// Projection output length (default 256).
    pub lambda_pj: usize,
    /// Original R1CS witness length (default 2^16).
    pub n_bar: usize,
    /// Number of R1CS constraints per instance (default 2^16).
    pub m: usize,
    /// Gadget decomposition base (default 16).
    pub b: usize,
    /// Gadget decomposition factor (default 16).
    pub k_cs: usize,
    /// Number of public input variables per R1CS instance (default 1).
    pub n_in: usize,
    /// Precomputed NTT context for O(d log d) ring multiplication.
    /// `None` only for deliberately invalid parameter sets in tests.
    pub ntt: Option<NttContext>,
}

impl SymphonyParams {
    /// Validate all parameter constraints required for correctness and security.
    ///
    /// Checks:
    /// - `d == D` (compile-time ring dimension)
    /// - `q` is prime
    /// - `q ≡ 1 (mod 2d)` (NTT compatibility)
    /// - `q < 2^61` (i128 overflow safety)
    /// - `b >= 2` and `k_cs >= 1` (decomposition sanity)
    /// - `kappa >= 1`, `ell_np >= 1` (structural)
    ///
    /// Must be called before using the params in any protocol step.
    pub fn validate(&self) {
        assert_eq!(
            self.d, D,
            "SymphonyParams.d ({}) does not match compile-time D ({D})",
            self.d
        );
        assert!(
            is_probably_prime(self.q),
            "SymphonyParams.q ({}) is not prime",
            self.q
        );
        assert_eq!(
            self.q % (2 * self.d as u64),
            1,
            "SymphonyParams.q ({}) does not satisfy q ≡ 1 (mod 2d = {})",
            self.q,
            2 * self.d
        );
        assert!(
            self.q < (1u64 << 61),
            "SymphonyParams.q ({}) must be < 2^61 for i128 overflow safety",
            self.q
        );
        assert!(self.kappa >= 1, "kappa must be >= 1");
        assert!(self.ell_np >= 1, "ell_np must be >= 1");
        assert!(self.b >= 2, "decomposition base b must be >= 2");
        assert!(self.k_cs >= 1, "decomposition factor k_cs must be >= 1");
    }

    /// Generalized witness length: n = n_bar * k_cs.
    pub fn n(&self) -> usize {
        self.n_bar * self.k_cs
    }

    /// Get the NTT context, panicking if unavailable (invalid params).
    pub fn ntt(&self) -> &NttContext {
        self.ntt.as_ref().expect("NTT context unavailable (invalid q for NTT)")
    }

    /// Try to build an NTT context for the given q. Returns None if q
    /// doesn't satisfy the NTT precondition (q ≡ 1 mod 2d).
    pub fn try_ntt(q: u64, d: usize) -> Option<NttContext> {
        if q >= 2 && q % (2 * d as u64) == 1 {
            Some(NttContext::new(q))
        } else {
            None
        }
    }

    /// Construct default parameters from Table 1.
    pub fn default_from_paper() -> Self {
        let q = find_suitable_prime();
        let params = Self {
            q,
            d: D,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 16,
            k_cs: 16,
            n_in: 1,
            ntt: Self::try_ntt(q, D),
        };
        params.validate();
        params
    }

    /// MSIS norm bound β_SIS = 2^37.
    pub fn beta_sis(&self) -> u64 {
        1u64 << 37
    }

    /// Relaxed opening norm bound B_rbnd = β_SIS / (4 * ‖S‖_op).
    ///
    /// ‖S‖_op ≤ 15 for the LaBRADOR challenge set.
    /// B_rbnd = 2^37 / 60 ≈ 2,290,649,225.
    pub fn b_rbnd(&self) -> u64 {
        self.beta_sis() / (4 * 15)
    }

    /// Strict opening norm bound B_bnd = B_rbnd / 2.
    pub fn b_bnd(&self) -> u64 {
        self.b_rbnd() / 2
    }

    /// Input witness norm bound B = 2^10.
    pub fn b_input(&self) -> u64 {
        1u64 << 10
    }

    /// Number of monomial decomposition layers k_g = 3.
    pub fn k_g(&self) -> usize {
        3
    }
}

/// Find a prime q with q ≡ 1 (mod 2d) for NTT compatibility.
///
/// q is capped below 2^61 to guarantee that all i128 intermediate
/// products (up to D × (q/2)^2 in schoolbook multiplication) stay
/// within range, and that `q as i64` never wraps.
fn find_suitable_prime() -> u64 {
    let two_d = 2 * D as u64; // 128
                              // Start near 2^60 so q fits comfortably in i64 and schoolbook
                              // accumulator stays within i128.
    let start = (1u64 << 60) - ((1u64 << 60) % two_d) + 1;
    let mut candidate = start;
    while !is_probably_prime(candidate) {
        candidate = candidate.checked_add(two_d).expect("prime search overflow");
    }
    assert!(candidate <= i64::MAX as u64, "q must fit in i64");
    candidate
}

/// Miller-Rabin primality test. Deterministic for all n < 3.317×10^24 with
/// the first 12 primes as witnesses (sufficient for all 64-bit values).
pub(crate) fn is_probably_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n.is_multiple_of(2) {
        return false;
    }

    // Write n-1 as 2^r * d
    let mut d = n - 1;
    let mut r = 0u32;
    while d.is_multiple_of(2) {
        d /= 2;
        r += 1;
    }

    // Test with a few small witnesses
    let witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    'outer: for &a in &witnesses {
        if a >= n {
            continue;
        }
        let mut x = mod_pow(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = mod_mul(x, x, n);
            if x == n - 1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let m = modulus as u128;
    base %= modulus;
    let mut b = base as u128;
    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * b) % m;
        }
        exp /= 2;
        b = (b * b) % m;
    }
    result as u64
}

fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params() {
        let p = SymphonyParams::default_from_paper();
        assert_eq!(p.d, 64);
        assert_eq!(p.kappa, 12);
        assert_eq!(p.n(), 1 << 20);
        assert!(p.q % 128 == 1, "q must be 1 mod 2d");
        assert!(is_probably_prime(p.q));
    }
}
