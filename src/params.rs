//! Global parameters matching Table 1 of the Symphony paper.

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
}

impl SymphonyParams {
    /// Generalized witness length: n = n_bar * k_cs.
    pub fn n(&self) -> usize {
        self.n_bar * self.k_cs
    }

    /// Construct default parameters from Table 1.
    pub fn default_from_paper() -> Self {
        Self {
            q: find_suitable_prime(),
            d: D,
            kappa: 12,
            ell_np: 1024,
            ell_h: 1 << 14,
            lambda_pj: 256,
            n_bar: 1 << 16,
            m: 1 << 16,
            b: 16,
            k_cs: 16,
        }
    }

    /// MSIS norm bound β_SIS = 2^37.
    pub fn beta_sis(&self) -> u64 {
        1u64 << 37
    }

    /// Relaxed opening norm bound B_rbnd = β_SIS / (4 * ‖S‖_op) ≈ 2^31.
    pub fn b_rbnd(&self) -> u64 {
        1u64 << 31
    }

    /// Strict opening norm bound B_bnd = B_rbnd / 2 = 2^30.
    pub fn b_bnd(&self) -> u64 {
        1u64 << 30
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

/// Find a 64-bit prime q with q ≡ 1 (mod 2d) for NTT compatibility.
fn find_suitable_prime() -> u64 {
    // q must satisfy q ≡ 1 (mod 128) since d = 64 and we need 2d | (q - 1).
    // Using a known suitable prime for the default instantiation.
    // This is a placeholder; a proper implementation should search for or
    // verify a prime meeting all security requirements.
    let two_d = 2 * D as u64; // 128
    let mut candidate = (1u64 << 63) - ((1u64 << 63) % two_d) + 1;
    while !is_probably_prime(candidate) {
        candidate += two_d;
    }
    candidate
}

/// Simple Miller-Rabin primality test (sufficient for parameter generation).
fn is_probably_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }

    // Write n-1 as 2^r * d
    let mut d = n - 1;
    let mut r = 0u32;
    while d % 2 == 0 {
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
