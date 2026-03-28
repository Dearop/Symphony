//! Wrapper around curve25519-dalek `Scalar` for Spartan arithmetic over Fp.
//!
//! Fp is the Ristretto scalar field (~2^252). Since q << p, elements of Zq
//! embed directly into Fp without modular reduction circuits.

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

/// Convert an i64 to a Scalar. Negative values are mapped to p - |v|.
pub fn from_i64(v: i64) -> Scalar {
    if v >= 0 {
        Scalar::from(v as u64)
    } else {
        // p - |v|
        Scalar::ZERO - Scalar::from(v.unsigned_abs())
    }
}

/// Convert a u64 to a Scalar.
pub fn from_u64(v: u64) -> Scalar {
    Scalar::from(v)
}

/// Compute the multiplicative inverse of a scalar. Panics if zero.
pub fn inv(a: &Scalar) -> Scalar {
    a.invert()
}

/// Derive a pseudorandom scalar from a transcript hash.
pub fn scalar_from_hash(data: &[u8]) -> Scalar {
    let hash = Sha256::digest(data);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Serialize a scalar to 32 bytes (little-endian).
pub fn to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

/// Deserialize a scalar from 32 bytes.
pub fn from_bytes(b: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(*b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_positive() {
        let s = from_i64(42);
        assert_eq!(s, Scalar::from(42u64));
    }

    #[test]
    fn roundtrip_negative() {
        let s = from_i64(-1);
        assert_eq!(s + Scalar::ONE, Scalar::ZERO);
    }

    #[test]
    fn inverse() {
        let a = from_i64(7);
        let a_inv = inv(&a);
        assert_eq!(a * a_inv, Scalar::ONE);
    }

    #[test]
    fn hash_deterministic() {
        let s1 = scalar_from_hash(b"test");
        let s2 = scalar_from_hash(b"test");
        assert_eq!(s1, s2);
    }
}
