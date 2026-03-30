//! Field conversion utilities: Symphony i64 coefficients <-> BabyBear limbs.
//!
//! BabyBear p = 2^31 - 2^27 + 1 = 2013265921 (~31 bits).
//! Symphony values are up to ~60 bits (modular), so each i64 is split into
//! two limbs: val = lo + hi * BASE where BASE = 2^30 and both lo, hi < 2^30 < p.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

/// Splitting base: 2^30 fits comfortably in BabyBear (p ~ 2^31).
pub const LIMB_BASE: u64 = 1 << 30;

/// Split a signed i64 value into two BabyBear limbs [lo, hi].
///
/// The value is first reduced to a positive canonical representative mod q,
/// then split as: val = lo + hi * 2^30.
pub fn i64_to_babybear_limbs(val: i64, q: u64) -> [BabyBear; 2] {
    // Reduce to [0, q) canonical form
    let pos = if val < 0 {
        (val as i128 + q as i128) as u64
    } else {
        val as u64 % q
    };
    let lo = pos % LIMB_BASE;
    let hi = pos / LIMB_BASE;
    [BabyBear::from_u64(lo), BabyBear::from_u64(hi)]
}

/// Reconstruct an i64 from two BabyBear limbs (for debugging/testing).
pub fn babybear_limbs_to_u64(limbs: [BabyBear; 2]) -> u64 {
    let lo = limbs[0].as_canonical_u64();
    let hi = limbs[1].as_canonical_u64();
    lo + hi * LIMB_BASE
}

/// Convert a byte slice to BabyBear elements.
/// Each 8 bytes is interpreted as i64 (le), then split into 2 BabyBear limbs.
/// A length sentinel is appended for injectivity.
pub fn bytes_to_babybear(data: &[u8], q: u64) -> Vec<BabyBear> {
    let mut result = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        let val = i64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        let limbs = i64_to_babybear_limbs(val, q);
        result.push(limbs[0]);
        result.push(limbs[1]);
        i += 8;
    }
    if i < data.len() {
        let mut buf = [0u8; 8];
        buf[..data.len() - i].copy_from_slice(&data[i..]);
        let val = i64::from_le_bytes(buf);
        let limbs = i64_to_babybear_limbs(val, q);
        result.push(limbs[0]);
        result.push(limbs[1]);
    }
    // Length sentinel
    result.push(BabyBear::from_u64(data.len() as u64 % (LIMB_BASE - 1)));
    result
}

/// Convert bytes to BabyBear elements for R1CS (one element per i64, no limb splitting).
/// Used by the output SNARK path where R1CS variable values fit in BabyBear.
/// No sentinel — the z vector has a fixed known size from the R1CS.
pub fn bytes_to_babybear_direct(data: &[u8]) -> Vec<BabyBear> {
    let mut result = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        let val = i64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        result.push(BabyBear::from_i64(val));
        i += 8;
    }
    if i < data.len() {
        let mut buf = [0u8; 8];
        buf[..data.len() - i].copy_from_slice(&data[i..]);
        let val = i64::from_le_bytes(buf);
        result.push(BabyBear::from_i64(val));
    }
    result
}

/// Pad a BabyBear vector to the next power of two.
pub fn pad_to_power_of_two(v: &mut Vec<BabyBear>) {
    let n = v.len().next_power_of_two();
    v.resize(n, BabyBear::ZERO);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_roundtrip() {
        let q = 1152921504606830593u64; // Symphony's q
        for val in [0i64, 1, -1, 42, -42, 1000000, -1000000] {
            let limbs = i64_to_babybear_limbs(val, q);
            let recovered = babybear_limbs_to_u64(limbs);
            let expected = if val < 0 {
                (val as i128 + q as i128) as u64
            } else {
                val as u64 % q
            };
            assert_eq!(recovered, expected, "roundtrip failed for val={val}");
        }
    }

    #[test]
    fn bytes_conversion() {
        let q = 1152921504606830593u64;
        let data = b"hello world";
        let elems = bytes_to_babybear(data, q);
        // 11 bytes -> 1 full i64 (8 bytes) + 1 partial (3 bytes) + 1 sentinel = 5 elements
        assert_eq!(elems.len(), 5);
    }
}
