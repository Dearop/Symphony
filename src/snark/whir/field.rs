//! Field conversion utilities: Symphony bytes <-> BabyBear elements.
//!
//! BabyBear p = 2^31 - 2^27 + 1 = 2013265921 (~31 bits).
//!
//! For the CP path, raw witness bytes are packed into BabyBear elements using
//! a canonical 3-byte packing (2^24 = 16M < p), which is injective. A length
//! element is appended for unambiguous padding.
//!
//! For the output path, R1CS variable values (already in-field) are converted
//! directly via `bytes_to_babybear_direct`.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

/// Bytes packed per BabyBear element. 3 bytes = 2^24 < p, so no modular
/// reduction occurs and the mapping is injective.
pub const BYTES_PER_ELEMENT: usize = 3;

/// Convert a byte slice to BabyBear elements using canonical 3-byte packing.
///
/// Each group of 3 bytes is packed little-endian into one BabyBear element.
/// The final element encodes `data.len()` so that different-length inputs
/// (including those that differ only in trailing zeros) produce distinct
/// field-element sequences.
///
/// # Injectivity
///
/// - Each 3-byte chunk maps to a unique value in [0, 2^24), well below p.
/// - The length sentinel is exact (no modular reduction for practical sizes).
/// - Padding bytes in the last partial chunk are zero, disambiguated by length.
pub fn bytes_to_babybear(data: &[u8], _q: u64) -> Vec<BabyBear> {
    // Estimate: ceil(len/3) data elements + 1 length sentinel
    let mut result = Vec::with_capacity(data.len() / BYTES_PER_ELEMENT + 2);

    for chunk in data.chunks(BYTES_PER_ELEMENT) {
        let mut val: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            val |= (b as u32) << (8 * i);
        }
        // val < 2^24 < p, so BabyBear::from_u32 is lossless
        result.push(BabyBear::from_u32(val));
    }

    // Length sentinel — exact for len < 2^31 (practical limit)
    assert!(
        data.len() < (1u64 << 31) as usize,
        "data too large for injective BabyBear encoding"
    );
    result.push(BabyBear::from_u32(data.len() as u32));

    result
}

/// Convert bytes to BabyBear elements for R1CS (one element per i64, no packing).
///
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
    use p3_field::PrimeField32;

    #[test]
    fn bytes_to_babybear_injective() {
        let q = 1152921504606830593u64;
        // Different inputs must produce different outputs
        let a = bytes_to_babybear(b"hello", q);
        let b = bytes_to_babybear(b"hellp", q);
        assert_ne!(a, b);
    }

    #[test]
    fn bytes_to_babybear_length_disambiguation() {
        let q = 1152921504606830593u64;
        // Inputs that differ only in trailing zeros must differ
        let a = bytes_to_babybear(&[1, 2, 3], q);
        let b = bytes_to_babybear(&[1, 2, 3, 0], q);
        assert_ne!(a, b);
    }

    #[test]
    fn bytes_to_babybear_empty() {
        let q = 1152921504606830593u64;
        let elems = bytes_to_babybear(b"", q);
        // Just the length sentinel (0)
        assert_eq!(elems.len(), 1);
        assert_eq!(elems[0].as_canonical_u32(), 0);
    }

    #[test]
    fn bytes_to_babybear_packing() {
        let q = 1152921504606830593u64;
        let data = vec![0xAB, 0xCD, 0xEF]; // one full 3-byte chunk
        let elems = bytes_to_babybear(&data, q);
        // 1 data element + 1 length sentinel
        assert_eq!(elems.len(), 2);
        let expected_val = 0xABu32 | (0xCDu32 << 8) | (0xEFu32 << 16);
        assert_eq!(elems[0].as_canonical_u32(), expected_val);
        assert_eq!(elems[1].as_canonical_u32(), 3); // length
    }

    #[test]
    fn bytes_conversion_size() {
        let q = 1152921504606830593u64;
        let data = b"hello world"; // 11 bytes
        let elems = bytes_to_babybear(data, q);
        // ceil(11/3) = 4 data elements + 1 sentinel = 5
        assert_eq!(elems.len(), 5);
    }
}
