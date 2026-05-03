//! Versioned public proof envelope helpers.
//!
//! The public verifier API remains typed Rust structs. This module defines the
//! canonical byte envelope used for fixtures, review, and future wire formats.
//! Backend proofs are length-delimited opaque payloads here; each backend owns
//! the canonical serialization of its own proof bytes.

use crate::digest_core::{Digest32, PublicDigestScheme};

pub const PUBLIC_PROOF_ENVELOPE_VERSION: u16 = 1;
pub const COMPRESSED_PUBLIC_PROOF_ENVELOPE_VERSION: u16 = 2;
const PUBLIC_PROOF_ENVELOPE_MAGIC: &[u8; 8] = b"SYMPUB2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicProofEnvelopeError {
    BadMagic,
    UnsupportedVersion(u16),
    UnknownDigestScheme(u8),
    Truncated,
    TrailingBytes,
    LengthOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProofEnvelope {
    pub digest_scheme: PublicDigestScheme,
    pub public_inputs: Vec<Vec<i64>>,
    pub r1cs_num_constraints: usize,
    pub r1cs_num_variables: usize,
    pub r1cs_num_public: usize,
    pub fs_commitments: Vec<Vec<u8>>,
    pub fs_root: Digest32,
    pub fold_root: Digest32,
    pub challenge_digest: Digest32,
    pub transcript_seed_digest: Digest32,
    pub folded_output_bytes: Vec<u8>,
    pub cp_proof_bytes: Vec<u8>,
    pub output_proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedPublicProofEnvelope {
    pub digest_scheme: PublicDigestScheme,
    pub public_inputs: Vec<Vec<i64>>,
    pub r1cs_num_constraints: usize,
    pub r1cs_num_variables: usize,
    pub r1cs_num_public: usize,
    pub fs_root: Digest32,
    pub fold_root: Digest32,
    pub challenge_digest: Digest32,
    pub transcript_seed_digest: Digest32,
    pub folded_output_bytes: Vec<u8>,
    pub cp_proof_bytes: Vec<u8>,
    pub output_proof_bytes: Vec<u8>,
}

impl PublicProofEnvelope {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PUBLIC_PROOF_ENVELOPE_MAGIC);
        write_u16(&mut out, PUBLIC_PROOF_ENVELOPE_VERSION);
        out.push(digest_scheme_id(self.digest_scheme));

        write_len(&mut out, self.public_inputs.len());
        for input in &self.public_inputs {
            write_len(&mut out, input.len());
            for value in input {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }

        write_len(&mut out, self.r1cs_num_constraints);
        write_len(&mut out, self.r1cs_num_variables);
        write_len(&mut out, self.r1cs_num_public);

        write_vec_vec(&mut out, &self.fs_commitments);
        out.extend_from_slice(&self.fs_root);
        out.extend_from_slice(&self.fold_root);
        out.extend_from_slice(&self.challenge_digest);
        out.extend_from_slice(&self.transcript_seed_digest);
        write_bytes(&mut out, &self.folded_output_bytes);
        write_bytes(&mut out, &self.cp_proof_bytes);
        write_bytes(&mut out, &self.output_proof_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublicProofEnvelopeError> {
        let mut reader = Reader::new(bytes);
        if reader.read_exact(PUBLIC_PROOF_ENVELOPE_MAGIC.len())? != PUBLIC_PROOF_ENVELOPE_MAGIC {
            return Err(PublicProofEnvelopeError::BadMagic);
        }

        let version = reader.read_u16()?;
        if version != PUBLIC_PROOF_ENVELOPE_VERSION {
            return Err(PublicProofEnvelopeError::UnsupportedVersion(version));
        }

        let digest_scheme = digest_scheme_from_id(reader.read_u8()?)?;
        let public_input_count = reader.read_len()?;
        let mut public_inputs = Vec::with_capacity(public_input_count);
        for _ in 0..public_input_count {
            let len = reader.read_len()?;
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                input.push(reader.read_i64()?);
            }
            public_inputs.push(input);
        }

        let r1cs_num_constraints = reader.read_len()?;
        let r1cs_num_variables = reader.read_len()?;
        let r1cs_num_public = reader.read_len()?;
        let fs_commitments = reader.read_vec_vec()?;
        let fs_root = reader.read_digest()?;
        let fold_root = reader.read_digest()?;
        let challenge_digest = reader.read_digest()?;
        let transcript_seed_digest = reader.read_digest()?;
        let folded_output_bytes = reader.read_bytes()?.to_vec();
        let cp_proof_bytes = reader.read_bytes()?.to_vec();
        let output_proof_bytes = reader.read_bytes()?.to_vec();

        if !reader.is_finished() {
            return Err(PublicProofEnvelopeError::TrailingBytes);
        }

        Ok(Self {
            digest_scheme,
            public_inputs,
            r1cs_num_constraints,
            r1cs_num_variables,
            r1cs_num_public,
            fs_commitments,
            fs_root,
            fold_root,
            challenge_digest,
            transcript_seed_digest,
            folded_output_bytes,
            cp_proof_bytes,
            output_proof_bytes,
        })
    }
}

impl CompressedPublicProofEnvelope {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PUBLIC_PROOF_ENVELOPE_MAGIC);
        write_u16(&mut out, COMPRESSED_PUBLIC_PROOF_ENVELOPE_VERSION);
        out.push(digest_scheme_id(self.digest_scheme));

        write_len(&mut out, self.public_inputs.len());
        for input in &self.public_inputs {
            write_len(&mut out, input.len());
            for value in input {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }

        write_len(&mut out, self.r1cs_num_constraints);
        write_len(&mut out, self.r1cs_num_variables);
        write_len(&mut out, self.r1cs_num_public);

        out.extend_from_slice(&self.fs_root);
        out.extend_from_slice(&self.fold_root);
        out.extend_from_slice(&self.challenge_digest);
        out.extend_from_slice(&self.transcript_seed_digest);
        write_bytes(&mut out, &self.folded_output_bytes);
        write_bytes(&mut out, &self.cp_proof_bytes);
        write_bytes(&mut out, &self.output_proof_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublicProofEnvelopeError> {
        let mut reader = Reader::new(bytes);
        if reader.read_exact(PUBLIC_PROOF_ENVELOPE_MAGIC.len())? != PUBLIC_PROOF_ENVELOPE_MAGIC {
            return Err(PublicProofEnvelopeError::BadMagic);
        }

        let version = reader.read_u16()?;
        if version != COMPRESSED_PUBLIC_PROOF_ENVELOPE_VERSION {
            return Err(PublicProofEnvelopeError::UnsupportedVersion(version));
        }

        let digest_scheme = digest_scheme_from_id(reader.read_u8()?)?;
        let public_input_count = reader.read_len()?;
        let mut public_inputs = Vec::with_capacity(public_input_count);
        for _ in 0..public_input_count {
            let len = reader.read_len()?;
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                input.push(reader.read_i64()?);
            }
            public_inputs.push(input);
        }

        let r1cs_num_constraints = reader.read_len()?;
        let r1cs_num_variables = reader.read_len()?;
        let r1cs_num_public = reader.read_len()?;
        let fs_root = reader.read_digest()?;
        let fold_root = reader.read_digest()?;
        let challenge_digest = reader.read_digest()?;
        let transcript_seed_digest = reader.read_digest()?;
        let folded_output_bytes = reader.read_bytes()?.to_vec();
        let cp_proof_bytes = reader.read_bytes()?.to_vec();
        let output_proof_bytes = reader.read_bytes()?.to_vec();

        if !reader.is_finished() {
            return Err(PublicProofEnvelopeError::TrailingBytes);
        }

        Ok(Self {
            digest_scheme,
            public_inputs,
            r1cs_num_constraints,
            r1cs_num_variables,
            r1cs_num_public,
            fs_root,
            fold_root,
            challenge_digest,
            transcript_seed_digest,
            folded_output_bytes,
            cp_proof_bytes,
            output_proof_bytes,
        })
    }
}

#[must_use]
pub fn digest_scheme_id(scheme: PublicDigestScheme) -> u8 {
    match scheme {
        PublicDigestScheme::Sha256 => 0,
        #[cfg(feature = "whir")]
        PublicDigestScheme::Poseidon2BabyBear => 1,
    }
}

pub fn digest_scheme_from_id(id: u8) -> Result<PublicDigestScheme, PublicProofEnvelopeError> {
    match id {
        0 => Ok(PublicDigestScheme::Sha256),
        #[cfg(feature = "whir")]
        1 => Ok(PublicDigestScheme::Poseidon2BabyBear),
        other => Err(PublicProofEnvelopeError::UnknownDigestScheme(other)),
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_len(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn write_vec_vec(out: &mut Vec<u8>, values: &[Vec<u8>]) {
    write_len(out, values.len());
    for value in values {
        write_bytes(out, value);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_finished(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PublicProofEnvelopeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(PublicProofEnvelopeError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(PublicProofEnvelopeError::Truncated);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, PublicProofEnvelopeError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PublicProofEnvelopeError> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.read_exact(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn read_u64(&mut self) -> Result<u64, PublicProofEnvelopeError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn read_len(&mut self) -> Result<usize, PublicProofEnvelopeError> {
        usize::try_from(self.read_u64()?).map_err(|_| PublicProofEnvelopeError::LengthOverflow)
    }

    fn read_i64(&mut self) -> Result<i64, PublicProofEnvelopeError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.read_exact(8)?);
        Ok(i64::from_le_bytes(raw))
    }

    fn read_digest(&mut self) -> Result<Digest32, PublicProofEnvelopeError> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(self.read_exact(32)?);
        Ok(digest)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], PublicProofEnvelopeError> {
        let len = self.read_len()?;
        self.read_exact(len)
    }

    fn read_vec_vec(&mut self) -> Result<Vec<Vec<u8>>, PublicProofEnvelopeError> {
        let len = self.read_len()?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.read_bytes()?.to_vec());
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> PublicProofEnvelope {
        PublicProofEnvelope {
            digest_scheme: PublicDigestScheme::Sha256,
            public_inputs: vec![vec![1, 2], vec![3]],
            r1cs_num_constraints: 4,
            r1cs_num_variables: 5,
            r1cs_num_public: 2,
            fs_commitments: vec![vec![7; 32], vec![8; 32]],
            fs_root: [1; 32],
            fold_root: [2; 32],
            challenge_digest: [3; 32],
            transcript_seed_digest: [4; 32],
            folded_output_bytes: vec![9, 10, 11],
            cp_proof_bytes: vec![12, 13],
            output_proof_bytes: vec![14, 15, 16],
        }
    }

    fn sample_compressed_envelope() -> CompressedPublicProofEnvelope {
        let envelope = sample_envelope();
        CompressedPublicProofEnvelope {
            digest_scheme: envelope.digest_scheme,
            public_inputs: envelope.public_inputs,
            r1cs_num_constraints: envelope.r1cs_num_constraints,
            r1cs_num_variables: envelope.r1cs_num_variables,
            r1cs_num_public: envelope.r1cs_num_public,
            fs_root: envelope.fs_root,
            fold_root: envelope.fold_root,
            challenge_digest: envelope.challenge_digest,
            transcript_seed_digest: envelope.transcript_seed_digest,
            folded_output_bytes: envelope.folded_output_bytes,
            cp_proof_bytes: envelope.cp_proof_bytes,
            output_proof_bytes: envelope.output_proof_bytes,
        }
    }

    #[test]
    fn public_proof_envelope_roundtrips() {
        let envelope = sample_envelope();
        let bytes = envelope.to_bytes();
        assert_eq!(PublicProofEnvelope::from_bytes(&bytes), Ok(envelope));
    }

    #[test]
    fn compressed_public_proof_envelope_roundtrips_and_omits_fs_commitments() {
        let uncompressed = sample_envelope().to_bytes();
        let envelope = sample_compressed_envelope();
        let bytes = envelope.to_bytes();

        assert_eq!(
            CompressedPublicProofEnvelope::from_bytes(&bytes),
            Ok(envelope)
        );
        assert!(bytes.len() < uncompressed.len());
        assert_eq!(
            PublicProofEnvelope::from_bytes(&bytes),
            Err(PublicProofEnvelopeError::UnsupportedVersion(
                COMPRESSED_PUBLIC_PROOF_ENVELOPE_VERSION
            ))
        );
    }

    #[test]
    fn public_proof_envelope_rejects_unknown_version() {
        let mut bytes = sample_envelope().to_bytes();
        let version_offset = PUBLIC_PROOF_ENVELOPE_MAGIC.len();
        bytes[version_offset] = 99;
        assert_eq!(
            PublicProofEnvelope::from_bytes(&bytes),
            Err(PublicProofEnvelopeError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn public_proof_envelope_rejects_unknown_digest_scheme() {
        let mut bytes = sample_envelope().to_bytes();
        let scheme_offset = PUBLIC_PROOF_ENVELOPE_MAGIC.len() + 2;
        bytes[scheme_offset] = 99;
        assert_eq!(
            PublicProofEnvelope::from_bytes(&bytes),
            Err(PublicProofEnvelopeError::UnknownDigestScheme(99))
        );
    }

    #[test]
    fn public_proof_envelope_rejects_truncation_and_trailing_bytes() {
        let mut bytes = sample_envelope().to_bytes();
        bytes.pop();
        assert_eq!(
            PublicProofEnvelope::from_bytes(&bytes),
            Err(PublicProofEnvelopeError::Truncated)
        );

        let mut bytes = sample_envelope().to_bytes();
        bytes.push(0);
        assert_eq!(
            PublicProofEnvelope::from_bytes(&bytes),
            Err(PublicProofEnvelopeError::TrailingBytes)
        );
    }

    #[test]
    fn minimal_public_proof_envelope_fixture_is_stable() {
        let envelope = PublicProofEnvelope {
            digest_scheme: PublicDigestScheme::Sha256,
            public_inputs: vec![],
            r1cs_num_constraints: 0,
            r1cs_num_variables: 0,
            r1cs_num_public: 0,
            fs_commitments: vec![],
            fs_root: [0; 32],
            fold_root: [0; 32],
            challenge_digest: [0; 32],
            transcript_seed_digest: [0; 32],
            folded_output_bytes: vec![],
            cp_proof_bytes: vec![],
            output_proof_bytes: vec![],
        };

        let mut expected = Vec::new();
        expected.extend_from_slice(PUBLIC_PROOF_ENVELOPE_MAGIC);
        expected.extend_from_slice(&PUBLIC_PROOF_ENVELOPE_VERSION.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0u8; 8]); // public input vector count
        expected.extend_from_slice(&[0u8; 8]); // R1CS constraints
        expected.extend_from_slice(&[0u8; 8]); // R1CS variables
        expected.extend_from_slice(&[0u8; 8]); // R1CS public arity
        expected.extend_from_slice(&[0u8; 8]); // FS commitment count
        expected.extend_from_slice(&[0u8; 32]); // fs_root
        expected.extend_from_slice(&[0u8; 32]); // fold_root
        expected.extend_from_slice(&[0u8; 32]); // challenge_digest
        expected.extend_from_slice(&[0u8; 32]); // transcript_seed_digest
        expected.extend_from_slice(&[0u8; 8]); // folded output length
        expected.extend_from_slice(&[0u8; 8]); // CP proof length
        expected.extend_from_slice(&[0u8; 8]); // output proof length

        assert_eq!(envelope.to_bytes(), expected);
    }

    #[cfg(feature = "whir")]
    #[test]
    fn poseidon2_babybear_scheme_id_roundtrips() {
        assert_eq!(digest_scheme_id(PublicDigestScheme::Poseidon2BabyBear), 1);
        assert_eq!(
            digest_scheme_from_id(1),
            Ok(PublicDigestScheme::Poseidon2BabyBear)
        );
    }
}
