//! Canonical transcript schema and challenge derivation utilities.

use sha2::{Digest, Sha256};

/// Magic prefix for canonical transcript encodings.
pub const TRANSCRIPT_MAGIC: &[u8; 8] = b"SYMTRN01";
/// Current transcript schema version.
pub const CURRENT_VERSION: u16 = 1;

/// Well-known transcript event tags used by the Symphony pipeline.
pub mod tags {
    pub const PUBLIC_INPUT: u8 = 1;
    pub const R1CS_META: u8 = 2;
    pub const FS_COMMITMENT: u8 = 3;
    pub const ROUND_MESSAGE: u8 = 4;
}

/// One ordered transcript event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptEvent {
    pub tag: u8,
    pub label: Vec<u8>,
    pub payload: Vec<u8>,
}

impl TranscriptEvent {
    pub fn new(tag: u8, label: &[u8], payload: &[u8]) -> Self {
        Self {
            tag,
            label: label.to_vec(),
            payload: payload.to_vec(),
        }
    }
}

/// Explicit, versioned transcript schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptSchema {
    pub version: u16,
    pub domain_tag: Vec<u8>,
    pub events: Vec<TranscriptEvent>,
}

impl TranscriptSchema {
    pub fn new(domain_tag: &[u8]) -> Self {
        Self {
            version: CURRENT_VERSION,
            domain_tag: domain_tag.to_vec(),
            events: Vec::new(),
        }
    }

    pub fn push_event(&mut self, event: TranscriptEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptDecodeError {
    InvalidMagic,
    UnsupportedVersion(u16),
    Truncated,
    LengthOverflow,
    TrailingBytes,
}

/// Canonical transcript codec interface.
pub trait TranscriptCodec {
    fn encode(&self, schema: &TranscriptSchema) -> Vec<u8>;
    fn decode(&self, bytes: &[u8]) -> Result<TranscriptSchema, TranscriptDecodeError>;
}

/// Versioned, length-delimited transcript codec.
#[derive(Debug, Clone, Default)]
pub struct CanonicalTranscriptCodec;

impl CanonicalTranscriptCodec {
    fn read_exact<'a>(
        bytes: &'a [u8],
        cursor: &mut usize,
        len: usize,
    ) -> Result<&'a [u8], TranscriptDecodeError> {
        let end = cursor
            .checked_add(len)
            .ok_or(TranscriptDecodeError::LengthOverflow)?;
        if end > bytes.len() {
            return Err(TranscriptDecodeError::Truncated);
        }
        let out = &bytes[*cursor..end];
        *cursor = end;
        Ok(out)
    }

    fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, TranscriptDecodeError> {
        let raw = Self::read_exact(bytes, cursor, 2)?;
        Ok(u16::from_le_bytes(raw.try_into().unwrap()))
    }

    fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, TranscriptDecodeError> {
        let raw = Self::read_exact(bytes, cursor, 8)?;
        Ok(u64::from_le_bytes(raw.try_into().unwrap()))
    }

    fn read_vec(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, TranscriptDecodeError> {
        let len_u64 = Self::read_u64(bytes, cursor)?;
        let len = usize::try_from(len_u64).map_err(|_| TranscriptDecodeError::LengthOverflow)?;
        Ok(Self::read_exact(bytes, cursor, len)?.to_vec())
    }
}

impl TranscriptCodec for CanonicalTranscriptCodec {
    fn encode(&self, schema: &TranscriptSchema) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(TRANSCRIPT_MAGIC);
        out.extend_from_slice(&schema.version.to_le_bytes());

        out.extend_from_slice(&(schema.domain_tag.len() as u64).to_le_bytes());
        out.extend_from_slice(&schema.domain_tag);

        out.extend_from_slice(&(schema.events.len() as u64).to_le_bytes());
        for event in &schema.events {
            out.push(event.tag);
            out.extend_from_slice(&(event.label.len() as u64).to_le_bytes());
            out.extend_from_slice(&event.label);
            out.extend_from_slice(&(event.payload.len() as u64).to_le_bytes());
            out.extend_from_slice(&event.payload);
        }

        out
    }

    fn decode(&self, bytes: &[u8]) -> Result<TranscriptSchema, TranscriptDecodeError> {
        let mut cursor = 0usize;

        let magic = Self::read_exact(bytes, &mut cursor, TRANSCRIPT_MAGIC.len())?;
        if magic != TRANSCRIPT_MAGIC {
            return Err(TranscriptDecodeError::InvalidMagic);
        }

        let version = Self::read_u16(bytes, &mut cursor)?;
        if version != CURRENT_VERSION {
            return Err(TranscriptDecodeError::UnsupportedVersion(version));
        }

        let domain_tag = Self::read_vec(bytes, &mut cursor)?;
        let num_events_u64 = Self::read_u64(bytes, &mut cursor)?;
        let num_events =
            usize::try_from(num_events_u64).map_err(|_| TranscriptDecodeError::LengthOverflow)?;

        let mut events = Vec::with_capacity(num_events);
        for _ in 0..num_events {
            let tag = *Self::read_exact(bytes, &mut cursor, 1)?
                .first()
                .ok_or(TranscriptDecodeError::Truncated)?;
            let label = Self::read_vec(bytes, &mut cursor)?;
            let payload = Self::read_vec(bytes, &mut cursor)?;
            events.push(TranscriptEvent {
                tag,
                label,
                payload,
            });
        }

        if cursor != bytes.len() {
            return Err(TranscriptDecodeError::TrailingBytes);
        }

        Ok(TranscriptSchema {
            version,
            domain_tag,
            events,
        })
    }
}

/// Deterministic challenge derivation interface.
pub trait ChallengeDeriver {
    fn derive_challenges(
        &self,
        domain_tag: &[u8],
        transcript_bytes: &[u8],
        count: usize,
        challenge_len: usize,
    ) -> Vec<Vec<u8>>;
}

/// SHA-256 based challenge derivation.
#[derive(Debug, Clone, Default)]
pub struct Sha256ChallengeDeriver;

impl Sha256ChallengeDeriver {
    fn squeeze(seed: &[u8; 32], out_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; out_len];
        let mut filled = 0usize;
        let mut block_counter = 0u64;

        while filled < out_len {
            let mut hasher = Sha256::new();
            hasher.update(b"symphony-challenge-expand-v1");
            hasher.update(seed);
            hasher.update(block_counter.to_le_bytes());
            let block: [u8; 32] = hasher.finalize().into();

            let take = (out_len - filled).min(block.len());
            out[filled..filled + take].copy_from_slice(&block[..take]);
            filled += take;
            block_counter += 1;
        }

        out
    }

    pub fn derive_fixed_32(
        &self,
        domain_tag: &[u8],
        transcript_bytes: &[u8],
        count: usize,
    ) -> Vec<Vec<u8>> {
        self.derive_challenges(domain_tag, transcript_bytes, count, 32)
    }
}

impl ChallengeDeriver for Sha256ChallengeDeriver {
    fn derive_challenges(
        &self,
        domain_tag: &[u8],
        transcript_bytes: &[u8],
        count: usize,
        challenge_len: usize,
    ) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(b"symphony-challenge-v1");
                hasher.update((domain_tag.len() as u64).to_le_bytes());
                hasher.update(domain_tag);
                hasher.update((transcript_bytes.len() as u64).to_le_bytes());
                hasher.update(transcript_bytes);
                hasher.update((i as u64).to_le_bytes());
                let seed: [u8; 32] = hasher.finalize().into();
                Self::squeeze(&seed, challenge_len)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roundtrip() {
        let codec = CanonicalTranscriptCodec;
        let mut schema = TranscriptSchema::new(b"symphony-v1");
        schema.push_event(TranscriptEvent::new(
            tags::PUBLIC_INPUT,
            b"public-input",
            &[1, 2],
        ));
        schema.push_event(TranscriptEvent::new(
            tags::FS_COMMITMENT,
            b"fs-commitment",
            &[7, 8, 9],
        ));

        let encoded = codec.encode(&schema);
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded, schema);
    }

    #[test]
    fn invalid_magic_rejected() {
        let codec = CanonicalTranscriptCodec;
        let bad = b"bad-data";
        assert_eq!(codec.decode(bad), Err(TranscriptDecodeError::InvalidMagic));

        let mut schema = TranscriptSchema::new(b"symphony-v1");
        schema.push_event(TranscriptEvent::new(
            tags::R1CS_META,
            b"r1cs-m",
            &1u64.to_le_bytes(),
        ));
        let mut encoded = codec.encode(&schema);
        encoded[0] ^= 1;
        assert_eq!(
            codec.decode(&encoded),
            Err(TranscriptDecodeError::InvalidMagic)
        );
    }

    #[test]
    fn challenge_derivation_is_binding() {
        let deriver = Sha256ChallengeDeriver;
        let a = deriver.derive_fixed_32(b"d", b"abc", 2);
        let b = deriver.derive_fixed_32(b"d", b"abd", 2);
        assert_ne!(a, b);
    }
}
