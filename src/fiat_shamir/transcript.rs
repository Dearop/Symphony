//! Transcript management for Fiat-Shamir.
//!
//! The transcript accumulates (statement, committed messages) and derives
//! verifier challenges deterministically via SHA-256.

use sha2::{Sha256, Digest};
use crate::ring::extension::ExtFieldElement;

/// A Fiat-Shamir transcript that accumulates committed messages.
pub struct Transcript {
    /// Running SHA-256 state (re-hashed on each squeeze).
    state: Vec<u8>,
    /// Domain separator for this protocol.
    domain: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with a domain separator.
    pub fn new(domain: &[u8]) -> Self {
        Self {
            state: domain.to_vec(),
            domain: domain.to_vec(),
        }
    }

    /// Append raw bytes to the transcript.
    pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.state.extend_from_slice(data);
    }

    /// Append a commitment to the transcript.
    pub fn append_commitment<C: Clone + AsRef<[u8]>>(&mut self, label: &[u8], commitment: &C) {
        self.append_bytes(label, commitment.as_ref());
    }

    /// Squeeze a challenge from the transcript via SHA-256.
    ///
    /// Derives `output.len()` bytes by repeatedly hashing:
    ///   H(state || label || counter)
    /// and feeding each digest back as state for the next block.
    pub fn challenge_bytes(&mut self, label: &[u8], output: &mut [u8]) {
        self.state.extend_from_slice(label);

        let mut filled = 0;
        let mut counter: u64 = 0;
        while filled < output.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.state);
            hasher.update(counter.to_le_bytes());
            let digest = hasher.finalize();

            let remaining = output.len() - filled;
            let take = remaining.min(digest.len());
            output[filled..filled + take].copy_from_slice(&digest[..take]);
            filled += take;
            counter += 1;
        }

        // Feed the first digest back into state for forward secrecy
        let mut hasher = Sha256::new();
        hasher.update(&self.state);
        hasher.update(b"state-update");
        self.state = hasher.finalize().to_vec();
    }

    /// Squeeze a challenge as an extension field element.
    pub fn challenge_ext_field(&mut self, label: &[u8], q: u64) -> ExtFieldElement {
        let mut bytes = [0u8; 16];
        self.challenge_bytes(label, &mut bytes);
        let c0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) % q;
        let c1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) % q;
        ExtFieldElement {
            c0: if c0 > q / 2 { c0 as i64 - q as i64 } else { c0 as i64 },
            c1: if c1 > q / 2 { c1 as i64 - q as i64 } else { c1 as i64 },
        }
    }

    /// Get a copy of the current domain separator.
    pub fn domain(&self) -> &[u8] {
        &self.domain
    }
}
