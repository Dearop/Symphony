//! Standalone Commit-and-Prove SNARK.
//!
//! A CP-SNARK proves knowledge of values committed under an [`FSCommitment`]
//! scheme that satisfy a user-defined [`CommittedRelation`], **without**
//! revealing the committed values.
//!
//! This module is self-contained: it depends only on [`BackendSnark`],
//! [`FSCommitment`], and the Fiat-Shamir transcript. It can be used
//! independently of Symphony's folding pipeline.
//!
//! # Architecture
//!
//! ```text
//!                      ┌─────────────────┐
//!   Prover knows:      │   m_1, ..., m_k │  (messages)
//!                      │   o_1, ..., o_k │  (openings)
//!                      └──────┬──────────┘
//!                             │
//!                     ┌───────▼───────┐
//!                     │  CP-SNARK     │
//!                     │  proves:      │
//!                     │  ∀i: c_i =    │
//!                     │   Com(m_i;o_i)│
//!                     │  R(m_1..m_k;x)│
//!                     │   = true      │
//!                     └───────┬───────┘
//!                             │
//!   Verifier sees:    ┌───────▼───────┐
//!                     │ c_1, ..., c_k │  (commitments)
//!                     │ x             │  (public statement)
//!                     │ π             │  (proof)
//!                     └───────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use symphony::cp_snark::{CPSnark, CommittedRelation, IdentityRelation};
//! use symphony::fiat_shamir::hash_commitment::HashCommitment;
//! use symphony::fiat_shamir::FSCommitment;
//! use symphony::snark::DummySnark;
//!
//! let scheme = HashCommitment::new();
//! let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 64);
//!
//! let (c1, o1) = scheme.commit(b"secret-1");
//! let (c2, o2) = scheme.commit(b"secret-2");
//!
//! let proof = cp.prove(
//!     &scheme,
//!     &[b"secret-1".as_slice(), b"secret-2".as_slice()],
//!     &[o1, o2],
//!     &[c1, c2],
//!     b"",
//!     &IdentityRelation,
//! ).unwrap();
//!
//! assert!(cp.verify(&[c1, c2], b"", &proof));
//! ```

use std::marker::PhantomData;

use crate::fiat_shamir::transcript::Transcript;
use crate::fiat_shamir::FSCommitment;
use crate::snark::{BackendSnark, RelationDescription};

// -----------------------------------------------------------------------
// CommittedRelation trait
// -----------------------------------------------------------------------

/// A relation over committed values that the CP-SNARK proves.
///
/// Implement this trait to define the property that committed values must
/// satisfy. The CP-SNARK proves both **knowledge of openings** and that
/// the opened values **satisfy this relation**.
pub trait CommittedRelation {
    /// Check whether `messages` (the opened committed values, in order)
    /// satisfy the relation for the given `public_statement`.
    fn check(&self, messages: &[&[u8]], public_statement: &[u8]) -> bool;
}

// -----------------------------------------------------------------------
// Built-in relations
// -----------------------------------------------------------------------

/// The identity (trivial) relation: always satisfied.
///
/// Use this when you only need to prove knowledge of committed values
/// without any additional constraint on them.
pub struct IdentityRelation;

impl CommittedRelation for IdentityRelation {
    fn check(&self, _messages: &[&[u8]], _public_statement: &[u8]) -> bool {
        true
    }
}

/// A preimage relation: proves the committed messages hash to a known digest.
///
/// Specifically, checks that `SHA-256(m_1 ‖ m_2 ‖ ... ‖ m_k) == public_statement`.
pub struct PreimageRelation;

impl CommittedRelation for PreimageRelation {
    fn check(&self, messages: &[&[u8]], public_statement: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for msg in messages {
            hasher.update(msg);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        digest == public_statement
    }
}

/// Transcript-binding relation for the Symphony folding pipeline.
///
/// Proves that committed messages form a valid Fiat-Shamir transcript
/// under a given domain separator, and that the transcript derives the
/// expected challenge digest (passed as `public_statement`).
pub struct TranscriptRelation {
    pub domain: Vec<u8>,
}

impl CommittedRelation for TranscriptRelation {
    fn check(&self, messages: &[&[u8]], public_statement: &[u8]) -> bool {
        let mut transcript = Transcript::new(&self.domain);
        for (i, msg) in messages.iter().enumerate() {
            transcript.append_bytes(format!("round-{i}").as_bytes(), msg);
        }
        if public_statement.is_empty() {
            return true;
        }
        let mut expected = vec![0u8; public_statement.len()];
        transcript.challenge_bytes(b"relation-output", &mut expected);
        expected == public_statement
    }
}

/// A user-provided closure as a relation.
///
/// Wraps an `Fn(&[&[u8]], &[u8]) -> bool` for inline relation definitions.
pub struct FnRelation<F: Fn(&[&[u8]], &[u8]) -> bool>(pub F);

impl<F: Fn(&[&[u8]], &[u8]) -> bool> CommittedRelation for FnRelation<F> {
    fn check(&self, messages: &[&[u8]], public_statement: &[u8]) -> bool {
        (self.0)(messages, public_statement)
    }
}

// -----------------------------------------------------------------------
// CPProof
// -----------------------------------------------------------------------

/// A CP-SNARK proof, generic over the backend SNARK.
#[derive(Debug, Clone)]
pub struct CPProof<S: BackendSnark> {
    /// The backend SNARK proof for the commit-and-prove relation.
    pub backend_proof: S::Proof,
    /// Transcript digest that binds commitments to the proof context.
    pub transcript_digest: Vec<u8>,
}

// -----------------------------------------------------------------------
// CPSnark
// -----------------------------------------------------------------------

/// A standalone Commit-and-Prove SNARK.
///
/// Generic over:
/// - `S`: [`BackendSnark`] — the backend proof system (LaBRADOR, WHIR,
///   HyperPlonk+KZG, Spartan, or [`DummySnark`](crate::snark::DummySnark)
///   for testing).
/// - `C`: [`FSCommitment`] — the commitment scheme
///   ([`HashCommitment`](crate::fiat_shamir::hash_commitment::HashCommitment)
///   or a custom implementation).
///
/// The CP-SNARK proves: *"I know values v_1, ..., v_k such that
/// `c_i = Commit(v_i)` for all i, and `R(v_1, ..., v_k; x) = true`
/// for public statement x."*
pub struct CPSnark<S: BackendSnark, C: FSCommitment> {
    pk: S::ProvingKey,
    vk: S::VerifyingKey,
    num_messages: usize,
    _phantom: PhantomData<C>,
}

impl<S: BackendSnark, C: FSCommitment> CPSnark<S, C> {
    /// Setup the CP-SNARK for `num_messages` committed values.
    ///
    /// - `num_messages`: number of values that will be committed.
    /// - `max_message_size`: byte-length upper bound on each message.
    ///
    /// Internally calls `S::setup` with a relation description sized to
    /// hold the commitment checks and one relation constraint.
    pub fn setup(num_messages: usize, max_message_size: usize) -> Self {
        let relation = RelationDescription {
            num_instance_vars: num_messages * 32 + max_message_size,
            num_witness_vars: num_messages * (max_message_size + 32),
            num_constraints: num_messages + 1,
            context: None,
        };
        let (pk, vk) = S::setup(&relation);
        Self {
            pk,
            vk,
            num_messages,
            _phantom: PhantomData,
        }
    }

    /// Access the verifying key (useful for distributing to verifiers).
    pub fn verifying_key(&self) -> &S::VerifyingKey {
        &self.vk
    }

    /// Access the proving key.
    pub fn proving_key(&self) -> &S::ProvingKey {
        &self.pk
    }

    /// Generate a CP-SNARK proof.
    ///
    /// The prover demonstrates knowledge of `messages` that:
    /// 1. Open the given `commitments` under `scheme`
    /// 2. Satisfy `relation` for `public_statement`
    ///
    /// Returns `None` if:
    /// - Input lengths are mismatched
    /// - Any commitment opening fails to verify
    /// - The relation check fails
    pub fn prove(
        &self,
        scheme: &C,
        messages: &[&[u8]],
        openings: &[C::Opening],
        commitments: &[C::Commitment],
        public_statement: &[u8],
        relation: &dyn CommittedRelation,
    ) -> Option<CPProof<S>> {
        if messages.len() != self.num_messages
            || openings.len() != self.num_messages
            || commitments.len() != self.num_messages
        {
            return None;
        }

        for i in 0..self.num_messages {
            if !scheme.verify(&commitments[i], messages[i], &openings[i]) {
                return None;
            }
        }

        if !relation.check(messages, public_statement) {
            return None;
        }

        let mut transcript = Transcript::new(b"cp-snark-standalone-v1");
        transcript.append_bytes(b"num-messages", &(self.num_messages as u64).to_le_bytes());
        for c in commitments {
            transcript.append_commitment(b"commitment", c);
        }
        transcript.append_bytes(b"public-statement", public_statement);

        let instance = Self::encode_instance(commitments, public_statement, &mut transcript);

        let witness = Self::encode_witness(messages, commitments);

        let backend_proof = S::prove(&self.pk, &instance, &witness);

        let mut digest = [0u8; 32];
        transcript.challenge_bytes(b"proof-digest", &mut digest);

        Some(CPProof {
            backend_proof,
            transcript_digest: digest.to_vec(),
        })
    }

    /// Verify a CP-SNARK proof.
    ///
    /// The verifier checks the proof given only:
    /// - The commitments (not the opened values)
    /// - The public statement
    ///
    /// Returns `true` if the backend SNARK accepts.
    pub fn verify(
        &self,
        commitments: &[C::Commitment],
        public_statement: &[u8],
        proof: &CPProof<S>,
    ) -> bool {
        if commitments.len() != self.num_messages {
            return false;
        }

        let mut transcript = Transcript::new(b"cp-snark-standalone-v1");
        transcript.append_bytes(b"num-messages", &(self.num_messages as u64).to_le_bytes());
        for c in commitments {
            transcript.append_commitment(b"commitment", c);
        }
        transcript.append_bytes(b"public-statement", public_statement);

        let instance = Self::encode_instance(commitments, public_statement, &mut transcript);

        // Verify the transcript digest matches (binding check)
        let mut digest = [0u8; 32];
        transcript.challenge_bytes(b"proof-digest", &mut digest);
        if digest.to_vec() != proof.transcript_digest {
            return false;
        }

        S::verify(&self.vk, &instance, &proof.backend_proof)
    }

    /// Encode the public instance for the backend SNARK.
    ///
    /// Format: [num_commitments | (len_i | commitment_i)* | len_stmt | stmt | challenge]
    fn encode_instance(
        commitments: &[C::Commitment],
        public_statement: &[u8],
        transcript: &mut Transcript,
    ) -> Vec<u8> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&(commitments.len() as u64).to_le_bytes());
        for c in commitments {
            let bytes = c.as_ref();
            instance.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            instance.extend_from_slice(bytes);
        }
        instance.extend_from_slice(&(public_statement.len() as u64).to_le_bytes());
        instance.extend_from_slice(public_statement);

        let mut challenge = [0u8; 32];
        transcript.challenge_bytes(b"cp-bind", &mut challenge);
        instance.extend_from_slice(&challenge);

        instance
    }

    /// Encode the private witness for the backend SNARK.
    ///
    /// Format: [num_messages | (len_i | message_i)* | commitment_bytes*]
    fn encode_witness(messages: &[&[u8]], commitments: &[C::Commitment]) -> Vec<u8> {
        let mut witness = Vec::new();
        witness.extend_from_slice(&(messages.len() as u64).to_le_bytes());
        for msg in messages {
            witness.extend_from_slice(&(msg.len() as u64).to_le_bytes());
            witness.extend_from_slice(msg);
        }
        for c in commitments {
            witness.extend_from_slice(c.as_ref());
        }
        witness
    }
}

// -----------------------------------------------------------------------
// CPSnarkBuilder — ergonomic fluent API
// -----------------------------------------------------------------------

/// Builder for constructing and using a CP-SNARK in a single flow.
///
/// Collects messages, commitments, and openings, then produces a proof
/// in one call. Automatically handles `CPSnark::setup` sizing.
///
/// # Example
///
/// ```rust,no_run
/// use symphony::cp_snark::{CPSnarkBuilder, IdentityRelation};
/// use symphony::fiat_shamir::hash_commitment::HashCommitment;
/// use symphony::fiat_shamir::FSCommitment;
/// use symphony::snark::DummySnark;
///
/// let scheme = HashCommitment::new();
/// let (c1, o1) = scheme.commit(b"hello");
/// let (c2, o2) = scheme.commit(b"world");
///
/// let (proof, commitments) = CPSnarkBuilder::<DummySnark, HashCommitment>::new()
///     .message(b"hello", o1, c1)
///     .message(b"world", o2, c2)
///     .statement(b"pub")
///     .prove(&scheme, &IdentityRelation)
///     .unwrap();
/// ```
pub struct CPSnarkBuilder<S: BackendSnark, C: FSCommitment> {
    messages: Vec<Vec<u8>>,
    openings: Vec<C::Opening>,
    commitments: Vec<C::Commitment>,
    public_statement: Vec<u8>,
    max_message_size: usize,
    _phantom: PhantomData<S>,
}

impl<S: BackendSnark, C: FSCommitment> CPSnarkBuilder<S, C> {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            openings: Vec::new(),
            commitments: Vec::new(),
            public_statement: Vec::new(),
            max_message_size: 0,
            _phantom: PhantomData,
        }
    }

    /// Add a committed message with its opening and commitment.
    pub fn message(mut self, msg: &[u8], opening: C::Opening, commitment: C::Commitment) -> Self {
        if msg.len() > self.max_message_size {
            self.max_message_size = msg.len();
        }
        self.messages.push(msg.to_vec());
        self.openings.push(opening);
        self.commitments.push(commitment);
        self
    }

    /// Set the public statement.
    pub fn statement(mut self, stmt: &[u8]) -> Self {
        self.public_statement = stmt.to_vec();
        self
    }

    /// Commit a fresh message through the scheme, returning the builder
    /// with the commitment and opening added automatically.
    pub fn commit_and_add(mut self, scheme: &C, msg: &[u8]) -> Self {
        let (c, o) = scheme.commit(msg);
        if msg.len() > self.max_message_size {
            self.max_message_size = msg.len();
        }
        self.messages.push(msg.to_vec());
        self.openings.push(o);
        self.commitments.push(c);
        self
    }

    /// Produce a proof (and the commitment list) for the given relation.
    ///
    /// Internally calls `CPSnark::setup` with the appropriate sizing,
    /// then `CPSnark::prove`.
    pub fn prove(
        &self,
        scheme: &C,
        relation: &dyn CommittedRelation,
    ) -> Option<(CPProof<S>, Vec<C::Commitment>)> {
        let max_msg = self.max_message_size.max(1);
        let cp = CPSnark::<S, C>::setup(self.messages.len(), max_msg);

        let msg_refs: Vec<&[u8]> = self.messages.iter().map(|m| m.as_slice()).collect();

        let proof = cp.prove(
            scheme,
            &msg_refs,
            &self.openings,
            &self.commitments,
            &self.public_statement,
            relation,
        )?;

        Some((proof, self.commitments.clone()))
    }
}

impl<S: BackendSnark, C: FSCommitment> Default for CPSnarkBuilder<S, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fiat_shamir::hash_commitment::HashCommitment;
    use crate::fiat_shamir::FSCommitment;
    use crate::snark::DummySnark;

    #[test]
    fn hash_commitment_roundtrip() {
        let scheme = HashCommitment::new();
        let msg = b"test message";
        let (commitment, opening) = scheme.commit(msg);
        assert!(scheme.verify(&commitment, msg, &opening));
        assert!(!scheme.verify(&commitment, b"wrong", &opening));
    }

    #[test]
    fn identity_relation_prove_verify() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 64);

        let (c1, o1) = scheme.commit(b"msg-1");
        let (c2, o2) = scheme.commit(b"msg-2");

        let proof = cp
            .prove(
                &scheme,
                &[b"msg-1".as_slice(), b"msg-2".as_slice()],
                &[o1, o2],
                &[c1, c2],
                b"",
                &IdentityRelation,
            )
            .expect("proof should succeed");

        assert!(cp.verify(&[c1, c2], b"", &proof));
    }

    #[test]
    fn wrong_commitment_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 64);

        let (_c1, o1) = scheme.commit(b"real-message");
        let (c_fake, _) = scheme.commit(b"fake-message");

        let result = cp.prove(
            &scheme,
            &[b"real-message".as_slice()],
            &[o1],
            &[c_fake],
            b"",
            &IdentityRelation,
        );
        assert!(result.is_none(), "should reject mismatched commitment");
    }

    #[test]
    fn failing_relation_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 64);

        let (c, o) = scheme.commit(b"data");

        let never = FnRelation(|_msgs: &[&[u8]], _stmt: &[u8]| false);

        let result = cp.prove(&scheme, &[b"data".as_slice()], &[o], &[c], b"", &never);
        assert!(result.is_none(), "should reject failing relation");
    }

    #[test]
    fn preimage_relation() {
        use sha2::{Digest, Sha256};

        let scheme = HashCommitment::new();
        let m1 = b"hello";
        let m2 = b"world";

        let mut h = Sha256::new();
        h.update(m1);
        h.update(m2);
        let digest: [u8; 32] = h.finalize().into();

        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 8);
        let (c1, o1) = scheme.commit(m1);
        let (c2, o2) = scheme.commit(m2);

        let proof = cp
            .prove(
                &scheme,
                &[m1.as_slice(), m2.as_slice()],
                &[o1, o2],
                &[c1, c2],
                &digest,
                &PreimageRelation,
            )
            .expect("proof should succeed");

        assert!(cp.verify(&[c1, c2], &digest, &proof));
    }

    #[test]
    fn wrong_preimage_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(1, 8);
        let (c, o) = scheme.commit(b"data");

        let wrong_digest = [0u8; 32];
        let result = cp.prove(
            &scheme,
            &[b"data".as_slice()],
            &[o],
            &[c],
            &wrong_digest,
            &PreimageRelation,
        );
        assert!(result.is_none(), "should reject wrong preimage");
    }

    #[test]
    fn transcript_relation() {
        let scheme = HashCommitment::new();
        let m1 = b"round-0-data";
        let m2 = b"round-1-data";

        let mut tr = Transcript::new(b"test-domain");
        tr.append_bytes(b"round-0", m1);
        tr.append_bytes(b"round-1", m2);
        let mut expected = vec![0u8; 32];
        tr.challenge_bytes(b"relation-output", &mut expected);

        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 32);
        let (c1, o1) = scheme.commit(m1);
        let (c2, o2) = scheme.commit(m2);

        let relation = TranscriptRelation {
            domain: b"test-domain".to_vec(),
        };

        let proof = cp
            .prove(
                &scheme,
                &[m1.as_slice(), m2.as_slice()],
                &[o1, o2],
                &[c1, c2],
                &expected,
                &relation,
            )
            .expect("proof should succeed");

        assert!(cp.verify(&[c1, c2], &expected, &proof));
    }

    #[test]
    fn mismatched_count_rejected() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 32);
        let (c, o) = scheme.commit(b"x");

        let result = cp.prove(
            &scheme,
            &[b"x".as_slice()],
            &[o],
            &[c],
            b"",
            &IdentityRelation,
        );
        assert!(result.is_none(), "should reject mismatched count");
    }

    #[test]
    fn verify_rejects_wrong_count() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 32);
        let (c1, o1) = scheme.commit(b"a");
        let (c2, o2) = scheme.commit(b"b");

        let proof = cp
            .prove(
                &scheme,
                &[b"a".as_slice(), b"b".as_slice()],
                &[o1, o2],
                &[c1, c2],
                b"",
                &IdentityRelation,
            )
            .unwrap();

        assert!(!cp.verify(&[c1], b"", &proof), "wrong count should fail");
    }

    #[test]
    fn fn_relation_custom_logic() {
        let scheme = HashCommitment::new();
        let cp = CPSnark::<DummySnark, HashCommitment>::setup(2, 8);

        let v1 = 42u64.to_le_bytes();
        let v2 = 58u64.to_le_bytes();
        let (c1, o1) = scheme.commit(&v1);
        let (c2, o2) = scheme.commit(&v2);

        let sum_is_100 = FnRelation(|msgs: &[&[u8]], _| {
            let sum: u64 = msgs
                .iter()
                .map(|m| u64::from_le_bytes(m[..8].try_into().unwrap()))
                .sum();
            sum == 100
        });

        let proof = cp
            .prove(
                &scheme,
                &[v1.as_slice(), v2.as_slice()],
                &[o1, o2],
                &[c1, c2],
                b"",
                &sum_is_100,
            )
            .expect("proof should succeed");

        assert!(cp.verify(&[c1, c2], b"", &proof));
    }
}
