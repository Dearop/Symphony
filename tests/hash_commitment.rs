//! Tests for the SHA-256-based Fiat-Shamir commitment scheme.

use symphony::fiat_shamir::hash_commitment::HashCommitment;
use symphony::fiat_shamir::FSCommitment;

mod hash_commitment_core {
    use super::*;

    #[test]
    fn commit_verify_roundtrip() {
        let hc = HashCommitment::new();
        let msg = b"hello world";
        let (commitment, opening) = hc.commit(msg);
        assert!(hc.verify(&commitment, msg, &opening));
    }

    #[test]
    fn wrong_message_rejected() {
        let hc = HashCommitment::new();
        let (commitment, opening) = hc.commit(b"correct message");
        assert!(!hc.verify(&commitment, b"wrong message", &opening));
    }

    #[test]
    fn wrong_opening_rejected() {
        let hc = HashCommitment::new();
        let (commitment, _opening) = hc.commit(b"test");
        let tampered_opening = [0xFFu8; 32];
        assert!(!hc.verify(&commitment, b"test", &tampered_opening));
    }

    #[test]
    fn empty_message() {
        let hc = HashCommitment::new();
        let (commitment, opening) = hc.commit(b"");
        assert!(hc.verify(&commitment, b"", &opening));
        assert!(!hc.verify(&commitment, b"nonempty", &opening));
    }

    #[test]
    fn fresh_randomness() {
        let hc = HashCommitment::new();
        let msg = b"same message";
        let (c1, o1) = hc.commit(msg);
        let (c2, o2) = hc.commit(msg);
        // Fresh randomness means different commitments (with overwhelming probability)
        assert_ne!(o1, o2, "randomness should be fresh each time");
        assert_ne!(c1, c2, "commitments should differ due to fresh randomness");
        // Both should still verify
        assert!(hc.verify(&c1, msg, &o1));
        assert!(hc.verify(&c2, msg, &o2));
    }

    #[test]
    fn large_message() {
        let hc = HashCommitment::new();
        let msg = vec![0xABu8; 10_000];
        let (commitment, opening) = hc.commit(&msg);
        assert!(hc.verify(&commitment, &msg, &opening));
    }

    #[test]
    fn default_impl() {
        let hc = HashCommitment::default();
        let msg = b"default test";
        let (commitment, opening) = hc.commit(msg);
        assert!(hc.verify(&commitment, msg, &opening));
    }
}
